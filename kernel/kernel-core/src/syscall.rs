//! ============================================================================
//! syscall.rs
//!
//! Purpose: the microkernel's entire user-facing API — the small
//! `SyscallOp` set (02-Microkernel-Layer.md §6) and `KernelState::dispatch`,
//! written as one explicit `match` state machine with a bounded, traceable
//! effect per arm and no hidden global mutation (§1.1).
//!
//! Architecture reference: 02-Microkernel-Layer.md §6 (`SyscallOp` — exact
//! variant set), §2 (`CapGrant`/`CapRevoke` semantics), §3 (`Retype`), §5
//! (`Send`/`Recv`/`Call` IPC), §1.1 (state-machine dispatcher).
//!
//! Position in the system: `kernel-arch-glue`'s trap handler decodes a
//! user trap into a `SyscallOp`, calls `dispatch`, and acts on the
//! `SyscallReturn` (e.g. performs a `context_switch` on `Reschedule`, or
//! resumes the caller with a return value). This crate never touches
//! architecture registers itself.
//!
//! Safety/invariants: `dispatch` never allocates, never spins, and never
//! itself performs a context switch — a syscall that must wait returns
//! `SyscallReturn::Blocked` and it is the caller's job to actually stop
//! running the calling thread and pick another.
//! ============================================================================

use crate::state::KernelState;
use crate::tcb::ThreadState;
use hal_core::{MapPermissions, VirtAddr};
use kernel_cap::{
    CapId, CapTableError, Capability, CapabilityRights, KernelObjectKind, ObjectId, ObjectRef,
    PageTableId, ThreadId, UntypedId,
};
use kernel_ipc::{EndpointError, IpcError, RecvOutcome, SendOutcome, SmallMessage};
use kernel_mm::{KernelObjectType, MmError, PAGE_SIZE};
use kernel_sched::SchedError;

/// The complete microkernel syscall set (02-Microkernel-Layer.md §6). Kept
/// tiny on purpose — seL4-scale, roughly a dozen, not Linux's ~350.
///
/// Every `CapId` is resolved against the *calling thread's* capability
/// space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallOp {
    /// Send `msg` on the endpoint named by `endpoint`; block if no
    /// receiver is waiting. Requires `WRITE` on the endpoint capability.
    Send {
        /// Endpoint capability.
        endpoint: CapId,
        /// The message.
        msg: SmallMessage,
    },
    /// Receive one message from `endpoint`; block if no sender is waiting.
    /// Requires `READ` on the endpoint capability.
    Recv {
        /// Endpoint capability.
        endpoint: CapId,
    },
    /// Atomic `Send` + `Recv` on `endpoint` (RPC): deliver `msg`, then
    /// block for the reply. Requires `READ | WRITE`.
    Call {
        /// Endpoint capability.
        endpoint: CapId,
        /// The request message.
        msg: SmallMessage,
    },
    /// Voluntarily yield the CPU. Always succeeds.
    Yield,
    /// Copy capability `cap` (narrowed to `rights`) into the capability
    /// space of the thread named by `target_thread`. Requires `GRANT` on
    /// `cap` (and, in the full model, authority over the target thread).
    CapGrant {
        /// A `ThreadControlBlock` capability for the destination thread.
        target_thread: CapId,
        /// The capability to copy.
        cap: CapId,
        /// Rights of the copy (must be a subset of `cap`'s rights).
        rights: CapabilityRights,
    },
    /// Revoke `cap` and every capability derived from it. Requires
    /// `REVOKE` on `cap`.
    CapRevoke {
        /// The capability (subtree root) to revoke.
        cap: CapId,
    },
    /// Retype `count` objects of `target_type` out of the `UntypedMemory`
    /// named by `untyped`, inserting a fresh capability for each into the
    /// caller's capability space. Requires `WRITE` on `untyped`.
    Retype {
        /// An `UntypedMemory` capability.
        untyped: CapId,
        /// What to create.
        target_type: KernelObjectType,
        /// How many.
        count: u32,
    },
    /// Map `frame` at `vaddr` in the address space named by `page_table`
    /// with `perms`. Requires `WRITE` on `page_table` and rights on
    /// `frame` matching `perms`.
    Map {
        /// A `PageTable` (address-space-root) capability.
        page_table: CapId,
        /// The frame to map (an `UntypedMemory` capability in this MVP
        /// model — one page of it).
        frame: CapId,
        /// Virtual address to map at (page-aligned).
        vaddr: VirtAddr,
        /// Mapping permissions.
        perms: MapPermissions,
    },
}

/// The result of a syscall. `kernel-arch-glue` translates this into a
/// user-visible return value and/or a scheduling action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallReturn {
    /// Completed with no value.
    Done,
    /// Completed; `value` should be placed in the caller's return
    /// register.
    Value(u64),
    /// `Retype` created `count` objects; the first capability is `cap`
    /// (subsequent ones follow at `cap + 1 ..` in the caller's space).
    NewCaps {
        /// First new capability slot.
        cap: CapId,
        /// Number created.
        count: u32,
    },
    /// `CapRevoke` freed `freed` capability slots (the target plus its
    /// derivatives).
    Revoked {
        /// Slots freed.
        freed: u32,
    },
    /// `CapGrant` placed a copy at `dst` in the target thread's space.
    Granted {
        /// Slot in the *target* thread's capability space.
        dst: CapId,
    },
    /// `Map` succeeded.
    Mapped,
    /// The calling thread must block (it has been queued on the relevant
    /// endpoint / notification). The caller stops running it and picks a
    /// successor.
    Blocked,
    /// An IPC operation completed a rendezvous and made `woke` runnable.
    /// The caller continues; `woke` becomes schedulable.
    Delivered {
        /// The thread made runnable by this rendezvous.
        woke: ThreadId,
    },
    /// A `Recv` delivered a message from `from`.
    Message {
        /// The sender.
        from: ThreadId,
        /// The message.
        msg: SmallMessage,
    },
    /// `Yield` (or a blocking op) — the caller should context-switch to
    /// `next` (or idle if `None`).
    Reschedule {
        /// Successor thread.
        next: Option<ThreadId>,
    },
}

/// Why a syscall failed. Flat and `Copy`, same rationale as every other
/// `kernel/*` error enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallError {
    /// The calling `ThreadId` has no live TCB.
    NoCaller,
    /// A `CapId` argument names an empty slot or is out of range.
    BadCap,
    /// A capability names an object of the wrong kind for this syscall.
    WrongObjectKind,
    /// The capability lacks a right this syscall requires.
    InsufficientRights,
    /// The object table for the kind being created is full.
    ObjectTableFull,
    /// A capability-table operation failed.
    Cap(CapTableError),
    /// A memory-management operation failed.
    Mm(MmError),
    /// An IPC operation failed.
    Ipc(IpcError),
    /// A scheduler operation failed.
    Sched(SchedError),
    /// The requested operation is not implemented in this MVP.
    Unsupported,
}

impl From<CapTableError> for SyscallError {
    fn from(e: CapTableError) -> Self {
        SyscallError::Cap(e)
    }
}
impl From<MmError> for SyscallError {
    fn from(e: MmError) -> Self {
        SyscallError::Mm(e)
    }
}
impl From<IpcError> for SyscallError {
    fn from(e: IpcError) -> Self {
        SyscallError::Ipc(e)
    }
}
impl From<EndpointError> for SyscallError {
    fn from(e: EndpointError) -> Self {
        // The only endpoint-level failure is a full wait queue; fold it
        // into the shared IPC error so the dispatcher has one IPC error
        // channel.
        match e {
            EndpointError::QueueFull => SyscallError::Ipc(IpcError::QueueFull),
        }
    }
}
impl From<SchedError> for SyscallError {
    fn from(e: SchedError) -> Self {
        SyscallError::Sched(e)
    }
}

impl KernelState {
    /// Resolves `cap` in `caller`'s capability space, checks it holds
    /// `kind` and every right in `needed`, and returns a copy of it.
    fn resolve(
        &self,
        caller: ThreadId,
        cap: CapId,
        kind: KernelObjectKind,
        needed: CapabilityRights,
    ) -> Result<Capability, SyscallError> {
        let cs_id = self.tcb(caller).ok_or(SyscallError::NoCaller)?.cap_space;
        let cs = self.cap_space(cs_id).ok_or(SyscallError::NoCaller)?;
        let c = *cs.lookup(cap).ok_or(SyscallError::BadCap)?;
        if c.object.kind != kind {
            return Err(SyscallError::WrongObjectKind);
        }
        if !c.allows(needed) {
            return Err(SyscallError::InsufficientRights);
        }
        Ok(c)
    }

    fn caller_cap_space(&self, caller: ThreadId) -> Result<kernel_cap::CapSpaceId, SyscallError> {
        Ok(self.tcb(caller).ok_or(SyscallError::NoCaller)?.cap_space)
    }

    /// The one syscall entry point. `now_ns` is the current monotonic
    /// time from `hal_core::TimerAbstraction::now_ns`, threaded in so the
    /// scheduler can charge run time without this crate touching the HAL.
    pub fn dispatch(
        &mut self,
        caller: ThreadId,
        now_ns: u64,
        op: SyscallOp,
    ) -> Result<SyscallReturn, SyscallError> {
        match op {
            SyscallOp::Yield => {
                self.sched.account(now_ns);
                let next = self.sched.pick_next(now_ns);
                Ok(SyscallReturn::Reschedule { next })
            }

            SyscallOp::CapRevoke { cap } => {
                let _ = self.resolve(
                    caller,
                    cap,
                    // A revoke target can name any object kind — the check
                    // that matters is the REVOKE right, so resolve against
                    // the actual kind stored in the slot rather than
                    // demanding a specific one.
                    self.cap_kind_of(caller, cap)?,
                    CapabilityRights::REVOKE,
                )?;
                let cs_id = self.caller_cap_space(caller)?;
                let cs = self.cap_space_mut(cs_id).ok_or(SyscallError::NoCaller)?;
                let freed = cs.revoke(cap)?;
                Ok(SyscallReturn::Revoked { freed })
            }

            SyscallOp::Retype {
                untyped,
                target_type,
                count,
            } => self.do_retype(caller, untyped, target_type, count),

            SyscallOp::CapGrant {
                target_thread,
                cap,
                rights,
            } => self.do_cap_grant(caller, target_thread, cap, rights),

            SyscallOp::Map {
                page_table,
                frame,
                vaddr,
                perms,
            } => self.do_map(caller, page_table, frame, vaddr, perms),

            SyscallOp::Send { endpoint, msg } => self.do_send(caller, endpoint, msg, false, now_ns),
            SyscallOp::Call { endpoint, msg } => self.do_send(caller, endpoint, msg, true, now_ns),
            SyscallOp::Recv { endpoint } => self.do_recv(caller, endpoint, now_ns),
        }
    }

    /// The object kind stored at `cap` in `caller`'s space (helper for
    /// `CapRevoke`, whose target kind is not fixed).
    fn cap_kind_of(&self, caller: ThreadId, cap: CapId) -> Result<KernelObjectKind, SyscallError> {
        let cs_id = self.tcb(caller).ok_or(SyscallError::NoCaller)?.cap_space;
        let cs = self.cap_space(cs_id).ok_or(SyscallError::NoCaller)?;
        Ok(cs.lookup(cap).ok_or(SyscallError::BadCap)?.object.kind)
    }

    fn do_retype(
        &mut self,
        caller: ThreadId,
        untyped: CapId,
        target_type: KernelObjectType,
        count: u32,
    ) -> Result<SyscallReturn, SyscallError> {
        let ucap = self.resolve(
            caller,
            untyped,
            KernelObjectKind::UntypedMemory,
            CapabilityRights::WRITE,
        )?;
        let uid = UntypedId::new(ucap.object.id.as_u32());
        // Reserve the backing physical range.
        let grant = {
            let u = self.untyped_mut(uid).ok_or(SyscallError::BadCap)?;
            u.retype(target_type, count)?
        };

        let cs_id = self.caller_cap_space(caller)?;
        let per = kernel_mm::object_size_bytes(target_type) as u64;
        let mut first: Option<CapId> = None;
        let mut made: u32 = 0;
        for i in 0..grant.count {
            // Physical slot for object `i` within the reserved range.
            let obj_phys = grant.phys_base.as_usize() as u64 + i as u64 * per;

            // Allocate the concrete object-table slot for this kind.
            let (kind, obj_id) = match target_type {
                KernelObjectType::Endpoint => {
                    let id = self.alloc_endpoint().ok_or(SyscallError::ObjectTableFull)?;
                    (KernelObjectKind::Endpoint, id.as_u32())
                }
                KernelObjectType::Notification => {
                    let id = self
                        .alloc_notification()
                        .ok_or(SyscallError::ObjectTableFull)?;
                    (KernelObjectKind::Notification, id.as_u32())
                }
                KernelObjectType::PageTable => {
                    // The retyped frame becomes the page-table root.
                    let id = self
                        .alloc_addr_space(obj_phys)
                        .ok_or(SyscallError::ObjectTableFull)?;
                    (KernelObjectKind::PageTable, id.as_u32())
                }
                KernelObjectType::CapabilitySpace => {
                    let id = self
                        .alloc_cap_space()
                        .ok_or(SyscallError::ObjectTableFull)?;
                    (KernelObjectKind::CapabilitySpace, id.as_u32())
                }
                KernelObjectType::ThreadControlBlock => {
                    // MVP: a freshly retyped TCB is bound to the caller's
                    // own cap space / address space. A later `feat:` adds
                    // a `Configure`-style op to rebind it (seL4's model).
                    let (cs0, as0) = {
                        let t = self.tcb(caller).ok_or(SyscallError::NoCaller)?;
                        (t.cap_space, t.addr_space)
                    };
                    let id = self
                        .alloc_tcb(cs0, as0)
                        .ok_or(SyscallError::ObjectTableFull)?;
                    (KernelObjectKind::ThreadControlBlock, id.as_u32())
                }
                KernelObjectType::Untyped => {
                    // Sub-divide: each child is one page of the reserved
                    // range (MVP granularity — `SyscallOp::Retype` carries
                    // no size argument; a `size_bits` field is a later
                    // extension, seL4-style).
                    let id = self
                        .alloc_untyped(obj_phys, per)
                        .ok_or(SyscallError::ObjectTableFull)?;
                    (KernelObjectKind::UntypedMemory, id.as_u32())
                }
            };

            let newcap = Capability::full(ObjectRef::new(kind, ObjectId::new(obj_id)));
            let cs = self.cap_space_mut(cs_id).ok_or(SyscallError::NoCaller)?;
            let slot = cs.insert_root(newcap)?;
            first.get_or_insert(slot);
            made += 1;
        }
        Ok(SyscallReturn::NewCaps {
            cap: first.ok_or(SyscallError::Mm(MmError::ZeroCount))?,
            count: made,
        })
    }

    fn do_cap_grant(
        &mut self,
        caller: ThreadId,
        target_thread: CapId,
        cap: CapId,
        rights: CapabilityRights,
    ) -> Result<SyscallReturn, SyscallError> {
        // The target-thread capability identifies which TCB (and thus
        // which capability space) receives the copy.
        let tcap = self.resolve(
            caller,
            target_thread,
            KernelObjectKind::ThreadControlBlock,
            CapabilityRights::WRITE,
        )?;
        let dst_tid = ThreadId::new(tcap.object.id.as_u32());
        let dst_cs = self.tcb(dst_tid).ok_or(SyscallError::BadCap)?.cap_space;

        // The capability being granted must carry GRANT.
        let _src = self.resolve(caller, cap, self.cap_kind_of(caller, cap)?, CapabilityRights::GRANT)?;

        let src_cs = self.caller_cap_space(caller)?;
        // Derive a narrowed child in the caller's space, then move it out.
        let child = {
            let cs = self.cap_space_mut(src_cs).ok_or(SyscallError::NoCaller)?;
            cs.derive_child(cap, rights, 0)?
        };
        let moved = {
            let cs = self.cap_space_mut(src_cs).ok_or(SyscallError::NoCaller)?;
            cs.take(child)?
        };
        let dst_slot = {
            let cs = self.cap_space_mut(dst_cs).ok_or(SyscallError::BadCap)?;
            cs.insert_root(moved)?
        };
        Ok(SyscallReturn::Granted { dst: dst_slot })
    }

    fn do_map(
        &mut self,
        caller: ThreadId,
        page_table: CapId,
        frame: CapId,
        vaddr: VirtAddr,
        perms: MapPermissions,
    ) -> Result<SyscallReturn, SyscallError> {
        let pt = self.resolve(
            caller,
            page_table,
            KernelObjectKind::PageTable,
            CapabilityRights::WRITE,
        )?;
        // In this MVP model a "frame" is one page of an UntypedMemory
        // object; require rights on it matching the mapping.
        let need = if perms.executable {
            CapabilityRights::READ | CapabilityRights::EXECUTE
        } else if perms.writable {
            CapabilityRights::READ | CapabilityRights::WRITE
        } else {
            CapabilityRights::READ
        };
        let fr = self.resolve(caller, frame, KernelObjectKind::UntypedMemory, need)?;
        let uid = UntypedId::new(fr.object.id.as_u32());
        let frame_phys = self
            .untyped_mut(uid)
            .ok_or(SyscallError::BadCap)?
            .base();

        let as_id = PageTableId::new(pt.object.id.as_u32());
        let space = self.addr_space_mut(as_id).ok_or(SyscallError::BadCap)?;
        space.map(vaddr, frame_phys, PAGE_SIZE, perms)?;
        Ok(SyscallReturn::Mapped)
    }

    fn do_send(
        &mut self,
        caller: ThreadId,
        endpoint: CapId,
        msg: SmallMessage,
        is_call: bool,
        now_ns: u64,
    ) -> Result<SyscallReturn, SyscallError> {
        let ep_cap = self.resolve(
            caller,
            endpoint,
            KernelObjectKind::Endpoint,
            CapabilityRights::WRITE,
        )?;
        let eid = kernel_cap::EndpointId::new(ep_cap.object.id.as_u32());
        let outcome = {
            let ep = self.endpoint_mut(eid).ok_or(SyscallError::BadCap)?;
            ep.try_send(caller, msg, true)?
        };
        match outcome {
            SendOutcome::DeliveredTo(rx) => {
                let delivered = self
                    .endpoint_mut(eid)
                    .and_then(|ep| ep.take_delivered());
                if let Some((rx2, m)) = delivered {
                    if let Some(t) = self.tcb_mut(rx2) {
                        t.pending_msg = Some(m);
                        t.state = ThreadState::Runnable;
                    }
                    self.sched.note_ready(rx2, now_ns)?;
                }
                if is_call {
                    // A Call sender blocks awaiting the reply.
                    if let Some(t) = self.tcb_mut(caller) {
                        t.state = ThreadState::BlockedOnReply;
                    }
                    self.sched.note_blocked(caller)?;
                    let next = self.sched.pick_next(now_ns);
                    return Ok(SyscallReturn::Reschedule { next });
                }
                Ok(SyscallReturn::Delivered { woke: rx })
            }
            SendOutcome::SenderQueued => {
                if let Some(t) = self.tcb_mut(caller) {
                    t.state = ThreadState::BlockedOnSend;
                }
                self.sched.note_blocked(caller)?;
                let next = self.sched.pick_next(now_ns);
                Ok(SyscallReturn::Reschedule { next })
            }
            SendOutcome::WouldBlock => Ok(SyscallReturn::Blocked),
        }
    }

    fn do_recv(
        &mut self,
        caller: ThreadId,
        endpoint: CapId,
        now_ns: u64,
    ) -> Result<SyscallReturn, SyscallError> {
        let ep_cap = self.resolve(
            caller,
            endpoint,
            KernelObjectKind::Endpoint,
            CapabilityRights::READ,
        )?;
        let eid = kernel_cap::EndpointId::new(ep_cap.object.id.as_u32());
        let outcome = {
            let ep = self.endpoint_mut(eid).ok_or(SyscallError::BadCap)?;
            ep.try_recv(caller, true)?
        };
        match outcome {
            RecvOutcome::Received { from, msg } => {
                // The queued sender becomes runnable (unless it was a
                // Call sender — in the full model it stays BlockedOnReply
                // until this receiver replies; MVP wakes it).
                if let Some(t) = self.tcb_mut(from) {
                    if t.state != ThreadState::BlockedOnReply {
                        t.state = ThreadState::Runnable;
                    }
                }
                let _ = self.sched.note_ready(from, now_ns);
                Ok(SyscallReturn::Message { from, msg })
            }
            RecvOutcome::ReceiverQueued => {
                if let Some(t) = self.tcb_mut(caller) {
                    t.state = ThreadState::BlockedOnRecv;
                }
                self.sched.note_blocked(caller)?;
                let next = self.sched.pick_next(now_ns);
                Ok(SyscallReturn::Reschedule { next })
            }
            RecvOutcome::WouldBlock => Ok(SyscallReturn::Blocked),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_core::{BootInfo, BootProtocol};
    use hal_manifest::raw::{
        HardwareManifestRaw, MemoryRegionKindRaw, MemoryRegionRaw, TimerInfoRaw, TimerKindRaw,
    };

    fn kernel() -> KernelState {
        let mut m = HardwareManifestRaw::zeroed();
        m.cpu_core_count = 1;
        m.push_memory_region(MemoryRegionRaw::new(
            0x100_0000,
            32 * 1024 * 1024,
            MemoryRegionKindRaw::Usable,
            false,
        ))
        .unwrap();
        m.timer = TimerInfoRaw::new(TimerKindRaw::Tsc, 1_000_000_000, false);
        let boot = BootInfo::new(
            BootProtocol::Uefi,
            m,
            0x1000,
            (0x10_0000, 0x20_0000),
            (0x20_0000, 0x21_0000),
            0,
        );
        KernelState::from_boot_info(&boot).unwrap()
    }

    #[test]
    fn retype_untyped_into_endpoint_gives_new_cap() {
        let mut k = kernel();
        let caller = k.root_thread;
        // The Root Task's first capability (slot 0) is an UntypedMemory cap.
        let r = k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::Endpoint,
                    count: 1,
                },
            )
            .unwrap();
        match r {
            SyscallReturn::NewCaps { cap, count } => {
                assert_eq!(count, 1);
                // The new endpoint capability resolves and is an Endpoint.
                let c = k.resolve(
                    caller,
                    cap,
                    KernelObjectKind::Endpoint,
                    CapabilityRights::READ,
                );
                assert!(c.is_ok());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn revoke_requires_revoke_right_and_frees_slots() {
        let mut k = kernel();
        let caller = k.root_thread;
        // Make an endpoint, then revoke the untyped it came from — the
        // untyped root cap has full rights (incl. REVOKE).
        k.dispatch(
            caller,
            0,
            SyscallOp::Retype {
                untyped: CapId::new(0),
                target_type: KernelObjectType::Endpoint,
                count: 1,
            },
        )
        .unwrap();
        let r = k
            .dispatch(caller, 0, SyscallOp::CapRevoke { cap: CapId::new(0) })
            .unwrap();
        assert!(matches!(r, SyscallReturn::Revoked { freed } if freed >= 1));
    }

    #[test]
    fn bad_cap_is_rejected() {
        let mut k = kernel();
        let caller = k.root_thread;
        let e = k.dispatch(caller, 0, SyscallOp::CapRevoke { cap: CapId::new(99) });
        assert_eq!(e, Err(SyscallError::BadCap));
    }

    #[test]
    fn yield_reports_reschedule() {
        let mut k = kernel();
        let caller = k.root_thread;
        // Root task must be dispatched first for account() to have work.
        k.sched.dispatch(caller, 0).unwrap();
        let r = k.dispatch(caller, 1_000_000, SyscallOp::Yield).unwrap();
        assert!(matches!(r, SyscallReturn::Reschedule { .. }));
    }
}
