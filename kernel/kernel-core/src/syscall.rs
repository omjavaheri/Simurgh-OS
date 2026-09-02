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
use hal_core::{HalInterface, MapPermissions, PhysAddr, VirtAddr};
use kernel_cap::{
    CapId, CapTableError, Capability, CapabilityRights, KernelObjectKind, MmioRegionId,
    NotificationId, ObjectId, ObjectRef, PageTableId, ThreadId, UntypedId,
};
use kernel_ipc::fastpath::{fast_path_eligible, FastPathDecision};
use kernel_ipc::{EndpointError, IpcError, RecvOutcome, SendOutcome, SharedRegion, SmallMessage};
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
    /// Wakes `to` (which must currently be `BlockedOnReply` — the
    /// caller of a prior `Call`) with `msg` as its reply, and hands the
    /// CPU straight to it. `to` is a raw `ThreadId`, not a capability:
    /// a receiver already learns it as `Recv`'s own `from` field with
    /// no separate grant needed, per the deliberate MVP simplification
    /// this crate's `doc/IMPLEMENTATION-PLAN.md` records ("direct
    /// `ThreadId` reply", not a seL4-style one-shot reply capability —
    /// flagged there as an accepted gap: nothing stops a thread that
    /// merely GUESSES another thread's id from replying to a call it
    /// never received; closing that needs the capability version this
    /// MVP explicitly deferred). The one enforced invariant is `to`'s
    /// `ThreadState` — you cannot "reply" to a thread that both is not
    /// and was never blocked awaiting exactly this.
    Reply {
        /// The `Call`er to wake.
        to: ThreadId,
        /// The reply message.
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
        /// The frame to map: either an `UntypedMemory` capability (one
        /// page of RAM, the original MVP model) or an `MmioRegion`
        /// capability (a device's transport window, 03 §2.1) — resolved
        /// by the capability's actual stored kind, not by a separate
        /// flag.
        frame: CapId,
        /// Virtual address to map at (page-aligned).
        vaddr: VirtAddr,
        /// Mapping permissions.
        perms: MapPermissions,
    },
    /// Signals `notification`, OR-ing `bits` into its sticky signal word
    /// and waking every thread currently blocked in `Wait` on it (02
    /// §5.1). Requires `WRITE`. Always succeeds once the capability
    /// resolves.
    Signal {
        /// A `Notification` capability.
        notification: CapId,
        /// Bits to OR into the signal word (badge/IRQ-line encoded by
        /// the caller — the kernel never interprets them).
        bits: u64,
    },
    /// Consumes and returns the current signal bits if any are pending;
    /// otherwise blocks the caller until the next `Signal` (02 §5.1).
    /// Requires `READ`.
    Wait {
        /// A `Notification` capability.
        notification: CapId,
    },
    /// Consumes and returns the current signal bits without blocking —
    /// `0` if nothing is pending (02 §5.1). Requires `READ`.
    Poll {
        /// A `Notification` capability.
        notification: CapId,
    },
    /// Binds the IRQ line named by the `MmioRegion` capability `mmio` to
    /// `notification`, and installs `handler` with the platform's
    /// `InterruptController` so a real hardware interrupt on that line
    /// signals it (03 §2.1: "صدور Capability محدود به هر درایور: فقط IRQ
    /// همان دستگاه" — holding `mmio` is what authorizes binding exactly
    /// its own IRQ, never an arbitrary line number). Requires `WRITE` on
    /// both `mmio` and `notification`.
    IrqBind {
        /// An `MmioRegion` capability — its own `irq` field is the line
        /// bound, not a separate caller-supplied number.
        mmio: CapId,
        /// A `Notification` capability to signal when the line fires.
        notification: CapId,
        /// The trampoline the platform's `InterruptController` invokes
        /// directly from interrupt context. A plain function pointer
        /// (no captured state, per `hal_core::interrupt::IrqHandler`'s
        /// own doc comment) supplied by the caller (`kernel-arch-glue`),
        /// which is the only layer that knows a concrete trampoline
        /// address — `kernel-core` must not name one itself (that would
        /// invert the crate dependency direction).
        handler: hal_core::interrupt::IrqHandler,
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
    /// `Reply { to, .. }` named a thread that is not (or is no longer)
    /// `BlockedOnReply` — nothing to wake.
    NotBlockedOnReply,
    /// A `Notification` operation failed (currently only `Wait`'s
    /// waiter-list-full case).
    Notify(kernel_ipc::NotificationError),
    /// `IrqBind`'s `hal.register_irq` call was rejected by the platform
    /// `InterruptController` (an out-of-range line, or one already
    /// registered to a different handler).
    IrqRegistrationFailed,
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
impl From<kernel_ipc::NotificationError> for SyscallError {
    fn from(e: kernel_ipc::NotificationError) -> Self {
        SyscallError::Notify(e)
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
    /// scheduler can charge run time without this crate touching the HAL
    /// otherwise. `hal` itself is threaded through only for `Map`'s real
    /// hardware page-table walk (`do_map`) — every other arm ignores it;
    /// this crate still never touches raw physical memory itself (see
    /// `KernelState`'s map-pool fields' doc comment).
    pub fn dispatch(
        &mut self,
        caller: ThreadId,
        now_ns: u64,
        op: SyscallOp,
        hal: &HalInterface,
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
            } => self.do_map(caller, page_table, frame, vaddr, perms, hal),

            SyscallOp::Send { endpoint, msg } => self.do_send(caller, endpoint, msg, false, now_ns),
            SyscallOp::Call { endpoint, msg } => self.do_send(caller, endpoint, msg, true, now_ns),
            SyscallOp::Recv { endpoint } => self.do_recv(caller, endpoint, now_ns),
            SyscallOp::Reply { to, msg } => self.do_reply(caller, to, msg, now_ns),

            SyscallOp::Signal { notification, bits } => {
                self.do_signal(caller, notification, bits, now_ns)
            }
            SyscallOp::Wait { notification } => self.do_wait(caller, notification, now_ns),
            SyscallOp::Poll { notification } => self.do_poll(caller, notification),
            SyscallOp::IrqBind {
                mmio,
                notification,
                handler,
            } => self.do_irq_bind(caller, mmio, notification, handler, hal),
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
                KernelObjectType::SharedRegion => {
                    // MVP: full RW is always the widest a fresh region
                    // permits — `Retype` carries no rights argument (same
                    // "no size/rights argument yet" gap `Untyped`'s own
                    // arm above already notes); a peer can still be
                    // GRANTed a narrower derived capability later via the
                    // ordinary `CapGrant` rights-narrowing path.
                    let region = SharedRegion::new(PhysAddr::new(obj_phys as usize), per as usize, CapabilityRights::RW);
                    let id = self
                        .alloc_shared_region(region)
                        .ok_or(SyscallError::ObjectTableFull)?;
                    (KernelObjectKind::SharedRegion, id.as_u32())
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

    /// `Map` (02-Microkernel-Layer.md §6): resolve the `page_table` /
    /// `frame` capabilities (rights-checked — the caller must hold
    /// `WRITE` on the page table and `READ`/`WRITE`/`EXECUTE` on the
    /// frame matching `perms`), record the mapping in the software
    /// `AddressSpace` model, then — if this architecture has a working
    /// `map_range` (`install_map_pool` was called at boot) — walk it into
    /// REAL hardware page-table entries too, rolling the software model
    /// back if that hardware walk fails so the two never drift (see
    /// `kernel_mm::address_space`'s module doc and `MmError::
    /// HardwareMapFailed`).
    fn do_map(
        &mut self,
        caller: ThreadId,
        page_table: CapId,
        frame: CapId,
        vaddr: VirtAddr,
        perms: MapPermissions,
        hal: &HalInterface,
    ) -> Result<SyscallReturn, SyscallError> {
        let pt = self.resolve(
            caller,
            page_table,
            KernelObjectKind::PageTable,
            CapabilityRights::WRITE,
        )?;
        // In this MVP model a "frame" is either one page of an
        // UntypedMemory object (RAM) or an entire MmioRegion (a device's
        // transport window, 03 §2.1) — resolved by the capability's own
        // stored kind rather than a separate flag; both currently map as
        // exactly one PAGE_SIZE region (every MmioRegion this kernel
        // mints today — virtio-mmio on riscv64 — is itself exactly one
        // page; a multi-page window would need a real generalization
        // here, not needed by any MVP driver yet). Require rights on it
        // matching the mapping.
        let need = if perms.executable {
            CapabilityRights::READ | CapabilityRights::EXECUTE
        } else if perms.writable {
            CapabilityRights::READ | CapabilityRights::WRITE
        } else {
            CapabilityRights::READ
        };
        let cs_id = self.tcb(caller).ok_or(SyscallError::NoCaller)?.cap_space;
        let fr = {
            let cs = self.cap_space(cs_id).ok_or(SyscallError::NoCaller)?;
            *cs.lookup(frame).ok_or(SyscallError::BadCap)?
        };
        if !fr.allows(need) {
            return Err(SyscallError::InsufficientRights);
        }
        let frame_phys = match fr.object.kind {
            KernelObjectKind::UntypedMemory => {
                let uid = UntypedId::new(fr.object.id.as_u32());
                self.untyped_mut(uid).ok_or(SyscallError::BadCap)?.base()
            }
            KernelObjectKind::MmioRegion => {
                let mid = MmioRegionId::new(fr.object.id.as_u32());
                PhysAddr::new(self.mmio_region(mid).ok_or(SyscallError::BadCap)?.phys_base as usize)
            }
            _ => return Err(SyscallError::WrongObjectKind),
        };

        let as_id = PageTableId::new(pt.object.id.as_u32());
        let root_phys = {
            let space = self.addr_space_mut(as_id).ok_or(SyscallError::BadCap)?;
            space.map(vaddr, frame_phys, PAGE_SIZE, perms)?;
            space.root_phys().as_usize()
        };

        if self.map_pool_base() != 0 {
            // R=1 | W=2 | X=4 | U=8 (`hal_core::CpuAbstraction::map_range`'s
            // portable bitfield). U is set unconditionally: `Map` is
            // always a user-space-facing syscall in this MVP — there is
            // no kernel-only variant of it.
            let perm_bits = (perms.readable as usize)
                | ((perms.writable as usize) << 1)
                | ((perms.executable as usize) << 2)
                | (1 << 3);
            let (pool_base, pool_len) = self.map_pool_remaining();
            let consumed = hal.map_range(
                root_phys,
                vaddr.as_usize(),
                frame_phys.as_usize(),
                PAGE_SIZE,
                perm_bits,
                pool_base,
                pool_len,
            );
            if consumed == u32::MAX {
                // Roll back: the hardware never saw this mapping, so the
                // software model must not claim it either.
                if let Some(space) = self.addr_space_mut(as_id) {
                    let _ = space.unmap(vaddr);
                }
                return Err(SyscallError::Mm(MmError::HardwareMapFailed));
            }
            self.map_pool_advance(consumed);
            hal.flush_tlb();
        }

        Ok(SyscallReturn::Mapped)
    }

    /// `SyscallOp::Signal`.
    fn do_signal(
        &mut self,
        caller: ThreadId,
        notification: CapId,
        bits: u64,
        now_ns: u64,
    ) -> Result<SyscallReturn, SyscallError> {
        let cap = self.resolve(
            caller,
            notification,
            KernelObjectKind::Notification,
            CapabilityRights::WRITE,
        )?;
        let nid = NotificationId::new(cap.object.id.as_u32());
        let woken = self
            .notification_mut(nid)
            .ok_or(SyscallError::BadCap)?
            .signal(bits);
        for &tid in woken.as_slice() {
            self.wake_blocked(tid, now_ns);
        }
        Ok(SyscallReturn::Done)
    }

    /// `SyscallOp::Wait` — consumes and returns pending bits immediately
    /// if any are set; otherwise blocks the caller (`Notification::wait`'s
    /// own contract: only call it when `poll` would return `0`).
    fn do_wait(
        &mut self,
        caller: ThreadId,
        notification: CapId,
        now_ns: u64,
    ) -> Result<SyscallReturn, SyscallError> {
        let cap = self.resolve(
            caller,
            notification,
            KernelObjectKind::Notification,
            CapabilityRights::READ,
        )?;
        let nid = NotificationId::new(cap.object.id.as_u32());
        let notif = self.notification_mut(nid).ok_or(SyscallError::BadCap)?;
        let bits = notif.poll();
        if bits != 0 {
            return Ok(SyscallReturn::Value(bits));
        }
        notif.wait(caller)?;
        // The caller is now on the notification's own waiter list, but
        // that alone does not remove it from the SCHEDULER's own Ready
        // pool — without this, `pick_next` could re-pick a thread that
        // is not actually resumable (the same "phantom Ready" bug class
        // `preempt.rs::block_thread`'s own doc comment already
        // documents for the IPC-block case; `Signal`'s own `wake_blocked`
        // call is `note_blocked`'s exact counterpart, undoing this).
        self.sched.account(now_ns);
        let _ = self.sched.note_blocked(caller);
        Ok(SyscallReturn::Blocked)
    }

    /// `SyscallOp::Poll` — never blocks.
    fn do_poll(
        &mut self,
        caller: ThreadId,
        notification: CapId,
    ) -> Result<SyscallReturn, SyscallError> {
        let cap = self.resolve(
            caller,
            notification,
            KernelObjectKind::Notification,
            CapabilityRights::READ,
        )?;
        let nid = NotificationId::new(cap.object.id.as_u32());
        let bits = self.notification_mut(nid).ok_or(SyscallError::BadCap)?.poll();
        Ok(SyscallReturn::Value(bits))
    }

    /// `SyscallOp::IrqBind`.
    fn do_irq_bind(
        &mut self,
        caller: ThreadId,
        mmio: CapId,
        notification: CapId,
        handler: hal_core::interrupt::IrqHandler,
        hal: &HalInterface,
    ) -> Result<SyscallReturn, SyscallError> {
        let mmio_cap = self.resolve(caller, mmio, KernelObjectKind::MmioRegion, CapabilityRights::WRITE)?;
        let mid = MmioRegionId::new(mmio_cap.object.id.as_u32());
        let irq = self.mmio_region(mid).ok_or(SyscallError::BadCap)?.irq;

        let notif_cap = self.resolve(
            caller,
            notification,
            KernelObjectKind::Notification,
            CapabilityRights::WRITE,
        )?;
        let nid = NotificationId::new(notif_cap.object.id.as_u32());

        if !self.bind_irq(irq, nid) {
            return Err(SyscallError::ObjectTableFull);
        }
        if !hal.register_irq(irq, handler) {
            return Err(SyscallError::IrqRegistrationFailed);
        }
        Ok(SyscallReturn::Done)
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

        // L4-style IPC fast path (02-Microkernel-Layer.md §5.3/§8.3):
        // predict, via the tested pure predicate in `kernel_ipc::
        // fastpath`, whether this call is about to synchronously
        // rendezvous with an ALREADY-blocked receiver — `try_send` below
        // independently re-derives the identical condition a moment
        // later via `SendOutcome::DeliveredTo`. Only `is_call` can ever
        // take the fast branch: a plain `Send`'s own `DeliveredTo` case
        // (below) already returns immediately without touching the
        // scheduler's `pick_next` at all, so there is nothing to skip.
        let fast_path = is_call
            && matches!(
                self.endpoint_mut(eid)
                    .map(|ep| fast_path_eligible(ep, &msg, is_call)),
                Some(FastPathDecision::Take { .. })
            );

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
                        // `rx2` was already blocked in `Recv` (that is
                        // exactly why delivery was synchronous) and is
                        // about to be switched straight back in, not
                        // returned to via `Recv`'s own synchronous
                        // `Message { from, .. }` — record `caller` so a
                        // later `Reply { to: caller, .. }` is possible
                        // (see `Tcb::pending_from`'s own doc comment).
                        t.pending_from = Some(caller);
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
                    let next = if fast_path {
                        // FAST PATH: `rx` is a confirmed, already-blocked
                        // receiver taking THIS message right now — hand
                        // the CPU to it directly instead of re-deriving
                        // the same answer via `pick_next`'s O(n) scan
                        // over every `Ready` thread. This is the SAME
                        // "direct named-thread handoff, not general
                        // fairness" pattern this crate's own `preempt`
                        // module already establishes for the fault-
                        // isolation demo (`terminate_thread_and_handoff`/
                        // `yield_to_thread`) — not a correctness
                        // compromise: an IPC rendezvous transfers control
                        // to the specific party being communicated with
                        // BY DEFINITION, in every L4-family kernel (the
                        // fast path is never subject to the general
                        // scheduler's fairness in the first place).
                        Some(rx)
                    } else {
                        self.sched.pick_next(now_ns)
                    };
                    return Ok(SyscallReturn::Reschedule { next });
                }
                Ok(SyscallReturn::Delivered { woke: rx })
            }
            SendOutcome::SenderQueued => {
                // **Real bug found via QEMU** (Session 22's own Netstack
                // work — the FIRST caller in this codebase to ever issue
                // TWO real `Call`s to the same `Endpoint` back-to-back,
                // in a tight retry loop, with no guarantee the receiver
                // has already looped back to its own `Recv` between
                // them): this arm set `BlockedOnSend` UNCONDITIONALLY,
                // ignoring `is_call` — correct for a plain `Send`, but
                // wrong for a `Call` whose message could not be
                // delivered synchronously (the receiver was not yet
                // blocked in `Recv`). `DeliveredTo`'s own fast-path arm
                // above already gets this right (`if is_call { ...
                // BlockedOnReply ... }`); this arm needs the identical
                // check for the QUEUED case. Left as `BlockedOnSend`,
                // `do_recv`'s own later pickup of this queued message
                // (`RecvOutcome::Received`'s own "unless it was a Call
                // sender" check) misreads a genuine `Call` as an
                // ordinary `Send`, marking the caller `Runnable`
                // WITHOUT ever calling `note_ready` on it (invisible to
                // `pick_next` forever) — and the eventual real `Reply`
                // then fails its own `state == BlockedOnReply`
                // precondition (`do_reply`'s own doc comment), silently
                // dropping the reply. Net effect: the caller never
                // resumes — a genuine, deterministic, 100%-reproducible
                // hang (not a QEMU-timing flake) the instant a `Call`'s
                // own message is queued instead of delivered
                // synchronously, confirmed via QEMU: a real Netstack
                // process's SECOND `IPC_CALL` (the first `PollFrame`
                // retry, immediately following a `SendFrame` reply)
                // hung forever, every single attempt.
                if let Some(t) = self.tcb_mut(caller) {
                    t.state = if is_call { ThreadState::BlockedOnReply } else { ThreadState::BlockedOnSend };
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

    /// `Reply { to, msg }` — see `SyscallOp::Reply`'s own doc comment
    /// for the accepted MVP simplification (raw `ThreadId`, no reply
    /// capability) this implements. Always a direct, unconditional
    /// handoff: unlike `Call`'s fast path (which only sometimes finds
    /// an already-blocked receiver), `Reply` NAMES its target — there
    /// is never a "no receiver, fall back to the general path" case, so
    /// this always skips `pick_next` and switches straight to `to`.
    fn do_reply(
        &mut self,
        caller: ThreadId,
        to: ThreadId,
        msg: SmallMessage,
        now_ns: u64,
    ) -> Result<SyscallReturn, SyscallError> {
        if caller == to {
            return Err(SyscallError::NotBlockedOnReply);
        }
        let target_ok = self
            .tcb(to)
            .map(|t| t.state == ThreadState::BlockedOnReply)
            .unwrap_or(false);
        if !target_ok {
            return Err(SyscallError::NotBlockedOnReply);
        }
        if let Some(t) = self.tcb_mut(to) {
            t.pending_msg = Some(msg);
            t.state = ThreadState::Runnable;
        }
        self.sched.note_ready(to, now_ns)?;
        // The replier itself is not blocking, so it must become `Ready`
        // too, not stay whatever `Scheduler::dispatch` last set it to —
        // `dispatch` only ever updates the INCOMING thread's own state,
        // never the outgoing one's (see its own doc comment), so
        // without this a direct-switch consumer's replier is left
        // (incorrectly) `Running` forever, invisible to a LATER
        // `pick_next` even though it is genuinely schedulable again.
        // **Real bug found via QEMU** (this session's real U-mode Call/
        // Recv/Reply demo — see `kernel_arch_glue::p2_ipc_demo_start`'s
        // own "Real bug found via QEMU" doc comment for the sibling bug
        // that surfaced it): an earlier version of this comment claimed
        // "the caller of `dispatch` always re-readies the outgoing
        // thread" — true for `kernel-core::run::yield_to` (the in-kernel
        // demo's own consumer, which DOES re-ready its outgoing thread),
        // but NOT for a direct `TrapOutcome::SwitchTo` consumer (a real
        // U-mode trap boundary), which has no such step at all. Calling
        // `note_ready` here, unconditionally, fixes it at the source for
        // EVERY consumer rather than requiring each one to remember to —
        // idempotent for `yield_to`'s own redundant call (harmless: it
        // would just re-set the same state/timestamp again).
        self.sched.note_ready(caller, now_ns)?;
        Ok(SyscallReturn::Reschedule { next: Some(to) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_core::cpu::{CpuAbstraction, CpuContext, CpuFeatureFlags, PrivilegeLevel};
    use hal_core::timer::{TimerAbstraction, TimerCallback, TimerMode};
    use hal_core::{BootInfo, BootProtocol, HalError, HAL_CONTEXT_BYTES};
    use hal_manifest::raw::{
        HardwareManifestRaw, MemoryRegionKindRaw, MemoryRegionRaw, TimerInfoRaw, TimerKindRaw,
    };

    // Minimal mock `HalInterface` for `dispatch`'s new `hal` parameter.
    // `map_range`/`flush_tlb` are left at their default (no-op /
    // `u32::MAX`-returning) trait implementations: no test here installs
    // a map pool, so `do_map`'s hardware path is never exercised —
    // exactly the "no pool on this architecture" MVP fallback these
    // tests stand in for.
    struct MockCpu;
    impl CpuAbstraction<HAL_CONTEXT_BYTES> for MockCpu {
        fn core_count(&self) -> usize {
            1
        }
        fn current_core_id(&self) -> usize {
            0
        }
        fn feature_flags(&self) -> CpuFeatureFlags {
            CpuFeatureFlags::empty()
        }
        unsafe fn context_switch(
            &self,
            _from: &mut CpuContext<HAL_CONTEXT_BYTES>,
            _to: &CpuContext<HAL_CONTEXT_BYTES>,
        ) {
        }
        fn set_privilege_level(&self, _level: PrivilegeLevel) -> Result<(), HalError> {
            Ok(())
        }
        fn bootstrap_current_core(&self) -> Result<(), HalError> {
            Ok(())
        }
    }

    struct MockTimer;
    impl TimerAbstraction for MockTimer {
        fn now_ns(&self) -> u64 {
            0
        }
        fn set_oneshot(&self, _deadline_ns: u64, _mode: TimerMode) -> Result<(), HalError> {
            Ok(())
        }
        fn cancel_oneshot(&self) {}
        fn set_tickless(&self, _enabled: bool) -> Result<(), HalError> {
            Ok(())
        }
        fn set_timer_callback(&self, _callback: TimerCallback) {}
        fn supports_tickless(&self) -> bool {
            false
        }
        fn frequency_hz(&self) -> u64 {
            1_000_000_000
        }
    }

    /// Always-succeeds `InterruptController` double: no test in this
    /// module exercises real IRQ delivery hardware, only `IrqBind`'s
    /// kernel-side bookkeeping (binding table + the `register_irq` call
    /// itself succeeding).
    struct MockInterrupt;
    impl hal_core::interrupt::InterruptController for MockInterrupt {
        fn register_irq(
            &self,
            _irq: hal_core::interrupt::IrqId,
            _handler: hal_core::interrupt::IrqHandler,
        ) -> Result<(), HalError> {
            Ok(())
        }
        fn unregister_irq(&self, _irq: hal_core::interrupt::IrqId) {}
        fn mask_irq(&self, _irq: hal_core::interrupt::IrqId) -> Result<(), HalError> {
            Ok(())
        }
        fn unmask_irq(&self, _irq: hal_core::interrupt::IrqId) -> Result<(), HalError> {
            Ok(())
        }
        fn send_ipi(&self, _target_core: usize, _vector: u8) -> Result<(), HalError> {
            Ok(())
        }
        fn irq_line_count(&self) -> u32 {
            64
        }
        fn ipi_target_core_count(&self) -> u32 {
            1
        }
        fn end_of_interrupt(&self, _irq: hal_core::interrupt::IrqId) {}
    }

    // `build_interface`'s `cpu`/`timer`/`interrupt` refs must outlive the
    // `HalInterface` it returns, so this returns owned values for each
    // test to bind as locals before building its own `hal` — kernel-core
    // is `#![no_std]` with no `alloc`, so no `Box::leak` shortcut (same
    // pattern `run.rs`'s tests already use).
    fn mock_hal_pair() -> (MockCpu, MockTimer, MockInterrupt) {
        (MockCpu, MockTimer, MockInterrupt)
    }

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
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);
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
                &hal,
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
    fn retype_untyped_into_shared_region_gives_new_cap() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);
        let r = k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::SharedRegion,
                    count: 1,
                },
                &hal,
            )
            .unwrap();
        match r {
            SyscallReturn::NewCaps { cap, count } => {
                assert_eq!(count, 1);
                let c = k
                    .resolve(caller, cap, KernelObjectKind::SharedRegion, CapabilityRights::READ)
                    .unwrap();
                let region = k
                    .shared_region(kernel_cap::SharedRegionId::new(c.object.id.as_u32()))
                    .unwrap();
                assert_eq!(region.size, PAGE_SIZE);
                assert!(region.max_rights.contains(CapabilityRights::RW));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Like `kernel()`, but the manifest also reports one `Block`-kind
    /// peripheral device, so `populate_from_boot_info`'s Step 3c seeds
    /// `root_mmio_blk_cap` — the boot-time-only path an `MmioRegion`
    /// capability can come from (never `Retype`, see
    /// `MmioRegionDescriptor`'s own doc comment).
    fn kernel_with_mmio_blk() -> KernelState {
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
        let _ = m.push_peripheral_device(hal_manifest::raw::PeripheralDeviceRaw::new(
            hal_manifest::raw::PeripheralKindRaw::Block,
            0x1000_1000,
            0x1000,
            7,
        ));
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
    fn boot_seeds_mmio_region_cap_for_the_discovered_block_device() {
        let k = kernel_with_mmio_blk();
        assert_ne!(k.root_mmio_blk_cap, CapId::new(u32::MAX));
        let c = k
            .resolve(
                k.root_thread,
                k.root_mmio_blk_cap,
                KernelObjectKind::MmioRegion,
                CapabilityRights::READ,
            )
            .unwrap();
        let region = k
            .mmio_region(kernel_cap::MmioRegionId::new(c.object.id.as_u32()))
            .unwrap();
        assert_eq!(region.phys_base, 0x1000_1000);
        assert_eq!(region.size, 0x1000);
        assert_eq!(region.irq, 7);
    }

    /// Same shape as `kernel_with_mmio_blk`, `Network`-kind instead —
    /// `populate_from_boot_info`'s Step 3d.
    fn kernel_with_mmio_net() -> KernelState {
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
        let _ = m.push_peripheral_device(hal_manifest::raw::PeripheralDeviceRaw::new(
            hal_manifest::raw::PeripheralKindRaw::Network,
            0x1000_2000,
            0x1000,
            8,
        ));
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
    fn boot_seeds_mmio_region_cap_for_the_discovered_network_device() {
        let k = kernel_with_mmio_net();
        assert_ne!(k.root_mmio_net_cap, CapId::new(u32::MAX));
        let c = k
            .resolve(
                k.root_thread,
                k.root_mmio_net_cap,
                KernelObjectKind::MmioRegion,
                CapabilityRights::READ,
            )
            .unwrap();
        let region = k
            .mmio_region(kernel_cap::MmioRegionId::new(c.object.id.as_u32()))
            .unwrap();
        assert_eq!(region.phys_base, 0x1000_2000);
        assert_eq!(region.size, 0x1000);
        assert_eq!(region.irq, 8);
    }

    #[test]
    fn map_accepts_an_mmio_region_frame() {
        let mut k = kernel_with_mmio_blk();
        let caller = k.root_thread;
        let mmio_cap = k.root_mmio_blk_cap;
        let pt_cap = k.root_page_table_cap;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);
        let r = k.dispatch(
            caller,
            0,
            SyscallOp::Map {
                page_table: pt_cap,
                frame: mmio_cap,
                vaddr: VirtAddr::new(0x9000_0000),
                perms: MapPermissions {
                    readable: true,
                    writable: true,
                    executable: false,
                    device_uncached: true,
                },
            },
            &hal,
        );
        assert_eq!(r, Ok(SyscallReturn::Mapped));
    }

    #[test]
    fn signal_wakes_a_waiting_thread() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);
        let notif_cap = match k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::Notification,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };

        // Nothing pending yet: Wait blocks the caller.
        let r = k.dispatch(caller, 0, SyscallOp::Wait { notification: notif_cap }, &hal);
        assert_eq!(r, Ok(SyscallReturn::Blocked));

        // Signal wakes it: `wake_blocked` marks `caller` Ready again.
        let r = k.dispatch(
            caller,
            0,
            SyscallOp::Signal { notification: notif_cap, bits: 0b101 },
            &hal,
        );
        assert_eq!(r, Ok(SyscallReturn::Done));
        assert_eq!(
            k.sched.entity(caller).unwrap().state,
            kernel_sched::RunState::Ready
        );

        // Now Poll/Wait see the (sticky) bits without blocking, and
        // consume them.
        let r = k.dispatch(caller, 0, SyscallOp::Poll { notification: notif_cap }, &hal);
        assert_eq!(r, Ok(SyscallReturn::Value(0b101)));
        let r = k.dispatch(caller, 0, SyscallOp::Poll { notification: notif_cap }, &hal);
        assert_eq!(r, Ok(SyscallReturn::Value(0)));
    }

    #[test]
    fn irq_bind_requires_mmio_and_notification_caps_and_registers_with_hal() {
        let mut k = kernel_with_mmio_blk();
        let caller = k.root_thread;
        let mmio_cap = k.root_mmio_blk_cap;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);
        let notif_cap = match k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::Notification,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };

        let r = k.dispatch(
            caller,
            0,
            SyscallOp::IrqBind {
                mmio: mmio_cap,
                notification: notif_cap,
                handler: dummy_irq_handler,
            },
            &hal,
        );
        assert_eq!(r, Ok(SyscallReturn::Done));
        assert_eq!(k.notification_for_irq(7), Some(kernel_cap::NotificationId::new(
            k.resolve(caller, notif_cap, KernelObjectKind::Notification, CapabilityRights::READ)
                .unwrap()
                .object
                .id
                .as_u32(),
        )));

        // Wrong-kind caps are rejected: naming the notification cap as
        // `mmio` (or vice versa) must not silently succeed.
        let r = k.dispatch(
            caller,
            0,
            SyscallOp::IrqBind {
                mmio: notif_cap,
                notification: notif_cap,
                handler: dummy_irq_handler,
            },
            &hal,
        );
        assert_eq!(r, Err(SyscallError::WrongObjectKind));
    }

    fn dummy_irq_handler(_irq: hal_core::interrupt::IrqId) {}

    #[test]
    fn revoke_requires_revoke_right_and_frees_slots() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);
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
            &hal,
        )
        .unwrap();
        let r = k
            .dispatch(caller, 0, SyscallOp::CapRevoke { cap: CapId::new(0) }, &hal)
            .unwrap();
        assert!(matches!(r, SyscallReturn::Revoked { freed } if freed >= 1));
    }

    #[test]
    fn bad_cap_is_rejected() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);
        let e = k.dispatch(caller, 0, SyscallOp::CapRevoke { cap: CapId::new(99) }, &hal);
        assert_eq!(e, Err(SyscallError::BadCap));
    }

    #[test]
    fn yield_reports_reschedule() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);
        // Root task must be dispatched first for account() to have work.
        k.sched.dispatch(caller, 0).unwrap();
        let r = k.dispatch(caller, 1_000_000, SyscallOp::Yield, &hal).unwrap();
        assert!(matches!(r, SyscallReturn::Reschedule { .. }));
    }

    #[test]
    fn map_installs_hardware_ptes_when_a_pool_is_present() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);

        // Retype a PageTable and a frame from the Root Task's first untyped.
        let pt_cap = match k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::PageTable,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };
        let frame_cap = match k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::Untyped,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };

        // No pool installed yet: `Map` succeeds, software-model-only
        // (`MockCpu`'s default `map_range` is never even consulted since
        // `do_map` skips the hardware path entirely when `map_pool_base`
        // is `0`).
        let r = k.dispatch(
            caller,
            0,
            SyscallOp::Map {
                page_table: pt_cap,
                frame: frame_cap,
                vaddr: VirtAddr::new(0x4000_0000),
                perms: MapPermissions::KERNEL_DATA,
            },
            &hal,
        );
        assert_eq!(r, Ok(SyscallReturn::Mapped));

        // With a pool installed, `MockCpu`'s DEFAULT `map_range` (which
        // returns `u32::MAX`, i.e. "unsupported") makes the hardware walk
        // fail — `do_map` must roll the software model back rather than
        // leave it claiming a mapping the hardware never saw.
        k.install_map_pool(0x1000, 8);
        let r2 = k.dispatch(
            caller,
            0,
            SyscallOp::Map {
                page_table: pt_cap,
                frame: frame_cap,
                vaddr: VirtAddr::new(0x5000_0000),
                perms: MapPermissions::KERNEL_DATA,
            },
            &hal,
        );
        assert_eq!(r2, Err(SyscallError::Mm(MmError::HardwareMapFailed)));
        // Rolled back: this VA must NOT resolve in the software model.
        let as_id = kernel_cap::PageTableId::new(
            k.cap_space(k.root_cap_space)
                .and_then(|t| t.lookup(pt_cap))
                .map(|c| c.object.id.as_u32())
                .unwrap(),
        );
        assert!(k
            .addr_space_mut(as_id)
            .unwrap()
            .translate(VirtAddr::new(0x5000_0000))
            .is_none());
    }

    /// The L4-style fast path (02-Microkernel-Layer.md §5.3/§8.3): a
    /// `Call` that rendezvouses with an already-blocked receiver must
    /// hand the CPU DIRECTLY to that receiver, bypassing `pick_next`'s
    /// fairness scan entirely — proven here by making `pick_next` WANT
    /// to pick a different (`decoy`) thread and confirming the actual
    /// `Reschedule { next }` names the receiver instead.
    #[test]
    fn call_fast_path_hands_off_directly_bypassing_pick_next() {
        use kernel_sched::{SchedulerMode, MAX_PRIORITY};

        let mut k = kernel();
        let root = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);

        let ep_cap = match k
            .dispatch(
                root,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::Endpoint,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };

        // `rx` blocks in Recv first, becoming the endpoint's queued
        // receiver — the precondition `fast_path_eligible` checks for.
        let rx = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        k.sched
            .admit(rx, SchedulerMode::Interactive, MAX_PRIORITY, None)
            .unwrap();
        let r = k
            .dispatch(rx, 0, SyscallOp::Recv { endpoint: ep_cap }, &hal)
            .unwrap();
        assert!(matches!(r, SyscallReturn::Reschedule { .. }));
        assert_eq!(k.tcb(rx).unwrap().state, ThreadState::BlockedOnRecv);

        // `decoy` is Ready — `pick_next`, consulted with `root` about to
        // block, would return `decoy` (the only OTHER Ready thread; `rx`
        // itself is `BlockedOnRecv`, never `Ready`, so `pick_next` could
        // never legitimately return it at all).
        let decoy = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        k.sched
            .admit(decoy, SchedulerMode::Interactive, MAX_PRIORITY, None)
            .unwrap();
        k.sched.note_ready(decoy, 0).unwrap();

        // `root` calls — synchronously rendezvouses with `rx`. The fast
        // path must switch straight to `rx`: NOT `decoy` (what a
        // `pick_next`-driven slow path would pick instead), and NOT
        // anything `pick_next` could have produced at all, since `rx`
        // is `BlockedOnRecv` rather than `Ready`.
        let msg = SmallMessage::from_words(0xCAFE, &[7]).unwrap();
        let r = k
            .dispatch(root, 0, SyscallOp::Call { endpoint: ep_cap, msg }, &hal)
            .unwrap();
        assert_eq!(r, SyscallReturn::Reschedule { next: Some(rx) });
        // `decoy` was never dispatched by the fast path — still `Ready`
        // in the scheduler, not `Running`.
        assert_ne!(k.sched.running(), Some(decoy));

        assert_eq!(k.tcb(root).unwrap().state, ThreadState::BlockedOnReply);
        let delivered = k.tcb(rx).unwrap().pending_msg.expect("message delivered to rx");
        assert_eq!(delivered.label, 0xCAFE);
    }

    /// A plain (non-`Call`) `Send` that rendezvouses immediately never
    /// touches the scheduler at all — there is nothing for the fast
    /// path to skip, and the caller keeps running (no `Reschedule`).
    #[test]
    fn plain_send_does_not_take_the_call_fast_path() {
        use kernel_sched::{SchedulerMode, MAX_PRIORITY};

        let mut k = kernel();
        let root = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);

        let ep_cap = match k
            .dispatch(
                root,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::Endpoint,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };

        let rx = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        k.sched
            .admit(rx, SchedulerMode::Interactive, MAX_PRIORITY, None)
            .unwrap();
        k.dispatch(rx, 0, SyscallOp::Recv { endpoint: ep_cap }, &hal)
            .unwrap();

        let msg = SmallMessage::new(0xF00D);
        let r = k
            .dispatch(root, 0, SyscallOp::Send { endpoint: ep_cap, msg }, &hal)
            .unwrap();
        assert_eq!(r, SyscallReturn::Delivered { woke: rx });
    }

    /// The full round trip `Call` was missing until this session: a
    /// `Call`er blocks (`BlockedOnReply`); the receiver later `Reply`s
    /// directly to it (by the `ThreadId` it already learned from its
    /// own `Recv`); the caller wakes with the reply message. Also
    /// confirms `Reply` is itself an unconditional direct handoff (no
    /// `decoy` needed here — `Reply` never has a `pick_next` fallback
    /// case at all, unlike `Call`'s fast path).
    #[test]
    fn call_then_reply_completes_the_round_trip() {
        use kernel_sched::{SchedulerMode, MAX_PRIORITY};

        let mut k = kernel();
        let root = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);

        let ep_cap = match k
            .dispatch(
                root,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::Endpoint,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };

        // `server` blocks in Recv first.
        let server = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        k.sched
            .admit(server, SchedulerMode::Interactive, MAX_PRIORITY, None)
            .unwrap();
        k.dispatch(server, 0, SyscallOp::Recv { endpoint: ep_cap }, &hal)
            .unwrap();

        // `root` Calls — rendezvouses immediately (the fast path from
        // the previous test), becomes `BlockedOnReply`.
        let request = SmallMessage::from_words(0x1, &[10]).unwrap();
        let r = k
            .dispatch(root, 0, SyscallOp::Call { endpoint: ep_cap, msg: request }, &hal)
            .unwrap();
        assert_eq!(r, SyscallReturn::Reschedule { next: Some(server) });
        assert_eq!(k.tcb(root).unwrap().state, ThreadState::BlockedOnReply);

        // `server` "processes" the request (it already has it via its
        // own `Recv`'s `pending_msg`) and replies directly to `root`.
        let reply_msg = SmallMessage::from_words(0x2, &[20]).unwrap();
        let r = k
            .dispatch(server, 0, SyscallOp::Reply { to: root, msg: reply_msg }, &hal)
            .unwrap();
        assert_eq!(r, SyscallReturn::Reschedule { next: Some(root) });

        // `root` is runnable again with the reply message waiting.
        assert_eq!(k.tcb(root).unwrap().state, ThreadState::Runnable);
        let delivered = k.tcb(root).unwrap().pending_msg.expect("reply delivered to root");
        assert_eq!(delivered.label, 0x2);
        assert_eq!(delivered.words(), &[20]);
    }

    /// A `Call` whose receiver is NOT yet blocked in `Recv` (the message
    /// gets QUEUED, `SendOutcome::SenderQueued` — the opposite of `call_
    /// then_reply_completes_the_round_trip`'s own fast-path case above)
    /// must STILL be correctly replied to once the receiver eventually
    /// calls `Recv` and picks it up. **Real bug found via QEMU**
    /// (Session 22's own Netstack work — the first real caller in this
    /// codebase to ever issue a `Call` that could race ahead of its
    /// receiver's own `Recv`): `do_send`'s `SenderQueued` arm set
    /// `BlockedOnSend` unconditionally, ignoring `is_call` — so a queued
    /// `Call`'s own caller was indistinguishable from a queued plain
    /// `Send`'s. `do_recv`'s later pickup then (correctly, given that
    /// wrong state) treated it as an ordinary `Send` and marked it
    /// `Runnable` WITHOUT ever calling `note_ready` (invisible to `pick_
    /// next` from then on), and the eventual real `Reply` failed its own
    /// `state == BlockedOnReply` precondition — the caller never resumed
    /// (a deterministic hang, reproduced via a real Netstack process's
    /// second `IPC_CALL` to `driver-virtio-net` hanging every single
    /// time). This test pins the fix: `SenderQueued` now sets
    /// `BlockedOnReply` for a queued `Call`, exactly like the fast-path
    /// `DeliveredTo` arm already does.
    #[test]
    fn call_queued_before_receiver_blocks_still_completes_the_round_trip() {
        use kernel_sched::{SchedulerMode, MAX_PRIORITY};

        let mut k = kernel();
        let root = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);

        let ep_cap = match k
            .dispatch(
                root,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::Endpoint,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };

        let server = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        k.sched
            .admit(server, SchedulerMode::Interactive, MAX_PRIORITY, None)
            .unwrap();

        // `root` Calls BEFORE `server` ever blocks in `Recv` — no
        // receiver waiting yet, so the message is QUEUED
        // (`SendOutcome::SenderQueued`), not delivered via the fast
        // path. `root` must still end up `BlockedOnReply`, not
        // `BlockedOnSend`.
        let request = SmallMessage::from_words(0x1, &[10]).unwrap();
        let r = k.dispatch(root, 0, SyscallOp::Call { endpoint: ep_cap, msg: request }, &hal).unwrap();
        assert!(matches!(r, SyscallReturn::Reschedule { .. }));
        assert_eq!(k.tcb(root).unwrap().state, ThreadState::BlockedOnReply);

        // `server` NOW blocks in `Recv` — picks up the already-queued
        // message immediately (`RecvOutcome::Received`), synchronously.
        let r = k.dispatch(server, 0, SyscallOp::Recv { endpoint: ep_cap }, &hal).unwrap();
        match r {
            SyscallReturn::Message { from, msg } => {
                assert_eq!(from, root);
                assert_eq!(msg.label, 0x1);
            }
            other => panic!("unexpected {other:?}"),
        }
        // `root` must still be `BlockedOnReply` (not incorrectly flipped
        // to `Runnable` by `do_recv`'s own "unless it was a Call sender"
        // check) — this is the exact condition `do_reply` requires next.
        assert_eq!(k.tcb(root).unwrap().state, ThreadState::BlockedOnReply);

        // `server` replies — this must succeed (the real bug made this
        // fail with `NotBlockedOnReply`).
        let reply_msg = SmallMessage::from_words(0x2, &[20]).unwrap();
        let r = k
            .dispatch(server, 0, SyscallOp::Reply { to: root, msg: reply_msg }, &hal)
            .unwrap();
        assert_eq!(r, SyscallReturn::Reschedule { next: Some(root) });

        assert_eq!(k.tcb(root).unwrap().state, ThreadState::Runnable);
        let delivered = k.tcb(root).unwrap().pending_msg.expect("reply delivered to root");
        assert_eq!(delivered.label, 0x2);
        assert_eq!(delivered.words(), &[20]);
    }

    /// `Reply` to a thread that is not (or is no longer) `BlockedOnReply`
    /// is rejected — this is the ONE enforced invariant standing in for
    /// the reply-capability check this MVP deliberately does not build
    /// (see `SyscallOp::Reply`'s own doc comment).
    #[test]
    fn reply_to_non_blocked_thread_is_rejected() {
        let mut k = kernel();
        let root = k.root_thread;
        let (cpu, timer, irqc) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);

        // `bystander` was never Called nor is it BlockedOnReply.
        let bystander = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        let r = k.dispatch(
            root,
            0,
            SyscallOp::Reply { to: bystander, msg: SmallMessage::new(0) },
            &hal,
        );
        assert_eq!(r, Err(SyscallError::NotBlockedOnReply));

        // Replying to yourself is rejected too (never a sensible target).
        let r = k.dispatch(root, 0, SyscallOp::Reply { to: root, msg: SmallMessage::new(0) }, &hal);
        assert_eq!(r, Err(SyscallError::NotBlockedOnReply));
    }
}
