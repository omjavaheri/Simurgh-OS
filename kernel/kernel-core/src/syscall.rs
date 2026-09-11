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
    /// `Signal` woke exactly one thread that was blocked in `Wait` and is
    /// handing it `value` (the notification's own freshly-drained
    /// `signal_word`) to deliver into its resumption context.
    ///
    /// **Real bug found via QEMU** (real-IPC plan Phase 2): unlike
    /// `Recv`'s own blocking case (woken via a DIRECT hand-off from
    /// `do_send`'s own Call fast path, in the SAME synchronous operation
    /// that delivers the message — see `IpcSwitch::poke`'s own doc
    /// comment), `Wait`'s blocking case (`do_wait`) returns `Blocked`
    /// SYNCHRONOUSLY, before any value is known, and the later `Signal`
    /// that actually wakes it (`do_signal`, THIS call) happens as a
    /// COMPLETELY SEPARATE syscall that never itself switches to the
    /// woken thread. Without this variant, the woken thread's saved
    /// return-value register kept whatever stale value it held from
    /// BEFORE it originally blocked — confirmed via a real QEMU
    /// checkpoint trace: security-broker's own `serve_requests` loop
    /// correctly read fresh bits the FIRST two times (both from an
    /// `Immediate`/non-blocking `Wait`), then crashed the THIRD time
    /// (the first time it had actually blocked-then-been-woken), because
    /// nothing had ever poked the real value in. The caller
    /// (`kernel_arch_glue::p2_signal`) is expected to poke `value` into
    /// `woke`'s saved context via the SAME `hal_<arch>::cpu::
    /// poke_saved_a0_a1` primitive `IpcSwitch::poke` already uses — see
    /// that field's own doc comment for why kernel-core cannot do this
    /// poke itself (no `UserContext` layout knowledge here).
    ///
    /// Only ever produced when exactly one thread was woken (this
    /// project's own design: `security-broker` is the sole `Wait`er on
    /// its own shared `Notification`, real-IPC plan Phase 2 — `Notification::
    /// signal`'s own `W`-wide waiter list exists for future multi-waiter
    /// use, not exercised yet). Zero or multiple woken threads fall back
    /// to plain `Done` — a known, documented limitation, not a silent
    /// gap: a multi-waiter caller would need a richer variant than this.
    DeliveredValue {
        /// The thread woken and handed `value`.
        woke: ThreadId,
        /// The notification's own drained `signal_word` at the moment of
        /// delivery.
        value: u64,
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
    /// `Retype { count, .. }` with `count > 1`: the destination capability
    /// table's free list did not hand out `count` contiguous slots for
    /// this batch — real bug found via review, see `do_retype`'s own doc
    /// comment. `SyscallReturn::NewCaps { cap, count }`'s documented
    /// contract ("subsequent ones follow at `cap + 1 ..`") only holds for
    /// a pristine, never-revoked-from table; rather than silently return
    /// a range the caller cannot actually trust, `do_retype` verifies
    /// contiguity for real and fails with this error instead. The whole
    /// batch is rolled back — nothing is left half-created.
    RetypeNotContiguous,
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
                // Cross-space: `cap`'s subtree may include capabilities a
                // `CapGrant` moved into OTHER capability spaces, so this
                // must scan every table, not just the caller's own
                // (kernel_cap::cdt::revoke_cross_space's whole reason to
                // exist over the single-table walk it replaced).
                let freed = kernel_cap::cdt::revoke_cross_space(
                    self.cap_spaces_mut(),
                    kernel_cap::GlobalCapId::new(cs_id, cap),
                )?;
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

    /// Allocates ONE fresh kernel-object-table entry of `target_type` at
    /// `obj_phys`, for one iteration of `do_retype`'s batch loop. A
    /// mechanical extraction of that loop's per-kind allocation logic
    /// (unchanged from before) into its own function, so a failure
    /// partway through a `count > 1` batch has exactly one call site to
    /// fail out of — `do_retype` wraps this call with its own
    /// roll-back-on-error handling.
    fn alloc_retyped_object(
        &mut self,
        caller: ThreadId,
        target_type: KernelObjectType,
        obj_phys: u64,
        per: u64,
    ) -> Result<u32, SyscallError> {
        Ok(match target_type {
            KernelObjectType::Endpoint => {
                self.alloc_endpoint().ok_or(SyscallError::ObjectTableFull)?.as_u32()
            }
            KernelObjectType::Notification => self
                .alloc_notification()
                .ok_or(SyscallError::ObjectTableFull)?
                .as_u32(),
            KernelObjectType::PageTable => {
                // The retyped frame becomes the page-table root.
                self.alloc_addr_space(obj_phys)
                    .ok_or(SyscallError::ObjectTableFull)?
                    .as_u32()
            }
            KernelObjectType::CapabilitySpace => {
                self.alloc_cap_space().ok_or(SyscallError::ObjectTableFull)?.as_u32()
            }
            KernelObjectType::ThreadControlBlock => {
                // MVP: a freshly retyped TCB is bound to the caller's own
                // cap space / address space. A later `feat:` adds a
                // `Configure`-style op to rebind it (seL4's model).
                let (cs0, as0) = {
                    let t = self.tcb(caller).ok_or(SyscallError::NoCaller)?;
                    (t.cap_space, t.addr_space)
                };
                self.alloc_tcb(cs0, as0).ok_or(SyscallError::ObjectTableFull)?.as_u32()
            }
            KernelObjectType::Untyped => {
                // Sub-divide: each child is one page of the reserved
                // range (MVP granularity — `SyscallOp::Retype` carries no
                // size argument; a `size_bits` field is a later
                // extension, seL4-style).
                self.alloc_untyped(obj_phys, per)
                    .ok_or(SyscallError::ObjectTableFull)?
                    .as_u32()
            }
            KernelObjectType::SharedRegion => {
                // MVP: full RW is always the widest a fresh region
                // permits — `Retype` carries no rights argument (same "no
                // size/rights argument yet" gap `Untyped`'s own arm above
                // already notes); a peer can still be GRANTed a narrower
                // derived capability later via the ordinary `CapGrant`
                // rights-narrowing path.
                let region =
                    SharedRegion::new(PhysAddr::new(obj_phys as usize), per as usize, CapabilityRights::RW);
                self.alloc_shared_region(region)
                    .ok_or(SyscallError::ObjectTableFull)?
                    .as_u32()
            }
        })
    }

    /// `target_type` (the `Retype` argument) mapped to the `KernelObjectKind`
    /// every object in the batch is created as — fixed for the whole call,
    /// computed once rather than re-derived per iteration.
    fn retype_target_kind(target_type: KernelObjectType) -> KernelObjectKind {
        match target_type {
            KernelObjectType::Endpoint => KernelObjectKind::Endpoint,
            KernelObjectType::Notification => KernelObjectKind::Notification,
            KernelObjectType::PageTable => KernelObjectKind::PageTable,
            KernelObjectType::CapabilitySpace => KernelObjectKind::CapabilitySpace,
            KernelObjectType::ThreadControlBlock => KernelObjectKind::ThreadControlBlock,
            KernelObjectType::Untyped => KernelObjectKind::UntypedMemory,
            KernelObjectType::SharedRegion => KernelObjectKind::SharedRegion,
        }
    }

    /// Rolls back the first `made` objects of an in-progress `Retype`
    /// batch (their cap-table root slots, then their kernel-object-table
    /// entries) after a later object in the SAME batch failed. Safe by
    /// construction: every one of these `made` objects is a fresh root,
    /// created moments ago in this same still-in-progress syscall
    /// dispatch — no other syscall can interleave mid-dispatch, so
    /// nothing could possibly have derived from or otherwise observed any
    /// of them yet.
    fn unwind_retype_batch(
        &mut self,
        cs_id: kernel_cap::CapSpaceId,
        kind: KernelObjectKind,
        first_cap: CapId,
        first_obj: u32,
        made: u32,
    ) {
        for j in 0..made {
            if let Some(cs) = self.cap_space_mut(cs_id) {
                cs.remove_root(CapId::new(first_cap.as_u32() + j));
            }
            self.free_kernel_object(kind, first_obj + j);
        }
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
        // Reserve the backing physical range. `UntypedMemory::retype`'s
        // own watermark is forward-only and reserves the WHOLE `count *
        // per` range here, upfront, in one shot — so a later partial
        // failure in this function never leaks MORE physical memory than
        // a full success would have used anyway. That is the one piece of
        // this operation this function does NOT roll back on failure (by
        // design, not oversight — see `UntypedMemory`'s own module doc
        // comment on why the watermark has no free path at all).
        let grant = {
            let u = self.untyped_mut(uid).ok_or(SyscallError::BadCap)?;
            u.retype(target_type, count)?
        };

        let cs_id = self.caller_cap_space(caller)?;
        let per = kernel_mm::object_size_bytes(target_type) as u64;
        let kind = Self::retype_target_kind(target_type);

        // `SharedRegion` is the one `target_type` where `count` means
        // something different from every other arm below: NOT "how many
        // separate objects", but "how many contiguous pages does this
        // ONE region span" — added for `Simurgh-UI-Template01`'s own
        // desktop-resolution frame buffer, which a single 4096-byte
        // region (this function's pre-existing `count`-as-object-count
        // behavior, still exactly what every OTHER `target_type` needs)
        // cannot come close to holding. A real desktop frame (e.g.
        // 800x600 BGRA8 = 1,920,000 bytes) would need roughly 470
        // SEPARATE `SharedRegion` objects under the old semantics — each
        // consuming its own capability-table slot, blowing straight
        // through `CAP_SLOTS_PER_SPACE` (96, `kernel-cap/src/cdt.rs`)
        // long before reaching a useful resolution. `UntypedMemory::
        // retype` (just above) already reserves `count * per` bytes as
        // ONE contiguous physical range regardless of `target_type` — so
        // the physical side needs no change at all; only object
        // CREATION does: this arm creates exactly ONE `SharedRegion`
        // spanning the WHOLE reserved range (`grant.phys_len` bytes,
        // i.e. `count` pages), consuming exactly one capability slot, in
        // place of the generic per-object loop below (which still
        // handles every other `target_type`, including a `SharedRegion`
        // caller passing `count: 1` — the common case, unaffected by
        // this arm beyond taking this path instead of one loop
        // iteration with an identical result).
        if target_type == KernelObjectType::SharedRegion {
            let obj_phys = grant.phys_base.as_usize() as u64;
            let region_bytes = grant.phys_len;
            let obj_id = self.alloc_retyped_object(caller, target_type, obj_phys, region_bytes)?;
            let newcap = Capability::full(ObjectRef::new(kind, ObjectId::new(obj_id)));
            let cs = self.cap_space_mut(cs_id).ok_or(SyscallError::NoCaller)?;
            return match cs.insert_root(newcap) {
                Ok(slot) => Ok(SyscallReturn::NewCaps { cap: slot, count: 1 }),
                Err(e) => {
                    self.free_kernel_object(kind, obj_id);
                    Err(e.into())
                }
            };
        }

        // `first_cap`/`first_obj`: the capability slot / kernel-object id
        // iteration 0 below is granted. Every later iteration in this
        // same batch must land EXACTLY at `first_cap + i` / `first_obj +
        // i` — checked for real below, not assumed.
        //
        // **Real bug found via review**: `SyscallReturn::NewCaps{cap,
        // count}`'s own doc comment claims "subsequent ones follow at
        // `cap + 1 ..`", but `cs.insert_root`'s allocator (`CapTable`'s
        // free list) is only contiguous for a pristine, never-revoked-
        // from table. `free_slot` pushes a freed slot onto the HEAD of
        // that list (kernel-cap/src/cdt.rs), so once ANY prior capability
        // in the destination table has ever been revoked, the next
        // `count - 1` insertions in a batch are no longer guaranteed
        // sequential with the first — silently making the returned
        // `NewCaps` describe capabilities that are NOT actually at `cap +
        // 1 ..`, with nothing telling the caller its assumption just
        // broke. Object-table ids (`self.endpoints`/etc. in `state.rs`)
        // are separately guaranteed monotonic today (nothing in this
        // crate ever frees one outside this very rollback path), so only
        // the CAPABILITY side of the contract can actually break in
        // practice — but this function checks both, since the object-id
        // side's monotonicity is an incidental fact about the rest of the
        // codebase today, not a documented invariant this function may
        // rely on going forward.
        //
        // Rather than let the false claim stand, this function verifies
        // contiguity for real and fails loudly (`RetypeNotContiguous`,
        // whole batch rolled back) instead of silently returning a range
        // the caller cannot trust. In practice this is unreachable today
        // — every real caller in this codebase (`kernel/kernel/src/
        // main.rs`, `kernel-arch-glue`) only ever requests `count: 1`,
        // and the one raw-ABI opcode that reaches this path
        // (`RETYPE_ENDPOINT`) hardcodes `count: 1` too — but the
        // dispatch-level `SyscallOp::Retype.count` field exists precisely
        // so a `count > 1` batch is a real, supported request, not a
        // hypothetical one, and this function's own return type must
        // either keep its documented promise or fail, never quietly break
        // it.
        let mut first_cap: Option<CapId> = None;
        let mut first_obj: Option<u32> = None;
        let mut made: u32 = 0;

        for i in 0..grant.count {
            // Physical slot for object `i` within the reserved range.
            let obj_phys = grant.phys_base.as_usize() as u64 + i as u64 * per;

            let obj_id = match self.alloc_retyped_object(caller, target_type, obj_phys, per) {
                Ok(id) => id,
                Err(e) => {
                    if let (Some(fc), Some(fo)) = (first_cap, first_obj) {
                        self.unwind_retype_batch(cs_id, kind, fc, fo, made);
                    }
                    return Err(e);
                }
            };

            let newcap = Capability::full(ObjectRef::new(kind, ObjectId::new(obj_id)));
            let cs = self.cap_space_mut(cs_id).ok_or(SyscallError::NoCaller)?;
            let slot = match cs.insert_root(newcap) {
                Ok(s) => s,
                Err(e) => {
                    // This iteration's own object was just created but
                    // never rooted — free it too before unwinding priors.
                    self.free_kernel_object(kind, obj_id);
                    if let (Some(fc), Some(fo)) = (first_cap, first_obj) {
                        self.unwind_retype_batch(cs_id, kind, fc, fo, made);
                    }
                    return Err(e.into());
                }
            };

            match (first_cap, first_obj) {
                (None, None) => {
                    first_cap = Some(slot);
                    first_obj = Some(obj_id);
                }
                (Some(fc), Some(fo)) => {
                    if slot.as_u32() != fc.as_u32() + i || obj_id != fo + i {
                        // Contiguity broken: undo THIS iteration's insert
                        // + object, then unwind every prior one.
                        if let Some(cs) = self.cap_space_mut(cs_id) {
                            cs.remove_root(slot);
                        }
                        self.free_kernel_object(kind, obj_id);
                        self.unwind_retype_batch(cs_id, kind, fc, fo, made);
                        return Err(SyscallError::RetypeNotContiguous);
                    }
                }
                _ => unreachable!("first_cap/first_obj are always set together"),
            }
            made += 1;
        }
        Ok(SyscallReturn::NewCaps {
            cap: first_cap.ok_or(SyscallError::Mm(MmError::ZeroCount))?,
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

        // **Real bug found via review**: `target_thread` naming a SIBLING
        // thread in the CALLER'S OWN capability space used to always fail
        // here with `BadCap` — a real, supported pattern (`do_retype`'s
        // `ThreadControlBlock` arm binds a freshly retyped TCB to "the
        // caller's own cap space", so a sibling thread sharing the
        // caller's table is an expected outcome, not an edge case).
        // `cap_space_pair_mut` needs two DISJOINT mutable borrows and
        // refuses `src == dst`, so the cross-space path below was the
        // ONLY one ever tried — even for a same-table grant that
        // `CapTable::derive_child` (same mechanism `kernel-cap`'s own
        // unit tests already exercise directly) handles just fine.
        let dst_slot = if src_cs == dst_cs {
            let cs = self.cap_space_mut(src_cs).ok_or(SyscallError::BadCap)?;
            cs.derive_child(cap, rights, 0)?
        } else {
            // Derive the narrowed child directly into the destination
            // space's table. This is a real CDT edge, not a copy-then-
            // move: `cap` itself is left untouched in `src_cs`, and the
            // new slot's parent link points back at it, so a later
            // `CapRevoke` on `cap` (or any of its ancestors) reaches this
            // grant even though it now lives in a different capability
            // space (kernel_cap::cdt::derive_child_cross_space's whole
            // reason to exist over the MVP's earlier derive-then-take-
            // then-insert_root sequence).
            let (src, dst) = self
                .cap_space_pair_mut(src_cs, dst_cs)
                .ok_or(SyscallError::BadCap)?;
            kernel_cap::cdt::derive_child_cross_space(src, src_cs, cap, dst, rights, 0)?
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
        let notif = self.notification_mut(nid).ok_or(SyscallError::BadCap)?;
        let woken = notif.signal(bits);
        // Only drain when there is actually someone to deliver to — a
        // REAL bug introduced while fixing `DeliveredValue`'s own
        // motivating one: draining unconditionally here (even with an
        // EMPTY `woken`, the common case when `Signal` races ahead of the
        // first `Wait`) would silently discard `bits` before any future
        // `Wait`'s own `poll()` fast path ever got a chance to see them —
        // the signal would be lost, not just delayed, and the eventual
        // `Wait` would block forever on a notification that already
        // fired. `woken` is only non-empty when a thread was ALREADY
        // blocked in `Wait` (`Notification::wait`'s own precondition:
        // `kernel-core` only calls it when `poll` would return `0`), so
        // gating the drain on that is exactly "drain only when someone is
        // there to receive the value right now".
        let value = if !woken.as_slice().is_empty() { notif.poll() } else { 0 };
        for &tid in woken.as_slice() {
            self.wake_blocked(tid, now_ns);
        }
        match woken.as_slice() {
            [tid] => Ok(SyscallReturn::DeliveredValue { woke: *tid, value }),
            _ => Ok(SyscallReturn::Done),
        }
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
                    // **Real bug found via review** (not via QEMU — 100%
                    // deterministic on every blocking IPC call, but
                    // invisible to any test that only asserts on
                    // `ThreadState`/`Reschedule` targets, never on
                    // `vruntime`): every OTHER place in this codebase that
                    // removes the CURRENTLY RUNNING thread from `running`
                    // (`do_wait`, every function in `preempt.rs`) calls
                    // `account(now_ns)` first, so the run slice about to
                    // be discarded gets charged before `note_blocked`
                    // clears `running`. This call site (and `SenderQueued`
                    // below, and `do_recv`'s `ReceiverQueued`/`do_reply`)
                    // used to skip it — `caller`'s vruntime for the
                    // interval since it was last dispatched was silently
                    // dropped, never added to `vruntime` or its chain
                    // group's `group_vruntime`. Since a synchronous IPC
                    // chain (§4.3's whole reason `ChainGroup` exists) ends
                    // a run slice via EXACTLY these calls on every hop,
                    // not via a timer tick, `group_vruntime` stayed at (or
                    // near) 0 for any chain that never happened to be
                    // interrupted mid-slice by an unrelated preemption —
                    // making Throughput mode's core "charge a chain once,
                    // split fairly" mechanism close to inert in practice.
                    self.sched.account(now_ns);
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
                // See the identical `account` call in `DeliveredTo`'s own
                // `is_call` arm above for the full "real bug found via
                // review" rationale — same fix, same reason, applied to
                // this second blocking exit point.
                self.sched.account(now_ns);
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
                // See `do_send`'s own identical "real bug found via
                // review" comment (its `DeliveredTo`/`is_call` arm) for
                // the full rationale — same fix, same reason.
                self.sched.account(now_ns);
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
        // See `do_send`'s own identical "real bug found via review"
        // comment (its `DeliveredTo`/`is_call` arm) for the full
        // rationale — same fix, same reason: `Reply` is ALWAYS an
        // unconditional handoff away from `caller` (this function's own
        // doc comment), so `caller`'s run slice since it was last
        // dispatched must be charged here, exactly like every OTHER
        // place that ends the running thread's slice already does.
        self.sched.account(now_ns);
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

    /// No `SyscallOp` in this module's tests ever reaches
    /// `hal_core::power::SystemControl::reboot`/`shutdown` (both `-> !`,
    /// and no dispatch path here calls them) — this mock exists purely
    /// to satisfy `build_interface`'s generic bound.
    struct MockPower;
    impl hal_core::power::SystemControl for MockPower {
        fn reboot(&self) -> ! {
            loop {}
        }
        fn shutdown(&self) -> ! {
            loop {}
        }
    }

    // `build_interface`'s `cpu`/`timer`/`interrupt`/`power` refs must
    // outlive the `HalInterface` it returns, so this returns owned
    // values for each test to bind as locals before building its own
    // `hal` — kernel-core is `#![no_std]` with no `alloc`, so no
    // `Box::leak` shortcut (same pattern `run.rs`'s tests already use).
    fn mock_hal_pair() -> (MockCpu, MockTimer, MockInterrupt, MockPower) {
        (MockCpu, MockTimer, MockInterrupt, MockPower)
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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
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

    /// `count > 1` for `SharedRegion` means "how many contiguous pages
    /// does this ONE region span", NOT "how many separate objects" (see
    /// `do_retype`'s own doc comment on this arm) — added for
    /// `Simurgh-UI-Template01`'s own desktop-resolution frame buffer,
    /// which a fixed single page cannot hold. This test is the
    /// count-as-object-count behavior's own direct counterpart above,
    /// proving the opposite semantic for the one `target_type` where it
    /// applies: exactly ONE capability/object comes back (not `count`
    /// of them), and that one object's own `size` is `count * PAGE_SIZE`.
    #[test]
    fn retype_untyped_into_multi_page_shared_region_gives_one_cap_spanning_every_page() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
        const PAGES: u32 = 470; // ~ an 800x600 BGRA8 frame's own page count.
        let r = k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::SharedRegion,
                    count: PAGES,
                },
                &hal,
            )
            .unwrap();
        match r {
            SyscallReturn::NewCaps { cap, count } => {
                // Exactly one capability/object — NOT `PAGES` of them
                // (the old, object-count semantic every OTHER
                // `target_type` still has, and this same `target_type`
                // still has for `count: 1`, per the test just above).
                assert_eq!(count, 1);
                let c = k
                    .resolve(caller, cap, KernelObjectKind::SharedRegion, CapabilityRights::READ)
                    .unwrap();
                let region = k
                    .shared_region(kernel_cap::SharedRegionId::new(c.object.id.as_u32()))
                    .unwrap();
                assert_eq!(region.size, PAGE_SIZE * PAGES as usize);
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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
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

        // Signal wakes it: `wake_blocked` marks `caller` Ready again, and
        // (real-IPC plan Phase 2's own `DeliveredValue` — see that
        // variant's own doc comment for the real bug this fixes) hands
        // back the drained bits for the caller's own glue to poke into
        // the woken thread's saved context, since `Wait`'s original
        // `Blocked` return happened before any value was known and
        // `Signal` itself never switches to the woken thread.
        let r = k.dispatch(
            caller,
            0,
            SyscallOp::Signal { notification: notif_cap, bits: 0b101 },
            &hal,
        );
        assert_eq!(r, Ok(SyscallReturn::DeliveredValue { woke: caller, value: 0b101 }));
        assert_eq!(
            k.sched.entity(caller).unwrap().state,
            kernel_sched::RunState::Ready
        );

        // The delivered value is ALREADY drained (not left sticky for a
        // later Poll to see again) — it was handed to `Signal`'s own
        // caller specifically so it does not need to be re-fetched.
        let r = k.dispatch(caller, 0, SyscallOp::Poll { notification: notif_cap }, &hal);
        assert_eq!(r, Ok(SyscallReturn::Value(0)));
    }

    #[test]
    fn signal_before_anyone_waits_leaves_the_bits_pending_for_a_later_wait() {
        // Real bug found while fixing `signal_wakes_a_waiting_thread`'s
        // own `DeliveredValue` case above: an earlier draft drained
        // `signal_word` unconditionally inside `do_signal`, even with an
        // EMPTY `woken` list (the common case — `Signal` racing ahead of
        // the first `Wait`) — silently discarding the bits before any
        // future `Wait`'s own immediate-return fast path could ever see
        // them, so the eventual `Wait` blocked forever on a signal that
        // had already fired. The drain must happen ONLY when there is a
        // woken thread to deliver the value to right now.
        let mut k = kernel_with_mmio_blk();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
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

        // Nobody is waiting yet.
        let r = k.dispatch(caller, 0, SyscallOp::Signal { notification: notif_cap, bits: 0b10 }, &hal);
        assert_eq!(r, Ok(SyscallReturn::Done));

        // A later Wait must still see the bits — not lost.
        let r = k.dispatch(caller, 0, SyscallOp::Wait { notification: notif_cap }, &hal);
        assert_eq!(r, Ok(SyscallReturn::Value(0b10)));
    }

    #[test]
    fn irq_bind_requires_mmio_and_notification_caps_and_registers_with_hal() {
        let mut k = kernel_with_mmio_blk();
        let caller = k.root_thread;
        let mmio_cap = k.root_mmio_blk_cap;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
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
    fn cap_grant_into_another_space_then_revoke_source_reaches_the_grant() {
        // The syscall-dispatcher-level counterpart to kernel-cap's own
        // `revoke_cross_space` unit tests: proves the whole path — a
        // real `SyscallOp::CapGrant` into a genuinely separate
        // `CapSpaceId`, then a real `SyscallOp::CapRevoke` on the
        // capability it was derived from — actually reaches through
        // `KernelState::dispatch`, not just `kernel_cap::cdt`'s own
        // lower-level API (02-Microkernel-Layer.md line 65).
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

        // An Endpoint capability in the caller's own (root) space — the
        // thing that will be granted elsewhere, then revoked from here.
        let src_cap = match k
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
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };

        // A genuinely separate capability space, with a TCB living in
        // it, and a capability naming that TCB minted directly into the
        // caller's own space (`Retype`'s own `ThreadControlBlock` arm
        // always binds the new TCB to the CALLER's space, so it can't
        // produce a cross-space target here — this mirrors the same
        // "mint a TCB cap for a space you didn't create the TCB request
        // from" shape `kernel-arch-glue::spawn_process` uses at a higher
        // level, simplified for a unit test).
        let dst_cs = k.alloc_cap_space().unwrap();
        let dst_tid = k.alloc_tcb(dst_cs, k.root_addr_space).unwrap();
        let target_thread = {
            let tcap = Capability::full(ObjectRef::new(
                KernelObjectKind::ThreadControlBlock,
                ObjectId::new(dst_tid.as_u32()),
            ));
            k.cap_space_mut(k.root_cap_space)
                .unwrap()
                .insert_root(tcap)
                .unwrap()
        };

        // Grant a READ-only copy of the endpoint into the destination space.
        let granted = match k
            .dispatch(
                caller,
                0,
                SyscallOp::CapGrant {
                    target_thread,
                    cap: src_cap,
                    rights: CapabilityRights::READ,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::Granted { dst } => dst,
            other => panic!("unexpected {other:?}"),
        };
        assert!(k.cap_space(dst_cs).unwrap().lookup(granted).is_some());
        // The source is untouched by the grant.
        assert!(k.cap_space(k.root_cap_space).unwrap().lookup(src_cap).is_some());

        // Revoking the SOURCE capability (still in the caller's own
        // space) must reach through and free the granted copy in the
        // OTHER space — the entire point of cross-space CDT.
        let freed = match k
            .dispatch(caller, 0, SyscallOp::CapRevoke { cap: src_cap }, &hal)
            .unwrap()
        {
            SyscallReturn::Revoked { freed } => freed,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(freed, 2); // src_cap itself + the cross-space grant
        assert!(k.cap_space(k.root_cap_space).unwrap().lookup(src_cap).is_none());
        assert!(k.cap_space(dst_cs).unwrap().lookup(granted).is_none());
    }

    #[test]
    fn bad_cap_is_rejected() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
        let e = k.dispatch(caller, 0, SyscallOp::CapRevoke { cap: CapId::new(99) }, &hal);
        assert_eq!(e, Err(SyscallError::BadCap));
    }

    #[test]
    fn yield_reports_reschedule() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);
        // Root task must be dispatched first for account() to have work.
        k.sched.dispatch(caller, 0).unwrap();
        let r = k.dispatch(caller, 1_000_000, SyscallOp::Yield, &hal).unwrap();
        assert!(matches!(r, SyscallReturn::Reschedule { .. }));
    }

    #[test]
    fn map_installs_hardware_ptes_when_a_pool_is_present() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

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
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

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

    /// **Real bug found via review**: a `Retype { count > 1 }` batch that
    /// fails partway through (the destination object table fills up)
    /// used to leave every object/capability created before the failing
    /// iteration in place — orphaned kernel objects with no capability
    /// referencing any of them (the syscall as a whole reports failure,
    /// so the caller never learns their ids), plus the caller's own cap
    /// table permanently larger than it was before the call. `do_retype`
    /// now rolls the whole batch back on any mid-batch failure.
    #[test]
    fn retype_batch_partial_failure_rolls_back_every_object_and_capability() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

        let cs_len_before = k.cap_space(k.root_cap_space).unwrap().len();

        // More endpoints than `MAX_ENDPOINTS` (config.rs) in one batch:
        // the `Endpoint` object table fills up strictly between
        // iteration 0 and `count`, so `do_retype` must fail with
        // `ObjectTableFull`.
        let r = k.dispatch(
            caller,
            0,
            SyscallOp::Retype {
                untyped: CapId::new(0),
                target_type: KernelObjectType::Endpoint,
                count: crate::config::MAX_ENDPOINTS as u32 + 5,
            },
            &hal,
        );
        assert_eq!(r, Err(SyscallError::ObjectTableFull));

        // The cap table must be exactly as the failed call found it.
        assert_eq!(
            k.cap_space(k.root_cap_space).unwrap().len(),
            cs_len_before,
            "a failed batch must leave the caller's cap table exactly as it found it"
        );

        // And the object table itself must be rolled back too, not just
        // the capabilities pointing at it — a fresh, ordinary retype
        // must still succeed afterward (it would fail with
        // `ObjectTableFull` again if the earlier orphaned objects were
        // still occupying `MAX_ENDPOINTS` object-table slots).
        let r2 = k.dispatch(
            caller,
            0,
            SyscallOp::Retype { untyped: CapId::new(0), target_type: KernelObjectType::Endpoint, count: 1 },
            &hal,
        );
        assert!(matches!(r2, Ok(SyscallReturn::NewCaps { count: 1, .. })));
    }

    /// **Real bug found via review**: `SyscallReturn::NewCaps` (`cap`
    /// plus `count`) claims in its own doc comment that subsequent caps
    /// follow sequentially after `cap`. But `CapTable`'s free list is
    /// only contiguous for a pristine, never-revoked-from table —
    /// `free_slot` pushes a freed slot onto the HEAD of the free list,
    /// so once any prior capability in the destination table has been
    /// revoked, the next allocation in a batch can land far from `cap`
    /// plus one, silently describing a capability that isn't actually
    /// there (worse: the slot it lands on can belong to a completely
    /// different, unrelated, still-live capability). `do_retype` now
    /// detects this for real and fails with `RetypeNotContiguous`
    /// instead of returning a range the caller cannot trust.
    #[test]
    fn retype_batch_detects_non_contiguous_slots_and_rolls_back() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

        // Three individual (count: 1) Endpoint capabilities land at
        // sequential slots in a pristine table.
        let mut caps = [CapId::new(0); 3];
        for c in caps.iter_mut() {
            *c = match k
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
                .unwrap()
            {
                SyscallReturn::NewCaps { cap, .. } => cap,
                other => panic!("unexpected {other:?}"),
            };
        }
        assert_eq!(caps[1].as_u32(), caps[0].as_u32() + 1);
        assert_eq!(caps[2].as_u32(), caps[0].as_u32() + 2);

        // Revoke ONLY the first of the three (not its Untyped parent) —
        // the real-world trigger for the false "contiguous" claim: the
        // freed slot goes to the free list's HEAD, so the next
        // allocation reuses it, but the allocation after THAT jumps to
        // the table's still-untouched tail — NOT `caps[0] + 1`, since
        // `caps[1]`/`caps[2]` are still occupying that range.
        let freed = match k.dispatch(caller, 0, SyscallOp::CapRevoke { cap: caps[0] }, &hal).unwrap() {
            SyscallReturn::Revoked { freed } => freed,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(freed, 1);

        let cs_len_before_batch = k.cap_space(k.root_cap_space).unwrap().len();

        // Before the fix, this silently returned `NewCaps { cap:
        // caps[0], count: 2 }`, falsely implying a second capability at
        // `caps[0] + 1` — `caps[1]`'s own slot, still occupied by a
        // DIFFERENT, unrelated, live capability.
        let r = k.dispatch(
            caller,
            0,
            SyscallOp::Retype {
                untyped: CapId::new(0),
                target_type: KernelObjectType::Notification,
                count: 2,
            },
            &hal,
        );
        assert_eq!(r, Err(SyscallError::RetypeNotContiguous));

        // Whole batch rolled back: the cap table is back to exactly
        // where it was right before this call.
        assert_eq!(k.cap_space(k.root_cap_space).unwrap().len(), cs_len_before_batch);

        // Crucially: `caps[1]` — the unrelated, still-live capability
        // whose slot the non-contiguous 2nd allocation reached for —
        // must be completely untouched by the failed batch.
        let c1 = k.resolve(caller, caps[1], KernelObjectKind::Endpoint, CapabilityRights::READ);
        assert!(c1.is_ok(), "an unrelated live capability must survive a failed Retype batch");
    }

    /// **Real bug found via review**: `CapGrant` to a sibling thread in
    /// the CALLER'S OWN capability space used to always fail with
    /// `BadCap` — `do_retype`'s own `ThreadControlBlock` arm binds a
    /// freshly retyped TCB to "the caller's own cap space", so this is a
    /// real, expected pattern (two threads sharing one process's
    /// capability table), not a hypothetical edge case.
    #[test]
    fn cap_grant_to_a_sibling_thread_in_the_same_cap_space_succeeds() {
        let mut k = kernel();
        let caller = k.root_thread;
        let (cpu, timer, irqc, power) = mock_hal_pair();
        let hal = hal_core::build_interface(&cpu, &timer, &irqc, &power);

        // A sibling TCB in the caller's own cap space (Retype's own
        // documented behavior for ThreadControlBlock).
        let sibling_cap = match k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype {
                    untyped: CapId::new(0),
                    target_type: KernelObjectType::ThreadControlBlock,
                    count: 1,
                },
                &hal,
            )
            .unwrap()
        {
            SyscallReturn::NewCaps { cap, .. } => cap,
            other => panic!("unexpected {other:?}"),
        };
        let sibling_tid = ThreadId::new(
            k.resolve(caller, sibling_cap, KernelObjectKind::ThreadControlBlock, CapabilityRights::WRITE)
                .unwrap()
                .object
                .id
                .as_u32(),
        );

        // An Endpoint (full rights) to grant a narrowed READ-only copy of.
        let ep_cap = match k
            .dispatch(
                caller,
                0,
                SyscallOp::Retype { untyped: CapId::new(0), target_type: KernelObjectType::Endpoint, count: 1 },
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
            SyscallOp::CapGrant { target_thread: sibling_cap, cap: ep_cap, rights: CapabilityRights::READ },
            &hal,
        );
        let dst = match r.unwrap() {
            SyscallReturn::Granted { dst } => dst,
            other => panic!("unexpected {other:?}"),
        };

        // The grant landed in the SIBLING's own cap space — the same
        // table `caller` used, since they share one cap space — with
        // exactly the narrowed rights requested, and the original `cap`
        // is untouched in the caller's table.
        let sibling_cs = k.tcb(sibling_tid).unwrap().cap_space;
        assert_eq!(sibling_cs, k.tcb(caller).unwrap().cap_space);
        let granted = k.cap_space(sibling_cs).unwrap().lookup(dst).unwrap();
        assert_eq!(granted.rights, CapabilityRights::READ);
        assert!(k.cap_space(sibling_cs).unwrap().lookup(ep_cap).is_some());

        // Revoking the original still reaches the same-space grant (the
        // CDT parent link works identically to the cross-space case).
        let freed = match k.dispatch(caller, 0, SyscallOp::CapRevoke { cap: ep_cap }, &hal).unwrap() {
            SyscallReturn::Revoked { freed } => freed,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(freed, 2); // ep_cap itself + the same-space grant
        assert!(k.cap_space(sibling_cs).unwrap().lookup(dst).is_none());
    }
}
