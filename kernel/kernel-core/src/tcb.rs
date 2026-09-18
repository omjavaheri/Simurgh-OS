//! ============================================================================
//! tcb.rs
//!
//! Purpose: `Tcb` — the kernel's per-thread record. Holds the saved
//! hardware register context (for `hal_core::CpuAbstraction::context_switch`),
//! which capability space and address space the thread runs in, its entry
//! point, and its lifecycle state. Scheduling metadata (priority,
//! `vruntime`, mode) lives separately in `kernel-sched`'s `SchedEntity`.
//!
//! Architecture reference: 02-Microkernel-Layer.md §3 (`ThreadControlBlock`
//! kernel object), §4 (scheduling is a separate concern), §6 (`CapGrant {
//! target_thread, .. }` — a TCB capability authorises acting on a thread).
//!
//! Position in the system: one `Tcb` per `ThreadControlBlock` object in
//! `KernelState`. `kernel-arch-glue` reads `context` to perform the first
//! and every subsequent context switch.
//!
//! Safety/invariants: `context` is opaque bytes only the architecture's
//! `context_switch` interprets; `cap_space` / `addr_space` always name
//! occupied slots while the TCB is live.
//! ============================================================================

use crate::CpuContext;
use hal_core::{UserContext, VirtAddr};
use kernel_cap::{CapSpaceId, PageTableId, ThreadId};
use kernel_ipc::SmallMessage;

/// Lifecycle state of a thread, as the kernel sees it.
///
/// Possible values and their meaning:
/// - `Inactive`: the TCB exists (was `Retype`d) but has never been
///   started. `context` is not yet valid to switch to.
/// - `Runnable`: eligible to run; the scheduler's `SchedEntity` for this
///   thread is `Ready` or `Running`.
/// - `BlockedOnSend`: parked in an endpoint's send queue awaiting a
///   receiver (02-Microkernel-Layer.md §5.1).
/// - `BlockedOnRecv`: parked in an endpoint's receive queue awaiting a
///   sender.
/// - `BlockedOnReply`: a `Call` sender that delivered its message and is
///   now waiting for the reply (§6 `Call` = atomic Send+Recv).
/// - `BlockedOnNotification`: waiting on a `Notification` object.
/// - `Exited`: the thread has terminated; its TCB slot is pending
///   reclamation by whoever holds the TCB capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Created, never started.
    Inactive,
    /// Eligible to run.
    Runnable,
    /// In an endpoint send queue.
    BlockedOnSend,
    /// In an endpoint receive queue.
    BlockedOnRecv,
    /// A `Call` sender awaiting its reply.
    BlockedOnReply,
    /// Waiting on a notification.
    BlockedOnNotification,
    /// Terminated.
    Exited,
}

impl ThreadState {
    /// True for any of the blocked-* states.
    pub fn is_blocked(self) -> bool {
        matches!(
            self,
            Self::BlockedOnSend
                | Self::BlockedOnRecv
                | Self::BlockedOnReply
                | Self::BlockedOnNotification
        )
    }
}

/// WHY a thread terminated — the payload `SyscallOp::ThreadExitStatus`
/// hands back to a terminated thread's own spawner (02-Microkernel-Layer.md
/// §3: the `ThreadControlBlock` kernel object's lifecycle; 03-Kernel-
/// Subsystems-Layer.md §5.2: per-process fault isolation, whose whole
/// point is that SOMEONE above can react to one process dying).
///
/// `ThreadState::Exited` alone answers "is it dead"; this answers "and
/// why", which is what any real supervisor actually needs — a crash and
/// an orderly shutdown call for opposite reactions (restart vs. accept),
/// and `simurgh-init`'s own `RestartPolicy::OnFailure` versus
/// `RestartPolicy::Always` are exactly that distinction. Recorded once,
/// at the moment of termination (`KernelState::mark_exited`, reached from
/// every real termination path), and never mutated afterward.
///
/// Variants and their effect on a supervisor:
/// - `Clean { code }`: the thread terminated voluntarily and in order.
///   `code` is whatever it reported for itself, `0` meaning success by
///   the usual convention — the kernel never interprets it. A supervisor
///   with a `restart-on-failure` policy should NOT restart on
///   `Clean { code: 0 }`.
///   TODO(spec): no U-mode thread can actually produce this variant yet
///   — this MVP has no voluntary process-exit syscall at all (a U-mode
///   subsystem either parks forever or faults), so today this variant is
///   only ever produced by the in-kernel S-mode demo threads
///   (`kernel_arch_glue`'s `thread2_main` / IPC-benchmark server). The
///   variant exists now, rather than being retrofitted later, precisely
///   so the supervision primitive below does not have to change shape
///   when a real exit syscall lands: a supervisor written against it
///   today already handles the clean case correctly.
/// - `Faulted { cause }`: the thread took a fatal exception and was
///   terminated BY the kernel (`kernel_arch_glue::p2_fault`, the same
///   path that already drives the real driver fault-isolation demo).
///   `cause` is the raw architecture trap cause code, passed through
///   verbatim and NOT normalized across architectures — the kernel has
///   no architecture-independent fault taxonomy to map it into, and
///   inventing one here would be a guess (see this crate's own
///   `CONTRIBUTING.md` rule). A supervisor should treat this as a
///   failure and consult it only for diagnostics/logging, never branch
///   portably on its value.
/// - `Unknown`: the thread is `Exited` but no reason was recorded. Not
///   produced by any path in this crate today (every termination site
///   goes through `mark_exited` with a real reason); it exists so
///   `SyscallOp::ThreadExitStatus` can stay TOTAL — reporting an honest
///   "dead, reason unrecorded" instead of having to either lie
///   (`Clean { code: 0 }`) or fail a query about a thread that has
///   demonstrably terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadExit {
    /// Voluntary, orderly termination; `code` is self-reported.
    Clean {
        /// Self-reported status, `0` = success by convention.
        code: u32,
    },
    /// Killed by the kernel after a fatal exception; `cause` is the raw
    /// architecture trap cause.
    Faulted {
        /// Raw, architecture-specific trap cause code.
        cause: u64,
    },
    /// Terminated with no recorded reason.
    Unknown,
}

impl ThreadExit {
    /// True iff this exit should count as a FAILURE to a supervisor with
    /// a restart-on-failure policy: a fault, or a clean exit with a
    /// non-zero self-reported code. `Unknown` counts as a failure too —
    /// a thread that died for an unrecorded reason is safer to treat as
    /// having crashed than as having shut down deliberately.
    pub fn is_failure(self) -> bool {
        match self {
            Self::Clean { code } => code != 0,
            Self::Faulted { .. } | Self::Unknown => true,
        }
    }
}

/// The kernel's control block for one thread.
#[derive(Clone, Copy)]
pub struct Tcb {
    /// This thread's id (index into the TCB table).
    pub id: ThreadId,
    /// Saved hardware register context for the kernel-to-kernel
    /// cooperative path (`hal_core::HalInterface::context_switch`).
    /// Written when the thread is switched out at a call boundary; read
    /// when switched back in.
    pub context: CpuContext,
    /// Saved U-mode register context, for threads that run in user space.
    /// Written from the trap frame when the thread is preempted or
    /// `P2_YIELD`s; restored via `hal_core::HalInterface::resume_user`.
    /// Distinct from `context` because a U-mode thread is snapshotted at
    /// an arbitrary trap point, not a call boundary (02-Microkernel-Layer.md
    /// §4 preemption).
    pub user_context: UserContext,
    /// The capability space `CapId` arguments in this thread's syscalls
    /// are resolved against.
    pub cap_space: CapSpaceId,
    /// The address space (`PageTable` root) this thread executes in.
    pub addr_space: PageTableId,
    /// Initial instruction pointer, recorded for (re)starting the thread.
    pub entry: VirtAddr,
    /// Lifecycle state.
    pub state: ThreadState,
    /// A message delivered to this thread while it was blocked in `Recv`,
    /// waiting to be consumed when it next runs. In the real kernel the
    /// message goes straight into the thread's argument registers via
    /// `context`; this field is the MVP stand-in until `HalInterface`
    /// grows a context-write primitive.
    pub pending_msg: Option<SmallMessage>,
    /// Who sent `pending_msg`, when it was delivered asynchronously (the
    /// receiving thread was already blocked in `Recv` and got switched
    /// straight back in — `SyscallOp::Send`/`Call`'s fast-delivery path
    /// in `do_send` — rather than receiving it as `Recv`'s own
    /// synchronous `SyscallReturn::Message { from, .. }`, which already
    /// carries `from` with no need to persist it here). Needed for
    /// `SyscallOp::Reply { to, .. }`: without this, a receiver woken
    /// this way would have the request message but no way to learn
    /// which caller to reply to.
    pub pending_from: Option<ThreadId>,
    /// The thread that created this one — recorded once, at TCB
    /// allocation time (`KernelState::alloc_tcb`), and never changed.
    ///
    /// `None` for a thread nothing spawned: the Root Task itself (created
    /// by `KernelState::init_global` before any thread is running at all),
    /// and any TCB a unit test allocates directly with no `running()`
    /// thread to attribute it to.
    ///
    /// This is the ACCESS CONTROL for `SyscallOp::ThreadExitStatus`: only
    /// a thread's own spawner may ask why it died. See that operation's
    /// own doc comment for the full reasoning — in short, a raw
    /// `ThreadId` is guessable in this MVP (`SyscallOp::Reply`'s own doc
    /// comment records that accepted gap), so without an ownership check
    /// ANY process could sweep the whole TCB table and read every other
    /// process's fault causes and faulting addresses. Restricting it to
    /// the spawner is the capability-consistent default: the spawner is
    /// the one party that provably already knows the `ThreadId` (it got
    /// it back from the spawn), and the one party with a legitimate
    /// reason to supervise it.
    ///
    /// TODO(spec): the fuller model is a real, first-class
    /// "child-exit-notification capability" minted to the spawner at
    /// spawn time and grantable onward (so a supervisor could DELEGATE
    /// supervision of one of its children, which a fixed spawner field
    /// cannot express) — the same generalization `sys::SPAWN_KNOWN_ELF`'s
    /// own doc comment defers for process creation itself, deliberately
    /// deferred here too rather than half-built.
    pub spawner: Option<ThreadId>,
    /// Why this thread terminated, or `None` while it is still alive.
    ///
    /// Invariant: `exit.is_some()` iff `state == ThreadState::Exited` —
    /// every real termination path goes through
    /// `KernelState::mark_exited`, which sets both together. The
    /// `Exited`-but-`None` combination is therefore unreachable today;
    /// `ThreadExit::Unknown` exists so the query syscall stays total if
    /// a future path ever breaks that (see its own doc comment).
    pub exit: Option<ThreadExit>,
}

impl Tcb {
    /// Creates an `Inactive` TCB with no recorded spawner. `kernel-core`
    /// sets `entry` and marks it `Runnable` when the owner starts it; the
    /// architecture layer seeds `context` with the entry point / initial
    /// stack via architecture-specific helpers before the first switch.
    pub const fn new_inactive(
        id: ThreadId,
        cap_space: CapSpaceId,
        addr_space: PageTableId,
    ) -> Self {
        Self::new_inactive_spawned_by(id, cap_space, addr_space, None)
    }

    /// Same as [`Tcb::new_inactive`], but attributing the new thread to
    /// `spawner` (see the [`Tcb::spawner`] field's own doc comment for
    /// what that attribution authorizes).
    pub const fn new_inactive_spawned_by(
        id: ThreadId,
        cap_space: CapSpaceId,
        addr_space: PageTableId,
        spawner: Option<ThreadId>,
    ) -> Self {
        Self {
            id,
            context: CpuContext::zeroed(),
            user_context: UserContext::zeroed(),
            cap_space,
            addr_space,
            entry: VirtAddr::new(0),
            state: ThreadState::Inactive,
            pending_msg: None,
            pending_from: None,
            spawner,
            exit: None,
        }
    }
}
