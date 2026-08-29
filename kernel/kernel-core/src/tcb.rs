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
}

impl Tcb {
    /// Creates an `Inactive` TCB. `kernel-core` sets `entry` and marks it
    /// `Runnable` when the owner starts it; the architecture layer seeds
    /// `context` with the entry point / initial stack via
    /// architecture-specific helpers before the first switch.
    pub const fn new_inactive(
        id: ThreadId,
        cap_space: CapSpaceId,
        addr_space: PageTableId,
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
        }
    }
}
