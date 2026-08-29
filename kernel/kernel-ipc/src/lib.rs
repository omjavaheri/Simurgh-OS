//! ============================================================================
//! kernel-ipc
//!
//! Purpose: the microkernel's IPC primitives. Because every driver,
//! filesystem, and network stack is a separate user-space process
//! (02-Microkernel-Layer.md §0), IPC cost is the dominant term in overall
//! system performance (§5) — so this crate is the one most worth
//! optimising. It provides:
//!   - `Endpoint`: synchronous rendezvous for small, register-sized
//!     messages (`ipc_call`/`Send`/`Recv`), zero copy (§5.1).
//!   - `Notification`: asynchronous sticky-bit signalling (§5.1).
//!   - `SharedRegion`: a capability to a physical range, mapped into both
//!     peers for bulk zero-copy transfer of frames / AI tensors (§5.2).
//!   - `fastpath`: the hook for the L4-style IPC fast path (§5.3).
//!
//! Architecture reference: 02-Microkernel-Layer.md §5 (all of it), §6
//! (`Send`/`Recv`/`Call` syscalls), §8.2/§8.3/§8.4 (MVP acceptance: a
//! second thread + synchronous IPC; fast-path < 500 ns; proven zero-copy).
//!
//! Position in the system: linked into the one privileged kernel binary
//! with `hal/*` (REPO-Simurgh-OS.md §6). `kernel-core` owns the `Endpoint`
//! / `Notification` object tables and drives them from the syscall
//! dispatcher; `kernel-sched` is told which thread to run next when a
//! rendezvous unblocks one.
//!
//! Safety/invariants:
//!   - An `Endpoint` never has threads queued on both its send and its
//!     receive side at the same time (a rendezvous always completes
//!     immediately when the second party arrives).
//!   - Wait queues are bounded fixed-capacity arrays; enqueue past
//!     capacity is an explicit error, never UB or silent drop.
//!   - `SmallMessage` carries no pointers — only inline words — so
//!     delivering one across address spaces copies nothing that could
//!     dangle.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod message;
pub mod endpoint;
pub mod notification;
pub mod shared_region;
pub mod fastpath;

pub use endpoint::{Endpoint, EndpointError, RecvOutcome, SendOutcome};
pub use message::{SmallMessage, MSG_MAX_WORDS};
pub use notification::{Notification, NotificationError};
pub use shared_region::SharedRegion;

/// Errors from IPC operations. Flat and `Copy`, same rationale as the
/// other `kernel/*` error enums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// A wait queue (send side or receive side of an endpoint, or a
    /// notification's waiter list) is at capacity.
    QueueFull,
    /// A non-blocking `Send`/`Recv` found no peer waiting.
    WouldBlock,
    /// A message carried more words than `MSG_MAX_WORDS`.
    MessageTooLong,
    /// The referenced endpoint / notification id was invalid.
    NoSuchObject,
}
