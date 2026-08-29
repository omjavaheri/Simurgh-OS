//! ============================================================================
//! kernel-cap
//!
//! Purpose: the capability model at the heart of the Simurgh microkernel's
//! security design (02-Microkernel-Layer.md §2). Every resource — physical
//! memory, a device, an IPC port, a HAL-Direct token — is named by an
//! unforgeable `Capability`, never by an ambient UID/GID/permission. This
//! crate defines: the `Capability` value itself, its `CapabilityRights`, the
//! `KernelObjectKind`/`ObjectId` reference model, and the Capability
//! Derivation Tree (CDT) plus revocation.
//!
//! Architecture reference: 02-Microkernel-Layer.md §2 (Capability model) and
//! §1.1 (formal-verification readiness: the CDT deliberately mirrors seL4's
//! proven structure, and grant/revoke carry pre/post-condition doc comments
//! that will become proof annotations later).
//!
//! Position in the system: linked into the one privileged kernel binary with
//! `hal/*` and the rest of `kernel/*` (REPO-Simurgh-OS.md §6); consumed by
//! `kernel-core` (syscall dispatch: `CapGrant`, `CapRevoke`), `kernel-mm`
//! (memory objects are capabilities), `kernel-ipc` (endpoint/notification
//! capabilities), and `kernel-sched` (thread ids). Never touched directly by
//! user space — layer 3+ reaches capabilities only through the syscall
//! boundary in `kernel-core` (02-Microkernel-Layer.md §0).
//!
//! Safety/invariants: no heap. All state is fixed-capacity and array-backed
//! (IMPLEMENTATION-PLAN.md D1). A `CapId` is an index into one `CapTable`; a
//! capability is valid iff its slot is occupied AND every ancestor slot up to
//! a root is still occupied (revocation clears whole subtrees — see
//! `CapTable::revoke`).
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod ids;
pub mod rights;
pub mod cdt;

pub use cdt::{CapSlot, CapTable, CapTableError};
pub use ids::{
    CapId, CapSpaceId, ChainGroupId, EndpointId, NotificationId, ObjectId, PageTableId, ThreadId,
    UntypedId,
};
pub use rights::CapabilityRights;

// ============================================================================
// Kernel object reference (02-Microkernel-Layer.md §2 / §3)
// ============================================================================

/// The kinds of first-class kernel object a `Capability` can name.
///
/// Exactly the set from 02-Microkernel-Layer.md §3 (`KernelObjectType`).
/// Possible values and their meaning:
/// - `UntypedMemory`: a contiguous physical memory range not yet given a
///   type. The only way memory enters the system: at boot the Root Task
///   receives the machine's RAM as `UntypedMemory` capabilities and
///   `retype`s them into the concrete kinds below (§3). Rights on it gate
///   who may `retype` it.
/// - `PageTable`: one level of a hardware page-table hierarchy, or an
///   address-space root. `map`/`unmap` operate through a capability to one
///   of these (§6 `Map`).
/// - `ThreadControlBlock`: the kernel's record for one schedulable thread
///   (register context lives in `kernel-core`'s TCB; scheduling metadata in
///   `kernel-sched`). A capability to a TCB is required to start/suspend it
///   or grant caps into its space (§6 `CapGrant { target_thread, .. }`).
/// - `Endpoint`: a synchronous IPC rendezvous point (§5.1). A capability to
///   an endpoint, with `WRITE`, lets a thread `Send`/`Call`; with `READ`,
///   `Recv`.
/// - `Notification`: an asynchronous signal object (§5.1) — a word of
///   sticky signal bits plus a wait queue.
/// - `CapabilitySpace`: the per-process table of capabilities itself (§3).
///   A thread's `CapSpaceId` selects which `CapabilitySpace` its `CapId`
///   arguments are resolved against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelObjectKind {
    /// Untyped physical memory awaiting `retype` (02-Microkernel-Layer.md §3).
    UntypedMemory,
    /// A page-table node / address-space root (§6 `Map`).
    PageTable,
    /// A thread control block (§3).
    ThreadControlBlock,
    /// A synchronous IPC endpoint (§5.1).
    Endpoint,
    /// An asynchronous notification object (§5.1).
    Notification,
    /// A process's capability table (§3).
    CapabilitySpace,
}

/// An unforgeable reference to one kernel object: its kind plus its
/// type-local id (an index into the matching `kernel-core` object table).
///
/// This is the `object_ref: KernelObjectRef` field of §2's `Capability`
/// struct. Kind and id together are the identity; two capabilities with the
/// same `ObjectRef` name the same object (possibly with different rights or
/// badge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRef {
    /// Which object table `id` indexes.
    pub kind: KernelObjectKind,
    /// Index into that table. `ObjectId` is a plain `u32` newtype; the
    /// kernel object tables are fixed-capacity (IMPLEMENTATION-PLAN.md D2).
    pub id: ObjectId,
}

impl ObjectRef {
    /// Constructs an object reference. `const` so boot-time capability
    /// wiring in `kernel-core` can build the Root Task's initial space
    /// without a runtime constructor call.
    pub const fn new(kind: KernelObjectKind, id: ObjectId) -> Self {
        Self { kind, id }
    }
}

// ============================================================================
// Capability (02-Microkernel-Layer.md §2, verbatim shape)
// ============================================================================

/// A capability = an unforgeable reference to a kernel object + a set of
/// rights + a badge.
///
/// Mirrors §2's `Capability { object_ref, rights, badge }`. `Copy` and
/// heap-free: a capability is a small value the kernel copies between table
/// slots during `derive`/`grant`, never a heap object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// The object this capability authorizes access to.
    pub object: ObjectRef,
    /// What the holder may do with `object`. Rights can only be narrowed
    /// when deriving a child capability, never widened (`CapTable::derive_child`).
    pub rights: CapabilityRights,
    /// A caller-chosen tag (§2: "شناسه‌ی دلخواه برای تفکیک درخواست‌ها هنگام
    /// IPC"). The kernel never interprets the badge; it is delivered
    /// alongside IPC messages so a server can tell which client/endpoint a
    /// request came in on. Set once when a capability is minted/badged and
    /// immutable thereafter.
    pub badge: u64,
}

impl Capability {
    /// A capability with all rights and a zero badge, for boot-time wiring
    /// of the Root Task's initial objects in `kernel-core` (§8.1). Ordinary
    /// code derives narrower capabilities from these roots.
    pub const fn full(object: ObjectRef) -> Self {
        Self {
            object,
            rights: CapabilityRights::all(),
            badge: 0,
        }
    }

    /// Returns a copy of this capability with `badge` set. Used when a
    /// server hands a client an endpoint capability stamped with a value
    /// that identifies the client on later requests (§2). Panics in debug
    /// if the capability already carries a non-zero badge — re-badging is a
    /// caller error, not a supported operation (badges are write-once).
    pub fn with_badge(self, badge: u64) -> Self {
        debug_assert!(
            self.badge == 0,
            "re-badging an already-badged capability is not allowed (badges are write-once)"
        );
        Self { badge, ..self }
    }

    /// True iff this capability carries every right in `needed`. The
    /// syscall dispatcher checks this before performing any privileged
    /// action on the named object (02-Microkernel-Layer.md §6).
    pub fn allows(&self, needed: CapabilityRights) -> bool {
        self.rights.contains(needed)
    }
}
