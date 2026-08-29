//! ============================================================================
//! ids.rs
//!
//! Purpose: the small integer newtypes that name things inside the kernel —
//! capability slots and each kind of kernel object. Kept in `kernel-cap`
//! (the lowest `kernel/*` crate) so every other kernel crate can share one
//! definition without a dependency cycle.
//!
//! Architecture reference: 02-Microkernel-Layer.md §2 (object references),
//! §3 (object kinds), §4.3 (`ChainGroupId`).
//!
//! Position in the system: `kernel-mm`, `kernel-ipc`, `kernel-sched`, and
//! `kernel-core` all use these. A user-space process never sees them
//! directly — it only ever holds `CapId`s into its own capability space,
//! and the kernel resolves those to object ids internally.
//!
//! Safety/invariants: every id is an index into a fixed-capacity table
//! owned by `kernel-core` (IMPLEMENTATION-PLAN.md D2). `u32` is deliberate:
//! four billion slots per table is far beyond any real configuration, and a
//! 32-bit id keeps `Capability` and IPC message words compact.
//! ============================================================================

/// Declares a `#[repr(transparent)]` `u32` newtype with the common
/// constructor/accessor pair. A macro rather than hand-repeating the same
/// six-line block for eight ids — every generated type has identical
/// semantics (an index into some fixed-capacity kernel table), so a single
/// definition keeps them provably consistent.
macro_rules! kernel_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[repr(transparent)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u32);

        impl $name {
            /// Wraps a raw table index.
            pub const fn new(index: u32) -> Self {
                Self(index)
            }

            /// The raw table index.
            pub const fn as_u32(self) -> u32 {
                self.0
            }

            /// The raw table index as `usize`, for slicing the backing
            /// array.
            pub const fn as_usize(self) -> usize {
                self.0 as usize
            }
        }
    };
}

kernel_id! {
    /// Index into a `CapabilitySpace` — i.e. one capability slot as seen by
    /// a particular process. Syscall arguments that reference an object
    /// (`02-Microkernel-Layer.md §6`) are `CapId`s, resolved against the
    /// calling thread's cap space.
    CapId
}

kernel_id! {
    /// A kind-local object id: an index into one of `kernel-core`'s object
    /// tables (which table is decided by the accompanying `KernelObjectKind`
    /// in an `ObjectRef`).
    ObjectId
}

kernel_id! {
    /// Id of a `ThreadControlBlock` object (02-Microkernel-Layer.md §3).
    ThreadId
}

kernel_id! {
    /// Id of an `Endpoint` object — a synchronous IPC rendezvous point
    /// (02-Microkernel-Layer.md §5.1).
    EndpointId
}

kernel_id! {
    /// Id of a `Notification` object — an asynchronous signal
    /// (02-Microkernel-Layer.md §5.1).
    NotificationId
}

kernel_id! {
    /// Id of an `UntypedMemory` object — a physical range awaiting `retype`
    /// (02-Microkernel-Layer.md §3).
    UntypedId
}

kernel_id! {
    /// Id of a `PageTable` object / address-space root (02-Microkernel-Layer.md §6).
    PageTableId
}

kernel_id! {
    /// Id of a `CapabilitySpace` object — a process's capability table
    /// (02-Microkernel-Layer.md §3).
    CapSpaceId
}

kernel_id! {
    /// Id of a scheduler `ChainGroup` — the set of threads participating in
    /// one synchronous IPC chain, charged a shared `vruntime`
    /// (02-Microkernel-Layer.md §4.3).
    ChainGroupId
}
