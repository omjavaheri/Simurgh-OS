//! ============================================================================
//! object_type.rs
//!
//! Purpose: the `KernelObjectType` enum used by the `Retype` syscall
//! (02-Microkernel-Layer.md §6) and the per-type physical-memory
//! reservation each retyped object costs against its backing
//! `UntypedMemory`.
//!
//! Architecture reference: 02-Microkernel-Layer.md §3 (`KernelObjectType`
//! variant list) and §6 (`Retype { untyped, target_type, count }`).
//!
//! Position in the system: `kernel-core` translates a user `Retype`
//! request into `UntypedMemory::retype(kind, count)` here, then pairs the
//! returned physical range with freshly allocated slots in the matching
//! static object table.
//!
//! Safety/invariants: `object_size_bytes` is always a non-zero multiple of
//! the base page size, so retyped ranges are always page-aligned and can be
//! mapped directly.
//! ============================================================================

use crate::PAGE_SIZE;
use kernel_cap::KernelObjectKind;

/// What an `UntypedMemory` region can be retyped into. Exactly the set from
/// 02-Microkernel-Layer.md §3.
///
/// Possible values and the object each produces:
/// - `Untyped`: split one `UntypedMemory` into `count` smaller
///   `UntypedMemory` regions (so the Root Task can sub-divide the RAM it
///   received before handing pieces to services — §3: "Root Task مسئول
///   تقسیم این حافظه بین سرویس‌ها است").
/// - `PageTable`: one page-table node / address-space root. One frame.
/// - `ThreadControlBlock`: one schedulable thread's kernel record.
/// - `Endpoint`: one synchronous IPC rendezvous point (§5.1).
/// - `Notification`: one asynchronous signal object (§5.1).
/// - `CapabilitySpace`: one process capability table. Sized at one frame
///   in this MVP model (the table's slot array itself lives in
///   `kernel-core` static storage — IMPLEMENTATION-PLAN.md D2 — so the
///   frame here is the resource-accounting charge, not the literal
///   backing store yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelObjectType {
    /// Sub-divide into smaller `UntypedMemory` regions.
    Untyped,
    /// A page-table node / address-space root.
    PageTable,
    /// A thread control block.
    ThreadControlBlock,
    /// A synchronous IPC endpoint.
    Endpoint,
    /// An asynchronous notification object.
    Notification,
    /// A process capability table.
    CapabilitySpace,
}

impl KernelObjectType {
    /// Maps to the `kernel-cap` object kind a capability to the retyped
    /// object will carry. `Untyped` maps to `UntypedMemory` (the result is
    /// still untyped, just smaller).
    pub const fn as_object_kind(self) -> KernelObjectKind {
        match self {
            Self::Untyped => KernelObjectKind::UntypedMemory,
            Self::PageTable => KernelObjectKind::PageTable,
            Self::ThreadControlBlock => KernelObjectKind::ThreadControlBlock,
            Self::Endpoint => KernelObjectKind::Endpoint,
            Self::Notification => KernelObjectKind::Notification,
            Self::CapabilitySpace => KernelObjectKind::CapabilitySpace,
        }
    }
}

/// Physical bytes one object of `kind` reserves from its backing
/// `UntypedMemory` when retyped.
///
/// All values are a multiple of `PAGE_SIZE` so retyped ranges are always
/// page-aligned (invariant relied on by `AddressSpace::map`). The concrete
/// numbers are deliberately generous, boot-time-stable choices for the MVP;
/// tightening them once the real object layouts are pinned down is a
/// `refactor:` follow-up that does not change the retype interface.
///
/// For `KernelObjectType::Untyped`, this returns `PAGE_SIZE` — the minimum
/// granularity a sub-divided untyped region is rounded to; `retype` with
/// `Untyped` additionally requires the caller to pass the desired child
/// size (see `UntypedMemory::retype`).
pub const fn object_size_bytes(kind: KernelObjectType) -> usize {
    match kind {
        // One frame minimum granularity for a sub-divided untyped region.
        KernelObjectType::Untyped => PAGE_SIZE,
        // One frame per page-table node.
        KernelObjectType::PageTable => PAGE_SIZE,
        // Generous single frame per TCB (register context + sched fields
        // fit comfortably; see IMPLEMENTATION-PLAN.md D1).
        KernelObjectType::ThreadControlBlock => PAGE_SIZE,
        // Endpoints and notifications are tiny, but page granularity keeps
        // every retyped range independently mappable/uncacheable if ever
        // needed, and avoids sub-page free-space tracking.
        KernelObjectType::Endpoint => PAGE_SIZE,
        KernelObjectType::Notification => PAGE_SIZE,
        // One frame charge per cap space (see enum doc).
        KernelObjectType::CapabilitySpace => PAGE_SIZE,
    }
}
