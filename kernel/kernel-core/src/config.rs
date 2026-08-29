//! ============================================================================
//! config.rs
//!
//! Purpose: the compile-time capacity constants that size every
//! fixed-capacity table in `KernelState`. Gathered in one place so the
//! kernel's total static memory footprint is auditable at a glance
//! (02-Microkernel-Layer.md §1.1 — a bounded, analysable kernel).
//!
//! Architecture reference: 02-Microkernel-Layer.md §3 (object model), §6
//! (small syscall/object surface), IMPLEMENTATION-PLAN.md D1/D2 (no heap;
//! array-backed object tables).
//!
//! Position in the system: consumed by `state.rs` (table sizes) and
//! `kernel-arch-glue` (scheduler quantum). Tuning these is a
//! configuration change, not an interface change.
//!
// TODO(omid): `KernelState` sized from these constants is ~0.5 MB and is
// currently returned by value from `from_boot_info`. Before running the
// real kernel on a constrained boot stack it should be placed in a `static`
// (via `MaybeUninit` + a one-time init), not moved through a stack frame.
//! ============================================================================

/// Saved-register-context width, in bytes. Matches every architecture
/// crate's own `*_CONTEXT_BYTES` (all three are 160 — 16 GPRs + PC + flags
/// + address-space register, 16-byte aligned with headroom) and the
/// architecture-erased `hal_core::HAL_CONTEXT_BYTES` the `HalInterface`
/// context-switch primitive works in.
pub const CONTEXT_BYTES: usize = 160;

// Compile-time check: the kernel's context width must equal the one the
// HAL's architecture-erased `context_switch` uses, or every switch would
// read/write the wrong number of bytes.
const _: () = assert!(CONTEXT_BYTES == hal_core::HAL_CONTEXT_BYTES);

/// Maximum thread control blocks. Also the `NT` bound of the scheduler
/// entity table; a `ThreadId` is an index `< MAX_THREADS`.
///
/// Kept modest for the MVP so the whole `KernelState` is ~0.25 MB and
/// safe to build on a constrained stack (see the module TODO); raise it
/// once `KernelState` lives in a `static`.
pub const MAX_THREADS: usize = 96;

/// Maximum concurrent synchronous-IPC chain groups (02-Microkernel-Layer.md §4.3).
pub const MAX_CHAIN_GROUPS: usize = 24;

/// Maximum capability spaces (roughly "processes" — each layer-3 service
/// plus the Root Task).
pub const MAX_CAP_SPACES: usize = 16;

/// Capability slots per capability space (the `N` of each `CapTable`).
pub const CAP_SLOTS_PER_SPACE: usize = 96;

/// Maximum address spaces (one per `PageTable` root object).
pub const MAX_ADDR_SPACES: usize = 24;

/// Distinct virtual mappings per address space (the `M` of each
/// `AddressSpace`).
pub const MAPPINGS_PER_SPACE: usize = 32;

/// Maximum `UntypedMemory` objects. The boot path creates one per usable
/// firmware memory region (`HardwareManifestRaw` reports up to
/// `hal_manifest::raw::MAX_MEMORY_REGIONS` = 64), and `Retype`-into-untyped
/// can create more, so this is set above the firmware ceiling.
pub const MAX_UNTYPED: usize = 80;

/// Maximum `Endpoint` objects.
pub const MAX_ENDPOINTS: usize = 48;

/// Maximum `Notification` objects.
pub const MAX_NOTIFICATIONS: usize = 48;

/// Blocked-thread queue depth on each endpoint (the `Q` of `Endpoint`).
pub const ENDPOINT_QUEUE: usize = 8;

/// Waiter-list depth on each notification (the `W` of `Notification`).
pub const NOTIF_WAITERS: usize = 8;

/// Interactive-mode scheduler quantum in nanoseconds — 3 ms, mid-range of
/// 02-Microkernel-Layer.md §4's stated ~1–4 ms. `kernel-arch-glue` arms
/// the HAL timer with this for interactive threads.
pub const INTERACTIVE_QUANTUM_NS: u64 = 3_000_000;
