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
//! `KernelState` sized from these constants is ~0.25-0.5 MB — too large
//! for the real kernel's own 64 KiB boot stack to build by value.
//! Resolved: `KernelState::init_global` builds it in a `.bss` `static`
//! (zero-initialized at compile time, never moved through a stack
//! frame) and is the ONLY constructor the bare-metal boot path uses;
//! `from_boot_info`'s own by-value constructor stays as the host-test
//! convenience path, where a stack frame this size is unremarkable.
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
/// Kept modest for the MVP so the whole `KernelState` stays a manageable
/// size (see the module doc comment on why that matters — resolved by
/// `KernelState::init_global`'s own `.bss` static, but still worth
/// keeping in check as new fixed-capacity tables are added).
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

/// Maximum `SharedRegion` objects (§5.2).
pub const MAX_SHARED_REGIONS: usize = 32;

/// Maximum `MmioRegion` objects (03 §2.1, §5.1). One per device the boot-
/// time HAL peripheral scan discovers; matches
/// `hal_manifest::raw::MAX_PERIPHERAL_DEVICES`.
pub const MAX_MMIO_REGIONS: usize = hal_manifest::raw::MAX_PERIPHERAL_DEVICES;

/// Number of hardware IRQ lines the kernel's IRQ->Notification binding
/// table can track simultaneously (03 §2.1: one binding per granted
/// driver). Set well above `MAX_MMIO_REGIONS` since a real platform's IRQ
/// numbering is sparse, not a dense 0..N matching device count.
pub const MAX_IRQ_BINDINGS: usize = 64;

/// Blocked-thread queue depth on each endpoint (the `Q` of `Endpoint`).
pub const ENDPOINT_QUEUE: usize = 8;

/// Waiter-list depth on each notification (the `W` of `Notification`).
pub const NOTIF_WAITERS: usize = 8;

/// Interactive-mode scheduler quantum in nanoseconds — 3 ms, mid-range of
/// 02-Microkernel-Layer.md §4's stated ~1–4 ms. `kernel-arch-glue` arms
/// the HAL timer with this for interactive threads.
pub const INTERACTIVE_QUANTUM_NS: u64 = 3_000_000;
