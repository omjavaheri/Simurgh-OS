//! ============================================================================
//! kernel-mm
//!
//! Purpose: the memory-management *mechanism* of the Simurgh microkernel —
//! `UntypedMemory` (physical RAM as a capability), `retype` (turning untyped
//! memory into typed kernel objects), and address-space `map`/`unmap`. No
//! allocation policy lives here: how the machine's RAM is divided among
//! services is decided by the Root Task in layer 3 (02-Microkernel-Layer.md
//! §3 — "سیاست تخصیص حافظه در کرنل نیست، فقط مکانیزم است").
//!
//! Architecture reference: 02-Microkernel-Layer.md §3 (Memory Management,
//! UntypedMemory / retype / map / unmap), §6 (`Retype`, `Map` syscalls),
//! and §2 (memory is a capability — the seL4 model).
//!
//! Position in the system: linked into the one privileged kernel binary
//! with `hal/*` (REPO-Simurgh-OS.md §6). Consumed by `kernel-core`, which
//! owns the `UntypedMemory` pool built from the boot `HardwareManifestRaw`
//! and calls `retype` / `AddressSpace::map` from the syscall dispatcher.
//! Reuses `hal_core::{PhysAddr, VirtAddr, MapPermissions}` rather than
//! defining parallel address types.
//!
//! Safety/invariants:
//!   - An `UntypedMemory` hands out strictly increasing, non-overlapping
//!     sub-ranges (bump watermark); it never reuses freed space (freeing
//!     untyped memory means revoking the whole region and re-retyping —
//!     02-Microkernel-Layer.md §3).
//!   - An `AddressSpace` never holds two mappings whose virtual ranges
//!     overlap, and never a single mapping that is both writable and
//!     executable (W^X).
//!   - No heap: `AddressSpace` mappings live in a fixed-capacity array.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod object_type;
pub mod untyped;
pub mod address_space;

pub use address_space::{AddressSpace, Mapping};
pub use object_type::{object_size_bytes, KernelObjectType};
pub use untyped::{RetypeGrant, UntypedMemory};

/// The base page size the kernel assumes for all three target
/// architectures (4 KiB — see `hal_core::MemoryBootstrap::base_page_size_bytes`,
/// which returns this on x86_64/aarch64/riscv64). Exposed here as a
/// constant because `retype` and `AddressSpace` need it pervasively and
/// threading a `&dyn MemoryBootstrap` purely to read a constant that is the
/// same on every supported architecture would add noise without value.
pub const PAGE_SIZE: usize = 4096;

/// Errors from memory-management operations. Flat and `Copy`, same
/// rationale as `hal_core::HalError` / `kernel_cap::CapTableError`: the
/// syscall dispatcher maps these straight to a `SyscallError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmError {
    /// An `UntypedMemory` region does not have enough space left to
    /// satisfy a `retype` / `alloc` request.
    OutOfMemory,
    /// A requested alignment was zero or not a power of two.
    BadAlignment,
    /// A `retype` asked for zero objects.
    ZeroCount,
    /// An address or size computation overflowed `u64` / `usize`.
    Overflow,
    /// A `map` request was not page-aligned in address or length.
    Unaligned,
    /// A `map` request would overlap an existing mapping in the same
    /// address space.
    MappingOverlap,
    /// A `map` request asked for a writable *and* executable mapping
    /// (W^X violation).
    WriteExecute,
    /// `unmap` / `translate` referenced a virtual address with no mapping.
    NotMapped,
    /// An `AddressSpace`'s fixed mapping capacity is exhausted.
    AddressSpaceFull,
    /// The software model accepted a `map`, but installing the real
    /// hardware page-table entries (`hal_core::HalInterface::map_range`)
    /// failed — the page-table scratch-frame pool is exhausted, or the
    /// architecture rejected the request (e.g. a superpage leaf already
    /// covers the range). Not raised when NO pool is installed at all
    /// (x86_64 / aarch64, MVP): that case is a silent software-model-only
    /// `Map`, since those architectures never claimed to enforce it in
    /// hardware yet. The caller (`kernel-core`'s `do_map`) rolls the
    /// software-model mapping back before returning this, so the two
    /// never drift.
    HardwareMapFailed,
}
