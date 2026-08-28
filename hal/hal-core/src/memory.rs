//! ============================================================================
//! memory.rs
//!
//! Memory Bootstrap, per 01-HAL-Layer.md section 3.2 and the trait
//! pre-draft in section 4:
//!
//!   pub trait MemoryBootstrap {
//!       fn physical_memory_map(&self) -> &[MemoryRegion];
//!       unsafe fn setup_identity_mapping(&self, region: MemoryRegion);
//!       fn iommu_present(&self) -> bool;
//!   }
//!
//! Responsibilities per section 3.2:
//!   - reading the firmware-provided memory map (UEFI Memory Map / e820
//!     on x86_64; Device Tree or ACPI on ARM64; Device Tree, mandatory
//!     per the SBI spec, on RISC-V)
//!   - bootstrapping only the MINIMAL initial page tables (identity
//!     mapping + kernel mapping); full virtual memory management is the
//!     microkernel's job (layer 2, section 3: UntypedMemory, retype,
//!     map/unmap)
//!   - a uniform abstraction over MMU/IOMMU across all three
//!     architectures (SMMU on ARM, IOMMU on x86, IOPMP on RISC-V)
//! ============================================================================

use crate::error::HalError;

// Re-export the raw memory region type directly from hal-manifest,
// rather than defining a second, parallel `MemoryRegion` struct here.
// This is deliberate: at the point MemoryBootstrap runs (before any
// heap exists — see hal-manifest, section 9), the raw, `#[repr(C)]`,
// no-heap representation IS the correct representation to use. Having
// hal-core and hal-manifest agree on a single type for this avoids
// a redundant conversion step during the hottest, most fragile part of
// boot (before an allocator is even available to convert into).
pub use hal_manifest::raw::{MemoryRegionKindRaw as MemoryRegionKind, MemoryRegionRaw as MemoryRegion};

// ============================================================================
// Physical / virtual address newtypes
//
// Defined here (not in hal-manifest, which is pure data) because these
// are used throughout hal-core's trait surface (MemoryBootstrap here,
// and later HalDirectAccess in the hal-direct crate, per section 5's
// `map_mmio_region(...) -> Result<VirtAddr, HalError>`). Kept as plain
// newtypes over `usize` rather than raw `usize` everywhere so that a
// physical address can never be silently passed where a virtual one is
// expected, or vice versa — a common and dangerous class of bug in
// low-level memory code.
// ============================================================================

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysAddr(pub usize);

impl PhysAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Aligns this address down to the given power-of-two alignment.
    /// Used by architecture code when carving out identity-mapped
    /// regions that must start on a page boundary.
    pub const fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    pub const fn align_up(self, align: usize) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtAddr(pub usize);

impl VirtAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    pub const fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    pub const fn align_up(self, align: usize) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }
}

// ============================================================================
// Mapping permissions for the minimal early page tables (section 3.2:
// "فقط identity mapping حداقلی + kernel mapping")
// ============================================================================

/// Permission bits for the minimal, early-boot page table entries HAL
/// sets up. This is intentionally a small, coarse set — full virtual
/// memory permission management (copy-on-write, guard pages, per-
/// process address spaces) belongs to the microkernel (layer 2), not
/// here. HAL only ever needs to express "how should this identity- or
/// kernel-mapped region behave" for the handful of regions it maps
/// before handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// Device/MMIO memory must never be cached the way normal RAM is
    /// (stale reads of a hardware register would be a correctness bug,
    /// not just a performance one). This flag tells the architecture
    /// implementation to use the appropriate uncached/device memory
    /// attribute (e.g. UC on x86_64 PAT, Device-nGnRE on ARM64 MAIR,
    /// the PMA "IO" region attribute pattern on RISC-V).
    pub device_uncached: bool,
}

impl MapPermissions {
    /// Read-write-execute is intentionally NOT provided as a preset:
    /// per the workspace-wide W^X discipline this project follows,
    /// callers should always ask for exactly the permissions a region
    /// needs, never all three at once.
    pub const KERNEL_CODE: Self = Self {
        readable: true,
        writable: false,
        executable: true,
        device_uncached: false,
    };

    pub const KERNEL_DATA: Self = Self {
        readable: true,
        writable: true,
        executable: false,
        device_uncached: false,
    };

    pub const KERNEL_RODATA: Self = Self {
        readable: true,
        writable: false,
        executable: false,
        device_uncached: false,
    };

    pub const DEVICE_MMIO: Self = Self {
        readable: true,
        writable: true,
        executable: false,
        device_uncached: true,
    };
}

// ============================================================================
// MemoryBootstrap trait (section 4 pre-draft, extended with error
// handling and explicit permissions since the pre-draft signatures were
// intentionally sketched at a high level in the spec)
// ============================================================================

/// Per-architecture memory bootstrap abstraction. Implemented once per
/// architecture crate (`hal-x86_64::memory::Memory`,
/// `hal-arm64::memory::Memory`, `hal-riscv64::memory::Memory`).
///
/// Every method here operates on PHYSICAL memory description and
/// MINIMAL early mapping only. Nothing in this trait allocates from a
/// heap — the returned slice from `physical_memory_map` borrows
/// directly from the architecture implementation's own fixed-capacity
/// storage (ultimately backed by `hal_manifest::raw::HardwareManifestRaw`,
/// per hal-manifest section 9), never from `alloc`.
pub trait MemoryBootstrap {
    /// Returns the physical memory map as reported by firmware, already
    /// parsed and classified into `MemoryRegion` (`MemoryRegionRaw`)
    /// entries — UEFI Memory Map / e820 on x86_64; Device Tree or ACPI
    /// on ARM64 (server-class ARM64 firmware increasingly reports both,
    /// per 01-HAL-Layer.md section 10 — HAL prefers ACPI when a valid
    /// RSDP is present); Device Tree, mandatory under the SBI spec, on
    /// RISC-V.
    ///
    /// The returned slice's lifetime is tied to `&self`: architecture
    /// implementations own this data directly (typically as part of
    /// their own boot-time `HardwareManifestRaw`), so no copy is made
    /// here.
    fn physical_memory_map(&self) -> &[MemoryRegion];

    /// Whether an IOMMU/SMMU/IOPMP was detected for the current core's
    /// address space. Per section 3.2: "Abstraction یکسان برای
    /// MMU/IOMMU روی هر سه معماری (SMMU در ARM، IOMMU در x86، IOPMP در
    /// RISC-V)".
    ///
    /// This is a coarse yes/no check at the HAL level; the actual
    /// per-device IOMMU domain setup (used by, e.g., the layer 5 Linux
    /// Compat Runtime for GPU passthrough, per 05-Legacy-Compat-
    /// Applications-Layer.md section 3.2) is a layer 3 Device Manager
    /// concern built on top of this primitive, not something HAL itself
    /// manages beyond detection.
    fn iommu_present(&self) -> bool;

    /// Establishes a minimal mapping for `region` with the given
    /// `perms`: either an identity mapping (virtual address == physical
    /// address, used for the earliest boot code before the kernel's own
    /// higher-half mapping is live) or a fixed kernel-space mapping,
    /// depending on how the architecture implementation interprets the
    /// region and permissions given.
    ///
    /// Per section 3.2: "راه‌اندازی اولیه‌ی page table (فقط identity
    /// mapping حداقلی + kernel mapping؛ مدیریت کامل virtual memory
    /// مسئولیت لایه ۲ است)" — this method is explicitly NOT a general
    /// purpose virtual memory manager. It is called a small, bounded
    /// number of times during early boot (kernel image, boot info
    /// structures, this manifest itself, essential MMIO for early
    /// serial output) — never as an ongoing service for layer 3+.
    ///
    /// # Safety
    /// The caller must guarantee:
    ///   - `region` describes physical memory that is actually backed
    ///     by RAM or a valid MMIO range (mapping a bogus physical range
    ///     is undefined behavior at the hardware level on most
    ///     architectures).
    ///   - `region` does not overlap a previously mapped region with
    ///     incompatible permissions (e.g. mapping the same physical
    ///     page as both `KERNEL_CODE` and `KERNEL_DATA` writable is a
    ///     W^X violation the caller, not this function, is responsible
    ///     for avoiding).
    ///   - This is called before any other code on this core depends on
    ///     `region`'s virtual address being valid.
    unsafe fn setup_identity_mapping(
        &self,
        region: MemoryRegion,
        perms: MapPermissions,
    ) -> Result<VirtAddr, HalError>;

    /// Returns the smallest page size supported by this architecture's
    /// MMU (4 KiB on all three target architectures at the base level;
    /// exposed as a method rather than a constant so upper layers never
    /// need `#[cfg(target_arch)]` to reason about it — per the section 4
    /// closing rule).
    fn base_page_size_bytes(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_manifest::raw::MemoryRegionRaw;

    // ------------------------------------------------------------------
    // Mock hardware implementation, per section 8.4.
    // ------------------------------------------------------------------

    struct MockMemory {
        regions: [MemoryRegion; 2],
        iommu: bool,
    }

    impl MemoryBootstrap for MockMemory {
        fn physical_memory_map(&self) -> &[MemoryRegion] {
            &self.regions
        }

        fn iommu_present(&self) -> bool {
            self.iommu
        }

        unsafe fn setup_identity_mapping(
            &self,
            region: MemoryRegion,
            _perms: MapPermissions,
        ) -> Result<VirtAddr, HalError> {
            // Mock behavior: identity mapping means virt == phys.
            Ok(VirtAddr::new(region.base_addr as usize))
        }

        fn base_page_size_bytes(&self) -> usize {
            4096
        }
    }

    fn mock_memory() -> MockMemory {
        // `::new` rather than struct-literal + `..ZERO`: `MemoryRegionRaw`'s
        // padding field is private to hal-manifest, so functional record
        // update across that crate boundary is E0451.
        MockMemory {
            regions: [
                MemoryRegionRaw::new(0, 0x1000_0000, MemoryRegionKind::Reserved, false),
                MemoryRegionRaw::new(0xFEE0_0000, 0x1000, MemoryRegionKind::Reserved, false),
            ],
            iommu: true,
        }
    }

    #[test]
    fn physical_memory_map_returns_all_regions() {
        let mem = mock_memory();
        assert_eq!(mem.physical_memory_map().len(), 2);
    }

    #[test]
    fn identity_mapping_returns_same_address() {
        let mem = mock_memory();
        let region = mem.physical_memory_map()[0];
        let virt = unsafe { mem.setup_identity_mapping(region, MapPermissions::KERNEL_DATA) }
            .unwrap();
        assert_eq!(virt.as_usize(), region.base_addr as usize);
    }

    #[test]
    fn phys_addr_alignment_rounds_correctly() {
        let addr = PhysAddr::new(0x1001);
        assert_eq!(addr.align_down(0x1000).as_usize(), 0x1000);
        assert_eq!(addr.align_up(0x1000).as_usize(), 0x2000);
    }

    #[test]
    fn device_mmio_permissions_are_uncached() {
        assert!(MapPermissions::DEVICE_MMIO.device_uncached);
        assert!(!MapPermissions::KERNEL_CODE.device_uncached);
    }
}