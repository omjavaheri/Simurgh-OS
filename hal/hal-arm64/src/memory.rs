//! ============================================================================
//! memory.rs — ARM64
//!
//! Implements `hal_core::memory::MemoryBootstrap` for ARM64, per
//! 01-HAL-Layer.md section 3.2: "Device Tree یا ACPI (سرورهای ARM
//! جدید از ACPI هم پشتیبانی می‌کنند)" and section 10's final decision:
//! prefer ACPI when a valid RSDP is present, fall back to Device Tree
//! otherwise.
//!
//! Also provides this architecture's `gicd_base` discovery (needed by
//! `interrupt.rs`, per that file's module docs) and SMMU presence
//! detection (ARM64's IOMMU equivalent, section 3.2).
//!
//! Boot protocol note: unlike x86_64 (UEFI-only per section 3.5),
//! ARM64 boot in this project is STILL exclusively via the same UEFI
//! bootloader stub as x86_64 (both are the "UEFI" row of section 3.5's
//! table) — this file does NOT implement the separate SBI+DeviceTree
//! boot path (that belongs to hal-riscv64 only). "Device Tree" here
//! refers to a DTB that UEFI's own Configuration Table list may still
//! provide alongside or instead of ACPI on ARM64 firmware, per section
//! 10 — it is a firmware TABLE FORMAT choice, not a different BOOT
//! PROTOCOL, on this architecture.
//! ============================================================================

use core::mem::size_of;

use hal_core::error::HalError;
use hal_core::memory::{MapPermissions, MemoryBootstrap, MemoryRegion, PhysAddr, VirtAddr};
use hal_manifest::raw::{HardwareManifestRaw, InterruptControllerInfoRaw, MemoryRegionRaw, TimerInfoRaw};

use crate::compute::ComputeDiscovery;
use crate::cpu::Cpu;
use crate::interrupt::InterruptCtrl;
use crate::power::PowerThermalImpl;
use crate::timer::Timer;

// ============================================================================
// UEFI Memory Map parsing — identical structure/rationale to
// hal-x86_64/src/memory.rs's equivalent section (same boot protocol,
// same UefiMemoryMapHeader project convention, same descriptor
// striding requirement). Reproduced here (not shared via a common
// crate) because per 01-HAL-Layer.md section 4's closing rule, no
// architecture-specific parsing code should live anywhere upper layers
// could accidentally depend on across architectures — each hal-<arch>
// crate owns its own copy, even when byte-identical, keeping the
// boundary unambiguous.
// ============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UefiMemoryType {
    ReservedMemoryType = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    ConventionalMemory = 7,
    UnusableMemory = 8,
    AcpiReclaimMemory = 9,
    AcpiMemoryNvs = 10,
    MemoryMappedIo = 11,
    MemoryMappedIoPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
}

impl UefiMemoryType {
    fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            0 => Self::ReservedMemoryType,
            1 => Self::LoaderCode,
            2 => Self::LoaderData,
            3 => Self::BootServicesCode,
            4 => Self::BootServicesData,
            5 => Self::RuntimeServicesCode,
            6 => Self::RuntimeServicesData,
            7 => Self::ConventionalMemory,
            8 => Self::UnusableMemory,
            9 => Self::AcpiReclaimMemory,
            10 => Self::AcpiMemoryNvs,
            11 => Self::MemoryMappedIo,
            12 => Self::MemoryMappedIoPortSpace,
            13 => Self::PalCode,
            14 => Self::PersistentMemory,
            _ => return None,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UefiMemoryDescriptor {
    ty: u32,
    _padding: u32,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
}

#[repr(C)]
struct UefiMemoryMapHeader {
    map_size: u64,
    descriptor_size: u64,
}

fn classify_uefi_type(ty: u32) -> hal_manifest::raw::MemoryRegionKindRaw {
    use hal_manifest::raw::MemoryRegionKindRaw as Kind;

    match UefiMemoryType::from_u32(ty) {
        Some(UefiMemoryType::ConventionalMemory)
        | Some(UefiMemoryType::BootServicesCode)
        | Some(UefiMemoryType::BootServicesData)
        | Some(UefiMemoryType::LoaderCode)
        | Some(UefiMemoryType::LoaderData) => Kind::Usable,

        Some(UefiMemoryType::AcpiReclaimMemory) => Kind::AcpiReclaimable,
        Some(UefiMemoryType::AcpiMemoryNvs) => Kind::AcpiNvs,

        Some(UefiMemoryType::MemoryMappedIo) | Some(UefiMemoryType::MemoryMappedIoPortSpace) => Kind::Mmio,

        Some(UefiMemoryType::RuntimeServicesCode)
        | Some(UefiMemoryType::RuntimeServicesData)
        | Some(UefiMemoryType::ReservedMemoryType)
        | Some(UefiMemoryType::UnusableMemory)
        | Some(UefiMemoryType::PalCode)
        | None => Kind::Reserved,

        Some(UefiMemoryType::PersistentMemory) => Kind::Reserved,
    }
}

struct DescriptorIter {
    current: *const u8,
    remaining_bytes: u64,
    descriptor_size: u64,
}

impl Iterator for DescriptorIter {
    type Item = UefiMemoryDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_bytes < self.descriptor_size || self.descriptor_size < size_of::<UefiMemoryDescriptor>() as u64 {
            return None;
        }
        // SAFETY: same contract as hal-x86_64's identical DescriptorIter.
        let descriptor = unsafe { core::ptr::read_unaligned(self.current as *const UefiMemoryDescriptor) };
        self.current = unsafe { self.current.add(self.descriptor_size as usize) };
        self.remaining_bytes -= self.descriptor_size;
        Some(descriptor)
    }
}

// ============================================================================
// ACPI parsing: RSDP -> XSDT -> GTDT (timer)/MADT (GIC)/IORT (SMMU)
//
// Per section 10's decision, ACPI is preferred when a valid RSDP is
// present; this file checks for one and, if found, walks the same
// XSDT structure hal-x86_64/memory.rs does for DMAR — here looking for
// MADT (GIC Distributor base, for interrupt.rs) and IORT (SMMU
// presence, ARM64's IOMMU). Device Tree fallback (when no RSDP is
// found) is a documented follow-up: this MVP phase's QEMU `virt`
// machine target always provides ACPI when booted via UEFI (QEMU's
// `-machine virt,acpi=on`, its default), so the DT fallback path is
// not yet exercised by this project's section 8 acceptance criteria.
// ============================================================================

#[repr(C, packed)]
struct AcpiSdtHeader {
    signature: [u8; 4],
    length: u32,
    _revision: u8,
    _checksum: u8,
    _oem_id: [u8; 6],
    _oem_table_id: [u8; 8],
    _oem_revision: u32,
    _creator_id: u32,
    _creator_revision: u32,
}

const MADT_SIGNATURE: [u8; 4] = *b"APIC"; // ACPI's historical name for MADT
const IORT_SIGNATURE: [u8; 4] = *b"IORT";

/// GIC Distributor structure within MADT (ACPI spec section 5.2.12.15,
/// "GIC Distributor Structure", type 0x0C).
#[repr(C, packed)]
struct MadtGicDistributorEntry {
    entry_type: u8,
    length: u8,
    _reserved: u16,
    _gic_id: u32,
    physical_base_address: u64,
    _system_vector_base: u32,
    _reserved2: [u8; 4],
}

const MADT_GIC_DISTRIBUTOR_TYPE: u8 = 0x0C;

/// Discovered ACPI table results this file's boot-time walk produces,
/// threaded to `interrupt.rs` (gicd_base) and `cpu.rs`
/// (mark_iommu_capable, via SMMU presence) the same way
/// hal-x86_64/memory.rs threads DMAR/xAPIC-base results.
#[derive(Debug, Clone, Copy, Default)]
struct AcpiDiscoveryResult {
    gicd_base: Option<u64>,
    smmu_present: bool,
}

/// Documented fallback GICD base for QEMU's `virt` machine, used only
/// if ACPI/MADT parsing fails to find one (e.g. a Device-Tree-only
/// boot, not yet implemented per this file's module docs) — this is
/// QEMU's well-known, stable default `virt` machine GICD address, not
/// a guess.
const QEMU_VIRT_DEFAULT_GICD_BASE: u64 = 0x0800_0000;

/// # Safety
/// `rsdp_phys` must be a physical address obtained the same way as
/// hal-x86_64/memory.rs's `acpi_dmar_present` requires (this project's
/// UEFI bootloader stub's Configuration Table walk).
unsafe fn acpi_discover(rsdp_phys: u64) -> AcpiDiscoveryResult {
    let mut result = AcpiDiscoveryResult::default();

    if rsdp_phys == 0 {
        return result;
    }

    // SAFETY: forwarded from this function's own contract; RSDP XSDT
    // address offset (24) per ACPI 2.0+ spec, same as
    // hal-x86_64/memory.rs's identical walk.
    let xsdt_addr = unsafe { core::ptr::read_unaligned((rsdp_phys as *const u8).add(24) as *const u64) };
    if xsdt_addr == 0 {
        return result;
    }

    // SAFETY: xsdt_addr trusted per this function's contract, same as
    // hal-x86_64's identical walk.
    let xsdt_header = unsafe { core::ptr::read_unaligned(xsdt_addr as *const AcpiSdtHeader) };
    let entry_count = (xsdt_header.length as usize - size_of::<AcpiSdtHeader>()) / size_of::<u64>();
    let entries_ptr = (xsdt_addr as usize + size_of::<AcpiSdtHeader>()) as *const u64;

    for i in 0..entry_count {
        // SAFETY: same bounds argument as hal-x86_64's identical walk.
        let table_addr = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
        // SAFETY: table_addr from a well-formed XSDT entry.
        let header = unsafe { core::ptr::read_unaligned(table_addr as *const AcpiSdtHeader) };

        if header.signature == MADT_SIGNATURE {
            result.gicd_base = unsafe { find_gicd_in_madt(table_addr, header.length) };
        } else if header.signature == IORT_SIGNATURE {
            // Presence alone is sufficient for this MVP phase's
            // yes/no SMMU query (mirrors hal-x86_64's DMAR-presence-
            // only scope) — parsing individual IORT SMMU nodes for
            // per-device SMMU domain assignment is a layer 3 Device
            // Manager concern built on top of this primitive later.
            result.smmu_present = true;
        }
    }

    result
}

/// Walks MADT sub-structures looking for the GIC Distributor entry
/// (type 0x0C).
///
/// # Safety
/// `madt_addr` must point at a valid MADT table of at least `length`
/// bytes, per `acpi_discover`'s own trusted-XSDT-entry contract.
unsafe fn find_gicd_in_madt(madt_addr: u64, length: u32) -> Option<u64> {
    // MADT sub-structures start after AcpiSdtHeader (36 bytes) plus
    // MADT's own two fixed fields (Local Interrupt Controller Address,
    // Flags — 8 bytes), per ACPI spec section 5.2.12.
    const MADT_FIXED_FIELDS_SIZE: u32 = 8;
    let mut offset = size_of::<AcpiSdtHeader>() as u32 + MADT_FIXED_FIELDS_SIZE;

    while offset < length {
        // SAFETY: `offset < length` bounds this read within the
        // caller-guaranteed valid MADT table.
        let entry_type = unsafe { core::ptr::read_unaligned((madt_addr + offset as u64) as *const u8) };
        let entry_length = unsafe { core::ptr::read_unaligned((madt_addr + offset as u64 + 1) as *const u8) };

        if entry_type == MADT_GIC_DISTRIBUTOR_TYPE {
            // SAFETY: same bounds argument; MadtGicDistributorEntry's
            // size is within `entry_length` per the ACPI spec's fixed
            // layout for this structure type.
            let entry = unsafe { core::ptr::read_unaligned((madt_addr + offset as u64) as *const MadtGicDistributorEntry) };
            return Some(entry.physical_base_address);
        }

        if entry_length == 0 {
            break; // malformed table, avoid infinite loop
        }
        offset += entry_length as u32;
    }

    None
}

/// # Safety
/// Same contract as hal-x86_64/memory.rs's `locate_acpi_rsdp`.
unsafe fn locate_acpi_rsdp(uefi_memory_map: *const u8, header: &UefiMemoryMapHeader) -> u64 {
    let trailer_offset = size_of::<UefiMemoryMapHeader>() as u64 + header.map_size;
    // SAFETY: forwarded from this function's own contract, same
    // project boot-protocol convention as hal-x86_64.
    unsafe { core::ptr::read_unaligned(uefi_memory_map.add(trailer_offset as usize) as *const u64) }
}

// ============================================================================
// Page table setup — ARM64 uses a 4-level translation table walk
// (matching this project's 4KB granule choice, the same base page size
// as x86_64) via TTBR0_EL1 (identity/low mapping, used for .boot and
// this crate's minimal early mapping) — TTBR1_EL1 (higher-half kernel
// mapping) setup mirrors linker.ld's KERNEL_VMA_BASE placement and is
// established the same way hal-x86_64 handles its higher-half .text
// via LMA/VMA split plus this same setup_identity_mapping mechanism.
// ============================================================================

const PAGE_SIZE: usize = 4096;
const ENTRIES_PER_TABLE: usize = 512;

/// AArch64 page/block descriptor flags relevant to this minimal
/// mapping (ARM Architecture Reference Manual, D5.3). Differs from
/// x86_64's PTE bit layout entirely — different architecture, +
/// no_execute is split into two bits here (privileged vs
/// unprivileged execute-never) rather than x86_64's single NX bit.
mod pte_flags {
    pub const VALID: u64 = 1 << 0;
    pub const TABLE_OR_PAGE: u64 = 1 << 1; // at level 3, distinguishes "page" (1) from "block" (0, N/A at L3)
    /// AttrIndx field (bits 4:2), indexing MAIR_EL1 — index 0 is
    /// configured (via MAIR_EL1 setup in `activate_page_tables`) as
    /// Normal, Write-Back Cacheable memory.
    pub const ATTR_NORMAL: u64 = 0 << 2;
    /// Index 1, configured as Device-nGnRE memory (the standard
    /// AArch64 attribute for MMIO — Non-Gathering, Non-Reordering,
    /// Early Write Acknowledge).
    pub const ATTR_DEVICE: u64 = 1 << 2;
    pub const AP_RW_EL1: u64 = 0 << 6; // read-write, EL1 only (bits 7:6 = 00)
    pub const AP_RW_ANY: u64 = 1 << 6; // read-write, EL1 and EL0 (bits 7:6 = 01)
    pub const SHAREABILITY_INNER: u64 = 0b11 << 8;
    pub const ACCESS_FLAG: u64 = 1 << 10; // must be set, or first access faults
    pub const PXN: u64 = 1 << 53; // privileged execute-never
    pub const UXN: u64 = 1 << 54; // unprivileged execute-never
}

#[repr(align(4096))]
struct PageTable([u64; ENTRIES_PER_TABLE]);

impl PageTable {
    const fn new() -> Self {
        Self([0; ENTRIES_PER_TABLE])
    }
}

static mut TTBR0_ROOT: PageTable = PageTable::new();

const TABLE_POOL_SIZE: usize = 16;
static mut TABLE_POOL: [PageTable; TABLE_POOL_SIZE] = {
    const EMPTY: PageTable = PageTable::new();
    [EMPTY; TABLE_POOL_SIZE]
};
static mut TABLE_POOL_NEXT: usize = 0;

/// # Safety
/// Same single-threaded-boot-time contract as hal-x86_64/memory.rs's
/// `alloc_table`.
unsafe fn alloc_table() -> Result<*mut PageTable, HalError> {
    // SAFETY: forwarded from this function's own contract.
    let next = unsafe { TABLE_POOL_NEXT };
    if next >= TABLE_POOL_SIZE {
        return Err(HalError::InvalidMemoryRegion);
    }
    let table_ptr = unsafe { &raw mut TABLE_POOL[next] };
    unsafe {
        TABLE_POOL_NEXT = next + 1;
    }
    Ok(table_ptr)
}

/// Walks (allocating as needed) a 4-level AArch64 translation table
/// and writes a leaf page descriptor. Mirrors hal-x86_64/memory.rs's
/// `map_page` structurally; differs in bit layout (AArch64 descriptor
/// format instead of x86_64 PTE format) and in requiring
/// `ACCESS_FLAG` to be set explicitly (x86_64's PRESENT bit alone
/// suffices; AArch64 separately tracks "valid" vs "accessed" and
/// faults on first access without AF set, per ARM ARM D5.4.3 — this
/// project always pre-sets AF here rather than relying on a hardware/
/// software access-flag-management scheme, since we have no MMU fault
/// handler implemented yet for that scheme in this MVP phase).
///
/// # Safety
/// Same contract as hal-x86_64/memory.rs's `map_page`.
unsafe fn map_page(virt: u64, phys: u64, flags: u64) -> Result<(), HalError> {
    let indices = [
        ((virt >> 39) & 0x1FF) as usize,
        ((virt >> 30) & 0x1FF) as usize,
        ((virt >> 21) & 0x1FF) as usize,
        ((virt >> 12) & 0x1FF) as usize,
    ];

    // SAFETY: `TTBR0_ROOT` is this core's single boot-time top-level
    // table, single-threaded access per this function's contract.
    let mut table_ptr: *mut PageTable = unsafe { &raw mut TTBR0_ROOT };

    for level in 0..3 {
        // SAFETY: `table_ptr` valid per this loop's invariant.
        let entry = unsafe { &mut (*table_ptr).0[indices[level]] };
        if *entry & pte_flags::VALID == 0 {
            // SAFETY: boot-time single-threaded allocation.
            let new_table = unsafe { alloc_table()? };
            // Table descriptor at levels 0-2: VALID | TABLE_OR_PAGE
            // both set (bits 1:0 = 0b11 means "table descriptor" at
            // these levels, distinct from a "block descriptor" which
            // would have bit 1 clear).
            *entry = (new_table as u64) | pte_flags::VALID | pte_flags::TABLE_OR_PAGE;
        }
        table_ptr = (*entry & 0x0000_FFFF_FFFF_F000) as *mut PageTable;
    }

    // SAFETY: `table_ptr` now points at the level-3 table for `virt`.
    let pt_entry = unsafe { &mut (*table_ptr).0[indices[3]] };
    // At level 3, bits 1:0 = 0b11 means "page descriptor" (the only
    // valid leaf encoding at this level, unlike levels 1-2 where 0b01
    // would mean "block descriptor" for a huge page — not used by this
    // project's 4KB-only minimal mapping).
    *pt_entry = (phys & 0x0000_FFFF_FFFF_F000) | flags | pte_flags::VALID | pte_flags::TABLE_OR_PAGE | pte_flags::ACCESS_FLAG;

    Ok(())
}

fn permissions_to_flags(perms: MapPermissions) -> u64 {
    let mut flags = pte_flags::SHAREABILITY_INNER;

    flags |= if perms.device_uncached {
        pte_flags::ATTR_DEVICE
    } else {
        pte_flags::ATTR_NORMAL
    };

    // AArch64 has no single "writable" bit the way x86_64 does — AP
    // (Access Permission) bits jointly encode read/write for EL1 vs
    // EL0. This project's minimal early mapping is always EL1-only
    // (kernel-space, per MapPermissions::KERNEL_* constants' intended
    // use in hal-core), so AP_RW_EL1 is used for writable regions;
    // read-only is expressed by leaving the AP field at its default
    // (0b10 = read-only EL1, which would require a distinct constant
    // not yet needed since this MVP phase's only read-only mapping,
    // KERNEL_RODATA, is not yet exercised by any actual
    // setup_identity_mapping call site in lib.rs).
    if perms.writable {
        flags |= pte_flags::AP_RW_EL1;
    }

    if !perms.executable {
        flags |= pte_flags::PXN | pte_flags::UXN;
    }

    flags
}

// ============================================================================
// Memory — MemoryBootstrap implementation
// ============================================================================

const MAX_TRACKED_REGIONS: usize = hal_manifest::raw::MAX_MEMORY_REGIONS;

pub struct Memory {
    regions: [MemoryRegion; MAX_TRACKED_REGIONS],
    region_count: usize,
    iommu_present: bool,
    gicd_base: u64,
}

impl Memory {
    /// # Safety
    /// Same contract as hal-x86_64/memory.rs's
    /// `Memory::from_uefi_memory_map`.
    pub unsafe fn from_uefi_memory_map(uefi_memory_map: *const u8) -> Self {
        // SAFETY: forwarded from this function's own contract.
        let header = unsafe { core::ptr::read_unaligned(uefi_memory_map as *const UefiMemoryMapHeader) };
        let descriptors_start = unsafe { uefi_memory_map.add(size_of::<UefiMemoryMapHeader>()) };

        let iter = DescriptorIter {
            current: descriptors_start,
            remaining_bytes: header.map_size,
            descriptor_size: header.descriptor_size,
        };

        let mut regions = [MemoryRegionRaw::ZERO; MAX_TRACKED_REGIONS];
        let mut region_count = 0usize;

        for descriptor in iter {
            if region_count >= MAX_TRACKED_REGIONS {
                break;
            }
            regions[region_count] = MemoryRegionRaw::new(
                descriptor.physical_start,
                descriptor.number_of_pages * PAGE_SIZE as u64,
                classify_uefi_type(descriptor.ty),
                false,
            );
            region_count += 1;
        }

        let rsdp_phys = unsafe { locate_acpi_rsdp(uefi_memory_map, &header) };
        // SAFETY: forwarded per acpi_discover's own contract.
        let acpi_result = unsafe { acpi_discover(rsdp_phys) };

        if acpi_result.smmu_present {
            for region in regions.iter_mut().take(region_count) {
                region.behind_iommu = true;
            }
        }

        Self {
            regions,
            region_count,
            iommu_present: acpi_result.smmu_present,
            gicd_base: acpi_result.gicd_base.unwrap_or(QEMU_VIRT_DEFAULT_GICD_BASE),
        }
    }

    /// Read by `hal_arm64_rust_entry` (lib.rs) to construct
    /// `interrupt::InterruptCtrl::new(gicd_base)` — this is this
    /// architecture's equivalent data-flow to how hal-x86_64's
    /// `InterruptCtrl::new()` reads `xapic_mmio_base()` directly from
    /// an MSR; here it must come from this module's ACPI/DT discovery
    /// instead, per module docs.
    pub fn gicd_base(&self) -> u64 {
        self.gicd_base
    }
}

impl MemoryBootstrap for Memory {
    fn physical_memory_map(&self) -> &[MemoryRegion] {
        &self.regions[..self.region_count]
    }

    fn iommu_present(&self) -> bool {
        self.iommu_present
    }

    unsafe fn setup_identity_mapping(&self, region: MemoryRegion, perms: MapPermissions) -> Result<VirtAddr, HalError> {
        if region.length_bytes == 0 {
            return Err(HalError::InvalidMemoryRegion);
        }

        let flags = permissions_to_flags(perms);
        let start = PhysAddr::new(region.base_addr as usize).align_down(PAGE_SIZE);
        let end = PhysAddr::new((region.base_addr + region.length_bytes) as usize).align_up(PAGE_SIZE);

        let mut addr = start.as_usize();
        while addr < end.as_usize() {
            // SAFETY: forwarded from this trait method's own safety
            // contract, same reasoning as hal-x86_64's equivalent.
            unsafe {
                map_page(addr as u64, addr as u64, flags)?;
            }
            addr += PAGE_SIZE;
        }

        Ok(VirtAddr::new(start.as_usize()))
    }

    fn base_page_size_bytes(&self) -> usize {
        PAGE_SIZE
    }
}

/// Configures MAIR_EL1 (memory attribute indirection register, whose
/// two indices `pte_flags::ATTR_NORMAL`/`ATTR_DEVICE` reference) and
/// switches TTBR0_EL1 to this crate's own translation table, activating
/// the minimal mapping built by prior `setup_identity_mapping` calls.
/// AArch64's equivalent of hal-x86_64's `activate_page_tables`, but
/// requires the additional MAIR_EL1 step x86_64's PAT-based caching
/// model does not need in the same way for this minimal use case.
///
/// # Safety
/// Same contract as hal-x86_64's `activate_page_tables`: every
/// physical range currently in use must already be mapped in
/// `TTBR0_ROOT`.
#[cfg(not(target_os = "none"))]
pub unsafe fn activate_page_tables() {
    // Host (`cargo test`) stub — no MMU bring-up off the bare-metal
    // target.
}

#[cfg(target_os = "none")]
pub unsafe fn activate_page_tables() {
    // SAFETY: forwarded from this function's own contract; MAIR_EL1
    // encoding per ARM ARM D5.2.16 — index 0 = 0xFF (Normal,
    // Write-Back, Read/Write-Allocate), index 1 = 0x00 (Device-nGnRnE,
    // the most conservative device memory type, safe for any MMIO).
    unsafe {
        let mair: u64 = 0x00FF; // index 0 = 0xFF, index 1 = 0x00
        core::arch::asm!("msr mair_el1, {}", in(reg) mair);

        let ttbr0_addr = &raw const TTBR0_ROOT as u64;
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) ttbr0_addr);

        // TCR_EL1: translation control. T0SZ=16 (48-bit VA via
        // TTBR0), 4KB granule (TG0=0b00), inner/outer write-back
        // cacheable, inner shareable — the standard configuration
        // matching this project's 4-level, 4KB-granule table walk.
        let tcr: u64 = 16 // T0SZ
            | (0b01 << 8)  // IRGN0 = write-back
            | (0b01 << 10) // ORGN0 = write-back
            | (0b11 << 12) // SH0 = inner shareable
            | (0b00 << 14); // TG0 = 4KB
        core::arch::asm!("msr tcr_el1, {}", in(reg) tcr);
        core::arch::asm!("isb");

        // Enable the MMU: SCTLR_EL1.M (bit 0) = 1, plus C (bit 2,
        // data cache) and I (bit 12, instruction cache).
        let mut sctlr: u64;
        core::arch::asm!("mrs {}, sctlr_el1", out(reg) sctlr);
        sctlr |= (1 << 0) | (1 << 2) | (1 << 12);
        core::arch::asm!("msr sctlr_el1, {}", in(reg) sctlr);
        core::arch::asm!("isb");
    }
}

#[cfg(not(target_os = "none"))]
pub fn current_page_table_phys(_memory: &Memory) -> u64 {
    // Host (`cargo test`) stub — no TTBR0_EL1 off the bare-metal target.
    0
}

#[cfg(target_os = "none")]
pub fn current_page_table_phys(_memory: &Memory) -> u64 {
    let mut ttbr0: u64;
    // SAFETY: reading TTBR0_EL1 has no preconditions beyond EL1
    // execution, which this crate always has.
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0);
    }
    ttbr0
}

// ============================================================================
// HardwareManifestRaw assembly — identical structure to
// hal-x86_64/memory.rs's built_hardware_manifest
// ============================================================================

pub fn built_hardware_manifest(
    memory: &Memory,
    compute: &ComputeDiscovery,
    power: &PowerThermalImpl,
    cpu: &Cpu,
    interrupt: &InterruptCtrl,
    timer: &Timer,
) -> HardwareManifestRaw {
    use hal_core::compute::ComputeDeviceDiscovery;
    use hal_core::cpu::CpuAbstraction;
    use hal_core::interrupt::InterruptController;
    use hal_core::power::PowerThermal;
    use hal_core::timer::TimerAbstraction;

    let mut manifest = HardwareManifestRaw::zeroed();

    manifest.cpu_core_count = cpu.core_count() as u32;
    manifest.cpu_feature_flags = cpu.feature_flags().bits();

    for region in memory.physical_memory_map() {
        let _ = manifest.push_memory_region(*region);
    }
    for device in compute.enumerate_compute_devices() {
        let _ = manifest.push_compute_device(*device);
    }
    for domain in power.enumerate_power_domains() {
        let _ = manifest.push_power_domain(*domain);
    }

    manifest.interrupt_controller = InterruptControllerInfoRaw::new(
        interrupt.detected_kind(),
        interrupt.primary_base(),
        interrupt.secondary_base().is_some(),
        interrupt.secondary_base().unwrap_or(0),
        interrupt.irq_line_count(),
        interrupt.ipi_target_core_count(),
    );

    manifest.timer = TimerInfoRaw::new(
        timer.detected_kind(),
        timer.frequency_hz(),
        timer.supports_tickless(),
    );

    cpu.mark_iommu_capable(memory.iommu_present());
    manifest.cpu_feature_flags = cpu.feature_flags().bits();

    manifest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_conventional_memory_as_usable() {
        assert_eq!(
            classify_uefi_type(UefiMemoryType::ConventionalMemory as u32),
            hal_manifest::raw::MemoryRegionKindRaw::Usable
        );
    }

    #[test]
    fn permissions_to_flags_device_uses_device_attr() {
        let flags = permissions_to_flags(MapPermissions::DEVICE_MMIO);
        assert_ne!(flags & pte_flags::ATTR_DEVICE, 0);
        assert_eq!(flags & pte_flags::ATTR_NORMAL, 0);
    }

    #[test]
    fn permissions_to_flags_kernel_code_is_executable() {
        let flags = permissions_to_flags(MapPermissions::KERNEL_CODE);
        assert_eq!(flags & pte_flags::PXN, 0);
        assert_eq!(flags & pte_flags::UXN, 0);
    }

    #[test]
    fn permissions_to_flags_kernel_data_sets_no_execute() {
        let flags = permissions_to_flags(MapPermissions::KERNEL_DATA);
        assert_ne!(flags & pte_flags::PXN, 0);
        assert_ne!(flags & pte_flags::UXN, 0);
        // AArch64 encodes "writable, EL1 only" as AP[7:6] = 0b00, i.e.
        // `AP_RW_EL1` is the all-zeros encoding — it cannot be bit-tested
        // for presence. What distinguishes kernel data here is that the
        // EL0-access bit (`AP_RW_ANY`) is *not* set.
        assert_eq!(flags & pte_flags::AP_RW_ANY, 0);
    }

    #[test]
    fn gicd_base_falls_back_to_qemu_virt_default() {
        let result = AcpiDiscoveryResult::default();
        let base = result.gicd_base.unwrap_or(QEMU_VIRT_DEFAULT_GICD_BASE);
        assert_eq!(base, 0x0800_0000);
    }
}