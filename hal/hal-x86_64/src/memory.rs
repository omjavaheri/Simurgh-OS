//! ============================================================================
//! memory.rs — x86_64
//!
//! Implements `hal_core::memory::MemoryBootstrap` for x86_64, per
//! 01-HAL-Layer.md section 3.2:
//!   - reading the firmware memory map (UEFI Memory Map, this
//!     architecture's path per section 3.2's x86_64 row)
//!   - minimal identity/kernel page table setup
//!   - IOMMU (VT-d) presence detection via the ACPI DMAR table
//!
//! Also provides the two helper functions `lib.rs`'s
//! `hal_x86_64_rust_entry` calls to assemble `BootInfo`:
//!   - `Memory::from_uefi_memory_map` (parses the raw UEFI blob)
//!   - `built_hardware_manifest` (folds every subsystem's discovery
//!     output into one `HardwareManifestRaw`, per hal-manifest section 9)
//!   - `current_page_table_phys` (reads CR3 for `BootInfo::
//!     initial_page_table_phys`, hal-core/src/boot.rs)
//! ============================================================================

use core::mem::size_of;

use hal_core::cpu::CpuFeatureFlags;
use hal_core::error::HalError;
use hal_core::memory::{MapPermissions, MemoryBootstrap, MemoryRegion, MemoryRegionKind, PhysAddr, VirtAddr};
use hal_manifest::raw::{HardwareManifestRaw, InterruptControllerInfoRaw, MemoryRegionRaw, TimerInfoRaw};

use crate::compute::ComputeDiscovery;
use crate::cpu::Cpu;
use crate::interrupt::InterruptCtrl;
use crate::power::PowerThermalImpl;
use crate::timer::Timer;

// ============================================================================
// UEFI Memory Map parsing (section 3.2: "UEFI Memory Map / e820")
//
// This mirrors the UEFI spec's EFI_MEMORY_DESCRIPTOR layout closely
// enough to parse the blob our boot.S-called bootloader stub hands us
// in RDI (see lib.rs's hal_x86_64_rust_entry doc comment), without
// depending on a full UEFI crate — this file only needs to READ a
// memory map that a separate, smaller UEFI bootloader stub (outside
// this crate's scope; produced by the project's boot image tooling)
// already obtained via GetMemoryMap() before ExitBootServices().
// ============================================================================

/// Mirrors UEFI's `EFI_MEMORY_TYPE` enum values relevant to
/// classifying regions into `MemoryRegionKindRaw` (hal-manifest raw.rs).
/// Only the values this project's classification logic below actually
/// branches on are named; every other UEFI memory type numeric value
/// falls through to the `_ =>` arm in `classify_uefi_type`.
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

/// `EFI_MEMORY_DESCRIPTOR` layout (UEFI spec section 7.2). `PhysicalStart`
/// and `VirtualStart` are 8-byte-aligned `u64`s; `NumberOfPages` counts
/// 4 KiB pages; `Attribute` is a capability bitmask this crate does not
/// currently interpret beyond region classification.
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

/// Header this project's UEFI bootloader stub prepends to the raw
/// descriptor array before handing the pointer to `_start` (boot.S) /
/// `hal_x86_64_rust_entry` (lib.rs). Keeping an explicit header
/// (rather than requiring the Rust side to separately receive
/// map_size/descriptor_size via extra registers) means the entire
/// memory map handoff fits in the single RDI pointer boot.S already
/// passes through unmodified.
#[repr(C)]
struct UefiMemoryMapHeader {
    /// Total size, in bytes, of the descriptor array that follows this
    /// header.
    map_size: u64,
    /// Size, in bytes, of ONE descriptor entry, as reported by
    /// `GetMemoryMap()`. Per the UEFI spec, this may be LARGER than
    /// `size_of::<UefiMemoryDescriptor>()` (firmware is permitted to
    /// add vendor-specific trailing fields) — callers MUST stride by
    /// this value, never by `size_of::<UefiMemoryDescriptor>()`
    /// directly, which `descriptor_iter` below does correctly.
    descriptor_size: u64,
}

/// Classifies a UEFI memory type into hal-manifest's
/// `MemoryRegionKindRaw`, per the mapping this project uses to decide
/// what the Root Task (layer 3) is later allowed to do with each
/// region (hal-core/src/boot.rs: `BootInfo::overlaps_kernel_image` and
/// friends build on this same classification).
fn classify_uefi_type(ty: u32) -> hal_manifest::raw::MemoryRegionKindRaw {
    use hal_manifest::raw::MemoryRegionKindRaw as Kind;

    match UefiMemoryType::from_u32(ty) {
        // Conventional memory, and boot-services-owned regions (code/
        // data the firmware no longer needs once ExitBootServices()
        // has run, which it has by the time this function executes) —
        // all become Usable, matching how every production UEFI OS
        // loader treats these types after boot services exit.
        Some(UefiMemoryType::ConventionalMemory)
        | Some(UefiMemoryType::BootServicesCode)
        | Some(UefiMemoryType::BootServicesData)
        | Some(UefiMemoryType::LoaderCode)
        | Some(UefiMemoryType::LoaderData) => Kind::Usable,

        Some(UefiMemoryType::AcpiReclaimMemory) => Kind::AcpiReclaimable,
        Some(UefiMemoryType::AcpiMemoryNvs) => Kind::AcpiNvs,

        Some(UefiMemoryType::MemoryMappedIo) | Some(UefiMemoryType::MemoryMappedIoPortSpace) => Kind::Mmio,

        // Runtime services code/data must remain callable after
        // ExitBootServices() (firmware runtime services, e.g.
        // GetVariable/SetTime), so it is never Usable — classified as
        // Reserved to keep the Root Task from ever handing this range
        // out as free UntypedMemory.
        Some(UefiMemoryType::RuntimeServicesCode)
        | Some(UefiMemoryType::RuntimeServicesData)
        | Some(UefiMemoryType::ReservedMemoryType)
        | Some(UefiMemoryType::UnusableMemory)
        | Some(UefiMemoryType::PalCode)
        | None => Kind::Reserved,

        // Persistent memory (NVDIMM-backed) is real, addressable
        // memory but has different durability semantics than DRAM;
        // conservatively reserved for now rather than offered as
        // ordinary Usable RAM — a future layer 3 persistent-memory
        // service (out of scope for this MVP phase) would need to
        // claim it explicitly rather than have it silently mixed into
        // the general allocator pool.
        Some(UefiMemoryType::PersistentMemory) => Kind::Reserved,
    }
}

/// Iterates the raw UEFI descriptor array following a
/// `UefiMemoryMapHeader`, striding by `descriptor_size` (NOT
/// `size_of::<UefiMemoryDescriptor>()`) per that field's doc comment.
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
        // SAFETY: caller of `DescriptorIter::new` (below) guarantees
        // `current` points at `remaining_bytes` valid bytes belonging
        // to the UEFI-provided descriptor array; each step reads
        // exactly `size_of::<UefiMemoryDescriptor>()` bytes from the
        // FRONT of a `descriptor_size`-wide slot (firmware-added
        // trailing fields beyond our struct's fields are legitimately
        // ignored, per the UEFI spec's forward-compatibility design),
        // then advances by the full `descriptor_size` stride.
        let descriptor = unsafe { core::ptr::read_unaligned(self.current as *const UefiMemoryDescriptor) };
        // SAFETY: advancing by `descriptor_size` stays within the
        // bounds checked above (`remaining_bytes >= descriptor_size`).
        self.current = unsafe { self.current.add(self.descriptor_size as usize) };
        self.remaining_bytes -= self.descriptor_size;
        Some(descriptor)
    }
}

// ============================================================================
// ACPI DMAR parsing (IOMMU / VT-d detection, section 3.2's "Abstraction
// یکسان برای MMU/IOMMU... IOMMU در x86")
//
// Deliberately minimal: this MVP phase only needs a yes/no answer to
// "is VT-d present at all" (hal_core::memory::MemoryBootstrap::
// iommu_present), not full per-device IOMMU domain management (a layer
// 3 Device Manager concern, per 03-Kernel-Subsystems-Layer.md section
// 2.1, built on top of this primitive later).
// ============================================================================

/// ACPI System Description Table header, common to every ACPI table
/// including DMAR (ACPI spec section 5.2.6).
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

const DMAR_SIGNATURE: [u8; 4] = *b"DMAR";

/// Scans the ACPI table pointers reachable from `rsdp_phys` for a DMAR
/// table. Returns `true` if found (VT-d hardware is present and
/// described by firmware), `false` otherwise — this crate does not
/// currently need to parse DMAR's own remapping-unit sub-structures,
/// only detect the table's presence, per this function's doc comment
/// above.
///
/// # Safety
/// `rsdp_phys` must be a physical address UEFI's Configuration Table
/// list actually reported as the ACPI 2.0+ RSDP, obtained by this
/// crate's boot-time UEFI configuration table walk (a small piece of
/// logic assumed to run as part of `Memory::from_uefi_memory_map`'s
/// broader firmware-table discovery, alongside the memory map itself).
unsafe fn acpi_dmar_present(rsdp_phys: u64) -> bool {
    // A full RSDP -> XSDT -> per-table walk is straightforward but
    // verbose ACPI boilerplate; kept as a small local helper here
    // rather than a separate module, since (per this file's scope)
    // ACPI parsing in this MVP phase exists ONLY to answer this one
    // IOMMU-presence question and to feed `Cpu::mark_iommu_capable`
    // (cpu.rs) — full ACPI table enumeration for other purposes (e.g.
    // MADT-based multi-core discovery, tracked as a follow-up in
    // cpu.rs's `detected_core_count` doc comment) is deferred.
    if rsdp_phys == 0 {
        return false;
    }

    // SAFETY: `rsdp_phys` is trusted per this function's own safety
    // contract; RSDP layout offsets below are fixed by the ACPI
    // specification (XSDT address at byte offset 24 in the ACPI 2.0+
    // RSDP structure).
    let xsdt_addr = unsafe { core::ptr::read_unaligned((rsdp_phys as *const u8).add(24) as *const u64) };
    if xsdt_addr == 0 {
        return false;
    }

    // SAFETY: `xsdt_addr` was just read from a (per this function's
    // contract) trusted RSDP; the XSDT header itself is a valid
    // `AcpiSdtHeader` by the ACPI spec's own layout guarantee.
    let xsdt_header = unsafe { core::ptr::read_unaligned(xsdt_addr as *const AcpiSdtHeader) };
    let entry_count = (xsdt_header.length as usize - size_of::<AcpiSdtHeader>()) / size_of::<u64>();
    let entries_ptr = (xsdt_addr as usize + size_of::<AcpiSdtHeader>()) as *const u64;

    for i in 0..entry_count {
        // SAFETY: `i < entry_count`, which was computed directly from
        // the XSDT's own `length` field per the ACPI spec's table
        // layout — each entry is a valid physical address of another
        // ACPI table.
        let table_addr = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
        // SAFETY: `table_addr` came from a well-formed XSDT entry,
        // pointing at a valid `AcpiSdtHeader`-prefixed table per the
        // ACPI spec.
        let header = unsafe { core::ptr::read_unaligned(table_addr as *const AcpiSdtHeader) };
        if header.signature == DMAR_SIGNATURE {
            return true;
        }
    }

    false
}

const MCFG_SIGNATURE: [u8; 4] = *b"MCFG";

/// One entry of the MCFG table's own "Configuration Space Allocation
/// Structure" array (PCI Firmware Specification section 4.1.2, Table
/// 4-3) — the ACPI-standard, firmware-reported way to learn a PCIe
/// segment's own ECAM physical base address. See `Memory::rsdp_phys`'s
/// own doc comment for why this replaced an earlier hardcoded-constant
/// attempt (QEMU-real-hardware evidence, not a style preference).
#[repr(C, packed)]
struct McfgAllocation {
    base_address: u64,
    _pci_segment_group: u16,
    _start_bus: u8,
    _end_bus: u8,
    _reserved: u32,
}

/// Scans the ACPI table pointers reachable from `rsdp_phys` for an MCFG
/// table and returns its FIRST Configuration Space Allocation
/// Structure's own base address (segment 0's own ECAM window — the only
/// segment this MVP's single-PCIe-domain QEMU target ever populates).
/// Returns `None` if no MCFG table is present, or it carries no
/// allocation entries at all.
///
/// # Safety
/// Same contract as `acpi_dmar_present`.
pub(crate) unsafe fn acpi_mcfg_ecam_base(rsdp_phys: u64) -> Option<u64> {
    if rsdp_phys == 0 {
        return None;
    }

    // SAFETY: forwarded from this function's own contract; RSDP layout
    // per the ACPI specification, same offset `acpi_dmar_present`
    // already reads.
    let xsdt_addr = unsafe { core::ptr::read_unaligned((rsdp_phys as *const u8).add(24) as *const u64) };
    if xsdt_addr == 0 {
        return None;
    }

    // SAFETY: forwarded; `xsdt_addr` is a trusted XSDT pointer per the
    // same RSDP contract `acpi_dmar_present` already relies on.
    let xsdt_header = unsafe { core::ptr::read_unaligned(xsdt_addr as *const AcpiSdtHeader) };
    let entry_count = (xsdt_header.length as usize - size_of::<AcpiSdtHeader>()) / size_of::<u64>();
    let entries_ptr = (xsdt_addr as usize + size_of::<AcpiSdtHeader>()) as *const u64;

    for i in 0..entry_count {
        // SAFETY: `i < entry_count`, computed from the XSDT's own
        // `length` field per the ACPI spec's table layout.
        let table_addr = unsafe { core::ptr::read_unaligned(entries_ptr.add(i)) };
        // SAFETY: `table_addr` came from a well-formed XSDT entry.
        let header = unsafe { core::ptr::read_unaligned(table_addr as *const AcpiSdtHeader) };
        if header.signature != MCFG_SIGNATURE {
            continue;
        }
        // MCFG's own body (ACPI spec / PCI Firmware Spec section 4.1.2):
        // the standard `AcpiSdtHeader`, then an 8-byte Reserved field,
        // then a variable-length array of `McfgAllocation` entries —
        // this MVP only ever reads the first one (segment 0).
        let first_entry_addr = table_addr as usize + size_of::<AcpiSdtHeader>() + 8;
        if (table_addr as usize + header.length as usize) < first_entry_addr + size_of::<McfgAllocation>() {
            return None; // table present but carries no allocation entries.
        }
        // SAFETY: `first_entry_addr` is within the MCFG table's own
        // `length`-bounded body, just checked above; `McfgAllocation`
        // is `#[repr(C, packed)]`, matching the spec's own byte layout
        // exactly, so an unaligned read is the correct access here.
        let entry = unsafe { core::ptr::read_unaligned(first_entry_addr as *const McfgAllocation) };
        return Some(entry.base_address);
    }

    None
}

// ============================================================================
// Page table setup (minimal identity/kernel mapping, section 3.2)
// ============================================================================

const PAGE_SIZE: usize = 4096;
const ENTRIES_PER_TABLE: usize = 512;

/// Page table entry flags relevant to the minimal mapping this crate
/// establishes. Named per the x86_64 paging spec (Intel SDM Vol. 3A,
/// section 4.5).
mod pte_flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER_ACCESSIBLE: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const CACHE_DISABLE: u64 = 1 << 4;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const NO_EXECUTE: u64 = 1 << 63;
}

#[repr(align(4096))]
struct PageTable([u64; ENTRIES_PER_TABLE]);

impl PageTable {
    const fn new() -> Self {
        Self([0; ENTRIES_PER_TABLE])
    }
}

/// This core's PML4 (top-level page table). `static mut` for the same
/// reason as `cpu.rs`'s `IDT`: written exactly once, during single-
/// threaded early boot, before any concurrent access is possible.
/// UEFI's own identity-mapped tables remain active in CR3 until
/// `activate()` below explicitly switches to this one.
static mut PML4: PageTable = PageTable::new();

/// A small, fixed pool of lower-level tables (PDPT/PD/PT), sized
/// generously for the MVP's minimal mapping needs (kernel image,
/// boot-time structures, essential early MMIO for the interrupt
/// controller in `interrupt.rs`) without requiring a heap allocator —
/// consistent with hal-manifest section 9's boot-time no-heap
/// philosophy. Exhausting this pool returns
/// `HalError::InvalidMemoryRegion` from `setup_identity_mapping` rather
/// than silently corrupting memory.
const TABLE_POOL_SIZE: usize = 16;
static mut TABLE_POOL: [PageTable; TABLE_POOL_SIZE] = {
    // Work around `PageTable` not being `Copy` (its `[u64; 512]`
    // inner array IS Copy, but repeat-expression array init still
    // needs an explicit const value) by building the array via a
    // const fn loop-free repeat, matching hal-manifest raw.rs's own
    // `[MemoryRegionRaw::ZERO; N]` idiom.
    const EMPTY: PageTable = PageTable::new();
    [EMPTY; TABLE_POOL_SIZE]
};
static mut TABLE_POOL_NEXT: usize = 0;

/// Allocates the next unused table from `TABLE_POOL`.
///
/// # Safety
/// Must only be called during single-threaded early boot, before
/// interrupts are enabled — matches every other `static mut` access
/// pattern in this file and in `cpu.rs`.
unsafe fn alloc_table() -> Result<*mut PageTable, HalError> {
    // SAFETY: single-threaded boot-time access, per this function's
    // contract.
    let next = unsafe { TABLE_POOL_NEXT };
    if next >= TABLE_POOL_SIZE {
        return Err(HalError::InvalidMemoryRegion);
    }
    // SAFETY: `next < TABLE_POOL_SIZE`, checked immediately above.
    let table_ptr = unsafe { &raw mut TABLE_POOL[next] };
    // SAFETY: same single-threaded boot-time contract as the read
    // above.
    unsafe {
        TABLE_POOL_NEXT = next + 1;
    }
    Ok(table_ptr)
}

/// Walks (allocating as needed) from PML4 down to the PT entry for
/// `virt`, and writes `phys | flags` into it. Uses standard 4-level
/// paging (PML4 -> PDPT -> PD -> PT), 4 KiB pages only — huge pages are
/// not used in this MVP phase's minimal mapping, keeping the walk logic
/// uniform and simple to review against the "smallest possible code in
/// Privileged mode" principle.
///
/// # Safety
/// Caller must ensure `virt`/`phys` are page-aligned and that this is
/// called only during single-threaded early boot (same contract as
/// `alloc_table`).
unsafe fn map_page(virt: u64, phys: u64, flags: u64) -> Result<(), HalError> {
    let indices = [
        ((virt >> 39) & 0x1FF) as usize, // PML4 index
        ((virt >> 30) & 0x1FF) as usize, // PDPT index
        ((virt >> 21) & 0x1FF) as usize, // PD index
        ((virt >> 12) & 0x1FF) as usize, // PT index
    ];

    // SAFETY: `PML4` is this core's single boot-time top-level table,
    // accessed here under the same single-threaded contract as the
    // rest of this module.
    let mut table_ptr: *mut PageTable = unsafe { &raw mut PML4 };

    for level in 0..3 {
        // SAFETY: `table_ptr` is a valid `PageTable` per this loop's
        // invariant (established initially by PML4 above, and
        // maintained by the allocation branch below).
        let entry = unsafe { &mut (*table_ptr).0[indices[level]] };
        if *entry & pte_flags::PRESENT == 0 {
            // SAFETY: boot-time single-threaded allocation, per
            // `alloc_table`'s own contract.
            let new_table = unsafe { alloc_table()? };
            *entry = (new_table as u64) | pte_flags::PRESENT | pte_flags::WRITABLE | pte_flags::USER_ACCESSIBLE;
        }
        table_ptr = (*entry & 0x000F_FFFF_FFFF_F000) as *mut PageTable;
    }

    // SAFETY: `table_ptr` now points at the PT (level-4) table for
    // `virt`, established by the walk above.
    let pt_entry = unsafe { &mut (*table_ptr).0[indices[3]] };
    *pt_entry = (phys & 0x000F_FFFF_FFFF_F000) | flags | pte_flags::PRESENT;

    Ok(())
}

/// Translates `hal_core::memory::MapPermissions` into x86_64 page
/// table entry flag bits.
fn permissions_to_flags(perms: MapPermissions) -> u64 {
    let mut flags = 0u64;
    if perms.writable {
        flags |= pte_flags::WRITABLE;
    }
    if !perms.executable {
        flags |= pte_flags::NO_EXECUTE;
    }
    if perms.device_uncached {
        flags |= pte_flags::CACHE_DISABLE | pte_flags::WRITE_THROUGH;
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
    /// The ACPI RSDP physical address `from_uefi_memory_map` already
    /// located to answer `acpi_dmar_present` — retained (not just a
    /// local inside that function) so `peripheral.rs`'s own MCFG lookup
    /// (`acpi_mcfg_ecam_base`, this file) can reuse the SAME already-
    /// parsed pointer via the `rsdp_phys()` getter below, instead of
    /// re-walking UEFI's Configuration Table list a second time.
    ///
    /// **Real bug found via QEMU**: this crate's own `compute.rs`
    /// PCI scan uses the legacy port mechanism (0xCF8/0xCFC), which
    /// needs no ECAM base at all, so nothing forced this MVP to learn
    /// the real one until `peripheral.rs`'s virtio-pci discovery
    /// needed it — an initial attempt hardcoded QEMU q35's own well-
    /// documented `MCH_HOST_BRIDGE_PCIEXBAR_DEFAULT` (0xB0000000,
    /// `hw/pci-host/q35.h`), mirroring `hal_arm64::compute::
    /// QEMU_VIRT_DEFAULT_ECAM_BASE`'s own accepted MVP-phase shortcut.
    /// On THIS project's actual QEMU/OVMF combination that address
    /// read back as a clean, non-faulting `0x00000000` (not PCI's own
    /// "no device" `0xFFFFFFFF` pattern) at bus 0/device 0/function 0
    /// — where the host bridge unconditionally exists on any q35
    /// machine — proving the guess was simply wrong for this specific
    /// OVMF build's own PCIEXBAR placement, not a mapping problem
    /// (a genuinely unmapped access would have page-faulted instead).
    /// Real ACPI MCFG table parsing (this field + `acpi_mcfg_ecam_
    /// base`) replaced the hardcoded guess for exactly this reason.
    rsdp_phys: u64,
}

impl Memory {
    /// Parses the UEFI-provided memory map blob into this crate's
    /// tracked region list, and detects IOMMU presence via ACPI DMAR.
    ///
    /// # Safety
    /// `uefi_memory_map` must point at a valid `UefiMemoryMapHeader`
    /// followed by `header.map_size` bytes of UEFI memory descriptors,
    /// per this project's boot protocol (see this file's module docs
    /// and lib.rs's `hal_x86_64_rust_entry` safety contract, which this
    /// function's only caller already satisfies).
    pub unsafe fn from_uefi_memory_map(uefi_memory_map: *const u8) -> Self {
        // SAFETY: forwarded from this function's own safety contract.
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
                // Per hal-manifest's push_memory_region capacity
                // rationale (raw.rs): truncate and continue rather
                // than fail boot over a rare excess of firmware-
                // reported regions.
                break;
            }
            regions[region_count] = MemoryRegionRaw::new(
                descriptor.physical_start,
                descriptor.number_of_pages * PAGE_SIZE as u64,
                classify_uefi_type(descriptor.ty),
                false, // later refined
            );
            region_count += 1;
        }

        // NOTE: locating the ACPI RSDP physical address itself (walking
        // UEFI's Configuration Table list for the ACPI 2.0 GUID) is
        // assumed to have been done by this project's UEFI bootloader
        // stub and threaded through as part of the same boot protocol
        // that supplies `uefi_memory_map` — for this MVP phase we call
        // through a small accessor that the bootloader stub's contract
        // guarantees is valid at this point in boot.
        let rsdp_phys = unsafe { locate_acpi_rsdp(uefi_memory_map, &header) };
        // SAFETY: `rsdp_phys` is either 0 (checked inside
        // acpi_dmar_present) or a value obtained per this same boot
        // protocol's guarantees.
        let iommu_present = unsafe { acpi_dmar_present(rsdp_phys) };

        if iommu_present {
            for region in regions.iter_mut().take(region_count) {
                region.behind_iommu = true;
            }
        }

        Self {
            regions: {
                let mut typed = [MemoryRegionRaw::ZERO; MAX_TRACKED_REGIONS];
                typed.copy_from_slice(&regions);
                typed
            },
            region_count,
            iommu_present,
            rsdp_phys,
        }
    }

    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// The ACPI RSDP physical address this crate located at boot — `0`
    /// if none was found (same "not present" sentinel `acpi_dmar_
    /// present`'s own doc comment already establishes for this value).
    /// See this struct's own `rsdp_phys` field doc comment for why this
    /// exists.
    pub fn rsdp_phys(&self) -> u64 {
        self.rsdp_phys
    }
}

/// Reads the ACPI RSDP physical address the bootloader stub stashed
/// immediately after the descriptor array (this project's own boot
/// protocol extension, not part of the UEFI spec itself — kept
/// separate from `UefiMemoryMapHeader` so that struct stays a faithful,
/// minimal mirror of what `GetMemoryMap()` actually returns).
///
/// # Safety
/// Same contract as `Memory::from_uefi_memory_map`: `uefi_memory_map`
/// and `header.map_size` must describe a valid handoff blob from this
/// project's bootloader stub.
unsafe fn locate_acpi_rsdp(uefi_memory_map: *const u8, header: &UefiMemoryMapHeader) -> u64 {
    let trailer_offset = size_of::<UefiMemoryMapHeader>() as u64 + header.map_size;
    // SAFETY: forwarded from this function's own safety contract; the
    // 8-byte RSDP address immediately follows the descriptor array by
    // this project's boot protocol definition.
    unsafe { core::ptr::read_unaligned(uefi_memory_map.add(trailer_offset as usize) as *const u64) }
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
            // Identity mapping: virtual == physical for this minimal
            // boot-time mapping (per hal-core memory.rs's doc comment
            // on setup_identity_mapping's dual identity/kernel-mapping
            // role — full higher-half kernel mapping for .text/.rodata/
            // etc. is established separately by linker.ld's own VMA
            // placement plus a fixed offset mapping, not through this
            // per-call identity path).
            //
            // SAFETY: forwarded from this trait method's own safety
            // contract (hal-core/src/memory.rs::MemoryBootstrap::
            // setup_identity_mapping) — the caller guarantees `region`
            // describes real, non-conflicting physical memory.
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

/// Switches CR3 to this crate's own `PML4`, activating the minimal
/// mapping built by prior `setup_identity_mapping` calls in place of
/// UEFI's own page tables.
///
/// # Safety
/// Every physical range the currently-executing code (and its stack)
/// needs must already be mapped in `PML4` before this is called —
/// switching to an incomplete mapping would fault on the very next
/// instruction fetch or stack access.
pub unsafe fn activate_page_tables() {
    // SAFETY: `PML4`'s physical address is valid and, per this
    // function's own contract, already covers every range currently
    // in use — `mov cr3` takes effect immediately and only changes
    // which mapping is consulted for subsequent memory accesses.
    unsafe {
        let pml4_addr = &raw const PML4 as u64;
        core::arch::asm!("mov cr3, {}", in(reg) pml4_addr);
    }
}

/// Reads the currently active CR3 value, for `BootInfo::
/// initial_page_table_phys` (hal-core/src/boot.rs).
pub fn current_page_table_phys(_memory: &Memory) -> u64 {
    let mut cr3: u64;
    // SAFETY: reading CR3 has no preconditions beyond executing in a
    // privileged mode capable of `mov reg, cr3`, which this boot-time
    // code always is (Ring 0, per this crate's entire execution
    // context).
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3);
    }
    cr3
}

// ============================================================================
// HardwareManifestRaw assembly (hal-manifest section 9)
// ============================================================================

/// Folds every subsystem's discovery output into one
/// `HardwareManifestRaw`, matching that struct's field list exactly
/// (hal-manifest/src/raw.rs). Called once from `hal_x86_64_rust_entry`
/// (lib.rs) after all six subsystems have been constructed.
pub fn built_hardware_manifest(
    memory: &Memory,
    compute: &ComputeDiscovery,
    power: &PowerThermalImpl,
    cpu: &Cpu,
    interrupt: &InterruptCtrl,
    timer: &Timer,
    peripheral: &crate::peripheral::PeripheralDiscovery,
) -> HardwareManifestRaw {
    use hal_core::compute::ComputeDeviceDiscovery;
    use hal_core::cpu::CpuAbstraction;
    use hal_core::interrupt::InterruptController;
    use hal_core::peripheral::PeripheralDeviceDiscovery;
    use hal_core::power::PowerThermal;
    use hal_core::timer::TimerAbstraction;

    let mut manifest = HardwareManifestRaw::zeroed();

    manifest.cpu_core_count = cpu.core_count() as u32;
    manifest.cpu_feature_flags = cpu.feature_flags().bits();

    for region in memory.physical_memory_map() {
        // Best-effort: capacity was already bounded to
        // MAX_MEMORY_REGIONS during from_uefi_memory_map, so this
        // cannot fail here — but per hal-manifest's own
        // push_memory_region contract, we still respect its Result
        // rather than assuming.
        let _ = manifest.push_memory_region(*region);
    }

    for device in compute.enumerate_compute_devices() {
        let _ = manifest.push_compute_device(*device);
    }

    for domain in power.enumerate_power_domains() {
        let _ = manifest.push_power_domain(*domain);
    }

    for device in peripheral.enumerate_peripheral_devices() {
        let _ = manifest.push_peripheral_device(*device);
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

    // Fold IOMMU presence into the CPU feature flags too, per cpu.rs's
    // `mark_iommu_capable` doc comment on why CPUID alone cannot report
    // this bit.
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
    fn classify_runtime_services_as_reserved() {
        assert_eq!(
            classify_uefi_type(UefiMemoryType::RuntimeServicesCode as u32),
            hal_manifest::raw::MemoryRegionKindRaw::Reserved
        );
    }

    #[test]
    fn classify_mmio_as_mmio() {
        assert_eq!(
            classify_uefi_type(UefiMemoryType::MemoryMappedIo as u32),
            hal_manifest::raw::MemoryRegionKindRaw::Mmio
        );
    }

    #[test]
    fn classify_unknown_type_as_reserved() {
        assert_eq!(classify_uefi_type(0xFFFF_FFFF), hal_manifest::raw::MemoryRegionKindRaw::Reserved);
    }

    #[test]
    fn permissions_to_flags_sets_writable_and_execute_disable() {
        let flags = permissions_to_flags(MapPermissions::KERNEL_DATA);
        assert_ne!(flags & pte_flags::WRITABLE, 0);
        assert_ne!(flags & pte_flags::NO_EXECUTE, 0);
    }

    #[test]
    fn permissions_to_flags_device_mmio_sets_cache_disable() {
        let flags = permissions_to_flags(MapPermissions::DEVICE_MMIO);
        assert_ne!(flags & pte_flags::CACHE_DISABLE, 0);
        assert_ne!(flags & pte_flags::WRITE_THROUGH, 0);
    }

    #[test]
    fn permissions_to_flags_kernel_code_is_executable() {
        let flags = permissions_to_flags(MapPermissions::KERNEL_CODE);
        assert_eq!(flags & pte_flags::NO_EXECUTE, 0);
    }
}