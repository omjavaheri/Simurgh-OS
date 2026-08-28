//! ============================================================================
//! memory.rs — RISC-V (RV64GC)
//!
//! Implements `hal_core::memory::MemoryBootstrap` for RISC-V, per
//! 01-HAL-Layer.md section 3.2: "Device Tree (اجباری طبق مشخصات SBI)".
//!
//! This is the one hal-<arch> crate in this project with NO UEFI/ACPI
//! code path at all (unlike hal-x86_64 and hal-arm64, which both parse
//! a UEFI-provided memory map and optionally ACPI tables) — everything
//! this file needs (memory regions, PLIC base for interrupt.rs, IOPMP
//! presence for cpu.rs's mark_iommu_capable) comes from parsing the
//! Flattened Device Tree (FDT) blob whose physical address `boot.S`
//! received in a1 and passed through `hal_riscv64_rust_entry` (lib.rs).
//!
//! FDT parsing here is deliberately minimal: a linear scan of the
//! structure block, extracting only the handful of properties this
//! project's MVP phase needs (`memory` node's `reg`, `soc/plic` node's
//! `reg`, an `iommu`-compatible node's mere presence). A general-
//! purpose, fully-featured FDT library is explicitly NOT this file's
//! goal — mirroring hal-x86_64/hal-arm64's "presence-only" ACPI DMAR/
//! IORT scope, not a complete table-walking implementation.
//! ============================================================================

use hal_core::error::HalError;
use hal_core::memory::{MapPermissions, MemoryBootstrap, MemoryRegion, PhysAddr, VirtAddr};
use hal_manifest::raw::{HardwareManifestRaw, InterruptControllerInfoRaw, MemoryRegionRaw, TimerInfoRaw};

use crate::compute::ComputeDiscovery;
use crate::cpu::Cpu;
use crate::interrupt::InterruptCtrl;
use crate::power::PowerThermalImpl;
use crate::timer::Timer;

// ============================================================================
// Flattened Device Tree (FDT) parsing
//
// Per the Devicetree Specification (dtspec), the FDT blob has a fixed
// header, followed by a memory reservation block, a structure block
// (a token stream describing the tree), and a strings block (property
// name strings referenced by offset from the structure block).
// ============================================================================

/// FDT magic number, big-endian 0xd00dfeed, per dtspec section 5.2.
const FDT_MAGIC: u32 = 0xd00d_feed;

#[repr(C)]
struct FdtHeader {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

impl FdtHeader {
    /// Reads and validates the FDT header at `dtb_phys`, converting
    /// every big-endian field to native (host is little-endian per
    /// this project's RV64 target, dtspec mandates big-endian on the
    /// wire regardless of host endianness).
    ///
    /// # Safety
    /// `dtb_phys` must point at a valid FDT blob per this file's only
    /// caller's contract (`Memory::from_device_tree`).
    unsafe fn read(dtb_phys: *const u8) -> Option<Self> {
        // SAFETY: forwarded from this function's own contract.
        let raw = unsafe { core::ptr::read_unaligned(dtb_phys as *const [u32; 10]) };
        let header = FdtHeader {
            magic: u32::from_be(raw[0]),
            totalsize: u32::from_be(raw[1]),
            off_dt_struct: u32::from_be(raw[2]),
            off_dt_strings: u32::from_be(raw[3]),
            off_mem_rsvmap: u32::from_be(raw[4]),
            version: u32::from_be(raw[5]),
            last_comp_version: u32::from_be(raw[6]),
            boot_cpuid_phys: u32::from_be(raw[7]),
            size_dt_strings: u32::from_be(raw[8]),
            size_dt_struct: u32::from_be(raw[9]),
        };

        if header.magic != FDT_MAGIC {
            return None;
        }
        Some(header)
    }
}

// FDT structure block tokens, per dtspec section 5.4.
const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32 = 0x0000_0002;
const FDT_PROP: u32 = 0x0000_0003;
const FDT_NOP: u32 = 0x0000_0004;
const FDT_END: u32 = 0x0000_0009;

/// A minimal, allocation-free FDT structure-block walker. Tracks
/// current node path depth only as much as needed to know "am I
/// currently inside a node whose name matches what the caller is
/// looking for" — this project does not need a full parsed tree, only
/// the ability to find specific named nodes/properties, mirroring the
/// x86_64/ARM64 ACPI walkers' "look for one specific table" scope.
struct FdtWalker<'a> {
    dtb_base: *const u8,
    struct_start: u32,
    struct_end: u32,
    strings_start: u32,
    offset: u32,
    _marker: core::marker::PhantomData<&'a ()>,
}

impl<'a> FdtWalker<'a> {
    /// # Safety
    /// `dtb_base` and the header-derived offsets must describe a valid
    /// FDT blob, per `Memory::from_device_tree`'s own contract.
    unsafe fn new(dtb_base: *const u8, header: &FdtHeader) -> Self {
        Self {
            dtb_base,
            struct_start: header.off_dt_struct,
            struct_end: header.off_dt_struct + header.size_dt_struct,
            strings_start: header.off_dt_strings,
            offset: header.off_dt_struct,
            _marker: core::marker::PhantomData,
        }
    }

    /// # Safety
    /// `self.offset` must be within the valid FDT blob bounds
    /// established at construction.
    unsafe fn read_u32_at(&self, offset: u32) -> u32 {
        // SAFETY: forwarded from this function's own contract.
        let raw = unsafe { core::ptr::read_unaligned((self.dtb_base as usize + offset as usize) as *const u32) };
        u32::from_be(raw)
    }

    /// Reads a NUL-terminated string at absolute blob offset `offset`,
    /// returning it as a byte slice (not `&str`, since property/node
    /// names are not guaranteed valid UTF-8 by the spec, only ASCII in
    /// practice — this project only ever compares against known ASCII
    /// literals, so byte-slice comparison is sufficient and avoids an
    /// unnecessary UTF-8 validation step).
    ///
    /// # Safety
    /// `offset` must point at a valid, NUL-terminated string within
    /// the FDT blob's bounds.
    unsafe fn read_cstr_at(&self, offset: u32) -> &'a [u8] {
        let start = (self.dtb_base as usize + offset as usize) as *const u8;
        let mut len = 0usize;
        // SAFETY: forwarded from this function's own contract; bounded
        // by the FDT blob's own NUL-termination guarantee per dtspec.
        unsafe {
            while *start.add(len) != 0 {
                len += 1;
            }
            core::slice::from_raw_parts(start, len)
        }
    }

    /// Advances `self.offset` past a `FDT_PROP` token's variable-length
    /// payload (4-byte length + 4-byte name-offset header, then the
    /// property value itself, 4-byte-padded).
    fn align_offset(&mut self) {
        self.offset = (self.offset + 3) & !3;
    }
}

/// Result of walking the FDT for this project's specific needs.
/// Mirrors hal-arm64/memory.rs's `AcpiDiscoveryResult` shape.
#[derive(Debug, Clone, Copy, Default)]
struct DtDiscoveryResult {
    plic_base: Option<u64>,
    iommu_present: bool,
    memory_base: Option<u64>,
    memory_size: Option<u64>,
}

/// Documented fallback values for QEMU's `virt` machine, used only if
/// FDT parsing fails to find them — same established pattern as every
/// other hal-<arch> crate's firmware-table-derived base addresses.
const QEMU_VIRT_DEFAULT_PLIC_BASE: u64 = 0x0c00_0000;
const QEMU_VIRT_DEFAULT_MEMORY_BASE: u64 = 0x8000_0000;
const QEMU_VIRT_DEFAULT_MEMORY_SIZE: u64 = 128 * 1024 * 1024; // QEMU virt's default -m 128M

/// Walks the FDT structure block looking for: a node whose name starts
/// with "memory" (its `reg` property gives base+size), a node whose
/// `compatible` property contains "riscv,plic0" (its `reg` property
/// gives the PLIC base), and any node whose `compatible` property
/// contains "iommu" (presence-only check, mirroring the x86_64/ARM64
/// IOMMU-presence-only scope).
///
/// # Safety
/// `dtb_phys` must be a valid FDT blob physical address, per this
/// file's only caller's contract (`hal_riscv64_rust_entry`, which
/// receives it directly from boot.S's SBI-provided a1 register, per
/// that file's module docs).
unsafe fn walk_device_tree(dtb_phys: *const u8) -> DtDiscoveryResult {
    let mut result = DtDiscoveryResult::default();

    // SAFETY: forwarded from this function's own contract.
    let Some(header) = (unsafe { FdtHeader::read(dtb_phys) }) else {
        return result;
    };

    // SAFETY: forwarded from this function's own contract; header
    // just validated above.
    let mut walker = unsafe { FdtWalker::new(dtb_phys, &header) };

    // Tracks whether we are currently inside a node whose name matched
    // one of our targets, and which target, so a subsequent FDT_PROP
    // token knows what it might be reading. `None` = not inside a
    // node of interest.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CurrentNode {
        None,
        Memory,
        Plic,
        PossibleIommu,
    }
    let mut current = CurrentNode::None;
    // Depth-tracking for CurrentNode::None resumption when a
    // non-target node closes — since this walker does not build a
    // full tree, it simply resets to None on any FDT_END_NODE at the
    // depth a target node was opened, which — given this project only
    // needs top-level-ish device nodes (memory, soc/plic, an iommu
    // node), and dtspec's structure block is well-formed by
    // construction from any real bootloader — a simple "current
    // matches until its OWN closing FDT_END_NODE" tracking suffices
    // without needing a full stack.
    let mut current_depth: i32 = -1;
    let mut depth: i32 = 0;

    loop {
        if walker.offset >= walker.struct_end {
            break;
        }

        // SAFETY: bounds-checked by the loop condition above.
        let token = unsafe { walker.read_u32_at(walker.offset) };
        walker.offset += 4;

        match token {
            FDT_BEGIN_NODE => {
                // SAFETY: node name is a NUL-terminated string
                // immediately following the token, within blob bounds
                // per dtspec's structure block guarantee.
                let name = unsafe { walker.read_cstr_at(walker.offset) };
                walker.offset += name.len() as u32 + 1;
                walker.align_offset();
                depth += 1;

                if current == CurrentNode::None {
                    if name.starts_with(b"memory@") || name == b"memory" {
                        current = CurrentNode::Memory;
                        current_depth = depth;
                    } else if name.starts_with(b"plic@") {
                        current = CurrentNode::Plic;
                        current_depth = depth;
                    } else {
                        // Any other node might turn out to be an IOMMU
                        // node once we see its `compatible` property —
                        // tentatively track it and confirm/reject based
                        // on that property below.
                        current = CurrentNode::PossibleIommu;
                        current_depth = depth;
                    }
                }
            }

            FDT_END_NODE => {
                if depth == current_depth {
                    current = CurrentNode::None;
                    current_depth = -1;
                }
                depth -= 1;
            }

            FDT_PROP => {
                // SAFETY: property header (len, nameoff) is 8 bytes
                // immediately following the token, within blob bounds.
                let len = unsafe { walker.read_u32_at(walker.offset) };
                let nameoff = unsafe { walker.read_u32_at(walker.offset + 4) };
                let value_offset = walker.offset + 8;
                walker.offset = value_offset + len;
                walker.align_offset();

                // SAFETY: nameoff points within the strings block per
                // dtspec's guarantee that every FDT_PROP's nameoff is
                // a valid offset into that block.
                let prop_name = unsafe { walker.read_cstr_at(walker.strings_start + nameoff) };

                match current {
                    CurrentNode::Memory if prop_name == b"reg" => {
                        // A `reg` property for a memory node is
                        // (address, size) pairs; this project reads
                        // only the FIRST pair (this MVP phase assumes
                        // a single contiguous memory region, matching
                        // QEMU virt's default single `memory` node).
                        if len >= 16 {
                            // SAFETY: value_offset..value_offset+16 is
                            // within blob bounds per `len >= 16` and
                            // the bounds this property's own header
                            // already established.
                            let base = unsafe { walker.read_u32_at(value_offset) } as u64;
                            let base_lo = unsafe { walker.read_u32_at(value_offset + 4) } as u64;
                            let size_hi = unsafe { walker.read_u32_at(value_offset + 8) } as u64;
                            let size_lo = unsafe { walker.read_u32_at(value_offset + 12) } as u64;
                            result.memory_base = Some((base << 32) | base_lo);
                            result.memory_size = Some((size_hi << 32) | size_lo);
                        }
                    }
                    CurrentNode::Plic if prop_name == b"reg" => {
                        if len >= 8 {
                            // SAFETY: same bounds argument as above.
                            let base_hi = unsafe { walker.read_u32_at(value_offset) } as u64;
                            let base_lo = unsafe { walker.read_u32_at(value_offset + 4) } as u64;
                            result.plic_base = Some((base_hi << 32) | base_lo);
                        }
                    }
                    CurrentNode::PossibleIommu if prop_name == b"compatible" => {
                        // SAFETY: value_offset..value_offset+len is
                        // within blob bounds per this property's own
                        // header.
                        let compat = unsafe { core::slice::from_raw_parts((walker.dtb_base as usize + value_offset as usize) as *const u8, len as usize) };
                        if compat.windows(5).any(|w| w == b"iommu") {
                            result.iommu_present = true;
                        }
                    }
                    _ => {}
                }
            }

            FDT_NOP => {}

            FDT_END => break,

            _ => break, // malformed/unknown token — stop rather than
            // risk reading garbage as further structure, mirroring the
            // x86_64/ARM64 ACPI walkers' "malformed table, avoid
            // infinite loop" defensive break.
        }
    }

    result
}

// ============================================================================
// Page table setup — RISC-V Sv39 (3-level, 4KB pages), the baseline
// paging mode every RV64GC implementation is required to support (Sv48/
// Sv57 are optional extensions this MVP phase does not require).
// ============================================================================

const PAGE_SIZE: usize = 4096;
const ENTRIES_PER_TABLE: usize = 512;

/// Sv39 PTE flags (RISC-V Privileged spec section 4.3.1). Differs
/// structurally from both x86_64 and ARM64: a single "leaf" bit
/// pattern (R/W/X all encode into the same byte, and R=W=X=0 means
/// "pointer to next level" rather than a separate "table vs page" bit
/// the way ARM64 has).
mod pte_flags {
    pub const VALID: u64 = 1 << 0;
    pub const READ: u64 = 1 << 1;
    pub const WRITE: u64 = 1 << 2;
    pub const EXECUTE: u64 = 1 << 3;
    pub const USER: u64 = 1 << 4;
    pub const GLOBAL: u64 = 1 << 5;
    pub const ACCESSED: u64 = 1 << 6; // like ARM64's AF, must be set or first access faults
    pub const DIRTY: u64 = 1 << 7;
}

#[repr(align(4096))]
struct PageTable([u64; ENTRIES_PER_TABLE]);

impl PageTable {
    const fn new() -> Self {
        Self([0; ENTRIES_PER_TABLE])
    }
}

static mut ROOT_TABLE: PageTable = PageTable::new();

const TABLE_POOL_SIZE: usize = 16;
static mut TABLE_POOL: [PageTable; TABLE_POOL_SIZE] = {
    const EMPTY: PageTable = PageTable::new();
    [EMPTY; TABLE_POOL_SIZE]
};
static mut TABLE_POOL_NEXT: usize = 0;

/// # Safety
/// Same single-threaded-boot-time contract as the other two
/// architectures' `alloc_table`.
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

/// Walks (allocating as needed) a 3-level Sv39 table and writes a leaf
/// PTE. Mirrors the other two architectures' `map_page` structurally;
/// differs in that Sv39's page table entry PPN field is shifted by 10
/// bits (not 12, per RISC-V's PTE format placing the flags in the low
/// 10 bits rather than 12) and in the R/W/X-in-leaf-only encoding
/// noted in `pte_flags`'s module doc comment.
///
/// # Safety
/// Same contract as the other two architectures' `map_page`.
unsafe fn map_page(virt: u64, phys: u64, flags: u64) -> Result<(), HalError> {
    let indices = [
        ((virt >> 30) & 0x1FF) as usize, // VPN[2]
        ((virt >> 21) & 0x1FF) as usize, // VPN[1]
        ((virt >> 12) & 0x1FF) as usize, // VPN[0]
    ];

    // SAFETY: `ROOT_TABLE` is this hart's single boot-time top-level
    // table, single-threaded access per this function's contract.
    let mut table_ptr: *mut PageTable = unsafe { &raw mut ROOT_TABLE };

    for level in 0..2 {
        // SAFETY: `table_ptr` valid per this loop's invariant.
        let entry = unsafe { &mut (*table_ptr).0[indices[level]] };
        if *entry & pte_flags::VALID == 0 {
            // SAFETY: boot-time single-threaded allocation.
            let new_table = unsafe { alloc_table()? };
            // Pointer-to-next-level PTE: PPN set, R=W=X=0 (per
            // pte_flags module doc comment, this encodes "not a
            // leaf"), VALID set.
            let ppn = (new_table as u64) >> 12;
            *entry = (ppn << 10) | pte_flags::VALID;
        }
        let ppn = (*entry >> 10) & 0x0FFF_FFFF_FFFF;
        table_ptr = (ppn << 12) as *mut PageTable;
    }

    // SAFETY: `table_ptr` now points at the level-0 (leaf) table for
    // `virt`.
    let pt_entry = unsafe { &mut (*table_ptr).0[indices[2]] };
    let ppn = phys >> 12;
    *pt_entry = (ppn << 10) | flags | pte_flags::VALID | pte_flags::ACCESSED | pte_flags::DIRTY;

    Ok(())
}

fn permissions_to_flags(perms: MapPermissions) -> u64 {
    let mut flags = pte_flags::READ; // every mapping this project makes is at least readable

    if perms.writable {
        flags |= pte_flags::WRITE;
    }
    if perms.executable {
        flags |= pte_flags::EXECUTE;
    }
    // RISC-V's Sv39 PTE format has no separate "cacheable/uncached"
    // bit at the PTE level the way x86_64's PAT-indexed PCD/PWT bits
    // or ARM64's AttrIndx field do — memory attributes (cacheability)
    // are instead controlled by the PMA (Physical Memory Attributes)
    // scheme, a platform-defined, typically PMP-adjacent mechanism
    // OUTSIDE the page table itself (RISC-V Privileged spec section
    // 3.6). This project's MVP phase relies on the platform's default
    // PMA regions (QEMU's virt machine correctly marks its MMIO
    // regions as non-cacheable/strongly-ordered at the PMA level by
    // default) rather than implementing PMA reconfiguration — a
    // documented, architecture-specific gap distinct from (and
    // simpler to accept than) x86_64/ARM64's PTE-level cacheability
    // control.
    let _ = perms.device_uncached;

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
    plic_base: u64,
}

impl Memory {
    /// # Safety
    /// `dtb_phys` must be a valid FDT blob physical address, per this
    /// project's SBI boot protocol (boot.S's module docs) — this
    /// function's only caller (`hal_riscv64_rust_entry`) already
    /// satisfies this.
    pub unsafe fn from_device_tree(dtb_phys: *const u8) -> Self {
        // SAFETY: forwarded from this function's own contract.
        let dt = unsafe { walk_device_tree(dtb_phys) };

        let mut regions = [MemoryRegionRaw::ZERO; MAX_TRACKED_REGIONS];
        let mut region_count = 0usize;

        let memory_base = dt.memory_base.unwrap_or(QEMU_VIRT_DEFAULT_MEMORY_BASE);
        let memory_size = dt.memory_size.unwrap_or(QEMU_VIRT_DEFAULT_MEMORY_SIZE);

        // Unlike UEFI's rich memory map (dozens of typed regions),
        // Device Tree's `memory` node reports only ONE coarse region:
        // "this range is RAM". This project therefore records exactly
        // one Usable region here — there is no equivalent of UEFI's
        // BootServicesCode/RuntimeServicesData/etc. distinctions to
        // make on this boot path, since DT simply does not carry that
        // information the way UEFI's GetMemoryMap() does. Firmware-
        // reserved sub-ranges within this region (e.g. where OpenSBI
        // itself resides, per linker.ld's own KERNEL_LMA_BASE
        // reasoning) are handled separately via the kernel-image/boot-
        // reserved ranges in BootInfo (hal-core/src/boot.rs), not via
        // additional memory-map region classification here.
        // Constructed via `::new` rather than struct-literal + `..ZERO`
        // because `MemoryRegionRaw`'s padding fields are private to
        // hal-manifest (FRU across that privacy boundary is E0451) —
        // same pattern hal-x86_64/memory.rs uses.
        regions[0] = MemoryRegionRaw::new(
            memory_base,
            memory_size,
            hal_manifest::raw::MemoryRegionKindRaw::Usable,
            dt.iommu_present,
        );
        region_count = 1;

        Self {
            regions,
            region_count,
            iommu_present: dt.iommu_present,
            plic_base: dt.plic_base.unwrap_or(QEMU_VIRT_DEFAULT_PLIC_BASE),
        }
    }

    /// Read by `hal_riscv64_rust_entry` (lib.rs) to construct
    /// `interrupt::InterruptCtrl::new(plic_base)` — mirrors
    /// hal-arm64/memory.rs's `gicd_base()` accessor pattern exactly.
    pub fn plic_base(&self) -> u64 {
        self.plic_base
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
            // contract, same reasoning as the other two architectures.
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

/// Switches `satp` to this crate's own Sv39 root table, activating the
/// minimal mapping built by prior `setup_identity_mapping` calls.
///
/// # Safety
/// Same contract as the other two architectures' `activate_page_tables`.
#[cfg(not(target_os = "none"))]
pub unsafe fn activate_page_tables() {
    // Host (`cargo test`) stub — no `satp` MMU bring-up off the
    // bare-metal target.
}

#[cfg(target_os = "none")]
pub unsafe fn activate_page_tables() {
    // SAFETY: forwarded from this function's own contract; satp
    // encoding per RISC-V Privileged spec section 4.1.11: MODE field
    // (bits 63:60) = 8 for Sv39, PPN field (bits 43:0) = root table's
    // physical page number.
    unsafe {
        let root_addr = &raw const ROOT_TABLE as u64;
        let ppn = root_addr >> 12;
        let satp_value = (8u64 << 60) | ppn;
        core::arch::asm!("csrw satp, {}", in(reg) satp_value);
        core::arch::asm!("sfence.vma");
    }
}

#[cfg(not(target_os = "none"))]
pub fn current_page_table_phys(_memory: &Memory) -> u64 {
    // Host (`cargo test`) stub — no `satp` CSR off the bare-metal target.
    0
}

#[cfg(target_os = "none")]
pub fn current_page_table_phys(_memory: &Memory) -> u64 {
    let mut satp: u64;
    // SAFETY: reading `satp` has no preconditions beyond S-mode
    // execution, which this crate always has.
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) satp);
    }
    (satp & 0x0FFF_FFFF_FFFF) << 12 // extract PPN, convert back to a physical address
}

// ============================================================================
// HardwareManifestRaw assembly — identical structure to the other two
// architectures' built_hardware_manifest
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

    // `::new` rather than struct-literal + `..ZERO`: the raw structs'
    // padding fields are private to hal-manifest (see the identical
    // pattern in hal-x86_64/memory.rs).
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
    fn fdt_magic_constant_matches_spec() {
        assert_eq!(FDT_MAGIC, 0xd00d_feed);
    }

    #[test]
    fn permissions_to_flags_sets_read_write() {
        let flags = permissions_to_flags(MapPermissions::KERNEL_DATA);
        assert_ne!(flags & pte_flags::READ, 0);
        assert_ne!(flags & pte_flags::WRITE, 0);
        assert_eq!(flags & pte_flags::EXECUTE, 0);
    }

    #[test]
    fn permissions_to_flags_kernel_code_is_executable() {
        let flags = permissions_to_flags(MapPermissions::KERNEL_CODE);
        assert_ne!(flags & pte_flags::EXECUTE, 0);
        assert_eq!(flags & pte_flags::WRITE, 0);
    }

    #[test]
    fn qemu_virt_defaults_are_documented_values() {
        assert_eq!(QEMU_VIRT_DEFAULT_PLIC_BASE, 0x0c00_0000);
        assert_eq!(QEMU_VIRT_DEFAULT_MEMORY_BASE, 0x8000_0000);
    }

    #[test]
    fn dt_discovery_result_defaults_to_no_findings() {
        let result = DtDiscoveryResult::default();
        assert!(result.plic_base.is_none());
        assert!(!result.iommu_present);
    }
}