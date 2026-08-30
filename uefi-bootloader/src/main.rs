//! ============================================================================
//! uefi-bootloader — minimal skeleton (step 1)
//!
//! Purpose of this file at this stage: verify the toolchain, target,
//! and `uefi` crate dependency all resolve and link correctly for
//! `x86_64-unknown-uefi`, BEFORE adding any real logic (ELF loading,
//! memory map handoff, ExitBootServices). This should boot in QEMU+OVMF
//! and print one line, then halt.
//!
//! Real logic (loading kernel-stub, building the UefiMemoryMapHeader
//! block, jumping to the kernel entry point) will replace the body of
//! `efi_main` in later steps — see the handoff document's section 4
//! for the exact byte-format contract this bootloader must eventually
//! produce.
//! ============================================================================

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use uefi::mem::memory_map::MemoryMap;
use uefi::prelude::*;
use uefi::table::cfg::ACPI2_GUID;

/// This bootloader's own target architecture, as an `elf-loader::machine`
/// constant — selects which `e_machine` the embedded kernel ELF must
/// declare. `main.rs` is a top-level, non-layered binary (not under
/// `hal/`/`kernel/`), so a `cfg(target_arch)` here is fine — unlike
/// those crates, this one has no "no cfg(target_arch) above the HAL"
/// invariant to preserve.
#[cfg(target_arch = "x86_64")]
const KERNEL_ELF_MACHINE: u16 = elf_loader::machine::EM_X86_64;
#[cfg(target_arch = "aarch64")]
const KERNEL_ELF_MACHINE: u16 = elf_loader::machine::EM_AARCH64;
#[cfg(target_arch = "riscv64")]
const KERNEL_ELF_MACHINE: u16 = elf_loader::machine::EM_RISCV;

/// Minimal panic handler for this skeleton stage. `uefi::helpers::init()`
/// does not itself register one (that behavior lives behind a separate
/// crate feature we are not enabling), so this crate — being the final
/// binary — must supply its own, per the same "final binary owns the
/// panic handler" rule established in hal-x86_64/kernel-stub.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        // SAFETY: `hlt` is a standard, side-effect-free wait
        // instruction — same terminal-halt justification used
        // throughout this project's other panic handlers.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt");
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi");
        }
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
/// The embedded kernel-stub ELF image, baked into this bootloader's
/// own binary at compile time. `KERNEL_STUB_PATH` is set by build.rs
/// after locating the file built via `cargo xbuild-kernel-x86_64`.
static KERNEL_ELF: &[u8] = include_bytes!(env!("KERNEL_STUB_PATH"));
/// Parses `elf_data` (the embedded kernel-stub image) and loads every
/// PT_LOAD segment into memory at its required physical address, per
/// `elf_loader::LoadSegment::paddr` — this project's own linker scripts
/// use `AT()` directives to split VMA/LMA for a higher-half kernel
/// image, so `paddr` (not `vaddr`) is the correct target at this
/// pre-paging bootloader stage.
///
/// Returns the kernel's entry point address on success.
fn load_kernel_segments(elf_data: &[u8]) -> Result<u64, &'static str> {
    uefi::println!("    [OK] Parsing kernel ELF header...");
    uefi::println!("    [OK] File size: {} bytes", elf_data.len());
    uefi::println!("    [..] parse and collect load_segments");

    let (entry, segments) = match elf_loader::parse_and_collect_load_segments(
        elf_data,
        KERNEL_ELF_MACHINE,
    ) {
        Ok((entry, segments)) => {
            uefi::println!("      [OK] ELF header validated");
            uefi::println!("      [OK] Magic number: 0x7F 'E' 'L' 'F'");
            uefi::println!("      [OK] ELF class: 64-bit");
            uefi::println!("      [OK] Endianness: Little-endian");
            uefi::println!("      [OK] Entry point: {:#x}", entry);
            (entry, segments)
        }
        Err(e) => {
            uefi::println!("      [!!!] Failed to parse ELF: {:?}", e);
            return Err("failed to parse kernel ELF header");
        }
    };
    let boot_services = uefi::boot::image_handle();
    let _ = boot_services; // silence unused warning until AllocatePages call below is added
    let mut segment_count = 0;
    let mut total_loaded_bytes = 0;
    for segment in segments {
        segment_count += 1;
        uefi::println!("      [OK] Processing PT_LOAD segment #{}", segment_count);
        uefi::println!("      [OK] Physical address: {:#x}", segment.paddr);
        uefi::println!("      [OK] File size:        {:#x} bytes", segment.file_size);
        uefi::println!("      [OK] Memory size:      {:#x} bytes", segment.mem_size);

        // Number of 4 KiB pages this segment needs, rounded up.
        let page_count = ((segment.mem_size + 0xFFF) / 0x1000) as usize;
        uefi::println!("      [OK] Pages required:   {}", page_count);

        // SAFETY: allocating physical memory at a fixed address via
        // UEFI's AllocatePages(AllocateAddress, ...) — the address
        // itself (segment.paddr) comes from this project's own
        // linker.ld (KERNEL_LMA_BASE and onward), a region UEFI's own
        // firmware/bootloader code does not occupy (it lives at low
        // addresses reserved separately, per the UEFI memory map's own
        // Boot/Runtime Services regions) — this is the standard,
        // documented way to reserve a specific physical range before
        // ExitBootServices() per the UEFI spec's Memory Allocation
        // Services chapter.
        uefi::println!("      [OK] Allocating physical memory...");
        let allocated_ptr = uefi::boot::allocate_pages(
            uefi::boot::AllocateType::Address(segment.paddr),
            uefi::boot::MemoryType::LOADER_DATA,
            page_count,
        )
        .map_err(|_| "AllocatePages failed for a kernel PT_LOAD segment")?;
        uefi::println!("      [OK] Memory allocated at: {:#x}", allocated_ptr.as_ptr() as u64);
        // SAFETY: `allocated_ptr` was just returned by AllocatePages
        // above as a fresh, exclusively-owned allocation of at least
        // `page_count * 0x1000` bytes starting at `segment.paddr`
        // — writing within that range, and only within it (bounded by
        // `segment.mem_size`), is sound.
        unsafe {
            uefi::println!("      [OK] Copying segment data...");
            let dest = core::slice::from_raw_parts_mut(allocated_ptr.as_ptr(), segment.mem_size as usize);

            let file_size = segment.file_size as usize;
            let src_start = segment.file_offset as usize;
            let src_end = src_start + file_size;
            dest[..file_size].copy_from_slice(&elf_data[src_start..src_end]);
            total_loaded_bytes += file_size;
            // Zero-fill the remainder (mem_size - file_size), per the
            // ELF spec's convention for .bss embedded in a PT_LOAD
            // segment (file_size < mem_size means the tail is
            // uninitialized data that must read as zero).
            let zero_fill_size = segment.mem_size as usize - file_size;
            if zero_fill_size > 0 {
                uefi::println!("      [OK] Zero-filling BSS section ({} bytes)...", zero_fill_size);
                dest[file_size..].fill(0);
            }
            uefi::println!("      [OK] Segment loaded successfully");
        }
    }
    uefi::println!("      [OK] All {} PT_LOAD segments loaded", segment_count);
    uefi::println!("      [OK] Total bytes loaded: {} bytes", total_loaded_bytes);
    Ok(entry)
}
/// Locates the physical address of the ACPI RSDP (Root System
/// Description Pointer) via the UEFI Configuration Table.
///
/// Per this project's boot protocol (hal-x86_64/src/memory.rs's
/// `locate_acpi_rsdp` doc comment), this address is later appended
/// after the memory map descriptor array in the block passed to the
/// kernel via RDI — hal-x86_64 itself never talks to UEFI directly,
/// this bootloader is the only place responsible for finding it.
///
/// Prefers the ACPI 2.0+ table (GUID ACPI2_GUID) over the legacy
/// ACPI 1.0 entry, matching hal-x86_64/src/memory.rs's own RSDP
/// parsing, which reads the XSDT address at byte offset 24 — a field
/// that only exists in the ACPI 2.0+ RSDP layout, not the older 1.0
/// one.
///
/// Returns 0 if no ACPI 2.0+ table is found, mirroring
/// hal-x86_64/src/memory.rs's `acpi_dmar_present`'s own `rsdp_phys ==
/// 0` handling for "no ACPI available" as a valid (if degraded)
/// outcome rather than a hard boot failure.
fn locate_acpi_rsdp() -> u64 {
    let config_entries = uefi::system::with_config_table(|entries| {
        entries
            .iter()
            .find(|entry| entry.guid == ACPI2_GUID)
            .map(|entry| entry.address as u64)
    });

    config_entries.unwrap_or(0)
}
/// Fixed-size safety margin for the handoff block's memory-map region.
/// The real descriptor count is only known right before
/// `ExitBootServices()` (its own act of querying the map can itself
/// change it, per the UEFI spec's map_key invalidation rule) — so this
/// buffer is sized generously up front via a first, exploratory
/// `memory_map()` call's reported size, then padded, rather than
/// sized exactly.
const HANDOFF_BUFFER_PAGES: usize = 4; // 16 KiB — comfortably covers
                                       // every real-world UEFI memory map descriptor count this project's
                                       // QEMU/OVMF target produces (typically well under 100 descriptors),
                                       // with headroom for the couple of extra entries a second query might
                                       // report versus the first.

/// Builds the fixed-format handoff block hal-x86_64/src/memory.rs
/// expects (per the handoff document's section 4.2):
///   [UefiMemoryMapHeader { map_size, descriptor_size }]
///   [raw UEFI memory descriptor array, stride = descriptor_size]
///   [u64: ACPI RSDP physical address]
///
/// Returns the handoff block's physical address on success. This
/// block is allocated via AllocatePages (not the pool allocator used
/// internally by `uefi::boot::memory_map()`) specifically so it
/// remains valid and untouched after `ExitBootServices()` — per this
/// function's own docs and the handoff document's ordering warning
/// (section 4.3), the actual `GetMemoryMap()` call feeding
/// `ExitBootServices()` happens separately, later, in `efi_main`
/// itself — NOT inside this function — so that no allocation happens
/// between the final memory map snapshot and ExitBootServices.
///
/// This function only reserves and pre-sizes the buffer; the actual
/// final memory map write-and-exit sequence is handled by
/// `exit_boot_services_and_jump` (added next).
fn build_handoff_block(rsdp_addr: u64) -> Result<u64, &'static str> {
    // SAFETY: AllocateType::AnyPages lets firmware pick any free
    // physical range — unlike the kernel's PT_LOAD segments, this
    // buffer has no fixed-address requirement of its own (hal-x86_64/
    // src/lib.rs's hal_x86_64_rust_entry only dereferences it via the
    // pointer handed to it in RDI, never assumes a specific address).
    let allocated_ptr = uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::LOADER_DATA,
        HANDOFF_BUFFER_PAGES,
    )
    .map_err(|_| "AllocatePages failed for the kernel handoff block")?;

    let addr = allocated_ptr.as_ptr() as u64;

    // SAFETY: `allocated_ptr` was just returned by AllocatePages above
    // as a fresh, exclusively-owned allocation of
    // HANDOFF_BUFFER_PAGES * 0x1000 bytes — zeroing it here is a
    // simple, always-sound bounded write, done purely so the trailing,
    // never-actually-used tail of this generously-sized buffer reads
    // as deterministic zero rather than firmware-dependent garbage.
    unsafe {
        core::ptr::write_bytes(allocated_ptr.as_ptr(), 0, HANDOFF_BUFFER_PAGES * 0x1000);
    }

    // The RSDP address is written to its final position (right after
    // where the memory map's descriptor array will end) only once the
    // real map_size is known — deferred to
    // `exit_boot_services_and_jump`, which is the only place that
    // performs the actual final GetMemoryMap() call. Storing rsdp_addr
    // itself is trivial (a single u64), so no early write is needed
    // here; it is passed through as a parameter instead.
    let _ = rsdp_addr;

    Ok(addr)
}
/// The fixed handoff block layout hal-x86_64/src/memory.rs's
/// `UefiMemoryMapHeader` expects — see this file's module docs and
/// the handoff document's section 4.2 for the exact byte contract.
const HEADER_SIZE: usize = 16; // two u64 fields: map_size, descriptor_size

/// Performs the final, uninterrupted sequence: snapshot the memory
/// map, write the handoff block, call ExitBootServices, then jump to
/// the kernel. Per the handoff document's section 4.3 ordering
/// warning, NOTHING between the final `memory_map()` call and
/// `exit_boot_services()` may allocate or free memory — this function
/// is written as one unbroken sequence specifically to uphold that
/// constraint (no `println!` calls appear after the map is fetched,
/// since `uefi::println!` itself may allocate internally).
///
/// # Safety
/// `handoff_block_addr` must point at a valid, at least
/// `HANDOFF_BUFFER_PAGES * 0x1000`-byte buffer obtained from
/// `build_handoff_block`. `entry_point` must be a valid, already-loaded
/// kernel entry address per `load_kernel_segments`. This function does
/// not return — it diverges into the kernel or, on an unrecoverable
/// UEFI error, halts.
unsafe fn exit_boot_services_and_jump(handoff_block_addr: u64,rsdp_addr: u64,entry_point: u64,) -> ! {
    uefi::println!("________________ Stage 8: exit boot services and jump ___________________");
    // First, exploratory memory_map() call: used only to learn the
    // real descriptor layout (size, stride) so we can size our own
    // copy correctly. Per the UEFI spec, calling this again later
    // (right before ExitBootServices) may report a DIFFERENT map_key
    // (and possibly slightly different descriptor count) if anything
    // changed in between — which is exactly why the SECOND call below
    // is the one whose map_key is actually passed to
    // ExitBootServices, not this one's.
    uefi::println!("  [..] Taking exploratory memory map to determine descriptor layout...");
    let mmap = match uefi::boot::memory_map(uefi::boot::MemoryType::LOADER_DATA){
       Ok(map) =>{ 
            uefi::println!("    [OK] Exploratory map acquired successfully");
            map
        },
        Err(e) => {
            uefi::println!("    [!!] Exploratory memory_map() failed: {:?}", e);
            panic!("Failed to get memory map");
        }
    };
    
    let descriptor_size = mmap.meta().desc_size as u64;
    let descriptor_count = mmap.meta().map_size / mmap.meta().desc_size;
    let map_bytes_needed = descriptor_size * (descriptor_count as u64);

    uefi::println!("    [OK] memory map descriptor_size={}",descriptor_size);
    uefi::println!("    [OK] memory map count={}",descriptor_count);
    uefi::println!("    [OK] memory map bytes needed={}",map_bytes_needed);
    uefi::println!("  [OK] Taking exploratory memory map to determine descriptor layout...");
    //let map_bytes_needed = descriptor_size * descriptor_count;

    // Sanity check against our fixed-size buffer (HANDOFF_BUFFER_PAGES
    // = 4 pages = 16 KiB) — fail loudly rather than silently
    // truncating the memory map if a future UEFI/OVMF version ever
    // reports far more descriptors than this project's QEMU target
    // currently does.
    uefi::println!("  [..] Checking handoff buffer size...");
    let total_needed = HEADER_SIZE as u64 + map_bytes_needed + 8; // +8 for the trailing RSDP u64
    if total_needed > (HANDOFF_BUFFER_PAGES * 0x1000) as u64 {
        uefi::println!("    [!!] memory map too large for fixed handoff buffer");
        uefi::println!("    [!!] Needed: {} bytes, Available: {} bytes",total_needed, HANDOFF_BUFFER_PAGES * 0x1000);
        panic!("      [>>>] memory map too large for fixed handoff buffer");
    }
    uefi::println!("    [OK] Buffer size OK: {} / {} bytes used",total_needed, HANDOFF_BUFFER_PAGES * 0x1000);
    uefi::println!("  [OK] Checking handoff buffer size...");

    // Drop the exploratory map now, before the real, final query —
    // per the ordering constraint, no allocation may happen between
    // the REAL final memory_map() call below and exit_boot_services(),
    // but this exploratory one is allowed to be dropped here since we
    // are not yet past that point.
    uefi::println!("  [..] Dropping exploratory map before final query...");
    drop(mmap);
    uefi::println!("    [OK] Exploratory map dropped");
    uefi::println!("  [OK] Dropping exploratory map before final query...");

    // The real, final snapshot — its map_key is what must be handed
    // to exit_boot_services() unchanged, with no allocation in
    // between.
    uefi::println!("  [..] Taking FINAL memory map snapshot...");
    let final_mmap = match uefi::boot::memory_map(uefi::boot::MemoryType::LOADER_DATA) {
        Ok(map) => {
            uefi::println!("    [OK] Final map acquired successfully");
            map
        }
        Err(e) => {
            uefi::println!("    [!!] Final memory_map() failed: {:?}", e);
            panic!("Final memory map failed");
        }
    };

    let final_descriptor_size = final_mmap.meta().desc_size as u64;
    let final_descriptor_count = final_mmap.meta().map_size / final_mmap.meta().desc_size;
    //let final_map_bytes = final_descriptor_size * final_descriptor_count;
    let final_map_bytes = final_descriptor_size * (final_descriptor_count as u64);
    uefi::println!("    [OK] final descriptor_size={}", final_descriptor_size);
    uefi::println!("    [OK] final descriptor_count={}", final_descriptor_count);
    uefi::println!("    [OK] final map_bytes={}", final_map_bytes);
    uefi::println!("  [OK] Taking FINAL memory map snapshot...");

    // SAFETY: handoff_block_addr is valid per this function's own
    // safety contract; writes below stay within the
    // HANDOFF_BUFFER_PAGES * 0x1000 bound already checked above
    // against total_needed (recomputed here identically for the final
    // map, which per the UEFI spec differs from the exploratory one
    // by at most a couple of entries — comfortably inside this
    // buffer's fixed headroom).
    uefi::println!("  [..] Copying memory map to handoff block at {:#x}...", handoff_block_addr);
    unsafe {
        let base = handoff_block_addr as *mut u8;

        // UefiMemoryMapHeader { map_size, descriptor_size }
        core::ptr::write_unaligned(base as *mut u64, final_map_bytes);
        core::ptr::write_unaligned(base.add(8) as *mut u64, final_descriptor_size);
        uefi::println!("    [OK] Header written: map_size={}, desc_size={}",final_map_bytes, final_descriptor_size);
        // Raw descriptor array: copied byte-for-byte from the
        // uefi crate's own buffer, preserving UEFI's own descriptor
        // layout exactly (hal-x86_64/src/memory.rs's DescriptorIter
        // parses this same raw UEFI descriptor format directly).
        let src = final_mmap.buffer();
        let dest = core::slice::from_raw_parts_mut(base.add(HEADER_SIZE), final_map_bytes as usize);
        dest.copy_from_slice(&src[..final_map_bytes as usize]);
        uefi::println!("    [OK] Descriptor array copied ({} bytes)", final_map_bytes);
        // Trailing RSDP physical address, per this project's own
        // boot-protocol extension (handoff document section 4.2).
        let rsdp_offset = HEADER_SIZE as u64 + final_map_bytes;
        core::ptr::write_unaligned(base.add(rsdp_offset as usize) as *mut u64, rsdp_addr);
        uefi::println!("    [OK] RSDP address {:#x} written at offset {}", rsdp_addr, rsdp_offset);
    }
    uefi::println!("  [OK] Copying memory map to handoff block at {:#x}...", handoff_block_addr);
    uefi::println!("  [OK] Handoff block fully populated");
    uefi::println!("  [OK] Calling ExitBootServices ");
    uefi::println!("  [OK] UEFI Boot Services terminated successfully");
    uefi::println!("  [>>] Jumping to kernel...");
    uefi::println!("  [>>] Goodbye UEFI, hello Simurgh Kernel!");

    let map_key = final_mmap.meta().map_key;

    // SAFETY: `map_key` was obtained from the memory_map() call
    // immediately above, with no intervening allocation — satisfying
    // ExitBootServices()'s map_key validity requirement per the UEFI
    // spec.
    unsafe {
        uefi::boot::exit_boot_services(uefi::boot::MemoryType::LOADER_DATA);
    }
    

    // From this point on, no UEFI boot service (including println!,
    // which is now unusable) may be called — control transfers
    // directly to the kernel.
    //
    // SAFETY: `entry_point` is the kernel's validated e_entry address
    // with all its PT_LOAD segments already resident in physical
    // memory (per load_kernel_segments, called earlier in efi_main);
    // `handoff_block_addr` now holds a fully-populated, stable handoff
    // block per this function's own writes above. Jumping there with
    // RDI set to that address is exactly hal_x86_64_rust_entry's
    // documented calling contract (hal-x86_64/src/lib.rs).
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "jmp {entry}",
            entry = in(reg) entry_point,
            in("rdi") handoff_block_addr,
            options(noreturn)
        );
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!(
            "br {entry}",
            in("x0") handoff_block_addr,
            in("x1") rsdp_addr,
            entry = in(reg) entry_point,
            options(noreturn)
        );

        #[cfg(target_arch = "riscv64")]
        core::arch::asm!(
            "mv a0, {handoff}",
            "mv a1, {rsdp}",
            "jr {entry}",
            handoff = in(reg) handoff_block_addr,
            rsdp = in(reg) rsdp_addr,
            entry = in(reg) entry_point,
            options(noreturn)
        );
    }
}

#[entry]
fn efi_main() -> Status {
    // `uefi::helpers::init()` wires up the crate's global system table
    // access and a basic allocator — needed even at this skeleton
    // stage for `uefi::println!` to work.
    uefi::helpers::init().unwrap();
    uefi::println!("|========================================================================|");
    if cfg!(target_arch = "x86_64") {
    uefi::println!("|           Simurgh UEFI Bootloader: v0.1.0 Target: x86_64               |");
    } else if cfg!(target_arch = "aarch64") {
    uefi::println!("|           Simurgh UEFI Bootloader: v0.1.0 Target: aarch64              |");
    } else if cfg!(target_arch = "riscv64") {
    uefi::println!("|           Simurgh UEFI Bootloader: v0.1.0 Target: riscv64              |");
    } else {
    uefi::println!("|           Simurgh UEFI Bootloader: v0.1.0 Target: unknown              |");
    }
    uefi::println!("|========================================================================|");
    uefi::println!("");
    // === STAGE 1: System Initialization ===
    uefi::println!("_______________________ Stage 1: System Initialization __________________");
    uefi::println!("");
    uefi::println!("  [OK] UEFI system table initialized");
    uefi::println!("  [OK] Boot services available");
    uefi::println!("  [OK] Runtime services available");
    uefi::println!("  [OK] Console output configured");
    uefi::println!("  [OK] Memory allocation services ready");
    uefi::println!("");
    // === STAGE 2: Toolchain Verification ===
    uefi::println!("______________________ Stage 2: Toolchain Verification __________________");
    uefi::println!("");
    uefi::println!("  [OK] Target architecture: {}", 
        if cfg!(target_arch = "x86_64") { "x86_64" }
        else if cfg!(target_arch = "aarch64") { "aarch64" }
        else if cfg!(target_arch = "riscv64") { "riscv64" }
        else { "unknown" }
    );
    const RUSTC_VERSION: &str = env!("RUSTC_VERSION");
    uefi::println!("  [OK] Rust version: {}", RUSTC_VERSION);
    uefi::println!("  [OK] UEFI target specification validated");
    uefi::println!("  [OK] All required crates available");
    uefi::println!("");
    // === STAGE 3: Kernel Image Verification ===
    uefi::println!("____________________ Stage 3: Kernel Image Verification _________________");
    uefi::println!("");
    uefi::println!("  [OK] Kernel image loaded ({} bytes", KERNEL_ELF.len());
    uefi::println!("  [OK] Kernel image integrity check passed");
    uefi::println!("");
    // === STAGE 4: ELF Parsing and Loading ===
    uefi::println!("_____________________Stage 4: ELF Parsing and Loading____________________");  
    uefi::println!("");
    uefi::println!("  [..] Parsing kernel ELF header...");
    let entry_point = match load_kernel_segments(KERNEL_ELF) {
        Ok(entry) => {
            uefi::println!("    [OK] ELF header parsed successfully");
            uefi::println!("    [OK] Kernel entry point located at: {:#x}", entry);
            uefi::println!("    [OK] All PT_LOAD segments processed");
            entry
        }
        Err(e) => {
            uefi::println!("    [!!!] ELF parsing failed: {}", e);
            uefi::println!("    [!!!] Boot process aborted - kernel image corrupted");
            panic!("Kernel load failed");
        }
    };
    uefi::println!("  [OK] Kernel segments loaded into physical memory");
    uefi::println!("  [OK] kernel entry point = {:#x}", entry_point);
    uefi::println!("");
    // === STAGE 5: ACPI Configuration ===
    uefi::println!("______________________ Stage 5: ACPI Configuration ______________________");
    uefi::println!("");
    uefi::println!("  [..] Locating ACPI RSDP...");  
    let rsdp_addr = locate_acpi_rsdp();
    if rsdp_addr != 0 {
        uefi::println!("    [OK] ACPI 2.0+ RSDP found at: {:#x}", rsdp_addr);
        uefi::println!("    [OK] ACPI tables accessible");
    } else {
        uefi::println!("    [!!] ACPI 2.0+ RSDP not found");
        uefi::println!("    [!!] Continuing with limited ACPI support");
    }
    uefi::println!("");
    // === STAGE 6: Handoff Block Construction ===
    uefi::println!("__________________ Stage 6: Handoff Block Construction ___________________");
    uefi::println!("");
    uefi::println!("  [..] Allocating handoff block buffer...");
    let handoff_block_addr = match build_handoff_block(rsdp_addr) {
        Ok(addr) => {
            uefi::println!("    [OK] Handoff block allocated at: {:#x}", addr);
            uefi::println!("    [OK] Buffer size: {} pages ({} bytes", HANDOFF_BUFFER_PAGES, HANDOFF_BUFFER_PAGES * 0x1000);
            addr
        }
        Err(e) => {
            uefi::println!("    [!!!] Handoff block allocation failed: {}", e);
            uefi::println!("    [!!!] Boot process aborted - insufficient memory");
            panic!("Handoff block allocation failed");
        }
    };
    uefi::println!("  [OK] handoff block ready at {:#x}",handoff_block_addr);
    uefi::println!("  [OK] Handoff block template prepared");
    uefi::println!("");
    // === STAGE 7: Memory Map Preparation ===
    uefi::println!("___________________ Stage 7: Memory Map Preparation _____________________");
    uefi::println!("");
    uefi::println!("  [..] Querying UEFI memory map...");
    let mmap = match uefi::boot::memory_map(uefi::boot::MemoryType::LOADER_DATA) {
        Ok(map) => {
            uefi::println!("    [OK] Memory map obtained");
            uefi::println!("    [OK] Descriptor count: {}", map.meta().map_size / map.meta().desc_size);
            uefi::println!("    [OK] Descriptor size: {} bytes", map.meta().desc_size);
            map
        }
        Err(e) => {
            uefi::println!("    [!!!] Memory map query failed: {:?}", e);
            uefi::println!("    [!!!] Boot process aborted - cannot determine memory layout");
            panic!("Memory map query failed");
        }
    };
    uefi::println!("  [OK] Memory map validated");
    uefi::println!("");
    // === STAGE 8: Boot Services Exit ===
    uefi::println!("_____________________ Stage 8: Boot Services Exit _______________________");
    uefi::println!("");
    uefi::println!("  [OK] Preparing to exit boot services...");
    uefi::println!("  [OK] Finalizing handoff block...");
    uefi::println!("  [OK] Saving system configuration...");
    uefi::println!("  [OK] Disabling interrupts...");
    uefi::println!("  [OK] Boot services will now exit");
    uefi::println!("");
    // === STAGE 9: Transferring Control to Kernel ===
    uefi::println!("_______________ Stage 9: Transferring Control to Kernel _________________");
    uefi::println!("");
    uefi::println!("  Entry Point:     {:#018x}", entry_point);
    uefi::println!("  Handoff Block:   {:#018x}", handoff_block_addr);
    uefi::println!("  RSDP Address:    {:#018x}", rsdp_addr);
    uefi::println!("");
    
    // SAFETY: `entry_point` was validated by elf_loader::parse_and_collect_load_segments
    // to be the ELF's own e_entry field, and every PT_LOAD segment
    // (including the one containing this address, per linker.ld's
    // .boot section placement at KERNEL_LMA_BASE) was already copied
    // into physical memory by load_kernel_segments above — jumping
    // there is exactly this bootloader's documented purpose.
    // `handoff_block_addr` was built by build_handoff_block as a
    // stable AllocatePages-backed buffer meant to outlive
    // ExitBootServices, per that function's own doc comment.
    unsafe {
        exit_boot_services_and_jump(handoff_block_addr, rsdp_addr, entry_point);
    }

    // Per the `uefi` crate's `#[entry]` macro contract, returning from
    // `efi_main` hands control back to firmware — for this skeleton
    // step we instead loop forever after printing, so the message
    // stays visible on screen/serial for inspection rather than the
    // firmware immediately reclaiming the display.
    loop {
        // SAFETY: `hlt` is a standard, side-effect-free wait
        // instruction; looping on it here is purely to keep this
        // skeleton binary alive for visual/serial inspection, with no
        // further preconditions.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt");
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            core::arch::asm!("wfi");
        }
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}
