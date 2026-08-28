/* ============================================================================
 * linker.ld — x86_64
 *
 * Links the HAL/microkernel image (boot.S + all Rust code compiled
 * against targets/x86_64-hal.json) into the higher-half kernel layout
 * implied by that target's "code-model": "kernel" setting
 * (01-HAL-Layer.md section 6/7; targets/x86_64-hal.json).
 *
 * Layout summary:
 *   - Entered by a UEFI bootloader stub (section 3.5: "Boot Abstraction
 *     ... UEFI (x86_64/ARM64)"), which loads this image at a
 *     physical address and jumps to `_start` (boot.S) in whatever mode
 *     UEFI leaves the CPU in (long mode, paging already enabled by the
 *     firmware's own identity-mapped page tables).
 *   - `_start` runs briefly at its LOAD (physical-ish, low) address
 *     before HAL's own `MemoryBootstrap::setup_identity_mapping`
 *     (hal-core/src/memory.rs) establishes the higher-half mapping;
 *     this script therefore separates LMA (load address) from VMA
 *     (virtual/link address) via `AT()`, so boot.S can locate its own
 *     early code/data at a known low physical address while the
 *     symbols the Rust code references resolve to the final
 *     higher-half kernel addresses.
 *   - `KERNEL_VMA_BASE` matches the "kernel" code model's assumed
 *     negative-2GB addressing window (0xffffffff80000000 upward),
 *     the same convention Linux x86_64 uses, chosen in
 *     01-HAL-Layer.md section 4's discussion of `code-model: "kernel"`.
 * ========================================================================= */

ENTRY(_start)

/* Higher-half base: top 2GB of the 64-bit address space, matching the
 * "kernel" code model's -mcmodel=kernel assumption (symbols must live
 * within the last 2GB so RIP-relative addressing with a 32-bit
 * displacement stays valid). */
KERNEL_VMA_BASE = 0xffffffff80000000;

/* Physical load address: where the UEFI bootloader stub actually places
 * this image in RAM before jumping to _start. Kept at a conventional
 * low, 2MB-aligned address that avoids the first megabyte (historically
 * reserved / used by firmware structures) and aligns to a 2MB huge-page
 * boundary, which hal-core's setup_identity_mapping (memory.rs) can use
 * directly for its minimal kernel mapping. */
KERNEL_LMA_BASE = 0x00200000;

SECTIONS
{
    . = KERNEL_LMA_BASE;

    /* ------------------------------------------------------------------
     * .boot — the earliest code, per section 7: "بخش‌های bootstrap
     * اولیه... در اسمبلی حداقلی، جدا در فایل boot.S". This section is
     * deliberately linked at its LOAD address (not the higher-half VMA)
     * because boot.S executes BEFORE any page table maps the higher
     * half — it must be directly reachable via the identity/low mapping
     * UEFI itself already set up.
     * ------------------------------------------------------------------ */
    .boot ALIGN(4K) : AT(ADDR(.boot))
    {
        KEEP(*(.boot.header))   /* optional boot protocol header, if any */
        KEEP(*(.boot.text))     /* _start and any code that must run pre-paging-switch */
        *(.boot.data)
    }

    

    /* Symbol upper layers (Root Task, per BootInfo's
     * kernel_image_phys_start/end fields, hal-core/src/boot.rs) use to
     * know exactly where the loaded image begins, so this range is
     * never handed out as free UntypedMemory. */
    __kernel_image_phys_start = KERNEL_LMA_BASE;

    /* ------------------------------------------------------------------
     * .text — all compiled Rust code (hal-core trait implementations,
     * this crate's cpu.rs/memory.rs/timer.rs/interrupt.rs/compute.rs,
     * and eventually the microkernel itself, linked into this same
     * Privileged binary per 01-HAL-Layer.md section 0).
     * ------------------------------------------------------------------ */
    .text ALIGN(4K) : AT(ADDR(.text))
    {
        *(.text .text.*)
    }

    /* ------------------------------------------------------------------
     * .rodata — read-only data: string constants, the HalError Display
     * messages (error.rs), and any `const` tables such as the
     * compile-time size assertions in hal-manifest's raw.rs.
     * ------------------------------------------------------------------ */
    .rodata ALIGN(4K) : AT(ADDR(.rodata))
    {
        *(.rodata .rodata.*)
    }

    /* ------------------------------------------------------------------
     * .data — initialized mutable statics. Expected to be small and
     * rare at this layer (hal-core/hal-x86_64 avoid global mutable
     * state wherever possible per the "smallest possible code in
     * Privileged mode" principle, 02-Microkernel-Layer.md section 0),
     * but architecture-level singletons (e.g. a lazily-initialized APIC
     * base address cache) may live here.
     * ------------------------------------------------------------------ */
    .data ALIGN(4K) : AT(ADDR(.data))
    {
        *(.data .data.*)
    }

    /* ------------------------------------------------------------------
     * .bss — zero-initialized statics, including the boot-time stack
     * (see stack_bottom/stack_top below, referenced from boot.S) and
     * any zeroed HardwareManifestRaw storage this crate keeps as a
     * `static mut` before handoff to BootInfo (hal-core/src/boot.rs).
     * ------------------------------------------------------------------ */
    .bss ALIGN(4K) : AT(ADDR(.bss))
    {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)

        /* Boot-time stack for the bootstrap processor (BSP), used by
         * boot.S between `_start` and the first call into Rust. Sized
         * generously (64 KiB) since this stack briefly hosts firmware
         * memory-map parsing (hal-core/src/memory.rs) before the
         * microkernel's own per-thread stacks (layer 2 concern) take
         * over entirely. 16-byte aligned per the x86_64 System V ABI's
         * stack alignment requirement at function-call boundaries. */
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += 64K;
        __boot_stack_top = .;

        __bss_end = .;
    }

    /* Symbol upper layers use, alongside __kernel_image_phys_start
     * above, to bound the kernel image range reported in BootInfo
     * (hal-core/src/boot.rs: kernel_image_phys_start/end) — computed
     * from the final VMA position translated back to LMA space. */
    __kernel_image_phys_end = .;

    /* ------------------------------------------------------------------
     * Discard sections we never want in the final bare-metal image:
     * debug info stays out of the loaded binary (still available in
     * the unstripped ELF for host-side `gdb`/`objdump` per rust-
     * toolchain.toml's llvm-tools-preview component, since debug
     * sections are conventionally excluded from allocatable output
     * segments but remain in the file); exception-handling machinery
     * we do not use (panic-strategy = "abort", eh-frame-header = false
     * on the RISC-V/x86_64 targets) must not sneak into the image
     * either.
     * ------------------------------------------------------------------ */
    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.*)
    }
}