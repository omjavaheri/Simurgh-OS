/* ============================================================================
 * linker.ld — ARM64
 *
 * Mirrors hal-x86_64/linker.ld's structure and rationale (LMA/VMA
 * split, kernel-image/boot-reserved symbols for BootInfo, discarded
 * eh_frame sections). Differences here are purely in the addressing
 * scheme, matching AArch64 conventions instead of x86_64's:
 *
 *   - No "kernel" code model / negative-2GB addressing window. ARM64
 *     kernel-space mapping is conventionally placed in the upper VA
 *     range covered by TTBR1_EL1 (per 01-HAL-Layer.md section 4's
 *     discussion of code-model choice for this architecture) — this
 *     project uses the common 0xffff000000000000 base, matching
 *     Linux's own AArch64 kernel VA convention for familiarity.
 *   - UEFI on ARM64 (per section 3.5) hands off in EL1 or EL2
 *     depending on firmware; boot.S handles dropping EL2 -> EL1 if
 *     needed BEFORE this linker script's higher-half mapping is
 *     relevant, so — like x86_64 — .boot stays at its load address.
 * ========================================================================= */

ENTRY(_start)

/* Upper VA base for TTBR1_EL1-mapped kernel space (Linux AArch64
 * convention, adopted here per code-model rationale in
 * 01-HAL-Layer.md section 4's ARM64 discussion). */
KERNEL_VMA_BASE = 0xffff000000000000;

/* Physical load address: 2MB-aligned, avoiding the first 2MB the way
 * hal-x86_64's KERNEL_LMA_BASE does — a conventional, safe low address
 * for a UEFI-loaded AArch64 image. */
KERNEL_LMA_BASE = 0x40200000;  /* common QEMU virt machine RAM base (0x40000000) + 2MB */

SECTIONS
{
    . = KERNEL_LMA_BASE;

    .boot ALIGN(4K) : AT(ADDR(.boot))
    {
        KEEP(*(.boot.header))
        KEEP(*(.boot.text))
        *(.boot.data)
    }

    __kernel_image_phys_start = KERNEL_LMA_BASE;

    .text ALIGN(4K) : AT(ADDR(.text))
    {
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata))
    {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4K) : AT(ADDR(.data))
    {
        *(.data .data.*)
    }

    .bss ALIGN(4K) : AT(ADDR(.bss))
    {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)

        /* Boot-time stack. AArch64's AAPCS64 ABI requires 16-byte stack
         * alignment at a public-interface function call boundary
         * (equivalent requirement to x86_64's SysV ABI).
         *
         * 512 KiB, NOT the 64 KiB every other architecture's own boot
         * stack uses (hal-x86_64's/hal-riscv64's own equivalents): this
         * is a STOPGAP, not a real fix, for a genuine, still-open bug —
         * `hal_arm64::cpu::restore_user_and_eret`'s own doc comment has
         * the full story. In short: unlike hal-x86_64 (whose hardware
         * TSS.rsp0 mechanism reloads a FIXED SP on every Ring3->Ring0
         * transition), AArch64 has no such automatic reset, and every
         * `SwitchTo`/`Terminate` process switch here permanently
         * consumes 256 bytes of this SAME shared stack (the exception
         * trampoline's own epilogue, which would reclaim it, never runs
         * for a diverging exit) — an unbounded leak across MANY
         * switches, but this session's own P2/device-manager demo is a
         * BOUNDED sequence (~6 restart cycles), so a generously
         * oversized stack comfortably survives it without masking the
         * underlying bug, which remains open and flagged. (A real link
         * error — `adr`'s encoding only reaching ±1 MiB from its own
         * address — was hit here first, since `boot.S`'s `_start`
         * addressed `__boot_stack_top`/`__bss_end` that way; fixed by
         * switching those two references to `adrp`+`add :lo12:`, which
         * has no such range limit — see `lib.rs`'s own `_start`.) */
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += 1024K;
        __boot_stack_top = .;

        __bss_end = .;
    }

    /* ------------------------------------------------------------------
     * User (layer-3) Root Task image.
     *
     * `.user_text` / `.user_stack` are linked for a VMA in an otherwise
     * empty GiB slot of the 39-bit identity-mappable VA range this
     * crate's own `aarch64_paging` module (cpu.rs) uses, but LOADED
     * (LMA) contiguously inside the kernel image, right after `.bss` —
     * same `__user_load`/LOADADDR split pattern hal-riscv64/linker.ld
     * and hal-x86_64/linker.ld use for the same purpose.
     *
     * VMA is 0x8000_0000 (GiB 2): `kernel-arch-glue::enter` computes
     * how many GiB to `map_ram_identity` generically from
     * `BootInfo::kernel_image_phys_end` (`(end / 1_GiB) + 1`, no
     * hardcoded per-architecture constant) — this crate's
     * `KERNEL_LMA_BASE` (0x4020_0000, ~1 GiB + 2 MiB) needs 2 GiB of
     * that, so GiB 2 is the first slot the identity map leaves free.
     *
     * Unlike hal-x86_64 (which is pinned to GiB 0-1 or the real
     * higher-half range by its `code-model: "kernel"` target setting),
     * this target's `code-model: "large"` (targets/aarch64-hal.json)
     * imposes NO restriction on symbol addresses — every access already
     * goes through a full 64-bit literal (MOVZ/MOVK sequence), not a
     * PC-relative displacement with a narrower field — so, like
     * riscv64, any GiB slot works equally well; GiB 2 is simply the
     * first one this image's own size leaves free, not a constraint
     * this architecture forces.
     * ------------------------------------------------------------------ */
    . = ALIGN(4K);
    __user_load = .;              /* LMA cursor (still identity here) */

    . = 0x80000000;               /* jump VMA into the user GiB slot */

    .user_text ALIGN(4K) : AT(__user_load)
    {
        __user_text_start = .;
        KEEP(*(.user_text .user_text.*))
        . = ALIGN(4K);
        __user_text_end = .;
    }

    .user_stack ALIGN(4K) : AT(__user_load + SIZEOF(.user_text))
    {
        __user_stack_start = .;
        . += 64K;
        . = ALIGN(4K);
        __user_stack_end = .;
    }

    __user_text_lma  = LOADADDR(.user_text);
    __user_stack_lma = LOADADDR(.user_stack);

    /* Symbol upper layers use, alongside __kernel_image_phys_start
     * above, to bound the kernel image range reported in BootInfo
     * (hal-core/src/boot.rs: kernel_image_phys_start/end) — computed
     * from the final VMA position translated back to LMA space.
     * Everything the bootloader loaded (kernel + the user image's LMA
     * copy) is off-limits as free memory. */
    __kernel_image_phys_end = LOADADDR(.user_stack) + SIZEOF(.user_stack);

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.*)
    }
}