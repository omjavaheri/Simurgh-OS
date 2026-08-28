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

        /* Boot-time stack, same 64 KiB sizing rationale as
         * hal-x86_64/linker.ld. AArch64's AAPCS64 ABI requires 16-byte
         * stack alignment at a public-interface function call boundary
         * (equivalent requirement to x86_64's SysV ABI). */
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += 64K;
        __boot_stack_top = .;

        __bss_end = .;
    }

    __kernel_image_phys_end = . ;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.*)
    }
}