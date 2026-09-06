/* ============================================================================
 * subsystem-bin-riscv64.ld
 *
 * Purpose: minimal linker script for `security-broker-intermediary-bin` —
 * a standalone process image loaded by `kernel-arch-glue::
 * security_broker_intermediary_demo_start`, NOT booted directly by
 * firmware. Identical shape to `compositor`'s own
 * `subsystem-bin-riscv64.ld` (see that file's own doc comment for the
 * full rationale) — copied rather than shared because each subsystem's
 * own linker script lives beside its own crate, matching this project's
 * established one-script-per-crate layout.
 *
 * Base address 0xC0000000: the SAME base every riscv64 subsystem-bin
 * uses — safe because each one is loaded into its OWN, separate process
 * address space, never two at once into the same space.
 * ============================================================================ */

ENTRY(_start)

SECTIONS
{
    . = 0xC0000000;

    .text : ALIGN(4K)
    {
        *(.text .text.*)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K)
    {
        *(.data .data.*)
    }

    .bss : ALIGN(4K)
    {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
        *(.note.*)
        *(.riscv.attributes)
    }
}
