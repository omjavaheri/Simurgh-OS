/* ============================================================================
 * subsystem-bin-aarch64.ld
 *
 * aarch64 counterpart of `subsystem-bin-riscv64.ld` — see that file's
 * own doc comment for the full rationale. Identical shape to device-
 * manager's own `subsystem-bin-aarch64.ld`.
 *
 * Base address 0x80000000 (GiB 2) — the SAME base device-manager-bin's
 * own aarch64 image uses.
 * ============================================================================ */

ENTRY(_start)

SECTIONS
{
    . = 0x80000000;

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
    }
}
