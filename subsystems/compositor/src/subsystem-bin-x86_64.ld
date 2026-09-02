/* ============================================================================
 * subsystem-bin-x86_64.ld
 *
 * x86_64 counterpart of `subsystem-bin-riscv64.ld` — see that file's own
 * doc comment for the full rationale. Identical shape to `netstack`'s
 * own `subsystem-bin-x86_64.ld`.
 *
 * Base address 0x40000000 (GiB 1), NOT riscv64's 0xC0000000 (GiB 3):
 * the SAME base every x86_64 subsystem-bin uses (required by this
 * target's `code-model:"kernel"` — see device-manager's own file for
 * the exact link-error this avoids).
 * ============================================================================ */

ENTRY(_start)

SECTIONS
{
    . = 0x40000000;

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
