/* ============================================================================
 * subsystem-bin-x86_64.ld
 *
 * Identical to `driver-virtio-net`'s own `subsystem-bin-x86_64.ld` —
 * same base address (0x40000000, GiB 1), same `code-model:"kernel"`
 * sign-extension constraint driving that choice, same reason it's
 * copied rather than shared (see that file's own doc comment, and
 * `subsystem-bin-riscv64.ld`'s own doc comment in THIS crate, for the
 * full picture).
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
