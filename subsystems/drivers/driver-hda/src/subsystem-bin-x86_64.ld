/* ============================================================================
 * subsystem-bin-x86_64.ld — driver-nvme
 *
 * Identical to `driver-i8042`'s own `subsystem-bin-x86_64.ld` — see that
 * file's own doc comment for the full rationale (standalone process image
 * loaded by `kernel-arch-glue::spawn_process_from_elf`, base address
 * 0x40000000 for the same `code-model:"kernel"` sign-extension reason).
 * x86_64-only, so this is the only linker script this crate has.
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
