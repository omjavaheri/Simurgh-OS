/* ============================================================================
 * subsystem-bin-x86_64.ld
 *
 * x86_64 counterpart of `subsystem-bin-riscv64.ld` — see that file's own
 * doc comment for the full rationale (this is a standalone process
 * image loaded by `kernel-arch-glue::spawn_process_from_elf`, not
 * booted directly by firmware, so it needs none of `hal-x86_64/src/
 * linker.ld`'s boot-assembly/VMA-LMA-split machinery).
 *
 * Base address 0x40000000 (GiB 1), NOT riscv64's 0xC0000000 (GiB 3):
 * the SAME "empty user GiB slot" convention `hal-x86_64/src/linker.ld`
 * already uses for its own `.user_text` — required by this target's
 * `code-model:"kernel"` (every symbol address must sign-extend-32-bit-
 * represent; 0xC0000000 hits a real `R_X86_64_32S out of range` link
 * error, exactly as documented in hal-x86_64/linker.ld's own doc
 * comment on why ITS `.user_text` moved off riscv64's base).
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
