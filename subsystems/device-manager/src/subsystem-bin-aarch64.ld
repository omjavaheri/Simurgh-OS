/* ============================================================================
 * subsystem-bin-aarch64.ld
 *
 * aarch64 counterpart of `subsystem-bin-riscv64.ld` — see that file's
 * own doc comment for the full rationale (this is a standalone process
 * image loaded by `kernel-arch-glue::spawn_process_from_elf`, not
 * booted directly by firmware, so it needs none of `hal-arm64/src/
 * linker.ld`'s boot-assembly/VMA-LMA-split machinery).
 *
 * Base address 0x80000000 (GiB 2), NOT riscv64's 0xC0000000 (GiB 3) or
 * x86_64's 0x40000000 (GiB 1): the SAME "empty user GiB slot"
 * convention `hal-arm64/src/linker.ld` already uses for its own
 * `.user_text`. This target's `code-model:"large"` imposes no
 * restriction on symbol addresses the way x86_64's `"kernel"` model
 * does, so this base was free to pick — chosen to match hal-arm64's
 * own convention rather than for any hard requirement.
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
