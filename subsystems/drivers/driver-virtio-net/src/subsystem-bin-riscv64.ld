/* ============================================================================
 * subsystem-bin-riscv64.ld
 *
 * Purpose: minimal linker script for `driver-virtio-net-bin` — a
 * standalone process image loaded by `kernel-arch-glue::
 * spawn_process_from_elf`, NOT booted directly by firmware. Identical
 * shape to `driver-virtio-blk`'s own `subsystem-bin-riscv64.ld` (see that
 * file's own doc comment for the full rationale) — copied rather than
 * shared because each subsystem's own linker script lives beside its own
 * crate, matching this project's established one-script-per-crate layout.
 *
 * Architecture reference: 03-Kernel-Subsystems-Layer.md's "subsystems as
 * processes" packaging.
 *
 * Base address 0xC0000000: the SAME base every riscv64 subsystem-bin
 * uses (device-manager-bin/fs-native-bin/driver-virtio-blk-bin all link
 * here too) — safe because each one is loaded into its OWN, separate
 * process address space (`spawn_process_from_elf`), never two at once
 * into the same space.
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
