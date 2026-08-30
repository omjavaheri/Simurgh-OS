/* ============================================================================
 * subsystem-bin-riscv64.ld
 *
 * Purpose: minimal linker script for `device-manager-bin` (and, by the
 * same pattern, any future subsystem's own `[[bin]]`) — a standalone
 * process image loaded by `kernel-arch-glue::spawn_process_from_elf`,
 * NOT booted directly by firmware. Unlike `hal-riscv64/src/linker.ld`
 * (a real boot image: `.boot` entry assembly, kernel VMA/LMA split,
 * `.user_text`/`.user_stack` carve-outs for demo processes embedded IN
 * the kernel), this script has none of that: no boot assembly runs
 * before `_start` (the loader — see `elf-loader`'s doc comment — zero-
 * fills `.bss` itself via each PT_LOAD segment's own file_size/mem_size
 * gap, and the kernel allocates this process's stack separately), so
 * this is just "one flat, non-relocatable image, linked at a fixed
 * base VMA no other mapping in a spawned process's address space uses".
 *
 * Architecture reference: 03-Kernel-Subsystems-Layer.md's "subsystems
 * as processes" packaging (IMPLEMENTATION-PLAN.md follow-up).
 *
 * Base address 0xC0000000: the SAME "empty Sv39 GiB slot" convention
 * `hal-riscv64/src/linker.ld` already uses for its own `.user_text` —
 * proven safe for a riscv64 U-mode process image at this base. This is
 * riscv64-ONLY: x86_64's `code-model:"kernel"` target needs a low,
 * sign-extend-32-bit-representable base (0x40000000, per hal-x86_64's
 * own `.user_text` VMA — see that crate's linker.ld doc comment for the
 * `R_X86_64_32S out of range` link error this avoids), and aarch64 uses
 * 0x80000000 (its own `.user_text` convention) — a separate script per
 * architecture is needed once this packaging work extends past riscv64
 * (this session's own scope, matching this project's established
 * one-architecture-at-a-time pace).
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
