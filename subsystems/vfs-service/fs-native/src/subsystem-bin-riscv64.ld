/* ============================================================================
 * subsystem-bin-riscv64.ld
 *
 * Purpose: minimal linker script for `fs-native-bin` — a standalone
 * process image loaded by `kernel-arch-glue::spawn_process_from_elf`,
 * NOT booted directly by firmware. Identical shape to `device-manager`'s
 * own `subsystem-bin-riscv64.ld` (see that file's own doc comment for
 * the full rationale) — copied rather than shared from a common
 * location, matching this workspace's existing convention of each
 * subsystem crate owning its own copy.
 *
 * Architecture reference: 03-Kernel-Subsystems-Layer.md's "subsystems
 * as processes" packaging (IMPLEMENTATION-PLAN.md follow-up).
 *
 * Base address 0xC0000000: the SAME base device-manager-bin's own
 * riscv64 image uses — safe to reuse since each spawned process gets
 * its own, independent address space.
 *
 * Explicit `PHDRS` (real bug found via QEMU, fs-native's own spawn —
 * see `kernel_arch_glue::spawn_process_from_elf`'s own doc comment on
 * the loader-side half of this fix): without this, rust-lld's default
 * PT_LOAD generation does not pad each output section's END up to a
 * page boundary — only each section's own explicit `ALIGN(4K)` START
 * is honored — so a section whose true content size is not itself a
 * multiple of 4 KiB (here, `.rodata`) lets the NEXT section (`.data`)
 * start mid-page, inside what the loader would otherwise treat as
 * `.rodata`'s own last (rounded-up) page. device-manager-bin's own
 * sections happened to each land on exact page multiples by luck;
 * fs-native-bin's larger, denser `.rodata` did not. Assigning each
 * output section its OWN named `PT_LOAD` program header forces lld to
 * page-align EVERY segment boundary, guaranteeing no two segments ever
 * share a page — the standard fix for a custom OS loader (mirrors how
 * a real kernel's own `vmlinux.lds`-style script separates segments).
 * ============================================================================ */

ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* R(4) + X(1) */
    rodata PT_LOAD FLAGS(4); /* R(4) */
    data   PT_LOAD FLAGS(6); /* R(4) + W(2) */
}

SECTIONS
{
    . = 0xC0000000;

    .text : ALIGN(4K)
    {
        *(.text .text.*)
    } :text

    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    } :rodata

    .data : ALIGN(4K)
    {
        *(.data .data.*)
    } :data

    .bss : ALIGN(4K)
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame)
        *(.note.*)
        *(.riscv.attributes)
    }
}
