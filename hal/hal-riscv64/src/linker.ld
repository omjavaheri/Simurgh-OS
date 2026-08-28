/* ============================================================================
 * linker.ld — RISC-V
 *
 * Mirrors hal-x86_64/hal-arm64's linker.ld structure (LMA/VMA split,
 * kernel-image/boot-reserved symbols, discarded eh_frame). Differences
 * here reflect RISC-V's addressing and boot conventions:
 *
 *   - No UEFI-loaded higher-half convention to match (no existing OS
 *     precedent this project is deliberately mirroring, unlike
 *     x86_64's "kernel" code model or ARM64's Linux-matching
 *     TTBR1_EL1 base) — this project adopts the RV64 "medany"-friendly
 *     convention of keeping kernel code within reach of PC-relative
 *     addressing without requiring a specific VA split, since RISC-V's
 *     supervisor-mode paging (Sv39/Sv48) does not have an x86/ARM-style
 *     forced upper/lower half distinction at the ISA level the way
 *     TTBR0/TTBR1 does — the split here is a project convention for
 *     consistency with the other two architectures' Root Task handoff
 *     expectations (a stable, documented higher-half kernel VA), not
 *     an ISA requirement.
 *   - SBI hands off in S-mode directly at a physical address OpenSBI
 *     (or an equivalent SBI implementation) loaded this image at —
 *     conventionally 0x80200000 on QEMU's `virt` machine (RAM base
 *     0x80000000 + a 2MB offset OpenSBI itself occupies, per OpenSBI's
 *     own well-known "supervisor payload" placement), NOT a UEFI-
 *     controlled address the way x86_64/ARM64's KERNEL_LMA_BASE is.
 * ========================================================================= */

ENTRY(_start)

/* Higher-half kernel VA base, adopted as a project convention (see
 * module docs) rather than mirroring a specific existing OS's exact
 * choice the way hal-x86_64/hal-arm64 do. Chosen within Sv39's 39-bit
 * VA range (this project's baseline paging mode) so it works
 * identically whether a given RV64 target ultimately uses Sv39, Sv48,
 * or Sv57 — Sv39's canonical upper half starts at
 * 0xFFFFFFC000000000.
 *
 * MVP-phase NOTE: like hal-x86_64/linker.ld and hal-arm64/linker.ld,
 * this constant is currently DEFINED BUT UNUSED — every section below is
 * linked identity (VMA == LMA) at KERNEL_LMA_BASE. `_start` (in .boot)
 * runs with the MMU off after the SBI handoff and references symbols in
 * .text/.bss via PC-relative addressing; a real higher-half split would
 * put those symbols ~0xFFFFFFC0_00000000 away and overflow every
 * R_RISCV_PCREL_HI20/R_RISCV_CALL_PLT relocation out of _start. Moving
 * to a true higher-half layout is a tracked follow-up that must land
 * together with an early trampoline that enables paging before jumping
 * into high .text — the same follow-up noted for the other two arches. */
KERNEL_VMA_BASE = 0xFFFFFFC000000000;

/* Physical load address: matches OpenSBI's standard "supervisor
 * payload" convention on QEMU's virt machine — RAM base (0x80000000)
 * plus OpenSBI's own 2MB firmware image, per that project's documented
 * default FW_JUMP/FW_PAYLOAD offset. */
KERNEL_LMA_BASE = 0x80200000;

SECTIONS
{
    . = KERNEL_LMA_BASE;

    .boot ALIGN(4K) : AT(ADDR(.boot))
    {
        KEEP(*(.boot.header))
        KEEP(*(.boot.text))
        *(.boot.data)
    }

    __kernel_image_phys_start = KERNEL_LMA_BASE;

    .text ALIGN(4K) : AT(ADDR(.text))
    {
        *(.text .text.*)
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata))
    {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4K) : AT(ADDR(.data))
    {
        *(.data .data.*)
    }

    .bss ALIGN(4K) : AT(ADDR(.bss))
    {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)

        /* Boot-time stack, same 64 KiB sizing rationale as the other
         * two architectures. RISC-V's calling convention (per the
         * RISC-V ELF psABI) requires 16-byte stack alignment at a
         * function call boundary, same as x86_64/ARM64. */
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += 64K;
        __boot_stack_top = .;

        __bss_end = .;
    }

    __kernel_image_phys_end = .;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.*)
    }
}