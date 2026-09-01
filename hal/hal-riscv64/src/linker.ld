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

        /* Boot-time stack. RISC-V's calling convention (per the RISC-V
         * ELF psABI) requires 16-byte stack alignment at a function
         * call boundary, same as x86_64/ARM64.
         *
         * 256 KiB, not the original 64 KiB — bumped defensively while
         * investigating an intermittent hang (below), and kept: this is
         * the KERNEL's own S-mode stack, with no guard page (it sits
         * directly inside `.bss`, immediately adjacent to ordinary
         * kernel statics — a RISC-V stack grows DOWN, so overflowing it
         * would silently overwrite whatever `.bss` data the linker
         * placed at lower addresses, no fault, no symptom until a
         * corrupted static is read later). EVERY trap/syscall dispatch
         * runs on it, including the virtio-net driver's own spawn/demo
         * code (`kernel_arch_glue::spawn_virtio_net_driver` and the
         * `drv_net_*` functions, 03-Kernel-Subsystems-Layer.md §2.3/
         * §5.4) — among the largest additions to that crate to date,
         * at `[profile.dev]`'s default `opt-level = 0` unless overridden
         * (see `kernel`/`driver-virtio-blk`'s own Cargo.toml comments for
         * this project's established precedent of exactly this class of
         * bug: `kernel/kernel/src/main.rs`'s `DM_STACK_LEN` doc comment
         * documents an earlier, CONFIRMED instance of this identical
         * 64 KiB -> larger stack fix, for device-manager's own stack).
         *
         * **Honest record, not a confirmed fix**: while adding the
         * virtio-net driver, a real, intermittent hang appeared —
         * arming the preemptive timer (02-Microkernel-Layer.md §4) then
         * never reaching device-manager's first scheduled turn, only
         * on boots where the new ARP-resolve + ICMP-echo round trip
         * actually succeeded end to end. `-d int` tracing showed an
         * otherwise perfectly ordinary-looking, endless `s_timer` +
         * `sbi_set_timer` cycle that never reached `kernel_arch_glue::
         * P2_TICK_BUDGET` — consistent with (though never conclusively
         * proven to BE) exactly this "no guard page, silent .bss
         * corruption" symptom. This stack bump, together with `[profile.
         * dev.package.kernel-arch-glue] opt-level = 2` (workspace
         * `Cargo.toml`), made the hang disappear on the FIRST retest —
         * but neither change, alone or together, reproduced that fix
         * reliably across the several repeated clean rebuild+boot
         * trials that followed (some passed, most did not, with no
         * single code change correlating consistently with the
         * outcome). The leading theory by the end of that investigation
         * shifted: `kernel_arch_glue::preempt`'s own doc comments
         * already flag the 40-tick preemption demo's vruntime fairness
         * as "too QEMU-timing-dependent" even without any networking
         * involved (see that module's own history, including a prior
         * aarch64 session where an atypical QEMU CPU config alone
         * flipped this SAME demo's verdict to MISMATCH) — attaching a
         * `-netdev user` (SLIRP) backend plausibly adds real host-side
         * jitter to the SAME single QEMU thread that also delivers the
         * guest's timer interrupts, on top of an already timing-fragile
         * demo, independent of any code in this repository. Kept at
         * 256 KiB anyway: real, harmless hardening against the ORIGINAL
         * 64 KiB genuinely being tight for this crate's now-larger call
         * graph, whether or not it was the deciding factor in any one
         * boot. TODO(omid): if this hang recurs and blocks real work,
         * treat it as a QEMU/host timing investigation (a dedicated
         * `-icount`/deterministic-timing QEMU run, or profiling the
         * host's own SLIRP thread), not a kernel-code one — this
         * comment's own investigation already covers the code-level
         * avenues that did NOT reliably fix it. */
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += 256K;
        __boot_stack_top = .;

        __bss_end = .;
    }

    /* ------------------------------------------------------------------
     * User (layer-3) Root Task image.
     *
     * `.user_text` / `.user_stack` are linked for a VMA in an otherwise
     * empty Sv39 GiB slot (0xC0000000) but LOADED (LMA) contiguously
     * inside the kernel image, right after .bss. The microkernel maps
     * these pages U=1 (see kernel-arch-glue::enter) while kernel .text
     * stays U=0, then activates paging before dropping to U-mode — so
     * the Root Task runs isolated. Kept in their own 4 KiB pages so no
     * kernel code/data shares a U=1 page.
     * ---------------------------------------------------------------- */
    . = ALIGN(4K);
    __user_load = .;              /* LMA cursor (still identity here) */

    . = 0xC0000000;              /* jump VMA into the user GiB slot */

    .user_text ALIGN(4K) : AT(__user_load)
    {
        __user_text_start = .;
        KEEP(*(.user_text .user_text.*))
        . = ALIGN(4K);
        __user_text_end = .;
    }

    .user_stack ALIGN(4K) : AT(__user_load + SIZEOF(.user_text))
    {
        __user_stack_start = .;
        . += 64K;
        . = ALIGN(4K);
        __user_stack_end = .;
    }

    __user_text_lma  = LOADADDR(.user_text);
    __user_stack_lma = LOADADDR(.user_stack);

    /* Everything the SBI loaded (kernel + the user image's LMA copy) is
     * off-limits as free memory. */
    __kernel_image_phys_end = LOADADDR(.user_stack) + SIZEOF(.user_stack);

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.*)
    }
}