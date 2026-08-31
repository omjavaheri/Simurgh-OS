/* ============================================================================
 * linker.ld — x86_64
 *
 * Links the HAL/microkernel image (boot.S + all Rust code compiled
 * against targets/x86_64-hal.json) into the higher-half kernel layout
 * implied by that target's "code-model": "kernel" setting
 * (01-HAL-Layer.md section 6/7; targets/x86_64-hal.json).
 *
 * Layout summary:
 *   - Entered by a UEFI bootloader stub (section 3.5: "Boot Abstraction
 *     ... UEFI (x86_64/ARM64)"), which loads this image at a
 *     physical address and jumps to `_start` (boot.S) in whatever mode
 *     UEFI leaves the CPU in (long mode, paging already enabled by the
 *     firmware's own identity-mapped page tables).
 *   - `_start` runs briefly at its LOAD (physical-ish, low) address
 *     before HAL's own `MemoryBootstrap::setup_identity_mapping`
 *     (hal-core/src/memory.rs) establishes the higher-half mapping;
 *     this script therefore separates LMA (load address) from VMA
 *     (virtual/link address) via `AT()`, so boot.S can locate its own
 *     early code/data at a known low physical address while the
 *     symbols the Rust code references resolve to the final
 *     higher-half kernel addresses.
 *   - `KERNEL_VMA_BASE` matches the "kernel" code model's assumed
 *     negative-2GB addressing window (0xffffffff80000000 upward),
 *     the same convention Linux x86_64 uses, chosen in
 *     01-HAL-Layer.md section 4's discussion of `code-model: "kernel"`.
 * ========================================================================= */

ENTRY(_start)

/* Higher-half base: top 2GB of the 64-bit address space, matching the
 * "kernel" code model's -mcmodel=kernel assumption (symbols must live
 * within the last 2GB so RIP-relative addressing with a 32-bit
 * displacement stays valid). */
KERNEL_VMA_BASE = 0xffffffff80000000;

/* Physical load address: where the UEFI bootloader stub actually places
 * this image in RAM before jumping to _start. 2MB-aligned, which
 * hal-core's setup_identity_mapping (memory.rs) can use directly for its
 * minimal kernel mapping.
 *
 * **Real bug found via QEMU** (this session's fs-native work, which
 * embeds a second subsystem ELF into the kernel image, growing it past
 * ~6MB): the ORIGINAL value here, 0x0020_0000 (2MB — "avoids the first
 * megabyte, historically reserved for firmware structures"), was too
 * close to the front of RAM. `uefi-bootloader`'s own ELF loader must
 * `AllocatePages(AllocateType::Address(segment.paddr), ...)` each
 * PT_LOAD segment at ITS OWN exact physical address (this kernel is not
 * position-independent — VMA and LMA are related by a fixed offset, see
 * this file's own header comment), which requires the ENTIRE segment's
 * range to already be free. OVMF/QEMU's own memory map (confirmed via a
 * temporary diagnostic dump in `uefi-bootloader::load_kernel_segments`)
 * reserves several small `ACPI_NON_VOLATILE` regions scattered through
 * 0x0080_0000-0x0090_0000, followed by a `BOOT_SERVICES_DATA` block
 * through 0x0178_0000 (very likely OVMF's own bookkeeping for the
 * ~11MB bootloader.efi image, which embeds this same kernel ELF as
 * `.rodata`, growing in lockstep with it) — a kernel image over ~6MB
 * now spans directly across those holes, and `AllocatePages` cannot
 * skip over them. The first LARGE contiguous free (`CONVENTIONAL`)
 * region in that same dump starts at 0x0178_0000 and runs for 163MB
 * (to 0x0BB6_C000) — comfortably past every firmware-reserved block
 * with room for this project's kernel to keep growing. `0x0180_0000`
 * (24MB, still 2MB-aligned) is chosen from inside it, not right at its
 * start, for a small margin against the exact boundary shifting by a
 * page or two on a different OVMF build. */
KERNEL_LMA_BASE = 0x01800000;

SECTIONS
{
    . = KERNEL_LMA_BASE;

    /* ------------------------------------------------------------------
     * .boot — the earliest code, per section 7: "بخش‌های bootstrap
     * اولیه... در اسمبلی حداقلی، جدا در فایل boot.S". This section is
     * deliberately linked at its LOAD address (not the higher-half VMA)
     * because boot.S executes BEFORE any page table maps the higher
     * half — it must be directly reachable via the identity/low mapping
     * UEFI itself already set up.
     * ------------------------------------------------------------------ */
    .boot ALIGN(4K) : AT(ADDR(.boot))
    {
        KEEP(*(.boot.header))   /* optional boot protocol header, if any */
        KEEP(*(.boot.text))     /* _start and any code that must run pre-paging-switch */
        *(.boot.data)
    }

    

    /* Symbol upper layers (Root Task, per BootInfo's
     * kernel_image_phys_start/end fields, hal-core/src/boot.rs) use to
     * know exactly where the loaded image begins, so this range is
     * never handed out as free UntypedMemory. */
    __kernel_image_phys_start = KERNEL_LMA_BASE;

    /* ------------------------------------------------------------------
     * .text — all compiled Rust code (hal-core trait implementations,
     * this crate's cpu.rs/memory.rs/timer.rs/interrupt.rs/compute.rs,
     * and eventually the microkernel itself, linked into this same
     * Privileged binary per 01-HAL-Layer.md section 0).
     * ------------------------------------------------------------------ */
    .text ALIGN(4K) : AT(ADDR(.text))
    {
        *(.text .text.*)
    }

    /* ------------------------------------------------------------------
     * .rodata — read-only data: string constants, the HalError Display
     * messages (error.rs), and any `const` tables such as the
     * compile-time size assertions in hal-manifest's raw.rs.
     * ------------------------------------------------------------------ */
    .rodata ALIGN(4K) : AT(ADDR(.rodata))
    {
        *(.rodata .rodata.*)
    }

    /* ------------------------------------------------------------------
     * .data — initialized mutable statics. Expected to be small and
     * rare at this layer (hal-core/hal-x86_64 avoid global mutable
     * state wherever possible per the "smallest possible code in
     * Privileged mode" principle, 02-Microkernel-Layer.md section 0),
     * but architecture-level singletons (e.g. a lazily-initialized APIC
     * base address cache) may live here.
     * ------------------------------------------------------------------ */
    .data ALIGN(4K) : AT(ADDR(.data))
    {
        *(.data .data.*)
    }

    /* ------------------------------------------------------------------
     * .bss — zero-initialized statics, including the boot-time stack
     * (see stack_bottom/stack_top below, referenced from boot.S) and
     * any zeroed HardwareManifestRaw storage this crate keeps as a
     * `static mut` before handoff to BootInfo (hal-core/src/boot.rs).
     * ------------------------------------------------------------------ */
    .bss ALIGN(4K) : AT(ADDR(.bss))
    {
        __bss_start = .;
        *(COMMON)
        *(.bss .bss.*)

        /* Boot-time stack for the bootstrap processor (BSP), used by
         * boot.S between `_start` and the first call into Rust. Sized
         * generously (64 KiB) since this stack briefly hosts firmware
         * memory-map parsing (hal-core/src/memory.rs) before the
         * microkernel's own per-thread stacks (layer 2 concern) take
         * over entirely. 16-byte aligned per the x86_64 System V ABI's
         * stack alignment requirement at function-call boundaries. */
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += 64K;
        __boot_stack_top = .;

        __bss_end = .;
    }

    /* ------------------------------------------------------------------
     * User (layer-3) Root Task image.
     *
     * `.user_text` / `.user_stack` are linked for a VMA in an otherwise
     * empty PML4[0]-mapped GiB slot, but LOADED (LMA) contiguously
     * inside the kernel image, right after `.bss` — same split
     * hal-riscv64/linker.ld uses for the same purpose. The microkernel
     * maps these pages `U=1` (kernel `.text` stays `U=0`) before
     * activating this table and dropping to Ring 3, so the Root Task
     * runs isolated. Kept in their own 4 KiB pages so no kernel
     * code/data ever shares a `U=1` page.
     *
     * VMA is 0x40000000 (GiB 1), NOT hal-riscv64's 0xC0000000 (GiB 3):
     * `kernel-arch-glue::enter` computes how many GiB to
     * `map_ram_identity` generically from `BootInfo::
     * kernel_image_phys_end` (`(end / 1_GiB) + 1`, no hardcoded
     * per-architecture constant) and this crate's tiny, low
     * (`KERNEL_LMA_BASE = 0x00200000`) image needs only 1 GiB of that —
     * so GiB 1 is the first slot that identity map leaves free.
     * Deliberately NOT GiB 3 (or anywhere >= 2 GiB / 0x80000000): this
     * target's `code-model: "kernel"` setting requires every symbol
     * address to be representable as a sign-extended 32-bit value
     * (`R_X86_64_32S`) — true for GiB 0-1 (positive, < 2 GiB) and for
     * the real higher-half kernel range near `0xFFFFFFFF80000000+`, but
     * NOT for anything in between (a genuine link failure hit while
     * building this: "relocation R_X86_64_32S out of range" against
     * `__user_text_start` when it was linked at 0xC0000000).
     * ------------------------------------------------------------------ */
    . = ALIGN(4K);
    __user_load = .;              /* LMA cursor (still identity here) */

    . = 0x40000000;              /* jump VMA into the user GiB slot */

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

    /* Symbol upper layers use, alongside __kernel_image_phys_start
     * above, to bound the kernel image range reported in BootInfo
     * (hal-core/src/boot.rs: kernel_image_phys_start/end) — computed
     * from the final VMA position translated back to LMA space.
     * Everything the bootloader loaded (kernel + the user image's LMA
     * copy) is off-limits as free memory. */
    __kernel_image_phys_end = LOADADDR(.user_stack) + SIZEOF(.user_stack);

    /* ------------------------------------------------------------------
     * Discard sections we never want in the final bare-metal image:
     * debug info stays out of the loaded binary (still available in
     * the unstripped ELF for host-side `gdb`/`objdump` per rust-
     * toolchain.toml's llvm-tools-preview component, since debug
     * sections are conventionally excluded from allocatable output
     * segments but remain in the file); exception-handling machinery
     * we do not use (panic-strategy = "abort", eh-frame-header = false
     * on the RISC-V/x86_64 targets) must not sneak into the image
     * either.
     * ------------------------------------------------------------------ */
    /DISCARD/ :
    {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note.*)
    }
}