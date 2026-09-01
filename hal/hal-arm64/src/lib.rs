//! ============================================================================
//! hal-arm64
//!
//! The ARM64 implementation of every hal-core trait. Mirrors
//! hal-x86_64/src/lib.rs's structure exactly — see that file's module
//! docs for the shared rationale (submodule layout, panic handler,
//! top-level PlatformHal type, entry-point responsibilities).
//! ============================================================================

#![no_std]
// `no_main` only on the bare-metal target — a host `cargo test` build
// needs the standard test-harness `main`. See hal-x86_64/src/lib.rs.
#![cfg_attr(target_os = "none", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

// ============================================================================
// Boot bootstrap assembly (formerly boot.S), embedded via global_asm!
// — see hal-x86_64/src/lib.rs's equivalent block for the general
// rationale (no external assembler required).
//
// Gated on `target_os = "none"` so `cargo test -p hal-arm64` can compile
// this crate for the host and run the per-module `#[cfg(test)]` suites:
// off the bare-metal target there is no `_start` / firmware handoff and
// the host assembler cannot take AArch64 mnemonics. Same gate on
// `hal_arm64_rust_entry` below.
// ============================================================================
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .boot.header, "a"

    .section .boot.text, "ax"
    .global _start
    .type _start, %function

_start:
    // Step 0: drop EL2 -> EL1 if UEFI left us in EL2.
    mrs     x1, CurrentEL
    and     x1, x1, #0xC
    cmp     x1, #0x8
    b.ne    1f

    mov     x1, #(1 << 31)
    msr     hcr_el2, x1
    msr     sctlr_el1, xzr
    mov     x1, #0x3C5
    msr     spsr_el2, x1
    adr     x1, 1f
    msr     elr_el2, x1
    eret
1:
    // Step 0.5 (unconditional, regardless of whether we dropped from
    // EL2 or were already handed off at EL1): explicitly disable this
    // core's EL1 MMU/caches before running any Rust code, which
    // assumes direct physical addressing at this pre-paging boot
    // stage. Without this, if firmware handed off DIRECTLY at EL1
    // (skipping the EL2 branch above entirely, per the b.ne above),
    // UEFI's own EL1 page tables would remain active — and since they
    // only map addresses UEFI itself uses, any access to memory this
    // project's code expects to reach directly (e.g. compute.rs's PCI
    // ECAM probing, or any hal-arm64 MMIO access before this crate's
    // own setup_identity_mapping/activate_page_tables run) takes a
    // Translation Fault, exactly as observed when jumping here
    // straight from QEMU's `virt` machine OVMF, which hands off at
    // EL1 with its own MMU still enabled.
    mrs     x1, sctlr_el1
    bic     x1, x1, #1        // clear bit 0 (M, MMU enable)
    msr     sctlr_el1, x1
    isb
    // Step 1: establish a known-good stack.
    //
    // `adrp`+`add :lo12:`, NOT the single-instruction `adr` this used
    // to be: `adr`'s encoding only reaches ±1 MiB from its OWN address,
    // and `_start` sits near the very START of the image while
    // `__boot_stack_top`/`__bss_end` sit AFTER the entire `.bss`
    // section — a real link error (`relocation ... out of range`) hit
    // once the boot stack was enlarged past a small size (see
    // `.bss`'s own doc comment on `__boot_stack_bottom`/`_top` for
    // why). `adrp`+`add` has no such range limit (reaches anywhere in
    // a 4 GiB window), matching the idiom this project's own compiled
    // Rust code already uses for far-symbol addressing.
    adrp    x1, __boot_stack_top
    add     x1, x1, :lo12:__boot_stack_top
    mov     sp, x1

    // Step 2: zero .bss.
    adrp    x1, __bss_start
    add     x1, x1, :lo12:__bss_start
    adrp    x2, __bss_end
    add     x2, x2, :lo12:__bss_end
2:  cmp     x1, x2
    b.ge    3f
    str     xzr, [x1], #8
    b       2b
3:

    // Step 4: hand off to Rust. X0 still holds the UEFI memory map
    // pointer.
    bl      hal_arm64_rust_entry

.halt_forever:
    wfi
    b       .halt_forever

    .size _start, . - _start

    .section .boot.data, "aw"
    "#
);

pub mod compute;
pub mod cpu;
pub mod interrupt;
pub mod memory;
pub mod peripheral;
pub mod power;
pub mod timer;

#[cfg(feature = "hal-direct-support")]
pub mod direct;

#[cfg(target_os = "none")]
unsafe extern "C" {
    static __kernel_image_phys_start: u8;
    static __kernel_image_phys_end: u8;
    static __boot_stack_bottom: u8;
    static __boot_stack_top: u8;
}

#[cfg(target_os = "none")]
fn linker_symbol_addr(sym: &u8) -> u64 {
    sym as *const u8 as u64
}

/// The ARM64 realization of `hal_core::PlatformHal`. Mirrors
/// hal-x86_64's `X86_64Hal` struct exactly in shape.
pub struct Arm64Hal {
    pub cpu: cpu::Cpu,
    pub memory: memory::Memory,
    pub timer: timer::Timer,
    pub interrupt: interrupt::InterruptCtrl,
    pub compute: compute::ComputeDiscovery,
    pub power: power::PowerThermalImpl,
}

/// Fixed size, in bytes, of one ARM64 saved hardware context. Covers:
/// X19-X30 callee-saved GPRs (per AAPCS64, X19-X28 are callee-saved,
/// plus FP=X29 and LR=X30) = 12 registers, SP, PC (ELR_EL1 on restore),
/// SPSR_EL1, TTBR0_EL1 (per-thread address space root, ARM64's
/// equivalent of x86_64's CR3) = 4 more = 16 × 8 = 128 bytes, rounded
/// to 160 for headroom (TPIDR_EL0 for thread-local storage, plus
/// reserved slots), matching X86_64_CONTEXT_BYTES's own sizing
/// rationale in hal-x86_64/src/lib.rs.
pub const ARM64_CONTEXT_BYTES: usize = 160;

/// # Safety
/// Same contract as hal-x86_64's `hal_x86_64_rust_entry`: only sound
/// when called from this crate's own `boot.S` `_start`, after the EL2
/// -> EL1 drop (if needed), stack setup, and `.bss` zeroing have
/// already completed.
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn hal_arm64_rust_entry(uefi_memory_map: *const u8) -> ! {
        // ------------------------------------------------------------------
    // Step 1: bring up this core's CPU abstraction (feature detection,
    // GDT/IDT — per hal-core section 3.1's per-core bootstrap
    // responsibility) before anything that might fault or interrupt.
    // ------------------------------------------------------------------
    let cpu = cpu::Cpu::new();

    // PRE-EXISTING GAP found while bringing up this session's U-mode/
    // syscall work (mirrors the identical gap found and fixed in
    // hal-x86_64's own entry point in the prior session): this call was
    // simply never here at all — confirmed via `grep -rn
    // "bootstrap_current_core"` across this crate turning up only the
    // method's own definition, never a call site. VBAR_EL1 was therefore
    // never installed, so any exception taken on this core (synchronous
    // or IRQ) would vector through whatever VBAR_EL1 value firmware left
    // active rather than this crate's own `arm64_vector_table`. Fixed by
    // calling it here, mirroring hal-riscv64's own entry point exactly.
    //
    // SAFETY: called exactly once, here, before anything on this core
    // can fault or take an interrupt (boot.S never unmasks DAIF between
    // `_start` and this point).
    if hal_core::cpu::CpuAbstraction::bootstrap_current_core(&cpu).is_err() {
        // Nothing sensible to do this early; fall through and let the
        // later BootInfo path surface the failure (same fallback
        // hal-riscv64's own entry point uses).
    }

    // ------------------------------------------------------------------
    // Step 2: parse the firmware memory map into
    // hal_manifest::raw::MemoryRegionRaw entries (section 3.2) and
    // build this core's minimal identity/kernel mapping.
    //
    // SAFETY: `uefi_memory_map` was validated by this function's own
    // safety contract above — same reasoning as hal-x86_64's
    // equivalent call.
    let memory = unsafe { memory::Memory::from_uefi_memory_map(uefi_memory_map) };
    
    // ------------------------------------------------------------------
    // Step 3: bring up the timer (section 3.3) and interrupt controller
    // (section 3.4) so the rest of boot can rely on both being usable.
    // ------------------------------------------------------------------
    let timer = timer::Timer::new();
    let interrupt = interrupt::InterruptCtrl::new(memory.gicd_base());
    // QEMU `virt` high-memory PCIe ECAM window base — 0x4010000000, the
    // same value edk2's ArmVirtQemu uses for PcdPciExpressBaseAddress.
    // Passed straight through to the ECAM MMIO scan below, which (with
    // the MMU still off at this boot stage) dereferences it as a
    // physical address, so it must be exact — an out-of-PA-range value
    // here faults as an "address size fault, level 0" the moment
    // ComputeDiscovery::new reads the first config dword.
    const QEMU_VIRT_DEFAULT_ECAM_BASE: u64 = 0x40_1000_0000;
    // ------------------------------------------------------------------
    // Step 4: run heterogeneous compute discovery (section 3.6) and
    // power/thermal domain discovery (section 3.7). Per section 2's
    // Discovery + Policy model, this ALWAYS runs in full regardless of
    // install profile — profile policy is applied later, in layer 4.
    // ------------------------------------------------------------------
    let compute = compute::ComputeDiscovery::new(QEMU_VIRT_DEFAULT_ECAM_BASE);
    let power = power::PowerThermalImpl::new(&compute);
    // Same `ecam_base`, same "MMU still off, dereferences as a physical
    // address" contract as `ComputeDiscovery::new` just above — see
    // this file's own comment on that call.
    let peripheral = peripheral::PeripheralDiscovery::new(QEMU_VIRT_DEFAULT_ECAM_BASE);

    // Built into `.bss` static storage, NOT a plain local: `build_interface`
    // below bakes raw pointers into `hal.cpu`/`hal.timer` (via `HalInterface`'s
    // opaque `*const ()` state fields) that must stay valid for the life of
    // the system — `kernel_main` never returns, and per-process `SwitchTo`/
    // `Terminate` handling in `cpu::restore_user_and_eret` resets SP_EL1 to a
    // fixed boot-stack baseline on every process switch (see that function's
    // own doc comment), reusing and overwriting stack memory above the
    // current frame. A genuinely-stack-resident `Arm64Hal` here was a REAL,
    // exposed bug this session: `hal.timer`'s bytes got corrupted the moment
    // enough post-switch stack depth was used, surfacing as a "divide by
    // zero" panic in `Timer::now_ns` reading a clobbered `frequency_hz`
    // through `HalInterface`'s `timer_state` pointer. Mirrors `kernel_main`'s
    // own identical fix for `HalInterface` itself (`kernel/kernel/src/
    // main.rs`) and `KernelState::init_global`'s "no stack temporary"
    // rationale.
    static mut HAL_STORAGE: core::mem::MaybeUninit<Arm64Hal> = core::mem::MaybeUninit::uninit();
    // SAFETY: single-core boot, this function runs exactly once, before
    // this static is read anywhere else. `addr_of_mut!`/`addr_of!` avoid
    // forming an intermediate `&mut`/`&` to the `static mut` itself.
    let hal: &'static Arm64Hal = unsafe {
        core::ptr::addr_of_mut!(HAL_STORAGE).cast::<Arm64Hal>().write(Arm64Hal {
            cpu,
            memory,
            timer,
            interrupt,
            compute,
            power,
        });
        &*core::ptr::addr_of!(HAL_STORAGE).cast::<Arm64Hal>()
    };

    // PRE-EXISTING GAP found while bringing up this session's preemptive-
    // scheduler work (same class of gap as `Cpu::bootstrap_current_core`'s
    // own, found+fixed in a prior session): `InterruptCtrl::
    // bootstrap_current_core` (interrupt.rs) — which enables the GICv3 CPU
    // interface and the timer PPI at the distributor — and `interrupt::
    // set_global_controller`/`set_global_timer` (which `dispatch_current_
    // irq` needs to have any effect at all — it no-ops while its stored
    // pointer is still null) were never called anywhere in this crate.
    // Without them, the timer PPI this session's `cpu::irq_el0_entry`
    // exists to handle would never even reach the core in the first
    // place. `hal.interrupt.gicd_base()` is accessed here via a plain
    // physical write (see `bootstrap_current_core`'s own SAFETY
    // contract) — sound at this point in boot exactly like every other
    // fixed-physical-address MMIO poke this crate already makes before
    // paging activates (e.g. `trap_diag`'s PL011 writes), since the MMU
    // is off and QEMU's `virt` machine places the GICD at a fixed
    // physical address requiring no translation.
    //
    // SAFETY: called exactly once, after `Cpu::bootstrap_current_core`
    // (VBAR_EL1 already loaded above) and before any interrupt can
    // legitimately be taken (boot.S never unmasks DAIF before this
    // function returns via `kernel_main`, which does so only once
    // dropping to EL0).
    if unsafe { hal.interrupt.bootstrap_current_core() }.is_err() {
        // Nothing sensible to do this early; same fallback as the CPU
        // bootstrap call above.
    }
    interrupt::set_global_controller(&hal.interrupt);
    interrupt::set_global_timer(&hal.timer);

    // ------------------------------------------------------------------
    // Step 5: assemble BootInfo (hal-core/src/boot.rs) from everything
    // discovered above, using the linker-provided image/stack bounds
    // for the kernel-image and boot-reserved ranges.
    // ------------------------------------------------------------------
    let kernel_image_phys_range = (
        // SAFETY: these are linker-defined symbol ADDRESSES (not data
        // to read through the pointer), taken via `&` on an `extern
        // "C" static` — the standard, sound idiom for consuming linker
        // script symbols; see `linker_symbol_addr`'s doc comment.
        unsafe { linker_symbol_addr(&__kernel_image_phys_start) },
        unsafe { linker_symbol_addr(&__kernel_image_phys_end) },
    );
    let boot_reserved_phys_range = (
        unsafe { linker_symbol_addr(&__boot_stack_bottom) },
        unsafe { linker_symbol_addr(&__boot_stack_top) },
    );

    let boot_info = hal_core::BootInfo::new(
        hal_core::BootProtocol::Uefi,
        memory::built_hardware_manifest(
            &hal.memory,
            &hal.compute,
            &peripheral,
            &hal.power,
            &hal.cpu,
            &hal.interrupt,
            &hal.timer,
        ),
        memory::current_page_table_phys(&hal.memory),
        kernel_image_phys_range,
        boot_reserved_phys_range,
        0,
    );

    debug_assert!(
        boot_info.validate().is_ok(),
        "hal-arm64 constructed an internally inconsistent BootInfo"
    );

    let hal_interface = hal_core::build_interface(&hal.cpu, &hal.timer, &hal.interrupt);

    extern "Rust" {
        fn kernel_main(hal: hal_core::HalInterface, boot_info: hal_core::BootInfo) -> !;
    }

    // SAFETY: same reasoning as hal-x86_64's equivalent call — see
    // hal-core/src/interface.rs's build_interface doc comment.
    unsafe { kernel_main(hal_interface, boot_info) }
}
