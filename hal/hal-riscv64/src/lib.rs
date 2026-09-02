//! ============================================================================
//! hal-riscv64
//!
//! The RISC-V (RV64GC) implementation of every hal-core trait. Mirrors
//! hal-x86_64/hal-arm64's lib.rs structure — see those files' module
//! docs for the shared rationale. The key difference here is the entry
//! point signature (two parameters: hart_id + dtb_phys, per boot.S's
//! module docs on SBI's boot protocol) and the boot protocol reported
//! to BootInfo (no BootProtocol::Uefi variant applies here — see
//! hal-core/src/boot.rs's BootProtocol enum, which already anticipates
//! this via its SbiDeviceTree variant).
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
// Gated on `target_os = "none"` so `cargo test -p hal-riscv64` can
// compile this crate for the host and run the per-module `#[cfg(test)]`
// suites: off the bare-metal target there is no `_start` / SBI handoff
// and the host assembler cannot take RISC-V mnemonics. Same gate on
// `hal_riscv64_rust_entry` below.
// ============================================================================
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .boot.header, "a"

    .section .boot.text, "ax"
    .global _start
    .type _start, @function

_start:
    // Step 1: only hart 0 continues; others park.
    bnez    a0, .park_secondary_hart

    la      sp, __boot_stack_top

    // Step 2: zero .bss.
    la      t0, __bss_start
    la      t1, __bss_end
1:  bgeu    t0, t1, 2f
    sd      zero, 0(t0)
    addi    t0, t0, 8
    j       1b
2:

    // Step 4: hand off to Rust. a0 = hart id, a1 = DTB pointer.
    call    hal_riscv64_rust_entry

.halt_forever:
    wfi
    j       .halt_forever

.park_secondary_hart:
    wfi
    j       .park_secondary_hart

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

// NOTE: no #[panic_handler] here. hal-riscv64 is a *library* crate
// (crate-type = ["rlib"]) always linked into a top-level binary
// (kernel-stub today, the real microkernel later, per 01-HAL-Layer.md
// section 0). Only ONE #[panic_handler] may exist in a linked binary,
// and it belongs to the final binary crate — the only place with a real
// diagnostics/SBI-console output path. See kernel-stub/src/main.rs, and
// the identical note in hal-x86_64/src/lib.rs.

/// The RISC-V realization of `hal_core::PlatformHal`. Mirrors the
/// other two architectures' top-level Hal struct exactly in shape.
pub struct Riscv64Hal {
    pub cpu: cpu::Cpu,
    pub memory: memory::Memory,
    pub timer: timer::Timer,
    pub interrupt: interrupt::InterruptCtrl,
    pub compute: compute::ComputeDiscovery,
    pub power: power::PowerThermalImpl,
}

/// Fixed size, in bytes, of one RISC-V saved hardware context. Covers:
/// callee-saved integer registers per the RISC-V ELF psABI (s0-s11,
/// i.e. x8-x9 and x18-x27 = 14 registers... actually s0/s1 = x8/x9,
/// s2-s11 = x18-x27, totaling 12 callee-saved "s" registers), plus ra
/// (x1, used as the resume PC on restore) and sp (x2) = 14 × 8 = 112
/// bytes, plus sepc/sstatus (S-mode equivalent of ARM64's
/// spsr_el1/elr) and satp (per-thread address space root, RISC-V's
/// equivalent of x86_64's CR3 / ARM64's TTBR0_EL1) = 3 more × 8 = 24,
/// totaling 136, rounded to 160 for headroom (tp / x4 for thread-local
/// storage per the RISC-V ELF psABI, plus reserved slots), matching
/// the other two architectures' context size rounding convention.
pub const RISCV64_CONTEXT_BYTES: usize = 160;

/// # Safety
/// Only sound when called from this crate's own `boot.S` `_start`,
/// after the secondary-hart park check, stack setup, and `.bss`
/// zeroing have already completed (per boot.S's module docs) — and
/// only ever for `hart_id == 0` (boot.S itself enforces this by
/// parking any other hart before reaching this call).
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn hal_riscv64_rust_entry(hart_id: usize, dtb_phys: *const u8) -> ! {
    let cpu = cpu::Cpu::new(hart_id);

    // Read this early — before `Memory::from_device_tree` — purely
    // because it's a linker symbol (no runtime dependency ordering),
    // and `from_device_tree` needs it to know where OpenSBI's own
    // reservation ends within Device Tree's single coarse `memory`
    // node range (see `memory::split_reserved_prefix`'s doc comment).
    let kernel_image_phys_start = unsafe { linker_symbol_addr(&__kernel_image_phys_start) };

    // Per-core bootstrap (hal_core::CpuAbstraction::bootstrap_current_core):
    // on RISC-V this installs `stvec` -> `trap_entry`, which the
    // microkernel needs BEFORE it drops the Root Task to U-mode — an
    // `ecall` from U-mode with an unset `stvec` traps into firmware /
    // nowhere. Called here, once, at the architecture entry point, exactly
    // as that trait method's doc comment prescribes. Interrupts are still
    // masked (SBI hands off S-mode with SIE clear; boot.S never sets it).
    if hal_core::cpu::CpuAbstraction::bootstrap_current_core(&cpu).is_err() {
        // Nothing sensible to do this early; fall through and let the
        // later BootInfo path surface the failure.
    }

    // SAFETY: `dtb_phys` was validated by this function's own safety
    // contract above — a valid Device Tree Blob pointer per the SBI
    // boot protocol's mandatory guarantee (01-HAL-Layer.md section
    // 3.2: "Device Tree (اجباری طبق مشخصات SBI)").
    let memory = unsafe { memory::Memory::from_device_tree(dtb_phys, kernel_image_phys_start) };

    // `Timer::new` takes the SBI TIME extension presence rather than
    // re-probing — see timer.rs's `Timer::new` doc comment. cpu.rs is
    // the single point of SBI extension probing (its module docs).
    let timer = timer::Timer::new(cpu.sbi_time_extension_present());
    let interrupt = interrupt::InterruptCtrl::new(memory.plic_base());
    // SAFETY: called once, this hart, right after `interrupt`'s own
    // construction (this method's own contract) and after `cpu`'s
    // `bootstrap_current_core` above (stvec already installed) — the
    // PLIC MMIO region needs no separate identity-map step at this
    // point in boot: `satp` is still Bare (paging is not activated
    // until `kernel-arch-glue::enter`, much later), so physical PLIC
    // MMIO addresses are already directly accessible, exactly as
    // `register_irq`'s own later PLIC register writes (reached from a
    // real `IrqBind` syscall, long after paging IS active and
    // identity-mapping the same low physical range) already prove
    // works throughout. Without this call, `sie.SEIE` is never set —
    // a gap this project's own boot sequence never surfaced until the
    // first real device-IRQ consumer (virtio-blk's `IrqBind`/`Wait`)
    // needed it: the PLIC-level unmask `register_irq` performs is a
    // SEPARATE gate from this CPU-level one, and a `wfi` waiting on a
    // masked `sie.SEIE` never wakes even once the device genuinely
    // raises the interrupt at the PLIC.
    if unsafe { interrupt.bootstrap_current_core() }.is_err() {
        // Nothing sensible to do this early; fall through and let a
        // later `register_irq` call surface the failure.
    }
    let compute = compute::ComputeDiscovery::new();
    let power = power::PowerThermalImpl::new(&compute);
    // SAFETY: `dtb_phys` was validated by this function's own safety
    // contract above — same DTB blob `memory::Memory::from_device_tree`
    // already parsed.
    let peripheral = unsafe { peripheral::PeripheralDiscovery::new(dtb_phys) };

    let hal = Riscv64Hal {
        cpu,
        memory,
        timer,
        interrupt,
        compute,
        power,
    };

    // Publish the timer pointer the trap dispatch reads when a
    // supervisor timer interrupt fires (02-Microkernel-Layer.md §4's
    // preemptive scheduler). `sie.STIE` is deliberately NOT set here:
    // OpenSBI can hand off with a timer interrupt already pending (an
    // uninitialised `mtimecmp`), and enabling delivery now would make it
    // fire the instant the first `sret` reaches U-mode — before the
    // kernel has armed a real deadline. Instead `TimerAbstraction::
    // set_oneshot` enables `sie.STIE` right after its `sbi_set_timer`
    // call, which clears any stale pending bit. `kernel-stub` never arms
    // the timer, so it is unaffected either way.
    interrupt::set_global_timer(&hal.timer);
    // Publish the interrupt controller pointer `dispatch_current_
    // interrupt`'s own `SCAUSE_SUPERVISOR_EXTERNAL_INTERRUPT` branch
    // reads (`cpu.rs`'s `common_trap_entry` calls it for every
    // interrupt cause, not just the timer) — **real bug found via
    // QEMU interrupt tracing** (the first-ever real exercise of a
    // genuine device IRQ end to end, virtio-blk's own `IrqBind`/`Wait`):
    // without this, `GLOBAL_CONTROLLER_PTR` stays the zero sentinel
    // forever, so that branch always takes its own "unreachable in
    // practice" early return — NEVER calling `read_claim`/`end_of_
    // interrupt` — meaning the PLIC's own pending state for a real
    // external interrupt is NEVER cleared, and the CPU re-takes the
    // SAME interrupt trap the instant it returns, forever (confirmed
    // via `-d int`: millions of identical `s_external` traps at one
    // `epc`, zero forward progress) — no earlier code path in this
    // project ever surfaced the gap because every interrupt serviced
    // before this session was the timer, which this same dispatch
    // function handles in a completely separate branch with no PLIC
    // involvement at all.
    interrupt::set_global_controller(&hal.interrupt);

    let kernel_image_phys_range = (
        kernel_image_phys_start,
        unsafe { linker_symbol_addr(&__kernel_image_phys_end) },
    );
    let boot_reserved_phys_range = (
        unsafe { linker_symbol_addr(&__boot_stack_bottom) },
        unsafe { linker_symbol_addr(&__boot_stack_top) },
    );

    let boot_info = hal_core::BootInfo::new(
        // Per section 3.5's RISC-V row: this architecture always uses
        // the SBI + Device Tree boot path, never UEFI — hal-core's
        // BootProtocol enum already anticipates this
        // (hal-core/src/boot.rs).
        hal_core::BootProtocol::SbiDeviceTree,
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
        hart_id as u32,
    );

    debug_assert!(
        boot_info.validate().is_ok(),
        "hal-riscv64 constructed an internally inconsistent BootInfo"
    );

    let hal_interface = hal_core::build_interface(&hal.cpu, &hal.timer, &hal.interrupt);

    extern "Rust" {
        fn kernel_main(hal: hal_core::HalInterface, boot_info: hal_core::BootInfo) -> !;
    }

    // SAFETY: same reasoning as hal-x86_64's equivalent call — see
    // hal-core/src/interface.rs's build_interface doc comment.
    unsafe { kernel_main(hal_interface, boot_info) }
}
