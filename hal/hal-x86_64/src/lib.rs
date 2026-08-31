//! ============================================================================
//! hal-x86_64
//!
//! The x86_64 implementation of every hal-core trait, per
//! 01-HAL-Layer.md sections 3 and 6. This file:
//!
//!   1. Declares the per-responsibility submodules (cpu, memory, timer,
//!      interrupt, compute, power) — one per hal-core trait, mirroring
//!      hal-core's own module layout so the mapping between "what a
//!      trait requires" and "how x86_64 provides it" stays obvious.
//!   2. Defines `hal_x86_64_rust_entry`, the first Rust function ever
//!      executed (called from `boot.S`'s `_start`, per that file's
//!      module docs).
//!   3. Assembles the top-level `X86_64Hal` type that implements every
//!      hal-core trait (and therefore, via hal-core's blanket impl,
//!      `PlatformHal`) by delegating to the submodules.
//!   4. Provides the `#[panic_handler]` this `no_std` binary needs
//!      (per 01-HAL-Layer.md section 0 / 02-Microkernel-Layer.md
//!      section 1.1: no unwinding, `panic = "abort"` — this handler is
//!      the terminal point every panic reaches).
//!
//! Per 01-HAL-Layer.md section 0, this crate and the microkernel are
//! compiled into the SAME final Privileged binary; `hal_x86_64_rust_entry`
//! is therefore the boundary where control eventually passes to the
//! microkernel's Root Task via a direct Rust function call — NOT a
//! syscall, NOT IPC (that boundary only starts existing one layer up,
//! per 02-Microkernel-Layer.md section 0).
//! ============================================================================

#![no_std]
// `no_main` only on the bare-metal target: a host `cargo test` build
// needs the standard test-harness `main`, and this crate defines no
// `_start` off the bare-metal target anyway (see the `global_asm!` gate).
#![cfg_attr(target_os = "none", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

// ============================================================================
// Boot bootstrap assembly (formerly boot.S), embedded via global_asm!
// so this crate builds with rustc/LLVM alone — no external assembler
// (clang/gcc) required. Content and behavior are unchanged from the
// original standalone boot.S; see the step-by-step comments below.
//
// Gated on `target_os = "none"` (true for targets/x86_64-hal.json, whose
// spec sets `"os": "none"`, false for a developer's host triple) so that
// `cargo test -p hal-x86_64` can compile this crate for the host and run
// the per-module `#[cfg(test)]` suites: the host assembler rejects the
// ELF-only `.type @function` / `.size` directives below, and there is no
// `_start` / firmware handoff on the host anyway. Same gate on
// `hal_x86_64_rust_entry` further down. See CONTRIBUTING/CI notes.
// ============================================================================
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .boot.header, "a"
    // (intentionally empty for the UEFI-stub-only MVP boot path)

    .section .boot.text, "ax"
    .global _start
    .type _start, @function

_start:
    // Step 1: establish a known-good stack.
    lea     rsp, [rip + __boot_stack_top]

    // The bootloader entered with RDI = handoff-block pointer (SysV
    // arg 0 = `uefi_memory_map`). Step 2 below clobbers RDI (it is the
    // `rep stosb` destination), so stash the pointer in a scratch
    // register first — nothing has been called yet, so r15 is free.
    mov     r15, rdi

    // Step 2: zero .bss.
    lea     rdi, [rip + __bss_start]
    lea     rcx, [rip + __bss_end]
    sub     rcx, rdi
    xor     al, al
    cld
    rep stosb

    // Step 3: minimal ABI environment (DF already clear from above).
    cld

    // Step 4: hand off to Rust. Restore the handoff-block pointer into
    // RDI (SysV first integer argument = `uefi_memory_map`).
    mov     rdi, r15
    call    hal_x86_64_rust_entry

.halt_forever:
    cli
    hlt
    jmp     .halt_forever

    .size _start, . - _start

    .section .boot.data, "aw"
    // (intentionally empty for the UEFI-stub-only MVP boot path)
    "#
);

// ----------------------------------------------------------------------------
// Submodules — one per hal-core responsibility area (01-HAL-Layer.md
// section 3), each implementing the matching hal-core trait for real
// x86_64 hardware.
// ----------------------------------------------------------------------------

/// CPU Abstraction (hal_core::cpu::CpuAbstraction) for x86_64: CPUID
/// feature detection, GDT/IDT setup, context switch via manual register
/// save/restore.
pub mod cpu;

/// Memory Bootstrap (hal_core::memory::MemoryBootstrap) for x86_64:
/// UEFI Memory Map parsing (section 3.2), minimal page table setup.
pub mod memory;

/// Timer & Clock (hal_core::timer::TimerAbstraction) for x86_64:
/// TSC/HPET (section 3.3).
pub mod timer;

/// Interrupt Controller (hal_core::interrupt::InterruptController) for
/// x86_64: APIC/x2APIC (section 3.4).
pub mod interrupt;

/// Heterogeneous Compute Discovery (hal_core::compute::ComputeDeviceDiscovery)
/// for x86_64: PCI config space scan for GPU/NPU/TPU/FPGA (section 3.6).
pub mod compute;

/// Power & Thermal (hal_core::power::PowerThermal) for x86_64: RAPL /
/// MSR-based DVFS and thermal reporting (section 3.7).
pub mod power;

/// Optional direct hardware access (hal_direct::HalDirectAccess) for
/// x86_64, only compiled when this crate's "hal-direct-support"
/// feature is enabled (see Cargo.toml) — per section 1's requirement
/// that hal-core and hal-direct stay separable in the final binary.
#[cfg(feature = "hal-direct-support")]
pub mod direct;

// ----------------------------------------------------------------------------
// Linker-provided symbols (from linker.ld)
//
// These are addresses, not values — hence `extern "C"` statics of type
// `u8` accessed only via `&raw const` / address-of, never dereferenced
// as actual byte data. This is the standard idiom for consuming linker
// script symbols from Rust.
// ----------------------------------------------------------------------------

unsafe extern "C" {
    /// Physical start of the loaded kernel image (linker.ld:
    /// __kernel_image_phys_start), used to populate
    /// `BootInfo::kernel_image_phys_start` (hal-core/src/boot.rs).
    static __kernel_image_phys_start: u8;
    /// Physical end of the loaded kernel image (linker.ld:
    /// __kernel_image_phys_end).
    static __kernel_image_phys_end: u8;
    /// Bounds of the boot-time stack (linker.ld: __boot_stack_bottom /
    /// __boot_stack_top), used to compute the `boot_reserved_phys_*`
    /// range in `BootInfo` — this stack is only needed until the
    /// microkernel's Root Task establishes its own, at which point the
    /// range it occupies is safe to reclaim (hal-core/src/boot.rs:
    /// `BootInfo::overlaps_boot_reserved`).
    static __boot_stack_bottom: u8;
    static __boot_stack_top: u8;
}

/// Reads a linker symbol's address as a `u64` physical address. Every
/// use site below immediately explains why taking the address (not the
/// value) is correct.
fn linker_symbol_addr(sym: &u8) -> u64 {
    sym as *const u8 as u64
}

// ----------------------------------------------------------------------------
// Panic handler
//
// Required by every no_std binary. Per 02-Microkernel-Layer.md section
// 1.1 and this workspace's `panic = "abort"` profile (os-project/
// Cargo.toml), there is no unwinding to perform here — this is
// genuinely the end of execution on whichever core panicked.
// ----------------------------------------------------------------------------
// NOTE: no #[panic_handler] here. hal-x86_64 is a *library* crate
// (crate-type = ["staticlib", "rlib"]) that always gets linked into a
// top-level binary crate (kernel-stub today, the real microkernel
// later per 01-HAL-Layer.md section 0). Only ONE #[panic_handler] may
// exist in a linked binary — it belongs to whichever crate is the
// final binary, since that is the only place with enough context
// (e.g. a real diagnostics/serial output path) to do anything useful
// with a panic. See kernel-stub/src/main.rs's #[panic_handler] for
// the current implementation.

// ----------------------------------------------------------------------------
// Top-level platform type
// ----------------------------------------------------------------------------

/// The x86_64 realization of `hal_core::PlatformHal`, aggregating this
/// crate's six per-responsibility submodules behind hal-core's trait
/// contracts. A single value of this type is constructed once, in
/// `hal_x86_64_rust_entry` below, and its address is effectively what
/// the microkernel's `kernel-arch-glue`
/// (02-Microkernel-Layer.md section 7) is generic over on this
/// architecture.
///
/// `Cpu`/`Memory`/`Timer`/`InterruptCtrl`/`ComputeDiscovery`/
/// `PowerThermalImpl` types and their `CpuAbstraction`/
/// `MemoryBootstrap`/etc. trait implementations live in the
/// correspondingly-named submodules above; this struct just wires them
/// together as fields.
pub struct X86_64Hal {
    pub cpu: cpu::Cpu,
    pub memory: memory::Memory,
    pub timer: timer::Timer,
    pub interrupt: interrupt::InterruptCtrl,
    pub compute: compute::ComputeDiscovery,
    pub power: power::PowerThermalImpl,
}

/// The fixed size, in bytes, of one x86_64 saved hardware context
/// (general-purpose registers + control registers relevant to a
/// context switch). Concrete layout is defined in `cpu.rs`; this
/// constant is what `hal_core::cpu::CpuContext<N>` and
/// `hal_core::cpu::CpuAbstraction<N>` are instantiated with for this
/// architecture, per hal-core/src/cpu.rs's doc comment on
/// `ARCH_CONTEXT_BYTES`.
///
/// Value covers: 16 general-purpose registers (RAX, RBX, RCX, RDX,
/// RSI, RDI, RBP, RSP, R8-R15 = 16 × 8 bytes) + RIP + RFLAGS + CR3
/// (for address-space-switch-capable contexts) = 19 × 8 = 152 bytes,
/// rounded up to a 16-byte-aligned 160 for headroom (segment selectors
/// FS/GS base, used for thread-local storage per the SysV x86_64 ABI).
pub const X86_64_CONTEXT_BYTES: usize = 160;

// ----------------------------------------------------------------------------
// Rust entry point — called from boot.S's `_start`
// ----------------------------------------------------------------------------

/// The first Rust code executed anywhere in the system, on this
/// architecture. Called directly from `boot.S` (see that file's step
/// 4) with `uefi_memory_map` pointing at the UEFI-provided memory map
/// blob the bootloader stub obtained via `GetMemoryMap()` before
/// `ExitBootServices()`.
///
/// # Safety
/// This function's entire premise relies on preconditions only
/// `boot.S` can guarantee: a valid, 16-byte-aligned stack is active
/// (boot.S step 1), `.bss` has been zeroed (boot.S step 2), and
/// `uefi_memory_map` is a valid pointer handed off by UEFI before
/// `ExitBootServices()` was called (i.e. firmware boot services were
/// still available when this pointer was obtained, per section 3.2's
/// requirement to read "UEFI Memory Map / e820"). Calling this from
/// anywhere other than `boot.S`'s `_start` is unsound.
///
/// Gated on `target_os = "none"` (see the `global_asm!` block above): it
/// is only meaningful on the bare-metal target, and excluding it from
/// host builds lets `cargo test -p hal-x86_64` run the per-module unit
/// suites without a firmware handoff.
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn hal_x86_64_rust_entry(uefi_memory_map: *const u8) -> ! {
    // ------------------------------------------------------------------
    // Step 1: bring up this core's CPU abstraction (feature detection
    // via `Cpu::new`, then GDT/IDT/TSS via `bootstrap_current_core` —
    // per hal-core section 3.1's per-core bootstrap responsibility)
    // before anything that might fault or interrupt.
    //
    // **Real bug found via QEMU**: `bootstrap_current_core` was never
    // actually CALLED anywhere in this crate — `Cpu::new()` only does
    // CPUID-based feature detection, not the GDT/IDT/TSS work its own
    // doc comment describes. hal-riscv64's own entry point calls it
    // explicitly (installs `stvec`); this one never did the x86_64
    // equivalent, so `load_gdt`/`load_idt`/`load_tss` were dead code —
    // every interrupt/exception (including this session's own `int
    // 0x80` syscall gate and `enter_user`'s Ring 3 drop) ran under
    // WHATEVER GDT/IDT the UEFI firmware itself left active, with
    // predictably wrong results (a #GP loading `SegmentSelector::
    // UserCode`, which names an index in OUR intended GDT, not
    // firmware's).
    // ------------------------------------------------------------------
    let cpu = cpu::Cpu::new();
    // SAFETY: called exactly once, here, before anything on this core
    // can fault or take an interrupt — mirrors hal-riscv64's own
    // `bootstrap_current_core` call at its entry point exactly.
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
    // safety contract above (a precondition only boot.S's caller can
    // establish, which is why hal_x86_64_rust_entry itself is not
    // marked unsafe — its only caller is boot.S, which is trusted by
    // construction as part of this same crate's boot path).
    let memory = unsafe { memory::Memory::from_uefi_memory_map(uefi_memory_map) };

    // ------------------------------------------------------------------
    // Step 3: bring up the timer (section 3.3) and interrupt controller
    // (section 3.4) so the rest of boot can rely on both being usable.
    // ------------------------------------------------------------------
    let timer = timer::Timer::new(timer::HpetPresence { present: true });
    let interrupt = interrupt::InterruptCtrl::new();

    // ------------------------------------------------------------------
    // Step 4: run heterogeneous compute discovery (section 3.6) and
    // power/thermal domain discovery (section 3.7). Per section 2's
    // Discovery + Policy model, this ALWAYS runs in full regardless of
    // install profile — profile policy is applied later, in layer 4.
    // ------------------------------------------------------------------
    let compute = compute::ComputeDiscovery::new();
    let power = power::PowerThermalImpl::new(&compute);

    // Built into `.bss` static storage, NOT a plain local — mirrors
    // hal-arm64's own identical fix (`hal_arm64_rust_entry`, this
    // session) and `KernelState::init_global`'s "no stack temporary"
    // rationale. `build_interface` below bakes raw pointers into
    // `hal.cpu`/`hal.timer` (via `HalInterface`'s opaque `*const ()`
    // state fields) that must stay valid for the life of the system.
    // The comment this replaced argued a plain local was safe because
    // `hal_x86_64_rust_entry` never returns — true in isolation, but
    // this project's own aarch64 port hit a REAL corruption from the
    // identical pattern the moment its own kernel-mode SP got reset to
    // a fixed baseline on every process switch (see hal-arm64::cpu::
    // restore_user_and_eret's own doc comment for the full story).
    // x86_64 has NOT hit this yet — its hardware TSS.rsp0 mechanism
    // resets Ring0 SP to the SAME fixed value on every Ring3->Ring0
    // transition already, so the danger zone was always bounded by
    // ordinary call depth, not a leak — but adding a timer ISR here
    // (this session's own preemption work) grows that call depth in a
    // new, not-yet-proven-safe way, and this fix is cheap enough not
    // to risk finding out the hard way via QEMU.
    static mut HAL_STORAGE: core::mem::MaybeUninit<X86_64Hal> = core::mem::MaybeUninit::uninit();
    // SAFETY: single-core boot, this function runs exactly once, before
    // this static is read anywhere else. `addr_of_mut!`/`addr_of!` avoid
    // forming an intermediate `&mut`/`&` to the `static mut` itself.
    let hal: &'static X86_64Hal = unsafe {
        core::ptr::addr_of_mut!(HAL_STORAGE).cast::<X86_64Hal>().write(X86_64Hal {
            cpu,
            memory,
            timer,
            interrupt,
            compute,
            power,
        });
        &*core::ptr::addr_of!(HAL_STORAGE).cast::<X86_64Hal>()
    };

    // PRE-EXISTING GAP found while bringing up this session's
    // preemptive-scheduler work (same class of gap `Cpu::bootstrap_
    // current_core`'s own doc comment above already flags for the CPU
    // side): `InterruptCtrl::bootstrap_current_core` — which enables
    // the Local APIC and configures its LVT Timer entry for TSC-
    // deadline mode — and `interrupt::set_global_controller`/
    // `set_global_timer` (which `dispatch_vector` needs to have any
    // effect at all) were never called anywhere in this crate
    // (confirmed via `grep -rn "bootstrap_current_core\|set_global_"`
    // across this crate turning up only their own definitions). Without
    // them, the LAPIC timer this session's preemption work depends on
    // would never even be configured to fire, let alone be dispatched
    // anywhere once it did.
    //
    // SAFETY: called exactly once, after `Cpu::bootstrap_current_core`
    // (IDT already loaded above) and before any interrupt can
    // legitimately be taken (boot.S never issues `sti` before this
    // function returns via `kernel_main`, which does so only once
    // dropping to Ring 3).
    if unsafe { hal.interrupt.bootstrap_current_core(hal.timer.tsc_deadline_capable()) }.is_err() {
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
            &hal.power,
            &hal.cpu,
            &hal.interrupt,
            &hal.timer,
        ),
        memory::current_page_table_phys(&hal.memory),
        kernel_image_phys_range,
        boot_reserved_phys_range,
        /* boot_core_id: */ 0, // bootstrap processor is always core 0
    );

    debug_assert!(
        boot_info.validate().is_ok(),
        "hal-x86_64 constructed an internally inconsistent BootInfo"
    );

    // ------------------------------------------------------------------
    // Step 6: hand off to the microkernel.
    //
    // Per 01-HAL-Layer.md section 0, this is a direct Rust function
    // call, not IPC/syscall — HAL and the microkernel share this same
    // Privileged binary. `kernel_main` is the microkernel's entry
    // point (02-Microkernel-Layer.md); for the current phase of this
    // project (HAL-only implementation), it is provided by the
    // separate `kernel-stub` crate's linked-in symbol until the real
    // microkernel (layer 2) is implemented.
    // ------------------------------------------------------------------
    let hal_interface = hal_core::build_interface(&hal.cpu, &hal.timer, &hal.interrupt);

    extern "Rust" {
        fn kernel_main(hal: hal_core::HalInterface, boot_info: hal_core::BootInfo) -> !;
    }

    // SAFETY: `hal_interface` borrows `hal.cpu`/`hal.timer`, which now
    // live in genuinely `'static` storage (`HAL_STORAGE` above) — safe
    // regardless of what this function's own stack frame, or any
    // later kernel-mode stack activity (including this session's own
    // preemption switches), does to memory below it. `kernel_main`'s
    // signature (hal_core::HalInterface, architecture-erased) is fixed
    // by this workspace regardless of
    // which hal-<arch> crate is linked in.
    unsafe { kernel_main(hal_interface, boot_info) }
}
