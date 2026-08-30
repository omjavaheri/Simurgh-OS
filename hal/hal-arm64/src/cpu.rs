//! ============================================================================
//! cpu.rs — ARM64
//!
//! Implements `hal_core::cpu::CpuAbstraction<ARM64_CONTEXT_BYTES>` for
//! ARM64, per 01-HAL-Layer.md section 3.1. Mirrors hal-x86_64/src/
//! cpu.rs's structure (feature detection via a testable ID-register
//! source, exception vector table setup, context switch, privilege
//! level mapping) — differences below are purely architectural:
//!
//!   - Feature detection: ID_AA64ISAR0/1_EL1, ID_AA64PFR0_EL1 registers
//!     (read via MRS) instead of CPUID.
//!   - Exception Vector Table: VBAR_EL1, a single 2KB-aligned table
//!     with 16 fixed-offset entries (4 exception types × 4 sources),
//!     instead of a 256-entry IDT array.
//!   - Privilege levels: EL0/EL1/EL2 instead of Ring 3/0, with EL2
//!     mapping onto hal-core's `PrivilegeLevel::Monitor` (unlike
//!     x86_64, where Monitor is unsupported — ARM64 actually HAS a
//!     distinct hypervisor level).
//! ============================================================================

use core::cell::Cell;
use core::mem::size_of;

use hal_core::cpu::{CpuAbstraction, CpuContext, CpuFeatureFlags, PrivilegeLevel};
use hal_core::error::HalError;

use crate::ARM64_CONTEXT_BYTES;

// ============================================================================
// ID register access, testable via a trait (mirrors hal-x86_64's
// CpuidSource pattern)
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
pub struct IdRegisters {
    pub id_aa64isar0: u64,
    pub id_aa64isar1: u64,
    pub id_aa64pfr0: u64,
    pub mpidr: u64,
}

pub trait IdRegisterSource {
    fn read(&self) -> IdRegisters;
}

pub struct RealIdRegisters;

// Host (`cargo test`) build: the per-module unit suites construct
// `IdRegisters` directly via test helpers and never touch a real MRS, so
// this stub only has to exist for the crate to compile off the
// bare-metal target. Same pattern for every other `mrs`/`msr` accessor
// in this crate.
#[cfg(not(target_os = "none"))]
impl IdRegisterSource for RealIdRegisters {
    fn read(&self) -> IdRegisters {
        unreachable!("RealIdRegisters::read is bare-metal only (host test build)")
    }
}

#[cfg(target_os = "none")]
impl IdRegisterSource for RealIdRegisters {
    fn read(&self) -> IdRegisters {
        let (isar0, isar1, pfr0, mpidr): (u64, u64, u64, u64);
        // SAFETY: reading these MRS system registers is unconditionally
        // available at EL1 on every ARMv8-A CPU (they are mandatory
        // identification registers, readable regardless of which
        // optional extensions they report) — no preconditions beyond
        // EL1 execution, which this crate always has after boot.S's
        // EL2->EL1 drop.
        unsafe {
            core::arch::asm!("mrs {}, ID_AA64ISAR0_EL1", out(reg) isar0);
            core::arch::asm!("mrs {}, ID_AA64ISAR1_EL1", out(reg) isar1);
            core::arch::asm!("mrs {}, ID_AA64PFR0_EL1", out(reg) pfr0);
            core::arch::asm!("mrs {}, MPIDR_EL1", out(reg) mpidr);
        }
        IdRegisters { id_aa64isar0: isar0, id_aa64isar1: isar1, id_aa64pfr0: pfr0, mpidr }
    }
}

/// Maps ID register fields onto hal-core's architecture-independent
/// `CpuFeatureFlags`. Field bit positions per the ARM Architecture
/// Reference Manual, ID_AA64ISAR0/1_EL1 and ID_AA64PFR0_EL1 sections.
pub fn detect_feature_flags(ids: &IdRegisters) -> CpuFeatureFlags {
    let mut flags = CpuFeatureFlags::empty();

    // NEON is baseline on every AArch64 core (ID_AA64PFR0_EL1.AdvSIMD,
    // bits 23:20, != 0b1111 means present) — always set given this
    // project only targets AArch64 (per 01-HAL-Layer.md section 6
    // building for aarch64-unknown-none), where NEON absence is not a
    // real-world configuration.
    let advsimd = (ids.id_aa64pfr0 >> 20) & 0xF;
    if advsimd != 0xF {
        flags |= CpuFeatureFlags::SIMD_128;
    }

    // SVE presence: ID_AA64PFR0_EL1.SVE, bits 35:32.
    let sve = (ids.id_aa64pfr0 >> 32) & 0xF;
    if sve != 0 {
        flags |= CpuFeatureFlags::SCALABLE_VECTOR;
        // SVE vector length itself requires ZCR_EL1 read, which
        // additionally needs the SVE trap disabled first (CPACR_EL1) —
        // deferred to a follow-up once a concrete need for exact
        // vector length (vs just presence) arises; SIMD_512 is
        // therefore not set here purely from this presence check.
    }

    // AES: ID_AA64ISAR0_EL1.AES, bits 7:4 (>= 1 means present).
    if (ids.id_aa64isar0 >> 4) & 0xF >= 1 {
        flags |= CpuFeatureFlags::CRYPTO_AES;
    }
    // SHA1/SHA2: ID_AA64ISAR0_EL1.SHA1 (bits 11:8) / SHA2 (bits 15:12).
    if (ids.id_aa64isar0 >> 8) & 0xF >= 1 || (ids.id_aa64isar0 >> 12) & 0xF >= 1 {
        flags |= CpuFeatureFlags::CRYPTO_SHA;
    }
    // Atomic (LSE): ID_AA64ISAR0_EL1.Atomic, bits 23:20 (>= 2 means
    // full LSE, including CAS/SWP/LD<op>).
    if (ids.id_aa64isar0 >> 20) & 0xF >= 2 {
        flags |= CpuFeatureFlags::WIDE_ATOMICS;
    }
    // Virtualization: EL2 support, ID_AA64PFR0_EL1.EL2, bits 11:8.
    if (ids.id_aa64pfr0 >> 8) & 0xF != 0 {
        flags |= CpuFeatureFlags::VIRTUALIZATION;
    }
    // Performance monitors: ID_AA64DFR0_EL1 would be the precise
    // source; approximated here via PFR0's reserved-for-this-purpose
    // absence check deferred to a follow-up — PERF_COUNTERS left unset
    // pending that dedicated register read (tracked alongside SVE
    // vector-length as a "needs its own register read" follow-up).

    flags
}

/// Extracts this core's Aff0 field from MPIDR_EL1 (bits 7:0), used as
/// `current_core_id()`. Full topology-aware core numbering (Aff0-3)
/// is a follow-up matching cpu.rs's x86_64 MADT-parsing deferral —
/// QEMU's `virt` machine (section 8's target) numbers cores
/// sequentially in Aff0 for the core counts this MVP phase boots with.
fn read_core_id(ids: &IdRegisters) -> u8 {
    (ids.mpidr & 0xFF) as u8
}

// ============================================================================
// Exception Vector Table (VBAR_EL1) — section 3.1's uniform
// Interrupt/Exception Vector Table requirement
// ============================================================================

// AArch64 exception vector table layout (ARM ARM D1.10.2): 16 entries
// of 128 bytes each (2KB total, 2KB-aligned), grouped into 4 sources
// (Current EL w/ SP0, Current EL w/ SPx, Lower EL AArch64, Lower EL
// AArch32) × 4 exception types (Synchronous, IRQ, FIQ, SError).
//
// This project only populates the "Current EL w/ SPx" group (offset
// 0x200) meaningfully, since all execution happens at EL1 using SP_EL1
// (per boot.S's SPSR_EL2 configuration, "EL1h") — the other groups
// contain a minimal trap-and-halt handler, since this MVP phase never
// legitimately takes an exception from EL0/AArch32/SP0 context.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text
    .global arm64_vector_table
    .align 11  // 2^11 = 2048-byte alignment, required by VBAR_EL1

    arm64_vector_table:
    // --- Current EL, SP0 (offsets 0x000-0x1FF): unused in this
    // project (we always run with SP_ELx) — minimal trap handlers.
    .align 7
    b generic_trap_halt         // Synchronous
    .align 7
    b generic_trap_halt         // IRQ
    .align 7
    b generic_trap_halt         // FIQ
    .align 7
    b generic_trap_halt         // SError

    // --- Current EL, SPx (offsets 0x200-0x3FF): the ACTIVE group for
    // this project's EL1h execution.
    .align 7
    b sync_exception_entry      // Synchronous
    .align 7
    b irq_exception_entry       // IRQ
    .align 7
    b generic_trap_halt         // FIQ (unused in this MVP phase)
    .align 7
    b generic_trap_halt         // SError

    // --- Lower EL, AArch64 (offsets 0x400-0x5FF): EL0 (U-mode) Root Task
    // support — the ACTIVE group once `enter_user`/`resume_user` below
    // drop this core to EL0. Synchronous is where `svc` (this project's
    // syscall boundary, analogous to x86_64's `int 0x80` / riscv64's
    // `ecall`) and per-process fault isolation both land (03-Kernel-
    // Subsystems-Layer.md §2.1/§5.2); IRQ is where the timer PPI lands
    // for preemptive scheduling (02-Microkernel-Layer.md §4) once a
    // running U-mode thread is interrupted — `irq_el0_entry` mirrors
    // `sync_el0_entry`'s own save/dispatch/restore shape exactly, just
    // keyed off a registered `TickHandler` instead of `SyscallHandler`/
    // `FaultHandler`. FIQ/SError from EL0 stay minimal trap-halts — this
    // project never legitimately takes either.
    .align 7
    b sync_el0_entry
    .align 7
    b irq_el0_entry
    .align 7
    b generic_trap_halt
    .align 7
    b generic_trap_halt

    // --- Lower EL, AArch32 (offsets 0x600-0x7FF): this project never
    // runs AArch32 code (01-HAL-Layer.md targets AArch64 only).
    .align 7
    b generic_trap_halt
    .align 7
    b generic_trap_halt
    .align 7
    b generic_trap_halt
    .align 7
    b generic_trap_halt

    generic_trap_halt:
        // An exception this MVP phase does not expect. Halt rather
        // than attempt recovery, matching hal-x86_64's philosophy for
        // an unhandled/misrouted interrupt vector.
        wfi
        b generic_trap_halt

    sync_exception_entry:
        // Synchronous exceptions (data/instruction aborts, SVC, etc.)
        // are not yet dispatched to a registered handler in this MVP
        // phase (no code in this crate currently issues SVC, and page
        // faults are not expected given the identity/kernel-only
        // mapping memory.rs establishes) — halted defensively rather
        // than silently ignored.
        wfi
        b sync_exception_entry

    irq_exception_entry:
        // Mirrors hal-x86_64's isr_common_trampoline: save the
        // registers common_interrupt_entry needs, read the interrupt
        // ID from the GIC (interrupt.rs owns that read via
        // acknowledge_interrupt), and dispatch.
        stp x29, x30, [sp, #-16]!
        stp x27, x28, [sp, #-16]!
        stp x25, x26, [sp, #-16]!
        stp x23, x24, [sp, #-16]!
        stp x21, x22, [sp, #-16]!
        stp x19, x20, [sp, #-16]!
        stp x17, x18, [sp, #-16]!
        stp x15, x16, [sp, #-16]!
        stp x13, x14, [sp, #-16]!
        stp x11, x12, [sp, #-16]!
        stp x9, x10, [sp, #-16]!
        stp x7, x8, [sp, #-16]!
        stp x5, x6, [sp, #-16]!
        stp x3, x4, [sp, #-16]!
        stp x1, x2, [sp, #-16]!
        str x0, [sp, #-16]!

        bl common_interrupt_entry

        ldr x0, [sp], #16
        ldp x1, x2, [sp], #16
        ldp x3, x4, [sp], #16
        ldp x5, x6, [sp], #16
        ldp x7, x8, [sp], #16
        ldp x9, x10, [sp], #16
        ldp x11, x12, [sp], #16
        ldp x13, x14, [sp], #16
        ldp x15, x16, [sp], #16
        ldp x17, x18, [sp], #16
        ldp x19, x20, [sp], #16
        ldp x21, x22, [sp], #16
        ldp x23, x24, [sp], #16
        ldp x25, x26, [sp], #16
        ldp x27, x28, [sp], #16
        ldp x29, x30, [sp], #16
        eret

    sync_el0_entry:
        // The EL0 (U-mode) synchronous-exception trampoline — where a
        // `svc` (this project's syscall boundary, mirroring hal-x86_64's
        // dedicated `int 0x80` gate / hal-riscv64's `ecall` handling)
        // from the Root Task lands. Saves ALL 31 GPRs (x0-x30) so
        // `common_sync_entry` gets a full syscall-argument view (x8 =
        // opcode, x0/x1 = a0/a1, per this project's own convention —
        // see `SyscallHandler`'s doc comment) AND so the frame is
        // sufficient, on its own, to seed a resumable `Aarch64UserContext`
        // for the `SwitchTo`/`Terminate` outcomes below — unlike
        // hal-riscv64's trap_entry, no sp-offset correction is needed
        // here: AArch64 banks SP_EL0/SP_EL1 separately, so the EL0
        // thread's stack pointer is never one of x0-x30 in the first
        // place (captured instead via `mrs sp_el0` in
        // `save_frame_as_user_context`).
        //
        // A `SwitchTo`/`Terminate` outcome diverges straight into
        // `restore_user_and_eret` and NEVER returns here to run this
        // trampoline's own `add sp, sp, #256` epilogue below — see that
        // function's own doc comment for the real stack-leak bug this
        // caused (across many repeated process switches) and how it is
        // fixed THERE instead of here (an earlier attempt at fixing it
        // in THIS prologue broke the cooperative two-process `SwitchTo`
        // round-trip and was reverted).
        sub sp, sp, #256
        stp x0, x1,   [sp, #0]
        stp x2, x3,   [sp, #16]
        stp x4, x5,   [sp, #32]
        stp x6, x7,   [sp, #48]
        stp x8, x9,   [sp, #64]
        stp x10, x11, [sp, #80]
        stp x12, x13, [sp, #96]
        stp x14, x15, [sp, #112]
        stp x16, x17, [sp, #128]
        stp x18, x19, [sp, #144]
        stp x20, x21, [sp, #160]
        stp x22, x23, [sp, #176]
        stp x24, x25, [sp, #192]
        stp x26, x27, [sp, #208]
        stp x28, x29, [sp, #224]
        str x30,      [sp, #240]

        mov x0, sp
        bl common_sync_entry

        ldp x0, x1,   [sp, #0]
        ldp x2, x3,   [sp, #16]
        ldp x4, x5,   [sp, #32]
        ldp x6, x7,   [sp, #48]
        ldp x8, x9,   [sp, #64]
        ldp x10, x11, [sp, #80]
        ldp x12, x13, [sp, #96]
        ldp x14, x15, [sp, #112]
        ldp x16, x17, [sp, #128]
        ldp x18, x19, [sp, #144]
        ldp x20, x21, [sp, #160]
        ldp x22, x23, [sp, #176]
        ldp x24, x25, [sp, #192]
        ldp x26, x27, [sp, #208]
        ldp x28, x29, [sp, #224]
        ldr x30,      [sp, #240]
        add sp, sp, #256
        eret

    irq_el0_entry:
        // The EL0 (U-mode) IRQ trampoline — where the timer PPI lands
        // once `enter_user`/`resume_user` has dropped this core to EL0
        // and `HalInterface::arm_timer` has armed a deadline
        // (02-Microkernel-Layer.md §4's preemptive scheduler). Saves ALL
        // 31 GPRs, identically to `sync_el0_entry` above (same reasoning:
        // `common_irq_el0_entry` needs the full frame to seed a resumable
        // `Aarch64UserContext` for the `SwitchTo`/`Terminate` outcomes —
        // no sp-offset correction needed here either, for the same
        // "SP_EL0/SP_EL1 banked separately" reason `sync_el0_entry`'s own
        // doc comment gives).
        //
        // A `SwitchTo`/`Terminate` outcome diverges the SAME way
        // `sync_el0_entry`'s own does — see `restore_user_and_eret`'s
        // doc comment for the stack-reset mechanism that makes this
        // safe regardless of which trampoline reaches it.
        sub sp, sp, #256
        stp x0, x1,   [sp, #0]
        stp x2, x3,   [sp, #16]
        stp x4, x5,   [sp, #32]
        stp x6, x7,   [sp, #48]
        stp x8, x9,   [sp, #64]
        stp x10, x11, [sp, #80]
        stp x12, x13, [sp, #96]
        stp x14, x15, [sp, #112]
        stp x16, x17, [sp, #128]
        stp x18, x19, [sp, #144]
        stp x20, x21, [sp, #160]
        stp x22, x23, [sp, #176]
        stp x24, x25, [sp, #192]
        stp x26, x27, [sp, #208]
        stp x28, x29, [sp, #224]
        str x30,      [sp, #240]

        mov x0, sp
        bl common_irq_el0_entry

        ldp x0, x1,   [sp, #0]
        ldp x2, x3,   [sp, #16]
        ldp x4, x5,   [sp, #32]
        ldp x6, x7,   [sp, #48]
        ldp x8, x9,   [sp, #64]
        ldp x10, x11, [sp, #80]
        ldp x12, x13, [sp, #96]
        ldp x14, x15, [sp, #112]
        ldp x16, x17, [sp, #128]
        ldp x18, x19, [sp, #144]
        ldp x20, x21, [sp, #160]
        ldp x22, x23, [sp, #176]
        ldp x24, x25, [sp, #192]
        ldp x26, x27, [sp, #208]
        ldp x28, x29, [sp, #224]
        ldr x30,      [sp, #240]
        add sp, sp, #256
        eret
    "#
);

/// Called from `irq_exception_entry`'s trampoline. Unlike x86_64,
/// where the vector number is captured by a per-vector stub and pushed
/// on the stack, ARM64's GIC reports which interrupt fired via a
/// dedicated register read (`interrupt.rs`'s `InterruptCtrl::
/// acknowledge_interrupt`) — this function performs that read itself
/// and dispatches, since the vector table above has no per-IRQ stubs
/// the way x86_64's IDT does (GICv3 is a single IRQ exception type
/// covering every line, disambiguated only after entry).
#[no_mangle]
extern "C" fn common_interrupt_entry() {
    crate::interrupt::dispatch_current_irq();
}

/// Loads VBAR_EL1 to point at `arm64_vector_table` above.
///
/// # Safety
/// Must only be called once per core, before this core relies on any
/// exception (including IRQ) being handled correctly.
#[cfg(not(target_os = "none"))]
unsafe fn load_vbar() {
    // Host (`cargo test`) stub — no VBAR_EL1 / vector table off the
    // bare-metal target.
}

#[cfg(target_os = "none")]
unsafe fn load_vbar() {
    unsafe extern "C" {
        static arm64_vector_table: u8;
    }
    // SAFETY: `arm64_vector_table`'s address is a `'static`,
    // 2KB-aligned, fully-populated table emitted by the global_asm!
    // block above — VBAR_EL1 has no further preconditions beyond
    // 2KB alignment, which the `.align 11` directive guarantees.
    unsafe {
        let addr = &arm64_vector_table as *const u8 as u64;
        core::arch::asm!("msr vbar_el1, {}", in(reg) addr);
        core::arch::asm!("isb");
    }
}

// ============================================================================
// Saved hardware context layout (matches ARM64_CONTEXT_BYTES = 160)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Arm64Context {
    // Callee-saved GPRs per AAPCS64 (X19-X28), plus FP (X29) and LR (X30):
    x19: u64, x20: u64, x21: u64, x22: u64, x23: u64, x24: u64,
    x25: u64, x26: u64, x27: u64, x28: u64,
    x29: u64, // frame pointer
    x30: u64, // link register (used as the resume PC on restore)
    sp: u64,
    // Address space root: TTBR0_EL1, ARM64's per-thread page table
    // base — the equivalent role x86_64's CR3 plays in X86_64Context.
    ttbr0_el1: u64,
    spsr_el1: u64,
    tpidr_el0: u64, // thread-local storage base, AAPCS64 convention
    _reserved: [u64; 4],
}

const _: () = {
    assert!(size_of::<Arm64Context>() == ARM64_CONTEXT_BYTES);
};

// ============================================================================
// Cpu — CpuAbstraction<ARM64_CONTEXT_BYTES> implementation
// ============================================================================

pub struct Cpu {
    feature_flags: Cell<CpuFeatureFlags>,
    core_id: u8,
}

impl Cpu {
    pub fn new() -> Self {
        let ids = RealIdRegisters.read();
        let feature_flags = Cell::new(detect_feature_flags(&ids));
        let core_id = read_core_id(&ids);
        Self { feature_flags, core_id }
    }

    /// Mirrors hal-x86_64's `Cpu::mark_iommu_capable`: SMMU presence
    /// is discovered via ACPI IORT / Device Tree by `memory.rs`, not
    /// via ID registers, so it is folded in after the fact.
    pub fn mark_iommu_capable(&self, present: bool) {
        let mut flags = self.feature_flags.get();
        flags.set(CpuFeatureFlags::IOMMU_CAPABLE, present);
        self.feature_flags.set(flags);
    }

    /// Same MVP-phase single-core scope as hal-x86_64's
    /// `detected_core_count` — real multi-core enumeration requires
    /// parsing the ACPI MADT (GICC entries) or Device Tree `cpu` nodes,
    /// a tracked follow-up alongside memory.rs's ACPI/DT parsing.
    fn detected_core_count(&self) -> usize {
        1
    }
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuAbstraction<{ crate::ARM64_CONTEXT_BYTES }> for Cpu {
    fn core_count(&self) -> usize {
        self.detected_core_count()
    }

    fn current_core_id(&self) -> usize {
        self.core_id as usize
    }

    fn feature_flags(&self) -> CpuFeatureFlags {
        self.feature_flags.get()
    }

    unsafe fn context_switch(
        &self,
        from: &mut CpuContext<{ crate::ARM64_CONTEXT_BYTES }>,
        to: &CpuContext<{ crate::ARM64_CONTEXT_BYTES }>,
    ) {
        // SAFETY: same reasoning as hal-x86_64's context_switch — the
        // buffer's size/alignment matches Arm64Context exactly (see
        // the `const _` assertion above), and this trait method's own
        // safety contract (hal-core/src/cpu.rs) guarantees valid,
        // non-aliasing, previously-saved-or-freshly-initialized
        // contexts.
        let from_ctx = unsafe { &mut *(from.as_bytes_mut().as_mut_ptr() as *mut Arm64Context) };
        let to_ctx = unsafe { &*(to.as_bytes().as_ptr() as *const Arm64Context) };

        // Host (`cargo test`) build: a real register save/restore cannot
        // run off the bare-metal target. No unit test drives an actual
        // context switch (they assert the context *layout* only), so the
        // host path is unreachable.
        #[cfg(not(target_os = "none"))]
        {
            let _ = (from_ctx, to_ctx);
            unreachable!("context_switch is bare-metal only (host test build)");
        }

        // SAFETY: hardware register save/restore this trait method
        // exists to perform; preconditions (interrupts masked,
        // non-aliasing contexts, valid to_ctx) are the caller's
        // responsibility per the trait's own safety documentation.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!(
                "stp x19, x20, [{from_ptr}, #0x00]",
                "stp x21, x22, [{from_ptr}, #0x10]",
                "stp x23, x24, [{from_ptr}, #0x20]",
                "stp x25, x26, [{from_ptr}, #0x30]",
                "stp x27, x28, [{from_ptr}, #0x40]",
                "stp x29, x30, [{from_ptr}, #0x50]",
                "mov x1, sp",
                "str x1, [{from_ptr}, #0x60]",
                "mrs x1, ttbr0_el1",
                "str x1, [{from_ptr}, #0x68]",
                // Capture resume point: label 1 below, the same way
                // hal-x86_64 captures RIP via `lea` + a local label.
                "adr x1, 1f",
                "str x1, [{from_ptr}, #0x50 + 8]", // overwrite saved x30 slot with resume addr

                "ldr x1, [{to_ptr}, #0x68]",
                "msr ttbr0_el1, x1",
                "isb",
                "ldr x1, [{to_ptr}, #0x60]",
                "mov sp, x1",
                "ldp x19, x20, [{to_ptr}, #0x00]",
                "ldp x21, x22, [{to_ptr}, #0x10]",
                "ldp x23, x24, [{to_ptr}, #0x20]",
                "ldp x25, x26, [{to_ptr}, #0x30]",
                "ldp x27, x28, [{to_ptr}, #0x40]",
                "ldp x29, x30, [{to_ptr}, #0x50]",
                "br x30",

                "1:",
                from_ptr = in(reg) from_ctx as *mut Arm64Context,
                to_ptr = in(reg) to_ctx as *const Arm64Context,
                out("x1") _,
            );
        }
    }

    fn init_context(
        &self,
        context: &mut CpuContext<{ crate::ARM64_CONTEXT_BYTES }>,
        entry: usize,
        stack_top: usize,
    ) {
        // SAFETY: a `[u8; ARM64_CONTEXT_BYTES]` buffer is layout-
        // compatible with `Arm64Context` (`#[repr(C)]`, size asserted by
        // the `const _` above). Zeroing then setting the fields the
        // `context_switch` restore path consumes for a fresh thread:
        // `x30` (branched to via `br x30`), `sp`, `ttbr0_el1`.
        let ctx = unsafe {
            &mut *(context.as_bytes_mut().as_mut_ptr() as *mut Arm64Context)
        };
        *ctx = Arm64Context::default();
        ctx.x30 = entry as u64;
        ctx.sp = stack_top as u64;

        #[cfg(target_os = "none")]
        {
            // SAFETY: `mrs ttbr0_el1` is a side-effect-free read; the new
            // thread runs in this same address space for now.
            let ttbr0: u64;
            unsafe { core::arch::asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack, preserves_flags)) };
            ctx.ttbr0_el1 = ttbr0;
        }
        #[cfg(not(target_os = "none"))]
        {
            ctx.ttbr0_el1 = 0;
        }
    }

    #[cfg(target_os = "none")]
    fn map_ram_identity(&self, root_frame: usize, bytes_gib: usize, user_accessible: bool) {
        aarch64_paging::map_ram_identity(root_frame, bytes_gib, user_accessible)
    }

    #[cfg(target_os = "none")]
    fn activate_address_space(&self, root_frame: usize) {
        if root_frame == 0 {
            // Disable the MMU, returning to boot.S's initial physical-
            // addressing state — mirrors hal-riscv64's `satp == 0` Bare-
            // mode sentinel. Unlike hal-x86_64 (where long mode REQUIRES
            // `CR0.PG = 1`, so there is no "disable" state to return
            // to), AArch64 can turn `SCTLR_EL1.M` back off just as
            // freely as it turned it on.
            // SAFETY: caller guarantees no code/data this core still
            // needs depends on the translation being torn down (same
            // precondition hal-riscv64's `activate_address_space(0)`
            // documents).
            unsafe {
                let mut sctlr: u64;
                core::arch::asm!("mrs {0}, sctlr_el1", out(reg) sctlr);
                sctlr &= !1u64; // clear M
                core::arch::asm!("msr sctlr_el1, {0}", in(reg) sctlr);
                core::arch::asm!("isb");
            }
            return;
        }
        // SAFETY: the caller guarantees `root_frame` is a valid, fully
        // built L1 table (via `map_ram_identity` / `map_range`) that
        // maps at least all memory this core is currently executing
        // from and about to touch. MAIR_EL1/TCR_EL1 are configured here
        // (not in `map_ram_identity`) because they are per-core control
        // state, not part of the table itself — reconfiguring them on
        // every activation is cheap and keeps this method self-
        // contained, mirroring how `memory.rs`'s OWN (separate, dormant
        // — see this module's doc comment) `activate_page_tables`
        // bundles the same two registers with its own TTBR0 write.
        unsafe {
            // MAIR_EL1: index 0 = Normal, Write-Back (0xFF); index 1 =
            // Device-nGnRnE (0x00) — unused by this mechanism today (no
            // MMIO is `map_range`d through it yet) but kept at the same
            // index convention `memory.rs`'s own mechanism uses, in case
            // a future caller needs it.
            let mair: u64 = 0x00FF;
            core::arch::asm!("msr mair_el1, {0}", in(reg) mair);

            core::arch::asm!("msr ttbr0_el1, {0}", in(reg) root_frame as u64);

            // TCR_EL1: T0SZ = 25 -> 39-bit input address space (2^39 =
            // 512 GiB), matching this module's 3-level (L1/L2/L3),
            // 4 KiB-granule table shape — deliberately the SAME VA bit
            // positions as hal-riscv64's Sv39 (both split a 39-bit VA
            // into three 9-bit indices + a 12-bit page offset), so a
            // single 4 KiB page can serve as the L1 ROOT exactly like
            // Sv39's root does — unlike hal-x86_64, whose CR3 always
            // names a PML4 and therefore needs a 2-page root (see
            // `hal_x86_64::cpu`'s `x86_64_paging` module doc comment).
            // EPD1 = 1 disables any TTBR1_EL1 walk (this project only
            // ever uses TTBR0/the lower half); IPS = 0b001 (36-bit,
            // 64 GiB) comfortably covers QEMU virt's RAM range for this
            // MVP phase and avoids relying on TCR_EL1.IPS's otherwise
            // architecturally UNSPECIFIED reset value.
            let tcr: u64 = 25          // T0SZ
                | (0b01 << 8)          // IRGN0 = write-back
                | (0b01 << 10)         // ORGN0 = write-back
                | (0b11 << 12)         // SH0 = inner shareable
                | (0b00 << 14)         // TG0 = 4 KiB granule
                | (0b001 << 16)        // IPS = 36-bit
                | (1u64 << 23);        // EPD1 = 1
            core::arch::asm!("msr tcr_el1, {0}", in(reg) tcr);
            core::arch::asm!("isb");

            // Enable the MMU (+ D/I caches) — a no-op if already on
            // (idempotent OR of the same three bits).
            let mut sctlr: u64;
            core::arch::asm!("mrs {0}, sctlr_el1", out(reg) sctlr);
            sctlr |= (1 << 0) | (1 << 2) | (1 << 12);
            core::arch::asm!("msr sctlr_el1, {0}", in(reg) sctlr);
            core::arch::asm!("isb");
        }
    }

    #[cfg(target_os = "none")]
    fn flush_tlb(&self) {
        // SAFETY: `tlbi vmalle1` (all stage-1 EL1&0 entries, every ASID)
        // with the standard DSB/ISB bracketing has no preconditions in
        // EL1 and no effect beyond the flush — same whole-TLB-shootdown
        // scope as hal-riscv64's bare `sfence.vma` / hal-x86_64's CR3
        // reload.
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "tlbi vmalle1",
                "dsb ish",
                "isb",
                options(nostack, preserves_flags),
            );
        }
    }

    #[cfg(target_os = "none")]
    fn map_range(
        &self,
        root_frame: usize,
        vaddr: usize,
        paddr: usize,
        len: usize,
        perm_bits: usize,
        pool_base: usize,
        pool_len: usize,
    ) -> u32 {
        aarch64_paging::map_range(root_frame, vaddr, paddr, len, perm_bits, pool_base, pool_len)
    }

    #[cfg(target_os = "none")]
    fn enter_user(&self, entry: usize, stack_top: usize) -> ! {
        // SPSR_EL1 target state for a fresh EL0 (U-mode) entry: M[3:0] =
        // 0b0000 (EL0t — EL0 always uses SP_EL0, there is no "EL0h"),
        // every other field (including the DAIF interrupt masks) clear
        // so the dropped thread runs with interrupts unmasked — mirrors
        // hal-riscv64's SPIE=1 / hal-x86_64's RFLAGS.IF=1 choice.
        //
        // SAFETY: a one-way `eret` into EL0: sets SP_EL0 (banked, so
        // EL1's own SP_EL1 is untouched), ELR_EL1 (resume PC), SPSR_EL1
        // (target state), then `eret` loads PSTATE from SPSR_EL1 and
        // branches to ELR_EL1, dropping privilege. Never returns.
        unsafe {
            core::arch::asm!(
                "msr sp_el0, {sp}",
                "msr elr_el1, {entry}",
                "msr spsr_el1, {spsr}",
                "eret",
                sp = in(reg) stack_top as u64,
                entry = in(reg) entry as u64,
                spsr = in(reg) 0u64,
                options(noreturn),
            );
        }
    }

    fn init_user_context(
        &self,
        context: &mut hal_core::UserContext,
        entry: usize,
        stack_top: usize,
        root_frame: usize,
    ) {
        // SAFETY: `hal_core::UserContext` is `#[repr(C, align(8))]` over
        // exactly `[u8; HAL_USER_CONTEXT_BYTES]`, and `Aarch64UserContext`
        // is `#[repr(C)]` of a size asserted `<=` that (the `const _`
        // beside its definition) — so the buffer's leading bytes ARE a
        // valid `Aarch64UserContext`.
        let ctx = unsafe {
            &mut *(context.as_bytes_mut().as_mut_ptr() as *mut Aarch64UserContext)
        };
        *ctx = Aarch64UserContext::default();
        ctx.sp_el0 = stack_top as u64;
        ctx.elr_el1 = entry as u64;
        ctx.spsr_el1 = 0; // EL0t, DAIF unmasked — same choice as enter_user.

        // `root_frame == 0` means "keep whatever is active" — read
        // TTBR0_EL1 back so the first `resume_user` does not clobber
        // the live translation (mirrors hal-riscv64's `satp` / hal-
        // x86_64's `cr3` handling here exactly).
        #[cfg(target_os = "none")]
        {
            let ttbr0: u64;
            // SAFETY: reading TTBR0_EL1 has no preconditions in EL1.
            unsafe { core::arch::asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack, preserves_flags)) };
            ctx.ttbr0_el1 = if root_frame != 0 { root_frame as u64 } else { ttbr0 };
        }
        #[cfg(not(target_os = "none"))]
        {
            ctx.ttbr0_el1 = root_frame as u64;
        }
    }

    #[cfg(target_os = "none")]
    unsafe fn resume_user(&self, context: &hal_core::UserContext) -> ! {
        // SAFETY: the buffer is a valid `Aarch64UserContext` (see
        // `init_user_context`); the resumable-context + interrupts-
        // masked obligations are this method's documented caller
        // contract.
        let blob = context.as_bytes().as_ptr() as *const Aarch64UserContext;
        unsafe { restore_user_and_eret(blob) }
    }

    #[cfg(not(target_os = "none"))]
    unsafe fn resume_user(&self, context: &hal_core::UserContext) -> ! {
        let _ = context;
        unreachable!("resume_user is bare-metal only (host test build)");
    }

    fn set_privilege_level(&self, level: PrivilegeLevel) -> Result<(), HalError> {
        match level {
            // Unlike x86_64 (where Monitor is unsupported), ARM64
            // genuinely has EL2 — but per this project's Discovery +
            // Policy model, EL2 involvement (as a hypervisor) belongs
            // to the layer 5 Linux Compat Runtime's VMM
            // (05-Legacy-Compat-Applications-Layer.md section 3.1),
            // not to this general-purpose kernel/user privilege
            // primitive. Reported as supported at the type level
            // (VIRTUALIZATION feature flag), but this specific
            // primitive still declines to perform an EL1 -> EL2
            // transition itself, mirroring x86_64's reasoning that
            // hypervisor-mode transitions are a specialized mechanism
            // (VMLAUNCH-equivalent, not a CPL/EL change) owned
            // elsewhere.
            PrivilegeLevel::Monitor => Err(HalError::UnsupportedPrivilegeLevel),
            // Same reasoning as hal-x86_64's set_privilege_level: which
            // EL a context resumes at is encoded in that context's
            // SPSR_EL1 field (Arm64Context::spsr_el1), applied only as
            // part of context_switch's restore path — never as a
            // standalone operation on the currently executing core.
            PrivilegeLevel::Kernel | PrivilegeLevel::User => Ok(()),
        }
    }

    fn bootstrap_current_core(&self) -> Result<(), HalError> {
        // SAFETY: called once per core, before any exception (Sync/
        // IRQ/FIQ/SError) can be taken on this core — boot.S's EL2
        // drop sequence masked interrupts via SPSR_EL2's D,A,I,F bits,
        // and nothing between there and here re-enables them.
        unsafe {
            load_vbar();
        }
        Ok(())
    }
}

// ============================================================================
// U-mode syscall boundary (`svc #0`, EL0 -> EL1) — analogous to
// hal-riscv64's `ecall`/`SyscallHandler`/`TrapOutcome`/`common_trap_entry`
// and hal-x86_64's `int 0x80` mechanism, routed through this crate's own
// `sync_el0_entry` trampoline (the "Lower EL, AArch64, Synchronous" slot
// of `arm64_vector_table` above) rather than a dedicated separate gate —
// AArch64 has no per-vector gate table the way x86_64's IDT does; every
// synchronous exception from EL0 shares ONE entry point, and Rust code
// (`common_sync_entry`) disambiguates via ESR_EL1.EC, mirroring exactly
// how hal-riscv64's single `stvec` target disambiguates via `scause`.
// ============================================================================

/// This project's own syscall convention on AArch64: `svc #0`, with
/// `x8` = opcode and `x0`/`x1` = the first two arguments — deliberately
/// the same register convention the real Linux AArch64 syscall ABI uses
/// (`x8` = syscall number, `x0`-`x5` = arguments, `x0` = return value),
/// for a convention any ARM developer recognizes, matching hal-x86_64's
/// own choice to reuse Linux's classic `int 0x80` vector for the same
/// reason.
const ESR_EC_SVC_AARCH64: u64 = 0x15;

/// The on-stack layout `sync_el0_entry` pushes/pops: all 31 general-
/// purpose registers, `regs[i]` holding `x{i}` directly (unlike
/// hal-riscv64's `TrapFrame`, which is 1-indexed because RISC-V's `x0`
/// is hardwired zero and never saved — AArch64 has no such register
/// among x0-x30, so no reindexing is needed here). Notably does NOT
/// include the stack pointer: AArch64 banks `SP_EL0`/`SP_EL1`
/// separately, so — unlike hal-riscv64's `trap_entry` (where `x2`/`sp`
/// is a normal GPR needing a post-hoc offset correction, see
/// `save_trap_frame_as_user_context`'s doc comment there) — the EL0
/// thread's stack pointer is never part of this frame at all; it is
/// read directly via `mrs sp_el0` in `save_frame_as_user_context` below.
#[repr(C)]
pub struct SyncFrame {
    /// x0..x30, in order.
    pub regs: [u64; 31],
}

#[cfg(target_os = "none")]
impl SyncFrame {
    const X0: usize = 0;
    const X8: usize = 8;
}

/// A suspended EL0 thread's full context: `SyncFrame`'s exact same 31
/// GPRs plus the banked/system state `eret` needs that never lives in a
/// GPR — `SP_EL0` (the thread's own stack pointer), `ELR_EL1` (resume
/// PC), `SPSR_EL1` (privilege/interrupt-enable state to restore), and
/// `TTBR0_EL1` (which address space the thread runs in) — the AArch64
/// analogue of hal-riscv64's `RiscvUserContext` (`sepc`/`sstatus`/
/// `satp`) and hal-x86_64's `X8664UserContext` (`rip`/`rflags`/`cr3`,
/// plus its own banked `ss`/`cs`/`rsp`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Aarch64UserContext {
    /// x0..x30, in order — same layout as `SyncFrame::regs`.
    regs: [u64; 31],
    /// The thread's own (banked) stack pointer.
    sp_el0: u64,
    /// Resume program counter in EL0.
    elr_el1: u64,
    /// Privilege / interrupt-enable snapshot `eret` restores PSTATE from.
    spsr_el1: u64,
    /// Address-space root (`TTBR0_EL1`) the thread executes under.
    ttbr0_el1: u64,
}

const _: () = {
    assert!(core::mem::size_of::<Aarch64UserContext>() <= hal_core::HAL_USER_CONTEXT_BYTES);
};

/// What the syscall handler decided should happen next — identical
/// shape to hal-riscv64's / hal-x86_64's own `TrapOutcome` (see either
/// type's doc comment for the rationale behind each variant); duplicated
/// here rather than shared for the same reason those two duplicate it
/// from each other: every other piece of the trap-handling surface
/// (frame layout, restore mechanism) is architecture-local too, and
/// hal_core defines no such type.
pub enum TrapOutcome {
    /// Return to the trapping thread with `.0` in `x0`, `ELR_EL1`
    /// advanced past the 4-byte `svc` (every AArch64 instruction is
    /// 4 bytes — unlike x86_64's 2-byte `int 0x80` or riscv64's 4-byte
    /// `ecall`, which happens to match here). The ordinary syscall
    /// return.
    Resume(usize),
    /// Serialise the trapping thread's full context into the
    /// `HAL_USER_CONTEXT_BYTES` blob at `save`, then restore `into` and
    /// `eret` into it. Both pointers are kernel-owned, 8-byte-aligned
    /// `hal_core::UserContext` storage.
    SwitchTo {
        /// Where to write the outgoing thread's snapshot.
        save: *mut u8,
        /// The incoming thread's context to resume.
        into: *const u8,
    },
    /// The trapping thread has been TERMINATED — no save (a terminated
    /// thread never resumes); just restores `into` and `eret`s into it.
    Terminate {
        /// The next thread's context to resume.
        into: *const u8,
    },
}

/// Signature of the handler the microkernel registers for a `svc` from
/// EL0: raw `(x8, x0, x1)` — this project's own convention (see
/// `ESR_EC_SVC_AARCH64`'s doc comment) — returning a `TrapOutcome`
/// telling the trampoline how to resume.
pub type SyscallHandler = fn(usize, usize, usize) -> TrapOutcome;

#[cfg(target_os = "none")]
static mut SYSCALL_HANDLER: Option<SyscallHandler> = None;

/// Registers the handler `common_sync_entry` calls for a `svc` from
/// EL0. The microkernel calls this once during boot, before it drops
/// any process to user mode — same "no handler, no behavior change"
/// contract as hal-riscv64's `set_syscall_handler` / hal-x86_64's own,
/// so a binary that links `hal-arm64` but never runs user code (e.g.
/// `kernel-stub`) simply never registers one.
#[cfg(target_os = "none")]
pub fn set_syscall_handler(handler: SyscallHandler) {
    // SAFETY: single-core boot; set exactly once before any EL0 `svc`
    // can be taken.
    unsafe {
        core::ptr::addr_of_mut!(SYSCALL_HANDLER).write(Some(handler));
    }
}

/// Signature of the handler the microkernel registers for a supervisor
/// timer interrupt (the timer PPI) taken **while a U-mode thread was
/// running** — the preemptive scheduler's entry point
/// (02-Microkernel-Layer.md §4). Takes no arguments (`irq_el0_entry`
/// owns the interrupted frame) and returns a `TrapOutcome`: `Resume` to
/// let the current thread keep its quantum, or `SwitchTo` to preempt
/// it. The handler is responsible for re-arming (or cancelling) the
/// timer via `HalInterface`. Mirrors hal-riscv64's `TickHandler`
/// exactly.
pub type TickHandler = fn() -> TrapOutcome;

#[cfg(target_os = "none")]
static mut TICK_HANDLER: Option<TickHandler> = None;

/// Registers the preemptive-scheduler tick handler `common_irq_el0_
/// entry` calls when the timer PPI lands on a running U-mode thread.
/// Set once during boot. Until it is set (and the kernel arms a
/// deadline via `HalInterface::arm_timer`), the timer PPI still fires
/// and gets acknowledged/EOI'd by `interrupt::dispatch_current_irq`
/// (matching `on_timer_interrupt`'s existing callback mechanism) but
/// triggers no thread switch — so `kernel-stub`, which registers no
/// handler and never enters U-mode, is unaffected.
#[cfg(target_os = "none")]
pub fn set_tick_handler(handler: TickHandler) {
    // SAFETY: single-core boot; set exactly once before the timer is
    // armed and before any drop to EL0.
    unsafe {
        core::ptr::addr_of_mut!(TICK_HANDLER).write(Some(handler));
    }
}

/// `ESR_EL1.EC` = 0x00, "Unknown reason" per the ARM Architecture
/// Reference Manual — the class every genuinely undefined A64 encoding
/// traps as, including `udf #0` (Permanently Undefined): this project's
/// aarch64 fault-injection demo choice (03-Kernel-Subsystems-Layer.md
/// §5.2), analogous to hal-riscv64's `.word 0` / hal-x86_64's `ud2`.
/// The ONLY exception class this mechanism currently handles — a real
/// kernel would extend this to every EC that can legitimately occur
/// from EL0 (e.g. Data/Instruction Abort, EC 0x24/0x20), a tracked
/// follow-up once a concrete need arises (same scope decision
/// hal-x86_64's own `FAULT_VECTOR_UD` doc comment makes).
const ESR_EC_UNKNOWN_AARCH64: u64 = 0x00;

/// Signature of the handler the microkernel registers for a fatal EL0
/// exception that is not a `svc`: raw `(ec, elr, far)` — the exception
/// class, the resume PC, and the fault address (0 for `ESR_EC_UNKNOWN_
/// AARCH64`, which carries no fault-address ISS field) — mirrors
/// hal-riscv64's `FaultHandler`'s `(cause_code, sepc, stval)` shape and
/// hal-x86_64's `FaultHandler`'s `(vector, rip, _reserved)` shape.
/// Always expected to return `TrapOutcome::Terminate` in practice (the
/// faulting thread cannot safely resume), though `Resume`/`SwitchTo`
/// remain valid if a future policy wants to retry or reschedule
/// instead — same contract as the other two architectures' own
/// `FaultHandler` types.
pub type FaultHandler = fn(usize, usize, usize) -> TrapOutcome;

#[cfg(target_os = "none")]
static mut FAULT_HANDLER: Option<FaultHandler> = None;

/// Registers the handler `common_sync_entry` calls for a fatal EL0
/// exception that is not a `svc` (03-Kernel-Subsystems-Layer.md §2.1/
/// §5.2 per-process fault isolation). Same "no handler, no behavior
/// change" contract as `set_syscall_handler` — a binary that never
/// registers one (e.g. `kernel-stub`) is unaffected; an unhandled fault
/// (no registered handler) falls through to the existing dump-and-halt
/// path unchanged.
#[cfg(target_os = "none")]
pub fn set_fault_handler(handler: FaultHandler) {
    // SAFETY: single-core boot; set exactly once before any drop to
    // EL0.
    unsafe {
        core::ptr::addr_of_mut!(FAULT_HANDLER).write(Some(handler));
    }
}

/// Host (`cargo test`) stub — reached only from the bare-metal
/// `sync_el0_entry`'s `bl common_sync_entry` above, which (being part of
/// a `global_asm!` block) is not itself `#[cfg(target_os = "none")]`-
/// gated and so is present in every build; without this stub the host
/// build fails to LINK (an unresolved `common_sync_entry` symbol) rather
/// than merely never executing this dead trampoline — same fix
/// hal-riscv64's `common_trap_entry` / hal-x86_64's `common_syscall_entry`
/// host stubs apply for the identical reason.
#[cfg(not(target_os = "none"))]
#[no_mangle]
extern "C" fn common_sync_entry(_frame: *mut SyncFrame) {}

/// Called from `sync_el0_entry` with a pointer to the saved `SyncFrame`.
/// Reads `ESR_EL1.EC` to identify the exception; routes a `svc` (EC =
/// `ESR_EC_SVC_AARCH64`) to the registered `SyscallHandler` and advances
/// `ELR_EL1` past it; anything else (this milestone registers no fault/
/// tick handler yet — same scope decision hal-x86_64's own U-mode+
/// syscall milestone made) dumps and halts.
#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn common_sync_entry(frame: *mut SyncFrame) {
    let (esr, elr, far): (u64, u64, u64);
    // SAFETY: reading ESR_EL1/ELR_EL1/FAR_EL1 has no preconditions
    // inside an exception handler, which `sync_el0_entry` guarantees
    // this runs inside of.
    unsafe {
        core::arch::asm!("mrs {0}, esr_el1", out(reg) esr);
        core::arch::asm!("mrs {0}, elr_el1", out(reg) elr);
        core::arch::asm!("mrs {0}, far_el1", out(reg) far);
    }
    let ec = (esr >> 26) & 0x3F;

    if ec == ESR_EC_SVC_AARCH64 {
        // SAFETY: `frame` is the on-stack register file `sync_el0_entry`
        // just saved; valid for this call, with no other live reference.
        let f = unsafe { &mut *frame };
        // SAFETY: single-core; `SYSCALL_HANDLER` is only written by
        // `set_syscall_handler` during boot, before any EL0 `svc`.
        let handler = unsafe { core::ptr::addr_of!(SYSCALL_HANDLER).read() };
        let Some(h) = handler else {
            trap_diag(ec, elr, far);
            halt_on_unexpected_exception();
        };
        match h(
            f.regs[SyncFrame::X8] as usize,
            f.regs[SyncFrame::X0] as usize,
            f.regs[SyncFrame::X0 + 1] as usize,
        ) {
            TrapOutcome::Resume(ret) => {
                f.regs[SyncFrame::X0] = ret as u64;
                // `elr` needs NO adjustment here: per the ARM
                // Architecture Reference Manual, the preferred return
                // address for an `SVC` exception is ALREADY the address
                // of the instruction AFTER the 4-byte `svc` — unlike a
                // Data/Instruction Abort (which points AT the faulting
                // instruction). **Real bug found via QEMU** (this
                // session's P2/device-manager demo — the exact same
                // class of bug hal-x86_64's own `common_syscall_entry`
                // had for `int 0x80`): an earlier draft added a manual
                // `elr + 4` here on top of that already-correct
                // hardware value, double-advancing past 4 bytes of the
                // NEXT instruction on every EL0 syscall this project has
                // ever made on aarch64. This went unnoticed through the
                // Root Task's own ALIVE/REPORT/two-process round-trip
                // purely by luck (the skipped instruction happened to be
                // harmless setup code that got redone anyway) — device-
                // manager's `subsystem_main` was the first code layout
                // where the skip corrupted something observable: its
                // `DM_WAIT_CRASH`/`DM_POLL_CRASH` calls' `svc`s got
                // skipped over ENTIRELY (each `svc` is exactly 4 bytes,
                // so a `+4` double-advance from one `svc`'s own trapped
                // `elr` lands exactly ON the mov/svc pair belonging to
                // the FOLLOWING syscall, silently replaying earlier
                // report() logic and reporting `Starting` an extra two
                // times before genuine "Restarting" — confirmed via
                // disassembly cross-referenced against a `-d int` trace:
                // every trapped `elr` was already exactly `svc_addr + 4`
                // on entry). Fixed: `elr` used AS-IS in both this arm and
                // `SwitchTo` below.
                //
                // SAFETY: writing ELR_EL1 is valid within an exception
                // handler.
                unsafe { core::arch::asm!("msr elr_el1, {0}", in(reg) elr) };
            }
            TrapOutcome::SwitchTo { save, into } => {
                // SAFETY: `save`/`into` are kernel-owned, 8-byte-aligned
                // `HAL_USER_CONTEXT_BYTES` blobs (the trampoline/
                // `hal_core::UserContext` contract). Snapshot the
                // outgoing thread — resuming AFTER its `svc` — then
                // never return: `restore_user_and_eret` abandons this
                // exception frame's stack and `eret`s into the incoming
                // thread.
                //
                // `elr` (NOT `elr + 4`): same bug/fix as the `Resume`
                // arm just above.
                unsafe {
                    save_frame_as_user_context(f, elr, save as *mut Aarch64UserContext);
                    restore_user_and_eret(into as *const Aarch64UserContext);
                }
            }
            TrapOutcome::Terminate { into } => {
                // No save: this exception frame is simply abandoned,
                // same as any other terminated thread.
                // SAFETY: `into` is a kernel-owned, 8-byte-aligned
                // `HAL_USER_CONTEXT_BYTES` blob.
                unsafe { restore_user_and_eret(into as *const Aarch64UserContext) };
            }
        }
        return;
    }

    if ec == ESR_EC_UNKNOWN_AARCH64 {
        // SAFETY: `frame` is the on-stack register file `sync_el0_entry`
        // just saved; valid for this call, with no other live reference
        // (the `svc` branch above already returned by this point).
        let f = unsafe { &mut *frame };
        // SAFETY: single-core; `FAULT_HANDLER` is only written by
        // `set_fault_handler` during boot, before any drop to EL0.
        let handler = unsafe { core::ptr::addr_of!(FAULT_HANDLER).read() };
        if let Some(h) = handler {
            match h(ec as usize, elr as usize, far as usize) {
                TrapOutcome::Resume(ret) => {
                    // Not the expected outcome for a fatal exception (the
                    // faulting instruction is still `udf`, so resuming at
                    // the SAME `elr` would just re-fault forever), but the
                    // type is shared with the syscall path, so this arm
                    // must exist — same as hal-riscv64's/hal-x86_64's own
                    // fault-handler `Resume` arms.
                    f.regs[SyncFrame::X0] = ret as u64;
                    return;
                }
                TrapOutcome::SwitchTo { save, into } => {
                    // SAFETY: `save`/`into` are kernel-owned, 8-byte-
                    // aligned `HAL_USER_CONTEXT_BYTES` blobs. Resume
                    // point is `elr` unchanged (the faulting instruction
                    // never legitimately completes).
                    unsafe {
                        save_frame_as_user_context(f, elr, save as *mut Aarch64UserContext);
                        restore_user_and_eret(into as *const Aarch64UserContext);
                    }
                }
                TrapOutcome::Terminate { into } => {
                    // The expected outcome: the faulting thread is dead,
                    // its exception frame abandoned, no save.
                    // SAFETY: `into` is a kernel-owned, 8-byte-aligned
                    // `HAL_USER_CONTEXT_BYTES` blob.
                    unsafe { restore_user_and_eret(into as *const Aarch64UserContext) };
                }
            }
            return;
        }
    }

    trap_diag(ec, elr, far);
    halt_on_unexpected_exception();
}

/// Host (`cargo test`) stub — reached only from the bare-metal
/// `irq_el0_entry`'s `bl common_irq_el0_entry` above, which (being part
/// of a `global_asm!` block) is not itself `#[cfg(target_os = "none")]`-
/// gated at the assembler level — exists purely so the host build
/// fails to LINK (an unresolved `common_irq_el0_entry` symbol) rather
/// than silently miscompiling if this file's own `#[cfg]` gating on the
/// Rust side ever drifted from the assembly's.
#[cfg(not(target_os = "none"))]
#[no_mangle]
extern "C" fn common_irq_el0_entry(_frame: *mut SyncFrame) {}

/// Called from `irq_el0_entry` with a pointer to the saved `SyncFrame`
/// — the timer PPI (or, in principle, any other GIC interrupt) landing
/// while a U-mode thread was running. Dispatches it exactly like the
/// EL1-native IRQ path (`interrupt::dispatch_current_irq` — GIC IAR
/// read, timer callback if it was the timer PPI, EOI), then — ONLY if
/// it WAS the timer PPI and a `TickHandler` is registered — asks the
/// preemptive scheduler what to do next (02-Microkernel-Layer.md §4).
/// Any other INTID (or no registered handler) simply returns: the
/// trampoline's own epilogue resumes the interrupted thread at the SAME
/// `elr` unchanged — an IRQ, unlike `svc`, never "completes" an
/// instruction, so there is nothing to advance past (mirrors
/// hal-riscv64's `common_trap_entry`'s own tick-interrupt `Resume` arm,
/// which likewise does not touch `sepc`).
#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn common_irq_el0_entry(frame: *mut SyncFrame) {
    let elr: u64;
    // SAFETY: reading ELR_EL1 has no preconditions inside an exception
    // handler, which `irq_el0_entry` guarantees this runs inside of.
    unsafe { core::arch::asm!("mrs {0}, elr_el1", out(reg) elr) };

    let intid = crate::interrupt::dispatch_current_irq();
    if intid != crate::interrupt::TIMER_PPI_INTID {
        return;
    }

    // SAFETY: single-core; `TICK_HANDLER` is only written by
    // `set_tick_handler` during boot, before the timer is armed.
    let handler = unsafe { core::ptr::addr_of!(TICK_HANDLER).read() };
    let Some(h) = handler else {
        return;
    };
    match h() {
        TrapOutcome::Resume(_) => {}
        TrapOutcome::SwitchTo { save, into } => {
            // SAFETY: `frame` is the on-stack register file `irq_el0_
            // entry` just saved, valid for this call with no other live
            // reference; `save`/`into` are kernel-owned, 8-byte-aligned
            // `HAL_USER_CONTEXT_BYTES` blobs. Never returns:
            // `restore_user_and_eret` abandons this exception frame's
            // stack and `eret`s into the incoming thread — see its own
            // doc comment for why that is safe.
            let f = unsafe { &mut *frame };
            unsafe {
                save_frame_as_user_context(f, elr, save as *mut Aarch64UserContext);
                restore_user_and_eret(into as *const Aarch64UserContext);
            }
        }
        TrapOutcome::Terminate { into } => {
            // Not the expected outcome for a plain preemption tick (the
            // preempted thread is still perfectly resumable), but the
            // type is shared with the syscall/fault paths, so this arm
            // must exist — same as hal-riscv64's own tick-handler
            // `Terminate` arm.
            // SAFETY: `into` is a kernel-owned, 8-byte-aligned
            // `HAL_USER_CONTEXT_BYTES` blob.
            unsafe { restore_user_and_eret(into as *const Aarch64UserContext) };
        }
    }
}

/// Minimal MMIO dump of an unexpected EL0 exception over QEMU virt's
/// PL011 (0x0900_0000) so a fault is visible instead of a silent hang —
/// same diagnostic scope as hal-riscv64's `trap_diag`.
#[cfg(target_os = "none")]
fn trap_diag(ec: u64, elr: u64, far: u64) {
    const PL011_BASE: u64 = 0x0900_0000;
    const PL011_DR: u64 = 0x000;
    const PL011_FR: u64 = 0x018;
    const PL011_FR_TXFF: u32 = 1 << 5;
    fn putb(b: u8) {
        // SAFETY: fixed, documented QEMU-virt PL011 MMIO base; poll
        // FR.TXFF then write DR — the standard polled-transmit sequence.
        unsafe {
            while (core::ptr::read_volatile((PL011_BASE + PL011_FR) as *const u32)
                & PL011_FR_TXFF)
                != 0
            {}
            core::ptr::write_volatile((PL011_BASE + PL011_DR) as *mut u32, b as u32);
        }
    }
    fn puts(s: &str) {
        for b in s.bytes() {
            putb(b);
        }
    }
    fn puthex(v: u64) {
        puts("0x");
        let mut started = false;
        for i in (0..16).rev() {
            let nib = ((v >> (i * 4)) & 0xF) as u8;
            if nib != 0 || started || i == 0 {
                started = true;
                putb(if nib < 10 { b'0' + nib } else { b'a' + nib - 10 });
            }
        }
    }
    puts("\r\nUNHANDLED EXCEPTION: esr.ec=");
    puthex(ec);
    puts(" elr=");
    puthex(elr);
    puts(" far=");
    puthex(far);
    puts("\r\n");
}

#[cfg(target_os = "none")]
fn halt_on_unexpected_exception() -> ! {
    loop {
        // SAFETY: `wfi` is the standard, side-effect-free halt.
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Serialises an interrupted `SyncFrame` into an `Aarch64UserContext` so
/// it can be `restore_user_and_eret`'d later. `resume_elr` is where the
/// thread should continue — for a suspended `svc`, the caller passes
/// `elr` UNCHANGED: the hardware-saved return address for `SVC` already
/// points past the 4-byte instruction (see `common_sync_entry`'s
/// `Resume` arm doc comment for the bug this fixes). Captures the
/// *live* `SP_EL0`/`TTBR0_EL1`, which for an exception taken from EL0
/// already describe the thread's own stack and address space.
///
/// # Safety
/// `dst` must point at valid, writable `HAL_USER_CONTEXT_BYTES`-sized,
/// 8-byte-aligned storage.
#[cfg(target_os = "none")]
unsafe fn save_frame_as_user_context(
    frame: &SyncFrame,
    resume_elr: u64,
    dst: *mut Aarch64UserContext,
) {
    let (sp_el0, spsr, ttbr0): (u64, u64, u64);
    // SAFETY: reading SP_EL0/SPSR_EL1/TTBR0_EL1 has no preconditions in
    // an exception handler.
    unsafe {
        core::arch::asm!("mrs {0}, sp_el0", out(reg) sp_el0);
        core::arch::asm!("mrs {0}, spsr_el1", out(reg) spsr);
        core::arch::asm!("mrs {0}, ttbr0_el1", out(reg) ttbr0);
    }
    // SAFETY: `dst` is valid writable storage of the matching size /
    // alignment per this function's contract.
    unsafe {
        (*dst).regs = frame.regs;
        (*dst).sp_el0 = sp_el0;
        (*dst).elr_el1 = resume_elr;
        (*dst).spsr_el1 = spsr;
        (*dst).ttbr0_el1 = ttbr0;
    }
}

/// Restores a full `Aarch64UserContext` and `eret`s into EL0. Never
/// returns. Shared by `resume_user` (first entry, from an
/// `init_user_context` blob) and `common_sync_entry`'s process hand-off
/// path (from a blob it just serialised out of an exception frame).
///
/// # Safety
/// `blob` must point at a valid, resumable `Aarch64UserContext` whose
/// `ttbr0_el1` names an address space that maps this core's exception
/// vector table and the identity-mapped low RAM `blob` itself lives in.
/// Interrupts must be masked (true throughout — EL1 exception entry
/// already masks DAIF, same as every other exception here).
#[cfg(target_os = "none")]
unsafe fn restore_user_and_eret(blob: *const Aarch64UserContext) -> ! {
    // SAFETY: contract above. `x30` carries the blob base for the whole
    // sequence: AArch64 has no spare GPR beyond the 31 a full context
    // restores, so — exactly like hal-riscv64's `restore_user_and_sret`
    // uses `t6` and hal-x86_64's `restore_user_and_iretq` uses `r15` —
    // ONE of the restored registers must double as the pointer, loaded
    // from its OWN saved slot dead last (here, `x30`/LR — the highest-
    // numbered GPR, the same "last register in the sequence" choice
    // hal-riscv64 makes with `x31`/`t6`).
    // **Real bug found via QEMU** (this session's P2/device-manager
    // demo — the FIRST thing to ever exercise `resume_user`/this
    // function for aarch64; the original U-mode+syscall milestone only
    // ever used `enter_user`'s own named-register fabrication, never
    // this struct-offset-based restore): these four offsets were
    // originally listed in the WRONG order relative to
    // `Aarch64UserContext`'s actual field layout (`regs: [u64; 31]`
    // ends at offset 248, THEN `sp_el0`, THEN `elr_el1`, THEN
    // `spsr_el1`, THEN `ttbr0_el1` — the comments below had swapped
    // `sp_el0` and `spsr_el1`). Loading `spsr_el1`'s value (a fresh
    // context's is always 0) into `SP_EL0` left every EL0 thread's own
    // stack pointer at 0 the instant it touched its own stack for the
    // first time — confirmed via a genuine `#PF`-equivalent `Data
    // Abort` (`ESR_EL1.EC=0x24`) at `FAR_EL1=0xffff...ffe8`, exactly
    // `0 - 24` in unsigned 64-bit wraparound, matching the Root Task's
    // own stack-relative store at `sp - 24` with `sp` genuinely 0.
    //
    // **A second real issue found via QEMU, FIXED this session**: this
    // function diverges straight into `eret` and never runs `sync_el0_
    // entry`'s own `add sp, sp, #256` epilogue — so the 256+ bytes that
    // trampoline's prologue (plus every enclosing Rust call frame)
    // reserved stayed PERMANENTLY consumed every single time a
    // `SwitchTo`/`Terminate` fired (unlike hal-x86_64, whose hardware
    // TSS.rsp0 mechanism reloads a FIXED SP on every Ring3->Ring0
    // transition regardless of what the previous handler left RSP as —
    // AArch64 has no such automatic reset). Measured leak: 608 bytes
    // per call (confirmed via instrumented QEMU runs, constant across
    // calls) — accumulating, unbounded, across repeated process
    // switches until SP_EL1 ran off the bottom of the boot stack and
    // the CPU executed garbage.
    //
    // Fixed by resetting SP_EL1 to the fixed `__boot_stack_top`
    // baseline right here, mirroring x86_64's TSS.rsp0 semantics:
    // unconditionally safe, since every enclosing frame between here
    // and the original `sync_el0_entry`/cold-boot entry is about to be
    // abandoned by `eret` below regardless (nothing at EL1 needs THIS
    // frame's stack contents again), and the NEXT exception into EL1
    // starts fresh from `sync_el0_entry`'s own `sub sp, sp, #256` off
    // this same baseline, exactly as it did on the very first exception
    // after boot. Addressed via `sym` (compiler-verified, distance-
    // independent `adrp`+`:lo12:`) rather than hand-written `adr` —
    // `_start` hit a real `adr`-range link error addressing this SAME
    // symbol from `boot.S` (see `lib.rs`'s own `_start` doc comment).
    //
    // TWO earlier attempts at an in-place reset (one in `sync_el0_
    // entry`'s own prologue; one right here) each independently broke
    // the cooperative two-process `SwitchTo` round-trip in ways not
    // root-caused at the time. This session's own attempt hit the SAME
    // regression — but root-caused it via bisection (instrumented
    // builds narrowing the hang to a single call, `kernel_main`'s own
    // `hal.now_ns()`) down to REAL, SEPARATE, pre-existing bugs this
    // reset merely exposed rather than caused, at TWO layers: (1)
    // `kernel_main` (`kernel/kernel/src/main.rs`) received `hal:
    // hal_core::HalInterface` BY VALUE (living in `kernel_main`'s OWN
    // stack frame, which never returns) and passed `&hal` down into
    // `kernel_arch_glue::enter`, which stashed that pointer in a static
    // (`G_HAL`) for the life of the system; (2) ONE LAYER DEEPER, this
    // crate's own `hal_arm64_rust_entry` (`lib.rs`) built `Arm64Hal`
    // (holding `cpu`/`timer`/etc.) as a plain local too, and `build_
    // interface` baked raw pointers into ITS fields (`HalInterface`'s
    // opaque `cpu_state`/`timer_state`) — copying the `HalInterface`
    // struct by value into `kernel_main` does not change what those
    // pointers point AT. Both were silently safe under the ORIGINAL
    // leaking design (SP only ever descended, so stack memory above the
    // current frame was never reused) and under riscv64/x86_64 (same
    // shared `kernel_main`/pattern, but neither resets its own kernel-
    // mode SP the way this fix does for aarch64) — but once aarch64's
    // OWN SP_EL1 resets to a fixed top on every switch, LATER exception
    // handling reuses and overwrites the exact memory this data lived
    // in, corrupting it the moment a deep-enough call chain reached it
    // (confirmed via bisection: `G_HAL`'s own stored POINTER survived,
    // since it is itself a separate, genuinely-static 8-byte slot, but
    // dereferencing THROUGH it — `hal.now_ns()`'s indirect call via a
    // function-pointer field — silently jumped to garbage; fixing layer
    // (1) alone then surfaced layer (2) as a "divide by zero" panic in
    // `Timer::now_ns` reading a clobbered `frequency_hz`). Fixed at
    // both sources: `hal` is moved into `.bss` static storage in
    // `kernel_main` before its first use, and `Arm64Hal` likewise in
    // `hal_arm64_rust_entry` before `build_interface` ever borrows from
    // it — both mirror `KernelState::init_global`'s own "no stack
    // temporary" rationale, making this reset safe regardless of what
    // any architecture's own SP does afterward. (`boot_info: &BootInfo`
    // is NOT similarly hazardous — `enter` only reads through it
    // locally, never storing the pointer past its own call.)
    unsafe {
        core::arch::asm!(
            "ldr x9, [x30, #248]",   // sp_el0 (offset 31*8 = 248)
            "msr sp_el0, x9",
            "ldr x9, [x30, #256]",   // elr_el1
            "msr elr_el1, x9",
            "ldr x9, [x30, #264]",   // spsr_el1
            "msr spsr_el1, x9",
            "ldr x9, [x30, #272]",   // ttbr0_el1
            "msr ttbr0_el1, x9",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            // Reset SP_EL1 to the fixed boot-stack baseline — see this
            // function's own doc comment above for the full story.
            // `x9` is reused as scratch (free at this point — its last
            // use above, the ttbr0_el1 load, is already committed via
            // `msr`) and clobbered again immediately below by the `ldp
            // x8, x9, [x30, #64]` GPR restore, so nothing here leaks
            // into the resumed thread's own register state.
            "adrp x9, {boot_stack_top}",
            "add x9, x9, :lo12:{boot_stack_top}",
            "mov sp, x9",
            "ldp x0, x1,   [x30, #0]",
            "ldp x2, x3,   [x30, #16]",
            "ldp x4, x5,   [x30, #32]",
            "ldp x6, x7,   [x30, #48]",
            "ldp x8, x9,   [x30, #64]",
            "ldp x10, x11, [x30, #80]",
            "ldp x12, x13, [x30, #96]",
            "ldp x14, x15, [x30, #112]",
            "ldp x16, x17, [x30, #128]",
            "ldp x18, x19, [x30, #144]",
            "ldp x20, x21, [x30, #160]",
            "ldp x22, x23, [x30, #176]",
            "ldp x24, x25, [x30, #192]",
            "ldp x26, x27, [x30, #208]",
            "ldp x28, x29, [x30, #224]",
            "ldr x30,      [x30, #240]",
            "eret",
            in("x30") blob,
            boot_stack_top = sym crate::__boot_stack_top,
            options(noreturn),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids_with(isar0: u64, isar1: u64, pfr0: u64) -> IdRegisters {
        IdRegisters { id_aa64isar0: isar0, id_aa64isar1: isar1, id_aa64pfr0: pfr0, mpidr: 0 }
    }

    #[test]
    fn detects_neon_baseline() {
        let ids = ids_with(0, 0, 0); // AdvSIMD field 0b0000 = present
        let flags = detect_feature_flags(&ids);
        assert!(flags.contains(CpuFeatureFlags::SIMD_128));
    }

    #[test]
    fn detects_sve_when_present() {
        let ids = ids_with(0, 0, 1u64 << 32); // SVE field = 1
        let flags = detect_feature_flags(&ids);
        assert!(flags.contains(CpuFeatureFlags::SCALABLE_VECTOR));
    }

    #[test]
    fn detects_aes_and_sha() {
        let ids = ids_with((1 << 4) | (1 << 8), 0, 0); // AES=1, SHA1=1
        let flags = detect_feature_flags(&ids);
        assert!(flags.contains(CpuFeatureFlags::CRYPTO_AES));
        assert!(flags.contains(CpuFeatureFlags::CRYPTO_SHA));
    }

    #[test]
    fn detects_lse_atomics() {
        let ids = ids_with(2 << 20, 0, 0); // Atomic field = 2
        let flags = detect_feature_flags(&ids);
        assert!(flags.contains(CpuFeatureFlags::WIDE_ATOMICS));
    }

    #[test]
    fn detects_el2_as_virtualization() {
        let ids = ids_with(0, 0, 1 << 8); // EL2 field != 0
        let flags = detect_feature_flags(&ids);
        assert!(flags.contains(CpuFeatureFlags::VIRTUALIZATION));
    }

    #[test]
    fn core_id_reads_mpidr_aff0() {
        let ids = IdRegisters { mpidr: 3, ..IdRegisters::default() };
        assert_eq!(read_core_id(&ids), 3);
    }

    #[test]
    fn arm64_context_matches_declared_size() {
        assert_eq!(size_of::<Arm64Context>(), ARM64_CONTEXT_BYTES);
    }
}
// ============================================================================
// AArch64 page-table helpers
//
// Bare-metal only. `map_ram_identity` / `activate_address_space` (above) plus
// `map_range` here are the whole page-table surface the microkernel drives
// through `hal_core::HalInterface` — the AArch64 counterpart of
// hal-riscv64's `riscv_sv39` module / hal-x86_64's `x86_64_paging` module.
//
// Deliberately mirrors `riscv_sv39` almost line-for-line: with
// `activate_address_space` configuring TCR_EL1.T0SZ=25 (see that method's
// own doc comment), a 39-bit AArch64 VA splits into three 9-bit indices
// (L1/L2/L3) + a 12-bit page offset at the SAME bit positions Sv39 uses,
// and — unlike hal-x86_64's PML4/PDPT — table descriptors here impose NO
// additional permission restriction of their own (their optional
// APTable/PXNTable/UXNTable override bits are left at 0 throughout this
// module), so permission is decided purely at the LEAF, exactly like
// Sv39 and unlike x86_64's every-level AND. This is also why `root_frame`
// needs only ONE page here (an L1 table), never x86_64's two-page
// PML4+PDPT pair.
// ============================================================================
#[cfg(target_os = "none")]
pub(crate) mod aarch64_paging {
    /// Descriptor valid bit (bit 0), common to block, table, and page
    /// descriptors alike.
    pub const VALID: u64 = 1 << 0;
    /// Bit 1: 1 = table descriptor (L1/L2, pointing at the next level) or
    /// page descriptor (L3, a leaf) — 0 = block descriptor (a 1 GiB/2 MiB
    /// leaf at L1/L2). The SAME bit position means a leaf-vs-table check
    /// at L1/L2 and a valid-page check at L3 are the same test, exactly
    /// like Sv39's `R|W|X != 0` distinguishing a leaf PTE from a pointer
    /// to the next table.
    pub const TABLE_OR_PAGE: u64 = 1 << 1;
    /// AttrIndx = 0 (MAIR_EL1 index 0, Normal Write-Back — see
    /// `activate_address_space`'s MAIR_EL1 setup).
    pub const ATTR_NORMAL: u64 = 0 << 2;
    /// AP[1] (bit 6): 1 = accessible at EL0 too, 0 = EL1-only. AArch64's
    /// equivalent of Sv39's leaf-only `U` bit / x86_64's `USER` bit —
    /// and, like Sv39 (unlike x86_64), ONLY the leaf's own bit matters;
    /// see this module's own doc comment.
    pub const AP_USER: u64 = 1 << 6;
    /// AP[2] (bit 7): 1 = read-only at every EL this descriptor is
    /// accessible from, 0 = read/write. There is no separate "readable"
    /// bit on AArch64 either (same as x86_64's `PRESENT`-alone-means-
    /// readable / Sv39's leaf `R` bit always being set here) — a valid
    /// descriptor is always readable.
    pub const AP_RO: u64 = 1 << 7;
    /// SH[1:0] = 0b11 (inner shareable) — matches the SH0 field
    /// `activate_address_space` programs into TCR_EL1.
    pub const SH_INNER: u64 = 0b11 << 8;
    /// Access flag (bit 10) — pre-set so no hardware Access-Flag fault is
    /// taken, same rationale as Sv39's pre-set `A` bit.
    pub const AF: u64 = 1 << 10;
    /// Privileged execute-never (bit 53): blocks EL1 from executing this
    /// page. AArch64's execute-permission model is a genuine third
    /// architectural point (beyond Sv39's single leaf-only `X` and
    /// x86_64's single every-level-AND `NO_EXECUTE`): PXN and UXN are
    /// SEPARATE bits, so a page can be executable at EXACTLY ONE
    /// privilege level in a single descriptor — `map_range` uses this to
    /// set PXN on every user-executable page (the kernel must never
    /// execute Root Task code, even by mistake) and UXN on every
    /// kernel-executable one, something neither Sv39 nor x86_64's single
    /// execute bit can express in one write.
    pub const PXN: u64 = 1 << 53;
    /// User (EL0) execute-never (bit 54) — see `PXN`'s doc comment.
    pub const UXN: u64 = 1 << 54;
    /// Output/next-level-table address mask, bits 47:12 (this project's
    /// IPS = 36-bit choice — see `activate_address_space` — comfortably
    /// fits within this 48-bit-capable field).
    const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    /// Zeroes `root_frame` (the L1 table) and installs `bytes_gib` 1 GiB
    /// BLOCK identity leaves (VA == PA) into it — L1 index `gib` covers
    /// exactly VA range `[gib * 1 GiB, (gib + 1) * 1 GiB)`, the same "L1
    /// index == GiB number" property Sv39's root has. Always
    /// readable/writable/executable (no separate control here — matches
    /// hal-riscv64's `map_ram_identity`, which always sets `X`, and
    /// hal-x86_64's, whose leaf flags never include `NO_EXECUTE`); if
    /// `user_accessible`, `AP_USER` is set too.
    ///
    /// # Preconditions
    /// `root_frame` is a page-aligned, writable physical frame, directly
    /// addressable via the CURRENTLY active mapping (MMU may be on or
    /// off — this project's boot.S disables it, so it is normally off
    /// the first time this runs); single core; called before
    /// `activate_address_space` switches TTBR0_EL1 to this table.
    pub fn map_ram_identity(root_frame: usize, bytes_gib: usize, user_accessible: bool) {
        let root = root_frame as *mut u64;
        // SAFETY: precondition above.
        unsafe {
            for i in 0..512 {
                root.add(i).write_volatile(0);
            }
            let mut leaf = VALID | ATTR_NORMAL | SH_INNER | AF; // bit1=0: block descriptor
            if user_accessible {
                leaf |= AP_USER;
            }
            for gib in 0..bytes_gib.min(512) {
                let pa = (gib as u64) << 30; // gib * 1 GiB
                root.add(gib).write_volatile((pa & ADDR_MASK) | leaf);
            }
        }
    }

    /// Maps `[vaddr, vaddr + len)` -> `[paddr, ...)` at 4 KiB granularity,
    /// descending from the L1 table at `root_frame` through L2 to L3,
    /// allocating any missing L2/L3 tables from the pre-zeroed pool at
    /// `[pool_base, pool_base + pool_len * 4096)`. `perm_bits` is
    /// `READ=1, WRITE=2, EXECUTE=4, USER=8` (`READ` is a no-op here too —
    /// see `AP_RO`'s doc comment).
    ///
    /// Returns the number of pool frames consumed, or `u32::MAX` on
    /// error (misaligned args, a block-descriptor leaf already covering
    /// the range, or the pool running out).
    ///
    /// # Preconditions
    /// `map_ram_identity` has already run on this `root_frame`; the pool
    /// frames are zeroed; single core; every physical address here
    /// (root, pool, leaves) is directly addressable via the CURRENTLY
    /// active mapping.
    pub fn map_range(
        root_frame: usize,
        vaddr: usize,
        paddr: usize,
        len: usize,
        perm_bits: usize,
        pool_base: usize,
        pool_len: usize,
    ) -> u32 {
        if root_frame == 0 || len == 0 || ((vaddr | paddr | len) & 0xFFF) != 0 {
            return u32::MAX;
        }
        let mut leaf = VALID | TABLE_OR_PAGE | ATTR_NORMAL | SH_INNER | AF;
        if perm_bits & 8 != 0 {
            leaf |= AP_USER;
        }
        if perm_bits & 2 == 0 {
            leaf |= AP_RO;
        }
        if perm_bits & 4 == 0 {
            // Not executable at all: block execution at BOTH privilege
            // levels — the conservative choice, matching x86_64's single
            // `NO_EXECUTE` applied uniformly.
            leaf |= UXN | PXN;
        } else if perm_bits & 8 != 0 {
            leaf |= PXN; // user-executable: EL0 only, never EL1 — see PXN's doc comment.
        } else {
            leaf |= UXN; // kernel-executable: EL1 only, never EL0.
        }

        let mut used = 0usize;
        let pages = len / 4096;
        for p in 0..pages {
            let va = vaddr + p * 4096;
            let pa = paddr + p * 4096;
            let (l1i, l2i, l3i) =
                ((va >> 30) & 0x1FF, (va >> 21) & 0x1FF, (va >> 12) & 0x1FF);

            // Descend / build L2.
            // SAFETY: `root_frame` is a valid, page-aligned L1 table per
            // this function's precondition.
            let l2 = unsafe {
                let slot = (root_frame as *mut u64).add(l1i);
                let e = slot.read_volatile();
                if e & VALID == 0 {
                    if used >= pool_len {
                        return u32::MAX;
                    }
                    let t = pool_base + used * 4096;
                    used += 1;
                    slot.write_volatile((t as u64 & ADDR_MASK) | VALID | TABLE_OR_PAGE);
                    t
                } else if e & TABLE_OR_PAGE == 0 {
                    return u32::MAX; // a 1 GiB block leaf already covers this VA
                } else {
                    (e & ADDR_MASK) as usize
                }
            };

            // Descend / build L3.
            // SAFETY: `l2` is a valid page-table frame just resolved above.
            let l3 = unsafe {
                let slot = (l2 as *mut u64).add(l2i);
                let e = slot.read_volatile();
                if e & VALID == 0 {
                    if used >= pool_len {
                        return u32::MAX;
                    }
                    let t = pool_base + used * 4096;
                    used += 1;
                    slot.write_volatile((t as u64 & ADDR_MASK) | VALID | TABLE_OR_PAGE);
                    t
                } else if e & TABLE_OR_PAGE == 0 {
                    return u32::MAX; // a 2 MiB block leaf already covers this VA
                } else {
                    (e & ADDR_MASK) as usize
                }
            };

            // Install the 4 KiB leaf (a page descriptor: bit1=1, same as
            // a table descriptor's own bit1 — L3 is always the last
            // level, so there is no ambiguity).
            // SAFETY: `l3` is a valid page-table frame just resolved above.
            unsafe {
                (l3 as *mut u64).add(l3i).write_volatile((pa as u64 & ADDR_MASK) | leaf);
            }
        }
        used as u32
    }
}