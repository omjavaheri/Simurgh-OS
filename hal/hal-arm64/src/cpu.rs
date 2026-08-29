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

    // --- Lower EL, AArch64 (offsets 0x400-0x5FF): reserved for future
    // EL0 user-space support (layer 3+, not yet implemented).
    .align 7
    b generic_trap_halt
    .align 7
    b generic_trap_halt
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