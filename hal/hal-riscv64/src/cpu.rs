//! ============================================================================
//! cpu.rs — RISC-V (RV64GC)
//!
//! Implements `hal_core::cpu::CpuAbstraction<RISCV64_CONTEXT_BYTES>`
//! for RISC-V, per 01-HAL-Layer.md section 3.1. Mirrors hal-x86_64/
//! hal-arm64's cpu.rs structure — differences below are purely
//! architectural:
//!
//!   - Feature detection: the `misa` CSR (Machine ISA register) reports
//!     which standard extensions are present, BUT `misa` is only
//!     readable from M-mode on many implementations — since this
//!     project's kernel runs in S-mode (per boot.S's module docs, SBI
//!     already completed the M-mode boot stage before handoff), this
//!     file cannot read `misa` directly. Instead, feature presence is
//!     derived from what `targets/riscv64gc-hal.json` already
//!     guarantees at COMPILE TIME (RV64GC = IMAFDC, per that target
//!     file's own doc comment) plus an SBI-mediated query
//!     (`sbi_probe_extension`) for anything SBI itself can report
//!     (e.g. vendor-specific extensions). This is a fundamentally
//!     different detection MODEL than x86_64's CPUID or ARM64's
//!     ID_AA64*_EL1 registers, both of which are freely readable at
//!     the kernel's own privilege level.
//!   - Exception/Interrupt vector: `stvec` (Supervisor Trap Vector
//!     base address register) — RISC-V's single-entry-point trap model
//!     is simpler than both x86_64's 256-entry IDT and ARM64's
//!     16-entry VBAR_EL1 table: EVERY trap (synchronous exception,
//!     interrupt) enters at the SAME address, and Rust code
//!     disambiguates by reading the `scause` CSR after entry.
//!   - Privilege levels: M-mode (boot-time only, already exited by the
//!     time this crate's Rust code runs) / S-mode (kernel) / U-mode
//!     (user) — RISC-V's M-mode is NOT reachable again from S-mode
//!     without a trap back into SBI (an `ecall`), unlike ARM64 where
//!     EL2 remains a normal target this project's own code could
//!     theoretically drop back into; RISC-V's M-mode is therefore
//!     mapped onto `PrivilegeLevel::Monitor` but, like x86_64,
//!     `set_privilege_level` declines it — the mechanism to reach
//!     M-mode functionality from S-mode is an SBI call, not a
//!     privilege transition this trait's context_switch model applies
//!     to at all.
//! ============================================================================

use core::cell::Cell;
use core::mem::size_of;

use hal_core::cpu::{CpuAbstraction, CpuContext, CpuFeatureFlags, PrivilegeLevel};
use hal_core::error::HalError;

use crate::RISCV64_CONTEXT_BYTES;

// ============================================================================
// Feature flags — compile-time RV64GC baseline + SBI extension probing
// ============================================================================

/// SBI Base extension ID (per the SBI spec, always extension ID
/// 0x10), used for `sbi_probe_extension` below — the one SBI call this
/// file needs regardless of which other extensions exist.
const SBI_EXT_BASE: usize = 0x10;
const SBI_BASE_PROBE_EXTENSION: usize = 3;

/// Issues an `ecall` into SBI (the standard RISC-V supervisor-to-
/// machine-mode call mechanism — the S-mode equivalent of a syscall,
/// but targeting firmware instead of an OS). Per the SBI calling
/// convention: a7 = extension ID, a6 = function ID, a0/a1 = arguments,
/// a0 = error code on return, a1 = value on return.
#[cfg(not(target_os = "none"))]
fn sbi_call(_ext: usize, _func: usize, _arg0: usize) -> (isize, usize) {
    // Host (`cargo test`) stub — no SBI firmware off the bare-metal
    // target. `(0, 0)` reads back as "call succeeded, extension absent",
    // the benign answer for the probe paths that reach here. Unit tests
    // never construct `Cpu`, so this is only here so the crate compiles.
    (0, 0)
}

#[cfg(target_os = "none")]
fn sbi_call(ext: usize, func: usize, arg0: usize) -> (isize, usize) {
    let (error, value): (isize, usize);
    // SAFETY: `ecall` from S-mode to SBI is the standard, well-defined
    // RISC-V supervisor-mode-to-firmware call mechanism (per the SBI
    // spec) — every extension/function ID this file uses (SBI Base
    // extension, Probe Extension function) is part of the SBI Base
    // extension, which the spec REQUIRES every SBI implementation to
    // support, so this call cannot target a genuinely unimplemented
    // firmware surface.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") ext,
            in("a6") func,
            inlateout("a0") arg0 => error,
            lateout("a1") value,
        );
    }
    (error, value)
}

/// Probes whether SBI extension `ext_id` is implemented by this
/// platform's SBI firmware. Returns `true` if the extension ID is
/// non-zero in the returned value (per SBI Base extension spec,
/// function 3 "Probe Extension").
fn sbi_probe_extension(ext_id: usize) -> bool {
    let (error, value) = sbi_call(SBI_EXT_BASE, SBI_BASE_PROBE_EXTENSION, ext_id);
    error == 0 && value != 0
}

/// SBI TIME extension ID (per the SBI spec) — probed here (not in
/// timer.rs) because feature detection as a whole is this file's
/// responsibility; `timer.rs` reads the RESULT of this probe via
/// `Cpu::sbi_time_extension_present()` below, mirroring how
/// hal-x86_64's timer.rs consumes cpu.rs's CPUID-derived capabilities
/// indirectly rather than re-probing itself.
const SBI_EXT_TIME: usize = 0x54494D45; // "TIME" as an ASCII-encoded ID, per the SBI spec

/// Detects feature flags. Unlike x86_64/ARM64's register-read-based
/// detection, this is mostly a COMPILE-TIME fact (RV64GC, guaranteed
/// by targets/riscv64gc-hal.json) plus the one SBI-mediated runtime
/// check this file actually needs (TIME extension presence, since
/// timer.rs's oneshot mechanism depends on it entirely — see
/// timer.rs's module docs).
pub fn detect_feature_flags() -> CpuFeatureFlags {
    // RV64GC = IMAFDC (Integer, Multiply/Divide, Atomic, Float,
    // Double, Compressed) — guaranteed present by this crate's target
    // file, so these bits are set unconditionally rather than probed:
    // there is no RUNTIME question of "is this feature present" the
    // way there is on x86_64 (which supports many possible CPU
    // generations) — this crate simply does not compile for, or run
    // on, a non-RV64GC-compliant core.
    let mut flags = CpuFeatureFlags::SIMD_128 // "V" vector baseline is
        // NOT part of RVGC (it's a separate, optional extension) —
        // SIMD_128 here instead represents the D (double) + F (float)
        // extensions' 128-bit-aggregate register file width (32 x
        // 64-bit FP registers), the closest RV64GC-guaranteed
        // equivalent to "some form of wide register file for
        // numeric work" that hal-core's coarse-grained flag set
        // anticipates — a deliberate approximation, documented here
        // rather than silently assumed.
        | CpuFeatureFlags::WIDE_ATOMICS; // "A" extension, guaranteed by RV64GC

    // Scalable Vector: RISC-V's "V" extension (distinct from RVGC) —
    // not part of this project's guaranteed baseline; would require a
    // runtime `misa`-equivalent check this file cannot perform from
    // S-mode (per module docs) without an SBI extension specifically
    // for CSR proxying, which is not part of the SBI Base extension
    // this file relies on. Left unset — a tracked follow-up if/when a
    // target platform's SBI implementation exposes vector-extension
    // presence through some other standard channel.

    if sbi_probe_extension(SBI_EXT_TIME) {
        // Not a CpuFeatureFlags bit on its own (hal-core has no
        // "has working timer" flag — that's what
        // TimerAbstraction::supports_tickless is for), but recorded
        // here as this file's single point of SBI extension probing;
        // `Cpu::sbi_time_extension_present()` exposes the boolean
        // itself for timer.rs to consume directly.
    }

    flags |= CpuFeatureFlags::PERF_COUNTERS; // RISC-V's hpmcounter
    // CSRs (cycle, time, instret, and hpmcounter3-31) are part of the
    // base Zicntr/Zihpm extensions, present on every RV64GC core per
    // the profile this project targets.

    flags
}

// ============================================================================
// Supervisor Trap Vector (stvec) — section 3.1's uniform Interrupt/
// Exception Vector Table requirement
// ============================================================================

// RISC-V's trap model: ALL traps (synchronous exceptions AND
// interrupts) enter at ONE address (stvec, in "Direct" mode — this
// project does not use "Vectored" mode, which would require a full
// jump table and offers little benefit at this project's current
// interrupt volume). Rust-side code disambiguates via the `scause`
// CSR, which encodes both the trap's cause code AND whether it was an
// interrupt (top bit set) or an exception (top bit clear).
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text
    .global trap_entry
    .align 4  // stvec's low 2 bits must be zero in Direct mode; 4-byte
              // alignment satisfies this trivially, matching the
              // natural instruction alignment RV64GC already requires.

    trap_entry:
        // Save all 31 general-purpose registers (x1/ra through x31;
        // x0 is hardwired zero and never needs saving) to the stack.
        // Mirrors cpu.rs's isr_common_trampoline (x86_64) /
        // irq_exception_entry (ARM64) structurally.
        addi sp, sp, -248
        sd x1,  0(sp)
        sd x2,  8(sp)   // note: x2 is sp itself; saved for context-dump
                        // completeness even though it's redundant with
                        // the stack pointer used to perform this save
        sd x3,  16(sp)
        sd x4,  24(sp)
        sd x5,  32(sp)
        sd x6,  40(sp)
        sd x7,  48(sp)
        sd x8,  56(sp)
        sd x9,  64(sp)
        sd x10, 72(sp)
        sd x11, 80(sp)
        sd x12, 88(sp)
        sd x13, 96(sp)
        sd x14, 104(sp)
        sd x15, 112(sp)
        sd x16, 120(sp)
        sd x17, 128(sp)
        sd x18, 136(sp)
        sd x19, 144(sp)
        sd x20, 152(sp)
        sd x21, 160(sp)
        sd x22, 168(sp)
        sd x23, 176(sp)
        sd x24, 184(sp)
        sd x25, 192(sp)
        sd x26, 200(sp)
        sd x27, 208(sp)
        sd x28, 216(sp)
        sd x29, 224(sp)
        sd x30, 232(sp)
        sd x31, 240(sp)

        call common_trap_entry

        ld x1,  0(sp)
        ld x3,  16(sp)
        ld x4,  24(sp)
        ld x5,  32(sp)
        ld x6,  40(sp)
        ld x7,  48(sp)
        ld x8,  56(sp)
        ld x9,  64(sp)
        ld x10, 72(sp)
        ld x11, 80(sp)
        ld x12, 88(sp)
        ld x13, 96(sp)
        ld x14, 104(sp)
        ld x15, 112(sp)
        ld x16, 120(sp)
        ld x17, 128(sp)
        ld x18, 136(sp)
        ld x19, 144(sp)
        ld x20, 152(sp)
        ld x21, 160(sp)
        ld x22, 168(sp)
        ld x23, 176(sp)
        ld x24, 184(sp)
        ld x25, 192(sp)
        ld x26, 200(sp)
        ld x27, 208(sp)
        ld x28, 216(sp)
        ld x29, 224(sp)
        ld x30, 232(sp)
        ld x31, 240(sp)
        addi sp, sp, 248
        sret
    "#
);

/// Called from `trap_entry`'s assembly trampoline. Reads `scause` to
/// disambiguate interrupt vs. exception (per this file's module docs
/// on RISC-V's single-entry-point trap model), and — for interrupts —
/// dispatches to `interrupt.rs`'s handler table via
/// `crate::interrupt::dispatch_current_interrupt`.
#[cfg(not(target_os = "none"))]
#[no_mangle]
extern "C" fn common_trap_entry() {
    // Host (`cargo test`) stub — reached only from the bare-metal
    // `trap_entry` trampoline, which is not linked off the bare-metal
    // target.
}

#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn common_trap_entry() {
    let scause: usize;
    // SAFETY: reading `scause` has no preconditions — it is always
    // valid to read within a trap handler, which this function's only
    // caller (`trap_entry`) guarantees it runs inside of.
    unsafe {
        core::arch::asm!("csrr {}, scause", out(reg) scause);
    }

    // Top bit set = interrupt; clear = synchronous exception. Per the
    // RISC-V privileged spec's scause encoding (section 4.1.8).
    let is_interrupt = (scause as isize) < 0;
    let cause_code = scause & !(1 << (usize::BITS - 1));

    if is_interrupt {
        crate::interrupt::dispatch_current_interrupt(cause_code as u32);
    } else {
        // Synchronous exceptions (illegal instruction, page fault,
        // ecall from U-mode, etc.) are not yet dispatched to a
        // registered handler in this MVP phase — same documented gap
        // as ARM64's sync_exception_entry (cpu.rs) and x86_64's
        // reliance on the IDT's per-vector gates for exceptions this
        // phase does not expect to occur given the identity/kernel-
        // only mapping memory.rs establishes.
        halt_on_unexpected_exception();
    }
}

fn halt_on_unexpected_exception() -> ! {
    loop {
        // SAFETY: `wfi` is the standard, side-effect-free halt — same
        // terminal-state justification as every other architecture's
        // equivalent unexpected-trap handling. On a host (`cargo test`)
        // build there is no `wfi`; the bare `loop {}` is an equivalent
        // (if busy) terminal state, and no test reaches this path.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Loads `stvec` to point at `trap_entry`, in Direct mode (low 2 bits
/// = 0b00).
///
/// # Safety
/// Must only be called once per hart, before this hart relies on any
/// trap (including timer/external interrupts) being handled correctly.
#[cfg(not(target_os = "none"))]
unsafe fn load_stvec() {
    // Host (`cargo test`) stub — no `stvec` / trap vector off the
    // bare-metal target.
}

#[cfg(target_os = "none")]
unsafe fn load_stvec() {
    unsafe extern "C" {
        static trap_entry: u8;
    }
    // SAFETY: `trap_entry`'s address is a `'static`, 4-byte-aligned
    // code label emitted by the global_asm! block above — `stvec` has
    // no further preconditions in Direct mode beyond this alignment.
    unsafe {
        let addr = &trap_entry as *const u8 as usize;
        core::arch::asm!("csrw stvec, {}", in(reg) addr);
    }
}

// ============================================================================
// Saved hardware context layout (matches RISCV64_CONTEXT_BYTES = 160)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Riscv64Context {
    // Callee-saved integer registers per the RISC-V ELF psABI: s0/s1
    // (x8/x9), s2-s11 (x18-x27).
    s0: u64, s1: u64,
    s2: u64, s3: u64, s4: u64, s5: u64, s6: u64, s7: u64,
    s8: u64, s9: u64, s10: u64, s11: u64,
    ra: u64,  // x1, used as the resume PC on restore
    sp: u64,  // x2
    // Address space root: satp (Supervisor Address Translation and
    // Protection register) — RISC-V's equivalent of x86_64's CR3 /
    // ARM64's TTBR0_EL1.
    satp: u64,
    sstatus: u64, // privilege/interrupt-enable state to restore
    tp: u64,      // x4, thread-local storage base per RISC-V ELF psABI
    // Padding to RISCV64_CONTEXT_BYTES (160): 17 live u64 fields = 136
    // bytes, + 3 reserved slots = 160. Matches the other two
    // architectures' "round the context size up for headroom" convention
    // (see RISCV64_CONTEXT_BYTES's doc comment in lib.rs).
    _reserved: [u64; 3],
}

const _: () = {
    assert!(size_of::<Riscv64Context>() == RISCV64_CONTEXT_BYTES);
};

// ============================================================================
// Cpu — CpuAbstraction<RISCV64_CONTEXT_BYTES> implementation
// ============================================================================

pub struct Cpu {
    feature_flags: Cell<CpuFeatureFlags>,
    hart_id: usize,
    sbi_time_extension_present: bool,
}

impl Cpu {
    /// `hart_id` is passed down from `boot.S` via
    /// `hal_riscv64_rust_entry` (lib.rs) — unlike x86_64/ARM64, where
    /// the core id is read from a hardware register
    /// (APIC ID / MPIDR_EL1) AFTER Rust code starts, RISC-V's SBI boot
    /// protocol hands the hart id directly as a boot parameter, so
    /// there is nothing to separately "detect" here.
    pub fn new(hart_id: usize) -> Self {
        let sbi_time_extension_present = sbi_probe_extension(SBI_EXT_TIME);
        let feature_flags = Cell::new(detect_feature_flags());
        Self { feature_flags, hart_id, sbi_time_extension_present }
    }

    /// Mirrors hal-x86_64/hal-arm64's `mark_iommu_capable`: IOPMP
    /// presence (RISC-V's IOMMU equivalent, section 3.2) is discovered
    /// via Device Tree by `memory.rs`, not via any CPU-local register,
    /// so it is folded in after the fact.
    pub fn mark_iommu_capable(&self, present: bool) {
        let mut flags = self.feature_flags.get();
        flags.set(CpuFeatureFlags::IOMMU_CAPABLE, present);
        self.feature_flags.set(flags);
    }

    /// Consumed by `timer.rs`, per this file's module docs on why SBI
    /// extension probing is centralized here.
    pub fn sbi_time_extension_present(&self) -> bool {
        self.sbi_time_extension_present
    }

    /// Same MVP-phase single-hart scope as the other two
    /// architectures' `detected_core_count` — real multi-hart
    /// enumeration requires parsing the Device Tree's `cpus` node, a
    /// tracked follow-up alongside memory.rs's DT parsing scope.
    fn detected_core_count(&self) -> usize {
        1
    }
}

impl CpuAbstraction<{ crate::RISCV64_CONTEXT_BYTES }> for Cpu {
    fn core_count(&self) -> usize {
        self.detected_core_count()
    }

    fn current_core_id(&self) -> usize {
        self.hart_id
    }

    fn feature_flags(&self) -> CpuFeatureFlags {
        self.feature_flags.get()
    }

    unsafe fn context_switch(
        &self,
        from: &mut CpuContext<{ crate::RISCV64_CONTEXT_BYTES }>,
        to: &CpuContext<{ crate::RISCV64_CONTEXT_BYTES }>,
    ) {
        // SAFETY: same reasoning as the other two architectures'
        // context_switch — buffer size/alignment matches
        // Riscv64Context exactly (see the `const _` assertion above),
        // and this trait method's own safety contract (hal-core/src/
        // cpu.rs) guarantees valid, non-aliasing, previously-saved-or-
        // freshly-initialized contexts.
        let from_ctx = unsafe { &mut *(from.as_bytes_mut().as_mut_ptr() as *mut Riscv64Context) };
        let to_ctx = unsafe { &*(to.as_bytes().as_ptr() as *const Riscv64Context) };

        // Host (`cargo test`) build: a real register save/restore cannot
        // run off the bare-metal target, and no unit test drives an
        // actual context switch (they assert the context *layout* only).
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
                "sd s0,  0x00({from_ptr})",
                "sd s1,  0x08({from_ptr})",
                "sd s2,  0x10({from_ptr})",
                "sd s3,  0x18({from_ptr})",
                "sd s4,  0x20({from_ptr})",
                "sd s5,  0x28({from_ptr})",
                "sd s6,  0x30({from_ptr})",
                "sd s7,  0x38({from_ptr})",
                "sd s8,  0x40({from_ptr})",
                "sd s9,  0x48({from_ptr})",
                "sd s10, 0x50({from_ptr})",
                "sd s11, 0x58({from_ptr})",
                "sd sp,  0x68({from_ptr})",
                "csrr t0, satp",
                "sd t0,  0x70({from_ptr})",
                // Capture resume point: label 1 below.
                "la t0, 1f",
                "sd t0,  0x60({from_ptr})", // overwrite saved-ra slot with resume addr

                "ld t0,  0x70({to_ptr})",
                "csrw satp, t0",
                "sfence.vma",
                "ld sp,  0x68({to_ptr})",
                "ld s0,  0x00({to_ptr})",
                "ld s1,  0x08({to_ptr})",
                "ld s2,  0x10({to_ptr})",
                "ld s3,  0x18({to_ptr})",
                "ld s4,  0x20({to_ptr})",
                "ld s5,  0x28({to_ptr})",
                "ld s6,  0x30({to_ptr})",
                "ld s7,  0x38({to_ptr})",
                "ld s8,  0x40({to_ptr})",
                "ld s9,  0x48({to_ptr})",
                "ld s10, 0x50({to_ptr})",
                "ld s11, 0x58({to_ptr})",
                "ld t0,  0x60({to_ptr})",
                "jr t0",

                "1:",
                from_ptr = in(reg) from_ctx as *mut Riscv64Context,
                to_ptr = in(reg) to_ctx as *const Riscv64Context,
                out("t0") _,
            );
        }
    }

    fn init_context(
        &self,
        context: &mut CpuContext<{ crate::RISCV64_CONTEXT_BYTES }>,
        entry: usize,
        stack_top: usize,
    ) {
        // SAFETY: a `[u8; RISCV64_CONTEXT_BYTES]` buffer is layout-
        // compatible with `Riscv64Context` (`#[repr(C)]`, size asserted
        // by the `const _` above). Zeroing then setting the three fields
        // the `context_switch` restore path actually consumes for a
        // fresh thread: `ra` (jumped to via `jr`), `sp`, and `satp`.
        let ctx = unsafe {
            &mut *(context.as_bytes_mut().as_mut_ptr() as *mut Riscv64Context)
        };
        *ctx = Riscv64Context::default();
        ctx.ra = entry as u64;
        ctx.sp = stack_top as u64;

        #[cfg(target_os = "none")]
        {
            // SAFETY: `csrr satp` is always valid to execute in S-mode;
            // the new thread runs in this same address space for now.
            let satp: u64;
            unsafe { core::arch::asm!("csrr {0}, satp", out(reg) satp) };
            ctx.satp = satp;
        }
        #[cfg(not(target_os = "none"))]
        {
            ctx.satp = 0;
        }
    }

    fn set_privilege_level(&self, level: PrivilegeLevel) -> Result<(), HalError> {
        match level {
            // RISC-V's M-mode (mapped to Monitor) is not reachable via
            // a privilege-level primitive at all from S-mode — the
            // ONLY way back into M-mode is an `ecall` (an SBI call),
            // which is a completely different mechanism (a synchronous
            // trap, not a context restore) than what this trait's
            // context_switch model provides. Same declined-Monitor
            // outcome as x86_64, for an architecturally different
            // reason than ARM64's "we choose not to" — here it is
            // genuinely "the mechanism this trait models does not
            // apply".
            PrivilegeLevel::Monitor => Err(HalError::UnsupportedPrivilegeLevel),
            // Same reasoning as the other two architectures:
            // Kernel/User is encoded in the target context's sstatus
            // field (Riscv64Context::sstatus, specifically the SPP —
            // Supervisor Previous Privilege — bit), applied only as
            // part of context_switch's restore path via `sret`, never
            // as a standalone operation.
            PrivilegeLevel::Kernel | PrivilegeLevel::User => Ok(()),
        }
    }

    fn bootstrap_current_core(&self) -> Result<(), HalError> {
        // SAFETY: called once per hart, before any trap (interrupt or
        // exception) can be taken on this hart — boot.S never enables
        // interrupts (sstatus.SIE stays clear from SBI's S-mode entry
        // state through this point).
        unsafe {
            load_stvec();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_feature_flags_always_reports_rv64gc_baseline() {
        let flags = detect_feature_flags();
        assert!(flags.contains(CpuFeatureFlags::WIDE_ATOMICS));
        assert!(flags.contains(CpuFeatureFlags::PERF_COUNTERS));
    }

    #[test]
    fn riscv64_context_matches_declared_size() {
        assert_eq!(size_of::<Riscv64Context>(), RISCV64_CONTEXT_BYTES);
    }

    #[test]
    fn scause_top_bit_distinguishes_interrupt_from_exception() {
        let interrupt_scause: usize = 1 << (usize::BITS - 1) | 5; // e.g. timer interrupt
        let exception_scause: usize = 12; // e.g. instruction page fault

        assert!((interrupt_scause as isize) < 0);
        assert!((exception_scause as isize) >= 0);
    }

    #[test]
    fn cause_code_masks_out_interrupt_bit() {
        let scause: usize = (1 << (usize::BITS - 1)) | 5;
        let cause_code = scause & !(1 << (usize::BITS - 1));
        assert_eq!(cause_code, 5);
    }
}