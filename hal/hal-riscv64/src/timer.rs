//! ============================================================================
//! timer.rs — RISC-V (RV64GC)
//!
//! Implements `hal_core::timer::TimerAbstraction` for RISC-V, per
//! 01-HAL-Layer.md section 3.3: "منابع سخت‌افزاری... mtime/mtimecmp
//! (RISC-V طبق SBI)".
//!
//! Design: RISC-V's timer model is unique among the three architectures
//! in WHERE the oneshot deadline is actually set. `mtime` (the free-
//! running counter) and `mtimecmp` (the per-hart comparator) are
//! MACHINE-MODE registers — an S-mode kernel cannot write `mtimecmp`
//! directly the way it can write x86_64's IA32_TSC_DEADLINE MSR
//! (accessible at Ring 0, this project's own privilege level) or
//! ARM64's CNTP_CVAL_EL0 (accessible at EL1, this project's own
//! privilege level). Instead, RISC-V requires an SBI call (the TIME
//! extension's "Set Timer" function) to ask M-mode firmware to program
//! `mtimecmp` on this hart's behalf — mirrored by `cpu.rs`'s
//! `sbi_time_extension_present()` capability check, which this file
//! consumes rather than re-probing (per cpu.rs's module docs on
//! centralizing SBI extension probing there).
//!
//! Reading the current time, by contrast, IS directly accessible at
//! S-mode: the `time` CSR is a read-only shadow of `mtime`, per the
//! RISC-V Privileged spec (section 10.1) — this needs no SBI call at
//! all, mirroring how reading TSC/CNTPCT_EL0 needs no privileged
//! mediation on the other two architectures.
//! ============================================================================

use core::cell::Cell;

use hal_core::error::HalError;
use hal_core::timer::{TimerAbstraction, TimerCallback, TimerMode};
use hal_manifest::raw::TimerKindRaw;

// ============================================================================
// `time` CSR access (direct, no SBI needed — see module docs)
// ============================================================================

#[cfg(not(target_os = "none"))]
fn read_time_csr() -> u64 {
    // Host (`cargo test`) stub — no `time` CSR off the bare-metal
    // target. Unit tests build a `Timer` via a test helper and never
    // call this.
    0
}

#[cfg(target_os = "none")]
fn read_time_csr() -> u64 {
    let value: u64;
    // SAFETY: the `time` CSR is unconditionally readable at S-mode on
    // every RV64GC core implementing the standard timer extension
    // (Zicntr) — no preconditions beyond S-mode execution, which this
    // crate always has after boot.S's SBI handoff.
    unsafe {
        core::arch::asm!("csrr {}, time", out(reg) value);
    }
    value
}

// ============================================================================
// SBI TIME extension (mediated deadline setting — see module docs)
// ============================================================================

const SBI_EXT_TIME: usize = 0x54494D45; // "TIME", matches cpu.rs's constant
const SBI_TIME_SET_TIMER: usize = 0;

/// Issues the SBI TIME extension's "Set Timer" call (function ID 0),
/// asking M-mode firmware to program `mtimecmp` for this hart such
/// that the timer interrupt fires when `mtime` reaches
/// `deadline_ticks`.
///
/// Mirrors `cpu.rs`'s `sbi_call` exactly — reproduced here (not
/// imported) because, per this project's established convention
/// (compute.rs's identical-but-separate ECAM/port-based PCI logic
/// across x86_64/ARM64), each hal-<arch> file owns its own copy of
/// low-level primitives even when the underlying mechanism (an
/// `ecall`) is shared with cpu.rs's use of it, keeping this file
/// self-contained and independently reviewable.
#[cfg(not(target_os = "none"))]
fn sbi_set_timer(_deadline_ticks: u64) {
    // Host (`cargo test`) stub — no SBI firmware off the bare-metal
    // target.
}

#[cfg(target_os = "none")]
fn sbi_set_timer(deadline_ticks: u64) {
    // SAFETY: `ecall` targeting the SBI TIME extension's Set Timer
    // function is well-defined per the SBI spec for any `u64`
    // deadline value (a deadline at or before the current `mtime`
    // simply fires the interrupt on the next opportunity, mirroring
    // x86_64's IA32_TSC_DEADLINE and ARM64's CNTP_CVAL_EL0 behavior
    // for a past deadline, per those files' own doc comments) — this
    // call is only ever made after `Timer::new` has confirmed the TIME
    // extension is present via `cpu.rs`'s probe, so it cannot target a
    // genuinely unimplemented firmware surface.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SBI_EXT_TIME,
            in("a6") SBI_TIME_SET_TIMER,
            in("a0") deadline_ticks,
            lateout("a0") _,
            lateout("a1") _,
        );
    }
}

/// The `sstatus.SIE`-independent per-interrupt enable bit for the
/// timer interrupt lives in `sie` (Supervisor Interrupt Enable), bit 5
/// (STIE — Supervisor Timer Interrupt Enable), per the RISC-V
/// Privileged spec section 4.1.3. Unlike x86_64 (where the Local
/// APIC's LVT Timer register needs explicit mode configuration) or
/// ARM64 (where the PPI needs distributor-level enabling), RISC-V's
/// timer interrupt enable is a single CSR bit with no distributor/APIC
/// equivalent step at all — set once here, consumed by
/// `interrupt.rs`'s `bootstrap_current_core` alongside its own
/// external-interrupt (`SEIE`) enable, per that file's module docs.
const SIE_STIE_BIT: u64 = 1 << 5;

/// # Safety
/// Must be called once per hart, before this hart relies on the timer
/// interrupt being delivered.
#[cfg(not(target_os = "none"))]
pub unsafe fn enable_timer_interrupt() {
    // Host (`cargo test`) stub — no `sie` CSR off the bare-metal target.
}

#[cfg(target_os = "none")]
pub unsafe fn enable_timer_interrupt() {
    // SAFETY: forwarded from this function's own contract; setting a
    // single well-defined bit in `sie` is always safe (it only affects
    // whether an already-pending or future timer interrupt is allowed
    // to trap, never immediately triggers a trap by itself).
    unsafe {
        core::arch::asm!(
            "csrs sie, {}",
            in(reg) SIE_STIE_BIT,
        );
    }
}

/// Documented fallback frequency for `mtime`'s tick rate. Unlike
/// x86_64 (CPUID leaf 0x15) or ARM64 (CNTFRQ_EL0), RISC-V has NO
/// standard register or SBI call to QUERY the timer frequency at all
/// — it is conventionally communicated to the OS via the Device
/// Tree's `/cpus` node `timebase-frequency` property instead (a
/// property this project's `memory.rs` does not currently parse, per
/// that file's documented minimal-FDT-parsing scope covering only
/// `memory`/`plic`/`iommu` nodes). 10 MHz is QEMU's `virt` machine's
/// well-known, documented default `timebase-frequency` — not a guess
/// — used here until `memory.rs`'s FDT walker is extended to read
/// this property directly (a tracked, low-risk follow-up, since it is
/// simply one more property lookup using the exact same walker
/// machinery already built).
const QEMU_VIRT_DEFAULT_TIMEBASE_FREQUENCY_HZ: u64 = 10_000_000;

// ============================================================================
// Timer — TimerAbstraction implementation
// ============================================================================

pub struct Timer {
    frequency_hz: u64,
    sbi_time_available: bool,
    callback: Cell<Option<TimerCallback>>,
    tickless_enabled: Cell<bool>,
}

impl Timer {
    /// Constructs the timer abstraction for the current hart.
    ///
    /// NOTE on the missing `sbi_time_available` parameter source: this
    /// MVP phase constructs `Timer` in `hal_riscv64_rust_entry`
    /// (lib.rs) using `cpu::Cpu`'s already-probed
    /// `sbi_time_extension_present()` — see that method's doc comment
    /// on why probing is centralized in cpu.rs. `Timer::new` itself
    /// takes this as a parameter rather than re-probing, mirroring
    /// hal-x86_64's `Timer::new(hpet: HpetPresence)` pattern of
    /// accepting externally-discovered capability information.
    pub fn new(sbi_time_available: bool) -> Self {
        Self {
            // Per this constant's own doc comment: a real
            // timebase-frequency read from Device Tree is a tracked
            // follow-up; QEMU virt's documented default is used until
            // then.
            frequency_hz: QEMU_VIRT_DEFAULT_TIMEBASE_FREQUENCY_HZ,
            sbi_time_available,
            callback: Cell::new(None),
            tickless_enabled: Cell::new(false),
        }
    }

    /// Always `TimerKindRaw::RiscvSbiTimer` on this architecture — the
    /// hal-manifest raw.rs variant defined specifically for this case
    /// (section 3.3: "mtime/mtimecmp (RISC-V طبق SBI)").
    pub fn detected_kind(&self) -> TimerKindRaw {
        TimerKindRaw::RiscvSbiTimer
    }

    fn deadline_ns_to_ticks(&self, deadline_ns: u64) -> u64 {
        (deadline_ns as u128 * self.frequency_hz as u128 / 1_000_000_000u128) as u64
    }
}

impl TimerAbstraction for Timer {
    fn now_ns(&self) -> u64 {
        let ticks = read_time_csr();
        (ticks as u128 * 1_000_000_000u128 / self.frequency_hz as u128) as u64
    }

    fn set_oneshot(&self, deadline_ns: u64, mode: TimerMode) -> Result<(), HalError> {
        // Per module docs: unlike x86_64 (genuine hardware capability
        // gap between TSC-deadline-capable and not) this check exists
        // because the SBI TIME extension itself is, per the SBI spec,
        // OPTIONAL for an SBI implementation to provide — so this is a
        // real (if rare in practice) capability gap on this
        // architecture too, just sourced from firmware capability
        // rather than CPU silicon capability.
        if !self.sbi_time_available {
            return Err(HalError::TicklessModeUnsupported);
        }

        let _ = mode; // mirrors ARM64's timer.rs: no distinct hardware
        // mode to select between Interactive/HighResolutionTickless on
        // this architecture — the SBI Set Timer call is inherently a
        // single, high-resolution oneshot mechanism regardless of
        // which hal_core::timer::TimerMode the caller specifies.

        if deadline_ns <= self.now_ns() {
            return Err(HalError::InvalidTimerDeadline);
        }

        let deadline_ticks = self.deadline_ns_to_ticks(deadline_ns);
        sbi_set_timer(deadline_ticks);

        Ok(())
    }

    fn cancel_oneshot(&self) {
        // Per the SBI TIME extension spec, passing u64::MAX as the
        // deadline is the documented way to effectively disarm the
        // timer (it will not fire again until a further Set Timer
        // call with a sooner deadline) — mirrors this project's
        // established "arm far into the future rather than toggle an
        // enable bit" pattern from the other two architectures' timer.rs.
        if self.sbi_time_available {
            sbi_set_timer(u64::MAX);
        }
    }

    fn set_tickless(&self, enabled: bool) -> Result<(), HalError> {
        if enabled && !self.sbi_time_available {
            return Err(HalError::TicklessModeUnsupported);
        }
        self.tickless_enabled.set(enabled);
        Ok(())
    }

    fn set_timer_callback(&self, callback: TimerCallback) {
        self.callback.set(Some(callback));
    }

    fn supports_tickless(&self) -> bool {
        self.sbi_time_available
    }

    fn frequency_hz(&self) -> u64 {
        self.frequency_hz
    }
}

/// Invoked by `interrupt.rs`'s `dispatch_current_interrupt` when the
/// Supervisor Timer Interrupt (scause code 5, per the RISC-V
/// Privileged spec's interrupt cause encoding) fires. Mirrors the
/// other two architectures' `on_timer_interrupt` exactly.
pub fn on_timer_interrupt(timer: &Timer) {
    if let Some(callback) = timer.callback.get() {
        callback();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timer_with(frequency_hz: u64, sbi_time_available: bool) -> Timer {
        Timer {
            frequency_hz,
            sbi_time_available,
            callback: Cell::new(None),
            tickless_enabled: Cell::new(false),
        }
    }

    #[test]
    fn deadline_conversion_is_consistent_with_frequency() {
        let timer = timer_with(1_000_000_000, true);
        assert_eq!(timer.deadline_ns_to_ticks(5_000), 5_000);
    }

    #[test]
    fn deadline_conversion_handles_qemu_virt_default_frequency() {
        let timer = timer_with(QEMU_VIRT_DEFAULT_TIMEBASE_FREQUENCY_HZ, true);
        let ticks = timer.deadline_ns_to_ticks(1_000_000_000); // 1 second
        assert_eq!(ticks, QEMU_VIRT_DEFAULT_TIMEBASE_FREQUENCY_HZ);
    }

    #[test]
    fn tickless_mode_rejected_without_sbi_time_extension() {
        let timer = timer_with(1_000_000_000, false);
        assert_eq!(timer.set_tickless(true), Err(HalError::TicklessModeUnsupported));
        assert!(!timer.supports_tickless());
    }

    #[test]
    fn tickless_mode_accepted_with_sbi_time_extension() {
        let timer = timer_with(1_000_000_000, true);
        assert!(timer.set_tickless(true).is_ok());
        assert!(timer.tickless_enabled.get());
    }

    #[test]
    fn detected_kind_is_always_riscv_sbi_timer() {
        let timer = timer_with(1_000_000_000, true);
        assert_eq!(timer.detected_kind(), TimerKindRaw::RiscvSbiTimer);
    }

    #[test]
    fn callback_registration_is_invoked_by_on_timer_interrupt() {
        static FIRED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        fn callback() {
            FIRED.store(true, core::sync::atomic::Ordering::SeqCst);
        }

        let timer = timer_with(1_000_000_000, true);
        timer.set_timer_callback(callback);
        on_timer_interrupt(&timer);

        assert!(FIRED.load(core::sync::atomic::Ordering::SeqCst));
    }
}