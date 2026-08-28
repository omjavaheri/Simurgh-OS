//! ============================================================================
//! timer.rs — ARM64
//!
//! Implements `hal_core::timer::TimerAbstraction` for ARM64, per
//! 01-HAL-Layer.md section 3.3: "منابع سخت‌افزاری... Generic Timer
//! (ARM64)".
//!
//! Design:
//!   - The ARM Generic Timer (CNTPCT_EL0 for reading the counter,
//!     CNTP_CVAL_EL0/CNTP_CTL_EL0 for the EL1 physical timer's
//!     oneshot deadline) is architecturally simpler than x86_64's
//!     TSC-deadline mechanism: there is no separate "does this CPU
//!     support deadline mode" capability check — the Generic Timer's
//!     comparator-based oneshot IS the baseline mechanism on every
//!     ARMv8-A core, unconditionally. This means, unlike timer.rs on
//!     x86_64, ARM64's `supports_tickless()` is always `true` for any
//!     CPU this project boots on (no HPET-style fallback path needed
//!     or possible).
//!   - Frequency is read directly from CNTFRQ_EL0 (a register firmware
//!     is required to program correctly before OS handoff, per the
//!     ARM Architecture Reference Manual) — far simpler than x86_64's
//!     CPUID leaf 0x15/0x16 frequency-derivation dance, since ARM64
//!     has no equivalent ambiguity about which leaf reports frequency.
//!   - Delivery is via the timer PPI (INTID 30, per interrupt.rs's
//!     module docs) — unlike x86_64 where the Local APIC's LVT Timer
//!     register needs explicit TSC-deadline-mode configuration before
//!     any interrupt fires, the Generic Timer's PPI is wired directly
//!     into the GIC by hardware; interrupt.rs's
//!     `bootstrap_current_core` only needs to ENABLE the PPI at the
//!     distributor (ISENABLER), not configure a delivery mode.
//! ============================================================================

use core::cell::Cell;

use hal_core::error::HalError;
use hal_core::timer::{TimerAbstraction, TimerCallback, TimerMode};
use hal_manifest::raw::TimerKindRaw;

// ============================================================================
// Generic Timer register access
// ============================================================================

/// Reads CNTFRQ_EL0: the timer's tick frequency in Hz, as programmed
/// by firmware before OS handoff (ARM ARM D11.2.4 — this register is
/// read-only at EL1 and below; only EL3/EL2 firmware may write it,
/// which is exactly why this project reads rather than derives it,
/// unlike x86_64's CPUID-based derivation).
#[cfg(not(target_os = "none"))]
fn read_cntfrq() -> u64 {
    // Host (`cargo test`) stub — no CNTFRQ_EL0 off the bare-metal
    // target. Unit tests build a `Timer` via the `timer_with(freq)` test
    // helper and never call this.
    0
}

#[cfg(target_os = "none")]
fn read_cntfrq() -> u64 {
    let value: u64;
    // SAFETY: CNTFRQ_EL0 is unconditionally readable at EL1 on every
    // ARMv8-A core implementing the Generic Timer (a mandatory
    // architectural feature, unlike x86_64's optional TSC-deadline
    // mode) — no preconditions beyond EL1 execution.
    unsafe {
        core::arch::asm!("mrs {}, CNTFRQ_EL0", out(reg) value);
    }
    value
}

/// Reads CNTPCT_EL0: the current physical counter value.
#[cfg(not(target_os = "none"))]
fn read_cntpct() -> u64 {
    // Host (`cargo test`) stub — see `read_cntfrq`.
    0
}

#[cfg(target_os = "none")]
fn read_cntpct() -> u64 {
    let value: u64;
    // SAFETY: same reasoning as read_cntfrq — CNTPCT_EL0 is
    // unconditionally readable at EL1.
    unsafe {
        core::arch::asm!("mrs {}, CNTPCT_EL0", out(reg) value);
    }
    value
}

/// Writes CNTP_CVAL_EL0: the EL1 physical timer's comparator value —
/// when CNTPCT_EL0 reaches this value, the timer PPI (INTID 30) is
/// asserted (subject to CNTP_CTL_EL0's enable bit, set separately by
/// `Timer::new`'s one-time bring-up below).
///
/// # Safety
/// No architectural precondition beyond EL1 execution — writing any
/// `u64` comparator value is well-defined per the ARM ARM (a value at
/// or before the current counter simply asserts the interrupt
/// immediately, mirroring x86_64's IA32_TSC_DEADLINE MSR behavior for
/// a past deadline, per timer.rs's own wrmsr doc comment on that
/// architecture).
#[cfg(not(target_os = "none"))]
unsafe fn write_cntp_cval(_value: u64) {
    // Host (`cargo test`) stub — see `read_cntfrq`.
}

#[cfg(target_os = "none")]
unsafe fn write_cntp_cval(value: u64) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("msr CNTP_CVAL_EL0, {}", in(reg) value);
    }
}

/// Writes CNTP_CTL_EL0: bit 0 = ENABLE, bit 1 = IMASK (interrupt
/// mask — set to prevent delivery while still counting down, unused
/// by this project which always wants delivery when enabled), bit 2 =
/// ISTATUS (read-only, condition met indicator).
///
/// # Safety
/// Same reasoning as `write_cntp_cval` — no precondition beyond EL1
/// execution.
#[cfg(not(target_os = "none"))]
unsafe fn write_cntp_ctl(_enable: bool) {
    // Host (`cargo test`) stub — see `read_cntfrq`.
}

#[cfg(target_os = "none")]
unsafe fn write_cntp_ctl(enable: bool) {
    let value: u64 = if enable { 1 } else { 0 };
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("msr CNTP_CTL_EL0, {}", in(reg) value);
    }
}

// ============================================================================
// Timer — TimerAbstraction implementation
// ============================================================================

pub struct Timer {
    frequency_hz: u64,
    callback: Cell<Option<TimerCallback>>,
    tickless_enabled: Cell<bool>,
}

impl Timer {
    /// Constructs the timer abstraction for the current core. Unlike
    /// hal-x86_64's `Timer::new`, this takes no `HpetPresence`-style
    /// parameter — the Generic Timer has no alternate/fallback
    /// hardware source on ARM64 the way HPET supplements TSC on
    /// x86_64 (per module docs).
    pub fn new() -> Self {
        let frequency_hz = read_cntfrq();

        // Enable the physical timer's comparator mechanism up front
        // (CNTP_CTL_EL0.ENABLE = 1) but with a comparator value in the
        // far future (u64::MAX) so it never actually fires until a
        // real `set_oneshot` call sets a meaningful deadline — this
        // mirrors x86_64's approach of writing 0 to IA32_TSC_DEADLINE
        // to keep the timer armed-but-inert (timer.rs's cancel_oneshot)
        // rather than leaving the mechanism fully disabled at
        // construction time and re-enabling it per-call, which would
        // add unnecessary CNTP_CTL_EL0 writes to the oneshot hot path.
        //
        // SAFETY: EL1 execution, no further precondition — see
        // write_cntp_cval/write_cntp_ctl's own doc comments.
        unsafe {
            write_cntp_cval(u64::MAX);
            write_cntp_ctl(true);
        }

        Self {
            frequency_hz,
            callback: Cell::new(None),
            tickless_enabled: Cell::new(false),
        }
    }

    /// Always `TimerKindRaw::ArmGenericTimer` on this architecture —
    /// unlike hal-x86_64's `detected_kind`, there is no
    /// primary-vs-fallback distinction to make (per module docs).
    pub fn detected_kind(&self) -> TimerKindRaw {
        TimerKindRaw::ArmGenericTimer
    }

    fn deadline_ns_to_ticks(&self, deadline_ns: u64) -> u64 {
        (deadline_ns as u128 * self.frequency_hz as u128 / 1_000_000_000u128) as u64
    }
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerAbstraction for Timer {
    fn now_ns(&self) -> u64 {
        let ticks = read_cntpct();
        (ticks as u128 * 1_000_000_000u128 / self.frequency_hz as u128) as u64
    }

    fn set_oneshot(&self, deadline_ns: u64, mode: TimerMode) -> Result<(), HalError> {
        // Per module docs: tickless/high-resolution mode is always
        // supported on this architecture — this check exists purely
        // for API symmetry with hal-core's trait contract (which must
        // accommodate x86_64's genuinely conditional support), not
        // because ARM64 can actually fail this check.
        let _ = mode;

        if deadline_ns <= self.now_ns() {
            return Err(HalError::InvalidTimerDeadline);
        }

        let deadline_ticks = self.deadline_ns_to_ticks(deadline_ns);

        // SAFETY: well-defined per the ARM ARM for any comparator
        // value, per write_cntp_cval's own doc comment.
        unsafe {
            write_cntp_cval(deadline_ticks);
        }

        Ok(())
    }

    fn cancel_oneshot(&self) {
        // Mirrors Timer::new's construction-time approach: rather than
        // disabling CNTP_CTL_EL0.ENABLE entirely (which this project
        // could also do), set the comparator far into the future — 
        // keeps the timer's enable state consistent and avoids a
        // CNTP_CTL_EL0 write on every cancel, matching this file's
        // hot-path-minimization reasoning in Timer::new's own doc
        // comment.
        //
        // SAFETY: same as set_oneshot's write_cntp_cval call.
        unsafe {
            write_cntp_cval(u64::MAX);
        }
    }

    fn set_tickless(&self, enabled: bool) -> Result<(), HalError> {
        // Always succeeds, per module docs — no capability check
        // needed on this architecture, unlike x86_64.
        self.tickless_enabled.set(enabled);
        Ok(())
    }

    fn set_timer_callback(&self, callback: TimerCallback) {
        self.callback.set(Some(callback));
    }

    fn supports_tickless(&self) -> bool {
        // Always true — see module docs.
        true
    }

    fn frequency_hz(&self) -> u64 {
        self.frequency_hz
    }
}

/// Invoked by `interrupt.rs`'s `dispatch_current_irq` when the timer
/// PPI (INTID 30) fires. Mirrors hal-x86_64's `on_timer_interrupt`
/// exactly — kept as a free function for the same reason (the
/// dispatch path has no way to pass a `&Timer` receiver through
/// `IrqHandler`'s fixed shape; here it's `dispatch_current_irq`'s
/// direct special-case call, not even routed through `IrqHandler` at
/// all, matching interrupt.rs's own module docs on why the timer PPI
/// is special-cased ahead of the general handler table).
pub fn on_timer_interrupt(timer: &Timer) {
    if let Some(callback) = timer.callback.get() {
        callback();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timer_with(frequency_hz: u64) -> Timer {
        Timer {
            frequency_hz,
            callback: Cell::new(None),
            tickless_enabled: Cell::new(false),
        }
    }

    #[test]
    fn deadline_conversion_is_consistent_with_frequency() {
        let timer = timer_with(1_000_000_000); // 1 GHz => 1 tick per ns
        assert_eq!(timer.deadline_ns_to_ticks(5_000), 5_000);
    }

    #[test]
    fn deadline_conversion_handles_typical_arm_frequency() {
        // QEMU's virt machine commonly reports 62.5 MHz or 24 MHz for
        // CNTFRQ_EL0 depending on configuration; verify the conversion
        // formula behaves sanely at a realistic non-round frequency.
        let timer = timer_with(62_500_000);
        let ticks = timer.deadline_ns_to_ticks(1_000_000_000); // 1 second
        assert_eq!(ticks, 62_500_000);
    }

    #[test]
    fn tickless_mode_always_supported() {
        let timer = timer_with(1_000_000_000);
        assert!(timer.supports_tickless());
        assert!(timer.set_tickless(true).is_ok());
        assert!(timer.tickless_enabled.get());
    }

    #[test]
    fn detected_kind_is_always_generic_timer() {
        let timer = timer_with(1_000_000_000);
        assert_eq!(timer.detected_kind(), TimerKindRaw::ArmGenericTimer);
    }

    #[test]
    fn callback_registration_is_invoked_by_on_timer_interrupt() {
        static FIRED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        fn callback() {
            FIRED.store(true, core::sync::atomic::Ordering::SeqCst);
        }

        let timer = timer_with(1_000_000_000);
        timer.set_timer_callback(callback);
        on_timer_interrupt(&timer);

        assert!(FIRED.load(core::sync::atomic::Ordering::SeqCst));
    }
}