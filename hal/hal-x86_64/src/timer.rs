//! ============================================================================
//! timer.rs — x86_64
//!
//! Implements `hal_core::timer::TimerAbstraction` for x86_64, per
//! 01-HAL-Layer.md section 3.3: "منابع سخت‌افزاری: TSC/HPET (x86_64)".
//!
//! Design:
//!   - `now_ns()` and oneshot deadlines are driven by the TSC
//!     (Time Stamp Counter), using the invariant-TSC + TSC-deadline-mode
//!     feature pair that every CPU targeted by this project's MVP QEMU
//!     acceptance criteria (section 8) supports.
//!   - HPET is detected and its frequency recorded (for
//!     `built_hardware_manifest`'s `TimerInfoRaw::kind` field, and as a
//!     documented fallback path) but is NOT this file's primary
//!     oneshot mechanism in the current MVP phase — TSC-deadline mode
//!     is simpler to drive correctly (a single WRMSR, no MMIO polling)
//!     and satisfies section 3.3's "High-resolution / tickless" mode
//!     requirement directly. Full HPET-based oneshot is a tracked
//!     follow-up should a target platform lack TSC-deadline support.
//!
//! Coordination with interrupt.rs: arming a TSC-deadline oneshot only
//! actually delivers an interrupt if the Local APIC's LVT Timer
//! register has ALREADY been configured for TSC-deadline mode. That
//! one-time LVT configuration is performed by
//! `InterruptCtrl::bootstrap_current_core` alongside the rest of this
//! core's APIC setup (interrupt.rs) — `Timer::new` documents this
//! ordering requirement rather than silently assuming it.
//! ============================================================================

use core::arch::x86_64::{__cpuid_count, _rdtsc};
use core::cell::Cell;

use hal_core::error::HalError;
use hal_core::timer::{TimerAbstraction, TimerCallback, TimerMode};
use hal_manifest::raw::TimerKindRaw;

// ============================================================================
// CPUID-based TSC capability + frequency detection
//
// Mirrors cpu.rs's CpuidSource/RealCpuid split: pure bit-parsing logic
// (detect_tsc_capabilities) is separated from real CPUID execution so
// it can be unit tested without depending on the actual test-runner
// host CPU's feature set, per section 8.4's mock-hardware philosophy.
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

trait CpuidSource {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidResult;
}

struct RealCpuid;

impl CpuidSource for RealCpuid {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidResult {
        // SAFETY: CPUID is unconditionally available in x86_64 long
        // mode (same reasoning as cpu.rs's RealCpuid::cpuid).
        let r = unsafe { __cpuid_count(leaf, subleaf) };
        CpuidResult { eax: r.eax, ebx: r.ebx, ecx: r.ecx, edx: r.edx }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TscCapabilities {
    /// CPUID leaf 0x80000007, EDX bit 8: TSC runs at a constant rate
    /// regardless of core P-state/C-state changes. Required for TSC to
    /// be usable as a monotonic wall-clock source at all — per
    /// hal_core::timer::TimerAbstraction::now_ns's doc comment
    /// requiring monotonic non-decreasing time.
    invariant_tsc: bool,
    /// CPUID leaf 1, ECX bit 24: the Local APIC's LVT Timer supports
    /// TSC-deadline mode (write an absolute TSC value to
    /// IA32_TSC_DEADLINE instead of a relative initial-count). This is
    /// what makes high-resolution, tickless oneshot deadlines
    /// (`TimerMode::HighResolutionTickless`) possible without polling.
    tsc_deadline_mode: bool,
}

fn detect_tsc_capabilities(cpuid: &impl CpuidSource) -> TscCapabilities {
    let leaf1 = cpuid.cpuid(1, 0);
    let leaf_ext = cpuid.cpuid(0x8000_0007, 0);
    TscCapabilities {
        invariant_tsc: leaf_ext.edx & (1 << 8) != 0,
        tsc_deadline_mode: leaf1.ecx & (1 << 24) != 0,
    }
}

/// Determines the TSC's tick frequency in Hz.
///
/// Preferred path: CPUID leaf 0x15 (Time Stamp Counter and Nominal
/// Core Crystal Clock Information), present on most modern Intel/AMD
/// CPUs and exactly what QEMU's `-cpu host`/recent `qemu64` CPU models
/// report — this covers this project's section 8 QEMU acceptance
/// criteria directly.
///
/// Fallback: if leaf 0x15 reports no usable ratio (EBX or the crystal
/// clock frequency in ECX is zero — legal per the CPUID spec on CPUs
/// that don't implement this leaf's full reporting), this function
/// returns `None`. The caller (`Timer::new`) then falls back to a
/// fixed, documented assumption rather than looping through a real PIT
/// calibration routine — full PIT-based calibration (measuring TSC
/// ticks across a known PIT interval) is a tracked follow-up for
/// hardware that needs it; every QEMU target in this project's section
/// 8 acceptance criteria reports usable leaf 0x15 data.
fn detect_tsc_frequency_hz(cpuid: &impl CpuidSource) -> Option<u64> {
    let leaf15 = cpuid.cpuid(0x15, 0);
    if leaf15.ebx == 0 || leaf15.eax == 0 {
        return None;
    }
    if leaf15.ecx != 0 {
        // ECX directly reports the crystal clock frequency in Hz;
        // TSC frequency = crystal_clock_hz * (ebx / eax).
        let crystal_hz = leaf15.ecx as u64;
        Some(crystal_hz * leaf15.ebx as u64 / leaf15.eax as u64)
    } else {
        // Some CPUs report the ratio but not the crystal frequency
        // directly; leaf 0x16 (EAX = base CPU frequency in MHz) can
        // recover it on those parts. Checked as a secondary source
        // rather than guessing.
        let leaf16 = cpuid.cpuid(0x16, 0);
        if leaf16.eax == 0 {
            return None;
        }
        let base_freq_hz = leaf16.eax as u64 * 1_000_000;
        Some(base_freq_hz)
    }
}

/// Documented fallback TSC frequency (1 GHz) used only when CPUID
/// leaves 0x15/0x16 both fail to report usable data — see
/// `detect_tsc_frequency_hz`'s doc comment. 1 GHz is a conservative,
/// round value that keeps nanosecond<->tick conversion arithmetic
/// simple (1 tick == 1 ns) if this path is ever actually hit; it is
/// NOT a claim about real hardware accuracy, and any platform that
/// reaches this fallback should have that fact surfaced through boot
/// diagnostics once hal-x86_64 has a serial output path (see lib.rs's
/// panic_handler TODO for the same currently-missing capability).
const FALLBACK_TSC_FREQUENCY_HZ: u64 = 1_000_000_000;

// ============================================================================
// HPET detection (recorded for TimerInfoRaw::kind / diagnostics; not
// this file's active oneshot mechanism in the current MVP phase — see
// module docs)
// ============================================================================

/// Whether an HPET was found via ACPI (the HPET table's presence is
/// the standard way firmware advertises it). This project's ACPI
/// walking logic already lives in `memory.rs` (DMAR detection); rather
/// than duplicate a second XSDT walk here, `Timer::new` accepts this
/// as a parameter supplied by the same boot-time ACPI pass memory.rs
/// already performs — see `Timer::new`'s parameter doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpetPresence {
    pub present: bool,
}

// ============================================================================
// MSR access — TSC read/write and TSC-deadline arming
// ============================================================================

/// IA32_TSC_DEADLINE MSR address (Intel SDM Vol. 3B, section 10.5.4.1).
const IA32_TSC_DEADLINE_MSR: u32 = 0x6E0;

/// Writes `value` to MSR `msr`.
///
/// # Safety
/// Caller must ensure `msr` is a valid, writable MSR on this CPU and
/// that `value` is a meaningful value for it — an arbitrary MSR write
/// can alter CPU behavior in ways ranging from harmless to fatal
/// (e.g. writing garbage to a control-flow-relevant MSR). Every call
/// site in this file targets `IA32_TSC_DEADLINE_MSR` specifically,
/// which is documented safe to write with any `u64` TSC value by the
/// Intel SDM (a value at or before the current TSC simply fires the
/// interrupt immediately, per SDM 10.5.4.1 — never undefined behavior).
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
        );
    }
}

/// Reads the current TSC value via the `RDTSC` instruction.
fn read_tsc() -> u64 {
    // SAFETY: RDTSC is unconditionally available in x86_64 long mode
    // and has no preconditions beyond CPL (readable from Ring 0, which
    // this crate always runs at) — `core::arch::x86_64::_rdtsc` is a
    // safe-to-call intrinsic wrapper requiring no unsafe block itself
    // for the read; the surrounding `unsafe` here is only because
    // `_rdtsc` is defined as an `unsafe fn` in `core::arch::x86_64` due
    // to being target-feature-gated, not because the read itself has
    // real preconditions on this baseline target.
    unsafe { _rdtsc() }
}

// ============================================================================
// Timer — TimerAbstraction implementation
// ============================================================================

pub struct Timer {
    frequency_hz: u64,
    tsc_deadline_capable: bool,
    hpet_present: bool,
    callback: Cell<Option<TimerCallback>>,
    tickless_enabled: Cell<bool>,
}

impl Timer {
    /// Constructs the timer abstraction for the current core.
    ///
    /// `hpet` is supplied by the caller (`hal_x86_64_rust_entry`, via
    /// `memory.rs`'s existing ACPI table walk) rather than this
    /// function performing a second, redundant XSDT scan — see the
    /// `HpetPresence` doc comment above.
    ///
    /// # Ordering requirement
    /// If TSC-deadline mode is detected as available, callers MUST
    /// ensure `InterruptCtrl::bootstrap_current_core` (interrupt.rs)
    /// runs — configuring the Local APIC's LVT Timer register for
    /// TSC-deadline mode — before the first `set_oneshot` call on this
    /// `Timer` actually expects an interrupt to fire. `Timer::new`
    /// itself does not touch the APIC (a separation of concerns
    /// consistent with each hal-core trait's implementation owning
    /// only its own hardware surface); `lib.rs`'s
    /// `hal_x86_64_rust_entry` is responsible for sequencing both
    /// `bootstrap_current_core` calls before any code relies on timer
    /// interrupts actually firing.
    pub fn new(hpet: HpetPresence) -> Self {
        let cpuid = RealCpuid;
        let caps = detect_tsc_capabilities(&cpuid);
        let frequency_hz = detect_tsc_frequency_hz(&cpuid).unwrap_or(FALLBACK_TSC_FREQUENCY_HZ);

        Self {
            frequency_hz,
            // Both the invariant-TSC guarantee (monotonic rate,
            // required for `now_ns` to be meaningful at all per
            // hal_core's trait contract) AND TSC-deadline mode
            // (required to ARM a oneshot without polling) must be
            // present for this implementation to offer tickless mode.
            tsc_deadline_capable: caps.invariant_tsc && caps.tsc_deadline_mode,
            hpet_present: hpet.present,
            callback: Cell::new(None),
            tickless_enabled: Cell::new(false),
        }
    }

    /// Reports which timer source this manifest entry should describe,
    /// for `built_hardware_manifest` (memory.rs) to place into
    /// `TimerInfoRaw::kind`. TSC is reported whenever it is the active
    /// oneshot mechanism (i.e. `tsc_deadline_capable`); HPET is
    /// reported only when TSC-deadline mode is unavailable but an HPET
    /// was still found by firmware — matching this file's stated
    /// primary-vs-fallback precedence in the module docs.
    pub fn detected_kind(&self) -> TimerKindRaw {
        if self.tsc_deadline_capable {
            TimerKindRaw::Tsc
        } else if self.hpet_present {
            TimerKindRaw::Hpet
        } else {
            // Neither TSC-deadline nor HPET detected: `now_ns` still
            // works off the plain TSC (invariant or not), but no
            // interrupt-driven oneshot path is available at all in
            // this MVP phase — `set_oneshot`/`set_tickless` report
            // `HalError::TicklessModeUnsupported` accordingly, and
            // `supports_tickless()` returns false, per this file's own
            // methods below. Reported as Tsc here since now_ns still
            // reads from it regardless of oneshot capability.
            TimerKindRaw::Tsc
        }
    }

    /// Converts an absolute nanosecond deadline into an absolute TSC
    /// tick count, for writing to `IA32_TSC_DEADLINE`.
    fn deadline_ns_to_tsc(&self, deadline_ns: u64) -> u64 {
        // frequency_hz ticks per second => frequency_hz / 1e9 ticks
        // per ns. Rearranged to avoid losing precision on integer
        // division for typical GHz-range frequencies and nanosecond-
        // range deadlines.
        (deadline_ns as u128 * self.frequency_hz as u128 / 1_000_000_000u128) as u64
    }
}

impl TimerAbstraction for Timer {
    fn now_ns(&self) -> u64 {
        let ticks = read_tsc();
        (ticks as u128 * 1_000_000_000u128 / self.frequency_hz as u128) as u64
    }

    fn set_oneshot(&self, deadline_ns: u64, mode: TimerMode) -> Result<(), HalError> {
        if mode == TimerMode::HighResolutionTickless && !self.tsc_deadline_capable {
            return Err(HalError::TicklessModeUnsupported);
        }
        if !self.tsc_deadline_capable {
            // Neither this MVP phase's Interactive-mode periodic-tick
            // path (which would be driven by the Local APIC's regular
            // one-shot/periodic initial-count mode, a separate
            // interrupt.rs-owned configuration not yet implemented —
            // see interrupt.rs's own module docs) nor tickless mode is
            // available without TSC-deadline support; surfacing this
            // as the same error keeps the caller's error handling
            // uniform rather than needing a third HalError variant for
            // what is, from the caller's perspective, the same
            // underlying "no oneshot mechanism available" condition.
            return Err(HalError::TicklessModeUnsupported);
        }

        if deadline_ns <= self.now_ns() {
            return Err(HalError::InvalidTimerDeadline);
        }

        let deadline_ticks = self.deadline_ns_to_tsc(deadline_ns);

        // SAFETY: writing an absolute TSC value to IA32_TSC_DEADLINE is
        // always well-defined per the Intel SDM (see `wrmsr`'s own
        // safety doc comment) — arming a oneshot is exactly this MSR's
        // purpose. The resulting interrupt is only actually DELIVERED
        // if the LVT Timer register was previously configured for
        // TSC-deadline mode, per this struct's `new()` doc comment on
        // that ordering requirement; if not, this write is harmless
        // but the interrupt simply never fires — a caller-ordering bug
        // outside what this function itself can detect or prevent.
        unsafe {
            wrmsr(IA32_TSC_DEADLINE_MSR, deadline_ticks);
        }

        Ok(())
    }

    fn cancel_oneshot(&self) {
        // Writing 0 to IA32_TSC_DEADLINE disarms it (SDM 10.5.4.1: a
        // value of 0 stops the timer without generating an interrupt).
        //
        // SAFETY: same justification as set_oneshot's wrmsr call — 0
        // is an explicitly well-defined "disarm" value for this MSR.
        unsafe {
            wrmsr(IA32_TSC_DEADLINE_MSR, 0);
        }
    }

    fn set_tickless(&self, enabled: bool) -> Result<(), HalError> {
        if enabled && !self.tsc_deadline_capable {
            return Err(HalError::TicklessModeUnsupported);
        }
        self.tickless_enabled.set(enabled);
        Ok(())
    }

    fn set_timer_callback(&self, callback: TimerCallback) {
        self.callback.set(Some(callback));
    }

    fn supports_tickless(&self) -> bool {
        self.tsc_deadline_capable
    }

    fn frequency_hz(&self) -> u64 {
        self.frequency_hz
    }
}

/// Invoked by `interrupt.rs`'s dispatch table when the Local APIC
/// timer vector fires (the vector `InterruptCtrl::bootstrap_current_core`
/// reserves for TSC-deadline delivery, per this file's `Timer::new` doc
/// comment on APIC/timer sequencing). Kept as a free function (not a
/// `Timer` method) because, per `hal_core::interrupt::IrqHandler`'s
/// `fn(IrqId)` signature, the dispatch path has no way to pass a
/// `&Timer` receiver through — this mirrors `interrupt.rs`'s own
/// `dispatch_vector` free-function pattern (cpu.rs's
/// `common_interrupt_entry` calls into it the same way).
///
/// This function itself only invokes whatever callback was registered
/// via `set_timer_callback` — actual scheduling decisions belong
/// entirely to the microkernel (02-Microkernel-Layer.md section 4),
/// consistent with `TimerCallback`'s own doc comment in hal-core.
pub fn on_timer_interrupt(timer: &Timer) {
    if let Some(callback) = timer.callback.get() {
        callback();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCpuid {
        leaf1: CpuidResult,
        leaf_ext: CpuidResult,
        leaf15: CpuidResult,
        leaf16: CpuidResult,
    }

    impl CpuidSource for MockCpuid {
        fn cpuid(&self, leaf: u32, _subleaf: u32) -> CpuidResult {
            match leaf {
                1 => self.leaf1,
                0x8000_0007 => self.leaf_ext,
                0x15 => self.leaf15,
                0x16 => self.leaf16,
                _ => CpuidResult::default(),
            }
        }
    }

    fn full_capability_mock() -> MockCpuid {
        MockCpuid {
            leaf1: CpuidResult { eax: 0, ebx: 0, ecx: 1 << 24, edx: 0 }, // TSC-deadline
            leaf_ext: CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: 1 << 8 }, // invariant TSC
            leaf15: CpuidResult { eax: 2, ebx: 3, ecx: 25_000_000, edx: 0 }, // 2:3 ratio, 25MHz crystal
            leaf16: CpuidResult::default(),
        }
    }

    #[test]
    fn detects_invariant_tsc_and_deadline_mode() {
        let mock = full_capability_mock();
        let caps = detect_tsc_capabilities(&mock);
        assert!(caps.invariant_tsc);
        assert!(caps.tsc_deadline_mode);
    }

    #[test]
    fn missing_deadline_mode_is_detected() {
        let mut mock = full_capability_mock();
        mock.leaf1.ecx = 0; // no TSC-deadline bit
        let caps = detect_tsc_capabilities(&mock);
        assert!(!caps.tsc_deadline_mode);
    }

    #[test]
    fn frequency_from_leaf15_ratio_and_crystal() {
        let mock = full_capability_mock();
        // crystal 25_000_000 * (ebx=3 / eax=2) = 37_500_000 Hz
        assert_eq!(detect_tsc_frequency_hz(&mock), Some(37_500_000));
    }

    #[test]
    fn frequency_falls_back_to_leaf16_when_leaf15_ecx_zero() {
        let mut mock = full_capability_mock();
        mock.leaf15.ecx = 0;
        mock.leaf16 = CpuidResult { eax: 3_000, ebx: 0, ecx: 0, edx: 0 }; // 3000 MHz
        assert_eq!(detect_tsc_frequency_hz(&mock), Some(3_000_000_000));
    }

    #[test]
    fn frequency_detection_fails_when_no_leaf_reports_data() {
        let mock = MockCpuid {
            leaf1: CpuidResult::default(),
            leaf_ext: CpuidResult::default(),
            leaf15: CpuidResult::default(),
            leaf16: CpuidResult::default(),
        };
        assert_eq!(detect_tsc_frequency_hz(&mock), None);
    }

    // ------------------------------------------------------------------
    // Timer behavior tests use a Timer constructed with a known,
    // fixed frequency_hz (bypassing real CPUID/RDTSC/WRMSR) by
    // constructing the struct fields directly — this file's `Timer` has
    // no hardware-access-free constructor otherwise, since `new()`
    // always calls RealCpuid. This is analogous to interrupt.rs/cpu.rs
    // tests exercising pure logic (deadline_ns_to_tsc conversion, error
    // paths) without requiring the test host to actually support
    // TSC-deadline mode.
    // ------------------------------------------------------------------

    fn timer_with(frequency_hz: u64, tsc_deadline_capable: bool) -> Timer {
        Timer {
            frequency_hz,
            tsc_deadline_capable,
            hpet_present: false,
            callback: Cell::new(None),
            tickless_enabled: Cell::new(false),
        }
    }

    #[test]
    fn deadline_conversion_is_consistent_with_frequency() {
        let timer = timer_with(1_000_000_000, true); // 1 GHz => 1 tick per ns
        assert_eq!(timer.deadline_ns_to_tsc(5_000), 5_000);
    }

    #[test]
    fn tickless_mode_rejected_without_deadline_capability() {
        let timer = timer_with(1_000_000_000, false);
        assert_eq!(timer.set_tickless(true), Err(HalError::TicklessModeUnsupported));
        assert!(!timer.supports_tickless());
    }

    #[test]
    fn tickless_mode_accepted_with_deadline_capability() {
        let timer = timer_with(1_000_000_000, true);
        assert!(timer.set_tickless(true).is_ok());
        assert!(timer.tickless_enabled.get());
    }

    #[test]
    fn detected_kind_prefers_tsc_when_deadline_capable() {
        let timer = timer_with(1_000_000_000, true);
        assert_eq!(timer.detected_kind(), TimerKindRaw::Tsc);
    }

    #[test]
    fn detected_kind_falls_back_to_hpet_when_present() {
        let mut timer = timer_with(1_000_000_000, false);
        timer.hpet_present = true;
        assert_eq!(timer.detected_kind(), TimerKindRaw::Hpet);
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