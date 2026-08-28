//! ============================================================================
//! timer.rs
//!
//! Timer & Clock abstraction, per 01-HAL-Layer.md section 3.3 and the
//! trait pre-draft in section 4:
//!
//!   pub trait TimerAbstraction {
//!       fn now_ns(&self) -> u64;
//!       fn set_oneshot(&self, deadline_ns: u64, mode: TimerMode);
//!       fn set_tickless(&self, enabled: bool);
//!   }
//!
//! Responsibilities per section 3.3:
//!   - uniform access to hardware timers with two modes:
//!       * Interactive tick: low latency, for general/gaming profiles
//!       * High-resolution / tickless: for AI batch workload and
//!         real-time-sensitive work
//!   - hardware sources: TSC/HPET (x86_64), Generic Timer (ARM64),
//!     mtime/mtimecmp per the SBI spec (RISC-V)
//!
//! This directly feeds the microkernel's dual-mode scheduler
//! (02-Microkernel-Layer.md section 4: Interactive vs Throughput/Batch
//! mode), which is why `TimerMode` here mirrors that same two-mode
//! split rather than inventing a separate vocabulary.
//! ============================================================================

use crate::error::HalError;

// ============================================================================
// Timer mode (section 3.3, mirrored against 02-Microkernel-Layer.md
// section 4's scheduler modes so both layers speak the same vocabulary)
// ============================================================================

/// Which timer behavior a `set_oneshot` deadline should use.
///
/// This is a HARDWARE-level distinction (which timer mechanism/IRQ
/// cadence to arm), not a scheduling POLICY decision — the policy of
/// "which threads should run in which mode" belongs entirely to the
/// microkernel's scheduler (02-Microkernel-Layer.md, section 4). HAL
/// only provides the two mechanisms; layer 2 decides when to use each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    /// Low-latency periodic-style tick, suited to interactive
    /// scheduling (general/gaming profiles per
    /// 04-System-Services-Policy-Layer.md section 6.2's "Scheduler
    /// default: Interactive"). Typical quantum per
    /// 02-Microkernel-Layer.md section 4: ~1-4ms.
    Interactive,
    /// High-resolution, tickless-capable deadline suited to AI batch
    /// workloads and real-time-sensitive work (section 3.3: "AI batch
    /// workload and real-time-sensitive"). Requires
    /// `TimerInfo::supports_tickless` to be true on the detected timer
    /// source (see hal-manifest raw::TimerInfoRaw) — if not,
    /// `set_oneshot` with this mode returns
    /// `HalError::TicklessModeUnsupported`.
    HighResolutionTickless,
}

// ============================================================================
// Timer IRQ handler — invoked by the architecture's interrupt vector
// when a previously armed oneshot deadline fires
// ============================================================================

/// Callback signature for a timer deadline firing.
///
/// Kept as a plain function pointer (not a boxed closure) because this
/// crate is `no_std` without `alloc` — see hal-manifest section 9's
/// boot-time no-heap philosophy, which applies transitively to hal-core
/// since both link into the same pre-heap boot binary per
/// 01-HAL-Layer.md section 0.
///
/// The microkernel (layer 2) registers a small, fixed dispatcher here
/// (typically one that posts to its own internal scheduling queue) and
/// does its real per-thread bookkeeping on its own side of this
/// boundary, not inside the callback itself.
pub type TimerCallback = fn();

// ============================================================================
// TimerAbstraction trait (section 4 pre-draft, extended with error
// handling per the same rationale as MemoryBootstrap/CpuAbstraction:
// the pre-draft signatures are an explicit starting sketch, not final)
// ============================================================================

/// Per-architecture timer & clock abstraction. Implemented once per
/// architecture crate (`hal-x86_64::timer::Timer`,
/// `hal-arm64::timer::Timer`, `hal-riscv64::timer::Timer`), each wrapping
/// its own hardware source (TSC/HPET, ARM Generic Timer,
/// mtime/mtimecmp) behind this one API.
pub trait TimerAbstraction {
    /// Current monotonic time in nanoseconds since an arbitrary,
    /// architecture-chosen epoch (NOT wall-clock time — wall-clock/RTC
    /// handling, if needed, is a layer 3+ concern, not HAL's).
    ///
    /// Guaranteed monotonically non-decreasing for the lifetime of the
    /// system on a single core; cross-core synchronization of this
    /// value (e.g. TSC drift compensation across sockets on x86_64) is
    /// the architecture implementation's responsibility, not something
    /// callers need to reason about.
    fn now_ns(&self) -> u64;

    /// Arms a one-shot deadline: the previously registered `callback`
    /// (see `set_timer_callback` below) will fire once, at or shortly
    /// after `deadline_ns` (an absolute value in the same time base as
    /// `now_ns`), using the hardware behavior implied by `mode`.
    ///
    /// A subsequent call replaces any previously armed deadline on this
    /// core (there is exactly one active oneshot deadline per core at
    /// the HAL level — the microkernel's scheduler is responsible for
    /// multiplexing this into per-thread timeouts, per
    /// 02-Microkernel-Layer.md section 4's scheduling policy layer).
    ///
    /// Returns `Err(HalError::TicklessModeUnsupported)` if
    /// `mode == TimerMode::HighResolutionTickless` but the detected
    /// hardware timer source does not support it (see
    /// hal_manifest::raw::TimerInfoRaw::supports_tickless).
    /// Returns `Err(HalError::InvalidTimerDeadline)` if `deadline_ns`
    /// is not in the future relative to `now_ns()`, or overflows the
    /// hardware counter's representable range.
    fn set_oneshot(&self, deadline_ns: u64, mode: TimerMode) -> Result<(), HalError>;

    /// Cancels any currently armed oneshot deadline on this core
    /// without firing its callback. A no-op (not an error) if no
    /// deadline is currently armed.
    fn cancel_oneshot(&self);

    /// Enables or disables tickless mode as the STANDING behavior for
    /// this core (as opposed to `set_oneshot`'s `TimerMode`, which
    /// applies to one specific deadline). When enabled, the hardware
    /// timer does not fire on a fixed periodic cadence at all — every
    /// wakeup is an explicit `set_oneshot` deadline. When disabled, the
    /// architecture implementation may run a periodic background tick
    /// (per section 3.3's "Interactive tick") to keep interactive-mode
    /// scheduling responsive without depending on an app registering
    /// explicit deadlines.
    ///
    /// Returns `Err(HalError::TicklessModeUnsupported)` if this
    /// hardware timer source cannot do tickless mode at all.
    fn set_tickless(&self, enabled: bool) -> Result<(), HalError>;

    /// Registers the callback the architecture's interrupt vector
    /// invokes when an armed `set_oneshot` deadline fires. Must be
    /// called once during per-core bootstrap
    /// (`CpuAbstraction::bootstrap_current_core`, cpu.rs) before the
    /// first `set_oneshot` call on this core.
    fn set_timer_callback(&self, callback: TimerCallback);

    /// Whether this core's detected timer source supports
    /// high-resolution/tickless mode at all (mirrors
    /// `hal_manifest::raw::TimerInfoRaw::supports_tickless`, exposed
    /// here as a direct query so callers do not need to separately hold
    /// onto a `TimerInfo` value just to check this).
    fn supports_tickless(&self) -> bool;

    /// The tick frequency, in Hz, of the underlying hardware counter.
    /// Used by upper layers (e.g. the microkernel's Throughput
    /// scheduler, 02-Microkernel-Layer.md section 4.3, for converting
    /// its `vruntime` accounting into wall time) that need to reason
    /// about hardware timer resolution directly.
    fn frequency_hz(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    // ------------------------------------------------------------------
    // Mock hardware implementation, per section 8.4.
    //
    // Uses `Cell` (not `Mutex`/`RefCell` with locking) since this mock
    // simulates a single-core, single-threaded test environment; real
    // architecture implementations use whatever synchronization their
    // actual hardware register access requires.
    // ------------------------------------------------------------------

    struct MockTimer {
        now: Cell<u64>,
        armed_deadline: Cell<Option<(u64, TimerMode)>>,
        tickless_enabled: Cell<bool>,
        supports_tickless: bool,
        callback: Cell<Option<TimerCallback>>,
    }

    impl MockTimer {
        fn new(supports_tickless: bool) -> Self {
            Self {
                now: Cell::new(1_000_000),
                armed_deadline: Cell::new(None),
                tickless_enabled: Cell::new(false),
                supports_tickless,
                callback: Cell::new(None),
            }
        }
    }

    impl TimerAbstraction for MockTimer {
        fn now_ns(&self) -> u64 {
            self.now.get()
        }

        fn set_oneshot(&self, deadline_ns: u64, mode: TimerMode) -> Result<(), HalError> {
            if deadline_ns <= self.now_ns() {
                return Err(HalError::InvalidTimerDeadline);
            }
            if mode == TimerMode::HighResolutionTickless && !self.supports_tickless {
                return Err(HalError::TicklessModeUnsupported);
            }
            self.armed_deadline.set(Some((deadline_ns, mode)));
            Ok(())
        }

        fn cancel_oneshot(&self) {
            self.armed_deadline.set(None);
        }

        fn set_tickless(&self, enabled: bool) -> Result<(), HalError> {
            if enabled && !self.supports_tickless {
                return Err(HalError::TicklessModeUnsupported);
            }
            self.tickless_enabled.set(enabled);
            Ok(())
        }

        fn set_timer_callback(&self, callback: TimerCallback) {
            self.callback.set(Some(callback));
        }

        fn supports_tickless(&self) -> bool {
            self.supports_tickless
        }

        fn frequency_hz(&self) -> u64 {
            1_000_000_000 // pretend 1 GHz counter
        }
    }

    #[test]
    fn oneshot_rejects_past_deadline() {
        let timer = MockTimer::new(true);
        let now = timer.now_ns();
        assert_eq!(
            timer.set_oneshot(now, TimerMode::Interactive),
            Err(HalError::InvalidTimerDeadline)
        );
    }

    #[test]
    fn oneshot_accepts_future_deadline() {
        let timer = MockTimer::new(true);
        let deadline = timer.now_ns() + 1000;
        assert!(timer.set_oneshot(deadline, TimerMode::Interactive).is_ok());
        assert_eq!(
            timer.armed_deadline.get(),
            Some((deadline, TimerMode::Interactive))
        );
    }

    #[test]
    fn tickless_mode_rejected_when_unsupported() {
        let timer = MockTimer::new(false);
        let deadline = timer.now_ns() + 1000;
        assert_eq!(
            timer.set_oneshot(deadline, TimerMode::HighResolutionTickless),
            Err(HalError::TicklessModeUnsupported)
        );
        assert_eq!(
            timer.set_tickless(true),
            Err(HalError::TicklessModeUnsupported)
        );
    }

    #[test]
    fn tickless_mode_accepted_when_supported() {
        let timer = MockTimer::new(true);
        assert!(timer.set_tickless(true).is_ok());
        assert!(timer.tickless_enabled.get());
    }

    #[test]
    fn cancel_oneshot_clears_armed_deadline() {
        let timer = MockTimer::new(true);
        let deadline = timer.now_ns() + 1000;
        timer.set_oneshot(deadline, TimerMode::Interactive).unwrap();
        timer.cancel_oneshot();
        assert_eq!(timer.armed_deadline.get(), None);
    }

    #[test]
    fn callback_registration_is_recorded() {
        fn dummy_callback() {}
        let timer = MockTimer::new(true);
        timer.set_timer_callback(dummy_callback);
        assert!(timer.callback.get().is_some());
    }
}