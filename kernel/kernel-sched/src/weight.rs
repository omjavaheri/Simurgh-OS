//! ============================================================================
//! weight.rs
//!
//! Purpose: the fixed-point implementation of 02-Microkernel-Layer.md
//! §4.3's Throughput-mode weight formula:
//!
//!   vruntime_next(t) = vruntime_current(t) + actual_runtime_ns / effective_weight
//!
//!   effective_weight = base_priority_weight
//!                     × (1 + aging_factor × min(wait_time_ms, aging_cap_ms))
//!                     × numa_locality_bonus
//!
//! Architecture reference: 02-Microkernel-Layer.md §4.3 (formula + starting
//! constants `aging_factor = 0.02`, `aging_cap_ms = 50`,
//! `numa_locality_bonus = 0.9`) and §9 (these numbers are benchmark-tuned
//! later, but the *shape* of the algorithm is fixed).
//!
//! Position in the system: called by `sched.rs` whenever a thread yields
//! or is preempted, to advance its (and its chain group's) `vruntime`.
//!
//! Safety/invariants:
//!   - integer only. `1.0` is represented as `WEIGHT_ONE` (a power of two)
//!     in Q`WEIGHT_FRAC_BITS` fixed point;
//!   - `effective_weight_fp` never returns `0` (it is a divisor);
//!   - `vruntime_next` saturates rather than overflowing.
//! ============================================================================

/// Number of fractional bits in the fixed-point representation. `10` gives
/// ~0.1% resolution, ample for scheduler weighting, and keeps every
/// intermediate product well inside `u128`.
pub const WEIGHT_FRAC_BITS: u32 = 10;

/// Fixed-point representation of `1.0`.
pub const WEIGHT_ONE: u64 = 1 << WEIGHT_FRAC_BITS;

/// `aging_factor = 0.02` in fixed point (`0.02 × 1024 ≈ 20.48`, rounded to
/// 20 ⇒ effective 0.01953). Per §4.3 this is a starting value to be tuned
/// against real benchmarks.
pub const AGING_FACTOR_FP: u64 = 20;

/// `aging_cap_ms = 50` — the wait time (in ms) past which extra aging
/// stops accruing, so aging cannot fully override base priority (§4.3).
pub const AGING_CAP_MS: u64 = 50;

/// `numa_locality_bonus = 0.9` in fixed point (`0.9 × 1024 ≈ 921.6`,
/// rounded to 922). Applied when a thread is scheduled on a core local to
/// its memory / compute device.
///
// TODO(omid): §4.3 states the formula line `effective_weight = ... ×
// numa_locality_bonus` with `numa_locality_bonus = 0.9`, but the
// parenthetical describes it as "کاهش ۱۰٪ در vruntime افزایشی برای دسترسی
// local" (a 10% REDUCTION of the incremental vruntime). Multiplying
// `effective_weight` by 0.9 *raises* the increment (increment =
// runtime / effective_weight), which is the opposite of the parenthetical.
// This code follows the formula line literally (multiply the weight by
// 0.9). Needs a decision: does the bonus multiply the weight, or divide
// the increment? Logged as an open question in IMPLEMENTATION-PLAN.md (Q4).
pub const NUMA_LOCALITY_BONUS_FP: u64 = 922;

/// Neutral NUMA multiplier (no locality bonus) — exactly `1.0`.
pub const NUMA_NEUTRAL_FP: u64 = WEIGHT_ONE;

/// Maps a coarse priority `0..=MAX_PRIORITY` to a `base_priority_weight`
/// in fixed point. Higher priority ⇒ higher weight ⇒ smaller `vruntime`
/// increment ⇒ scheduled more often.
///
/// The mapping here is a simple linear ramp from `1.0` at priority 0 to
/// `~4.0` at `MAX_PRIORITY`, per §4.3's note that "پروفایل AI مقدار پایه‌ی
/// بالاتری به تردهای inference می‌دهد". Deliberately simple for the MVP;
/// the real curve is a benchmark-phase decision (§9).
pub const MAX_PRIORITY: u8 = 39;

/// Fixed-point `base_priority_weight` for `priority` (clamped to
/// `MAX_PRIORITY`).
pub fn base_priority_weight_fp(priority: u8) -> u64 {
    let p = priority.min(MAX_PRIORITY) as u64;
    // 1.0 + p * (3.0 / MAX_PRIORITY)  ⇒  ranges [1.0, 4.0].
    WEIGHT_ONE + p * (3 * WEIGHT_ONE) / MAX_PRIORITY as u64
}

/// Computes `effective_weight` in fixed point from its three factors.
///
/// - `base_fp`: `base_priority_weight` (see `base_priority_weight_fp`).
/// - `wait_time_ms`: how long the thread sat ready-but-not-running since it
///   last became runnable. Clamped to `AGING_CAP_MS` internally.
/// - `numa_local`: whether the thread is being scheduled local to its
///   memory/compute affinity.
///
/// Returns a value `>= 1` (never a zero divisor).
pub fn effective_weight_fp(base_fp: u64, wait_time_ms: u64, numa_local: bool) -> u64 {
    let capped_wait = wait_time_ms.min(AGING_CAP_MS);
    // (1 + aging_factor * wait)  in fixed point.
    let aging_mul_fp = WEIGHT_ONE + AGING_FACTOR_FP * capped_wait;
    let numa_fp = if numa_local {
        NUMA_LOCALITY_BONUS_FP
    } else {
        NUMA_NEUTRAL_FP
    };
    // effective = base * aging_mul * numa, dividing out one WEIGHT_ONE per
    // multiplication to stay in fixed point. u128 intermediate so the two
    // multiplications cannot overflow for any realistic inputs.
    let e = (base_fp as u128 * aging_mul_fp as u128) >> WEIGHT_FRAC_BITS;
    let e = (e * numa_fp as u128) >> WEIGHT_FRAC_BITS;
    (e as u64).max(1)
}

/// Advances a `vruntime` by one run slice, per §4.3's `vruntime_next`.
///
/// `increment = actual_runtime_ns * WEIGHT_ONE / effective_weight_fp`
/// (the `WEIGHT_ONE` factor undoes the fixed-point scaling of the weight,
/// so a weight of exactly `1.0` gives `increment == actual_runtime_ns`).
///
/// Saturating add so a pathological run time cannot wrap `vruntime`.
pub fn vruntime_next(vruntime_current: u64, actual_runtime_ns: u64, effective_weight_fp: u64) -> u64 {
    let w = effective_weight_fp.max(1) as u128;
    let inc = (actual_runtime_ns as u128 * WEIGHT_ONE as u128 / w) as u64;
    vruntime_current.saturating_add(inc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weight_one_is_identity_increment() {
        // effective_weight == 1.0 ⇒ vruntime advances by exactly the run time.
        let next = vruntime_next(1000, 500, WEIGHT_ONE);
        assert_eq!(next, 1500);
    }

    #[test]
    fn higher_priority_advances_vruntime_slower() {
        let lo = base_priority_weight_fp(0);
        let hi = base_priority_weight_fp(MAX_PRIORITY);
        assert!(hi > lo);
        let inc_lo = vruntime_next(0, 1_000_000, effective_weight_fp(lo, 0, false));
        let inc_hi = vruntime_next(0, 1_000_000, effective_weight_fp(hi, 0, false));
        assert!(inc_hi < inc_lo, "high priority should accrue vruntime slower");
    }

    #[test]
    fn aging_raises_effective_weight_up_to_cap() {
        let base = base_priority_weight_fp(10);
        let w0 = effective_weight_fp(base, 0, false);
        let w25 = effective_weight_fp(base, 25, false);
        let w50 = effective_weight_fp(base, 50, false);
        let w_over = effective_weight_fp(base, 10_000, false);
        assert!(w25 > w0);
        assert!(w50 > w25);
        assert_eq!(w50, w_over, "aging is capped at AGING_CAP_MS");
    }

    #[test]
    fn effective_weight_never_zero() {
        assert!(effective_weight_fp(0, 0, true) >= 1);
    }
}
