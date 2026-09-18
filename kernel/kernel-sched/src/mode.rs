//! ============================================================================
//! mode.rs
//!
//! Purpose: `SchedulerMode` — the per-thread choice between the two
//! scheduling disciplines (02-Microkernel-Layer.md §4.4: "انتخاب مود در سطح
//! per-thread است، نه سراسری").
//!
//! Architecture reference: 02-Microkernel-Layer.md §4 (mode table), §4.4.
//!
//! Position in the system: stored on each `SchedEntity`. `kernel-core`
//! sets it from a thread-creation argument that, higher up, comes from
//! layer-4 Profile Policy; the scheduler branches on it in `pick_next` and
//! in how it charges `vruntime`.
//!
//! How layer-4 Profile Policy actually reaches this enum (2026-09-18):
//! §4.4's "per-thread, not global" wording constrains where the mode is
//! STORED and applied (one `SchedulerMode` per `SchedEntity`, which is
//! still exactly true), not where its DEFAULT comes from. `Scheduler`
//! carries a system default mode that every thread admitted via
//! `Scheduler::admit_following_system_default` follows, and
//! `simurgh-profile-policy` sets that default over the real
//! `sys::SCHED_SET_SYSTEM_POLICY` syscall when a user switches profile.
//! A thread admitted through plain `Scheduler::admit` names its mode
//! explicitly and is left alone by such a switch — so the per-thread
//! override §4.4 requires genuinely still exists.
//! ============================================================================

/// Scheduling discipline applied to one thread.
///
/// Possible values and their effects:
/// - `Interactive`: priority-based with aging and a short time quantum
///   (~1–4 ms per 02-Microkernel-Layer.md §4). A ready `Interactive`
///   thread is always preferred over a ready `Throughput` thread, so
///   input/UI latency is protected. Used for general-purpose and gaming
///   profiles. Within this mode, the next thread is the ready one with the
///   highest effective priority, ties broken by lowest `vruntime`.
/// - `Throughput`: the custom algorithm of §4.1/§4.3, optimised for batch
///   work where total throughput matters more than latency. `vruntime` is
///   accumulated at the **chain-group** level (§4.3) so a long
///   synchronous IPC chain is charged once, fairly split among its
///   members, instead of each member being billed independently. Used for
///   AI-inference and professional profiles. Within this mode, the next
///   thread is the ready one whose (group, else own) `vruntime` is lowest.
///
/// There is intentionally no third "real-time" variant yet: §4 describes
/// only these two, and hard-real-time guarantees are out of MVP scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerMode {
    /// Priority + aging, short quantum, latency-first (§4).
    Interactive,
    /// Chain-group-aware `vruntime`, throughput-first (§4.1, §4.3).
    Throughput,
}

impl SchedulerMode {
    /// A coarse ordering class: `Interactive` sorts before `Throughput`,
    /// so `pick_next` prefers any ready interactive thread over any ready
    /// throughput thread (the latency guarantee of §4.4).
    pub const fn preference_class(self) -> u8 {
        match self {
            Self::Interactive => 0,
            Self::Throughput => 1,
        }
    }

    /// This mode's stable syscall-ABI code, as carried in `a0` of
    /// `kernel/src/main.rs`'s own `sys::SCHED_SET_SYSTEM_POLICY`.
    ///
    /// Deliberately NOT the enum's own declaration order via `as usize`:
    /// a cross-repo ABI a separate git repo (`simurgh-profile-policy`,
    /// which mirrors this enum by hand in its own `scheduler.rs`) encodes
    /// against must not silently change meaning if a variant is ever
    /// reordered or inserted. Same reasoning `kernel_arch_glue::
    /// thread_state_wire_code` already applies to `ThreadState`.
    pub const fn wire_code(self) -> u8 {
        match self {
            Self::Interactive => 0,
            Self::Throughput => 1,
        }
    }

    /// Inverse of [`Self::wire_code`]. `None` for any code this kernel does
    /// not know — an out-of-range value from a user-space caller is a
    /// normal, expected input to reject, not a kernel bug.
    pub const fn from_wire_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Interactive),
            1 => Some(Self::Throughput),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_codes_round_trip_both_modes() {
        for mode in [SchedulerMode::Interactive, SchedulerMode::Throughput] {
            assert_eq!(SchedulerMode::from_wire_code(mode.wire_code()), Some(mode));
        }
    }

    #[test]
    fn an_unknown_wire_code_is_rejected_rather_than_defaulted() {
        // A user-space caller passing garbage must NOT silently land on
        // `Interactive` — `set_system_scheduler_policy` needs to be able to
        // tell "asked for interactive" apart from "asked for nonsense".
        assert_eq!(SchedulerMode::from_wire_code(2), None);
        assert_eq!(SchedulerMode::from_wire_code(u8::MAX), None);
    }
}
