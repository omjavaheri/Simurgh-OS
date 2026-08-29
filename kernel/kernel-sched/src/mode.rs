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
}
