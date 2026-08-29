//! ============================================================================
//! mm-service
//!
//! Purpose: the *policy* layer of memory management, sitting above the
//! microkernel's raw `UntypedMemory` mechanism (02 §3). It owns the
//! swapping/paging decision, the out-of-memory victim policy (which
//! process to reclaim from under pressure — tunable by layer-4 Profile
//! Policy), and unified-memory coordination across CPU/GPU/NPU pools when
//! CXL is present in the Hardware Manifest
//! (03-Kernel-Subsystems-Layer.md §2.5).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.5 (this
//! service's three responsibilities), §0 (talks to the kernel only via
//! syscall/IPC).
//!
//! Position in the system: an isolated layer-3 process. Other services
//! register their memory accounting with it; on pressure it asks the
//! kernel (via the process that holds the relevant capabilities) to
//! reclaim from the chosen victim.
//!
//! MVP scope: the OOM victim-selection policy is implemented and tested.
//! Swap and CXL unified-memory coordination are `// TODO(omid)` — they
//! need block-device and compute-device capabilities respectively.
//!
//! Safety/invariants: victim selection is total and deterministic given
//! the same inputs; a process marked `Protected` is never chosen while any
//! unprotected candidate exists.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

/// How aggressively a process should be reclaimed from, set per process by
/// layer-4 Profile Policy.
///
/// Possible values and their effect on OOM victim selection:
/// - `Protected`: never chosen as the OOM victim unless it is the only
///   process left (e.g. the Root Task, the compositor in a desktop
///   profile).
/// - `Normal`: ordinary candidate; ranked by memory footprint.
/// - `Sacrificial`: preferred victim — chosen before any `Normal`
///   process regardless of footprint (e.g. a best-effort batch job, a
///   restartable cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimClass {
    /// Spare unless nothing else remains.
    Protected,
    /// Ordinary candidate, ranked by footprint.
    Normal,
    /// Preferred victim.
    Sacrificial,
}

/// A process's memory accounting, as registered with this service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcMemInfo {
    /// The process's thread id (its handle for reclaim requests).
    pub thread: u32,
    /// Resident bytes it is currently charged for.
    pub resident_bytes: u64,
    /// How reclaimable it is.
    pub class: ReclaimClass,
}

/// Selects the OOM victim from `procs` under memory pressure.
///
/// Policy (deterministic):
///   1. any `Sacrificial` process, largest footprint first;
///   2. else any `Normal` process, largest footprint first;
///   3. else (all `Protected`) the largest-footprint process overall.
///
/// Ties on footprint break toward the lower `thread` id for determinism.
/// Returns `None` only if `procs` is empty.
pub fn choose_oom_victim(procs: &[ProcMemInfo]) -> Option<u32> {
    fn best_by_footprint<'a>(
        it: impl Iterator<Item = &'a ProcMemInfo>,
    ) -> Option<&'a ProcMemInfo> {
        it.reduce(|a, b| {
            if b.resident_bytes > a.resident_bytes
                || (b.resident_bytes == a.resident_bytes && b.thread < a.thread)
            {
                b
            } else {
                a
            }
        })
    }

    for class in [
        ReclaimClass::Sacrificial,
        ReclaimClass::Normal,
        ReclaimClass::Protected,
    ] {
        if let Some(p) = best_by_footprint(procs.iter().filter(|p| p.class == class)) {
            return Some(p.thread);
        }
    }
    None
}

/// Running total of resident memory across a set of processes — a cheap
/// input to the "are we under pressure?" check.
pub fn total_resident(procs: &[ProcMemInfo]) -> u64 {
    procs.iter().map(|p| p.resident_bytes).sum()
}

/// A tiny registry the service keeps of registered processes.
#[derive(Debug, Default)]
pub struct MemRegistry {
    procs: Vec<ProcMemInfo>,
}

impl MemRegistry {
    /// An empty registry.
    pub const fn new() -> Self {
        Self { procs: Vec::new() }
    }

    /// Registers or updates a process's accounting.
    pub fn upsert(&mut self, info: ProcMemInfo) {
        if let Some(p) = self.procs.iter_mut().find(|p| p.thread == info.thread) {
            *p = info;
        } else {
            self.procs.push(info);
        }
    }

    /// Drops a process (it exited).
    pub fn remove(&mut self, thread: u32) {
        self.procs.retain(|p| p.thread != thread);
    }

    /// Chooses a victim from the registered set.
    pub fn oom_victim(&self) -> Option<u32> {
        choose_oom_victim(&self.procs)
    }

    /// Total resident memory across registered processes.
    pub fn total_resident(&self) -> u64 {
        total_resident(&self.procs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(thread: u32, resident_bytes: u64, class: ReclaimClass) -> ProcMemInfo {
        ProcMemInfo {
            thread,
            resident_bytes,
            class,
        }
    }

    #[test]
    fn sacrificial_chosen_before_larger_normal() {
        let procs = [
            p(1, 100 * 1024 * 1024, ReclaimClass::Normal),
            p(2, 4 * 1024 * 1024, ReclaimClass::Sacrificial),
        ];
        assert_eq!(choose_oom_victim(&procs), Some(2));
    }

    #[test]
    fn largest_normal_when_no_sacrificial() {
        let procs = [
            p(1, 10, ReclaimClass::Normal),
            p(2, 50, ReclaimClass::Normal),
            p(3, 50, ReclaimClass::Protected),
        ];
        assert_eq!(choose_oom_victim(&procs), Some(2));
    }

    #[test]
    fn protected_only_chosen_as_last_resort() {
        let procs = [
            p(5, 10, ReclaimClass::Protected),
            p(3, 30, ReclaimClass::Protected),
        ];
        assert_eq!(choose_oom_victim(&procs), Some(3));
    }

    #[test]
    fn footprint_tie_breaks_to_lower_thread_id() {
        let procs = [
            p(9, 42, ReclaimClass::Normal),
            p(4, 42, ReclaimClass::Normal),
        ];
        assert_eq!(choose_oom_victim(&procs), Some(4));
    }

    #[test]
    fn registry_upsert_and_remove() {
        let mut r = MemRegistry::new();
        r.upsert(p(1, 100, ReclaimClass::Normal));
        r.upsert(p(1, 200, ReclaimClass::Sacrificial));
        assert_eq!(r.total_resident(), 200);
        assert_eq!(r.oom_victim(), Some(1));
        r.remove(1);
        assert_eq!(r.oom_victim(), None);
    }

    #[test]
    fn empty_set_has_no_victim() {
        assert_eq!(choose_oom_victim(&[]), None);
    }
}
