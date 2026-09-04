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
//! MVP scope: all three responsibilities are implemented and tested as
//! deterministic, pure DECISION policy — matching the OOM victim policy's
//! own established shape ("mm-service... asks the kernel, via the process
//! that holds the relevant capabilities, to reclaim" — it decides, it does
//! not itself perform I/O). Swap decides WHICH registered region to evict
//! (`choose_swap_victim`); CXL/unified-memory coordination decides WHICH
//! registered compute pool should satisfy an allocation
//! (`choose_compute_pool`). Actually moving bytes to a block device or
//! performing the cross-pool copy is a follow-up for whichever process
//! holds the block-device/compute-device capability (a driver, not
//! mm-service) — out of scope here, same as OOM's own victim policy never
//! itself terminates the chosen process.
//!
//! Safety/invariants: victim/pool selection is total and deterministic
//! given the same inputs; a process marked `Protected` is never chosen
//! while any unprotected candidate exists (OOM); a pool is never chosen
//! without enough free space for the request (compute pool).
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;
use hal_manifest::ComputeKind;

/// mm-service's real process entry point (03-Kernel-Subsystems-Layer.md
/// §2.5) — see that module's own doc comment. Mirrors `compositor::
/// subsystem_entry`'s own unconditional module declaration (per-
/// architecture gating lives inside the file, not at this level).
pub mod subsystem_entry;

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

// ============================================================================
// Swap — 03-Kernel-Subsystems-Layer.md §2.5's second responsibility.
// ============================================================================

/// A single swappable memory region a process has registered with this
/// service — distinct from `ProcMemInfo`'s own whole-process accounting,
/// since one process may register more than one independently-swappable
/// region (e.g. a cache it can rebuild vs. state it cannot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapRegion {
    /// The owning process's thread id.
    pub thread: u32,
    /// This process's own identifier for the region (unique per-thread,
    /// not globally — the `(thread, region_id)` pair is the real key).
    pub region_id: u32,
    /// The region's size.
    pub bytes: u64,
    /// Monotonic timestamp (same clock as `hal_core::TimerAbstraction::
    /// now_ns`) of this region's last access, as reported by its own
    /// owning process — the input to the LRU ordering below.
    pub last_touched_ns: u64,
}

/// Chooses which registered region to swap OUT under memory pressure.
///
/// Policy (deterministic): least-recently-touched first (classic LRU —
/// the region least likely to be needed again soon); ties broken toward
/// the LARGEST region (frees the most memory per swap); remaining ties
/// broken toward the lower `(thread, region_id)` pair for determinism.
/// Returns `None` only if `regions` is empty.
pub fn choose_swap_victim(regions: &[SwapRegion]) -> Option<(u32, u32)> {
    regions
        .iter()
        .reduce(|a, b| {
            let a_key = (a.thread, a.region_id);
            let b_key = (b.thread, b.region_id);
            let b_wins = b.last_touched_ns < a.last_touched_ns
                || (b.last_touched_ns == a.last_touched_ns && b.bytes > a.bytes)
                || (b.last_touched_ns == a.last_touched_ns
                    && b.bytes == a.bytes
                    && b_key < a_key);
            if b_wins {
                b
            } else {
                a
            }
        })
        .map(|r| (r.thread, r.region_id))
}

/// A tiny registry of registered swappable regions, mirroring
/// `MemRegistry`'s own shape.
#[derive(Debug, Default)]
pub struct SwapRegistry {
    regions: Vec<SwapRegion>,
}

impl SwapRegistry {
    /// An empty registry.
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Registers or updates one region's accounting, keyed on
    /// `(thread, region_id)`.
    pub fn upsert(&mut self, region: SwapRegion) {
        if let Some(r) = self
            .regions
            .iter_mut()
            .find(|r| r.thread == region.thread && r.region_id == region.region_id)
        {
            *r = region;
        } else {
            self.regions.push(region);
        }
    }

    /// Drops one region's accounting (swapped back in permanently, or its
    /// owning process exited).
    pub fn remove(&mut self, thread: u32, region_id: u32) {
        self.regions
            .retain(|r| !(r.thread == thread && r.region_id == region_id));
    }

    /// Chooses a swap-out victim from the registered set.
    pub fn swap_victim(&self) -> Option<(u32, u32)> {
        choose_swap_victim(&self.regions)
    }
}

// ============================================================================
// CXL / unified-memory pool coordination — 03-Kernel-Subsystems-Layer.md
// §2.5's third responsibility.
// ============================================================================

/// A compute-memory pool this service load-balances allocation requests
/// across — CPU-attached DRAM plus any GPU/NPU/TPU/FPGA-attached pool the
/// Hardware Manifest reports (`hal_manifest::ComputeDevice::unified_
/// memory_capable`/CXL-attached memory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputePool {
    /// Stable identifier for this pool (a `hal_manifest::ComputeDevice::
    /// device_index`, for a device-attached pool).
    pub pool_id: u32,
    /// Which kind of compute unit this pool is attached to/local to.
    pub kind: ComputeKind,
    /// The pool's total size.
    pub capacity_bytes: u64,
    /// Bytes currently allocated from this pool.
    pub used_bytes: u64,
}

impl ComputePool {
    /// Bytes still available in this pool.
    pub fn free_bytes(&self) -> u64 {
        self.capacity_bytes.saturating_sub(self.used_bytes)
    }
}

fn best_fit(pools: &[ComputePool], bytes: u64) -> Option<&ComputePool> {
    pools
        .iter()
        .filter(|p| p.free_bytes() >= bytes)
        .reduce(|a, b| {
            if b.free_bytes() > a.free_bytes() || (b.free_bytes() == a.free_bytes() && b.pool_id < a.pool_id) {
                b
            } else {
                a
            }
        })
}

/// Chooses which registered pool should satisfy an allocation of `bytes`.
///
/// Policy (deterministic):
///   1. if `preferred_kind` is given and some pool of that kind has
///      `bytes` free, use it — locality first, keeping data near the
///      compute unit that will actually use it;
///   2. else the pool with the most free space that still fits `bytes`
///      — load-balance across whatever else is available;
///   3. `None` if no pool has room.
/// Ties broken toward the lower `pool_id` for determinism.
pub fn choose_compute_pool(
    pools: &[ComputePool],
    bytes: u64,
    preferred_kind: Option<ComputeKind>,
) -> Option<u32> {
    if let Some(kind) = preferred_kind {
        let of_kind: Vec<ComputePool> = pools.iter().copied().filter(|p| p.kind == kind).collect();
        if let Some(p) = best_fit(&of_kind, bytes) {
            return Some(p.pool_id);
        }
    }
    best_fit(pools, bytes).map(|p| p.pool_id)
}

/// A tiny registry of registered compute pools, mirroring `MemRegistry`'s
/// own shape.
#[derive(Debug, Default)]
pub struct PoolRegistry {
    pools: Vec<ComputePool>,
}

impl PoolRegistry {
    /// An empty registry.
    pub const fn new() -> Self {
        Self { pools: Vec::new() }
    }

    /// Registers or updates one pool's accounting, keyed on `pool_id`.
    pub fn upsert(&mut self, pool: ComputePool) {
        if let Some(p) = self.pools.iter_mut().find(|p| p.pool_id == pool.pool_id) {
            *p = pool;
        } else {
            self.pools.push(pool);
        }
    }

    /// Chooses which registered pool should satisfy an allocation of
    /// `bytes`, per `choose_compute_pool`'s own policy.
    pub fn choose(&self, bytes: u64, preferred_kind: Option<ComputeKind>) -> Option<u32> {
        choose_compute_pool(&self.pools, bytes, preferred_kind)
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

    fn sr(thread: u32, region_id: u32, bytes: u64, last_touched_ns: u64) -> SwapRegion {
        SwapRegion {
            thread,
            region_id,
            bytes,
            last_touched_ns,
        }
    }

    #[test]
    fn swap_victim_is_least_recently_touched() {
        let regions = [sr(1, 0, 1024, 5_000), sr(2, 0, 1024, 1_000)];
        assert_eq!(choose_swap_victim(&regions), Some((2, 0)));
    }

    #[test]
    fn swap_tie_on_touch_time_breaks_to_larger_region() {
        let regions = [sr(1, 0, 4096, 1_000), sr(2, 0, 8192, 1_000)];
        assert_eq!(choose_swap_victim(&regions), Some((2, 0)));
    }

    #[test]
    fn swap_full_tie_breaks_to_lower_thread_then_region_id() {
        let regions = [sr(3, 1, 4096, 1_000), sr(3, 0, 4096, 1_000)];
        assert_eq!(choose_swap_victim(&regions), Some((3, 0)));
    }

    #[test]
    fn swap_empty_set_has_no_victim() {
        assert_eq!(choose_swap_victim(&[]), None);
    }

    #[test]
    fn swap_registry_upsert_keyed_on_thread_and_region() {
        let mut r = SwapRegistry::new();
        r.upsert(sr(1, 0, 100, 1));
        r.upsert(sr(1, 1, 200, 2));
        r.upsert(sr(1, 0, 300, 3)); // updates the (1,0) entry, not a 3rd one
        assert_eq!(r.swap_victim(), Some((1, 1))); // (1,1) still least-recently-touched
        r.remove(1, 1);
        assert_eq!(r.swap_victim(), Some((1, 0)));
        r.remove(1, 0);
        assert_eq!(r.swap_victim(), None);
    }

    fn pool(pool_id: u32, kind: ComputeKind, capacity_bytes: u64, used_bytes: u64) -> ComputePool {
        ComputePool {
            pool_id,
            kind,
            capacity_bytes,
            used_bytes,
        }
    }

    #[test]
    fn compute_pool_prefers_the_requested_kind_when_it_fits() {
        let pools = [
            pool(1, ComputeKind::Cpu, 1_000_000, 0),
            pool(2, ComputeKind::Gpu, 1_000_000, 0),
        ];
        assert_eq!(
            choose_compute_pool(&pools, 1_000, Some(ComputeKind::Gpu)),
            Some(2)
        );
    }

    #[test]
    fn compute_pool_falls_back_when_preferred_kind_has_no_room() {
        let pools = [
            pool(1, ComputeKind::Cpu, 1_000_000, 0),
            pool(2, ComputeKind::Gpu, 1_000, 900), // only 100 bytes free
        ];
        assert_eq!(
            choose_compute_pool(&pools, 1_000, Some(ComputeKind::Gpu)),
            Some(1)
        );
    }

    #[test]
    fn compute_pool_load_balances_to_most_free_space_with_no_preference() {
        let pools = [
            pool(1, ComputeKind::Cpu, 1_000_000, 900_000), // 100_000 free
            pool(2, ComputeKind::Cpu, 1_000_000, 100_000), // 900_000 free
        ];
        assert_eq!(choose_compute_pool(&pools, 1_000, None), Some(2));
    }

    #[test]
    fn compute_pool_tie_breaks_to_lower_pool_id() {
        let pools = [
            pool(2, ComputeKind::Cpu, 1_000_000, 0),
            pool(1, ComputeKind::Cpu, 1_000_000, 0),
        ];
        assert_eq!(choose_compute_pool(&pools, 1_000, None), Some(1));
    }

    #[test]
    fn compute_pool_none_when_nothing_fits() {
        let pools = [pool(1, ComputeKind::Cpu, 1_000, 999)];
        assert_eq!(choose_compute_pool(&pools, 1_000, None), None);
    }

    #[test]
    fn compute_pool_registry_upsert_and_choose() {
        let mut r = PoolRegistry::new();
        r.upsert(pool(1, ComputeKind::Cpu, 1_000_000, 999_500));
        r.upsert(pool(2, ComputeKind::Npu, 2_000_000, 0));
        assert_eq!(r.choose(1_000, Some(ComputeKind::Npu)), Some(2));
        assert_eq!(r.choose(1_000, None), Some(2));
        // Update pool 2 to be full; only pool 1 no longer fits either.
        r.upsert(pool(2, ComputeKind::Npu, 2_000_000, 2_000_000));
        assert_eq!(r.choose(1_000, None), None);
    }
}
