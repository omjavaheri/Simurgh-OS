//! ============================================================================
//! sched.rs
//!
//! Purpose: the `Scheduler` itself — the per-thread scheduling entities,
//! the chain-group table, and the `account` / `pick_next` / `dispatch`
//! cycle the kernel runs on every timer tick and every IPC block/unblock.
//!
//! Architecture reference: 02-Microkernel-Layer.md §4 (dual mode), §4.3
//! (chain-group `vruntime` accounting), §4.4 (per-thread mode, NUMA
//! awareness input, mandatory priority inheritance), §1.1 (each operation
//! is a small function with a scoped, traceable effect — no hidden global
//! mutation).
//!
//! Position in the system: `kernel-core` holds one `Scheduler` in
//! `KernelState`. On a timer tick it calls `account(now)` to charge the
//! running thread, `pick_next(now)` to choose the successor, then
//! `dispatch(next, now)` and asks the HAL to `context_switch`. On an IPC
//! rendezvous it calls `note_ready` / `note_blocked`.
//!
//! Safety/invariants:
//!   - exactly one entity is `Running` at a time (or none, between
//!     `account` and `dispatch`);
//!   - a thread's `vruntime` only ever increases;
//!   - `effective_priority >= base_priority` always (priority inheritance
//!     can only raise it);
//!   - entity and group tables are fixed-capacity.
//! ============================================================================

use crate::chain_group::{ChainGroup, ChainGroupError};
use crate::mode::SchedulerMode;
use crate::weight::{base_priority_weight_fp, effective_weight_fp, vruntime_next, MAX_PRIORITY};
use kernel_cap::{ChainGroupId, ThreadId};

/// Runnability state of a scheduling entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Eligible to be picked by `pick_next`.
    Ready,
    /// Currently the running thread (set by `dispatch`).
    Running,
    /// Blocked in IPC / on a notification / not yet started; ignored by
    /// `pick_next` until `note_ready`.
    Blocked,
}

/// Errors from scheduler operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedError {
    /// The entity table has no free slot for this `ThreadId`, or the id
    /// is out of range.
    TableFull,
    /// No entity is registered for the given `ThreadId`.
    NoSuchThread,
    /// No chain group with the given id.
    NoSuchGroup,
    /// The chain-group table has no free slot.
    GroupTableFull,
    /// A chain-group membership change failed.
    ChainGroup(ChainGroupError),
}

impl From<ChainGroupError> for SchedError {
    fn from(e: ChainGroupError) -> Self {
        SchedError::ChainGroup(e)
    }
}

/// Per-thread scheduling state.
#[derive(Debug, Clone, Copy)]
pub struct SchedEntity {
    /// The thread this entity schedules.
    pub thread: ThreadId,
    /// Which discipline applies (02-Microkernel-Layer.md §4.4).
    pub mode: SchedulerMode,
    /// Static priority from layer-4 Profile Policy (0..=`MAX_PRIORITY`).
    pub base_priority: u8,
    /// Effective priority — `base_priority`, or higher while this thread
    /// holds a resource a higher-priority thread is blocked on (priority
    /// inheritance, §4.4).
    pub effective_priority: u8,
    /// Cached `base_priority_weight` in fixed point.
    base_weight_fp: u64,
    /// Virtual runtime accumulated by this thread (§4.3).
    pub vruntime: u64,
    /// Chain group this thread belongs to, if it is mid-IPC-chain (§4.3).
    pub chain_group: Option<ChainGroupId>,
    /// Current runnability.
    pub state: RunState,
    /// Monotonic time this entity last entered `Ready` — used to derive
    /// `wait_time_ms` for the aging term.
    became_ready_ns: u64,
    /// `wait_time_ms` captured at the last `dispatch`, fed into
    /// `effective_weight_fp` when the run slice is accounted.
    last_wait_ms: u64,
    /// Whether the thread's current core is local to its memory / compute
    /// affinity (input to `numa_locality_bonus`). Set by the kernel from
    /// HAL NUMA topology; defaults to `false` (no bonus).
    numa_local: bool,
}

impl SchedEntity {
    fn new(thread: ThreadId, mode: SchedulerMode, priority: u8, group: Option<ChainGroupId>) -> Self {
        let p = priority.min(MAX_PRIORITY);
        Self {
            thread,
            mode,
            base_priority: p,
            effective_priority: p,
            base_weight_fp: base_priority_weight_fp(p),
            vruntime: 0,
            chain_group: group,
            state: RunState::Blocked,
            became_ready_ns: 0,
            last_wait_ms: 0,
            numa_local: false,
        }
    }
}

/// The scheduler. `NT` = max threads, `NCG` = max concurrent IPC chain
/// groups (IMPLEMENTATION-PLAN.md D1). `kernel-core` fixes both.
pub struct Scheduler<const NT: usize, const NCG: usize> {
    entities: [Option<SchedEntity>; NT],
    groups: [Option<ChainGroup>; NCG],
    running: Option<ThreadId>,
    /// Monotonic time the current thread was `dispatch`ed.
    running_since_ns: u64,
    /// Interactive-mode time quantum in ns (§4: ~1–4 ms). `kernel-core`
    /// arms the HAL timer with this.
    quantum_ns: u64,
}

impl<const NT: usize, const NCG: usize> Scheduler<NT, NCG> {
    /// Creates an empty scheduler with the given interactive quantum.
    pub const fn new(quantum_ns: u64) -> Self {
        Self {
            entities: [None; NT],
            groups: [None; NCG],
            running: None,
            running_since_ns: 0,
            quantum_ns,
        }
    }

    /// The interactive time quantum in nanoseconds.
    pub const fn quantum_ns(&self) -> u64 {
        self.quantum_ns
    }

    /// The currently running thread, if any.
    pub fn running(&self) -> Option<ThreadId> {
        self.running
    }

    // ---- entity table -------------------------------------------------

    fn slot(&self, t: ThreadId) -> Option<&SchedEntity> {
        self.entities.get(t.as_usize()).and_then(|s| s.as_ref())
    }

    fn slot_mut(&mut self, t: ThreadId) -> Option<&mut SchedEntity> {
        self.entities.get_mut(t.as_usize()).and_then(|s| s.as_mut())
    }

    /// Borrows a thread's scheduling entity.
    pub fn entity(&self, t: ThreadId) -> Option<&SchedEntity> {
        self.slot(t)
    }

    /// Registers a thread with the scheduler in `Blocked` state (call
    /// `note_ready` to make it runnable). The `ThreadId` doubles as the
    /// table index, so it must be `< NT`.
    pub fn admit(
        &mut self,
        thread: ThreadId,
        mode: SchedulerMode,
        priority: u8,
        group: Option<ChainGroupId>,
    ) -> Result<(), SchedError> {
        let idx = thread.as_usize();
        if idx >= NT {
            return Err(SchedError::TableFull);
        }
        self.entities[idx] = Some(SchedEntity::new(thread, mode, priority, group));
        Ok(())
    }

    /// Removes a thread from scheduling (e.g. on TCB revoke). If it was
    /// running, `running` is cleared.
    pub fn remove(&mut self, thread: ThreadId) {
        if self.entities.get(thread.as_usize()).map(|s| s.is_some()) == Some(true) {
            self.entities[thread.as_usize()] = None;
        }
        if self.running == Some(thread) {
            self.running = None;
        }
    }

    // ---- readiness transitions --------------------------------------

    /// Marks `thread` `Ready` and records `now_ns` as the moment it began
    /// waiting (start of the aging clock).
    pub fn note_ready(&mut self, thread: ThreadId, now_ns: u64) -> Result<(), SchedError> {
        let e = self.slot_mut(thread).ok_or(SchedError::NoSuchThread)?;
        e.state = RunState::Ready;
        e.became_ready_ns = now_ns;
        Ok(())
    }

    /// Marks `thread` `Blocked`. If it was the running thread, clears
    /// `running` (the caller should then `pick_next`).
    pub fn note_blocked(&mut self, thread: ThreadId) -> Result<(), SchedError> {
        let e = self.slot_mut(thread).ok_or(SchedError::NoSuchThread)?;
        e.state = RunState::Blocked;
        if self.running == Some(thread) {
            self.running = None;
        }
        Ok(())
    }

    /// Sets the NUMA-locality hint for `thread` (input to
    /// `numa_locality_bonus`).
    pub fn set_numa_local(&mut self, thread: ThreadId, local: bool) -> Result<(), SchedError> {
        self.slot_mut(thread).ok_or(SchedError::NoSuchThread)?.numa_local = local;
        Ok(())
    }

    // ---- priority inheritance (§4.4, mandatory) ---------------------

    /// Raises `holder`'s effective priority to at least `donor_priority`
    /// (call when `holder` holds a resource a higher-priority thread is
    /// now blocked on). Never lowers it.
    pub fn inherit_priority(
        &mut self,
        holder: ThreadId,
        donor_priority: u8,
    ) -> Result<(), SchedError> {
        let e = self.slot_mut(holder).ok_or(SchedError::NoSuchThread)?;
        e.effective_priority = e.effective_priority.max(donor_priority.min(MAX_PRIORITY));
        Ok(())
    }

    /// Restores `holder`'s effective priority to its base (call when it
    /// releases the resource that triggered inheritance).
    pub fn restore_priority(&mut self, holder: ThreadId) -> Result<(), SchedError> {
        let e = self.slot_mut(holder).ok_or(SchedError::NoSuchThread)?;
        e.effective_priority = e.base_priority;
        Ok(())
    }

    // ---- chain groups (§4.3) --------------------------------------

    /// Creates chain group `id` (index into the group table).
    pub fn create_group(&mut self, id: ChainGroupId) -> Result<(), SchedError> {
        let idx = id.as_usize();
        if idx >= NCG {
            return Err(SchedError::GroupTableFull);
        }
        self.groups[idx] = Some(ChainGroup::new(id));
        Ok(())
    }

    /// Borrows a chain group.
    pub fn group(&self, id: ChainGroupId) -> Option<&ChainGroup> {
        self.groups.get(id.as_usize()).and_then(|s| s.as_ref())
    }

    /// Adds `thread` to chain group `id` and records the membership on
    /// the entity.
    pub fn join_group(&mut self, thread: ThreadId, id: ChainGroupId) -> Result<(), SchedError> {
        let g = self
            .groups
            .get_mut(id.as_usize())
            .and_then(|s| s.as_mut())
            .ok_or(SchedError::NoSuchGroup)?;
        g.add_member(thread)?;
        self.slot_mut(thread).ok_or(SchedError::NoSuchThread)?.chain_group = Some(id);
        Ok(())
    }

    /// Removes `thread` from its chain group (if any). If the group
    /// becomes empty it is recycled.
    pub fn leave_group(&mut self, thread: ThreadId) -> Result<(), SchedError> {
        let gid = match self.slot(thread).and_then(|e| e.chain_group) {
            Some(g) => g,
            None => return Ok(()),
        };
        if let Some(Some(g)) = self.groups.get_mut(gid.as_usize()) {
            let _ = g.remove_member(thread);
            if g.is_empty() {
                self.groups[gid.as_usize()] = None;
            }
        }
        self.slot_mut(thread).ok_or(SchedError::NoSuchThread)?.chain_group = None;
        Ok(())
    }

    // ---- the account / pick / dispatch cycle ---------------------

    /// Charges the run slice the currently running thread just completed
    /// to its `vruntime` (and its chain group's `group_vruntime`, §4.3),
    /// then returns it to `Ready` (unless it was already `Blocked`). Clears
    /// `running`. Idempotent when nothing is running.
    ///
    /// `now_ns` is the current monotonic time (`hal_core::TimerAbstraction::now_ns`).
    pub fn account(&mut self, now_ns: u64) {
        let Some(cur) = self.running else { return };
        let since = self.running_since_ns;
        let (inc, group, still_running) = {
            let Some(e) = self.slot_mut(cur) else {
                self.running = None;
                return;
            };
            let ran = now_ns.saturating_sub(since);
            let w = effective_weight_fp(e.base_weight_fp, e.last_wait_ms, e.numa_local);
            let newv = vruntime_next(e.vruntime, ran, w);
            let inc = newv - e.vruntime;
            e.vruntime = newv;
            let still_running = e.state == RunState::Running;
            if still_running {
                e.state = RunState::Ready;
                e.became_ready_ns = now_ns;
            }
            (inc, e.chain_group, still_running)
        };
        let _ = still_running;
        if let Some(gid) = group {
            if let Some(Some(g)) = self.groups.get_mut(gid.as_usize()) {
                g.charge(inc);
            }
        }
        self.running = None;
    }

    /// Selects the next thread to run, without committing to it. Returns
    /// `None` if nothing is `Ready`.
    ///
    /// Selection key (lowest wins), per §4.4's "interactive first" and
    /// §4.3's chain-group accounting:
    ///   1. mode class — every `Ready` `Interactive` thread outranks every
    ///      `Ready` `Throughput` thread;
    ///   2. for `Interactive`: `MAX_PRIORITY - effective_priority` (higher
    ///      priority first);
    ///   3. effective virtual runtime — for a `Throughput` thread in a
    ///      chain group, the group's `group_vruntime`; otherwise the
    ///      thread's own `vruntime`;
    ///   4. `ThreadId` as a stable tie-break.
    pub fn pick_next(&self, _now_ns: u64) -> Option<ThreadId> {
        let mut best: Option<(u8, u8, u64, u32)> = None;
        let mut best_thread = None;
        for e in self.entities.iter().flatten() {
            if e.state != RunState::Ready {
                continue;
            }
            let class = e.mode.preference_class();
            let prio_key = match e.mode {
                SchedulerMode::Interactive => MAX_PRIORITY - e.effective_priority,
                SchedulerMode::Throughput => 0,
            };
            let effective_v = match (e.mode, e.chain_group) {
                (SchedulerMode::Throughput, Some(gid)) => self
                    .group(gid)
                    .map(|g| g.group_vruntime)
                    .unwrap_or(e.vruntime),
                _ => e.vruntime,
            };
            let key = (class, prio_key, effective_v, e.thread.as_u32());
            if best.map(|b| key < b).unwrap_or(true) {
                best = Some(key);
                best_thread = Some(e.thread);
            }
        }
        best_thread
    }

    /// Commits `thread` as the running thread: captures its accumulated
    /// wait time for the aging term, marks it `Running`, and starts its
    /// run-slice clock at `now_ns`. The caller then performs the HAL
    /// `context_switch`.
    pub fn dispatch(&mut self, thread: ThreadId, now_ns: u64) -> Result<(), SchedError> {
        let e = self.slot_mut(thread).ok_or(SchedError::NoSuchThread)?;
        e.last_wait_ms = now_ns.saturating_sub(e.became_ready_ns) / 1_000_000;
        e.state = RunState::Running;
        self.running = Some(thread);
        self.running_since_ns = now_ns;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NT: usize = 8;
    const NCG: usize = 4;
    const Q: u64 = 3_000_000; // 3 ms

    fn t(n: u32) -> ThreadId {
        ThreadId::new(n)
    }

    fn sched() -> Scheduler<NT, NCG> {
        Scheduler::new(Q)
    }

    #[test]
    fn interactive_preferred_over_throughput() {
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Throughput, 20, None).unwrap();
        s.admit(t(1), SchedulerMode::Interactive, 0, None).unwrap();
        s.note_ready(t(0), 0).unwrap();
        s.note_ready(t(1), 0).unwrap();
        assert_eq!(s.pick_next(0), Some(t(1)));
    }

    #[test]
    fn higher_priority_interactive_wins() {
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Interactive, 5, None).unwrap();
        s.admit(t(1), SchedulerMode::Interactive, 30, None).unwrap();
        s.note_ready(t(0), 0).unwrap();
        s.note_ready(t(1), 0).unwrap();
        assert_eq!(s.pick_next(0), Some(t(1)));
    }

    #[test]
    fn account_advances_vruntime_and_charges_group() {
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Throughput, 10, None).unwrap();
        s.create_group(ChainGroupId::new(0)).unwrap();
        s.note_ready(t(0), 0).unwrap();
        s.join_group(t(0), ChainGroupId::new(0)).unwrap();

        s.dispatch(t(0), 0).unwrap();
        s.account(1_000_000); // ran 1 ms
        assert!(s.entity(t(0)).unwrap().vruntime > 0);
        assert!(s.group(ChainGroupId::new(0)).unwrap().group_vruntime > 0);
        assert_eq!(s.running(), None);
        assert_eq!(s.entity(t(0)).unwrap().state, RunState::Ready);
    }

    #[test]
    fn throughput_picks_lowest_group_vruntime() {
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Throughput, 10, None).unwrap();
        s.admit(t(1), SchedulerMode::Throughput, 10, None).unwrap();
        s.note_ready(t(0), 0).unwrap();
        s.note_ready(t(1), 0).unwrap();
        // Run t(0) for a while so its vruntime climbs.
        s.dispatch(t(0), 0).unwrap();
        s.account(5_000_000);
        s.note_ready(t(0), 5_000_000).unwrap();
        assert_eq!(s.pick_next(5_000_000), Some(t(1)));
    }

    #[test]
    fn priority_inheritance_only_raises() {
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Interactive, 5, None).unwrap();
        s.inherit_priority(t(0), 25).unwrap();
        assert_eq!(s.entity(t(0)).unwrap().effective_priority, 25);
        s.inherit_priority(t(0), 10).unwrap(); // lower donor: no change
        assert_eq!(s.entity(t(0)).unwrap().effective_priority, 25);
        s.restore_priority(t(0)).unwrap();
        assert_eq!(s.entity(t(0)).unwrap().effective_priority, 5);
    }

    #[test]
    fn blocked_threads_are_not_picked() {
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Interactive, 10, None).unwrap();
        assert_eq!(s.pick_next(0), None); // admitted == Blocked
        s.note_ready(t(0), 0).unwrap();
        assert_eq!(s.pick_next(0), Some(t(0)));
        s.note_blocked(t(0)).unwrap();
        assert_eq!(s.pick_next(0), None);
    }
}
