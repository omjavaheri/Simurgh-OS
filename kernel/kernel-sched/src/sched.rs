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
use crate::weight::{
    base_priority_weight_fp, effective_weight_fp_capped, vruntime_next, AGING_CAP_MS, MAX_PRIORITY,
};
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
    /// Whether this thread's [`SchedEntity::mode`] tracks the scheduler's
    /// system default (`Scheduler::system_default_mode`) rather than being
    /// a mode the admitting code named explicitly.
    ///
    /// `true` for anything admitted via
    /// `Scheduler::admit_following_system_default` (the ordinary path for
    /// a spawned user-space process), `false` for plain `Scheduler::admit`.
    /// Only `true` entities are re-moded by
    /// `Scheduler::set_system_scheduler_policy`, which is what keeps
    /// 02-Microkernel-Layer.md §4.4's per-thread override real: a thread
    /// that genuinely needs one specific discipline says so at admit time
    /// and no profile switch can take it away.
    follows_system_default_mode: bool,
}

impl SchedEntity {
    fn new(
        thread: ThreadId,
        mode: SchedulerMode,
        priority: u8,
        group: Option<ChainGroupId>,
        follows_system_default_mode: bool,
    ) -> Self {
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
            follows_system_default_mode,
        }
    }

    /// Whether this thread follows the system default mode (see the field's
    /// own doc comment) rather than a mode pinned at admit time.
    pub const fn follows_system_default_mode(&self) -> bool {
        self.follows_system_default_mode
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
    /// The discipline a thread admitted via
    /// [`Scheduler::admit_following_system_default`] gets, and which
    /// [`Scheduler::set_system_scheduler_policy`] retargets across every
    /// such already-admitted thread.
    ///
    /// This is the one genuinely system-wide scheduling knob layer-4
    /// Profile Policy owns. It starts at `Interactive` — the mode every
    /// production admit site hard-coded before this existed, so a kernel
    /// nobody ever calls `set_system_scheduler_policy` on schedules
    /// exactly as it always did.
    system_default_mode: SchedulerMode,
    /// The aging cap (`crate::weight`'s `aging_cap_ms`) in effect
    /// system-wide, in milliseconds. Starts at [`AGING_CAP_MS`]
    /// (02-Microkernel-Layer.md §4.3's own stated 50ms starting value) and
    /// is retargeted by [`Scheduler::set_system_scheduler_policy`].
    ///
    /// Unlike `system_default_mode` this has no per-thread override to
    /// respect — §4.3 states the formula's constants once, for the whole
    /// scheduler, and 04-System-Services-Policy-Layer-v2.md §7.3 likewise
    /// treats `aging_cap_ms` as a property of the active profile set, not
    /// of one thread. `0` is a real value (aging off), not "unset".
    system_aging_cap_ms: u64,
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
            system_default_mode: SchedulerMode::Interactive,
            system_aging_cap_ms: AGING_CAP_MS,
        }
    }

    /// The interactive time quantum in nanoseconds.
    pub const fn quantum_ns(&self) -> u64 {
        self.quantum_ns
    }

    // ---- system-wide scheduling policy (layer-4 Profile Policy) ------

    /// The mode newly `admit_following_system_default`ed threads get.
    pub const fn system_default_mode(&self) -> SchedulerMode {
        self.system_default_mode
    }

    /// The system-wide aging cap in ms currently charged by `account`.
    pub const fn system_aging_cap_ms(&self) -> u64 {
        self.system_aging_cap_ms
    }

    /// Installs a new system-wide scheduling policy — the kernel side of
    /// `simurgh-profile-policy`'s real profile switch
    /// (`kernel/src/main.rs`'s own `sys::SCHED_SET_SYSTEM_POLICY`).
    ///
    /// Two effects, both immediate:
    ///   1. `mode` becomes the default for every FUTURE
    ///      `admit_following_system_default`, and is applied right now to
    ///      every already-admitted thread whose
    ///      `SchedEntity::follows_system_default_mode` is `true`;
    ///   2. `aging_cap_ms` becomes the cap `account` charges `vruntime`
    ///      against, for every thread in either mode.
    ///
    /// Returns how many already-admitted threads had their mode actually
    /// CHANGED (not merely visited) — the caller logs it, which is what
    /// makes a profile switch observable on a real serial console rather
    /// than an invisible field write.
    ///
    /// Threads admitted via plain `admit` keep their explicitly-named
    /// mode (§4.4's per-thread override). `vruntime` is deliberately left
    /// untouched: it is a monotonically non-decreasing fairness account
    /// (this module's own stated invariant), and a mode switch is not a
    /// reason to forgive or invent runtime a thread did or did not have.
    /// A thread moving `Interactive` → `Throughput` therefore enters the
    /// throughput ordering already carrying its real history, which is
    /// the fair outcome.
    pub fn set_system_scheduler_policy(
        &mut self,
        mode: SchedulerMode,
        aging_cap_ms: u64,
    ) -> usize {
        self.system_default_mode = mode;
        self.system_aging_cap_ms = aging_cap_ms;
        let mut changed = 0;
        for e in self.entities.iter_mut().flatten() {
            if e.follows_system_default_mode && e.mode != mode {
                e.mode = mode;
                changed += 1;
            }
        }
        changed
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
    ///
    /// `mode` is PINNED: naming it here opts the thread out of
    /// [`Scheduler::set_system_scheduler_policy`]'s re-moding sweep
    /// (02-Microkernel-Layer.md §4.4's per-thread override). Use
    /// [`Scheduler::admit_following_system_default`] for an ordinary
    /// thread that should simply follow the active profile.
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
        self.entities[idx] = Some(SchedEntity::new(thread, mode, priority, group, false));
        Ok(())
    }

    /// [`Scheduler::admit`] with the mode taken from — and thereafter
    /// tracking — [`Scheduler::system_default_mode`].
    ///
    /// This is the right admit path for an ordinary thread: a spawned
    /// layer-3 subsystem or a user-space process has no opinion of its own
    /// about scheduling discipline, so it should follow whatever profile
    /// the user has actually selected. A later profile switch re-modes it
    /// in place.
    pub fn admit_following_system_default(
        &mut self,
        thread: ThreadId,
        priority: u8,
        group: Option<ChainGroupId>,
    ) -> Result<(), SchedError> {
        let idx = thread.as_usize();
        if idx >= NT {
            return Err(SchedError::TableFull);
        }
        let mode = self.system_default_mode;
        self.entities[idx] = Some(SchedEntity::new(thread, mode, priority, group, true));
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

    // ---- static priority changes ------------------------------------

    /// Changes an ALREADY-admitted thread's static priority (layer-4
    /// policy's "base priority", §4.3) in place: `base_priority`, its
    /// cached weight, and `effective_priority` (never below what an
    /// active inheritance already raised it to).
    ///
    /// Why a setter rather than re-`admit`: `admit` builds a fresh entity —
    /// `Blocked`, `vruntime = 0` — which is only correct for a thread that
    /// has never been scheduled. A thread already waiting in IPC, or
    /// already `Ready`, would have its run state silently overwritten.
    /// This touches nothing but the priority fields: run state,
    /// `vruntime`, mode and chain group are left exactly as they were.
    pub fn set_base_priority(&mut self, thread: ThreadId, priority: u8) -> Result<(), SchedError> {
        let e = self.slot_mut(thread).ok_or(SchedError::NoSuchThread)?;
        let p = priority.min(MAX_PRIORITY);
        let inherited_boost = e.effective_priority > e.base_priority;
        e.base_priority = p;
        e.base_weight_fp = base_priority_weight_fp(p);
        e.effective_priority = if inherited_boost { e.effective_priority.max(p) } else { p };
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
        // Read before the `slot_mut` borrow below takes `self` mutably.
        let cap_ms = self.system_aging_cap_ms;
        let (inc, group, still_running) = {
            let Some(e) = self.slot_mut(cur) else {
                self.running = None;
                return;
            };
            let ran = now_ns.saturating_sub(since);
            let w = effective_weight_fp_capped(
                e.base_weight_fp,
                e.last_wait_ms,
                e.numa_local,
                cap_ms,
            );
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

    // ---- system-wide scheduling policy (layer-4 profile switch) ------

    #[test]
    fn a_fresh_scheduler_defaults_to_interactive_and_the_doc_aging_cap() {
        // No regression for a kernel nobody ever sets a policy on: this is
        // exactly what every production admit site hard-coded before.
        let s = sched();
        assert_eq!(s.system_default_mode(), SchedulerMode::Interactive);
        assert_eq!(s.system_aging_cap_ms(), crate::weight::AGING_CAP_MS);
    }

    #[test]
    fn admit_following_system_default_picks_up_the_current_default() {
        let mut s = sched();
        s.admit_following_system_default(t(0), 10, None).unwrap();
        assert_eq!(s.entity(t(0)).unwrap().mode, SchedulerMode::Interactive);

        s.set_system_scheduler_policy(SchedulerMode::Throughput, 50);
        // A thread admitted AFTER the switch is born in the new mode.
        s.admit_following_system_default(t(1), 10, None).unwrap();
        assert_eq!(s.entity(t(1)).unwrap().mode, SchedulerMode::Throughput);
    }

    #[test]
    fn a_profile_switch_re_modes_already_admitted_following_threads() {
        // The whole point: a switch must change how threads that ALREADY
        // exist get scheduled, not just future ones.
        let mut s = sched();
        s.admit_following_system_default(t(0), 10, None).unwrap();
        s.admit_following_system_default(t(1), 10, None).unwrap();
        assert_eq!(s.set_system_scheduler_policy(SchedulerMode::Throughput, 50), 2);
        assert_eq!(s.entity(t(0)).unwrap().mode, SchedulerMode::Throughput);
        assert_eq!(s.entity(t(1)).unwrap().mode, SchedulerMode::Throughput);
        // Switching back is symmetric.
        assert_eq!(s.set_system_scheduler_policy(SchedulerMode::Interactive, 50), 2);
        assert_eq!(s.entity(t(0)).unwrap().mode, SchedulerMode::Interactive);
    }

    #[test]
    fn a_profile_switch_never_touches_an_explicitly_pinned_thread() {
        // 02-Microkernel-Layer.md §4.4's per-thread override, kept real.
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Interactive, 10, None).unwrap();
        s.admit_following_system_default(t(1), 10, None).unwrap();
        assert!(!s.entity(t(0)).unwrap().follows_system_default_mode());
        assert!(s.entity(t(1)).unwrap().follows_system_default_mode());

        assert_eq!(s.set_system_scheduler_policy(SchedulerMode::Throughput, 50), 1);
        assert_eq!(
            s.entity(t(0)).unwrap().mode,
            SchedulerMode::Interactive,
            "a pinned thread must survive a profile switch"
        );
        assert_eq!(s.entity(t(1)).unwrap().mode, SchedulerMode::Throughput);
    }

    #[test]
    fn re_moding_reports_only_threads_whose_mode_actually_changed() {
        let mut s = sched();
        s.admit_following_system_default(t(0), 10, None).unwrap();
        // Already Interactive: an Interactive switch changes nothing.
        assert_eq!(s.set_system_scheduler_policy(SchedulerMode::Interactive, 50), 0);
        assert_eq!(s.set_system_scheduler_policy(SchedulerMode::Throughput, 50), 1);
        // Idempotent: a repeated switch to the same mode is also a no-op.
        assert_eq!(s.set_system_scheduler_policy(SchedulerMode::Throughput, 50), 0);
    }

    #[test]
    fn a_profile_switch_really_changes_which_thread_pick_next_chooses() {
        // The real, end-to-end behavioural proof this whole edge exists
        // for: two threads, identical except priority. Under Interactive,
        // priority decides and the high-priority one wins every time.
        // Under Throughput, priority is not part of the ordering key at
        // all — lowest vruntime wins — so the thread that has run LESS is
        // picked even though it is the lower-priority one.
        let mut s = sched();
        let (lo_prio, hi_prio) = (t(0), t(1));
        s.admit_following_system_default(lo_prio, 0, None).unwrap();
        s.admit_following_system_default(hi_prio, MAX_PRIORITY, None).unwrap();
        s.note_ready(lo_prio, 0).unwrap();
        s.note_ready(hi_prio, 0).unwrap();

        // Interactive: priority wins outright.
        assert_eq!(s.pick_next(0), Some(hi_prio));

        // Burn real runtime on the high-priority thread so it owes the
        // most vruntime, then let the profile switch land.
        s.dispatch(hi_prio, 0).unwrap();
        s.account(20_000_000); // ran 20 ms
        s.note_ready(hi_prio, 20_000_000).unwrap();
        // Still Interactive, so priority STILL wins despite that debt.
        assert_eq!(s.pick_next(20_000_000), Some(hi_prio));

        s.set_system_scheduler_policy(SchedulerMode::Throughput, crate::weight::AGING_CAP_MS);
        // Now fairness wins and the starved low-priority thread runs.
        assert_eq!(
            s.pick_next(20_000_000),
            Some(lo_prio),
            "Throughput mode must order by vruntime, not priority"
        );
    }

    #[test]
    fn the_system_aging_cap_really_changes_how_vruntime_is_charged() {
        // Proof the RealTime profile's `aging_cap_ms = 0` reaches real
        // accounting: the same thread, the same run slice, the same wait
        // time, charged under two different caps must differ.
        fn vruntime_after_a_slice_with_cap(cap_ms: u64) -> u64 {
            let mut s = sched();
            s.admit_following_system_default(t(0), 10, None).unwrap();
            s.set_system_scheduler_policy(SchedulerMode::Interactive, cap_ms);
            // Become ready at 0, dispatch at 40ms ⇒ last_wait_ms = 40.
            s.note_ready(t(0), 0).unwrap();
            s.dispatch(t(0), 40_000_000).unwrap();
            s.account(41_000_000); // ran 1 ms
            s.entity(t(0)).unwrap().vruntime
        }

        let with_aging = vruntime_after_a_slice_with_cap(crate::weight::AGING_CAP_MS);
        let without_aging = vruntime_after_a_slice_with_cap(0);
        assert!(
            without_aging > with_aging,
            "a zero cap removes the aging weight bonus, so the same slice \
             must cost MORE vruntime ({without_aging} vs {with_aging})"
        );
    }

    #[test]
    fn set_base_priority_reorders_without_touching_run_state_or_vruntime() {
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Interactive, MAX_PRIORITY, None).unwrap();
        s.admit(t(1), SchedulerMode::Interactive, MAX_PRIORITY, None).unwrap();
        s.note_ready(t(0), 0).unwrap();
        s.note_ready(t(1), 0).unwrap();
        s.dispatch(t(1), 0).unwrap();
        s.account(1_000_000);
        let v1 = s.entity(t(1)).unwrap().vruntime;
        assert_eq!(s.pick_next(0), Some(t(0)), "equal priority: lower vruntime wins");

        s.set_base_priority(t(0), 10).unwrap();
        assert_eq!(s.pick_next(0), Some(t(1)), "now strictly outranked");
        assert_eq!(s.entity(t(0)).unwrap().state, RunState::Ready);
        assert_eq!(s.entity(t(1)).unwrap().vruntime, v1);

        // A blocked thread stays blocked.
        s.note_blocked(t(1)).unwrap();
        s.set_base_priority(t(1), MAX_PRIORITY).unwrap();
        assert_eq!(s.entity(t(1)).unwrap().state, RunState::Blocked);
        assert_eq!(s.pick_next(0), Some(t(0)));
    }

    #[test]
    fn set_base_priority_keeps_an_active_inheritance_boost() {
        let mut s = sched();
        s.admit(t(0), SchedulerMode::Interactive, 5, None).unwrap();
        s.inherit_priority(t(0), 30).unwrap();
        s.set_base_priority(t(0), 10).unwrap();
        assert_eq!(s.entity(t(0)).unwrap().effective_priority, 30);
        s.restore_priority(t(0)).unwrap();
        assert_eq!(s.entity(t(0)).unwrap().effective_priority, 10);
        assert!(s.set_base_priority(t(5), 1).is_err());
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
