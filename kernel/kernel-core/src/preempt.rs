//! ============================================================================
//! preempt.rs
//!
//! Purpose: the preemptive-scheduler tick (02-Microkernel-Layer.md §4). On
//! a supervisor timer interrupt the arch trap vector calls
//! `KernelState::preempt_tick`; it charges the running thread, asks
//! `kernel-sched` for the next `Ready` one, and returns a `PreemptStep`.
//! The trap vector — which owns the interrupted register frame — then does
//! the actual save/restore, using the raw context pointers
//! `user_ctx_switch_ptrs` hands back.
//!
//! Position in the system: `kernel-arch-glue`'s registered tick handler is
//! a thin shim over `preempt_tick` + `user_ctx_switch_ptrs`. The same
//! `preempt_tick` also backs a cooperative voluntary yield (an explicit
//! syscall), which is just "tick without a timer involved".
//!
//! Safety/invariants: `preempt_tick` performs no hardware operation — it is
//! pure `kernel-sched` bookkeeping. `user_ctx_switch_ptrs` returns raw
//! pointers into two DISTINCT `Tcb::user_context` buffers (checked
//! `outgoing != incoming`); they live for the life of the system
//! (`KernelState` is a `'static`), and on the single-core MVP the trap
//! vector uses them immediately with interrupts masked.
//! ============================================================================

use crate::config::MAX_THREADS;
use crate::state::KernelState;
use crate::tcb::ThreadState;
use hal_core::HalInterface;
use kernel_cap::ThreadId;
use kernel_sched::{SchedulerMode, MAX_PRIORITY};

/// What one `preempt_tick` resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreemptStep {
    /// Snapshot `outgoing`'s U-mode context and resume `incoming`'s. The
    /// scheduler has already been updated (`outgoing` → `Ready`,
    /// `incoming` → `Running`).
    Switch {
        /// The thread being preempted / yielding.
        outgoing: ThreadId,
        /// The thread to run next.
        incoming: ThreadId,
    },
    /// The best pick is the thread already running — keep it on the CPU,
    /// no register save/restore needed.
    Continue,
    /// Nothing is `Ready`. The caller keeps whatever was running (or idles
    /// if nothing was).
    Idle,
}

impl KernelState {
    /// One preemptive-scheduler tick. `now_ns` is `HalInterface::now_ns()`.
    ///
    /// `account(now)` charges the running thread's slice and returns it to
    /// `Ready`; `pick_next(now)` then selects the lowest-vruntime `Ready`
    /// thread (§4.3/§4.4). If that is a different thread, it is
    /// `dispatch`ed (marked `Running`) and returned as `Switch`; if it is
    /// the same thread, it is re-`dispatch`ed and `Continue` is returned.
    ///
    /// Does not touch the timer or any hardware — arming the next deadline
    /// and performing the context save/restore are the caller's job.
    pub fn preempt_tick(&mut self, now_ns: u64) -> PreemptStep {
        let outgoing = self.sched.running();
        self.sched.account(now_ns);
        let next = self.sched.pick_next(now_ns);

        match (outgoing, next) {
            (Some(o), Some(n)) if n != o => {
                let _ = self.sched.dispatch(n, now_ns);
                PreemptStep::Switch {
                    outgoing: o,
                    incoming: n,
                }
            }
            (Some(o), Some(_)) => {
                // Re-picked the same thread: restore the `Running` state
                // `account` cleared and keep going.
                let _ = self.sched.dispatch(o, now_ns);
                PreemptStep::Continue
            }
            (Some(o), None) => {
                // Nothing else `Ready` (a single runnable thread): put the
                // one we just charged back on the CPU.
                let _ = self.sched.note_ready(o, now_ns);
                let _ = self.sched.dispatch(o, now_ns);
                PreemptStep::Continue
            }
            (None, Some(n)) => {
                // No prior runner (cold): just start `n`. The caller has
                // no outgoing context to save.
                let _ = self.sched.dispatch(n, now_ns);
                PreemptStep::Continue
            }
            (None, None) => PreemptStep::Idle,
        }
    }

    /// A *voluntary* yield: like `preempt_tick`, but the caller goes to
    /// the back of the line unconditionally — even if fair vruntime
    /// accounting would re-pick it. Used for an explicit "yield to
    /// whoever is next" syscall, where the point is to hand the CPU over,
    /// not to let the scheduler decide the same thread should keep it.
    ///
    /// Implemented by hiding the yielder from `pick_next` for exactly one
    /// selection (`Blocked` → pick → `Ready`), so it stays runnable but
    /// is not a candidate this round. If it is the only `Ready` thread,
    /// it simply keeps running (`Continue`).
    pub fn cooperative_yield(&mut self, now_ns: u64) -> PreemptStep {
        let outgoing = self.sched.running();
        self.sched.account(now_ns);

        let next = match outgoing {
            Some(o) => {
                let _ = self.sched.note_blocked(o);
                let n = self.sched.pick_next(now_ns);
                let _ = self.sched.note_ready(o, now_ns);
                n
            }
            None => self.sched.pick_next(now_ns),
        };

        match (outgoing, next) {
            (Some(o), Some(n)) if n != o => {
                let _ = self.sched.dispatch(n, now_ns);
                PreemptStep::Switch {
                    outgoing: o,
                    incoming: n,
                }
            }
            (Some(o), _) => {
                let _ = self.sched.dispatch(o, now_ns);
                PreemptStep::Continue
            }
            (None, Some(n)) => {
                let _ = self.sched.dispatch(n, now_ns);
                PreemptStep::Continue
            }
            (None, None) => PreemptStep::Idle,
        }
    }

    /// Raw byte pointers into `outgoing`'s and `incoming`'s
    /// `Tcb::user_context` buffers, for the arch trap vector's
    /// `save`/`restore`. `None` if the threads are the same or either TCB
    /// is absent.
    ///
    /// The two indices are distinct and in range, so the mutable pointer
    /// to one slot and the const pointer to the other never alias.
    pub fn user_ctx_switch_ptrs(
        &mut self,
        outgoing: ThreadId,
        incoming: ThreadId,
    ) -> Option<(*mut u8, *const u8)> {
        let (oi, ii) = (outgoing.as_usize(), incoming.as_usize());
        if oi == ii || oi >= MAX_THREADS || ii >= MAX_THREADS {
            return None;
        }
        // Distinct in-range indices into the same array, single-core: the
        // `&mut` to one slot and the `&` to the other never alias.
        let base = self.tcbs_mut_ptr();
        // SAFETY: `oi` / `ii` are `< MAX_THREADS` (the array length) and
        // distinct; `base` is the array's element pointer.
        let save = unsafe { (*base.add(oi)).as_mut()? }
            .user_context
            .as_bytes_mut()
            .as_mut_ptr();
        // SAFETY: as above, different index → no aliasing with `save`.
        let into = unsafe { (*base.add(ii)).as_ref()? }
            .user_context
            .as_bytes()
            .as_ptr();
        Some((save, into))
    }

    /// Const byte view of thread `tid`'s saved U-mode context (for the
    /// very first `resume_user` into it). `None` if the TCB is absent.
    pub fn user_context_bytes(&self, tid: ThreadId) -> Option<&[u8; hal_core::HAL_USER_CONTEXT_BYTES]> {
        Some(self.tcb(tid)?.user_context.as_bytes())
    }

    /// Turns a freshly-`Retype`d / `alloc`ed TCB into a runnable U-mode
    /// thread: seeds its `user_context` (entry, stack, address-space root)
    /// via the HAL, marks it `Runnable`, and admits it to the scheduler
    /// (Interactive, `MAX_PRIORITY`). Re-admitting an already-admitted
    /// thread (e.g. the Root Task) is a no-op — its `note_ready` still
    /// refreshes it.
    ///
    /// `root_frame` is the physical address of the thread's page-table
    /// root (`0` = keep the active one).
    pub fn init_user_thread(
        &mut self,
        tid: ThreadId,
        entry: usize,
        stack_top: usize,
        root_frame: usize,
        hal: &HalInterface,
    ) {
        if let Some(tcb) = self.tcb_mut(tid) {
            hal.init_user_context(tcb.user_context.as_bytes_mut(), entry, stack_top, root_frame);
            tcb.entry = hal_core::VirtAddr::new(entry);
            tcb.state = ThreadState::Runnable;
        }
        let _ = self
            .sched
            .admit(tid, SchedulerMode::Interactive, MAX_PRIORITY, None);
        let _ = self.sched.note_ready(tid, hal.now_ns());
    }

    /// `tid` took a fatal U-mode exception — per-process fault isolation
    /// (03-Kernel-Subsystems-Layer.md §2.1/§5.2: a crash kills only that
    /// ONE process, never the system). Marks `tid`'s TCB `Exited` and
    /// removes it from the scheduler UNCONDITIONALLY (unlike
    /// `preempt_tick`, there is no question of `tid` staying `Ready` for
    /// a future tick — a genuinely isolated microkernel does not resume a
    /// thread that just faulted), then picks whatever else is `Ready`.
    ///
    /// `tid` is expected to be `self.sched.running()` at the point of the
    /// fault (the caller — the arch trap vector — has no OTHER thread to
    /// blame the fault on); if the scheduler's `running` bookkeeping still
    /// names `tid`, this charges it its final (partial) run slice via
    /// `account` first, purely to leave `kernel-sched`'s own state
    /// internally consistent — irrelevant to `tid` itself, which is being
    /// destroyed either way.
    pub fn terminate_thread(&mut self, tid: ThreadId, now_ns: u64) -> TerminationOutcome {
        if self.sched.running() == Some(tid) {
            self.sched.account(now_ns);
        }
        if let Some(t) = self.tcb_mut(tid) {
            t.state = ThreadState::Exited;
        }
        self.sched.remove(tid);

        match self.sched.pick_next(now_ns) {
            Some(incoming) => {
                let _ = self.sched.dispatch(incoming, now_ns);
                TerminationOutcome::Switched { incoming }
            }
            None => TerminationOutcome::Idle,
        }
    }
<<<<<<< HEAD

    /// `tid` voluntarily blocks waiting on an external event (this
    /// session's real crash-notification wait — `kernel-arch-glue::
    /// p2_dm_wait_crash` — is the first caller) rather than yielding to
    /// the back of the ready queue. Unlike `cooperative_yield` (which
    /// re-admits the caller to `Ready` immediately, just hidden from that
    /// ONE `pick_next` selection), `tid` stays genuinely `Blocked` until
    /// something else calls `wake_blocked` on it — there is no built-in
    /// timeout or self-wake here, by design: the caller is expected to
    /// know the wake condition can genuinely never fire on its own (the
    /// way a real IPC `Recv` blocks until a matching `Send`).
    ///
    /// If nothing else is `Ready` to take over, blocking the only
    /// runnable thread would strand the CPU with nothing to run at all —
    /// so the block is undone (mirrors `preempt_tick`'s `(Some(o), None)`
    /// arm) and `tid` keeps running (`Continue`). The caller must not
    /// assume it was really put to sleep just because it called this —
    /// only a `Switch` result means another thread is now running instead.
    pub fn block_thread(&mut self, tid: ThreadId, now_ns: u64) -> PreemptStep {
        self.sched.account(now_ns);
        let _ = self.sched.note_blocked(tid);
        match self.sched.pick_next(now_ns) {
            Some(incoming) if incoming != tid => {
                let _ = self.sched.dispatch(incoming, now_ns);
                PreemptStep::Switch {
                    outgoing: tid,
                    incoming,
                }
            }
            _ => {
                // Nothing else `Ready` (or, impossible with `tid` now
                // `Blocked`, `pick_next` naming `tid` itself): undo the
                // block rather than strand the CPU.
                let _ = self.sched.note_ready(tid, now_ns);
                let _ = self.sched.dispatch(tid, now_ns);
                PreemptStep::Continue
            }
        }
    }

    /// Wakes a thread previously put to sleep by `block_thread`: makes it
    /// `Ready` again so a future `pick_next` (the next timer tick, or
    /// another `block_thread`/`terminate_thread` call) can select it.
    /// Does not itself switch to it — the caller (typically `p2_fault`,
    /// reacting to an unrelated thread's crash) keeps running; `tid` only
    /// becomes eligible for the NEXT dispatch.
    pub fn wake_blocked(&mut self, tid: ThreadId, now_ns: u64) {
        let _ = self.sched.note_ready(tid, now_ns);
    }

    /// Like `terminate_thread`, but for when the caller ALREADY knows
    /// exactly which thread should run next — typically a supervisor
    /// that was specifically `block_thread`ed waiting for `tid`'s death
    /// (`kernel_arch_glue::p2_fault`'s crash-notify hand-off). Skips
    /// `pick_next`'s generic fairness entirely and dispatches `incoming`
    /// directly: the same "direct hand-off" philosophy a real IPC
    /// reply/wake uses, since `incoming` is DEFINITELY who should run
    /// next here, not one more competitor in a vruntime race against
    /// unrelated best-effort work (which is exactly the race a
    /// long-running supervisor CAN lose — see IMPLEMENTATION-PLAN.md's
    /// note on this).
    ///
    /// `incoming` must already be `Ready` (e.g. via `wake_blocked`) —
    /// this does not check or change its readiness, only commits it as
    /// `running`.
    pub fn terminate_thread_and_handoff(&mut self, tid: ThreadId, incoming: ThreadId, now_ns: u64) {
        if self.sched.running() == Some(tid) {
            self.sched.account(now_ns);
        }
        if let Some(t) = self.tcb_mut(tid) {
            t.state = ThreadState::Exited;
        }
        self.sched.remove(tid);
        let _ = self.sched.dispatch(incoming, now_ns);
    }

    /// Voluntarily hands the CPU from `from` DIRECTLY to `to` — `from` is
    /// blocked (exactly like `block_thread`), but the incoming thread is
    /// CHOSEN BY THE CALLER instead of `pick_next`. Used when the caller
    /// already knows exactly who should run next and cannot afford to
    /// trust the ordinary fairness scheduler (or an already-cancelled
    /// preemption timer) to ever pick it — `kernel_arch_glue::
    /// p2_dm_handoff_to_driver` (device-manager, having just spawned a
    /// fresh driver thread, gives it the CPU immediately) is the first
    /// caller. The same class of starvation `terminate_thread_and_handoff`
    /// closes for the crash-notify direction; this closes it for the
    /// respawn direction.
    ///
    /// Always succeeds (`from` and `to` are assumed distinct, already-
    /// admitted threads — the caller controls both).
    pub fn yield_to_thread(&mut self, from: ThreadId, to: ThreadId, now_ns: u64) -> PreemptStep {
        self.sched.account(now_ns);
        let _ = self.sched.note_blocked(from);
        let _ = self.sched.dispatch(to, now_ns);
        PreemptStep::Switch {
            outgoing: from,
            incoming: to,
        }
    }
=======
>>>>>>> c823464 (feat(kernel): real per-thread fault isolation — a crashing process dies alone (riscv64))
}

/// What `terminate_thread` resolved to. Unlike `PreemptStep`, there is no
/// "keep running" case — the terminated thread can never be `pick_next`'s
/// answer again (it was just removed from the scheduler entirely), so the
/// only two possibilities are "someone else is Ready" or "nothing is".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationOutcome {
    /// `incoming` was picked to run next. The caller resumes its
    /// `user_context` (via `KernelState::user_context_bytes`) — there is
    /// nothing to save for the terminated thread, unlike `PreemptStep::
    /// Switch`'s `outgoing`.
    Switched {
        /// The thread to run next.
        incoming: ThreadId,
    },
    /// Nothing else is runnable. The caller has no thread left to
    /// resume — a real kernel would idle/wait for an interrupt; this
    /// MVP's callers simply have nothing to `sret` into.
    Idle,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_core::{BootInfo, BootProtocol};
<<<<<<< HEAD
    use kernel_sched::RunState;
=======
>>>>>>> c823464 (feat(kernel): real per-thread fault isolation — a crashing process dies alone (riscv64))
    use hal_manifest::raw::{
        HardwareManifestRaw, MemoryRegionKindRaw, MemoryRegionRaw, TimerInfoRaw, TimerKindRaw,
    };

    fn boot() -> BootInfo {
        let mut m = HardwareManifestRaw::zeroed();
        m.cpu_core_count = 1;
        m.push_memory_region(MemoryRegionRaw::new(
            0x100_0000,
            32 * 1024 * 1024,
            MemoryRegionKindRaw::Usable,
            false,
        ))
        .unwrap();
        m.timer = TimerInfoRaw::new(TimerKindRaw::Tsc, 1_000_000_000, false);
        BootInfo::new(
            BootProtocol::Uefi,
            m,
            0x1000,
            (0x10_0000, 0x20_0000),
            (0x20_0000, 0x21_0000),
            0,
        )
    }

    #[test]
    fn terminate_thread_marks_exited_and_removed() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        let root = k.root_thread;
        // Root Task is admitted+ready at boot but never `dispatch`ed —
        // give `terminate_thread` a `running() == Some(root)` to charge.
        let _ = k.sched.dispatch(root, 0);

        let outcome = k.terminate_thread(root, 1_000);
        assert_eq!(outcome, TerminationOutcome::Idle);
        assert_eq!(k.tcb(root).unwrap().state, ThreadState::Exited);
        assert!(k.sched.entity(root).is_none());
        assert_eq!(k.sched.running(), None);
    }

    #[test]
    fn terminate_thread_switches_to_another_ready_thread() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        let root = k.root_thread;
        let other = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        let _ = k
            .sched
            .admit(other, SchedulerMode::Interactive, MAX_PRIORITY, None);
        let _ = k.sched.note_ready(other, 0);
        let _ = k.sched.dispatch(root, 0);

        let outcome = k.terminate_thread(root, 1_000);
        assert_eq!(outcome, TerminationOutcome::Switched { incoming: other });
        assert_eq!(k.tcb(root).unwrap().state, ThreadState::Exited);
        assert!(k.sched.entity(root).is_none());
        assert_eq!(k.sched.running(), Some(other));
    }
<<<<<<< HEAD

    #[test]
    fn block_thread_switches_to_another_ready_thread() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        let root = k.root_thread;
        let other = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        let _ = k
            .sched
            .admit(other, SchedulerMode::Interactive, MAX_PRIORITY, None);
        let _ = k.sched.note_ready(other, 0);
        let _ = k.sched.dispatch(root, 0);

        let step = k.block_thread(root, 1_000);
        assert_eq!(
            step,
            PreemptStep::Switch {
                outgoing: root,
                incoming: other
            }
        );
        assert_eq!(k.sched.entity(root).unwrap().state, RunState::Blocked);
        assert_eq!(k.sched.running(), Some(other));
    }

    #[test]
    fn block_thread_undoes_the_block_when_nothing_else_is_ready() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        let root = k.root_thread;
        let _ = k.sched.dispatch(root, 0);

        // No other thread is Ready - blocking `root` would strand the CPU,
        // so it stays `Running` instead.
        let step = k.block_thread(root, 1_000);
        assert_eq!(step, PreemptStep::Continue);
        assert_eq!(k.sched.entity(root).unwrap().state, RunState::Running);
        assert_eq!(k.sched.running(), Some(root));
    }

    #[test]
    fn wake_blocked_makes_a_blocked_thread_pickable_again() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        let root = k.root_thread;
        let other = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        let _ = k
            .sched
            .admit(other, SchedulerMode::Interactive, MAX_PRIORITY, None);
        let _ = k.sched.note_ready(other, 0);
        let _ = k.sched.dispatch(root, 0);

        // `root` blocks (switches to `other`), then something wakes it.
        let _ = k.block_thread(root, 1_000);
        assert_eq!(k.sched.entity(root).unwrap().state, RunState::Blocked);
        k.wake_blocked(root, 2_000);
        assert_eq!(k.sched.entity(root).unwrap().state, RunState::Ready);

        // A subsequent `terminate_thread` on `other` (standing in for
        // "whatever runs next picks it up") should now be able to select
        // the woken `root`.
        let outcome = k.terminate_thread(other, 3_000);
        assert_eq!(outcome, TerminationOutcome::Switched { incoming: root });
    }

    #[test]
    fn terminate_thread_and_handoff_dispatches_incoming_unconditionally() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        let root = k.root_thread;
        // A third, much-longer-vruntime thread that a fairness-driven
        // `pick_next` would normally prefer over a freshly-woken one -
        // exactly the starvation `terminate_thread_and_handoff` exists to
        // bypass (see its own doc comment).
        let hog = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        let waiter = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        let _ = k
            .sched
            .admit(hog, SchedulerMode::Interactive, MAX_PRIORITY, None);
        let _ = k.sched.note_ready(hog, 0);
        let _ = k.sched.dispatch(hog, 0);
        let _ = k.sched.account(1_000_000_000); // `hog` accrues a lot of vruntime
        let _ = k.sched.note_ready(hog, 1_000_000_000);
        let _ = k
            .sched
            .admit(waiter, SchedulerMode::Interactive, MAX_PRIORITY, None);
        let _ = k.sched.note_ready(waiter, 1_000_000_000); // fresh, vruntime 0
        let _ = k.sched.dispatch(root, 1_000_000_000);

        // A plain `pick_next` here would favor `hog`'s zero-wait / plain
        // fairness comparison in ways this test does not need to pin down
        // exactly - the point of `terminate_thread_and_handoff` is that it
        // is never even asked.
        k.terminate_thread_and_handoff(root, waiter, 1_000_001_000);
        assert_eq!(k.tcb(root).unwrap().state, ThreadState::Exited);
        assert!(k.sched.entity(root).is_none());
        assert_eq!(k.sched.running(), Some(waiter));
    }

    #[test]
    fn yield_to_thread_switches_to_the_named_target_unconditionally() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        let root = k.root_thread;
        // A thread with a much lower vruntime that a fairness-driven
        // `pick_next` would normally prefer over whichever target
        // `yield_to_thread` is asked for - exactly the race this method
        // exists to bypass.
        let favored = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        let target = k.alloc_tcb(k.root_cap_space, k.root_addr_space).unwrap();
        let _ = k
            .sched
            .admit(favored, SchedulerMode::Interactive, MAX_PRIORITY, None);
        let _ = k.sched.note_ready(favored, 0); // vruntime 0 - pick_next would love this one
        let _ = k
            .sched
            .admit(target, SchedulerMode::Interactive, MAX_PRIORITY, None);
        let _ = k.sched.dispatch(root, 0);

        let step = k.yield_to_thread(root, target, 1_000);
        assert_eq!(
            step,
            PreemptStep::Switch {
                outgoing: root,
                incoming: target
            }
        );
        assert_eq!(k.sched.running(), Some(target));
        assert_eq!(k.sched.entity(root).unwrap().state, RunState::Blocked);
    }
=======
>>>>>>> c823464 (feat(kernel): real per-thread fault isolation — a crashing process dies alone (riscv64))
}
