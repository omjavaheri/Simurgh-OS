//! ============================================================================
//! run.rs
//!
//! Purpose: the kernel's scheduling drive step — the "other half" of the
//! kernel loop from `syscall::dispatch`. `schedule_step` accounts the
//! outgoing thread, asks the scheduler for the next one, and performs the
//! hardware `context_switch` via the HAL.
//!
//! Architecture reference: 02-Microkernel-Layer.md §4 (scheduler), §8.2
//! (MVP: Root Task spawns a second thread and does synchronous IPC — that
//! requires exactly this switch), §0 (HAL↔kernel is a direct call — the
//! switch goes through `hal_core::HalInterface`, not IPC).
//!
//! Position in the system: `kernel-arch-glue` calls `schedule_step` after
//! building `KernelState` and on every return from `dispatch` that yields
//! `SyscallReturn::Reschedule`.
//!
//! Safety/invariants: `schedule_step` calls `HalInterface::context_switch`
//! (an `unsafe fn`) only with two non-aliasing `[u8; CONTEXT_BYTES]`
//! buffers, and only for a thread whose TCB is `Runnable` with a loaded
//! entry point. Interrupts-disabled is the caller's (arch-glue trap
//! handler's) responsibility, exactly as the HAL contract states.
//! ============================================================================

use crate::config::CONTEXT_BYTES;
use crate::state::KernelState;
use crate::tcb::ThreadState;
use hal_core::{HalInterface, VirtAddr};
use kernel_cap::ThreadId;
use kernel_sched::{RunState, SchedulerMode};

/// What one `schedule_step` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleOutcome {
    /// Switched to `to` (a real `context_switch` happened, or a cold
    /// first entry into `to`).
    Switched {
        /// The thread now running.
        to: ThreadId,
    },
    /// The scheduler picked `thread`, but it cannot be started yet — its
    /// TCB is not `Runnable` or has no loaded entry point (a zeroed
    /// context would jump to address 0). No switch performed.
    NotStartable {
        /// The thread that was picked but skipped.
        thread: ThreadId,
    },
    /// Nothing is runnable. The core should idle (wait for an interrupt).
    Idle,
}

impl KernelState {
    /// Runs one scheduling step against `hal`.
    ///
    /// 1. remember the outgoing thread (if any);
    /// 2. `scheduler.account(now)` — charge its run slice;
    /// 3. `scheduler.pick_next(now)`;
    /// 4. if the pick is startable, `scheduler.dispatch(next, now)` then
    ///    `hal.context_switch(outgoing_ctx, next_ctx)`.
    ///
    /// Returns immediately (with `Switched`) from the perspective of a
    /// cold first entry; for a warm switch, control returns here only
    /// when some later `schedule_step` switches back to `outgoing`.
    pub fn schedule_step(&mut self, hal: &HalInterface) -> ScheduleOutcome {
        let now = hal.now_ns();
        let outgoing = self.sched.running();
        self.sched.account(now);

        let Some(next) = self.sched.pick_next(now) else {
            return ScheduleOutcome::Idle;
        };

        // Startable check: Runnable + a real entry point (non-zero).
        let startable = self
            .tcb(next)
            .map(|t| t.state == ThreadState::Runnable && t.entry.as_usize() != 0)
            .unwrap_or(false);
        if !startable {
            return ScheduleOutcome::NotStartable { thread: next };
        }

        let _ = self.sched.dispatch(next, now);

        // Copy the target context out first (ends the immutable borrow),
        // then take the mutable borrow of the outgoing TCB.
        let to_bytes: [u8; CONTEXT_BYTES] = *self
            .tcb(next)
            .expect("startable implies present")
            .context
            .as_bytes();

        match outgoing {
            Some(prev) if prev != next => {
                let from = self
                    .tcb_mut(prev)
                    .expect("outgoing thread still present")
                    .context
                    .as_bytes_mut();
                // SAFETY: `from` and `to_bytes` are distinct, fully
                // initialised `[u8; CONTEXT_BYTES]` buffers; `to_bytes`
                // holds a context the scheduler vouched is `Runnable`
                // with a loaded entry point. Interrupts-off is the arch
                // trap handler's responsibility (module docs).
                unsafe { hal.context_switch(from, &to_bytes) };
            }
            Some(_) => {
                // Same thread re-picked: nothing to switch.
            }
            None => {
                // Cold start: there is no outgoing context worth saving.
                // With only `context_switch` available (no dedicated
                // "jump into context" primitive yet — Q2), save into a
                // throwaway buffer.
                let mut scratch = [0u8; CONTEXT_BYTES];
                // SAFETY: `scratch` and `to_bytes` are distinct valid
                // buffers; see the branch above.
                unsafe { hal.context_switch(&mut scratch, &to_bytes) };
            }
        }

        ScheduleOutcome::Switched { to: next }
    }

    /// Makes a freshly-`Retype`d TCB runnable: seeds its saved context to
    /// begin executing `entry` (a `-> !` function) on `stack_top`, admits
    /// it to the scheduler (Interactive mode, mid priority), and marks it
    /// `Ready` / `Runnable`.
    ///
    /// Used by the in-kernel Root Task to bring up a second thread
    /// (02-Microkernel-Layer.md §8.2). A real `TCB_Resume`-style syscall
    /// replaces this once the trap boundary exists.
    pub fn start_thread(
        &mut self,
        tid: ThreadId,
        entry: usize,
        stack_top: usize,
        hal: &HalInterface,
    ) {
        if let Some(tcb) = self.tcb_mut(tid) {
            hal.init_context(tcb.context.as_bytes_mut(), entry, stack_top);
            tcb.entry = VirtAddr::new(entry);
            tcb.state = ThreadState::Runnable;
        }
        let _ = self.sched.admit(tid, SchedulerMode::Interactive, 20, None);
        let _ = self.sched.note_ready(tid, hal.now_ns());
    }

    /// Directly switches the CPU from thread `from` to thread `to`,
    /// saving `from`'s register context into its TCB (so a later switch
    /// back to `from` resumes right after this call).
    ///
    /// This is how the in-kernel Root Task hands the CPU to a thread it
    /// just started, or to a thread an IPC rendezvous just unblocked,
    /// when it got a `SyscallReturn::Reschedule` from `dispatch`. A no-op
    /// if `from == to`.
    ///
    /// # Panics
    /// If either `from` or `to` names an absent TCB.
    pub fn yield_to(&mut self, from: ThreadId, to: ThreadId, hal: &HalInterface) {
        if from == to {
            return;
        }
        let now = hal.now_ns();
        // `from` is giving up the CPU cooperatively. If it has not
        // already blocked itself (e.g. via `dispatch(Recv)` earlier in
        // this call chain), it stays schedulable — mark it `Ready` so a
        // later `pick_next` can return to it.
        let from_running = matches!(
            self.sched.entity(from).map(|e| e.state),
            Some(RunState::Running)
        );
        if from_running {
            let _ = self.sched.note_ready(from, now);
        }
        let _ = self.sched.dispatch(to, now);
        let to_bytes: [u8; CONTEXT_BYTES] =
            *self.tcb(to).expect("yield_to: `to` TCB present").context.as_bytes();
        let from_ctx = self
            .tcb_mut(from)
            .expect("yield_to: `from` TCB present")
            .context
            .as_bytes_mut();
        // SAFETY: `from != to` (checked), both are valid initialised
        // contexts, and this is the single-core in-kernel MVP path with
        // interrupts not yet enabled — matching `context_switch`'s
        // contract.
        unsafe { hal.context_switch(from_ctx, &to_bytes) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use hal_core::cpu::{CpuAbstraction, CpuContext, CpuFeatureFlags, PrivilegeLevel};
    use hal_core::timer::{TimerAbstraction, TimerCallback, TimerMode};
    use hal_core::{BootInfo, BootProtocol, HalError, HAL_CONTEXT_BYTES};
    use hal_manifest::raw::{
        HardwareManifestRaw, MemoryRegionKindRaw, MemoryRegionRaw, TimerInfoRaw, TimerKindRaw,
    };

    struct MockCpu {
        switches: Cell<u32>,
    }
    impl CpuAbstraction<HAL_CONTEXT_BYTES> for MockCpu {
        fn core_count(&self) -> usize {
            1
        }
        fn current_core_id(&self) -> usize {
            0
        }
        fn feature_flags(&self) -> CpuFeatureFlags {
            CpuFeatureFlags::empty()
        }
        unsafe fn context_switch(
            &self,
            from: &mut CpuContext<HAL_CONTEXT_BYTES>,
            to: &CpuContext<HAL_CONTEXT_BYTES>,
        ) {
            self.switches.set(self.switches.get() + 1);
            *from.as_bytes_mut() = *to.as_bytes();
        }
        fn set_privilege_level(&self, _l: PrivilegeLevel) -> Result<(), HalError> {
            Ok(())
        }
        fn bootstrap_current_core(&self) -> Result<(), HalError> {
            Ok(())
        }
    }

    struct MockTimer {
        now: Cell<u64>,
    }
    impl TimerAbstraction for MockTimer {
        fn now_ns(&self) -> u64 {
            self.now.get()
        }
        fn set_oneshot(&self, _d: u64, _m: TimerMode) -> Result<(), HalError> {
            Ok(())
        }
        fn cancel_oneshot(&self) {}
        fn set_tickless(&self, _e: bool) -> Result<(), HalError> {
            Ok(())
        }
        fn set_timer_callback(&self, _c: TimerCallback) {}
        fn supports_tickless(&self) -> bool {
            false
        }
        fn frequency_hz(&self) -> u64 {
            1_000_000_000
        }
    }

    struct MockInterrupt;
    impl hal_core::interrupt::InterruptController for MockInterrupt {
        fn register_irq(
            &self,
            _irq: hal_core::interrupt::IrqId,
            _handler: hal_core::interrupt::IrqHandler,
        ) -> Result<(), HalError> {
            Ok(())
        }
        fn unregister_irq(&self, _irq: hal_core::interrupt::IrqId) {}
        fn mask_irq(&self, _irq: hal_core::interrupt::IrqId) -> Result<(), HalError> {
            Ok(())
        }
        fn unmask_irq(&self, _irq: hal_core::interrupt::IrqId) -> Result<(), HalError> {
            Ok(())
        }
        fn send_ipi(&self, _target_core: usize, _vector: u8) -> Result<(), HalError> {
            Ok(())
        }
        fn irq_line_count(&self) -> u32 {
            64
        }
        fn ipi_target_core_count(&self) -> u32 {
            1
        }
        fn end_of_interrupt(&self, _irq: hal_core::interrupt::IrqId) {}
    }

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
    fn root_task_without_loaded_image_is_not_startable() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        let cpu = MockCpu { switches: Cell::new(0) };
        let timer = MockTimer { now: Cell::new(1000) };
        let irqc = MockInterrupt;
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);

        // Root Task exists and is Runnable, but entry == 0 (no image).
        assert_eq!(
            k.schedule_step(&hal),
            ScheduleOutcome::NotStartable {
                thread: k.root_thread
            }
        );
        assert_eq!(cpu.switches.get(), 0);
    }

    #[test]
    fn cold_start_switches_into_a_thread_with_an_entry_point() {
        let mut k = KernelState::from_boot_info(&boot()).unwrap();
        // Pretend an image loader set the Root Task's entry point and
        // seeded a byte into its context.
        {
            let t = k.tcb_mut(k.root_thread).unwrap();
            t.entry = hal_core::VirtAddr::new(0x20_0000);
            t.context.as_bytes_mut()[0] = 0x11;
        }
        let cpu = MockCpu { switches: Cell::new(0) };
        let timer = MockTimer { now: Cell::new(2000) };
        let irqc = MockInterrupt;
        let hal = hal_core::build_interface(&cpu, &timer, &irqc);

        let out = k.schedule_step(&hal);
        assert_eq!(
            out,
            ScheduleOutcome::Switched {
                to: k.root_thread
            }
        );
        assert_eq!(cpu.switches.get(), 1);
        assert_eq!(k.sched.running(), Some(k.root_thread));
    }
}
