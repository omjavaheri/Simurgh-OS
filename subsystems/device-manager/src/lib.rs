//! ============================================================================
//! device-manager
//!
//! Purpose: supervise driver processes. Each driver runs in its own
//! isolated process with a capability set scoped to exactly one device (its
//! MMIO region + its IRQ line — 03-Kernel-Subsystems-Layer.md §2.1). When a
//! driver crashes, the Device Manager brings it back up in a *new* process
//! without disturbing the rest of the system — "مهم‌ترین دستاورد کل معماری
//! در برابر لینوکس مونولیتیک" (§2.1), and an automated MVP acceptance test
//! (§5.2).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (isolation,
//! scoped capabilities, restart policy), §5.1 (bring up a virtio-blk
//! driver), §5.2 (injected panic → automatic restart).
//!
//! Position in the system: an isolated layer-3 process, started by the Root
//! Task. Talks to drivers with `ipc_protocol::DriverRequest`/`DriverResponse`
//! and to the kernel via syscalls (capability grants, process spawn).
//!
//! MVP scope: `Supervised`/`DriverState` — the restart-policy state
//! machine — are pure and host-testable (`#[cfg(test)]` below). The
//! `subsystem_entry` module (riscv64-only) is this crate's first REAL
//! process entry point: it runs `Supervised` through a scripted
//! probe/crash/respawn lifecycle as a genuinely isolated U-mode process,
//! spawned by `kernel-arch-glue::spawn_process` and launched from
//! `root-task`'s `plan_boot` decision — proof the layer-2 TCB-load /
//! process-spawn path this crate's own docs used to say was pending now
//! exists and a real `subsystems/*` crate can run on it. It does not yet
//! talk to a real driver over IPC (no driver process exists to crash on
//! its own yet) — that remains the actual §5.2 acceptance test.
//!
//! Safety/invariants: the restart policy has a bounded retry budget and a
//! back-off, so a driver that crashes in a tight loop is eventually parked
//! `Failed` rather than restarted forever.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

/// This crate's first real process entry point (riscv64/x86_64/
/// aarch64 — all three architectures now have their "P2 demo parity"
/// milestone wired up). See the module's own doc comment.
#[cfg(any(
    target_arch = "riscv64",
    target_arch = "x86_64",
    target_arch = "aarch64"
))]
pub mod subsystem_entry;

/// How many times the Device Manager will restart one driver within the
/// failure window before giving up and leaving it `Failed`.
pub const MAX_RESTARTS_IN_WINDOW: u32 = 5;

/// The failure window, in nanoseconds. Restarts older than this are
/// forgiven (the counter effectively decays).
pub const FAILURE_WINDOW_NS: u64 = 60_000_000_000; // 60 s

/// A driver's supervision state.
///
/// Possible values and their meaning:
/// - `Starting`: the process has been spawned; awaiting its `Probe` reply.
/// - `Running`: probed successfully and serving requests.
/// - `Restarting`: crashed (or failed `Probe`) and within its restart
///   budget; a fresh process is being spawned.
/// - `Failed`: exceeded `MAX_RESTARTS_IN_WINDOW`; parked. An operator /
///   higher layer must intervene. The rest of the system is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    /// Spawned, awaiting `Probe` reply.
    Starting,
    /// Probed, serving requests.
    Running,
    /// Crashed within budget; respawning.
    Restarting,
    /// Restart budget exhausted; parked.
    Failed,
}

/// Per-driver supervision record.
#[derive(Debug, Clone, Copy)]
pub struct Supervised {
    /// Current state.
    pub state: DriverState,
    /// Restarts counted within the current failure window.
    pub restarts_in_window: u32,
    /// Monotonic time of the first restart in the current window (0 if
    /// none yet).
    pub window_start_ns: u64,
    /// Total lifetime restarts (diagnostic).
    pub lifetime_restarts: u64,
}

impl Supervised {
    /// A freshly spawned driver.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            state: DriverState::Starting,
            restarts_in_window: 0,
            window_start_ns: 0,
            lifetime_restarts: 0,
        }
    }

    /// The driver reported a successful `Probe`.
    #[inline(always)]
    pub fn on_probe_ok(&mut self) {
        self.state = DriverState::Running;
    }

    /// The driver crashed or failed `Probe` at `now_ns`. Updates the
    /// restart accounting and returns the new state: `Restarting` if the
    /// Device Manager should spawn a fresh process, `Failed` if the budget
    /// is exhausted.
    ///
    /// Postcondition: `state` is exactly the returned value;
    /// `lifetime_restarts` increased by one.
    ///
    /// `#[inline(always)]` on every method here (not just this one) is
    /// deliberate, not a performance tweak: `subsystem_entry::
    /// subsystem_main` runs from `.user_text`, a page range mapped `U=1`
    /// in a spawned process's OWN address space — a real function *call*
    /// into this crate's normal `.text` (mapped `U=0`, kernel-only) would
    /// fault the instant U-mode tried to fetch from it. Forcing every
    /// `Supervised` method to inline keeps its logic entirely inside the
    /// caller's own compiled body, so no such call ever exists in the
    /// object code (verified via `llvm-objdump` when this was added).
    pub fn on_crash(&mut self, now_ns: u64) -> DriverState {
        self.lifetime_restarts += 1;

        // Decay: if the window has elapsed, start a new one.
        if self.window_start_ns == 0 || now_ns.saturating_sub(self.window_start_ns) > FAILURE_WINDOW_NS
        {
            self.window_start_ns = now_ns;
            self.restarts_in_window = 0;
        }
        self.restarts_in_window += 1;

        self.state = if self.restarts_in_window > MAX_RESTARTS_IN_WINDOW {
            DriverState::Failed
        } else {
            DriverState::Restarting
        };
        self.state
    }

    /// The replacement process has been spawned; back to `Starting`.
    #[inline(always)]
    pub fn on_respawn(&mut self) {
        if self.state == DriverState::Restarting {
            self.state = DriverState::Starting;
        }
    }
}

impl Default for Supervised {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_within_budget_restarts() {
        let mut d = Supervised::new();
        d.on_probe_ok();
        assert_eq!(d.on_crash(1_000), DriverState::Restarting);
        d.on_respawn();
        assert_eq!(d.state, DriverState::Starting);
    }

    #[test]
    fn crash_loop_eventually_fails() {
        let mut d = Supervised::new();
        for i in 0..=MAX_RESTARTS_IN_WINDOW {
            let st = d.on_crash(1_000 + i as u64);
            if i < MAX_RESTARTS_IN_WINDOW {
                assert_eq!(st, DriverState::Restarting);
            } else {
                assert_eq!(st, DriverState::Failed);
            }
        }
    }

    #[test]
    fn window_decay_forgives_old_restarts() {
        let mut d = Supervised::new();
        d.on_crash(0);
        // Much later: window elapsed, counter resets.
        let st = d.on_crash(FAILURE_WINDOW_NS + 1_000_000_000);
        assert_eq!(st, DriverState::Restarting);
        assert_eq!(d.restarts_in_window, 1);
    }
}
