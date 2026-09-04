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

// ============================================================================
// Stateful driver recovery — REPO-Simurgh-OS-Remediation.md item 09.
//
// `Supervised` above already proves the restart MECHANISM end to end on
// QEMU (03 §5.2's own acceptance test); what it does not address is
// STATE: the current restart policy implicitly assumes a driver is
// stateless, so an I/O request that was in flight when the driver
// crashed is simply lost. `RequestLog` is the per-driver accounting a
// supervisor needs to know which requests were still outstanding at
// the moment of a crash, so they can be replayed (or reported as
// idempotent-safe failures) once the replacement process comes up.
//
// Scope note: this is the POLICY/accounting half only — pure,
// host-testable, capacity-bounded — mirroring `Supervised`'s own
// scope. Actually wiring this into a real Device Manager process (so
// every client request is observed here before reaching a driver, and
// replayed after a real restart) needs client requests to route
// THROUGH Device Manager rather than directly to a driver's own
// Endpoint, which is a real, separate architectural decision (today's
// demo traffic goes straight from a client to the driver's own
// Endpoint, bypassing Device Manager entirely) — deliberately not
// decided or implemented here, same as this crate's own `subsystem_
// entry` module doc comment already draws that exact "mechanism proven,
// full real-driver wiring is the acceptance test" boundary.
// ============================================================================

/// One in-flight (not yet acknowledged) request a supervised driver is
/// known to be working on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InFlightRequest {
    /// The client-supplied identifier this request was submitted with —
    /// stable across a crash+restart, so both the log and the client
    /// itself can recognise a replay of the same logical request
    /// (server-side idempotency: processing it twice must be safe).
    pub request_id: u32,
}

/// How many in-flight requests one driver's log tracks at once before
/// Device Manager must start rejecting new ones with `DriverBusy`
/// rather than growing unbounded.
pub const MAX_IN_FLIGHT_REQUESTS: usize = 256;

/// Why `RequestLog::try_insert` refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestLogError {
    /// The log already holds `MAX_IN_FLIGHT_REQUESTS` entries — the
    /// caller should reply `DriverBusy` (`ipc_protocol::driver::
    /// DriverErrorCode`) rather than accept more work this driver has
    /// not yet caught up on.
    Full,
}

/// The in-flight request log for ONE supervised driver (Device Manager
/// holds one of these per driver it supervises, alongside that
/// driver's own `Supervised` record).
#[derive(Debug, Clone, Copy)]
pub struct RequestLog {
    entries: [Option<InFlightRequest>; MAX_IN_FLIGHT_REQUESTS],
    len: usize,
}

impl RequestLog {
    /// An empty log.
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_IN_FLIGHT_REQUESTS],
            len: 0,
        }
    }

    /// How many requests are currently tracked as in-flight.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Records a request as in-flight, right before it is handed to the
    /// driver — per this item's own log-size/backpressure requirement,
    /// refuses (`Err(RequestLogError::Full)`) rather than growing past
    /// `MAX_IN_FLIGHT_REQUESTS`. A duplicate `request_id` already
    /// present is left as-is (idempotent no-op, not a second entry) —
    /// a client retrying the exact same request it never got a reply
    /// for should not itself trip the capacity limit.
    #[inline(always)]
    pub fn try_insert(&mut self, request_id: u32) -> Result<(), RequestLogError> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|e| e.request_id == request_id)
        {
            return Ok(());
        }
        if self.len >= MAX_IN_FLIGHT_REQUESTS {
            return Err(RequestLogError::Full);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|e| e.is_none())
            .expect("len < MAX_IN_FLIGHT_REQUESTS implies a free slot exists");
        *slot = Some(InFlightRequest { request_id });
        self.len += 1;
        Ok(())
    }

    /// Removes a request from the log once its reply has actually been
    /// delivered — per this item's own cleanup requirement, the log
    /// only ever holds requests genuinely in flight, never full
    /// history. Acknowledging an id the log does not hold (already
    /// removed, or never inserted) is a safe no-op, not an error —
    /// acks are not expected to race with replay in a way this method
    /// needs to reject.
    #[inline(always)]
    pub fn ack(&mut self, request_id: u32) {
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|e| matches!(e, Some(r) if r.request_id == request_id))
        {
            *slot = None;
            self.len -= 1;
        }
    }

    /// The requests still in flight, in no particular order — what
    /// Device Manager replays against a freshly restarted driver.
    pub fn in_flight(&self) -> impl Iterator<Item = &InFlightRequest> {
        self.entries.iter().flatten()
    }
}

impl Default for RequestLog {
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

    #[test]
    fn request_log_tracks_and_acks() {
        let mut log = RequestLog::new();
        assert!(log.is_empty());
        log.try_insert(1).unwrap();
        log.try_insert(2).unwrap();
        assert_eq!(log.len(), 2);
        log.ack(1);
        assert_eq!(log.len(), 1);
        assert!(log.in_flight().any(|r| r.request_id == 2));
        assert!(!log.in_flight().any(|r| r.request_id == 1));
    }

    #[test]
    fn request_log_duplicate_insert_is_a_noop() {
        let mut log = RequestLog::new();
        log.try_insert(42).unwrap();
        log.try_insert(42).unwrap();
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn request_log_ack_unknown_id_is_a_safe_noop() {
        let mut log = RequestLog::new();
        log.try_insert(1).unwrap();
        log.ack(999); // never inserted
        assert_eq!(log.len(), 1);
        log.ack(1);
        log.ack(1); // already gone - acking twice must not panic/underflow
        assert!(log.is_empty());
    }

    #[test]
    fn request_log_rejects_past_capacity_with_busy() {
        let mut log = RequestLog::new();
        for id in 0..MAX_IN_FLIGHT_REQUESTS as u32 {
            assert!(log.try_insert(id).is_ok());
        }
        assert_eq!(log.len(), MAX_IN_FLIGHT_REQUESTS);
        assert_eq!(
            log.try_insert(MAX_IN_FLIGHT_REQUESTS as u32),
            Err(RequestLogError::Full)
        );
        // Freeing exactly one slot (an ack) makes room for exactly one
        // more - not an error, not silently dropped.
        log.ack(0);
        assert!(log.try_insert(MAX_IN_FLIGHT_REQUESTS as u32).is_ok());
    }

    #[test]
    fn request_log_in_flight_lists_only_unacked_entries() {
        let mut log = RequestLog::new();
        log.try_insert(1).unwrap();
        log.try_insert(2).unwrap();
        log.try_insert(3).unwrap();
        log.ack(2);
        let mut ids: [u32; 4] = [0; 4];
        let mut n = 0;
        for r in log.in_flight() {
            ids[n] = r.request_id;
            n += 1;
        }
        ids[..n].sort_unstable();
        assert_eq!(&ids[..n], &[1, 3]);
    }
}
