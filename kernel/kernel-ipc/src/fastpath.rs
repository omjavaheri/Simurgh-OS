//! ============================================================================
//! fastpath.rs
//!
//! Purpose: the L4-style IPC fast path (02-Microkernel-Layer.md §5.3):
//! for a hot `Call` on an endpoint where a receiver is already blocked
//! waiting, skip the general scheduler's fairness search and switch
//! straight to that receiver — forming part of the MVP acceptance
//! benchmark (§8.3: `ipc_call` fast path < 500 ns on reference
//! hardware). This module is the pure ELIGIBILITY predicate only; see
//! this file's "Position in the system" below for what actually
//! consumes it and exactly which overhead is (and is not yet) skipped.
//!
//! Architecture reference: 02-Microkernel-Layer.md §5.3, §8.3.
//!
//! Position in the system: `kernel-core::syscall::KernelState::do_send`
//! checks `fast_path_eligible` before delivering a `Call`. When eligible,
//! it skips `kernel-sched::Scheduler::pick_next`'s O(n) fairness scan
//! entirely — the receiver is already known, so there is nothing to
//! search for — and switches straight to it (the same "direct named-
//! thread handoff, not general fairness" pattern `kernel-core::preempt`'s
//! `terminate_thread_and_handoff`/`yield_to_thread` already established
//! for the fault-isolation demo). This is the scheduler-bookkeeping half
//! of the fast path. A FURTHER optimization — a true register-only
//! partial context switch, skipping the full GPR save/restore
//! `TrapOutcome::SwitchTo` performs today — needs an architecture
//! primitive `hal_core::HalInterface` does not expose yet; not done
//! here, tracked as a follow-up.
//!
//! Safety/invariants: `fast_path_eligible` is a pure predicate with no
//! side effects; taking the fast path must produce exactly the same
//! observable result as the slow path (§1.1 — traceable, equivalent
//! effects), only faster.
//! ============================================================================

use crate::endpoint::Endpoint;
use crate::message::SmallMessage;
use kernel_cap::ThreadId;

/// Why a `Call` did or did not qualify for the fast path — returned so the
/// benchmark harness (§8.3) and tracing can see the hit rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathDecision {
    /// Eligible: a receiver is blocked on the endpoint and the message
    /// fits in registers. `kernel-core` should perform the direct
    /// switch to `receiver`.
    Take {
        /// The blocked receiver to switch to.
        receiver: ThreadId,
    },
    /// Not eligible — fall through to the general syscall dispatch path.
    Fallback(FastPathReject),
}

/// Specific reasons the fast path was declined (for tracing / tuning).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPathReject {
    /// No receiver is currently blocked on the endpoint.
    NoBlockedReceiver,
    /// The message does not fit the fast-path register budget.
    MessageTooLarge,
    /// The caller requested behaviour (e.g. a timeout) the fast path
    /// does not implement.
    UnsupportedMode,
}

/// Pure predicate: can this `Call` on `endpoint` with `msg` take the fast
/// path? Does not mutate anything.
///
/// A `Call` is eligible when a receiver is already parked on the endpoint
/// (so the send half rendezvouses immediately) and the message is small
/// enough that the architecture handoff can keep it in registers. `msg`
/// always fits today (`SmallMessage` is register-sized by construction —
/// see `message.rs`), but the check is kept explicit so a future larger
/// message type does not silently regress the fast path.
pub fn fast_path_eligible<const Q: usize>(
    endpoint: &Endpoint<Q>,
    msg: &SmallMessage,
    blocking: bool,
) -> FastPathDecision {
    if !blocking {
        return FastPathDecision::Fallback(FastPathReject::UnsupportedMode);
    }
    if msg.len() > crate::message::MSG_MAX_WORDS {
        return FastPathDecision::Fallback(FastPathReject::MessageTooLarge);
    }
    match endpoint.blocked_receiver() {
        Some(receiver) => FastPathDecision::Take { receiver },
        None => FastPathDecision::Fallback(FastPathReject::NoBlockedReceiver),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::RecvOutcome;

    const Q: usize = 2;

    #[test]
    fn eligible_when_receiver_blocked() {
        let mut ep: Endpoint<Q> = Endpoint::new();
        assert!(matches!(
            ep.try_recv(ThreadId::new(1), true).unwrap(),
            RecvOutcome::ReceiverQueued
        ));
        let d = fast_path_eligible(&ep, &SmallMessage::new(0), true);
        assert_eq!(d, FastPathDecision::Take { receiver: ThreadId::new(1) });
    }

    #[test]
    fn fallback_when_no_receiver() {
        let ep: Endpoint<Q> = Endpoint::new();
        let d = fast_path_eligible(&ep, &SmallMessage::new(0), true);
        assert_eq!(d, FastPathDecision::Fallback(FastPathReject::NoBlockedReceiver));
    }

    #[test]
    fn fallback_when_non_blocking() {
        let ep: Endpoint<Q> = Endpoint::new();
        let d = fast_path_eligible(&ep, &SmallMessage::new(0), false);
        assert_eq!(d, FastPathDecision::Fallback(FastPathReject::UnsupportedMode));
    }
}
