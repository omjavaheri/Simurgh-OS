//! ============================================================================
//! fastpath.rs
//!
//! Purpose: the hook point for the L4-style IPC fast path
//! (02-Microkernel-Layer.md §5.3): for a hot `Call` on an endpoint where a
//! receiver is already blocked waiting, skip the full syscall/scheduler
//! machinery and switch straight to the receiver with the message left in
//! registers — taking `ipc_call` from ~microseconds to ~hundreds of
//! nanoseconds, and forming part of the MVP acceptance benchmark (§8.3:
//! `ipc_call` fast path < 500 ns on reference hardware).
//!
//! Architecture reference: 02-Microkernel-Layer.md §5.3, §8.3.
//!
//! Position in the system: `kernel-core`'s syscall entry checks
//! `fast_path_eligible` before falling through to the general `dispatch`
//! path. The actual register-to-register handoff needs an architecture
//! primitive (a partial context switch that preserves the message
//! registers) that today's `hal_core::HalInterface` does not expose.
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
