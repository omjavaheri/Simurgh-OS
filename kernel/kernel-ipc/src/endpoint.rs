//! ============================================================================
//! endpoint.rs
//!
//! Purpose: `Endpoint` — the synchronous IPC rendezvous object
//! (02-Microkernel-Layer.md §5.1). A sender and a receiver "meet" at an
//! endpoint; whichever arrives first blocks until the other shows up, at
//! which point the message is copied sender→receiver and both are runnable.
//!
//! Architecture reference: 02-Microkernel-Layer.md §5.1 (`Endpoint`,
//! `ipc_call`), §6 (`Send`/`Recv`/`Call`), §4.4 (priority inheritance
//! across a blocked IPC — the hook is noted here, the mechanism lives in
//! `kernel-sched`).
//!
//! Position in the system: `kernel-core` owns the endpoint table and calls
//! `try_send` / `try_recv` from the syscall dispatcher, then hands the
//! unblocked `ThreadId` to `kernel-sched`.
//!
//! Safety/invariants:
//!   - at most one side (send OR receive) is ever non-empty — the other
//!     side draining it to zero is what a rendezvous *is*;
//!   - queue capacity is fixed (`Q`); enqueue past it returns
//!     `EndpointError::QueueFull`, never panics or drops silently.
//! ============================================================================

use crate::message::SmallMessage;
use kernel_cap::ThreadId;

/// Errors specific to endpoint operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    /// The relevant wait queue is at capacity.
    QueueFull,
}

/// Outcome of a `try_send`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// A receiver was waiting; the message is now pending delivery to this
    /// thread (retrieve it with `take_delivered`), which `kernel-core`
    /// should make runnable. The sender does not block.
    DeliveredTo(ThreadId),
    /// No receiver was waiting; the sending thread has been queued and
    /// must be blocked by `kernel-core`.
    SenderQueued,
    /// Non-blocking send only: no receiver waiting, nothing queued.
    WouldBlock,
}

/// Outcome of a `try_recv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvOutcome {
    /// A sender was waiting; its message and thread id are returned. The
    /// sender should be made runnable (a `Call` sender instead stays
    /// blocked awaiting the reply — that policy is applied by
    /// `kernel-core`, not here).
    Received {
        /// The waiting sender.
        from: ThreadId,
        /// Its message.
        msg: SmallMessage,
    },
    /// No sender was waiting; the receiving thread has been queued and
    /// must be blocked by `kernel-core`.
    ReceiverQueued,
    /// Non-blocking recv only: no sender waiting, nothing queued.
    WouldBlock,
}

/// One blocked party on an endpoint.
#[derive(Debug, Clone, Copy)]
struct Waiter {
    thread: ThreadId,
    /// For a queued sender: the message it is trying to deliver. Unused
    /// (a zero-label empty message) for a queued receiver.
    msg: SmallMessage,
}

/// A synchronous IPC endpoint with fixed-capacity send and receive queues.
/// `Q` is the max number of threads that can be blocked on either side
/// (IMPLEMENTATION-PLAN.md D1).
pub struct Endpoint<const Q: usize> {
    /// Threads blocked trying to send (each with its pending message).
    senders: [Option<Waiter>; Q],
    senders_len: usize,
    /// Threads blocked trying to receive.
    receivers: [Option<Waiter>; Q],
    receivers_len: usize,
    /// Set by `try_send` when it completes a rendezvous: the `(receiver,
    /// message)` pair `kernel-core` must inject into the receiver's saved
    /// context. Cleared by `take_delivered`.
    pending_delivery: Option<(ThreadId, SmallMessage)>,
}

impl<const Q: usize> Endpoint<Q> {
    /// Creates an endpoint with both queues empty.
    pub const fn new() -> Self {
        Self {
            senders: [None; Q],
            senders_len: 0,
            receivers: [None; Q],
            receivers_len: 0,
            pending_delivery: None,
        }
    }

    /// True if no thread is blocked on either side and no delivery is
    /// pending.
    pub fn is_idle(&self) -> bool {
        self.senders_len == 0 && self.receivers_len == 0 && self.pending_delivery.is_none()
    }

    /// The receiver at the head of the receive queue, if any. Used by the
    /// IPC fast path (`fastpath::fast_path_eligible`) to check, without
    /// mutating anything, whether a `Call` can rendezvous immediately.
    pub fn blocked_receiver(&self) -> Option<ThreadId> {
        if self.receivers_len > 0 {
            self.receivers[0].as_ref().map(|w| w.thread)
        } else {
            None
        }
    }

    /// Number of senders currently blocked.
    pub fn blocked_sender_count(&self) -> usize {
        self.senders_len
    }

    fn push(
        queue: &mut [Option<Waiter>; Q],
        len: &mut usize,
        w: Waiter,
    ) -> Result<(), EndpointError> {
        if *len >= Q {
            return Err(EndpointError::QueueFull);
        }
        // FIFO: slots fill left to right; `pop_front` shifts the rest down.
        // Q is small, so the shift is cheap and its cost is predictable —
        // which suits a future verification target.
        queue[*len] = Some(w);
        *len += 1;
        Ok(())
    }

    fn pop_front(queue: &mut [Option<Waiter>; Q], len: &mut usize) -> Option<Waiter> {
        if *len == 0 {
            return None;
        }
        let front = queue[0].take();
        for i in 1..*len {
            queue[i - 1] = queue[i].take();
        }
        *len -= 1;
        front
    }

    /// Sending thread `sender` tries to deliver `msg`.
    ///
    /// If a receiver is queued: the rendezvous completes, `msg` becomes
    /// pending delivery to that receiver, and `DeliveredTo(receiver)` is
    /// returned (sender does not block). Otherwise, if `blocking`, the
    /// sender is queued and `SenderQueued` is returned; if not `blocking`,
    /// `WouldBlock`.
    ///
    /// Postcondition: the send and receive queues are never both non-empty
    /// afterwards.
    pub fn try_send(
        &mut self,
        sender: ThreadId,
        msg: SmallMessage,
        blocking: bool,
    ) -> Result<SendOutcome, EndpointError> {
        if let Some(recv) = Self::pop_front(&mut self.receivers, &mut self.receivers_len) {
            self.pending_delivery = Some((recv.thread, msg));
            return Ok(SendOutcome::DeliveredTo(recv.thread));
        }
        if !blocking {
            return Ok(SendOutcome::WouldBlock);
        }
        Self::push(
            &mut self.senders,
            &mut self.senders_len,
            Waiter { thread: sender, msg },
        )?;
        Ok(SendOutcome::SenderQueued)
    }

    /// Receiving thread `receiver` tries to take a message.
    ///
    /// If a sender is queued, its message + thread id are returned as
    /// `Received { .. }`. Otherwise, if `blocking`, the receiver is queued
    /// and `ReceiverQueued` is returned; if not `blocking`, `WouldBlock`.
    pub fn try_recv(
        &mut self,
        receiver: ThreadId,
        blocking: bool,
    ) -> Result<RecvOutcome, EndpointError> {
        if let Some(send) = Self::pop_front(&mut self.senders, &mut self.senders_len) {
            return Ok(RecvOutcome::Received {
                from: send.thread,
                msg: send.msg,
            });
        }
        if !blocking {
            return Ok(RecvOutcome::WouldBlock);
        }
        Self::push(
            &mut self.receivers,
            &mut self.receivers_len,
            Waiter {
                thread: receiver,
                msg: SmallMessage::new(0),
            },
        )?;
        Ok(RecvOutcome::ReceiverQueued)
    }

    /// After `try_send` returned `DeliveredTo`, `kernel-core` calls this to
    /// retrieve the `(receiver, message)` it must inject into the
    /// receiver's saved context. Returns `None` if no delivery is pending.
    pub fn take_delivered(&mut self) -> Option<(ThreadId, SmallMessage)> {
        self.pending_delivery.take()
    }
}

impl<const Q: usize> Default for Endpoint<Q> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q: usize = 4;

    fn t(n: u32) -> ThreadId {
        ThreadId::new(n)
    }

    #[test]
    fn send_then_recv_rendezvous() {
        let mut ep: Endpoint<Q> = Endpoint::new();
        assert_eq!(ep.try_recv(t(1), true), Ok(RecvOutcome::ReceiverQueued));
        let msg = SmallMessage::from_words(9, &[42]).unwrap();
        assert_eq!(
            ep.try_send(t(2), msg, true),
            Ok(SendOutcome::DeliveredTo(t(1)))
        );
        assert_eq!(ep.take_delivered(), Some((t(1), msg)));
        assert!(ep.is_idle());
    }

    #[test]
    fn recv_then_send_rendezvous() {
        let mut ep: Endpoint<Q> = Endpoint::new();
        let msg = SmallMessage::new(3);
        assert_eq!(ep.try_send(t(5), msg, true), Ok(SendOutcome::SenderQueued));
        match ep.try_recv(t(6), true).unwrap() {
            RecvOutcome::Received { from, msg: m } => {
                assert_eq!(from, t(5));
                assert_eq!(m, msg);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(ep.is_idle());
    }

    #[test]
    fn non_blocking_would_block() {
        let mut ep: Endpoint<Q> = Endpoint::new();
        assert_eq!(
            ep.try_send(t(1), SmallMessage::new(0), false),
            Ok(SendOutcome::WouldBlock)
        );
        assert_eq!(ep.try_recv(t(1), false), Ok(RecvOutcome::WouldBlock));
    }

    #[test]
    fn queue_full_is_reported() {
        let mut ep: Endpoint<Q> = Endpoint::new();
        for i in 0..Q {
            assert_eq!(
                ep.try_send(t(i as u32), SmallMessage::new(0), true),
                Ok(SendOutcome::SenderQueued)
            );
        }
        assert_eq!(
            ep.try_send(t(99), SmallMessage::new(0), true),
            Err(EndpointError::QueueFull)
        );
    }
}
