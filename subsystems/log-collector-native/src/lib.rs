//! # log-collector-native
//!
//! Purpose: the real, kernel-side Log Collector service — the layer-3
//! MECHANISM half 04-System-Services-Policy-Layer-v2.md §2.2 describes,
//! answering `simurgh-diagnostics::diagnostics-manager` (a separate,
//! out-of-tree repo, the POLICY half) real queries over real IPC.
//!
//! Architecture reference: 04-System-Services-Policy-Layer-v2.md §2.2.
//! `simurgh-diagnostics`'s own README/module doc comments (confirmed by
//! direct research before this crate existed): a real CLIENT-side
//! transport already existed there with no real peer to talk to. This
//! crate is that peer.
//!
//! Position in the system: a real, isolated Simurgh-OS subsystem process
//! ("subsystems as processes" packaging, `src/bin/log-collector-native-
//! bin.rs`), spawned and wired by `kernel-arch-glue`/`kernel/kernel/src/
//! main.rs` (x86_64 boot sequence only for this first pass — see this
//! repo's own top-level `README.md` for why).
//!
//! Design note, not an oversight: this service holds events as opaque
//! byte blobs (`log_wire::EventBlob`), never as a typed Rust struct — see
//! `log_wire`'s own module doc comment for the full reasoning (this
//! service never needs to inspect a single field of what it stores).
//!
//! `#![no_std] + alloc`: this crate is consumed two ways — as a `no_std`
//! library linked into a real, separately-built Simurgh-OS subsystem
//! binary, and, unchanged, as a normal host-target crate for `cargo
//! test`'s own harness.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod log_wire;
pub mod subsystem_entry;

use alloc::collections::VecDeque;
use log_wire::EventBlob;

/// How many events [`EventQueue`] keeps before evicting the OLDEST —
/// real, bounded memory use for a process with no way to know how many
/// real crash events might arrive before `simurgh-diagnostics` gets
/// around to draining them (same "bounded, oldest-evicted-first" shape
/// `Simurgh-UI-Template01::ui-core::desktop::Window`'s own content
/// buffer and `simurgh-shell::shell_core::LineEditor`'s own history
/// already establish elsewhere in this project). Small on purpose: this
/// service's own real MVP scope is "prove the mechanism works," not
/// "survive an unbounded flood" — 8 is generous for that.
pub const MAX_QUEUED_EVENTS: usize = 8;

/// A real, bounded FIFO queue of pending crash-event blobs — oldest
/// first out, matching a log's own natural "report what happened, in
/// order" semantics (distinct from `Window`'s own newest-visible
/// scrollback, which is a DISPLAY concern this service has none of).
#[derive(Debug, Default)]
pub struct EventQueue {
    events: VecDeque<EventBlob>,
}

impl EventQueue {
    pub fn new() -> Self {
        Self { events: VecDeque::new() }
    }

    /// Enqueues `blob`, evicting the OLDEST entry first if this would
    /// exceed [`MAX_QUEUED_EVENTS`].
    pub fn push(&mut self, blob: EventBlob) {
        if self.events.len() >= MAX_QUEUED_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(blob);
    }

    /// Removes and returns the oldest pending event, if any.
    pub fn pop(&mut self) -> Option<EventBlob> {
        self.events.pop_front()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(fill: u8) -> EventBlob {
        [fill; log_wire::BULK_TOTAL_SIZE]
    }

    #[test]
    fn a_fresh_queue_is_empty() {
        let q = EventQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn push_then_pop_round_trips_the_exact_bytes() {
        let mut q = EventQueue::new();
        q.push(blob(7));
        assert_eq!(q.pop(), Some(blob(7)));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn events_drain_oldest_first() {
        let mut q = EventQueue::new();
        q.push(blob(1));
        q.push(blob(2));
        q.push(blob(3));
        assert_eq!(q.pop(), Some(blob(1)));
        assert_eq!(q.pop(), Some(blob(2)));
        assert_eq!(q.pop(), Some(blob(3)));
    }

    #[test]
    fn pushing_past_the_cap_evicts_the_oldest_event() {
        let mut q = EventQueue::new();
        for i in 0..(MAX_QUEUED_EVENTS + 3) {
            q.push(blob(i as u8));
        }
        assert_eq!(q.len(), MAX_QUEUED_EVENTS);
        // The first 3 pushed (0, 1, 2) were evicted; oldest surviving is 3.
        assert_eq!(q.pop(), Some(blob(3)));
    }
}
