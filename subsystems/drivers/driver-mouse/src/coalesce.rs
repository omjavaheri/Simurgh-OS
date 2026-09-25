//! ============================================================================
//! coalesce.rs — merge a drained run of PS/2 packets into as few events
//! as possible, without ever moving or losing a click
//!
//! Purpose: part of the input-latency work (2026-09-24). Every event this
//! driver sends is one blocking `Call` to the Compositor, and the
//! Compositor only takes ONE driver message per display request it serves
//! (its own `subsystem_main` loop). With one message per 3-byte packet,
//! motion arriving faster than those requests queues up behind that
//! one-per-request gate and the cursor trails the hand by the backlog.
//! Summing a whole drained run into one event makes each round trip carry
//! all motion so far, so the lag is bounded by one round trip instead of
//! growing with the backlog. (At a steady ~100 Hz the measured desktop
//! keeps up either way — one packet per wake — so this matters when the
//! guest falls behind, not in the common case.)
//!
//! The one rule that keeps this exact rather than approximate: a
//! consumer applies each event as "move by (dx, dy), THEN take the new
//! button state" (`ui-core`'s `Desktop::apply_mouse_delta` then
//! `apply_mouse_buttons`, which clicks at the cursor position). So a run
//! of packets may only be merged while the button state stays equal to
//! the state the consumer last saw; the packet that CHANGES the buttons
//! closes the run (its own motion included, since it happened before the
//! change was reported) and goes out immediately. Result: every press
//! and release edge is delivered as its own event, at exactly the
//! position the unmerged stream would have clicked at — a press and a
//! release in the same drain become two events, never one that cancels
//! out.
//!
//! Deltas are summed in `i16` (the wire's own width, `crate::wire`);
//! a sum that would overflow is sent first rather than saturated, so no
//! motion is lost either.
//! ============================================================================

use crate::mouse_packet::MouseEvent;

fn same_buttons(a: &MouseEvent, b: &MouseEvent) -> bool {
    a.left == b.left && a.right == b.right && a.middle == b.middle
}

/// Accumulates decoded packets; see the module doc comment.
#[derive(Debug, Default)]
pub struct Coalescer {
    /// Motion (and current buttons) not yet sent. `None` = nothing
    /// pending.
    pending: Option<MouseEvent>,
    /// The button state the consumer has last been sent (all released
    /// at boot, matching the device's own power-on state).
    sent: MouseEvent,
}

impl Coalescer {
    pub const fn new() -> Self {
        Self {
            pending: None,
            sent: MouseEvent { dx: 0, dy: 0, left: false, right: false, middle: false },
        }
    }

    /// Feeds one decoded packet. `emit` is called for every event that
    /// must go out NOW (in order): at most twice per packet — once for
    /// pending motion that would otherwise overflow, once for a button
    /// change.
    pub fn push(&mut self, packet: MouseEvent, mut emit: impl FnMut(MouseEvent)) {
        let merged = match self.pending {
            None => Some(packet),
            Some(p) => match (p.dx.checked_add(packet.dx), p.dy.checked_add(packet.dy)) {
                (Some(dx), Some(dy)) => Some(MouseEvent { dx, dy, ..packet }),
                _ => None,
            },
        };
        let acc = match merged {
            Some(acc) => acc,
            None => {
                // Overflow: send what is pending (its buttons are still
                // `sent`'s, so this is pure motion), then start over.
                if let Some(p) = self.pending.take() {
                    emit(p);
                }
                packet
            }
        };
        if same_buttons(&acc, &self.sent) {
            self.pending = Some(acc);
        } else {
            self.pending = None;
            self.sent = acc;
            emit(acc);
        }
    }

    /// Takes whatever motion is still pending (e.g. at the end of a
    /// drain), if any. Its buttons equal the last state sent.
    pub fn take(&mut self) -> Option<MouseEvent> {
        let p = self.pending.take()?;
        if p.dx == 0 && p.dy == 0 {
            // Nothing the consumer could observe: same buttons, no motion.
            return None;
        }
        Some(p)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn mv(dx: i16, dy: i16) -> MouseEvent {
        MouseEvent { dx, dy, left: false, right: false, middle: false }
    }

    fn run(packets: &[MouseEvent]) -> Vec<MouseEvent> {
        let mut c = Coalescer::new();
        let mut out = Vec::new();
        for &p in packets {
            c.push(p, |e| out.push(e));
        }
        out.extend(c.take());
        out
    }

    /// What a consumer that applies "move, then buttons" ends up doing:
    /// the list of (x, y) positions at which a left press edge happens,
    /// plus the final position.
    fn clicks_and_end(events: &[MouseEvent]) -> (Vec<(i32, i32)>, (i32, i32)) {
        let (mut x, mut y, mut left) = (0i32, 0i32, false);
        let mut clicks = Vec::new();
        for e in events {
            x += e.dx as i32;
            y += e.dy as i32;
            if e.left && !left {
                clicks.push((x, y));
            }
            left = e.left;
        }
        (clicks, (x, y))
    }

    #[test]
    fn pure_motion_becomes_one_summed_event() {
        let out = run(&[mv(3, 1), mv(4, -2), mv(-1, 5)]);
        assert_eq!(out, [mv(6, 4)]);
    }

    #[test]
    fn a_press_and_release_in_one_drain_stay_two_events() {
        let press = MouseEvent { left: true, ..mv(0, 0) };
        let release = mv(0, 0);
        let out = run(&[mv(5, 0), press, release]);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(out[0].left && out[0].dx == 5, "the press carries the motion before it");
        assert!(!out[1].left);
    }

    #[test]
    fn clicks_happen_exactly_where_the_unmerged_stream_clicks() {
        let down = |dx| MouseEvent { dx, dy: 0, left: true, right: false, middle: false };
        let stream = [mv(2, 0), mv(3, 1), down(4), down(1), down(1), mv(7, 0), mv(1, 1), down(0), mv(2, 2)];
        let merged = run(&stream);
        assert_eq!(clicks_and_end(&merged), clicks_and_end(&stream));
        assert!(merged.len() < stream.len());
    }

    #[test]
    fn motion_while_a_button_is_held_is_merged_too() {
        let down = |dx| MouseEvent { dx, dy: 0, left: true, right: false, middle: false };
        let out = run(&[down(0), down(3), down(4)]);
        assert_eq!(out, [down(0), down(7)]);
    }

    #[test]
    fn every_button_is_an_edge_not_just_left() {
        let mid = MouseEvent { middle: true, ..mv(0, 0) };
        let right = MouseEvent { right: true, ..mv(0, 0) };
        let out = run(&[mid, mv(0, 0), right, mv(0, 0)]);
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn an_overflowing_sum_is_sent_first_not_saturated() {
        let out = run(&[mv(i16::MAX - 10, 0), mv(20, 0)]);
        let total: i32 = out.iter().map(|e| e.dx as i32).sum();
        assert_eq!(total, i16::MAX as i32 + 10);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn no_motion_and_no_change_sends_nothing() {
        assert!(run(&[mv(0, 0), mv(0, 0)]).is_empty());
    }
}
