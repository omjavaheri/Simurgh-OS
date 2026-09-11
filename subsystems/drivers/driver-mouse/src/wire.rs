//! ============================================================================
//! wire.rs — driver-mouse -> Compositor wire encoding
//!
//! Purpose: the tiny, LOCALLY-scoped message shape this driver sends to
//! Compositor over its own dedicated `Endpoint` — mirrors `driver_
//! i8042::wire`'s own identical convention (see that module's own doc
//! comment for the full rationale: this edge carries exactly one
//! message kind, fire-and-forget, so no namespace-byte/opcode scheme is
//! needed).
//! ============================================================================

use kernel_ipc::SmallMessage;

use crate::mouse_packet::MouseEvent;

/// The one message label this edge ever carries.
const MOUSE_EVENT_LABEL: u64 = 1;

/// Encodes a [`MouseEvent`] as `{ label: MOUSE_EVENT_LABEL, words: [dx,
/// dy, buttons] }` — `dx`/`dy` travel as their own raw bit pattern
/// (`i16 as u16 as u64`), decoded back the same way; `buttons` packs
/// left/right/middle into bits 0/1/2.
pub fn encode_mouse_event(event: MouseEvent) -> SmallMessage {
    let buttons = (event.left as u64) | ((event.right as u64) << 1) | ((event.middle as u64) << 2);
    SmallMessage::from_words(
        MOUSE_EVENT_LABEL,
        &[event.dx as u16 as u64, event.dy as u16 as u64, buttons],
    )
    .unwrap_or(SmallMessage::new(MOUSE_EVENT_LABEL))
}

/// Decodes a [`MouseEvent`] from the wire shape [`encode_mouse_event`]
/// writes. `None` if `msg` is not a well-formed mouse event.
pub fn decode_mouse_event(msg: &SmallMessage) -> Option<MouseEvent> {
    if msg.label != MOUSE_EVENT_LABEL {
        return None;
    }
    let words = msg.words();
    if words.len() < 3 {
        return None;
    }
    let buttons = words[2];
    Some(MouseEvent {
        dx: words[0] as u16 as i16,
        dy: words[1] as u16 as i16,
        left: buttons & 1 != 0,
        right: buttons & 2 != 0,
        middle: buttons & 4 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mouse_event_round_trips_through_encode_decode() {
        let event = MouseEvent { dx: 12, dy: -7, left: true, right: false, middle: true };
        assert_eq!(decode_mouse_event(&encode_mouse_event(event)), Some(event));
    }

    #[test]
    fn negative_deltas_round_trip_correctly() {
        let event = MouseEvent { dx: -128, dy: -1, left: false, right: false, middle: false };
        assert_eq!(decode_mouse_event(&encode_mouse_event(event)), Some(event));
    }

    #[test]
    fn a_message_with_the_wrong_label_is_rejected() {
        let msg = SmallMessage::from_words(0xDEAD, &[1, 2, 3]).unwrap();
        assert_eq!(decode_mouse_event(&msg), None);
    }

    #[test]
    fn a_truncated_message_is_rejected() {
        let msg = SmallMessage::from_words(MOUSE_EVENT_LABEL, &[1, 2]).unwrap();
        assert_eq!(decode_mouse_event(&msg), None);
    }
}
