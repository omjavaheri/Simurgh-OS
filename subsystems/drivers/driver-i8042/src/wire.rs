//! ============================================================================
//! wire.rs — driver-i8042 -> Compositor wire encoding
//!
//! Purpose: the tiny, LOCALLY-scoped message shape this driver sends to
//! Compositor over its own dedicated `Endpoint` (`kernel_arch_glue::
//! wire_service_endpoint`'s own edge, distinct from `ipc-protocol`'s
//! real `DisplayProtocol` namespace `ui-core` uses — this edge carries
//! exactly one message kind, fire-and-forget, so it does not need a
//! namespace-byte/opcode scheme the way a real multi-request protocol
//! would). Mirrors `simurgh-account-manager::session_manager::wire`'s
//! own "small, locally-agreed `SmallMessage` shape" convention from this
//! same project's earlier real-IPC work.
//! ============================================================================

use kernel_ipc::SmallMessage;

use crate::scancode::KeyEvent;

/// The one message label this edge ever carries — no dispatch needed on
/// the receiving side, unlike a real multi-opcode protocol.
const KEY_EVENT_LABEL: u64 = 1;

/// Encodes a [`KeyEvent`] as `{ label: KEY_EVENT_LABEL, words: [keycode,
/// pressed] }` — trivially fits `SmallMessage`'s own word budget.
pub fn encode_key_event(event: KeyEvent) -> SmallMessage {
    SmallMessage::from_words(KEY_EVENT_LABEL, &[event.keycode as u64, event.pressed as u64])
        .unwrap_or(SmallMessage::new(KEY_EVENT_LABEL))
}

/// Decodes a [`KeyEvent`] from the wire shape [`encode_key_event`]
/// writes. `None` if `msg` is not a well-formed key event (wrong label,
/// or too few words) — the receiver's own "malformed message, ignore"
/// posture, matching every other wire-decode function in this project.
pub fn decode_key_event(msg: &SmallMessage) -> Option<KeyEvent> {
    if msg.label != KEY_EVENT_LABEL {
        return None;
    }
    let words = msg.words();
    if words.len() < 2 {
        return None;
    }
    Some(KeyEvent { keycode: words[0] as u8, pressed: words[1] != 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_event_round_trips_through_encode_decode() {
        let event = KeyEvent { keycode: 0x1e, pressed: true };
        assert_eq!(decode_key_event(&encode_key_event(event)), Some(event));

        let event = KeyEvent { keycode: 0x1e, pressed: false };
        assert_eq!(decode_key_event(&encode_key_event(event)), Some(event));
    }

    #[test]
    fn a_message_with_the_wrong_label_is_rejected() {
        let msg = SmallMessage::from_words(0xDEAD, &[0x1e, 1]).unwrap();
        assert_eq!(decode_key_event(&msg), None);
    }

    #[test]
    fn a_truncated_message_is_rejected() {
        let msg = SmallMessage::from_words(KEY_EVENT_LABEL, &[0x1e]).unwrap();
        assert_eq!(decode_key_event(&msg), None);
    }
}
