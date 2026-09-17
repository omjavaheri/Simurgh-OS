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

/// The wire-format decision for [`KeyEvent::extended`]: it rides packed
/// into bit 7 of the FIRST word (the keycode word), rather than as a
/// third `SmallMessage` word. This is deliberate, not a space-saving
/// afterthought: [`crate::scancode::KeyEvent::keycode`] is ALREADY
/// guaranteed `<= 0x7F` (Set 1's own make/break bit, bit 7 of the raw
/// byte, is stripped into the separate `pressed` field before a
/// `KeyEvent` ever exists) — so bit 7 of the keycode word was always
/// zero on this wire before today, a genuinely free, reserved bit rather
/// than one taken from somewhere else. Packing here keeps this edge's
/// own word count at 2 (unchanged) and, just as importantly, keeps the
/// SAME convention `ipc_protocol::codec`'s own `DisplayResponse::
/// InputEvent` encoding uses one hop further down this same pipeline
/// (`Simurgh-OS/ipc-protocol/src/codec.rs`'s own `OP_DPR_INPUT_EVENT`
/// arm) — one wire-format idea, not two independently invented ones for
/// the two hops.
const EXTENDED_BIT: u64 = 0x80;

/// Encodes a [`KeyEvent`] as `{ label: KEY_EVENT_LABEL, words:
/// [keycode | (extended << 7), pressed] }` — see [`EXTENDED_BIT`]'s own
/// doc comment for why the extended flag packs into the keycode word
/// rather than growing this edge to 3 words.
pub fn encode_key_event(event: KeyEvent) -> SmallMessage {
    let keycode_word = event.keycode as u64 | if event.extended { EXTENDED_BIT } else { 0 };
    SmallMessage::from_words(KEY_EVENT_LABEL, &[keycode_word, event.pressed as u64])
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
    let keycode_word = words[0];
    Some(KeyEvent {
        keycode: (keycode_word & 0x7F) as u8,
        pressed: words[1] != 0,
        extended: keycode_word & EXTENDED_BIT != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_event_round_trips_through_encode_decode() {
        let event = KeyEvent { keycode: 0x1e, pressed: true, extended: false };
        assert_eq!(decode_key_event(&encode_key_event(event)), Some(event));

        let event = KeyEvent { keycode: 0x1e, pressed: false, extended: false };
        assert_eq!(decode_key_event(&encode_key_event(event)), Some(event));
    }

    #[test]
    fn an_extended_key_event_round_trips_with_its_own_flag_set() {
        // Up Arrow: keycode 0x48, the same byte Numpad-8 (non-extended)
        // uses — only `extended` tells them apart on the wire.
        let event = KeyEvent { keycode: 0x48, pressed: true, extended: true };
        assert_eq!(decode_key_event(&encode_key_event(event)), Some(event));

        let event = KeyEvent { keycode: 0x48, pressed: false, extended: true };
        assert_eq!(decode_key_event(&encode_key_event(event)), Some(event));
    }

    #[test]
    fn extended_and_non_extended_events_with_the_same_keycode_encode_to_different_words() {
        let plain = encode_key_event(KeyEvent { keycode: 0x48, pressed: true, extended: false });
        let extended = encode_key_event(KeyEvent { keycode: 0x48, pressed: true, extended: true });
        assert_ne!(plain.words()[0], extended.words()[0]);
        assert_eq!(plain.words()[0], 0x48);
        assert_eq!(extended.words()[0], 0x48 | EXTENDED_BIT);
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
