//! ============================================================================
//! scancode.rs — PC/AT Scan Code Set 1 decode
//!
//! Purpose: turns a raw i8042 data-port byte (`hal_x86_64::pic::
//! read_scancode`, relayed through `kernel_arch_glue::i8042_irq_
//! trampoline`'s own ring) into a structured `(keycode, pressed)` pair.
//!
//! Scope, named honestly (this project's own "gap over guess" convention
//! — see `Simurgh-OS/subsystems/compositor/src/subsystem_entry.rs`'s own
//! `SubscribeInput` stub doc comment for the identical posture): Scan
//! Code Set 1 only (the default set every BIOS/QEMU emits unless
//! reprogrammed — no Set 2/3 negotiation), make/break only (bit 7 of the
//! raw byte), no 0xE0-prefixed extended keys (arrow keys, right Ctrl/
//! Alt, media keys — an 0xE0 byte is dropped, not buffered, so the
//! following byte is decoded as if it arrived alone, which is wrong for
//! an extended key but never panics or corrupts state), no mouse
//! support. `ui-core` has no keyboard-event type or arrow-key-aware
//! navigation at all yet, so extended-key support would mean designing
//! the consumption side twice for no present benefit.
//! ============================================================================
#![allow(clippy::unusual_byte_groupings)]

/// A decoded key event: `keycode` is simply the Scan Code Set 1 make
/// code (bit 7 cleared) — NOT yet mapped to any higher-level `KeyCode`
/// enum (that mapping belongs to whichever consumer actually needs
/// named keys; this driver's own job ends at "which physical key,
/// pressed or released").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub keycode: u8,
    pub pressed: bool,
}

/// The 0xE0 extended-key prefix byte — dropped per this module's own
/// scope (see module doc comment).
const EXTENDED_PREFIX: u8 = 0xE0;

/// Decodes one raw i8042 data-port byte. Returns `None` for the 0xE0
/// extended-key prefix (dropped, not buffered) — every other byte
/// decodes to `Some`, since Set 1's own make/break encoding (bit 7)
/// covers the full `0x00..=0xFF` range with no reserved/invalid bytes
/// this driver needs to reject.
pub fn decode(byte: u8) -> Option<KeyEvent> {
    if byte == EXTENDED_PREFIX {
        return None;
    }
    let pressed = byte & 0x80 == 0;
    let keycode = byte & 0x7F;
    Some(KeyEvent { keycode, pressed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_prefix_decodes_to_none() {
        assert_eq!(decode(EXTENDED_PREFIX), None);
    }

    #[test]
    fn a_key_make_and_break_match_the_real_qemu_verified_values() {
        // Confirmed on real QEMU x86_64 boots (2026-09-11) via a real
        // `sendkey a` injected through QEMU's own emulated i8042 —
        // Stage A's own verification record (`kernel_arch_glue::wire_
        // i8042_irq`'s own doc comment) has the full story.
        assert_eq!(decode(0x1e), Some(KeyEvent { keycode: 0x1e, pressed: true }));
        assert_eq!(decode(0x9e), Some(KeyEvent { keycode: 0x1e, pressed: false }));
    }

    #[test]
    fn d_and_e_key_make_and_break_match_the_real_qemu_verified_values() {
        assert_eq!(decode(0x20), Some(KeyEvent { keycode: 0x20, pressed: true }));
        assert_eq!(decode(0xa0), Some(KeyEvent { keycode: 0x20, pressed: false }));
        assert_eq!(decode(0x12), Some(KeyEvent { keycode: 0x12, pressed: true }));
        assert_eq!(decode(0x92), Some(KeyEvent { keycode: 0x12, pressed: false }));
    }

    #[test]
    fn every_byte_except_the_extended_prefix_decodes_to_some() {
        for byte in 0u8..=0xFF {
            if byte == EXTENDED_PREFIX {
                continue;
            }
            assert!(decode(byte).is_some());
        }
    }
}
