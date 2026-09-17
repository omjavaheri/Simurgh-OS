//! ============================================================================
//! scancode.rs — PC/AT Scan Code Set 1 decode
//!
//! Purpose: turns raw i8042 data-port bytes (`hal_x86_64::pic::
//! read_scancode`, relayed through `kernel_arch_glue::i8042_irq_
//! trampoline`'s own ring) into structured `(keycode, pressed, extended)`
//! triples.
//!
//! Scope, named honestly (this project's own "gap over guess" convention
//! — see `Simurgh-OS/subsystems/compositor/src/subsystem_entry.rs`'s own
//! `SubscribeInput` stub doc comment for the identical posture): Scan
//! Code Set 1 only (the default set every BIOS/QEMU emits unless
//! reprogrammed — no Set 2/3 negotiation), make/break only (bit 7 of the
//! raw byte), no mouse support.
//!
//! **Real 0xE0 extended-key support (added 2026-09-17, closing a
//! previously-named gap)**: a real `0xE0` prefix byte is now buffered
//! (via [`Decoder`]'s own `extended_pending` state) rather than dropped,
//! and the byte that follows it decodes with [`KeyEvent::extended`] set —
//! a genuine, complete hardware-discovery capability (`MD/00-Overview.md`'s
//! own "hardware/capability discovery is always complete" principle),
//! not an arrow-keys-only special case: EVERY `0xE0`-prefixed key this
//! keyboard can send decodes correctly, including the ones no consumer
//! names an action for yet (Right Ctrl/Alt, Insert, Numpad Enter/`/`,
//! media keys) — `Simurgh-UI-Template01::ui-core::keymap`'s own doc
//! comment is where POLICY (which extended keys get a named
//! [`crate::scancode`]-consumer-facing action) is decided; this module's
//! own job stays "which physical key, pressed or released, extended or
//! not" only. Two real PS/2 sequences are still deliberately NOT
//! covered, named rather than silently guessed at: the 4-byte Print
//! Screen make/break (a `0xE0`-prefixed TWO-byte-then-TWO-byte sequence,
//! not this module's simple one-prefix-one-follow-up-byte shape) and the
//! 6-byte `0xE1`-prefixed Pause/Break (no break code at all, a wholly
//! different shape) — neither is a real gap `ui-core`'s own text-input/
//! terminal use cases need today, and inventing decode logic for either
//! without a real consumer would be exactly the kind of guess this
//! project's own `CONTRIBUTING.md` says not to make.
//! ============================================================================
#![allow(clippy::unusual_byte_groupings)]

/// A decoded key event: `keycode` is the Scan Code Set 1 make code (bit 7
/// cleared) — NOT yet mapped to any higher-level `KeyCode` enum (that
/// mapping belongs to whichever consumer actually needs named keys; this
/// driver's own job ends at "which physical key, pressed or released,
/// extended or not"). `extended` is `true` iff this byte arrived
/// immediately after a real `0xE0` prefix byte (this struct's own module
/// doc comment) — e.g. Up Arrow (`0xE0 0x48`) and Numpad-8 (`0x48` alone)
/// share the same `keycode`, distinguished ONLY by this flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub keycode: u8,
    pub pressed: bool,
    pub extended: bool,
}

/// The 0xE0 extended-key prefix byte — buffered (not dropped) by
/// [`Decoder::feed`], see this module's own doc comment.
const EXTENDED_PREFIX: u8 = 0xE0;

/// Stateful Scan Code Set 1 decoder. A real `0xE0` prefix byte is a
/// single-byte LOOKAHEAD this module's own protocol needs to buffer
/// across two separate `feed` calls (the prefix and its follow-up byte
/// can, in principle, land in different ring drains — `subsystem_entry`'s
/// own doc comment on why this decoder is owned for the whole process
/// lifetime, not reconstructed per drain) — every other byte in Scan Code
/// Set 1 decodes on its own, with no lookahead needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Decoder {
    /// `true` iff the immediately-preceding byte fed to this decoder was
    /// a real `0xE0` prefix, not yet consumed by the byte that follows
    /// it.
    extended_pending: bool,
}

impl Decoder {
    /// A fresh decoder: no extended prefix pending.
    pub const fn new() -> Self {
        Self { extended_pending: false }
    }

    /// Decodes one raw i8042 data-port byte. Returns `None` for the real
    /// `0xE0` extended-key prefix itself (buffered into this decoder's
    /// own state, not a key event on its own) — every other byte decodes
    /// to `Some`, since Set 1's own make/break encoding (bit 7) covers
    /// the full `0x00..=0xFF` range with no reserved/invalid bytes this
    /// driver needs to reject.
    pub fn feed(&mut self, byte: u8) -> Option<KeyEvent> {
        if byte == EXTENDED_PREFIX {
            self.extended_pending = true;
            return None;
        }
        let extended = core::mem::take(&mut self.extended_pending);
        let pressed = byte & 0x80 == 0;
        let keycode = byte & 0x7F;
        Some(KeyEvent { keycode, pressed, extended })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_prefix_alone_decodes_to_none() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(EXTENDED_PREFIX), None);
    }

    #[test]
    fn a_key_make_and_break_match_the_real_qemu_verified_values() {
        // Confirmed on real QEMU x86_64 boots (2026-09-11) via a real
        // `sendkey a` injected through QEMU's own emulated i8042 —
        // Stage A's own verification record (`kernel_arch_glue::wire_
        // i8042_irq`'s own doc comment) has the full story.
        let mut d = Decoder::new();
        assert_eq!(d.feed(0x1e), Some(KeyEvent { keycode: 0x1e, pressed: true, extended: false }));
        let mut d = Decoder::new();
        assert_eq!(d.feed(0x9e), Some(KeyEvent { keycode: 0x1e, pressed: false, extended: false }));
    }

    #[test]
    fn d_and_e_key_make_and_break_match_the_real_qemu_verified_values() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(0x20), Some(KeyEvent { keycode: 0x20, pressed: true, extended: false }));
        let mut d = Decoder::new();
        assert_eq!(d.feed(0xa0), Some(KeyEvent { keycode: 0x20, pressed: false, extended: false }));
        let mut d = Decoder::new();
        assert_eq!(d.feed(0x12), Some(KeyEvent { keycode: 0x12, pressed: true, extended: false }));
        let mut d = Decoder::new();
        assert_eq!(d.feed(0x92), Some(KeyEvent { keycode: 0x12, pressed: false, extended: false }));
    }

    #[test]
    fn every_byte_except_the_extended_prefix_decodes_to_some() {
        for byte in 0u8..=0xFF {
            let mut d = Decoder::new();
            if byte == EXTENDED_PREFIX {
                continue;
            }
            assert!(d.feed(byte).is_some());
        }
    }

    /// The four real arrow keys this project's real-input-handling plan
    /// names as the immediate, concrete need (`ui-core`'s TERMINAL
    /// history recall) — each one a real Set 1 `0xE0`-prefixed sequence,
    /// each one reusing the SAME low byte as an unrelated non-extended
    /// numpad key (this module's own `KeyEvent` doc comment), confirmed
    /// against the real PC/AT Scan Code Set 1 table.
    #[test]
    fn all_four_arrow_keys_decode_as_extended_with_their_real_scancodes() {
        let cases: &[(u8, u8)] = &[
            (0x48, 0x48), // Up    (0xE0 0x48) — shares 0x48 with Numpad-8.
            (0x50, 0x50), // Down  (0xE0 0x50) — shares 0x50 with Numpad-2.
            (0x4B, 0x4B), // Left  (0xE0 0x4B) — shares 0x4B with Numpad-4.
            (0x4D, 0x4D), // Right (0xE0 0x4D) — shares 0x4D with Numpad-6.
        ];
        for &(make, keycode) in cases {
            let mut d = Decoder::new();
            assert_eq!(d.feed(EXTENDED_PREFIX), None);
            assert_eq!(
                d.feed(make),
                Some(KeyEvent { keycode, pressed: true, extended: true }),
                "extended make byte {make:#x}"
            );

            let mut d = Decoder::new();
            assert_eq!(d.feed(EXTENDED_PREFIX), None);
            assert_eq!(
                d.feed(make | 0x80),
                Some(KeyEvent { keycode, pressed: false, extended: true }),
                "extended break byte {make:#x}"
            );
        }
    }

    #[test]
    fn the_same_low_byte_decodes_differently_extended_vs_not() {
        // 0x48 alone is Numpad-8 (not extended); 0xE0 0x48 is Up Arrow
        // (extended) — the exact ambiguity this module's own doc comment
        // says `extended` exists to resolve.
        let mut d = Decoder::new();
        assert_eq!(d.feed(0x48), Some(KeyEvent { keycode: 0x48, pressed: true, extended: false }));

        let mut d = Decoder::new();
        assert_eq!(d.feed(EXTENDED_PREFIX), None);
        assert_eq!(d.feed(0x48), Some(KeyEvent { keycode: 0x48, pressed: true, extended: true }));
    }

    #[test]
    fn an_extended_prefix_pending_state_does_not_leak_into_the_next_unrelated_byte() {
        // Feeding 0xE0 then a plain, unrelated byte still marks that byte
        // extended (this decoder's own real, honest contract: it cannot
        // know the prefix was "for" a specific key ahead of time) — but
        // the state resets afterward and does NOT leak into a THIRD byte.
        let mut d = Decoder::new();
        assert_eq!(d.feed(EXTENDED_PREFIX), None);
        assert_eq!(d.feed(0x48), Some(KeyEvent { keycode: 0x48, pressed: true, extended: true }));
        // A following plain 'a' make code is NOT extended.
        assert_eq!(d.feed(0x1e), Some(KeyEvent { keycode: 0x1e, pressed: true, extended: false }));
    }

    #[test]
    fn a_real_0xe0_prefix_can_arrive_in_a_separate_feed_call_from_its_follow_up_byte() {
        // Exercises the exact reason `Decoder` is stateful across calls
        // rather than a pure per-byte function (this module's own
        // `Decoder` doc comment): the prefix and its follow-up byte are
        // NOT required to be fed back-to-back with no intervening state
        // reset.
        let mut d = Decoder::new();
        assert_eq!(d.feed(EXTENDED_PREFIX), None);
        // (in a real driver loop, an IRQ-driven ring drain boundary could
        // fall exactly here)
        assert_eq!(d.feed(0x50), Some(KeyEvent { keycode: 0x50, pressed: true, extended: true }));
    }
}
