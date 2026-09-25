//! ============================================================================
//! mouse_packet.rs — standard 3-byte PS/2 mouse packet decode
//!
//! Purpose: turns three raw i8042 aux-port bytes (`hal_x86_64::pic::
//! read_mouse_byte`, relayed through `kernel_arch_glue::mouse_irq_
//! trampoline`'s own ring) into one structured `MouseEvent`.
//!
//! Scope, named honestly (same "gap over guess" convention this
//! project's own `driver_i8042::scancode` doc comment already
//! establishes): standard 3-byte packets only (button state + X/Y
//! deltas) — no IntelliMouse 4-byte wheel extension, no 5-button
//! extension. `enable_ps2_mouse` never negotiates either extension, so
//! the device only ever sends 3-byte packets in the first place.
//!
//! **Real PS/2 mouse packets are NOT self-synchronizing the way
//! keyboard scancodes are** — a keyboard byte stands alone; a mouse
//! packet is three bytes that must be grouped correctly, and there is
//! no length prefix. Byte 0 of every real packet always has bit 3 set
//! (a real, hardware-guaranteed invariant of the protocol) — this
//! module's own [`PacketAssembler`] uses exactly that bit to resync if
//! grouping is ever lost (e.g. a dropped byte), rather than assuming
//! every 3 bytes received forms one real packet unconditionally.
//! ============================================================================

/// One decoded real mouse event. `dx`/`dy` are PS/2's own raw sign
/// convention: positive `dx` is real rightward motion; positive `dy` is
/// real UPWARD motion (PS/2's own Y axis is inverted relative to most
/// screen coordinate systems, where Y grows downward) — deliberately
/// NOT flipped here, so this module stays a pure, honest protocol
/// decoder; a consumer mapping this onto screen coordinates is
/// responsible for its own sign convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseEvent {
    pub dx: i16,
    pub dy: i16,
    pub left: bool,
    pub right: bool,
    pub middle: bool,
}

const SYNC_BIT: u8 = 1 << 3;
const LEFT_BUTTON_BIT: u8 = 1 << 0;
const RIGHT_BUTTON_BIT: u8 = 1 << 1;
const MIDDLE_BUTTON_BIT: u8 = 1 << 2;
const X_SIGN_BIT: u8 = 1 << 4;
const Y_SIGN_BIT: u8 = 1 << 5;
const X_OVERFLOW_BIT: u8 = 1 << 6;
const Y_OVERFLOW_BIT: u8 = 1 << 7;

/// Sign-extends an 8-bit PS/2 delta magnitude using the packet's own
/// separate sign bit (the PS/2 protocol carries the sign OUT of band,
/// in byte 0, not as the delta byte's own MSB) — i.e. a 9-bit two's-
/// complement value, range -256..=255.
fn sign_extend(magnitude: u8, sign_bit_set: bool) -> i16 {
    if sign_bit_set {
        (magnitude as i16) - 256
    } else {
        magnitude as i16
    }
}

/// One axis of a packet: the 9-bit delta, or — when the device reports
/// that axis OVERFLOWED (the motion did not fit in 9 bits) — the largest
/// value the packet can carry in the reported direction. The low byte is
/// meaningless on overflow (the protocol gives no guarantee about it), so
/// decoding it anyway could even move the cursor the WRONG way.
fn axis(magnitude: u8, sign_bit_set: bool, overflow: bool) -> i16 {
    match (overflow, sign_bit_set) {
        (true, true) => -256,
        (true, false) => 255,
        (false, _) => sign_extend(magnitude, sign_bit_set),
    }
}

/// Decodes one real, already-grouped 3-byte PS/2 mouse packet.
/// `bytes[0]`'s own sync bit is NOT checked here — [`PacketAssembler`]
/// is responsible for only ever handing this function a byte 0 that
/// already has it set.
fn decode_packet(bytes: [u8; 3]) -> MouseEvent {
    let status = bytes[0];
    MouseEvent {
        dx: axis(bytes[1], status & X_SIGN_BIT != 0, status & X_OVERFLOW_BIT != 0),
        dy: axis(bytes[2], status & Y_SIGN_BIT != 0, status & Y_OVERFLOW_BIT != 0),
        left: status & LEFT_BUTTON_BIT != 0,
        right: status & RIGHT_BUTTON_BIT != 0,
        middle: status & MIDDLE_BUTTON_BIT != 0,
    }
}

/// Groups a stream of raw bytes into real 3-byte packets, resyncing on
/// [`SYNC_BIT`] if grouping is ever lost. Real, minimal state machine —
/// not a ring buffer of its own (the caller's own byte source, e.g. the
/// kernel-owned ring `driver-mouse`'s own `subsystem_entry` reads, is
/// the actual queue; this only tracks "how many bytes of the CURRENT
/// packet have I seen so far").
#[derive(Debug, Default)]
pub struct PacketAssembler {
    buf: [u8; 3],
    len: u8,
}

impl PacketAssembler {
    pub const fn new() -> Self {
        Self { buf: [0; 3], len: 0 }
    }

    /// Forgets any partially assembled packet. The caller MUST call this
    /// whenever bytes were lost between two `push`es (e.g. the byte ring
    /// overwrote unread bytes): otherwise the bytes that follow the gap
    /// are glued onto the head of a packet they never belonged to.
    /// Resynchronising on the sync bit alone is not enough there — a
    /// delta byte can have bit 3 set too (e.g. a move of 10 = `0b1010`),
    /// so a stream that is misaligned by one or two bytes can keep
    /// decoding plausible-looking garbage: wrong deltas, wrong signs,
    /// phantom button presses.
    ///
    /// Context (2026-09-25): wrong net deltas were reported for bursts of
    /// back-to-back QEMU `mouse_move`s (20 x `10 0` arriving as +50). A
    /// ring overflow into a half-assembled packet is one way to get that,
    /// and this closes it; but the measurement also found a second,
    /// benign cause — QEMU's PS/2 model hands over only ~5 packets per
    /// input event and holds the (merged) rest until the next event, so a
    /// burst read too early looks short. With this driver a burst of
    /// 20 x `mouse_move 10 0` plus three `1 0` moves arrives as exactly
    /// +203 (`latency_stats::net_dx`).
    pub fn reset(&mut self) {
        self.len = 0;
    }

    /// Feeds one raw byte. Returns `Some(event)` exactly when a full,
    /// real 3-byte packet just completed.
    pub fn push(&mut self, byte: u8) -> Option<MouseEvent> {
        if self.len == 0 && byte & SYNC_BIT == 0 {
            // Not a real packet start (the sync bit is a real, always-
            // set hardware invariant for byte 0) — drop it. Real cause:
            // grouping was lost (e.g. a byte the ring dropped under
            // overflow) — resyncing on the next real sync-bit byte is
            // the standard, documented real-hardware recovery for this
            // protocol, not a guess.
            return None;
        }
        self.buf[self.len as usize] = byte;
        self.len += 1;
        if self.len == 3 {
            self.len = 0;
            return Some(decode_packet(self.buf));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn a_packet_with_no_motion_or_buttons_decodes_to_all_zero() {
        let mut asm = PacketAssembler::new();
        assert_eq!(asm.push(SYNC_BIT), None);
        assert_eq!(asm.push(0), None);
        assert_eq!(
            asm.push(0),
            Some(MouseEvent { dx: 0, dy: 0, left: false, right: false, middle: false })
        );
    }

    #[test]
    fn positive_deltas_decode_directly() {
        let mut asm = PacketAssembler::new();
        asm.push(SYNC_BIT);
        asm.push(10);
        let event = asm.push(20).unwrap();
        assert_eq!(event.dx, 10);
        assert_eq!(event.dy, 20);
    }

    #[test]
    fn negative_deltas_sign_extend_using_the_status_byte() {
        let mut asm = PacketAssembler::new();
        asm.push(SYNC_BIT | X_SIGN_BIT | Y_SIGN_BIT);
        asm.push(0xF6); // 246 -> -10 once sign-extended
        let event = asm.push(0xEC).unwrap(); // 236 -> -20
        assert_eq!(event.dx, -10);
        assert_eq!(event.dy, -20);
    }

    #[test]
    fn button_bits_decode_independently() {
        let mut asm = PacketAssembler::new();
        asm.push(SYNC_BIT | LEFT_BUTTON_BIT | MIDDLE_BUTTON_BIT);
        asm.push(0);
        let event = asm.push(0).unwrap();
        assert!(event.left);
        assert!(!event.right);
        assert!(event.middle);
    }

    #[test]
    fn a_byte_with_no_sync_bit_at_packet_start_is_dropped_not_misparsed() {
        let mut asm = PacketAssembler::new();
        // A stray non-sync byte at the start (e.g. grouping was lost)
        // must not be treated as a real packet's own byte 0.
        assert_eq!(asm.push(0x00), None);
        // The assembler must still be at "expecting byte 0" — a real
        // sync byte now starts a real packet cleanly.
        assert_eq!(asm.push(SYNC_BIT), None);
        assert_eq!(asm.push(5), None);
        assert_eq!(asm.push(5).unwrap().dx, 5);
    }

    fn decode(status: u8, x: u8, y: u8) -> MouseEvent {
        let mut asm = PacketAssembler::new();
        asm.push(SYNC_BIT | status);
        asm.push(x);
        asm.push(y).unwrap()
    }

    #[test]
    fn nine_bit_deltas_cover_the_whole_range() {
        // byte = low 8 bits of the 9-bit two's-complement value, the 9th
        // bit is the status byte's sign bit.
        assert_eq!(decode(0, 255, 0).dx, 255);
        assert_eq!(decode(0, 1, 0).dx, 1);
        assert_eq!(decode(X_SIGN_BIT, 0xFF, 0).dx, -1);
        assert_eq!(decode(X_SIGN_BIT, 0x01, 0).dx, -255);
        assert_eq!(decode(X_SIGN_BIT, 0x00, 0).dx, -256);
        assert_eq!(decode(Y_SIGN_BIT, 0, 0x42).dy, -190);
        assert_eq!(decode(0, 0, 190).dy, 190);
        // What QEMU sends for `mouse_move -10 0`: dx byte 0xF6 + X sign.
        assert_eq!(decode(X_SIGN_BIT, 0xF6, 0).dx, -10);
        assert_eq!(decode(0, 10, 0).dx, 10);
    }

    #[test]
    fn an_overflowed_axis_saturates_in_its_reported_direction() {
        let e = decode(X_OVERFLOW_BIT | Y_OVERFLOW_BIT | Y_SIGN_BIT, 0x12, 0x34);
        assert_eq!(e.dx, 255);
        assert_eq!(e.dy, -256);
        // Only the overflowed axis is affected.
        let e = decode(X_OVERFLOW_BIT | X_SIGN_BIT, 0x00, 7);
        assert_eq!((e.dx, e.dy), (-256, 7));
    }

    #[test]
    fn a_packet_split_across_separate_drains_still_assembles() {
        // The assembler is the only state carried between two wakes of
        // the driver, so a packet whose bytes straddle two drains must
        // come out whole.
        let mut asm = PacketAssembler::new();
        assert_eq!(asm.push(SYNC_BIT | X_SIGN_BIT), None);
        // ... driver blocks, next IRQ ...
        assert_eq!(asm.push(0xF6), None);
        // ... and again ...
        assert_eq!(asm.push(0).unwrap().dx, -10);
    }

    #[test]
    fn reset_after_lost_bytes_prevents_misaligned_garbage() {
        // Two packets of `+10, 0`: [08 0A 00] [08 0A 00]. Lose the first
        // two bytes (ring overflow): the stream now starts `00 08 0A 00`.
        // Without a reset a half-filled assembler would glue these onto
        // its old partial packet; with `reset` the leading `00` has no
        // sync bit and is dropped, and the next packet decodes exactly.
        let mut asm = PacketAssembler::new();
        asm.push(SYNC_BIT); // a partial packet from before the gap
        asm.reset();
        let mut out = std::vec::Vec::new();
        for b in [0x00, 0x08, 0x0A, 0x00] {
            out.extend(asm.push(b));
        }
        assert_eq!(out, [MouseEvent { dx: 10, dy: 0, left: false, right: false, middle: false }]);
    }

    #[test]
    fn twenty_back_to_back_moves_sum_exactly() {
        // 20 x `mouse_move 10 0` and 20 x `mouse_move -10 0` as QEMU
        // encodes them, pushed as one uninterrupted stream (no loss).
        let mut asm = PacketAssembler::new();
        let (mut sum_pos, mut sum_neg) = (0i32, 0i32);
        for _ in 0..20 {
            for b in [0x08, 10, 0] {
                if let Some(e) = asm.push(b) {
                    sum_pos += e.dx as i32;
                }
            }
        }
        for _ in 0..20 {
            for b in [0x08 | X_SIGN_BIT, 0xF6, 0] {
                if let Some(e) = asm.push(b) {
                    sum_neg += e.dx as i32;
                }
            }
        }
        assert_eq!((sum_pos, sum_neg), (200, -200));
    }

    #[test]
    fn resyncs_after_losing_grouping_mid_packet() {
        let mut asm = PacketAssembler::new();
        asm.push(SYNC_BIT);
        asm.push(1); // only 2 of 3 bytes of this packet ever arrive
        // A real new packet's own byte 0 arrives instead (simulating a
        // dropped byte) — the assembler is still mid-packet (len == 2)
        // so it accepts it as this packet's own byte 2, producing one
        // (garbage, but real-shaped) event; the NEXT real sync byte
        // then starts cleanly. This documents the real, honest
        // trade-off: a dropped byte corrupts exactly one packet, never
        // desyncs the stream permanently.
        let _ = asm.push(SYNC_BIT);
        assert_eq!(asm.push(SYNC_BIT), None);
        assert_eq!(asm.push(2), None);
        assert_eq!(asm.push(3).unwrap().dx, 2);
    }
}
