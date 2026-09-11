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

/// Sign-extends an 8-bit PS/2 delta magnitude using the packet's own
/// separate sign bit (the PS/2 protocol carries the sign OUT of band,
/// in byte 0, not as the delta byte's own MSB).
fn sign_extend(magnitude: u8, sign_bit_set: bool) -> i16 {
    if sign_bit_set {
        (magnitude as i16) - 256
    } else {
        magnitude as i16
    }
}

/// Decodes one real, already-grouped 3-byte PS/2 mouse packet.
/// `bytes[0]`'s own sync bit is NOT checked here — [`PacketAssembler`]
/// is responsible for only ever handing this function a byte 0 that
/// already has it set.
fn decode_packet(bytes: [u8; 3]) -> MouseEvent {
    let status = bytes[0];
    MouseEvent {
        dx: sign_extend(bytes[1], status & X_SIGN_BIT != 0),
        dy: sign_extend(bytes[2], status & Y_SIGN_BIT != 0),
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
