//! ============================================================================
//! page.rs — the shared audio page (client interface), docs/audio-plan.md.
//!
//! Purpose: ONE 4 KiB page shared between the driver (read-write) and ui-core
//! (read-write, but by convention it only writes the mailbox). Bytes 0..64 are
//! a seqlocked STATUS record written by the driver; bytes 64..96 are the
//! MAILBOX written by the client. Everything little-endian.
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | u64 | magic `0x5349_4D41_5544_0001` ("SIMAUD" + layout 1); wrong magic = no audio device |
//! | 8 | u32 | seqlock counter: odd while the driver writes, even when stable |
//! | 12 | u8 | flags: 1 present, 2 playing, 4 muted, 8 has volume control |
//! | 13 | u8 | volume 0..=100 |
//! | 14 | u8 | state: 0 no device, 1 starting, 2 ready, 3 error |
//! | 15 | u8 | codec name length |
//! | 16 | u32 | number of clips played to completion |
//! | 20 | u32 | last error code (0 none) |
//! | 24 | 32 bytes | codec name, ASCII |
//! | 64 | u32 | mailbox `cmd_seq`: the client bumps it AFTER writing cmd/args |
//! | 68 | u32 | mailbox `ack_seq`: the driver copies `cmd_seq` here once done |
//! | 72 | u32 | command |
//! | 76 / 80 | u32 | argument 0 / 1 |
//!
//! A client may issue a command only while `ack_seq == cmd_seq` (previous one
//! finished). Commands: 1 set volume (arg0 0..=100), 2 set mute (arg0 0/1),
//! 3 play tone (arg0 Hz, arg1 milliseconds), 4 play PCM (arg0 bytes already in
//! the ring, 48 kHz 16-bit stereo), 5 stop. TODO(spec) 1/2: who may write the
//! mailbox is decided by the kernel mapping, not by a capability.
//! ============================================================================

/// Page magic: ASCII "SIMAUD" + layout version 1.
pub const MAGIC: u64 = 0x5349_4D41_5544_0001;
/// Size of the STATUS record in bytes.
pub const STATUS_LEN: usize = 64;

/// Byte offsets inside the page.
pub mod off {
    /// Magic.
    pub const MAGIC: usize = 0;
    /// Seqlock counter.
    pub const SEQ: usize = 8;
    /// Flags byte.
    pub const FLAGS: usize = 12;
    /// Volume byte.
    pub const VOLUME: usize = 13;
    /// State byte.
    pub const STATE: usize = 14;
    /// Codec name length.
    pub const NAME_LEN: usize = 15;
    /// Clips played.
    pub const PLAYS: usize = 16;
    /// Last error.
    pub const ERROR: usize = 20;
    /// Codec name (32 bytes).
    pub const NAME: usize = 24;
    /// Mailbox command sequence (written by the client).
    pub const CMD_SEQ: usize = 64;
    /// Mailbox acknowledge sequence (written by the driver).
    pub const ACK_SEQ: usize = 68;
    /// Mailbox command.
    pub const CMD: usize = 72;
    /// Mailbox argument 0.
    pub const ARG0: usize = 76;
    /// Mailbox argument 1.
    pub const ARG1: usize = 80;
}

/// Flag: an audio controller with a usable codec was found.
pub const FLAG_PRESENT: u8 = 1;
/// Flag: a clip is playing.
pub const FLAG_PLAYING: u8 = 2;
/// Flag: output is muted.
pub const FLAG_MUTED: u8 = 4;
/// Flag: the output path has an adjustable amp (volume works in hardware).
pub const FLAG_HAS_VOLUME: u8 = 8;

/// State: no controller / no codec.
pub const STATE_NO_DEVICE: u8 = 0;
/// State: driver starting up.
pub const STATE_STARTING: u8 = 1;
/// State: ready to play.
pub const STATE_READY: u8 = 2;
/// State: probe failed after finding a controller.
pub const STATE_ERROR: u8 = 3;

/// Mailbox command: set volume.
pub const CMD_SET_VOLUME: u32 = 1;
/// Mailbox command: set mute.
pub const CMD_SET_MUTE: u32 = 2;
/// Mailbox command: play a sine tone.
pub const CMD_PLAY_TONE: u32 = 3;
/// Mailbox command: play PCM already placed in the ring.
pub const CMD_PLAY_PCM: u32 = 4;
/// Mailbox command: stop playback.
pub const CMD_STOP: u32 = 5;

/// Decoded STATUS record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    /// Flag bits (`FLAG_*`).
    pub flags: u8,
    /// Volume 0..=100.
    pub volume: u8,
    /// `STATE_*`.
    pub state: u8,
    /// Clips played to completion.
    pub plays: u32,
    /// Last error code.
    pub error: u32,
    /// Codec name bytes.
    pub name: [u8; 32],
    /// Valid bytes in `name`.
    pub name_len: u8,
}

impl Status {
    /// The all-zero "no device" status.
    pub const NONE: Status = Status { flags: 0, volume: 0, state: STATE_NO_DEVICE, plays: 0, error: 0, name: [0; 32], name_len: 0 };

    /// Codec name as text.
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..(self.name_len as usize).min(32)]).unwrap_or("")
    }
    /// Device present.
    pub fn present(&self) -> bool {
        self.flags & FLAG_PRESENT != 0
    }
    /// Playing.
    pub fn playing(&self) -> bool {
        self.flags & FLAG_PLAYING != 0
    }
    /// Muted.
    pub fn muted(&self) -> bool {
        self.flags & FLAG_MUTED != 0
    }
}

/// Encodes `st` into a full STATUS record with the given (even) seqlock value.
pub fn encode_status(st: &Status, seq: u32) -> [u8; STATUS_LEN] {
    let mut b = [0u8; STATUS_LEN];
    b[off::MAGIC..off::MAGIC + 8].copy_from_slice(&MAGIC.to_le_bytes());
    b[off::SEQ..off::SEQ + 4].copy_from_slice(&seq.to_le_bytes());
    b[off::FLAGS] = st.flags;
    b[off::VOLUME] = st.volume;
    b[off::STATE] = st.state;
    b[off::NAME_LEN] = st.name_len.min(32);
    b[off::PLAYS..off::PLAYS + 4].copy_from_slice(&st.plays.to_le_bytes());
    b[off::ERROR..off::ERROR + 4].copy_from_slice(&st.error.to_le_bytes());
    b[off::NAME..off::NAME + 32].copy_from_slice(&st.name);
    b
}

/// Decodes a STATUS record. `None` on a wrong magic (no device) or a torn read
/// (odd seqlock counter). Returns the status and the seqlock value.
pub fn decode_status(b: &[u8]) -> Option<(Status, u32)> {
    if b.len() < STATUS_LEN {
        return None;
    }
    let magic = u64::from_le_bytes(b[0..8].try_into().ok()?);
    let seq = u32::from_le_bytes(b[off::SEQ..off::SEQ + 4].try_into().ok()?);
    if magic != MAGIC || seq & 1 != 0 {
        return None;
    }
    let mut name = [0u8; 32];
    name.copy_from_slice(&b[off::NAME..off::NAME + 32]);
    Some((
        Status {
            flags: b[off::FLAGS],
            volume: b[off::VOLUME].min(100),
            state: b[off::STATE],
            plays: u32::from_le_bytes(b[off::PLAYS..off::PLAYS + 4].try_into().ok()?),
            error: u32::from_le_bytes(b[off::ERROR..off::ERROR + 4].try_into().ok()?),
            name,
            name_len: b[off::NAME_LEN].min(32),
        },
        seq,
    ))
}

/// A decoded mailbox command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Set the master volume, 0..=100.
    SetVolume(u8),
    /// Mute or unmute.
    SetMute(bool),
    /// Play a sine of `hz` for `ms` milliseconds.
    PlayTone {
        /// Frequency in Hz.
        hz: u32,
        /// Duration in milliseconds.
        ms: u32,
    },
    /// Play `bytes` of PCM already in the ring.
    PlayPcm {
        /// Clip length in bytes.
        bytes: u32,
    },
    /// Stop playback.
    Stop,
}

/// Decodes `(cmd, arg0, arg1)`; `None` for an unknown command.
pub fn decode_command(cmd: u32, a0: u32, a1: u32) -> Option<Command> {
    Some(match cmd {
        CMD_SET_VOLUME => Command::SetVolume(a0.min(100) as u8),
        CMD_SET_MUTE => Command::SetMute(a0 != 0),
        CMD_PLAY_TONE => Command::PlayTone { hz: a0, ms: a1 },
        CMD_PLAY_PCM => Command::PlayPcm { bytes: a0 },
        CMD_STOP => Command::Stop,
        _ => return None,
    })
}

/// Builds the codec name shown to clients: "<Vendor> codec VVVV:DDDD" (or
/// "HDA codec VVVV:DDDD" for an unknown vendor). Returns `(bytes, len)`.
pub fn codec_name(vendor_device: u32) -> ([u8; 32], u8) {
    let mut out = [0u8; 32];
    let mut n = 0usize;
    let mut push = |s: &[u8]| {
        for &c in s {
            if n < 32 {
                out[n] = c;
                n += 1;
            }
        }
    };
    if let Some(v) = crate::verb::vendor_name((vendor_device >> 16) as u16) {
        push(v.as_bytes());
        push(b" codec ");
    } else {
        push(b"HDA codec ");
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for shift in [28u32, 24, 20, 16] {
        push(&[HEX[((vendor_device >> shift) & 0xF) as usize]]);
    }
    push(b":");
    for shift in [12u32, 8, 4, 0] {
        push(&[HEX[((vendor_device >> shift) & 0xF) as usize]]);
    }
    (out, n as u8)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn status_round_trips_and_has_the_documented_layout() {
        let (name, len) = codec_name(0x1af4_0011);
        let st = Status { flags: FLAG_PRESENT | FLAG_MUTED | FLAG_HAS_VOLUME, volume: 65, state: STATE_READY, plays: 3, error: 0, name, name_len: len };
        let b = encode_status(&st, 6);
        assert_eq!(&b[0..8], &MAGIC.to_le_bytes());
        assert_eq!(b[12], 13);
        assert_eq!(b[13], 65);
        assert_eq!(b[14], 2);
        assert_eq!(&b[24..24 + len as usize], b"QEMU codec 1af4:0011");
        let (d, seq) = decode_status(&b).unwrap();
        assert_eq!(seq, 6);
        assert_eq!(d, st);
        assert_eq!(d.name_str(), "QEMU codec 1af4:0011");
        assert!(d.present() && d.muted() && !d.playing());
    }

    #[test]
    fn reader_rejects_torn_and_foreign_pages() {
        let b = encode_status(&Status::NONE, 3); // odd = writer in progress
        assert!(decode_status(&b).is_none());
        assert!(decode_status(&[0u8; 64]).is_none(), "zero page = no device");
        assert!(decode_status(&[0u8; 8]).is_none(), "short");
    }

    #[test]
    fn mailbox_commands_decode() {
        assert_eq!(decode_command(1, 150, 0), Some(Command::SetVolume(100)));
        assert_eq!(decode_command(2, 1, 0), Some(Command::SetMute(true)));
        assert_eq!(decode_command(3, 440, 1000), Some(Command::PlayTone { hz: 440, ms: 1000 }));
        assert_eq!(decode_command(4, 192_000, 0), Some(Command::PlayPcm { bytes: 192_000 }));
        assert_eq!(decode_command(5, 0, 0), Some(Command::Stop));
        assert_eq!(decode_command(99, 0, 0), None);
    }

    #[test]
    fn codec_name_for_unknown_vendor() {
        let (n, l) = codec_name(0x1234_abcd);
        assert_eq!(&n[..l as usize], b"HDA codec 1234:abcd");
    }
}
