//! ============================================================================
//! driver-hda
//!
//! Purpose: Intel High Definition Audio driver (Intel HD Audio Specification
//! rev 1.0a; section numbers below refer to it). Reset the controller, run the
//! CORB/RIRB command rings, discover the codec and walk its widget graph to an
//! output path (DAC -> ... -> pin), set up ONE output stream for 48 kHz 16-bit
//! stereo PCM with a buffer descriptor list (BDL), and drive per-widget amp
//! gain/mute. Clients talk to it through the shared audio page (`page`).
//!
//! Architecture reference: docs/audio-plan.md (03-Kernel-Subsystems-Layer.md
//! section 2.1, driver process model).
//!
//! Position in the system: `kernel_arch_glue::spawn_hda_driver` spawns the
//! `driver-hda-bin` process with BAR0 mapped, a command area (CORB/RIRB/BDL), a
//! contiguous PCM ring and the audio page. Everything in this library except
//! `subsystem_entry` is pure protocol logic (host-tested); the MMIO accessors
//! in `controller` are the only place raw pointers are dereferenced.
//!
//! Safety/invariants: register offsets and bit positions are spec-literal.
//! Polling only (no interrupts). One command in flight, one output stream.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod codec;
pub mod controller;
pub mod page;
pub mod subsystem_entry;
pub mod tone;
pub mod verb;

/// Controller register offsets from BAR0 (spec section 3.3).
pub mod regs {
    /// Global Capabilities (u16): OSS 15:12, ISS 11:8, BSS 7:3, 64OK bit 0.
    pub const GCAP: usize = 0x00;
    /// Global Control (u32): bit 0 CRST (0 = controller in reset).
    pub const GCTL: usize = 0x08;
    /// State Change Status (u16): bit n = codec n present, write 1 to clear.
    pub const STATESTS: usize = 0x0E;
    /// Interrupt Control (u32).
    pub const INTCTL: usize = 0x20;
    /// CORB lower base address (u32); 128-byte aligned.
    pub const CORBLBASE: usize = 0x40;
    /// CORB upper base address (u32).
    pub const CORBUBASE: usize = 0x44;
    /// CORB write pointer (u16, low 8 bits).
    pub const CORBWP: usize = 0x48;
    /// CORB read pointer (u16); bit 15 = reset.
    pub const CORBRP: usize = 0x4A;
    /// CORB control (u8): bit 1 = DMA run.
    pub const CORBCTL: usize = 0x4C;
    /// CORB size (u8): bits 1:0 = size select, bits 7:4 = supported sizes.
    pub const CORBSIZE: usize = 0x4E;
    /// RIRB lower base address (u32); 128-byte aligned.
    pub const RIRBLBASE: usize = 0x50;
    /// RIRB upper base address (u32).
    pub const RIRBUBASE: usize = 0x54;
    /// RIRB write pointer (u16); bit 15 = reset.
    pub const RIRBWP: usize = 0x58;
    /// Response interrupt count (u16).
    pub const RINTCNT: usize = 0x5A;
    /// RIRB control (u8): bit 1 = DMA enable.
    pub const RIRBCTL: usize = 0x5C;
    /// RIRB status (u8).
    pub const RIRBSTS: usize = 0x5D;
    /// RIRB size (u8): same encoding as `CORBSIZE`.
    pub const RIRBSIZE: usize = 0x5E;
    /// First stream descriptor (input streams first, then output streams).
    pub const STREAM_BASE: usize = 0x80;
    /// Byte size of one stream descriptor.
    pub const STREAM_STRIDE: usize = 0x20;

    /// Stream descriptor: control, bytes 0..2 (u16 at +0, u8 at +2).
    pub const SD_CTL: usize = 0x00;
    /// Stream descriptor: status (u8); bit 2 = BCIS (buffer completion).
    pub const SD_STS: usize = 0x03;
    /// Stream descriptor: link position in buffer (u32).
    pub const SD_LPIB: usize = 0x04;
    /// Stream descriptor: cyclic buffer length (u32).
    pub const SD_CBL: usize = 0x08;
    /// Stream descriptor: last valid index (u16).
    pub const SD_LVI: usize = 0x0C;
    /// Stream descriptor: format (u16).
    pub const SD_FMT: usize = 0x12;
    /// Stream descriptor: BDL lower base (u32); 128-byte aligned.
    pub const SD_BDPL: usize = 0x18;
    /// Stream descriptor: BDL upper base (u32).
    pub const SD_BDPU: usize = 0x1C;

    /// SD_CTL bit 0: stream reset.
    pub const SD_CTL_SRST: u16 = 1 << 0;
    /// SD_CTL bit 1: stream run.
    pub const SD_CTL_RUN: u16 = 1 << 1;
    /// SD_STS bit 2: buffer completion interrupt status (set when a BDL entry
    /// with IOC completes; write 1 to clear).
    pub const SD_STS_BCIS: u8 = 1 << 2;

    /// Number of input streams from GCAP.
    pub fn input_streams(gcap: u16) -> usize {
        ((gcap >> 8) & 0xF) as usize
    }
    /// Number of output streams from GCAP.
    pub fn output_streams(gcap: u16) -> usize {
        ((gcap >> 12) & 0xF) as usize
    }
    /// Offset of output stream descriptor `n` (0-based among output streams):
    /// the input descriptors come first (section 3.3.1).
    pub fn output_stream_offset(gcap: u16, n: usize) -> usize {
        STREAM_BASE + (input_streams(gcap) + n) * STREAM_STRIDE
    }
}

/// Stream format word (section 3.7.1): 48 kHz base, x1 multiplier, /1 divisor,
/// 16-bit samples, stereo. Bit 14 = 44.1 kHz base (0 here), bits 13:11 mult,
/// 10:8 div, 6:4 bits per sample (001 = 16), 3:0 channels - 1.
pub const FORMAT_48K_16BIT_STEREO: u16 = 0x0011;
/// Sample rate the driver programs, in Hz.
pub const SAMPLE_RATE: u32 = 48_000;
/// Bytes per stereo frame (2 channels x 16 bits).
pub const FRAME_BYTES: usize = 4;

/// One Buffer Descriptor List entry (section 3.6.2), 16 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BdlEntry {
    /// Physical address of the buffer (128-byte aligned in practice).
    pub addr: u64,
    /// Buffer length in bytes.
    pub len: u32,
    /// Interrupt on completion: BCIS is set when this entry finishes.
    pub ioc: bool,
}

impl BdlEntry {
    /// Serialises to the 16-byte little-endian wire form.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.addr.to_le_bytes());
        b[8..12].copy_from_slice(&self.len.to_le_bytes());
        b[12..16].copy_from_slice(&(self.ioc as u32).to_le_bytes());
        b
    }
}

/// Splits a clip of `len` bytes (multiple of `FRAME_BYTES`) at `ring_phys`
/// into a two-entry BDL (the minimum the spec allows: LVI >= 1). The first
/// half is rounded down to 128 bytes; IOC is set on the last entry only.
/// Returns the entries and the cyclic buffer length to program.
pub fn one_shot_bdl(ring_phys: u64, len: u32) -> ([BdlEntry; 2], u32) {
    let first = (len / 2) & !127;
    let second = len - first;
    (
        [
            BdlEntry { addr: ring_phys, len: first, ioc: false },
            BdlEntry { addr: ring_phys + first as u64, len: second, ioc: true },
        ],
        len,
    )
}

/// Maps a percentage (0-100) to an amp gain step for an amp with `num_steps`
/// (the "number of steps" field of the amp capabilities, 0 = a single step;
/// valid gains are `0..=num_steps`), rounding to nearest.
pub fn volume_to_gain(volume: u8, num_steps: u8) -> u8 {
    let v = volume.min(100) as u32;
    ((v * num_steps as u32 + 50) / 100) as u8
}

/// Inverse of `volume_to_gain`, for reading back a gain into a percentage.
pub fn gain_to_volume(gain: u8, num_steps: u8) -> u8 {
    if num_steps == 0 {
        return 100;
    }
    (((gain.min(num_steps) as u32) * 100 + num_steps as u32 / 2) / num_steps as u32) as u8
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn stream_offsets_follow_gcap() {
        // QEMU intel-hda: 4 input + 4 output streams.
        let gcap = 0x4401u16;
        assert_eq!(regs::input_streams(gcap), 4);
        assert_eq!(regs::output_streams(gcap), 4);
        assert_eq!(regs::output_stream_offset(gcap, 0), 0x80 + 4 * 0x20);
        assert_eq!(regs::output_stream_offset(gcap, 1), 0x80 + 5 * 0x20);
    }

    #[test]
    fn format_word_is_48k_16bit_stereo() {
        let f = FORMAT_48K_16BIT_STEREO;
        assert_eq!(f >> 14 & 1, 0, "48 kHz base");
        assert_eq!(f >> 11 & 7, 0, "x1 multiplier");
        assert_eq!(f >> 8 & 7, 0, "/1 divisor");
        assert_eq!(f >> 4 & 7, 1, "16 bits");
        assert_eq!(f & 0xF, 1, "2 channels");
    }

    #[test]
    fn bdl_entry_wire_layout() {
        let e = BdlEntry { addr: 0x1_2345_6780, len: 0xC000, ioc: true };
        let b = e.to_bytes();
        assert_eq!(&b[0..8], &0x1_2345_6780u64.to_le_bytes());
        assert_eq!(&b[8..12], &0xC000u32.to_le_bytes());
        assert_eq!(b[12], 1);
        assert_eq!(&b[13..16], &[0, 0, 0]);
    }

    #[test]
    fn one_shot_bdl_covers_the_clip_exactly() {
        for len in [4096u32, 192_000, 100, 128, 255 * 4] {
            let (e, cbl) = one_shot_bdl(0x10_0000, len);
            assert_eq!(cbl, len);
            assert_eq!(e[0].len + e[1].len, len);
            assert_eq!(e[1].addr, e[0].addr + e[0].len as u64);
            assert_eq!(e[0].len % 128, 0);
            assert!(!e[0].ioc && e[1].ioc);
        }
    }

    #[test]
    fn volume_maps_to_gain_steps() {
        assert_eq!(volume_to_gain(0, 74), 0);
        assert_eq!(volume_to_gain(100, 74), 74);
        assert_eq!(volume_to_gain(50, 74), 37);
        assert_eq!(volume_to_gain(200, 74), 74, "clamped");
        assert_eq!(volume_to_gain(80, 0), 0, "single-step amp");
        assert_eq!(gain_to_volume(74, 74), 100);
        assert_eq!(gain_to_volume(37, 74), 50);
        assert_eq!(gain_to_volume(0, 0), 100);
    }
}
