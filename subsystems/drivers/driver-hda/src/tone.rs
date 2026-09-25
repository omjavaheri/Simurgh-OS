//! ============================================================================
//! tone.rs — test tone generator (no floating point, no libm).
//!
//! Purpose: fill a PCM buffer with a sine of a given frequency for the boot
//! self-check, the UI "Test" button and host tests. Sine by the parabolic
//! approximation with one correction pass (about 0.1 percent error), driven by
//! a 32-bit phase accumulator, all in integers so it also runs in the
//! `no_std` driver process without soft-float support.
//! ============================================================================

use crate::{FRAME_BYTES, SAMPLE_RATE};

/// Sine of a phase (full turn = 2^32) as a Q15 value in `-32767..=32767`.
pub fn sin_q15(phase: u32) -> i32 {
    // t in Q15 covers [-1, 1) for half-turn units: sin(pi * t).
    let t = (phase as i32) >> 16;
    let a = t.abs();
    let y = (4 * t * (32768 - a)) >> 15;
    let ya = y.abs();
    // Correction: y + 0.225 * (y*|y| - y), 0.225 ~ 7373 / 32768.
    let corr = (((y * ya) >> 15) - y) * 7373 >> 15;
    (y + corr).clamp(-32767, 32767)
}

/// Writes `frames` stereo frames (16-bit little-endian, same sample on both
/// channels) of a `freq_hz` sine at `amplitude_q15` (32767 = full scale) into
/// `out`, starting at frame 0. Returns the number of bytes written (limited by
/// `out.len()`, a whole number of frames).
pub fn fill_sine(out: &mut [u8], freq_hz: u32, frames: usize, amplitude_q15: i32) -> usize {
    let inc = ((freq_hz as u64) << 32) / SAMPLE_RATE as u64;
    let n = frames.min(out.len() / FRAME_BYTES);
    let mut phase = 0u32;
    for i in 0..n {
        let s = ((sin_q15(phase) as i64 * amplitude_q15 as i64) >> 15) as i16;
        let b = s.to_le_bytes();
        let o = i * FRAME_BYTES;
        out[o] = b[0];
        out[o + 1] = b[1];
        out[o + 2] = b[0];
        out[o + 3] = b[1];
        phase = phase.wrapping_add(inc as u32);
    }
    n * FRAME_BYTES
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    #[test]
    fn sine_hits_the_key_points_within_a_small_error() {
        assert_eq!(sin_q15(0), 0);
        assert!((sin_q15(1 << 30) - 32767).abs() < 200, "quarter turn is the peak");
        assert!((sin_q15(3 << 30) + 32767).abs() < 200, "three quarters is the trough");
        assert!(sin_q15(1 << 31).abs() < 50, "half turn is zero");
        // Compare against a straightforward f64 sine over the whole turn.
        for i in 0..1024u32 {
            let phase = i << 22;
            let want = (phase as f64 / 4294967296.0 * 2.0 * core::f64::consts::PI).sin() * 32767.0;
            assert!((sin_q15(phase) as f64 - want).abs() < 400.0, "phase {i}");
        }
    }

    #[test]
    fn tone_has_the_requested_frequency_and_amplitude() {
        let frames = 48_000;
        let mut buf = vec![0u8; frames * FRAME_BYTES];
        let n = fill_sine(&mut buf, 440, frames, 16384);
        assert_eq!(n, frames * FRAME_BYTES);
        let mut crossings = 0;
        let mut prev = 0i16;
        let mut peak = 0i16;
        for f in buf.chunks(FRAME_BYTES) {
            let l = i16::from_le_bytes([f[0], f[1]]);
            let r = i16::from_le_bytes([f[2], f[3]]);
            assert_eq!(l, r, "both channels carry the tone");
            if prev < 0 && l >= 0 {
                crossings += 1;
            }
            prev = l;
            peak = peak.max(l);
        }
        assert!((439..=441).contains(&crossings), "got {crossings} cycles in 1 s");
        assert!((peak as i32 - 16384).abs() < 300, "peak {peak}");
    }

    #[test]
    fn fill_is_bounded_by_the_buffer() {
        let mut buf = [0u8; 10];
        assert_eq!(fill_sine(&mut buf, 1000, 100, 32767), 8);
    }
}
