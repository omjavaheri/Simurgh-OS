//! ============================================================================
//! controller.rs — the HDA controller over MMIO: reset, CORB/RIRB, stream.
//!
//! Purpose: the only module that dereferences raw pointers. It drives the
//! register protocol of spec sections 3 and 4 through a `Layout` (BAR0 VA plus
//! the driver's DMA areas with their PHYSICAL addresses, which a driver process
//! cannot translate itself, so the kernel passes them in) and a `Platform`
//! (clock + sleep). Codec-side setup (`configure_path`, `set_volume`) is built
//! from the verb encoders, so it only ever talks through `command`.
//!
//! Safety/invariants: `Layout` must describe mapped memory: BAR0 covering the
//! registers used here (first 0x200 bytes plus stream descriptors), the command
//! area of `CMD_AREA_LEN` bytes and the PCM ring. DMA areas are only touched
//! through volatile accesses.
//! ============================================================================

use crate::codec::OutputPath;
use crate::regs;
use crate::verb::*;
use crate::{one_shot_bdl, volume_to_gain, FORMAT_48K_16BIT_STEREO};
use core::ptr::{read_volatile, write_volatile};

/// Offsets inside the two-page command area.
pub mod cmd_area {
    /// Header the kernel fills: u64 cmd_phys, u64 ring_phys, u64 ring_len,
    /// u64 flags (bit 0: boot self-check requested), u64 initial volume.
    pub const HEADER: usize = 0x000;
    /// The two-entry BDL (128-byte aligned).
    pub const BDL: usize = 0x080;
    /// Text log area read by the kernel's `HDA_LOG` syscall.
    pub const LOG: usize = 0x400;
    /// Longest log line.
    pub const LOG_MAX: usize = 512;
    /// CORB (256 entries x 4 bytes, 128-byte aligned).
    pub const CORB: usize = 0x1000;
    /// RIRB (256 entries x 8 bytes, 128-byte aligned).
    pub const RIRB: usize = 0x1400;
    /// Total bytes of the area (two pages).
    pub const LEN: usize = 0x2000;
}

/// Stream tag used for the single output stream (1..=15; 0 is reserved).
pub const STREAM_TAG: u8 = 1;

/// Time source for polling waits.
pub trait Platform {
    /// Monotonic nanoseconds.
    fn now_ns(&self) -> u64;
    /// Sleep for about `ns` (scheduler tick granularity).
    fn sleep_ns(&self, ns: u64);
}

/// Where the controller's memory lives.
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    /// BAR0 virtual address.
    pub bar0: usize,
    /// Command area virtual address.
    pub cmd_va: usize,
    /// Command area physical address.
    pub cmd_phys: u64,
    /// PCM ring virtual address.
    pub ring_va: usize,
    /// PCM ring physical address (contiguous).
    pub ring_phys: u64,
    /// PCM ring length in bytes.
    pub ring_len: usize,
}

/// Controller-level failures (codes are published in the status page).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HdaError {
    /// GCTL.CRST did not toggle.
    ResetTimeout = 1,
    /// No codec signalled presence after reset.
    NoCodec = 2,
    /// CORB/RIRB pointer reset did not complete.
    RingSetup = 3,
    /// A stream register did not respond.
    StreamTimeout = 4,
    /// Clip does not fit the ring or is empty.
    BadLength = 5,
}

/// The controller.
pub struct Hda<'p, P: Platform> {
    l: Layout,
    p: &'p P,
    gcap: u16,
    corb_entries: u16,
    rirb_entries: u16,
    corb_wp: u16,
    rirb_rp: u16,
    sd: usize,
}

impl<'p, P: Platform> Hda<'p, P> {
    /// Wraps a mapped controller. Nothing is touched until `init`.
    pub fn new(l: Layout, p: &'p P) -> Self {
        Hda { l, p, gcap: 0, corb_entries: 256, rirb_entries: 256, corb_wp: 0, rirb_rp: 0, sd: 0 }
    }

    fn rd8(&self, off: usize) -> u8 {
        // SAFETY: `Layout::bar0` maps the register file (module contract).
        unsafe { read_volatile((self.l.bar0 + off) as *const u8) }
    }
    fn rd16(&self, off: usize) -> u16 {
        // SAFETY: as `rd8`.
        unsafe { read_volatile((self.l.bar0 + off) as *const u16) }
    }
    fn rd32(&self, off: usize) -> u32 {
        // SAFETY: as `rd8`.
        unsafe { read_volatile((self.l.bar0 + off) as *const u32) }
    }
    fn wr8(&self, off: usize, v: u8) {
        // SAFETY: as `rd8`.
        unsafe { write_volatile((self.l.bar0 + off) as *mut u8, v) }
    }
    fn wr16(&self, off: usize, v: u16) {
        // SAFETY: as `rd8`.
        unsafe { write_volatile((self.l.bar0 + off) as *mut u16, v) }
    }
    fn wr32(&self, off: usize, v: u32) {
        // SAFETY: as `rd8`.
        unsafe { write_volatile((self.l.bar0 + off) as *mut u32, v) }
    }

    /// Polls `cond` until true or `timeout_ns`: spins for the first 300 us
    /// (device answers are usually immediate), then sleeps.
    fn wait_until(&self, timeout_ns: u64, mut cond: impl FnMut(&Self) -> bool) -> bool {
        let start = self.p.now_ns();
        loop {
            if cond(self) {
                return true;
            }
            let el = self.p.now_ns().wrapping_sub(start);
            if el > timeout_ns {
                return false;
            }
            if el < 300_000 {
                core::hint::spin_loop();
            } else {
                self.p.sleep_ns(1_000_000);
            }
        }
    }

    /// Resets the controller and returns the bitmask of codecs that reported
    /// presence (STATESTS). Section 4.2.2: CRST low, then high, wait >= 521 us.
    pub fn reset(&mut self) -> Result<u16, HdaError> {
        self.gcap = self.rd16(regs::GCAP);
        self.wr32(regs::GCTL, self.rd32(regs::GCTL) & !1);
        if !self.wait_until(50_000_000, |s| s.rd32(regs::GCTL) & 1 == 0) {
            return Err(HdaError::ResetTimeout);
        }
        self.p.sleep_ns(100_000);
        self.wr32(regs::GCTL, self.rd32(regs::GCTL) | 1);
        if !self.wait_until(50_000_000, |s| s.rd32(regs::GCTL) & 1 == 1) {
            return Err(HdaError::ResetTimeout);
        }
        // Codecs need up to ~1 ms after CRST to signal; allow much longer.
        self.wait_until(200_000_000, |s| s.rd16(regs::STATESTS) & 0x7FFF != 0);
        let mask = self.rd16(regs::STATESTS) & 0x7FFF;
        if mask == 0 {
            return Err(HdaError::NoCodec);
        }
        self.wr16(regs::STATESTS, mask);
        self.sd = regs::output_stream_offset(self.gcap, 0);
        Ok(mask)
    }

    fn ring_size_bits(cap_byte: u8) -> (u8, u16) {
        // Bits 7:4 of CORBSIZE/RIRBSIZE: supported sizes (4 = 256, 5 = 16, 6 = 2
        // entries as bit flags 0x40, 0x20, 0x10); bits 1:0 select (2 = 256, 1 = 16, 0 = 2).
        if cap_byte & 0x40 != 0 {
            (2, 256)
        } else if cap_byte & 0x20 != 0 {
            (1, 16)
        } else {
            (0, 2)
        }
    }

    /// Sets up and starts the CORB and RIRB (section 4.4).
    pub fn start_rings(&mut self) -> Result<(), HdaError> {
        self.wr8(regs::CORBCTL, 0);
        self.wr8(regs::RIRBCTL, 0);
        let (csel, centries) = Self::ring_size_bits(self.rd8(regs::CORBSIZE));
        let (rsel, rentries) = Self::ring_size_bits(self.rd8(regs::RIRBSIZE));
        self.wr8(regs::CORBSIZE, (self.rd8(regs::CORBSIZE) & !3) | csel);
        self.wr8(regs::RIRBSIZE, (self.rd8(regs::RIRBSIZE) & !3) | rsel);
        self.corb_entries = centries;
        self.rirb_entries = rentries;
        let corb = self.l.cmd_phys + cmd_area::CORB as u64;
        let rirb = self.l.cmd_phys + cmd_area::RIRB as u64;
        self.wr32(regs::CORBLBASE, corb as u32);
        self.wr32(regs::CORBUBASE, (corb >> 32) as u32);
        self.wr32(regs::RIRBLBASE, rirb as u32);
        self.wr32(regs::RIRBUBASE, (rirb >> 32) as u32);
        // CORB read pointer reset handshake (section 3.3.21): set bit 15,
        // wait until it reads back 1, clear it, wait until it reads 0.
        self.wr16(regs::CORBRP, 1 << 15);
        if !self.wait_until(10_000_000, |s| s.rd16(regs::CORBRP) & (1 << 15) != 0) {
            return Err(HdaError::RingSetup);
        }
        self.wr16(regs::CORBRP, 0);
        if !self.wait_until(10_000_000, |s| s.rd16(regs::CORBRP) & (1 << 15) == 0) {
            return Err(HdaError::RingSetup);
        }
        self.wr16(regs::CORBWP, 0);
        self.corb_wp = 0;
        self.wr16(regs::RIRBWP, 1 << 15);
        self.rirb_rp = 0;
        self.wr16(regs::RINTCNT, 1);
        // DMA enable + response-interrupt flag enable (bit 0): QEMU only counts and
        // flags RINTCNT responses when it is set, and only then does the RIRBSTS
        // acknowledge restart the CORB. No interrupt is delivered: INTCTL stays 0.
        self.wr8(regs::RIRBCTL, 0x03);
        self.wr8(regs::CORBCTL, 1 << 1); // DMA run
        if !self.wait_until(10_000_000, |s| s.rd8(regs::CORBCTL) & (1 << 1) != 0) {
            return Err(HdaError::RingSetup);
        }
        Ok(())
    }

    /// Sends one verb through the CORB and returns its solicited response.
    pub fn command(&mut self, cmd: u32) -> Option<u32> {
        let wp = (self.corb_wp + 1) % self.corb_entries;
        // SAFETY: the CORB lives in the command area (module contract).
        unsafe { write_volatile((self.l.cmd_va + cmd_area::CORB + wp as usize * 4) as *mut u32, cmd) };
        self.corb_wp = wp;
        self.wr16(regs::CORBWP, wp);
        let deadline = self.p.now_ns() + 100_000_000;
        loop {
            let hw = self.rd16(regs::RIRBWP) & 0xFF;
            while self.rirb_rp != hw {
                self.rirb_rp = (self.rirb_rp + 1) % self.rirb_entries;
                let e = self.l.cmd_va + cmd_area::RIRB + self.rirb_rp as usize * 8;
                // SAFETY: the RIRB lives in the command area (module contract).
                let (resp, ex) = unsafe { (read_volatile(e as *const u32), read_volatile((e + 4) as *const u32)) };
                if ex & (1 << 4) == 0 {
                    // Acknowledge RINTFL (write 1 to clear): the controller stops
                    // fetching commands once RINTCNT responses are unacknowledged.
                    self.wr8(regs::RIRBSTS, 0x05);
                    return Some(resp);
                }
                // Unsolicited response (jack event): not used, skip it.
            }
            if self.p.now_ns() > deadline {
                return None;
            }
            core::hint::spin_loop();
        }
    }

    /// Codec-side setup for the chosen path: power up, select connections,
    /// bind the DAC to the stream tag and format, enable the pin output/EAPD,
    /// and put every path amp at 0 dB unmuted. Volume is applied separately.
    pub fn configure_path(&mut self, p: &OutputPath) {
        let cad = p.cad;
        self.command(verb12(cad, p.afg, SET_POWER, 0));
        for j in 0..p.len {
            let nid = p.nodes[j];
            self.command(verb12(cad, nid, SET_POWER, 0));
            if j >= 1 {
                self.command(verb12(cad, nid, SET_CONN_SEL, p.conn_sel[j]));
            }
            if let Some(a) = p.amps[j] {
                self.command(verb4(cad, nid, SET_AMP, amp_payload(true, true, true, false, a.offset)));
            }
        }
        self.command(verb4(cad, p.dac(), SET_FMT, FORMAT_48K_16BIT_STEREO));
        self.command(verb12(cad, p.dac(), SET_STREAM_CHAN, STREAM_TAG << 4));
        self.command(verb12(cad, p.pin(), SET_PIN_CTL, 0x40));
        if p.pin_eapd {
            self.command(verb12(cad, p.pin(), SET_EAPD, 0x02));
        }
    }

    /// Applies master volume (0..=100) and mute on the path's volume amp.
    /// Returns false when the path has no adjustable amp at all.
    pub fn set_volume(&mut self, p: &OutputPath, volume: u8, muted: bool) -> bool {
        let Some(i) = p.volume_node() else { return false };
        let a = p.amps[i].expect("volume_node points at an amp");
        let (mute_bit, gain) = if a.mute {
            (muted, volume_to_gain(volume, a.num_steps))
        } else {
            // No mute bit: mute by gain 0.
            (false, if muted { 0 } else { volume_to_gain(volume, a.num_steps) })
        };
        self.command(verb4(p.cad, p.nodes[i], SET_AMP, amp_payload(true, true, true, mute_bit, gain)));
        true
    }

    /// Resets the output stream descriptor (section 3.3.35: SRST handshake).
    pub fn stream_reset(&mut self) -> Result<(), HdaError> {
        let sd = self.sd;
        self.wr16(sd + regs::SD_CTL, 0);
        self.wr16(sd + regs::SD_CTL, regs::SD_CTL_SRST);
        if !self.wait_until(10_000_000, |s| s.rd16(sd + regs::SD_CTL) & regs::SD_CTL_SRST != 0) {
            return Err(HdaError::StreamTimeout);
        }
        self.wr16(sd + regs::SD_CTL, 0);
        if !self.wait_until(10_000_000, |s| s.rd16(sd + regs::SD_CTL) & regs::SD_CTL_SRST == 0) {
            return Err(HdaError::StreamTimeout);
        }
        Ok(())
    }

    /// Starts the one-shot clip of `len` bytes already in the ring.
    pub fn stream_start(&mut self, len: u32) -> Result<(), HdaError> {
        if len < 512 || len as usize > self.l.ring_len || len as usize % crate::FRAME_BYTES != 0 {
            return Err(HdaError::BadLength);
        }
        self.stream_reset()?;
        let sd = self.sd;
        let (entries, cbl) = one_shot_bdl(self.l.ring_phys, len);
        for (i, e) in entries.iter().enumerate() {
            let b = e.to_bytes();
            for (k, byte) in b.iter().enumerate() {
                // SAFETY: the BDL lives in the command area (module contract).
                unsafe { write_volatile((self.l.cmd_va + cmd_area::BDL + i * 16 + k) as *mut u8, *byte) };
            }
        }
        let bdl = self.l.cmd_phys + cmd_area::BDL as u64;
        self.wr32(sd + regs::SD_BDPL, bdl as u32);
        self.wr32(sd + regs::SD_BDPU, (bdl >> 32) as u32);
        self.wr32(sd + regs::SD_CBL, cbl);
        self.wr16(sd + regs::SD_LVI, 1);
        self.wr16(sd + regs::SD_FMT, FORMAT_48K_16BIT_STEREO);
        self.wr8(sd + regs::SD_STS, 0x1C); // clear BCIS/FIFOE/DESCE
        self.wr8(sd + regs::SD_CTL + 2, STREAM_TAG << 4);
        self.wr16(sd + regs::SD_CTL, regs::SD_CTL_RUN);
        Ok(())
    }

    /// Stops the stream (RUN low, then a descriptor reset so the next start
    /// begins at position 0).
    pub fn stream_stop(&mut self) {
        let sd = self.sd;
        self.wr16(sd + regs::SD_CTL, 0);
        self.wait_until(10_000_000, |s| s.rd16(sd + regs::SD_CTL) & regs::SD_CTL_RUN == 0);
        let _ = self.stream_reset();
    }

    /// Link position in buffer of the output stream, in bytes.
    pub fn position(&self) -> u32 {
        self.rd32(self.sd + regs::SD_LPIB)
    }

    /// Whether the last BDL entry (IOC) completed since the stream started.
    pub fn buffer_done(&self) -> bool {
        self.rd8(self.sd + regs::SD_STS) & regs::SD_STS_BCIS != 0
    }

    /// The PCM ring as a mutable byte slice (for the driver to fill).
    ///
    /// # Safety
    /// The caller must not hold another slice of the ring and must not call
    /// this while the DMA engine is reading a region it rewrites.
    pub unsafe fn ring_mut(&self) -> &'static mut [u8] {
        // SAFETY: `Layout::ring_va` maps `ring_len` bytes (module contract).
        unsafe { core::slice::from_raw_parts_mut(self.l.ring_va as *mut u8, self.l.ring_len) }
    }
}

impl<'p, P: Platform> Hda<'p, P> {
    /// Register snapshot for failure diagnostics: GCTL, STATESTS, CORBWP,
    /// CORBRP, CORBCTL, CORBSIZE, RIRBWP, RIRBCTL, RIRBSTS, RIRBSIZE, and the
    /// first RIRB dword.
    pub fn diagnostics(&self) -> [u32; 11] {
        // SAFETY: the RIRB lives in the command area (module contract).
        let r0 = unsafe { read_volatile((self.l.cmd_va + cmd_area::RIRB + 8) as *const u32) };
        [
            self.rd32(regs::GCTL),
            self.rd16(regs::STATESTS) as u32,
            self.rd16(regs::CORBWP) as u32,
            self.rd16(regs::CORBRP) as u32,
            self.rd8(regs::CORBCTL) as u32,
            self.rd8(regs::CORBSIZE) as u32,
            self.rd16(regs::RIRBWP) as u32,
            self.rd8(regs::RIRBCTL) as u32,
            self.rd8(regs::RIRBSTS) as u32,
            self.rd8(regs::RIRBSIZE) as u32,
            r0,
        ]
    }
}
