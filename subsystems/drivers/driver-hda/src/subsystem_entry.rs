//! ============================================================================
//! subsystem_entry.rs — the HDA driver's process entry point (x86_64 only).
//!
//! Purpose: `subsystem_main` probes the controller (reset, CORB/RIRB, codec
//! walk, path setup), publishes the STATUS record on the shared audio page,
//! optionally plays a 440 Hz self-check tone, then serves the page's mailbox
//! forever (set volume / mute, play tone, play PCM from the ring, stop).
//!
//! Architecture reference: docs/audio-plan.md.
//!
//! Position in the system: `kernel_arch_glue::spawn_hda_driver` spawns this
//! process, pre-maps BAR0, the audio page, the two-page command area and the
//! PCM ring at the VAs below, and grants one Notification at capability slot 0
//! that nobody signals: the driver sleeps on it with a timeout (Netstack's
//! pattern) since it polls. There is no IPC endpoint: clients use the page.
//!
//! The only architecture-specific piece is `raw_syscall` (`int 0x80`), the same
//! narrow exception every other x86_64 U-mode subsystem documents.
//! ============================================================================

use crate::codec::{self, OutputPath};
use crate::controller::{cmd_area, Hda, HdaError, Layout, Platform};
use crate::page::{self, off, Command, Status};
use crate::tone;
use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};

/// BAR0 window VA (one page: the registers used live below 0x1000).
const BAR0_VA: usize = 0xD8E0_0000;
/// Audio page VA.
const PAGE_VA: usize = 0xD8E1_0000;
/// Command area VA (two pages: header/BDL/log, then CORB/RIRB).
const CMD_VA: usize = 0xD8E2_0000;
/// PCM ring VA (contiguous physical memory).
const RING_VA: usize = 0xD8E4_0000;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::NOW_NS`.
const NOW_NS: usize = 86;
/// Must stay numerically equal to `sys::NOTIF_WAIT_TIMEOUT`.
const NOTIF_WAIT_TIMEOUT: usize = 139;
/// Must stay numerically equal to `sys::HDA_LOG`.
const HDA_LOG: usize = 141;
/// Capability slot of the sleep Notification (first grant into an empty space).
const SLEEP_NOTIF_CAP: usize = 0;

/// Header flag set by the kernel: play the boot self-check tone.
const HDR_FLAG_SELFTEST: u64 = 1;
/// Volume used when the kernel supplies none.
const DEFAULT_VOLUME: u8 = 75;
/// Silence appended after a clip so the DMA wrap-around replays nothing.
const TAIL_BYTES: usize = 7680;

/// # Safety
/// `int 0x80` from Ring 3 traps to `hal_x86_64::cpu`'s DPL-3 gate, which
/// preserves every register except `rax`/`rsi`.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn raw_syscall(a7: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") a7 => ret,
            in("rdi") a0,
            in("rsi") a1,
            options(nostack),
        );
    }
    ret
}

/// Host-build stand-in (this process never runs on a non-x86_64 build).
#[cfg(not(target_arch = "x86_64"))]
#[inline(never)]
unsafe fn raw_syscall(_a7: usize, _a0: usize, _a1: usize) -> usize {
    unreachable!("driver-hda's subsystem_main never runs on a non-x86_64 build")
}

// Same stack-slot-reuse defence every other subsystem entry applies to literal
// syscall arguments (see driver_virtio_blk::subsystem_entry's zero!()).
#[cfg(target_arch = "x86_64")]
macro_rules! zero {
    () => {{
        let mut v: usize = 0;
        // SAFETY: a no-op asm block; `v` is read back unchanged.
        core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
        v
    }};
}
#[cfg(not(target_arch = "x86_64"))]
macro_rules! zero {
    () => {
        0usize
    };
}

struct Sys;

impl Platform for Sys {
    fn now_ns(&self) -> u64 {
        // SAFETY: `raw_syscall`'s contract; never blocks.
        unsafe { raw_syscall(NOW_NS, zero!(), zero!()) as u64 }
    }
    fn sleep_ns(&self, ns: u64) {
        // SAFETY: `raw_syscall`'s contract. Blocks on a notification nobody
        // signals until the deadline; the result is irrelevant.
        unsafe { raw_syscall(NOTIF_WAIT_TIMEOUT, SLEEP_NOTIF_CAP, ns as usize) };
    }
}

/// Fixed-buffer writer over the log area of the command area.
struct LogBuf {
    len: usize,
}

impl Write for LogBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len < cmd_area::LOG_MAX {
                // SAFETY: the log area lies inside the mapped command area.
                unsafe { write_volatile((CMD_VA + cmd_area::LOG + self.len) as *mut u8, b) };
                self.len += 1;
            }
        }
        Ok(())
    }
}

/// Prints one line on the kernel serial log (`hda: <text>`).
fn log(args: core::fmt::Arguments) {
    let mut w = LogBuf { len: 0 };
    let _ = w.write_fmt(args);
    // SAFETY: `raw_syscall`'s contract; never blocks.
    unsafe { raw_syscall(HDA_LOG, w.len, zero!()) };
}

fn page_rd32(o: usize) -> u32 {
    // SAFETY: the audio page is mapped R+W at `PAGE_VA`.
    unsafe { read_volatile((PAGE_VA + o) as *const u32) }
}
fn page_wr32(o: usize, v: u32) {
    // SAFETY: as `page_rd32`.
    unsafe { write_volatile((PAGE_VA + o) as *mut u32, v) }
}

/// Publishes `st` on the page under the seqlock (odd while writing).
fn publish(st: &Status) {
    let cur = page_rd32(off::SEQ);
    let base = cur & !1;
    page_wr32(off::SEQ, base.wrapping_add(1));
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    let rec = page::encode_status(st, 0);
    // Bytes 0..8 (magic) and 12..64; bytes 8..12 are the seqlock counter.
    for (i, b) in rec.iter().enumerate() {
        if !(8..12).contains(&i) {
            // SAFETY: inside the mapped audio page.
            unsafe { write_volatile((PAGE_VA + i) as *mut u8, *b) };
        }
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    page_wr32(off::SEQ, base.wrapping_add(2));
}

struct Driver<'p> {
    hda: Hda<'p, Sys>,
    path: OutputPath,
    st: Status,
    ring_len: usize,
    plat: &'p Sys,
}

impl<'p> Driver<'p> {
    fn apply_volume(&mut self) {
        self.hda.set_volume(&self.path, self.st.volume, self.st.muted());
    }

    fn set_flag(&mut self, flag: u8, on: bool) {
        if on {
            self.st.flags |= flag;
        } else {
            self.st.flags &= !flag;
        }
    }

    /// Runs the mailbox command, if a new one is pending. While `playing`,
    /// only volume, mute and stop are honoured. Returns true on a stop request.
    fn poll_mailbox(&mut self, playing: bool) -> Option<(Command, u32)> {
        let seq = page_rd32(off::CMD_SEQ);
        if seq == page_rd32(off::ACK_SEQ) {
            return None;
        }
        let cmd = page::decode_command(page_rd32(off::CMD), page_rd32(off::ARG0), page_rd32(off::ARG1));
        let mut deferred = None;
        match cmd {
            Some(Command::SetVolume(v)) => {
                self.st.volume = v;
                self.apply_volume();
                log(format_args!("volume set to {}%", v));
            }
            Some(Command::SetMute(m)) => {
                self.set_flag(page::FLAG_MUTED, m);
                self.apply_volume();
                log(format_args!("mute {}", if m { "on" } else { "off" }));
            }
            Some(c @ Command::Stop) => deferred = Some((c, seq)),
            Some(c) if !playing => deferred = Some((c, seq)),
            _ => {}
        }
        publish(&self.st);
        if deferred.is_none() {
            page_wr32(off::ACK_SEQ, seq);
        }
        deferred
    }

    /// Plays `clip_bytes` of PCM already in the ring; returns when done.
    fn play(&mut self, clip_bytes: usize) {
        let tail = TAIL_BYTES.min(self.ring_len.saturating_sub(clip_bytes)) & !3;
        // SAFETY: only this driver touches the ring; the stream is stopped.
        let ring = unsafe { self.hda.ring_mut() };
        for b in &mut ring[clip_bytes..clip_bytes + tail] {
            *b = 0;
        }
        self.set_flag(page::FLAG_PLAYING, true);
        publish(&self.st);
        if let Err(e) = self.hda.stream_start((clip_bytes + tail) as u32) {
            log(format_args!("stream start failed: {:?}", e));
            self.st.error = e as u32;
            self.set_flag(page::FLAG_PLAYING, false);
            publish(&self.st);
            return;
        }
        let start = self.plat.now_ns();
        let dur_ns = clip_bytes as u64 * 1_000_000_000 / (crate::SAMPLE_RATE as u64 * crate::FRAME_BYTES as u64);
        let mut last = 0u32;
        let reason = loop {
            self.plat.sleep_ns(4_000_000);
            if let Some((Command::Stop, seq)) = self.poll_mailbox(true) {
                page_wr32(off::ACK_SEQ, seq);
                break "stopped by request";
            }
            let pos = self.hda.position();
            if self.hda.buffer_done() {
                break "buffer complete";
            }
            if pos < last {
                break "position wrapped";
            }
            last = pos;
            if pos as usize >= clip_bytes + 960 {
                break "end of clip reached";
            }
            // Generous: the emulated audio clock can run slower than the guest clock.
            if self.plat.now_ns().wrapping_sub(start) > dur_ns * 4 + 400_000_000 {
                break "time limit";
            }
        };
        let end_pos = self.hda.position();
        self.hda.stream_stop();
        self.st.plays += 1;
        self.set_flag(page::FLAG_PLAYING, false);
        publish(&self.st);
        log(format_args!(
            "playback finished ({}): {} of {} bytes, {} ms elapsed, clips played {}",
            reason,
            end_pos,
            clip_bytes,
            self.plat.now_ns().wrapping_sub(start) / 1_000_000,
            self.st.plays
        ));
    }

    fn play_tone(&mut self, hz: u32, ms: u32) {
        let hz = hz.clamp(20, 20_000);
        let frames = (ms as usize * crate::SAMPLE_RATE as usize / 1000).min(self.ring_len / crate::FRAME_BYTES - TAIL_BYTES / crate::FRAME_BYTES);
        // SAFETY: only this driver touches the ring; the stream is stopped.
        let ring = unsafe { self.hda.ring_mut() };
        let bytes = tone::fill_sine(ring, hz, frames, 16384);
        log(format_args!("playing {} Hz tone, {} ms ({} bytes)", hz, ms, bytes));
        self.play(bytes);
    }

    fn play_pcm(&mut self, bytes: u32) {
        let n = (bytes as usize) & !3;
        if n == 0 || n > self.ring_len {
            log(format_args!("play PCM rejected: {} bytes", bytes));
            return;
        }
        log(format_args!("playing {} bytes of PCM from the ring", n));
        self.play(n);
    }

    fn run_deferred(&mut self, c: Command, seq: u32) {
        match c {
            Command::PlayTone { hz, ms } => self.play_tone(hz, ms),
            Command::PlayPcm { bytes } => self.play_pcm(bytes),
            _ => {}
        }
        page_wr32(off::ACK_SEQ, seq);
    }
}

fn header_u64(i: usize) -> u64 {
    // SAFETY: the command area header is mapped R+W at `CMD_VA`.
    unsafe { read_volatile((CMD_VA + cmd_area::HEADER + i * 8) as *const u64) }
}

fn fail(st: &mut Status, e: HdaError, what: &str) -> ! {
    log(format_args!("probe failed: {} ({:?})", what, e));
    st.state = page::STATE_ERROR;
    st.error = e as u32;
    publish(st);
    idle_forever()
}

fn idle_forever() -> ! {
    loop {
        Sys.sleep_ns(500_000_000);
    }
}

/// The HDA driver's process entry point.
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let plat = Sys;
    let layout = Layout {
        bar0: BAR0_VA,
        cmd_va: CMD_VA,
        cmd_phys: header_u64(0),
        ring_va: RING_VA,
        ring_phys: header_u64(1),
        ring_len: header_u64(2) as usize,
    };
    let selftest = header_u64(3) & HDR_FLAG_SELFTEST != 0;
    let init_volume = match header_u64(4) {
        0 => DEFAULT_VOLUME,
        v => v.min(100) as u8,
    };

    let mut st = Status::NONE;
    st.state = page::STATE_STARTING;
    publish(&st);

    let mut hda = Hda::new(layout, &plat);
    let mask = match hda.reset() {
        Ok(m) => m,
        Err(e) => fail(&mut st, e, "controller reset"),
    };
    if let Err(e) = hda.start_rings() {
        fail(&mut st, e, "CORB/RIRB setup");
    }
    log(format_args!("controller up, codec mask {:#x}", mask));

    let mut found = None;
    for cad in 0..15u8 {
        if mask & (1 << cad) == 0 {
            continue;
        }
        match codec::walk(cad, &mut |c| hda.command(c)) {
            Ok(p) => {
                found = Some(p);
                break;
            }
            Err(e) => {
                log(format_args!("codec {}: no output path ({:?}) regs {:x?}", cad, e, hda.diagnostics()));
            }
        }
    }
    let Some(path) = found else { fail(&mut st, HdaError::NoCodec, "no usable codec") };
    log(format_args!(
        "codec {} vendor/device {:08x}: DAC nid {}, pin nid {}, path length {}",
        path.cad,
        path.vendor,
        path.dac(),
        path.pin(),
        path.len
    ));
    hda.configure_path(&path);

    let (name, name_len) = page::codec_name(path.vendor);
    st.name = name;
    st.name_len = name_len;
    st.flags = page::FLAG_PRESENT | if path.volume_node().is_some() { page::FLAG_HAS_VOLUME } else { 0 };
    st.volume = init_volume;
    st.state = page::STATE_READY;
    let mut d = Driver { hda, path, st, ring_len: layout.ring_len, plat: &plat };
    d.apply_volume();
    publish(&d.st);
    log(format_args!("ready: {} volume {}%", d.st.name_str(), d.st.volume));

    if selftest {
        d.play_tone(440, 1000);
    }
    loop {
        if let Some((c, seq)) = d.poll_mailbox(false) {
            d.run_deferred(c, seq);
        }
        plat.sleep_ns(10_000_000);
    }
}
