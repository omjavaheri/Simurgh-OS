//! ============================================================================
//! latency_stats.rs — driver-mouse's own input-latency measurement
//!
//! Purpose: lets the input path be MEASURED on a real boot rather than
//! argued about. The owner's complaint ("the mouse is extremely slow")
//! crosses four scheduling hops (IRQ12 -> driver-mouse -> Compositor ->
//! ui-core); without numbers there is no way to tell which hop costs
//! what, or whether a change helped.
//!
//! What is measured, and where each timestamp comes from:
//! - **wake latency**: IRQ time of the oldest byte this wake consumed
//!   (stamped by `kernel_arch_glue::mouse_irq_trampoline` into the ring
//!   page, see `subsystem_entry::RING_PENDING_SINCE_OFF`) to the moment
//!   this process actually runs after `DRV_IRQ_WAIT` returns. This is
//!   pure scheduler latency — how long a ready driver waits for the CPU.
//! - **burst span**: IRQ time of the first byte after the last report to
//!   the moment the Compositor `Reply`s to the message carrying the
//!   marker (see below), i.e. "first motion byte arrives" -> "the last
//!   event of the burst has been taken by the Compositor".
//! - counts: bytes, packets, messages sent, `Call` round trips waited on.
//!
//! When a report is printed: only when a delivered message carries a
//! MIDDLE-button press edge. ui-core ignores the middle button entirely
//! (`desktop::Desktop::apply_mouse_buttons`), so a benchmark can end a
//! burst with `mouse_button 4` / `mouse_button 0` over the QEMU monitor
//! without changing anything on screen, and ordinary use never prints
//! anything (no serial spam, no cost on the hot path beyond a few adds).
//! `simurgh-mouse-bench.ps1` at the workspace root drives exactly this.
//!
//! Pure logic + formatting only (host-testable); the syscalls live in
//! `subsystem_entry`.
//! ============================================================================

/// Running totals since the last report.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LatencyStats {
    pub bytes: u64,
    pub packets: u64,
    pub messages: u64,
    pub wakes: u64,
    pub wake_latency_sum_ns: u64,
    pub wake_latency_max_ns: u64,
    /// IRQ time of the first byte since the last report; `0` = none yet.
    pub burst_start_ns: u64,
    /// Bytes the ring overwrote before this process could read them.
    pub dropped_bytes: u64,
    /// Net motion handed to the Compositor — lets a benchmark check the
    /// deltas are CORRECT, not just fast (N x `mouse_move 10 0` must
    /// report `net_dx = 10 N`).
    pub net_dx: i64,
    pub net_dy: i64,
}

impl LatencyStats {
    pub const fn new() -> Self {
        Self {
            bytes: 0,
            packets: 0,
            messages: 0,
            wakes: 0,
            wake_latency_sum_ns: 0,
            wake_latency_max_ns: 0,
            burst_start_ns: 0,
            dropped_bytes: 0,
            net_dx: 0,
            net_dy: 0,
        }
    }

    /// Records one wake that found data. `pending_since_ns` is the IRQ
    /// time of the oldest unread byte (`0` if the kernel did not stamp
    /// one — then only the count is recorded).
    pub fn note_wake(&mut self, pending_since_ns: u64, now_ns: u64) {
        self.wakes += 1;
        if pending_since_ns == 0 {
            return;
        }
        if self.burst_start_ns == 0 {
            self.burst_start_ns = pending_since_ns;
        }
        let lat = now_ns.saturating_sub(pending_since_ns);
        self.wake_latency_sum_ns = self.wake_latency_sum_ns.saturating_add(lat);
        self.wake_latency_max_ns = self.wake_latency_max_ns.max(lat);
    }

    /// Formats the report line into `out`, returning the byte count
    /// written (truncated silently if `out` is too small).
    pub fn format_report(&self, now_ns: u64, out: &mut [u8]) -> usize {
        let mut w = ByteWriter { buf: out, len: 0 };
        let avg_us = if self.wakes == 0 { 0 } else { self.wake_latency_sum_ns / self.wakes / 1000 };
        let span_us = if self.burst_start_ns == 0 { 0 } else { now_ns.saturating_sub(self.burst_start_ns) / 1000 };
        w.put(b"driver-mouse latency: bytes=");
        w.num(self.bytes);
        w.put(b" packets=");
        w.num(self.packets);
        w.put(b" messages=");
        w.num(self.messages);
        w.put(b" wakes=");
        w.num(self.wakes);
        w.put(b" dropped=");
        w.num(self.dropped_bytes);
        w.put(b" wake_avg_us=");
        w.num(avg_us);
        w.put(b" wake_max_us=");
        w.num(self.wake_latency_max_ns / 1000);
        w.put(b" burst_us=");
        w.num(span_us);
        w.put(b" net_dx=");
        w.signed(self.net_dx);
        w.put(b" net_dy=");
        w.signed(self.net_dy);
        w.put(b"\r\n");
        w.len
    }
}

struct ByteWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl ByteWriter<'_> {
    fn put(&mut self, s: &[u8]) {
        for &b in s {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            }
        }
    }

    fn signed(&mut self, v: i64) {
        if v < 0 {
            self.put(b"-");
        }
        self.num(v.unsigned_abs());
    }

    fn num(&mut self, mut v: u64) {
        let mut digits = [0u8; 20];
        let mut n = 0;
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        while n > 0 {
            n -= 1;
            self.put(&[digits[n]]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wake_latency_tracks_average_and_max() {
        let mut s = LatencyStats::new();
        s.note_wake(1_000, 3_000); // 2 us
        s.note_wake(10_000, 16_000); // 6 us
        assert_eq!(s.wakes, 2);
        assert_eq!(s.wake_latency_max_ns, 6_000);
        assert_eq!(s.wake_latency_sum_ns, 8_000);
        assert_eq!(s.burst_start_ns, 1_000, "the burst starts at the FIRST stamped byte");
    }

    #[test]
    fn an_unstamped_wake_is_counted_but_not_timed() {
        let mut s = LatencyStats::new();
        s.note_wake(0, 5_000);
        assert_eq!(s.wakes, 1);
        assert_eq!(s.wake_latency_sum_ns, 0);
        assert_eq!(s.burst_start_ns, 0);
    }

    #[test]
    fn the_report_line_formats_every_field() {
        let mut s = LatencyStats::new();
        s.bytes = 12;
        s.packets = 4;
        s.messages = 2;
        s.net_dx = 200;
        s.net_dy = -190;
        s.note_wake(1_000_000, 1_500_000);
        let mut buf = [0u8; 256];
        let n = s.format_report(3_000_000, &mut buf);
        let line = core::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(
            line,
            "driver-mouse latency: bytes=12 packets=4 messages=2 wakes=1 dropped=0 wake_avg_us=500 wake_max_us=500 burst_us=2000 net_dx=200 net_dy=-190\r\n"
        );
    }

    #[test]
    fn a_too_small_buffer_truncates_instead_of_panicking() {
        let s = LatencyStats::new();
        let mut buf = [0u8; 8];
        assert_eq!(s.format_report(0, &mut buf), 8);
    }
}
