//! ============================================================================
//! selftest.rs
//!
//! Purpose: the boot-time acceptance checks of the network stack, written as
//! small non-blocking state machines over the SOCKET LAYER (`sock_*`), so they
//! double as the first real client of that API. Each check reports one
//! `TestEvent` that the service prints on the serial console:
//!   - TCP echo over loopback (127.0.0.1 and ::1): listen/accept/connect,
//!     bulk send, echo, close.
//!   - UDP echo over loopback (v4 and v6).
//!   - Raw ICMP echo over loopback (v4 and v6).
//!   - HTTP: connect to a resolved address on port 80, send `GET /
//!     HTTP/1.0`, report the status line of the response.
//! The same code runs in host tests against a simulated network and under QEMU
//! against the real internet (NAT'd by the emulated network).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md Section 2.3, 5.4.
//! Position in the system: driven by `subsystem_entry::service_main` (one
//! `step` per service-loop iteration) and by host tests.
//! Safety/invariants: no heap, no `unsafe`; fixed-size buffers only.
//! ============================================================================

use crate::sockets::{Shutdown, SockError, SockId, SockState, SockType};
use crate::stack::{FrameIo, NetStack};
use smoltcp::wire::{IpAddress, IpEndpoint};

/// How long any single check may take before it is reported as failed.
pub const CHECK_TIMEOUT_NS: u64 = 15_000_000_000;
/// The HTTP check may take longer (real internet, DNS already done).
pub const HTTP_TIMEOUT_NS: u64 = 30_000_000_000;

/// Payload size of the echo checks.
const ECHO_LEN: usize = 1200;

/// Longest status line kept for the report.
pub const STATUS_MAX: usize = 60;

/// Which loopback address a check uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// 127.0.0.1
    V4,
    /// ::1
    V6,
}

impl Family {
    fn loopback(self, port: u16) -> IpEndpoint {
        match self {
            Family::V4 => IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), port),
            Family::V6 => IpEndpoint::new(
                IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(crate::ndp_wire::LOOPBACK)),
                port,
            ),
        }
    }
}

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestEvent {
    /// TCP echo over loopback finished.
    TcpLoopback {
        /// Address family.
        family: Family,
        /// `true` when every byte came back intact.
        ok: bool,
        /// Bytes echoed back.
        bytes: usize,
    },
    /// UDP echo over loopback finished.
    UdpLoopback {
        /// Address family.
        family: Family,
        /// `true` when the datagram was echoed intact.
        ok: bool,
    },
    /// Raw ICMP echo over loopback finished.
    RawIcmp {
        /// Address family.
        family: Family,
        /// `true` when an echo reply with the right identifier arrived.
        ok: bool,
    },
    /// The HTTP GET finished.
    Http {
        /// The server address that was contacted.
        addr: IpAddress,
        /// `true` when a status line ("HTTP/...") was received.
        ok: bool,
        /// The response status line (first line), truncated.
        status: [u8; STATUS_MAX],
        /// Valid bytes of `status`.
        status_len: usize,
        /// Response bytes received in total.
        bytes: usize,
        /// Why it failed, when it did (`None` = success or a timeout).
        error: Option<SockError>,
    },
}

fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(131).wrapping_add(7)) as u8
}

// ---------------------------------------------------------------------------
// TCP echo over loopback
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpPhase {
    Start,
    WaitAccept,
    Transfer,
    Done,
}

/// TCP echo over loopback: a listener, a client, a server-side socket that
/// echoes everything, and a check that the bytes return in order.
pub struct TcpEcho {
    family: Family,
    port: u16,
    phase: TcpPhase,
    started_ns: u64,
    listener: Option<SockId>,
    client: Option<SockId>,
    server: Option<SockId>,
    sent: usize,
    received: usize,
    echoed_out: usize,
    /// Bytes read from the client but not yet written back by the server.
    pending: [u8; 256],
    pending_len: usize,
    ok: bool,
}

impl TcpEcho {
    /// A new check over `family` on `port`.
    pub const fn new(family: Family, port: u16) -> Self {
        Self {
            family,
            port,
            phase: TcpPhase::Start,
            started_ns: 0,
            listener: None,
            client: None,
            server: None,
            sent: 0,
            received: 0,
            echoed_out: 0,
            pending: [0; 256],
            pending_len: 0,
            ok: true,
        }
    }

    fn finish<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>, ok: bool) -> TestEvent {
        for s in [self.client.take(), self.server.take(), self.listener.take()].into_iter().flatten() {
            let _ = stack.sock_close(s);
        }
        self.phase = TcpPhase::Done;
        TestEvent::TcpLoopback { family: self.family, ok, bytes: self.received }
    }

    /// Advances the check; returns its result once finished.
    pub fn step<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>, now_ns: u64) -> Option<TestEvent> {
        match self.phase {
            TcpPhase::Done => None,
            TcpPhase::Start => {
                self.started_ns = now_ns;
                let ep = self.family.loopback(self.port);
                let l = stack.sock_open(SockType::Stream).ok();
                let c = stack.sock_open(SockType::Stream).ok();
                let (Some(l), Some(c)) = (l, c) else {
                    self.listener = l;
                    self.client = c;
                    return Some(self.finish(stack, false));
                };
                self.listener = Some(l);
                self.client = Some(c);
                let setup = stack
                    .sock_bind(l, None, self.port)
                    .and_then(|_| stack.sock_listen(l, 2))
                    .and_then(|_| stack.sock_connect(c, ep, now_ns));
                if setup.is_err() {
                    return Some(self.finish(stack, false));
                }
                self.phase = TcpPhase::WaitAccept;
                None
            }
            TcpPhase::WaitAccept => {
                if now_ns - self.started_ns > CHECK_TIMEOUT_NS {
                    return Some(self.finish(stack, false));
                }
                let l = self.listener?;
                match stack.sock_accept(l) {
                    Ok((s, _peer)) => {
                        self.server = Some(s);
                        self.phase = TcpPhase::Transfer;
                        None
                    }
                    Err(SockError::WouldBlock) => None,
                    Err(_) => Some(self.finish(stack, false)),
                }
            }
            TcpPhase::Transfer => {
                if now_ns - self.started_ns > CHECK_TIMEOUT_NS {
                    return Some(self.finish(stack, false));
                }
                let (c, s) = (self.client?, self.server?);
                if stack.sock_state(c) != Ok(SockState::Connected) {
                    return None;
                }
                // Client -> server.
                if self.sent < ECHO_LEN {
                    let mut chunk = [0u8; 256];
                    let n = (ECHO_LEN - self.sent).min(chunk.len());
                    for (i, b) in chunk[..n].iter_mut().enumerate() {
                        *b = pattern(self.sent + i);
                    }
                    if let Ok(k) = stack.sock_send(c, &chunk[..n]) {
                        self.sent += k;
                    }
                }
                // Server: echo what arrived (finish writing the pending chunk first).
                if self.pending_len == 0 {
                    if let Ok(n) = stack.sock_recv(s, &mut self.pending) {
                        self.pending_len = n;
                        self.echoed_out = 0;
                    }
                }
                if self.pending_len > 0 {
                    if let Ok(k) = stack.sock_send(s, &self.pending[self.echoed_out..self.pending_len]) {
                        self.echoed_out += k;
                        if self.echoed_out == self.pending_len {
                            self.pending_len = 0;
                        }
                    }
                }
                // Client: collect the echo and verify it byte for byte.
                let mut back = [0u8; 256];
                if let Ok(n) = stack.sock_recv(c, &mut back) {
                    for (i, b) in back[..n].iter().enumerate() {
                        if *b != pattern(self.received + i) {
                            self.ok = false;
                        }
                    }
                    self.received += n;
                }
                if self.received >= ECHO_LEN || !self.ok {
                    let _ = stack.sock_shutdown(c, Shutdown::Both);
                    let ok = self.ok && self.received == ECHO_LEN;
                    return Some(self.finish(stack, ok));
                }
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// UDP echo over loopback
// ---------------------------------------------------------------------------

/// UDP echo over loopback: a server socket that answers, a client with a
/// default peer.
pub struct UdpEcho {
    family: Family,
    port: u16,
    started_ns: u64,
    server: Option<SockId>,
    client: Option<SockId>,
    stage: u8,
}

impl UdpEcho {
    /// A new check over `family` on `port`.
    pub const fn new(family: Family, port: u16) -> Self {
        Self { family, port, started_ns: 0, server: None, client: None, stage: 0 }
    }

    fn finish<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>, ok: bool) -> Option<TestEvent> {
        for s in [self.client.take(), self.server.take()].into_iter().flatten() {
            let _ = stack.sock_close(s);
        }
        self.stage = 9;
        Some(TestEvent::UdpLoopback { family: self.family, ok })
    }

    /// Advances the check; returns its result once finished.
    pub fn step<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>, now_ns: u64) -> Option<TestEvent> {
        const MSG: &[u8] = b"simurgh udp echo";
        match self.stage {
            0 => {
                self.started_ns = now_ns;
                let (Ok(srv), Ok(cli)) = (stack.sock_open(SockType::Dgram), stack.sock_open(SockType::Dgram)) else {
                    return self.finish(stack, false);
                };
                self.server = Some(srv);
                self.client = Some(cli);
                let ok = stack.sock_bind(srv, None, self.port).is_ok()
                    && stack.sock_connect(cli, self.family.loopback(self.port), now_ns).is_ok()
                    && stack.sock_send(cli, MSG).is_ok();
                if !ok {
                    return self.finish(stack, false);
                }
                self.stage = 1;
                None
            }
            1 => {
                if now_ns - self.started_ns > CHECK_TIMEOUT_NS {
                    return self.finish(stack, false);
                }
                let mut buf = [0u8; 64];
                if let Ok(r) = stack.sock_recvfrom(self.server?, &mut buf) {
                    if &buf[..r.len] != MSG || stack.sock_sendto(self.server?, &buf[..r.len], r.from).is_err() {
                        return self.finish(stack, false);
                    }
                    self.stage = 2;
                }
                None
            }
            2 => {
                if now_ns - self.started_ns > CHECK_TIMEOUT_NS {
                    return self.finish(stack, false);
                }
                let mut buf = [0u8; 64];
                if let Ok(n) = stack.sock_recv(self.client?, &mut buf) {
                    return self.finish(stack, &buf[..n] == MSG);
                }
                None
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Raw ICMP echo over loopback
// ---------------------------------------------------------------------------

/// Raw ICMP echo: a raw socket sends an echo request (checksum left zero for
/// the stack to fill in) and waits for the reply of the same identifier.
pub struct RawIcmpEcho {
    family: Family,
    ident: u16,
    started_ns: u64,
    sock: Option<SockId>,
    stage: u8,
}

impl RawIcmpEcho {
    /// A new check over `family` using ICMP identifier `ident`.
    pub const fn new(family: Family, ident: u16) -> Self {
        Self { family, ident, started_ns: 0, sock: None, stage: 0 }
    }

    fn finish<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>, ok: bool) -> Option<TestEvent> {
        if let Some(s) = self.sock.take() {
            let _ = stack.sock_close(s);
        }
        self.stage = 9;
        Some(TestEvent::RawIcmp { family: self.family, ok })
    }

    /// Advances the check; returns its result once finished.
    pub fn step<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>, now_ns: u64) -> Option<TestEvent> {
        match self.stage {
            0 => {
                self.started_ns = now_ns;
                let Ok(s) = stack.sock_open(SockType::RawIcmp) else { return self.finish(stack, false) };
                self.sock = Some(s);
                let mut msg = [0u8; 16];
                msg[0] = if self.family == Family::V4 { 8 } else { 128 };
                msg[4..6].copy_from_slice(&self.ident.to_be_bytes());
                msg[6..8].copy_from_slice(&1u16.to_be_bytes());
                msg[8..].copy_from_slice(b"rawecho!");
                let ok = stack.sock_bind(s, None, self.ident).is_ok()
                    && stack.sock_sendto(s, &msg, self.family.loopback(0)).is_ok();
                if !ok {
                    return self.finish(stack, false);
                }
                self.stage = 1;
                None
            }
            1 => {
                if now_ns - self.started_ns > CHECK_TIMEOUT_NS {
                    return self.finish(stack, false);
                }
                let reply_type = if self.family == Family::V4 { 0 } else { 129 };
                let mut buf = [0u8; 64];
                // A raw socket also sees the looped-back request: skip it.
                while let Ok(r) = stack.sock_recvfrom(self.sock?, &mut buf) {
                    if r.len >= 8 && buf[0] == reply_type && u16::from_be_bytes([buf[4], buf[5]]) == self.ident {
                        return self.finish(stack, &buf[8..r.len] == b"rawecho!");
                    }
                }
                None
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP GET
// ---------------------------------------------------------------------------

/// HTTP/1.0 GET of `/` from `addr:80`: connect, send the request, read until
/// the status line is complete (and a little beyond), report it.
pub struct HttpGet {
    addr: IpAddress,
    host: &'static str,
    started_ns: u64,
    sock: Option<SockId>,
    stage: u8,
    req_sent: usize,
    status: [u8; STATUS_MAX],
    status_len: usize,
    have_line: bool,
    bytes: usize,
    error: Option<SockError>,
}

impl HttpGet {
    /// A new GET of `/` from `addr`, with `Host: host`.
    pub const fn new(addr: IpAddress, host: &'static str) -> Self {
        Self {
            addr,
            host,
            started_ns: 0,
            sock: None,
            stage: 0,
            req_sent: 0,
            status: [0; STATUS_MAX],
            status_len: 0,
            have_line: false,
            bytes: 0,
            error: None,
        }
    }

    fn finish<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>) -> Option<TestEvent> {
        if let Some(s) = self.sock.take() {
            let _ = stack.sock_close(s);
        }
        self.stage = 9;
        let ok = self.status_len >= 5 && &self.status[..5] == b"HTTP/";
        Some(TestEvent::Http {
            addr: self.addr,
            ok,
            status: self.status,
            status_len: self.status_len,
            bytes: self.bytes,
            error: self.error,
        })
    }

    /// Advances the check; returns its result once finished.
    pub fn step<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>, now_ns: u64) -> Option<TestEvent> {
        match self.stage {
            0 => {
                self.started_ns = now_ns;
                let Ok(s) = stack.sock_open(SockType::Stream) else { return self.finish(stack) };
                self.sock = Some(s);
                match stack.sock_connect(s, IpEndpoint::new(self.addr, 80), now_ns) {
                    Ok(()) => {
                        self.stage = 1;
                        None
                    }
                    Err(e) => {
                        self.error = Some(e);
                        self.finish(stack)
                    }
                }
            }
            1 | 2 => {
                if now_ns - self.started_ns > HTTP_TIMEOUT_NS {
                    return self.finish(stack);
                }
                let s = self.sock?;
                if self.stage == 1 {
                    match stack.sock_state(s) {
                        Ok(SockState::Connected) | Ok(SockState::PeerClosed) => self.stage = 2,
                        Ok(SockState::Failed) => {
                            self.error = stack.sock_take_error(s).ok().flatten();
                            return self.finish(stack);
                        }
                        _ => return None,
                    }
                }
                // Send the request (it fits the send buffer in one go).
                let mut req = [0u8; 128];
                let n = build_request(&mut req, self.host);
                if self.req_sent < n {
                    if let Ok(k) = stack.sock_send(s, &req[self.req_sent..n]) {
                        self.req_sent += k;
                    }
                }
                let mut buf = [0u8; 256];
                loop {
                    match stack.sock_recv(s, &mut buf) {
                        Ok(0) => return self.finish(stack), // server closed: end of response
                        Ok(n) => {
                            if !self.have_line {
                                for &b in &buf[..n] {
                                    if b == b'\r' || b == b'\n' {
                                        self.have_line = true;
                                        break;
                                    }
                                    if self.status_len < STATUS_MAX {
                                        self.status[self.status_len] = b;
                                        self.status_len += 1;
                                    }
                                }
                            }
                            self.bytes += n;
                            // Once the status line is in and we have seen
                            // some body, that is enough evidence.
                            if self.have_line && self.bytes >= 200 {
                                return self.finish(stack);
                            }
                        }
                        Err(SockError::WouldBlock) => return None,
                        Err(e) => {
                            self.error = Some(e);
                            return self.finish(stack);
                        }
                    }
                }
            }
            _ => None,
        }
    }
}

/// Writes `GET / HTTP/1.0` with a Host header into `buf`; returns its length.
fn build_request(buf: &mut [u8], host: &str) -> usize {
    let parts: [&[u8]; 3] = [b"GET / HTTP/1.0\r\nHost: ", host.as_bytes(), b"\r\nUser-Agent: simurgh-netstack\r\nConnection: close\r\n\r\n"];
    let mut n = 0;
    for p in parts {
        let k = p.len().min(buf.len() - n);
        buf[n..n + k].copy_from_slice(&p[..k]);
        n += k;
    }
    n
}

// ---------------------------------------------------------------------------
// The boot sequence
// ---------------------------------------------------------------------------

/// One check of the boot sequence.
enum Check {
    Tcp(TcpEcho),
    Udp(UdpEcho),
    Raw(RawIcmpEcho),
    Http(HttpGet),
}

/// Runs the checks one after another: the loopback checks first (they need no
/// network), then any HTTP GET queued with `queue_http` (the service queues
/// one when a name resolves). One check is active at a time.
pub struct BootChecks {
    stage: u8,
    current: Option<Check>,
    http_queue: [Option<(IpAddress, &'static str)>; 4],
}

/// Loopback checks in the boot script.
const LOOPBACK_STAGES: u8 = 6;

impl BootChecks {
    /// A fresh sequence.
    pub const fn new() -> Self {
        Self { stage: 0, current: None, http_queue: [None; 4] }
    }

    /// Queues an HTTP GET of `/` from `addr:80` (with `Host: host`).
    pub fn queue_http(&mut self, addr: IpAddress, host: &'static str) {
        if let Some(slot) = self.http_queue.iter_mut().find(|s| s.is_none()) {
            *slot = Some((addr, host));
        }
    }

    /// `true` while the loopback part of the script has not finished.
    pub fn loopback_done(&self) -> bool {
        self.stage >= LOOPBACK_STAGES && self.current.is_none()
    }

    fn next(&mut self) -> Option<Check> {
        if self.stage < LOOPBACK_STAGES {
            let s = self.stage;
            self.stage += 1;
            return Some(match s {
                0 => Check::Tcp(TcpEcho::new(Family::V4, 7007)),
                1 => Check::Tcp(TcpEcho::new(Family::V6, 7007)),
                2 => Check::Udp(UdpEcho::new(Family::V4, 7008)),
                3 => Check::Udp(UdpEcho::new(Family::V6, 7008)),
                4 => Check::Raw(RawIcmpEcho::new(Family::V4, 0x7171)),
                _ => Check::Raw(RawIcmpEcho::new(Family::V6, 0x7171)),
            });
        }
        let (addr, host) = self.http_queue.iter_mut().find_map(|s| s.take())?;
        Some(Check::Http(HttpGet::new(addr, host)))
    }

    /// Advances the active check (starting the next one when idle); every
    /// finished check is reported through `on_event`.
    pub fn step<IO: FrameIo>(&mut self, stack: &mut NetStack<IO>, now_ns: u64, on_event: &mut dyn FnMut(TestEvent)) {
        if self.current.is_none() {
            self.current = self.next();
        }
        let ev = match self.current.as_mut() {
            None => return,
            Some(Check::Tcp(c)) => c.step(stack, now_ns),
            Some(Check::Udp(c)) => c.step(stack, now_ns),
            Some(Check::Raw(c)) => c.step(stack, now_ns),
            Some(Check::Http(c)) => c.step(stack, now_ns),
        };
        if let Some(ev) = ev {
            self.current = None;
            on_event(ev);
        }
    }
}

impl Default for BootChecks {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "selftest_tests.rs"]
mod tests;
