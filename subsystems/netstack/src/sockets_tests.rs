//! ============================================================================
//! sockets_tests.rs
//!
//! Purpose: host tests for the socket layer (`sockets.rs`) and the TCP/UDP/
//! ICMP machinery under it. Two real `NetStack`s are joined by an in-memory
//! wire (optionally lossy), and a single stack talks to itself over the
//! loopback path, so every test drives complete protocol exchanges - no
//! hand-built packets except where a wire-level property is asserted.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md Section 2.3.
//! Position in the system: `#[cfg(test)]` child module of `stack`.
//! Safety/invariants: none (host-only, std available).
//! ============================================================================

extern crate std;

use super::tests::{leak_buffers, leak_storage};
use super::*;
use crate::sockets::*;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

const A_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];
const B_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0b];
pub(crate) const A_IP: [u8; 4] = [10, 0, 2, 15];
pub(crate) const B_IP: [u8; 4] = [10, 0, 2, 16];

pub(crate) fn ep4(ip: [u8; 4], port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), port)
}

fn lo4(port: u16) -> IpEndpoint {
    ep4([127, 0, 0, 1], port)
}

fn lo6(port: u16) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(crate::ndp_wire::LOOPBACK)), port)
}

// ---------------------------------------------------------------------------
// The wire
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct WireState {
    /// Frames waiting for side 0 / side 1.
    inbox: [VecDeque<Vec<u8>>; 2],
    /// Every frame either side sent: (side, frame).
    log: Vec<(usize, Vec<u8>)>,
    /// Drop every n-th frame side 0 sends (0 = never).
    drop_every_from_a: usize,
    sent_from_a: usize,
    /// Drop everything (a dead peer).
    pub(crate) cut: bool,
}

#[derive(Clone)]
pub(crate) struct PortIo {
    pub(crate) wire: Rc<RefCell<WireState>>,
    side: usize,
}

impl FrameIo for PortIo {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Option<usize> {
        let f = self.wire.borrow_mut().inbox[self.side].pop_front()?;
        buf[..f.len()].copy_from_slice(&f);
        Some(f.len())
    }

    fn send_frame(&mut self, frame: &[u8]) -> bool {
        let mut w = self.wire.borrow_mut();
        w.log.push((self.side, frame.to_vec()));
        if w.cut {
            return true;
        }
        if self.side == 0 {
            w.sent_from_a += 1;
            // Only drop TCP data-sized frames so the ARP exchange is stable.
            if w.drop_every_from_a != 0 && w.sent_from_a % w.drop_every_from_a == 0 && frame.len() > 200 {
                return true;
            }
        }
        w.inbox[1 - self.side].push_back(frame.to_vec());
        true
    }
}

pub(crate) struct Lan {
    pub(crate) a: NetStack<PortIo>,
    pub(crate) b: NetStack<PortIo>,
    pub(crate) wire: Rc<RefCell<WireState>>,
    pub(crate) now_ms: u64,
}

fn make_stack(io: PortIo, mac: [u8; 6], ip: [u8; 4], peer: [u8; 4]) -> NetStack<PortIo> {
    NetStack::new(
        leak_storage(),
        leak_buffers(),
        io,
        mac,
        AddrMode::Static { ip, prefix: 24, gateway: peer, dns: None },
        0,
    )
}

impl Lan {
    pub(crate) fn new() -> Self {
        let wire = Rc::new(RefCell::new(WireState::default()));
        Lan {
            a: make_stack(PortIo { wire: wire.clone(), side: 0 }, A_MAC, A_IP, B_IP),
            b: make_stack(PortIo { wire: wire.clone(), side: 1 }, B_MAC, B_IP, A_IP),
            wire,
            now_ms: 1,
        }
    }

    pub(crate) fn now_ns(&self) -> u64 {
        self.now_ms * 1_000_000
    }

    /// One millisecond of simulated time: both stacks poll.
    pub(crate) fn step(&mut self) {
        let now = self.now_ns();
        self.a.poll(now, &mut |_| {});
        self.b.poll(now, &mut |_| {});
        self.now_ms += 1;
    }

    pub(crate) fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.step();
        }
    }

    /// Steps until `cond` holds or `limit_ms` pass; returns whether it held.
    pub(crate) fn run_until(&mut self, limit_ms: u64, mut cond: impl FnMut(&mut Lan) -> bool) -> bool {
        for _ in 0..limit_ms {
            if cond(self) {
                return true;
            }
            self.step();
        }
        cond(self)
    }
}

/// A single stack with no reachable network (frames go nowhere): for
/// loopback, UDP-on-loopback and table logic tests.
pub(crate) struct NullIo {
    sent: Vec<Vec<u8>>,
}

impl FrameIo for NullIo {
    fn recv_frame(&mut self, _buf: &mut [u8]) -> Option<usize> {
        None
    }
    fn send_frame(&mut self, frame: &[u8]) -> bool {
        self.sent.push(frame.to_vec());
        true
    }
}

pub(crate) struct Solo {
    pub(crate) s: NetStack<NullIo>,
    pub(crate) now_ms: u64,
}

impl Solo {
    pub(crate) fn new() -> Self {
        let s = NetStack::new(
            leak_storage(),
            leak_buffers(),
            NullIo { sent: Vec::new() },
            A_MAC,
            AddrMode::Static { ip: A_IP, prefix: 24, gateway: [10, 0, 2, 2], dns: None },
            0,
        );
        Solo { s, now_ms: 1 }
    }

    pub(crate) fn step(&mut self) {
        self.s.poll(self.now_ms * 1_000_000, &mut |_| {});
        self.now_ms += 1;
    }

    pub(crate) fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.step();
        }
    }

    pub(crate) fn now_ns(&self) -> u64 {
        self.now_ms * 1_000_000
    }

    pub(crate) fn run_until(&mut self, limit_ms: u64, mut cond: impl FnMut(&mut Solo) -> bool) -> bool {
        for _ in 0..limit_ms {
            if cond(self) {
                return true;
            }
            self.step();
        }
        cond(self)
    }
}

/// Deterministic test payload.
fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31).wrapping_add(i >> 8)) as u8).collect()
}

// ---------------------------------------------------------------------------
// Loopback
// ---------------------------------------------------------------------------

#[test]
fn tcp_loopback_echo_v4() {
    let mut t = Solo::new();
    let l = t.s.sock_open(SockType::Stream).unwrap();
    assert_eq!(t.s.sock_bind(l, Some(IpAddress::v4(127, 0, 0, 1)), 7777).unwrap(), 7777);
    t.s.sock_listen(l, 2).unwrap();
    let c = t.s.sock_open(SockType::Stream).unwrap();
    t.s.sock_connect(c, lo4(7777), t.now_ns()).unwrap();
    assert_eq!(t.s.sock_state(c).unwrap(), SockState::Connecting);
    assert!(t.run_until(100, |t| t.s.sock_events(l).unwrap().acceptable));
    let (srv, peer) = t.s.sock_accept(l).unwrap();
    assert_eq!(peer.addr, IpAddress::v4(127, 0, 0, 1));
    assert!(t.run_until(100, |t| t.s.sock_state(c).unwrap() == SockState::Connected));
    assert_eq!(t.s.sock_state(srv).unwrap(), SockState::Connected);

    // 20 000 bytes through a 32 KiB buffer and back again.
    let data = pattern(20_000);
    let mut sent = 0;
    let mut echoed: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..2_000 {
        if sent < data.len() {
            match t.s.sock_send(c, &data[sent..]) {
                Ok(n) => sent += n,
                Err(SockError::WouldBlock) => {}
                Err(e) => panic!("send: {e:?}"),
            }
        }
        // The server echoes whatever arrives.
        if let Ok(n) = t.s.sock_recv(srv, &mut buf) {
            let mut off = 0;
            while off < n {
                match t.s.sock_send(srv, &buf[off..n]) {
                    Ok(k) => off += k,
                    Err(SockError::WouldBlock) => t.step(),
                    Err(e) => panic!("echo send: {e:?}"),
                }
            }
        }
        if let Ok(n) = t.s.sock_recv(c, &mut buf) {
            echoed.extend_from_slice(&buf[..n]);
        }
        if echoed.len() == data.len() {
            break;
        }
        t.step();
    }
    assert_eq!(echoed, data);

    // Nothing of this conversation touched the wire (only MLD/ND chatter is
    // allowed, never IPv4 to 127.x).
    for f in &t.s.io().sent {
        assert!(f.len() < 34 || f[12..14] != [0x08, 0x00] || (f[26] != 127 && f[30] != 127), "loopback leaked");
    }
}

#[test]
fn tcp_loopback_echo_v6() {
    let mut t = Solo::new();
    let l = t.s.sock_open(SockType::Stream).unwrap();
    t.s.sock_bind(l, None, 8080).unwrap(); // dual-stack listener
    t.s.sock_listen(l, 1).unwrap();
    let c = t.s.sock_open(SockType::Stream).unwrap();
    t.s.sock_connect(c, lo6(8080), t.now_ns()).unwrap();
    assert!(t.run_until(200, |t| t.s.sock_events(l).unwrap().acceptable), "no v6 connection reached the listener");
    let (srv, peer) = t.s.sock_accept(l).unwrap();
    assert!(matches!(peer.addr, IpAddress::Ipv6(_)));
    assert!(t.run_until(100, |t| t.s.sock_state(c).unwrap() == SockState::Connected));
    assert_eq!(t.s.sock_send(c, b"ping over ::1").unwrap(), 13);
    let mut buf = [0u8; 64];
    assert!(t.run_until(100, |t| t.s.sock_events(srv).unwrap().readable));
    let n = t.s.sock_recv(srv, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"ping over ::1");
    // No IPv6 frame with ::1 left the machine.
    for f in &t.s.io().sent {
        if f.len() >= 54 && f[12..14] == [0x86, 0xdd] {
            assert_ne!(&f[22..38], &crate::ndp_wire::LOOPBACK[..]);
            assert_ne!(&f[38..54], &crate::ndp_wire::LOOPBACK[..]);
        }
    }
}

#[test]
fn one_dual_stack_listener_serves_both_families() {
    let mut t = Solo::new();
    let l = t.s.sock_open(SockType::Stream).unwrap();
    t.s.sock_bind(l, None, 9000).unwrap();
    t.s.sock_listen(l, 2).unwrap();
    let c4 = t.s.sock_open(SockType::Stream).unwrap();
    let c6 = t.s.sock_open(SockType::Stream).unwrap();
    t.s.sock_connect(c4, lo4(9000), t.now_ns()).unwrap();
    t.s.sock_connect(c6, lo6(9000), t.now_ns()).unwrap();
    let mut accepted = Vec::new();
    for _ in 0..500 {
        if let Ok((s, peer)) = t.s.sock_accept(l) {
            accepted.push(peer.addr);
            let _ = s;
        }
        if accepted.len() == 2 {
            break;
        }
        t.step();
    }
    assert_eq!(accepted.len(), 2);
    assert!(accepted.iter().any(|a| matches!(a, IpAddress::Ipv4(_))));
    assert!(accepted.iter().any(|a| matches!(a, IpAddress::Ipv6(_))));
}

#[test]
fn udp_loopback_round_trip_with_sendto_and_recvfrom() {
    let mut t = Solo::new();
    let srv = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_bind(srv, None, 5353).unwrap();
    let cli = t.s.sock_open(SockType::Dgram).unwrap();
    // Unbound sender: bound to an ephemeral port on first send.
    t.s.sock_sendto(cli, b"hello udp", lo4(5353)).unwrap();
    assert!(t.run_until(50, |t| t.s.sock_events(srv).unwrap().readable));
    let mut buf = [0u8; 64];
    let r = t.s.sock_recvfrom(srv, &mut buf).unwrap();
    assert_eq!(&buf[..r.len], b"hello udp");
    assert_eq!(r.from.addr, IpAddress::v4(127, 0, 0, 1));
    assert!(r.from.port >= EPHEMERAL_FIRST);
    // Reply to the sender.
    t.s.sock_sendto(srv, b"hello back", r.from).unwrap();
    assert!(t.run_until(50, |t| t.s.sock_events(cli).unwrap().readable));
    let r2 = t.s.sock_recvfrom(cli, &mut buf).unwrap();
    assert_eq!(&buf[..r2.len], b"hello back");
    assert_eq!(r2.from.port, 5353);
    // Nothing more.
    assert_eq!(t.s.sock_recv(cli, &mut buf), Err(SockError::WouldBlock));
}

#[test]
fn udp_connected_socket_uses_default_peer_and_v6_loopback() {
    let mut t = Solo::new();
    let srv = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_bind(srv, None, 6000).unwrap();
    let cli = t.s.sock_open(SockType::Dgram).unwrap();
    assert_eq!(t.s.sock_send(cli, b"x"), Err(SockError::NotConnected));
    t.s.sock_connect(cli, lo6(6000), t.now_ns()).unwrap();
    assert_eq!(t.s.sock_state(cli).unwrap(), SockState::Connected);
    assert_eq!(t.s.sock_send(cli, b"over v6").unwrap(), 7);
    assert!(t.run_until(100, |t| t.s.sock_events(srv).unwrap().readable));
    let mut buf = [0u8; 32];
    let r = t.s.sock_recvfrom(srv, &mut buf).unwrap();
    assert_eq!(&buf[..r.len], b"over v6");
    assert!(matches!(r.from.addr, IpAddress::Ipv6(_)));
}

#[test]
fn udp_rejects_bad_arguments() {
    let mut t = Solo::new();
    let s = t.s.sock_open(SockType::Dgram).unwrap();
    assert_eq!(t.s.sock_sendto(s, &[0; 10], ep4([1, 2, 3, 4], 0)), Err(SockError::InvalidArgument));
    assert_eq!(t.s.sock_sendto(s, &[0; 10_000], lo4(9)), Err(SockError::MessageSize));
    assert_eq!(t.s.sock_listen(s, 1), Err(SockError::NotSupported));
    assert_eq!(t.s.sock_accept(s), Err(SockError::InvalidState));
    let mut small = [0u8; 4];
    let rx = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_bind(rx, None, 4000).unwrap();
    let c = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_sendto(c, b"0123456789", lo4(4000)).unwrap();
    assert!(t.run_until(50, |t| t.s.sock_events(rx).unwrap().readable));
    assert_eq!(t.s.sock_recv(rx, &mut small), Err(SockError::MessageSize));
    // Binding an address that is not ours.
    let x = t.s.sock_open(SockType::Dgram).unwrap();
    assert_eq!(t.s.sock_bind(x, Some(IpAddress::v4(8, 8, 8, 8)), 1234), Err(SockError::AddrNotAvailable));
}

#[test]
fn raw_icmp_socket_pings_loopback_and_fixes_checksums() {
    let mut t = Solo::new();
    let s = t.s.sock_open(SockType::RawIcmp).unwrap();
    assert_eq!(t.s.sock_bind(s, None, 0x5151), Err(SockError::AddrInUse), "the stack's own ping identifier is reserved");
    let ident = t.s.sock_bind(s, None, 0x4242).unwrap();
    assert_eq!(ident, 0x4242);
    // Echo request with a ZERO checksum: the stack fills it in.
    let mut msg = [0u8; 16];
    msg[0] = 8;
    msg[4..6].copy_from_slice(&0x4242u16.to_be_bytes());
    msg[6..8].copy_from_slice(&7u16.to_be_bytes());
    msg[8..].copy_from_slice(b"rawping!");
    t.s.sock_sendto(s, &msg, lo4(0)).unwrap();
    let mut buf = [0u8; 64];
    let r = recv_until_type(&mut t, s, &mut buf, 0);
    assert_eq!(buf[0], 0, "echo reply type");
    assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 7);
    assert_eq!(&buf[8..r.len], b"rawping!");
    assert_eq!(r.from.addr, IpAddress::v4(127, 0, 0, 1));
}

#[test]
fn raw_icmpv6_socket_pings_loopback() {
    let mut t = Solo::new();
    let s = t.s.sock_open(SockType::RawIcmp).unwrap();
    t.s.sock_bind(s, None, 0x1234).unwrap();
    let mut msg = [0u8; 12];
    msg[0] = 128; // echo request
    msg[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    msg[6..8].copy_from_slice(&1u16.to_be_bytes());
    msg[8..].copy_from_slice(b"v6!!");
    t.s.sock_sendto(s, &msg, lo6(0)).unwrap();
    let mut buf = [0u8; 64];
    let r = recv_until_type(&mut t, s, &mut buf, 129);
    assert_eq!(buf[0], 129, "ICMPv6 echo reply type");
    assert_eq!(&buf[8..r.len], b"v6!!");
}

#[test]
fn raw_icmp_slots_are_reused_after_close() {
    let mut t = Solo::new();
    for round in 0..3u16 {
        let mut ids = Vec::new();
        for i in 0..ICMP_SOCKETS as u16 {
            let s = t.s.sock_open(SockType::RawIcmp).unwrap();
            // The same identifiers every round: a slot keeps the identifier it was
            // first bound to, so later sockets reuse the slots by binding it again.
            t.s.sock_bind(s, None, 100 + i + round * 0).unwrap();
            ids.push(s);
        }
        let extra = t.s.sock_open(SockType::RawIcmp).unwrap();
        assert_eq!(t.s.sock_bind(extra, None, 999), Err(SockError::NoBuffers), "round {round}");
        t.s.sock_close(extra).unwrap();
        for s in ids {
            t.s.sock_close(s).unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// TCP between two stacks
// ---------------------------------------------------------------------------

/// Connects A -> B:`port` and returns (client on A, accepted server socket on B).
fn connect_pair(lan: &mut Lan, port: u16) -> (SockId, SockId, SockId) {
    let l = lan.b.sock_open(SockType::Stream).unwrap();
    lan.b.sock_bind(l, None, port).unwrap();
    lan.b.sock_listen(l, 4).unwrap();
    let c = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c, ep4(B_IP, port), now).unwrap();
    assert!(lan.run_until(2_000, |l2| l2.b.sock_events(l).unwrap().acceptable), "handshake did not complete");
    let (s, peer) = lan.b.sock_accept(l).unwrap();
    assert_eq!(peer.addr, IpAddress::v4(10, 0, 2, 15));
    assert!(lan.run_until(500, |l2| l2.a.sock_state(c).unwrap() == SockState::Connected));
    (l, c, s)
}

/// Sends `data` from (`tx_stack`, `tx`) and reads it all on the other side.
fn transfer(lan: &mut Lan, a_to_b: bool, tx: SockId, rx: SockId, data: &[u8], limit_ms: u64) -> Vec<u8> {
    let mut sent = 0;
    let mut got: Vec<u8> = Vec::new();
    let mut buf = std::vec![0u8; 8192];
    for _ in 0..limit_ms {
        if sent < data.len() {
            let r = if a_to_b { lan.a.sock_send(tx, &data[sent..]) } else { lan.b.sock_send(tx, &data[sent..]) };
            match r {
                Ok(n) => sent += n,
                Err(SockError::WouldBlock) => {}
                Err(e) => panic!("send failed: {e:?}"),
            }
        }
        let r = if a_to_b { lan.b.sock_recv(rx, &mut buf) } else { lan.a.sock_recv(rx, &mut buf) };
        match r {
            Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
            Ok(_) => break, // EOF
            Err(SockError::WouldBlock) => {}
            Err(e) => panic!("recv failed: {e:?}"),
        }
        if got.len() >= data.len() {
            break;
        }
        lan.step();
    }
    got
}

#[test]
fn tcp_bulk_transfer_between_two_stacks() {
    let mut lan = Lan::new();
    let (_l, c, s) = connect_pair(&mut lan, 80);
    let data = pattern(300_000);
    let got = transfer(&mut lan, true, c, s, &data, 20_000);
    assert_eq!(got.len(), data.len());
    assert!(got == data, "payload corrupted");
    // And the other direction on the same connection.
    let back = pattern(120_000);
    let got2 = transfer(&mut lan, false, s, c, &back, 20_000);
    assert!(got2 == back);
}

#[test]
fn tcp_transfer_survives_packet_loss() {
    let mut lan = Lan::new();
    let (_l, c, s) = connect_pair(&mut lan, 81);
    lan.wire.borrow_mut().drop_every_from_a = 7;
    let data = pattern(60_000);
    let got = transfer(&mut lan, true, c, s, &data, 120_000);
    assert!(got == data, "retransmission failed to repair the stream ({} of {} bytes)", got.len(), data.len());
    assert!(lan.wire.borrow().sent_from_a > 30);
}

#[test]
fn tcp_syn_offers_window_scale_sack_and_timestamps() {
    let mut lan = Lan::new();
    let _ = connect_pair(&mut lan, 82);
    // Find A's SYN in the log and walk its TCP options.
    let w = lan.wire.borrow();
    let syn = w
        .log
        .iter()
        .find(|(side, f)| *side == 0 && f.len() > 54 && f[12..14] == [0x08, 0x00] && f[23] == 6 && f[47] & 0x12 == 0x02)
        .expect("no SYN captured");
    let f = &syn.1;
    let data_off = ((f[46] >> 4) as usize) * 4;
    let opts = &f[34 + 20..34 + data_off];
    let mut i = 0;
    let (mut ws, mut sack, mut ts, mut mss) = (false, false, false, None);
    while i < opts.len() {
        match opts[i] {
            0 => break,
            1 => i += 1,
            k => {
                let l = opts[i + 1] as usize;
                match k {
                    2 => mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]])),
                    3 => ws = true,
                    4 => sack = true,
                    8 => ts = true,
                    _ => {}
                }
                i += l;
            }
        }
    }
    assert_eq!(mss, Some(1460), "MSS must reflect the 1514-byte frames");
    assert!(ws, "window scaling not offered (64 KiB buffers need it)");
    assert!(sack, "SACK-permitted not offered");
    assert!(!ts, "timestamps must stay off (they push full segments over the MTU in smoltcp 0.12)");
}

#[test]
fn tcp_full_size_segments_are_used() {
    let mut lan = Lan::new();
    let (_l, c, s) = connect_pair(&mut lan, 83);
    let data = pattern(30_000);
    let got = transfer(&mut lan, true, c, s, &data, 5_000);
    assert!(got == data);
    let w = lan.wire.borrow();
    let biggest = w.log.iter().map(|(_, f)| f.len()).max().unwrap();
    assert_eq!(biggest, 1514, "no full-MTU frame was ever sent");
}

#[test]
fn tcp_close_gives_the_peer_eof_then_resources_come_back() {
    let mut lan = Lan::new();
    let (l, c, s) = connect_pair(&mut lan, 84);
    assert_eq!(lan.a.sock_send(c, b"bye").unwrap(), 3);
    lan.a.sock_shutdown(c, Shutdown::Write).unwrap();
    let mut buf = [0u8; 16];
    assert!(lan.run_until(500, |l2| l2.b.sock_events(s).unwrap().readable));
    assert_eq!(lan.b.sock_recv(s, &mut buf).unwrap(), 3);
    // The FIN follows the data: EOF now, and the state says so.
    assert!(lan.run_until(500, |l2| l2.b.sock_state(s).unwrap() == SockState::PeerClosed));
    assert_eq!(lan.b.sock_recv(s, &mut buf), Ok(0));
    // B may still send (half-close), A still receives.
    assert_eq!(lan.b.sock_send(s, b"ok").unwrap(), 2);
    assert!(lan.run_until(500, |l2| l2.a.sock_events(c).unwrap().readable));
    assert_eq!(lan.a.sock_recv(c, &mut buf).unwrap(), 2);
    lan.b.sock_close(s).unwrap();
    assert!(lan.run_until(500, |l2| l2.a.sock_state(c).unwrap() == SockState::PeerClosed));
    assert_eq!(lan.a.sock_recv(c, &mut buf), Ok(0));
    lan.a.sock_close(c).unwrap();
    lan.b.sock_close(l).unwrap();
    // Zombie sockets are reaped as their connections end (TIME-WAIT is cut
    // short): after a while every pool slot is free again.
    lan.run(80_000);
    let mut opened = Vec::new();
    for _ in 0..TCP_SOCKETS {
        opened.push(lan.a.sock_open(SockType::Stream).expect("pool slot leaked"));
    }
    assert_eq!(lan.a.sock_open(SockType::Stream), Err(SockError::NoBuffers));
}

#[test]
fn stale_socket_ids_are_rejected() {
    let mut t = Solo::new();
    let s = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_close(s).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(t.s.sock_recv(s, &mut buf), Err(SockError::BadSocket));
    assert_eq!(t.s.sock_close(s), Err(SockError::BadSocket));
    assert_eq!(t.s.sock_state(s), Err(SockError::BadSocket));
    assert_eq!(t.s.sock_recv(SockId(200), &mut buf), Err(SockError::BadSocket));
}

#[test]
fn connect_to_a_closed_port_is_refused() {
    let mut lan = Lan::new();
    let c = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c, ep4(B_IP, 9), now).unwrap();
    assert!(lan.run_until(2_000, |l| l.a.sock_state(c).unwrap() == SockState::Failed));
    assert_eq!(lan.a.sock_take_error(c).unwrap(), Some(SockError::ConnectionRefused));
    assert_eq!(lan.a.sock_take_error(c).unwrap(), None, "the error is cleared once read");
    assert_eq!(lan.a.sock_send(c, b"x"), Err(SockError::BrokenPipe));
}

#[test]
fn connect_to_a_silent_peer_times_out() {
    let mut lan = Lan::new();
    lan.wire.borrow_mut().cut = true;
    let c = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c, ep4(B_IP, 80), now).unwrap();
    assert_eq!(lan.a.sock_state(c).unwrap(), SockState::Connecting);
    lan.run(19_000);
    assert_eq!(lan.a.sock_state(c).unwrap(), SockState::Connecting, "gave up too early");
    lan.run(2_500);
    assert_eq!(lan.a.sock_state(c).unwrap(), SockState::Failed);
    assert_eq!(lan.a.sock_take_error(c).unwrap(), Some(SockError::TimedOut));
}

#[test]
fn listen_backlog_queues_connections_and_refuses_the_rest() {
    let mut lan = Lan::new();
    let l = lan.b.sock_open(SockType::Stream).unwrap();
    lan.b.sock_bind(l, None, 8000).unwrap();
    lan.b.sock_listen(l, 3).unwrap();
    assert_eq!(lan.b.sock_accept(l), Err(SockError::WouldBlock));
    let mut clients = Vec::new();
    for _ in 0..5 {
        let c = lan.a.sock_open(SockType::Stream).unwrap();
        let now = lan.now_ns();
        lan.a.sock_connect(c, ep4(B_IP, 8000), now).unwrap();
        clients.push(c);
        lan.run(30);
    }
    lan.run(500);
    let connected = clients.iter().filter(|c| lan.a.sock_state(**c).unwrap() == SockState::Connected).count();
    let refused = clients.iter().filter(|c| lan.a.sock_state(**c).unwrap() == SockState::Failed).count();
    assert_eq!(connected, 3, "exactly the backlog fits");
    assert_eq!(refused, 2, "the rest is refused");
    // All three can be accepted, then a fresh connection fits again.
    for _ in 0..3 {
        lan.b.sock_accept(l).unwrap();
    }
    assert_eq!(lan.b.sock_accept(l), Err(SockError::WouldBlock));
    let c = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c, ep4(B_IP, 8000), now).unwrap();
    assert!(lan.run_until(2_000, |l2| l2.a.sock_state(c).unwrap() == SockState::Connected));
    lan.b.sock_accept(l).unwrap();
}

#[test]
fn a_connection_closed_by_the_peer_before_accept_is_still_delivered() {
    let mut lan = Lan::new();
    let l = lan.b.sock_open(SockType::Stream).unwrap();
    lan.b.sock_bind(l, None, 8100).unwrap();
    lan.b.sock_listen(l, 1).unwrap();
    let c = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c, ep4(B_IP, 8100), now).unwrap();
    assert!(lan.run_until(2_000, |l2| l2.b.sock_events(l).unwrap().acceptable));
    // The client sends, then closes before anyone accepts (like a fast HTTP
    // client): the queued connection must survive until accept and still
    // yield its data and then EOF.
    assert_eq!(lan.a.sock_send(c, b"late").unwrap(), 4);
    lan.a.sock_close(c).unwrap();
    lan.run(500);
    let (s, _) = lan.b.sock_accept(l).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(lan.b.sock_recv(s, &mut buf).unwrap(), 4);
    assert_eq!(lan.b.sock_recv(s, &mut buf), Ok(0));
    lan.b.sock_close(s).unwrap();
    // The listener has been re-armed and takes a new connection.
    let c2 = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c2, ep4(B_IP, 8100), now).unwrap();
    assert!(lan.run_until(3_000, |l2| l2.a.sock_state(c2).unwrap() == SockState::Connected));
}

#[test]
fn a_reset_before_accept_frees_the_listen_slot() {
    let mut lan = Lan::new();
    let l = lan.b.sock_open(SockType::Stream).unwrap();
    lan.b.sock_bind(l, None, 8110).unwrap();
    lan.b.sock_listen(l, 1).unwrap();
    let c = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c, ep4(B_IP, 8110), now).unwrap();
    assert!(lan.run_until(2_000, |l2| l2.b.sock_events(l).unwrap().acceptable));
    // The client's smoltcp socket is aborted (RST goes out).
    lan.a.table_abort_for_test(c);
    lan.run(500);
    let c2 = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c2, ep4(B_IP, 8110), now).unwrap();
    assert!(lan.run_until(3_000, |l2| l2.a.sock_state(c2).unwrap() == SockState::Connected));
}

#[test]
fn recv_and_accept_report_would_block_and_state_errors() {
    let mut t = Solo::new();
    let c = t.s.sock_open(SockType::Stream).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(t.s.sock_recv(c, &mut buf), Err(SockError::NotConnected));
    assert_eq!(t.s.sock_send(c, b"x"), Err(SockError::NotConnected));
    assert_eq!(t.s.sock_accept(c), Err(SockError::InvalidState));
    assert_eq!(t.s.sock_listen(c, 1), Err(SockError::InvalidState), "listen needs a bound socket");
    assert_eq!(t.s.sock_shutdown(c, Shutdown::Both), Err(SockError::NotConnected));
    assert_eq!(t.s.sock_connect(c, ep4([1, 1, 1, 1], 0), 0), Err(SockError::InvalidArgument));
    assert_eq!(t.s.sock_state(c).unwrap(), SockState::Unbound);
    t.s.sock_bind(c, None, 5000).unwrap();
    assert_eq!(t.s.sock_state(c).unwrap(), SockState::Bound);
    assert_eq!(t.s.sock_bind(c, None, 5001), Err(SockError::InvalidState), "already bound");
    t.s.sock_listen(c, 1).unwrap();
    assert_eq!(t.s.sock_state(c).unwrap(), SockState::Listening);
    assert_eq!(t.s.sock_accept(c), Err(SockError::WouldBlock));
    assert_eq!(t.s.sock_connect(c, lo4(5000), 0), Err(SockError::InvalidState));
    let ev = t.s.sock_events(c).unwrap();
    assert!(!ev.acceptable && !ev.readable);
}

#[test]
fn bind_conflicts_reuseaddr_and_ephemeral_ports() {
    let mut t = Solo::new();
    let a = t.s.sock_open(SockType::Dgram).unwrap();
    let b = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_bind(a, None, 3000).unwrap();
    assert_eq!(t.s.sock_bind(b, None, 3000), Err(SockError::AddrInUse));
    assert_eq!(t.s.sock_bind(b, Some(IpAddress::v4(127, 0, 0, 1)), 3000), Err(SockError::AddrInUse), "wildcard overlaps");
    // With SO_REUSEADDR on both, sharing is allowed.
    t.s.sock_close(a).unwrap();
    let a = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_setopt(a, SockOpt::ReuseAddr(true)).unwrap();
    t.s.sock_setopt(b, SockOpt::ReuseAddr(true)).unwrap();
    t.s.sock_bind(a, None, 3001).unwrap();
    t.s.sock_bind(b, None, 3001).unwrap();
    // Different specific addresses do not conflict.
    let c = t.s.sock_open(SockType::Dgram).unwrap();
    let d = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_bind(c, Some(IpAddress::v4(127, 0, 0, 1)), 3002).unwrap();
    t.s.sock_bind(d, Some(IpAddress::v4(10, 0, 2, 15)), 3002).unwrap();
    // Stream: a listener blocks even a REUSEADDR binder.
    let l1 = t.s.sock_open(SockType::Stream).unwrap();
    let l2 = t.s.sock_open(SockType::Stream).unwrap();
    t.s.sock_setopt(l1, SockOpt::ReuseAddr(true)).unwrap();
    t.s.sock_setopt(l2, SockOpt::ReuseAddr(true)).unwrap();
    t.s.sock_bind(l1, None, 3100).unwrap();
    t.s.sock_listen(l1, 1).unwrap();
    assert_eq!(t.s.sock_bind(l2, None, 3100), Err(SockError::AddrInUse));
    // Ephemeral ports are distinct and in the dynamic range.
    let mut ports = Vec::new();
    for _ in 0..8 {
        let s = t.s.sock_open(SockType::Dgram).unwrap();
        let p = t.s.sock_bind(s, None, 0).unwrap();
        assert!(p >= EPHEMERAL_FIRST);
        assert!(!ports.contains(&p));
        ports.push(p);
    }
}

#[test]
fn table_exhaustion_and_recovery() {
    let mut t = Solo::new();
    let mut udp = Vec::new();
    for _ in 0..UDP_SOCKETS {
        udp.push(t.s.sock_open(SockType::Dgram).unwrap());
    }
    assert_eq!(t.s.sock_open(SockType::Dgram), Err(SockError::NoBuffers));
    t.s.sock_close(udp.pop().unwrap()).unwrap();
    assert!(t.s.sock_open(SockType::Dgram).is_ok());
    // Datagram sockets and streams draw from separate pools.
    let mut tcp = Vec::new();
    for _ in 0..TCP_SOCKETS {
        tcp.push(t.s.sock_open(SockType::Stream).unwrap());
    }
    assert_eq!(t.s.sock_open(SockType::Stream), Err(SockError::NoBuffers));
    // The logical table is the outer limit (MAX_SOCKS) - the pools are
    // smaller, so the pools bind first.
    assert!(UDP_SOCKETS + TCP_SOCKETS + ICMP_SOCKETS <= MAX_SOCKS);
    let (s, d, r) = t.s.sock_counts();
    assert_eq!((s, d, r), (TCP_SOCKETS, UDP_SOCKETS, 0));
}

#[test]
fn socket_options_round_trip_and_take_effect() {
    let mut t = Solo::new();
    let s = t.s.sock_open(SockType::Stream).unwrap();
    for opt in [
        SockOpt::ReuseAddr(true),
        SockOpt::NoDelay(true),
        SockOpt::KeepAlive(Some(30)),
        SockOpt::Broadcast(true),
        SockOpt::Ttl(Some(33)),
        SockOpt::RecvTimeoutMs(Some(1500)),
        SockOpt::SendTimeoutMs(Some(2500)),
        SockOpt::NonBlocking(true),
        SockOpt::TcpTimeoutMs(Some(9000)),
        SockOpt::Congestion(Congestion::Reno),
    ] {
        t.s.sock_setopt(s, opt).unwrap();
        assert_eq!(t.s.sock_getopt(s, opt).unwrap(), opt);
    }
    assert_eq!(t.s.sock_getopt(s, SockOpt::Congestion(Congestion::None)).unwrap(), SockOpt::Congestion(Congestion::Reno));
    // Defaults on a fresh socket.
    let d = t.s.sock_open(SockType::Stream).unwrap();
    assert_eq!(t.s.sock_getopt(d, SockOpt::NoDelay(true)).unwrap(), SockOpt::NoDelay(false));
    assert_eq!(t.s.sock_getopt(d, SockOpt::Congestion(Congestion::None)).unwrap(), SockOpt::Congestion(Congestion::Cubic));
    assert_eq!(t.s.sock_getopt(d, SockOpt::KeepAlive(None)).unwrap(), SockOpt::KeepAlive(None));
    // The smoltcp socket really got them.
    let pool = t.s.table_pool_of(s);
    let sock = t.s.sockets.get::<smoltcp::socket::tcp::Socket>(t.s.table_tcp_handle(pool));
    assert!(sock.nagle_enabled() == false);
    assert_eq!(sock.keep_alive(), Some(smoltcp::time::Duration::from_secs(30)));
    assert_eq!(sock.hop_limit(), Some(33));
    assert_eq!(sock.timeout(), Some(smoltcp::time::Duration::from_millis(9000)));
    assert_eq!(sock.congestion_control(), smoltcp::socket::tcp::CongestionControl::Reno);
    assert!(!sock.timestamp_enabled());
}

#[test]
fn accepted_sockets_inherit_listener_options() {
    let mut lan = Lan::new();
    let l = lan.b.sock_open(SockType::Stream).unwrap();
    lan.b.sock_setopt(l, SockOpt::NoDelay(true)).unwrap();
    lan.b.sock_setopt(l, SockOpt::KeepAlive(Some(10))).unwrap();
    lan.b.sock_bind(l, None, 8200).unwrap();
    lan.b.sock_listen(l, 2).unwrap();
    let c = lan.a.sock_open(SockType::Stream).unwrap();
    let now = lan.now_ns();
    lan.a.sock_connect(c, ep4(B_IP, 8200), now).unwrap();
    assert!(lan.run_until(2_000, |l2| l2.b.sock_events(l).unwrap().acceptable));
    let (s, _) = lan.b.sock_accept(l).unwrap();
    assert_eq!(lan.b.sock_getopt(s, SockOpt::NoDelay(false)).unwrap(), SockOpt::NoDelay(true));
    assert_eq!(lan.b.sock_getopt(s, SockOpt::KeepAlive(None)).unwrap(), SockOpt::KeepAlive(Some(10)));
    // Endpoints are reported.
    assert_eq!(lan.b.sock_peer(s).unwrap().unwrap().addr, IpAddress::v4(10, 0, 2, 15));
    assert_eq!(lan.b.sock_local(s).unwrap().unwrap().port, 8200);
}

#[test]
fn keepalive_sends_probes_on_an_idle_connection() {
    let mut lan = Lan::new();
    let (_l, c, _s) = connect_pair(&mut lan, 8300);
    lan.a.sock_setopt(c, SockOpt::KeepAlive(Some(2))).unwrap();
    let before = lan.wire.borrow().log.len();
    lan.run(6_000);
    let probes = lan.wire.borrow().log[before..].iter().filter(|(side, f)| *side == 0 && f.len() >= 54 && f[23] == 6).count();
    assert!(probes >= 2, "no keep-alive probes seen ({probes})");
    // The peer answers them, so the connection stays up.
    assert_eq!(lan.a.sock_state(c).unwrap(), SockState::Connected);
}

#[test]
fn user_timeout_kills_a_connection_whose_peer_vanished() {
    let mut lan = Lan::new();
    let (_l, c, _s) = connect_pair(&mut lan, 8400);
    lan.a.sock_setopt(c, SockOpt::TcpTimeoutMs(Some(3_000))).unwrap();
    lan.wire.borrow_mut().cut = true;
    assert_eq!(lan.a.sock_send(c, b"anyone there?").unwrap(), 13);
    lan.run(20_000);
    assert_eq!(lan.a.sock_state(c).unwrap(), SockState::Failed);
    assert_eq!(lan.a.sock_take_error(c).unwrap(), Some(SockError::ConnectionReset));
}

#[test]
fn concurrent_bidirectional_transfer_on_several_connections() {
    let mut lan = Lan::new();
    let l = lan.b.sock_open(SockType::Stream).unwrap();
    lan.b.sock_bind(l, None, 8500).unwrap();
    lan.b.sock_listen(l, 4).unwrap();
    let mut clients = Vec::new();
    let mut servers = Vec::new();
    for _ in 0..3 {
        let c = lan.a.sock_open(SockType::Stream).unwrap();
        let now = lan.now_ns();
        lan.a.sock_connect(c, ep4(B_IP, 8500), now).unwrap();
        clients.push(c);
        assert!(lan.run_until(2_000, |l2| l2.b.sock_events(l).unwrap().acceptable));
        servers.push(lan.b.sock_accept(l).unwrap().0);
    }
    lan.run(200);
    let data: Vec<Vec<u8>> = (0..3).map(|i| pattern(40_000 + i * 1000)).collect();
    let mut sent = [0usize; 3];
    let mut got: Vec<Vec<u8>> = std::vec![Vec::new(); 3];
    let mut buf = std::vec![0u8; 4096];
    for _ in 0..30_000 {
        for i in 0..3 {
            if sent[i] < data[i].len() {
                if let Ok(n) = lan.a.sock_send(clients[i], &data[i][sent[i]..]) {
                    sent[i] += n;
                }
            }
            if let Ok(n) = lan.b.sock_recv(servers[i], &mut buf) {
                got[i].extend_from_slice(&buf[..n]);
            }
        }
        if (0..3).all(|i| got[i].len() == data[i].len()) {
            break;
        }
        lan.step();
    }
    for i in 0..3 {
        assert!(got[i] == data[i], "stream {i} mismatch");
    }
}

#[test]
fn loopback_frames_never_reach_the_driver_but_own_address_traffic_loops() {
    let mut t = Solo::new();
    // A datagram to our OWN LAN address also stays inside.
    let srv = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_bind(srv, None, 7000).unwrap();
    let cli = t.s.sock_open(SockType::Dgram).unwrap();
    t.s.sock_sendto(cli, b"to myself", ep4(A_IP, 7000)).unwrap();
    assert!(t.run_until(100, |t| t.s.sock_events(srv).unwrap().readable));
    let mut buf = [0u8; 32];
    let r = t.s.sock_recvfrom(srv, &mut buf).unwrap();
    assert_eq!(&buf[..r.len], b"to myself");
    assert_eq!(r.from.addr, IpAddress::v4(10, 0, 2, 15));
    for f in &t.s.io().sent {
        // No ARP request for our own address and no UDP to it left the wire.
        assert!(!(f.len() >= 42 && f[12..14] == [0x08, 0x06] && f[38..42] == A_IP), "ARP for own address leaked");
        assert!(!(f.len() >= 34 && f[12..14] == [0x08, 0x00] && f[30..34] == A_IP), "own-address packet leaked");
    }
}


/// Reads raw-ICMP messages until one has ICMP type `ty` (a raw socket also
/// sees the looped-back echo REQUEST, like a Linux raw socket does).
fn recv_until_type(t: &mut Solo, s: SockId, buf: &mut [u8], ty: u8) -> RecvFrom {
    for _ in 0..400 {
        if let Ok(r) = t.s.sock_recvfrom(s, buf) {
            if buf[0] == ty {
                return r;
            }
        }
        t.step();
    }
    panic!("no ICMP message of type {ty}");
}

