//! Host tests of the boot-time self-checks (`selftest.rs`): loopback checks on
//! a lone stack, and the HTTP check against a small server running on the
//! second stack of a simulated LAN.

extern crate std;

use super::*;
use crate::sockets::SockOpt;
use crate::stack::socket_tests::{ep4, Lan, Solo, A_IP, B_IP};
use std::vec::Vec;

fn run_solo(t: &mut Solo, mut step: impl FnMut(&mut Solo, u64) -> Option<TestEvent>) -> TestEvent {
    for _ in 0..30_000 {
        let now = t.now_ns();
        if let Some(ev) = step(t, now) {
            return ev;
        }
        t.step();
    }
    panic!("check did not finish");
}

#[test]
fn tcp_echo_loopback_v4_and_v6() {
    for family in [Family::V4, Family::V6] {
        let mut t = Solo::new();
        let mut check = TcpEcho::new(family, 7007);
        let ev = run_solo(&mut t, |t, now| check.step(&mut t.s, now));
        assert_eq!(ev, TestEvent::TcpLoopback { family, ok: true, bytes: 1200 }, "{family:?}");
        // Everything was released.
        assert_eq!(t.s.sock_counts(), (0, 0, 0));
    }
}

#[test]
fn udp_echo_loopback_v4_and_v6() {
    for family in [Family::V4, Family::V6] {
        let mut t = Solo::new();
        let mut check = UdpEcho::new(family, 7008);
        let ev = run_solo(&mut t, |t, now| check.step(&mut t.s, now));
        assert_eq!(ev, TestEvent::UdpLoopback { family, ok: true });
        assert_eq!(t.s.sock_counts(), (0, 0, 0));
    }
}

#[test]
fn raw_icmp_echo_loopback_v4_and_v6() {
    for family in [Family::V4, Family::V6] {
        let mut t = Solo::new();
        let mut check = RawIcmpEcho::new(family, 0x7171);
        let ev = run_solo(&mut t, |t, now| check.step(&mut t.s, now));
        assert_eq!(ev, TestEvent::RawIcmp { family, ok: true });
        assert_eq!(t.s.sock_counts(), (0, 0, 0));
    }
}

#[test]
fn all_loopback_checks_can_run_back_to_back_on_one_stack() {
    let mut t = Solo::new();
    for round in 0..3 {
        let mut a = TcpEcho::new(Family::V4, 7007);
        let mut b = TcpEcho::new(Family::V6, 7007);
        let mut c = UdpEcho::new(Family::V4, 7008);
        let mut d = RawIcmpEcho::new(Family::V6, 0x7171);
        for ev in [
            run_solo(&mut t, |t, now| a.step(&mut t.s, now)),
            run_solo(&mut t, |t, now| b.step(&mut t.s, now)),
            run_solo(&mut t, |t, now| c.step(&mut t.s, now)),
            run_solo(&mut t, |t, now| d.step(&mut t.s, now)),
        ] {
            let ok = match ev {
                TestEvent::TcpLoopback { ok, .. } | TestEvent::UdpLoopback { ok, .. } | TestEvent::RawIcmp { ok, .. } => ok,
                TestEvent::Http { ok, .. } => ok,
            };
            assert!(ok, "round {round}: {ev:?}");
        }
    }
}

/// A tiny HTTP server on stack B: answers one request per connection.
struct MiniServer {
    listener: SockId,
    conns: Vec<(SockId, Vec<u8>, bool)>,
    requests: Vec<Vec<u8>>,
    body_len: usize,
}

impl MiniServer {
    fn new(lan: &mut Lan, body_len: usize) -> Self {
        let l = lan.b.sock_open(SockType::Stream).unwrap();
        lan.b.sock_setopt(l, SockOpt::ReuseAddr(true)).unwrap();
        lan.b.sock_bind(l, None, 80).unwrap();
        lan.b.sock_listen(l, 2).unwrap();
        MiniServer { listener: l, conns: Vec::new(), requests: Vec::new(), body_len }
    }

    fn poll(&mut self, lan: &mut Lan) {
        while let Ok((s, _)) = lan.b.sock_accept(self.listener) {
            self.conns.push((s, Vec::new(), false));
        }
        for (s, req, replied) in self.conns.iter_mut() {
            let mut buf = [0u8; 512];
            while let Ok(n) = lan.b.sock_recv(*s, &mut buf) {
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            if !*replied && req.windows(4).any(|w| w == b"\r\n\r\n") {
                let mut resp = std::format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", self.body_len).into_bytes();
                resp.extend(std::iter::repeat(b'x').take(self.body_len));
                let mut off = 0;
                // Push as much as fits; the rest goes out on later polls.
                while off < resp.len() {
                    match lan.b.sock_send(*s, &resp[off..]) {
                        Ok(k) => off += k,
                        Err(_) => break,
                    }
                }
                self.requests.push(req.clone());
                *replied = true;
                let _ = lan.b.sock_shutdown(*s, Shutdown::Write);
            }
        }
    }
}

fn run_http(lan: &mut Lan, server: Option<&mut MiniServer>, check: &mut HttpGet, limit_ms: u64) -> TestEvent {
    let mut server = server;
    for _ in 0..limit_ms {
        if let Some(s) = server.as_deref_mut() {
            s.poll(lan);
        }
        let now = lan.now_ns();
        if let Some(ev) = check.step(&mut lan.a, now) {
            return ev;
        }
        lan.step();
    }
    panic!("http check did not finish");
}

#[test]
fn http_get_reads_the_status_line() {
    let mut lan = Lan::new();
    let mut server = MiniServer::new(&mut lan, 900);
    let mut check = HttpGet::new(ep4(B_IP, 80).addr, "example.test");
    let ev = run_http(&mut lan, Some(&mut server), &mut check, 40_000);
    let TestEvent::Http { addr, ok, status, status_len, bytes, error } = ev else { panic!("wrong event {ev:?}") };
    assert!(ok, "{ev:?}");
    assert_eq!(addr, ep4(B_IP, 80).addr);
    assert_eq!(&status[..status_len], b"HTTP/1.0 200 OK");
    assert!(bytes >= 200);
    assert_eq!(error, None);
    // The request the server saw is a proper HTTP/1.0 GET with a Host header.
    let req = std::string::String::from_utf8(server.requests[0].clone()).unwrap();
    assert!(req.starts_with("GET / HTTP/1.0\r\n"), "{req}");
    assert!(req.contains("Host: example.test\r\n"));
    let _ = A_IP;
}

#[test]
fn http_get_of_a_small_response_ends_at_eof() {
    let mut lan = Lan::new();
    let mut server = MiniServer::new(&mut lan, 10);
    let mut check = HttpGet::new(ep4(B_IP, 80).addr, "x");
    let ev = run_http(&mut lan, Some(&mut server), &mut check, 40_000);
    let TestEvent::Http { ok, status, status_len, bytes, .. } = ev else { panic!() };
    assert!(ok);
    assert_eq!(&status[..status_len], b"HTTP/1.0 200 OK");
    assert!(bytes < 200, "the whole response is small ({bytes})");
}

#[test]
fn http_get_reports_a_refused_connection() {
    let mut lan = Lan::new();
    let mut check = HttpGet::new(ep4(B_IP, 80).addr, "x");
    let ev = run_http(&mut lan, None, &mut check, 40_000);
    let TestEvent::Http { ok, error, bytes, .. } = ev else { panic!() };
    assert!(!ok);
    assert_eq!(error, Some(SockError::ConnectionRefused));
    assert_eq!(bytes, 0);
}

#[test]
fn http_get_times_out_against_a_dead_peer() {
    let mut lan = Lan::new();
    lan.wire.borrow_mut().cut = true;
    let mut check = HttpGet::new(ep4(B_IP, 80).addr, "x");
    let ev = run_http(&mut lan, None, &mut check, 60_000);
    let TestEvent::Http { ok, error, .. } = ev else { panic!() };
    assert!(!ok);
    // Either the connect timeout (20 s) or the check timeout (30 s) fires.
    assert!(matches!(error, Some(SockError::TimedOut) | None), "{error:?}");
    assert_eq!(lan.a.sock_counts(), (0, 0, 0), "the socket is released");
}

#[test]
fn request_builder_truncates_instead_of_overflowing() {
    let mut small = [0u8; 20];
    let n = build_request(&mut small, "example.com");
    assert_eq!(n, 20);
    let mut big = [0u8; 128];
    let n = build_request(&mut big, "example.com");
    assert!(big[..n].starts_with(b"GET / HTTP/1.0\r\nHost: example.com\r\n"));
    assert!(big[..n].ends_with(b"\r\n\r\n"));
}

#[test]
fn boot_sequence_runs_every_loopback_check_then_the_queued_http_get() {
    let mut lan = Lan::new();
    let mut server = MiniServer::new(&mut lan, 300);
    let mut seq = BootChecks::new();
    seq.queue_http(ep4(B_IP, 80).addr, "example.test");
    let mut events: Vec<TestEvent> = Vec::new();
    for _ in 0..200_000 {
        server.poll(&mut lan);
        let now = lan.now_ns();
        seq.step(&mut lan.a, now, &mut |e| events.push(e));
        if events.len() == 7 {
            break;
        }
        lan.step();
    }
    assert_eq!(events.len(), 7, "{events:?}");
    for (i, e) in events.iter().enumerate() {
        let ok = match e {
            TestEvent::TcpLoopback { ok, .. } | TestEvent::UdpLoopback { ok, .. } | TestEvent::RawIcmp { ok, .. } => *ok,
            TestEvent::Http { ok, .. } => *ok,
        };
        assert!(ok, "check {i} failed: {e:?}");
    }
    assert!(matches!(events[0], TestEvent::TcpLoopback { family: Family::V4, .. }));
    assert!(matches!(events[1], TestEvent::TcpLoopback { family: Family::V6, .. }));
    assert!(matches!(events[6], TestEvent::Http { .. }));
    assert!(seq.loopback_done());
}
