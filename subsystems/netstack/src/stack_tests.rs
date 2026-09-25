//! ============================================================================
//! stack_tests.rs
//!
//! Purpose: host tests for `stack.rs` - a mock LAN with a gateway that
//! answers ARP and ICMP echo drives the real smoltcp-based `NetStack` through
//! the `FrameIo` adapter, exactly as the process image does over IPC.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md Section 2.3, 5.4.
//! Position in the system: `#[cfg(test)]` child module of `stack`.
//! Safety/invariants: none (host-only, std available).
//! ============================================================================

extern crate std;

use super::*;
use std::boxed::Box;
use std::collections::VecDeque;
use std::vec::Vec;

const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GW_IP: [u8; 4] = [10, 0, 2, 2];

/// A LAN with exactly one neighbour, the gateway: it answers ARP requests
/// for its own address and ICMP echo requests to any address (like SLIRP,
/// which also answers for the outside world). Everything the stack transmits
/// is recorded.
struct MockLan {
    inbox: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    answer_echo: bool,
}

impl MockLan {
    fn new() -> Self {
        Self { inbox: VecDeque::new(), sent: Vec::new(), answer_echo: true }
    }

    fn arp_reply(target_mac: [u8; 6], target_ip: [u8; 4], asker_mac: [u8; 6], asker_ip: [u8; 4]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&asker_mac);
        f.extend_from_slice(&target_mac);
        f.extend_from_slice(&[0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 2]);
        f.extend_from_slice(&target_mac);
        f.extend_from_slice(&target_ip);
        f.extend_from_slice(&asker_mac);
        f.extend_from_slice(&asker_ip);
        f
    }
}

impl FrameIo for MockLan {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Option<usize> {
        let frame = self.inbox.pop_front()?;
        let n = frame.len().min(buf.len());
        buf[..n].copy_from_slice(&frame[..n]);
        Some(n)
    }

    fn send_frame(&mut self, frame: &[u8]) -> bool {
        self.sent.push(frame.to_vec());
        // ARP request for the gateway address.
        if frame.len() >= 42 && frame[12..14] == [0x08, 0x06] && frame[20..22] == [0, 1] && frame[38..42] == GW_IP {
            let mut asker_mac = [0u8; 6];
            asker_mac.copy_from_slice(&frame[22..28]);
            let mut asker_ip = [0u8; 4];
            asker_ip.copy_from_slice(&frame[28..32]);
            self.inbox.push_back(Self::arp_reply(GW_MAC, GW_IP, asker_mac, asker_ip));
        }
        // ICMP echo request (any destination): answer via the existing
        // pure-function implementation in lib.rs, which cross-checks it
        // against smoltcp's wire format.
        if self.answer_echo {
            if let Some(req) = crate::parse_echo_request(frame) {
                self.inbox.push_back(crate::build_echo_reply(&req));
            }
        }
        true
    }
}

fn new_stack() -> NetStack<MockLan> {
    let storage: &'static mut StackStorage = Box::leak(Box::new(StackStorage::new()));
    NetStack::new(storage, MockLan::new(), OUR_MAC, AddrMode::Static { ip: OUR_IP, prefix: 24, gateway: GW_IP }, 0)
}

/// Polls in 1 ms steps starting at `*now_ms` until `stop` matches an event
/// or `limit_ms` pass; returns every event seen.
fn run_until(stack: &mut NetStack<MockLan>, now_ms: &mut u64, limit_ms: u64, stop: impl Fn(&NetEvent) -> bool) -> Vec<NetEvent> {
    let mut events = Vec::new();
    let end = *now_ms + limit_ms;
    while *now_ms < end {
        let mut batch = Vec::new();
        stack.poll(*now_ms * 1_000_000, &mut |e| batch.push(e));
        *now_ms += 1;
        let done = batch.iter().any(&stop);
        events.extend(batch);
        if done {
            break;
        }
    }
    events
}

fn is_reply(e: &NetEvent) -> bool {
    matches!(e, NetEvent::PingReply { .. })
}

#[test]
fn static_config_is_reported_once() {
    let mut stack = new_stack();
    let mut now = 0;
    let events = run_until(&mut stack, &mut now, 5, |_| false);
    assert_eq!(events.iter().filter(|e| matches!(e, NetEvent::LinkConfigured { .. })).count(), 1);
    assert!(events.contains(&NetEvent::LinkConfigured { ip: OUR_IP, prefix: 24, gateway: Some(GW_IP) }));
}

#[test]
fn ping_gateway_resolves_arp_then_gets_reply() {
    let mut stack = new_stack();
    let mut now = 0;
    stack.ping(GW_IP, 1, 0).unwrap();
    let events = run_until(&mut stack, &mut now, 500, is_reply);
    let reply = events.iter().find_map(|e| {
        if let NetEvent::PingReply { from, seq, rtt_us } = e {
            Some((*from, *seq, *rtt_us))
        } else {
            None
        }
    });
    let (from, seq, _rtt) = reply.expect("no ping reply");
    assert_eq!((from, seq), (GW_IP, 1));
    // First frame out is the ARP request, second the echo request to the MAC
    // the ARP reply taught the stack.
    let sent = &stack.io().sent;
    assert_eq!(sent[0][12..14], [0x08, 0x06], "first frame must be ARP");
    assert_eq!(sent[1][12..14], [0x08, 0x00], "second frame must be IPv4");
    assert_eq!(sent[1][0..6], GW_MAC, "echo request must use the ARP-resolved MAC");
    assert!(!stack.ping_outstanding());
}

#[test]
fn repeated_pings_reuse_the_arp_cache_and_keep_sequence_numbers() {
    let mut stack = new_stack();
    let mut now = 0u64;
    for seq in 1..=5u16 {
        stack.ping(GW_IP, seq, now * 1_000_000).unwrap();
        let events = run_until(&mut stack, &mut now, 500, is_reply);
        assert!(
            events.iter().any(|e| matches!(e, NetEvent::PingReply { seq: s, .. } if *s == seq)),
            "no reply for {seq}"
        );
    }
    let arp_requests = stack.io().sent.iter().filter(|f| f[12..14] == [0x08, 0x06]).count();
    assert_eq!(arp_requests, 1, "ARP must be cached after the first resolution");
}

#[test]
fn unanswered_ping_times_out() {
    let mut stack = new_stack();
    stack.io_mut().answer_echo = false;
    let mut now = 0;
    stack.ping(GW_IP, 7, 0).unwrap();
    let events = run_until(&mut stack, &mut now, 2_000, |e| matches!(e, NetEvent::PingTimeout { .. }));
    assert!(events.contains(&NetEvent::PingTimeout { seq: 7 }));
    // The slot is free again afterwards.
    assert!(stack.ping(GW_IP, 8, now * 1_000_000).is_ok());
}

#[test]
fn second_ping_while_one_is_outstanding_is_refused() {
    let mut stack = new_stack();
    stack.ping(GW_IP, 1, 0).unwrap();
    assert_eq!(stack.ping(GW_IP, 2, 0), Err(PingError::Busy));
}

#[test]
fn off_link_destination_goes_through_the_gateway_mac() {
    let mut stack = new_stack();
    let mut now = 0;
    stack.ping([93, 184, 216, 34], 1, 0).unwrap();
    let events = run_until(&mut stack, &mut now, 500, is_reply);
    assert!(events.iter().any(is_reply));
    let echo = stack.io().sent.iter().find(|f| f[12..14] == [0x08, 0x00]).expect("no IPv4 frame");
    assert_eq!(echo[0..6], GW_MAC, "off-link traffic must be sent to the gateway's MAC");
    assert_eq!(echo[30..34], [93, 184, 216, 34], "destination IP stays the real target");
}

#[test]
fn inbound_echo_request_is_answered() {
    let mut stack = new_stack();
    let mut now = 0;
    // Let the stack learn the gateway first (via a normal ping).
    stack.ping(GW_IP, 1, 0).unwrap();
    run_until(&mut stack, &mut now, 500, is_reply);
    let sent_before = stack.io().sent.len();
    let req = crate::build_echo_request(GW_MAC, OUR_MAC, GW_IP, OUR_IP, 0x1234, 9, b"hello");
    stack.io_mut().inbox.push_back(req);
    run_until(&mut stack, &mut now, 20, |_| false);
    let replies: Vec<_> = stack.io().sent[sent_before..].iter().filter_map(|f| crate::parse_echo_reply(f)).collect();
    assert_eq!(replies.len(), 1, "exactly one echo reply expected");
    assert_eq!((replies[0].ident, replies[0].seq), (0x1234, 9));
}

#[test]
fn malformed_frames_are_ignored() {
    let mut stack = new_stack();
    let mut now = 0;
    let frames: Vec<Vec<u8>> = std::vec![
        std::vec![],
        std::vec![0u8; 3],
        std::vec![0xffu8; 14],
        std::vec![0xffu8; 700],
        // Valid Ethernet header, IPv4 ethertype, truncated IP header.
        [OUR_MAC.as_slice(), GW_MAC.as_slice(), &[0x08, 0x00, 0x45, 0x00, 0x00]].concat(),
        // ARP ethertype, truncated body.
        [OUR_MAC.as_slice(), GW_MAC.as_slice(), &[0x08, 0x06, 0, 1]].concat(),
    ];
    for frame in frames {
        stack.io_mut().inbox.push_back(frame);
    }
    run_until(&mut stack, &mut now, 20, |_| false);
    // Still fully functional afterwards.
    stack.ping(GW_IP, 1, now * 1_000_000).unwrap();
    let events = run_until(&mut stack, &mut now, 500, is_reply);
    assert!(events.iter().any(is_reply));
}

#[test]
fn oversized_receive_is_clamped_and_nothing_transmitted_exceeds_the_driver_buffer() {
    let mut stack = new_stack();
    let mut now = 0;
    stack.io_mut().inbox.push_back(std::vec![0u8; 3000]);
    stack.ping(GW_IP, 1, 0).unwrap();
    run_until(&mut stack, &mut now, 500, is_reply);
    assert!(stack.io().sent.iter().all(|f| f.len() <= MAX_FRAME));
}

#[test]
fn device_reports_ethernet_with_driver_sized_mtu() {
    let dev = FrameDevice::new(MockLan::new());
    let caps = dev.capabilities();
    assert_eq!(caps.medium, Medium::Ethernet);
    assert_eq!(caps.max_transmission_unit, MAX_FRAME);
}

#[test]
fn poll_delay_is_zero_while_a_request_is_pending() {
    let mut stack = new_stack();
    stack.ping(GW_IP, 1, 0).unwrap();
    assert_eq!(stack.poll_delay_ms(0), Some(0));
}
