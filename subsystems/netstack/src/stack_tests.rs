//! ============================================================================
//! stack_tests.rs
//!
//! Purpose: host tests for `stack.rs` - a mock LAN drives the real smoltcp-
//! based `NetStack` through the `FrameIo` adapter, exactly as the process
//! image does over IPC. The LAN has QEMU-SLIRP-like neighbours: a gateway
//! (10.0.2.2) that answers ARP and ICMP echo, a DHCP server on it, an UDP
//! echo service, and a DNS server at 10.0.2.3 - all switchable so failure
//! paths (no DHCP answer, lease not renewed, DNS silence, NXDOMAIN) are
//! tested too.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md Section 2.3, 5.4.
//! Position in the system: `#[cfg(test)]` child module of `stack`.
//! Safety/invariants: none (host-only, std available).
//! ============================================================================

extern crate std;

use super::*;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr,
};
use std::boxed::Box;
use std::collections::VecDeque;
use std::vec::Vec;

const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const DNS_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x03];
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const GW_IP: [u8; 4] = [10, 0, 2, 2];
const DNS_IP: [u8; 4] = [10, 0, 2, 3];
const EXAMPLE_ADDR: [u8; 4] = [93, 184, 216, 34];
const BROADCAST: [u8; 6] = [0xff; 6];

/// UDP port of the mock echo service on the gateway.
const ECHO_PORT: u16 = 7000;

/// DHCP lease length the mock hands out, seconds.
const LEASE_SECS: u32 = 8;

fn caps() -> ChecksumCapabilities {
    ChecksumCapabilities::default()
}

/// Builds Ethernet + IPv4 + UDP with valid checksums.
fn udp_frame(eth_src: [u8; 6], eth_dst: [u8; 6], ip_src: [u8; 4], ip_dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = std::vec![0u8; 14 + 20 + 8 + payload.len()];
    EthernetRepr {
        src_addr: EthernetAddress(eth_src),
        dst_addr: EthernetAddress(eth_dst),
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut EthernetFrame::new_unchecked(&mut buf[..]));
    Ipv4Repr {
        src_addr: v4(ip_src),
        dst_addr: v4(ip_dst),
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    }
    .emit(&mut Ipv4Packet::new_unchecked(&mut buf[14..]), &caps());
    UdpRepr { src_port: sport, dst_port: dport }.emit(
        &mut UdpPacket::new_unchecked(&mut buf[34..]),
        &IpAddress::Ipv4(v4(ip_src)),
        &IpAddress::Ipv4(v4(ip_dst)),
        payload.len(),
        |p| p.copy_from_slice(payload),
        &caps(),
    );
    buf
}

/// A UDP datagram the stack transmitted.
struct SeenUdp {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
}

fn parse_udp(frame: &[u8]) -> Option<SeenUdp> {
    if frame.len() < 42 || frame[12..14] != [0x08, 0x00] || frame[14] != 0x45 || frame[23] != 17 {
        return None;
    }
    let len = u16::from_be_bytes([frame[38], frame[39]]) as usize;
    if len < 8 || 34 + len > frame.len() {
        return None;
    }
    Some(SeenUdp {
        src_ip: frame[26..30].try_into().unwrap(),
        dst_ip: frame[30..34].try_into().unwrap(),
        src_port: u16::from_be_bytes([frame[34], frame[35]]),
        dst_port: u16::from_be_bytes([frame[36], frame[37]]),
        payload: frame[42..34 + len].to_vec(),
    })
}

/// DHCP message type option (53) of a client message.
fn dhcp_msg_type(payload: &[u8]) -> Option<u8> {
    let mut i = 240;
    while i + 1 < payload.len() {
        match payload[i] {
            255 => return None,
            0 => i += 1,
            code => {
                let len = payload[i + 1] as usize;
                if code == 53 && len == 1 {
                    return payload.get(i + 2).copied();
                }
                i += 2 + len;
            }
        }
    }
    None
}

/// OFFER (2) or ACK (5) for the client message `req`.
fn dhcp_reply(msg_type: u8, req: &[u8]) -> Vec<u8> {
    let mut p = std::vec![0u8; 240];
    p[0] = 2; // BOOTREPLY
    p[1] = 1; // Ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(&req[4..8]); // xid
    p[10..12].copy_from_slice(&req[10..12]); // flags
    p[16..20].copy_from_slice(&OUR_IP); // yiaddr
    p[20..24].copy_from_slice(&GW_IP); // siaddr
    p[28..34].copy_from_slice(&req[28..34]); // chaddr
    p[236..240].copy_from_slice(&[99, 130, 83, 99]); // magic cookie
    p.extend_from_slice(&[53, 1, msg_type]);
    p.extend_from_slice(&[54, 4, 10, 0, 2, 2]); // server id
    p.extend_from_slice(&[51, 4]);
    p.extend_from_slice(&LEASE_SECS.to_be_bytes());
    p.extend_from_slice(&[1, 4, 255, 255, 255, 0]); // subnet mask
    p.extend_from_slice(&[3, 4, 10, 0, 2, 2]); // router
    p.extend_from_slice(&[6, 4, 10, 0, 2, 3]); // dns
    p.push(255);
    p
}

/// The name in a DNS query (dotted), or `None` for anything malformed.
fn dns_qname(payload: &[u8]) -> Option<std::string::String> {
    let mut i = 12;
    let mut name = std::string::String::new();
    loop {
        let len = *payload.get(i)? as usize;
        i += 1;
        if len == 0 {
            return Some(name);
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(payload.get(i..i + len)?).ok()?);
        i += len;
    }
}

/// DNS response to `query`: an A record for `addr`, or NXDOMAIN if `None`.
fn dns_reply(query: &[u8], addr: Option<[u8; 4]>) -> Vec<u8> {
    // Question section length: name + 4.
    let mut end = 12;
    while query[end] != 0 {
        end += query[end] as usize + 1;
    }
    end += 1 + 4;
    let mut r = Vec::new();
    r.extend_from_slice(&query[0..2]); // id
    r.extend_from_slice(&if addr.is_some() { [0x81, 0x80] } else { [0x81, 0x83] });
    r.extend_from_slice(&[0, 1, 0, if addr.is_some() { 1 } else { 0 }, 0, 0, 0, 0]);
    r.extend_from_slice(&query[12..end]); // question
    if let Some(a) = addr {
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&a);
    }
    r
}

/// A LAN with a gateway/DHCP/DNS/echo neighbourhood. Everything the stack
/// transmits is recorded; each service can be switched off.
struct MockLan {
    inbox: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    answer_echo: bool,
    answer_dhcp: bool,
    answer_dns: bool,
    /// Names the DNS server knows; others get NXDOMAIN.
    dns_known: Vec<&'static str>,
    dhcp_discovers: usize,
    dhcp_requests: usize,
    dns_queries: Vec<std::string::String>,
}

impl MockLan {
    fn new() -> Self {
        Self {
            inbox: VecDeque::new(),
            sent: Vec::new(),
            answer_echo: true,
            answer_dhcp: true,
            answer_dns: true,
            dns_known: std::vec!["example.com"],
            dhcp_discovers: 0,
            dhcp_requests: 0,
            dns_queries: Vec::new(),
        }
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
        // ARP request for the gateway or the DNS server.
        if frame.len() >= 42 && frame[12..14] == [0x08, 0x06] && frame[20..22] == [0, 1] {
            let target: [u8; 4] = frame[38..42].try_into().unwrap();
            let mac = if target == GW_IP {
                Some(GW_MAC)
            } else if target == DNS_IP {
                Some(DNS_MAC)
            } else {
                None
            };
            if let Some(mac) = mac {
                let mut asker_mac = [0u8; 6];
                asker_mac.copy_from_slice(&frame[22..28]);
                let mut asker_ip = [0u8; 4];
                asker_ip.copy_from_slice(&frame[28..32]);
                self.inbox.push_back(Self::arp_reply(mac, target, asker_mac, asker_ip));
            }
        }
        // ICMP echo request (any destination): answer via the existing
        // pure-function implementation in lib.rs, which cross-checks it
        // against smoltcp's wire format.
        if self.answer_echo {
            if let Some(req) = crate::parse_echo_request(frame) {
                self.inbox.push_back(crate::build_echo_reply(&req));
            }
        }
        if let Some(udp) = parse_udp(frame) {
            self.serve_udp(&udp, frame);
        }
        true
    }
}

impl MockLan {
    fn serve_udp(&mut self, udp: &SeenUdp, frame: &[u8]) {
        // DHCP (client 68 -> server 67).
        if udp.dst_port == 67 {
            let mut client_mac = [0u8; 6];
            client_mac.copy_from_slice(&frame[6..12]);
            match dhcp_msg_type(&udp.payload) {
                Some(1) => {
                    self.dhcp_discovers += 1;
                    if self.answer_dhcp {
                        let reply = dhcp_reply(2, &udp.payload);
                        self.inbox.push_back(udp_frame(GW_MAC, BROADCAST, GW_IP, [255, 255, 255, 255], 67, 68, &reply));
                    }
                }
                Some(3) => {
                    self.dhcp_requests += 1;
                    if self.answer_dhcp {
                        let reply = dhcp_reply(5, &udp.payload);
                        // Renewals are unicast to the server, initial requests
                        // broadcast; the client is reachable at its MAC either way.
                        let dst_ip = if udp.src_ip == [0, 0, 0, 0] { [255, 255, 255, 255] } else { udp.src_ip };
                        let dst_mac = if udp.src_ip == [0, 0, 0, 0] { BROADCAST } else { client_mac };
                        self.inbox.push_back(udp_frame(GW_MAC, dst_mac, GW_IP, dst_ip, 67, 68, &reply));
                    }
                }
                _ => {}
            }
        }
        // DNS server.
        if udp.dst_port == 53 && udp.dst_ip == DNS_IP {
            if let Some(name) = dns_qname(&udp.payload) {
                self.dns_queries.push(name.clone());
                if self.answer_dns {
                    let addr = self.dns_known.iter().any(|n| *n == name).then_some(EXAMPLE_ADDR);
                    let reply = dns_reply(&udp.payload, addr);
                    self.inbox.push_back(udp_frame(DNS_MAC, OUR_MAC, DNS_IP, udp.src_ip, 53, udp.src_port, &reply));
                }
            }
        }
        // UDP echo on the gateway.
        if udp.dst_port == ECHO_PORT && udp.dst_ip == GW_IP {
            self.inbox.push_back(udp_frame(GW_MAC, OUR_MAC, GW_IP, udp.src_ip, ECHO_PORT, udp.src_port, &udp.payload));
        }
    }
}

fn new_stack_with(mode: AddrMode) -> NetStack<MockLan> {
    let storage: &'static mut StackStorage = Box::leak(Box::new(StackStorage::new()));
    NetStack::new(storage, MockLan::new(), OUR_MAC, mode, 0)
}

fn new_stack() -> NetStack<MockLan> {
    new_stack_with(AddrMode::Static { ip: OUR_IP, prefix: 24, gateway: GW_IP, dns: Some(DNS_IP) })
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

fn is_configured(e: &NetEvent) -> bool {
    matches!(e, NetEvent::LinkConfigured { .. })
}

fn is_dns_done(e: &NetEvent) -> bool {
    matches!(e, NetEvent::DnsResolved { .. } | NetEvent::DnsFailed { .. })
}

/// A DHCP stack that already holds its lease (the common starting point).
fn leased_stack() -> (NetStack<MockLan>, u64) {
    let mut stack = new_stack_with(AddrMode::Dhcp);
    let mut now = 0;
    let events = run_until(&mut stack, &mut now, 5_000, is_configured);
    assert!(events.iter().any(is_configured), "no DHCP lease");
    (stack, now)
}

// ---------------------------------------------------------------------------
// Phase 1: static configuration, ARP, ICMP
// ---------------------------------------------------------------------------

#[test]
fn static_config_is_reported_once() {
    let mut stack = new_stack();
    let mut now = 0;
    let events = run_until(&mut stack, &mut now, 5, |_| false);
    assert_eq!(events.iter().filter(|e| is_configured(e)).count(), 1);
    assert!(events.contains(&NetEvent::LinkConfigured {
        ip: OUR_IP,
        prefix: 24,
        gateway: Some(GW_IP),
        dns: Some(DNS_IP),
        dhcp: false
    }));
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
        // A UDP frame with a lying length field.
        {
            let mut f = udp_frame(GW_MAC, OUR_MAC, GW_IP, OUR_IP, 1, 2, b"x");
            f[38] = 0xff;
            f
        },
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

// ---------------------------------------------------------------------------
// Phase 2: DHCP
// ---------------------------------------------------------------------------

#[test]
fn dhcp_has_no_address_until_a_lease_arrives() {
    let mut stack = new_stack_with(AddrMode::Dhcp);
    assert_eq!(stack.config(), None);
    // The only traffic before any lease is the DISCOVER broadcast.
    let mut now = 0;
    stack.io_mut().answer_dhcp = false;
    run_until(&mut stack, &mut now, 10, |_| false);
    let discover = stack.io().sent.iter().find_map(|f| parse_udp(f)).expect("no DHCP DISCOVER sent");
    assert_eq!((discover.src_ip, discover.dst_ip), ([0, 0, 0, 0], [255, 255, 255, 255]));
    assert_eq!((discover.src_port, discover.dst_port), (68, 67));
    assert_eq!(dhcp_msg_type(&discover.payload), Some(1));
}

#[test]
fn dhcp_lease_configures_address_gateway_and_dns() {
    let mut stack = new_stack_with(AddrMode::Dhcp);
    let mut now = 0;
    let events = run_until(&mut stack, &mut now, 5_000, is_configured);
    let expected = NetEvent::LinkConfigured { ip: OUR_IP, prefix: 24, gateway: Some(GW_IP), dns: Some(DNS_IP), dhcp: true };
    assert!(events.contains(&expected), "events: {events:?}");
    assert_eq!(stack.config(), Some(expected));
    // DISCOVER then REQUEST, once each.
    assert_eq!((stack.io().dhcp_discovers, stack.io().dhcp_requests), (1, 1));
}

#[test]
fn ping_works_through_the_dhcp_provided_gateway() {
    let (mut stack, mut now) = leased_stack();
    stack.ping(GW_IP, 1, now * 1_000_000).unwrap();
    let events = run_until(&mut stack, &mut now, 500, is_reply);
    assert!(events.iter().any(is_reply));
}

#[test]
fn dhcp_without_a_server_keeps_retrying_and_stays_unconfigured() {
    let mut stack = new_stack_with(AddrMode::Dhcp);
    stack.io_mut().answer_dhcp = false;
    let mut now = 0;
    let events = run_until(&mut stack, &mut now, 20_000, |_| false);
    assert!(!events.iter().any(is_configured));
    assert!(stack.io().dhcp_discovers >= 2, "DISCOVER must be retransmitted, saw {}", stack.io().dhcp_discovers);
    assert_eq!(stack.config(), None);
}

#[test]
fn dhcp_lease_is_renewed_before_it_expires() {
    let (mut stack, mut now) = leased_stack();
    // Run well past the lease length with a server that keeps answering.
    let events = run_until(&mut stack, &mut now, 3 * LEASE_SECS as u64 * 1_000, |_| false);
    assert!(!events.iter().any(|e| matches!(e, NetEvent::LinkLost)), "lease lost despite renewals: {events:?}");
    assert!(stack.io().dhcp_requests >= 2, "no renewal REQUEST seen ({})", stack.io().dhcp_requests);
    assert!(stack.config().is_some());
}

#[test]
fn dhcp_lease_expiry_takes_the_link_down() {
    let (mut stack, mut now) = leased_stack();
    stack.io_mut().answer_dhcp = false;
    let events = run_until(&mut stack, &mut now, 2 * LEASE_SECS as u64 * 1_000, |e| matches!(e, NetEvent::LinkLost));
    assert!(events.contains(&NetEvent::LinkLost), "lease expiry not detected");
    assert_eq!(stack.config(), None);
    // No address any more: a lookup has nowhere to go.
    assert_eq!(stack.dns_resolve("example.com", now * 1_000_000), Err(DnsError::NoServer));
}

// ---------------------------------------------------------------------------
// Phase 2: DNS
// ---------------------------------------------------------------------------

#[test]
fn dns_resolves_a_name_through_the_dhcp_provided_server() {
    let (mut stack, mut now) = leased_stack();
    let token = stack.dns_resolve("example.com", now * 1_000_000).unwrap();
    let events = run_until(&mut stack, &mut now, 2_000, is_dns_done);
    assert!(
        events.contains(&NetEvent::DnsResolved { token, addr: EXAMPLE_ADDR, cached: false }),
        "events: {events:?}"
    );
    assert_eq!(stack.io().dns_queries, ["example.com"]);
    // The query went to the DHCP-provided server (10.0.2.3), from our address.
    let q = stack.io().sent.iter().filter_map(|f| parse_udp(f)).find(|u| u.dst_port == 53).unwrap();
    assert_eq!((q.src_ip, q.dst_ip), (OUR_IP, DNS_IP));
}

#[test]
fn dns_second_lookup_is_answered_from_the_cache_without_packets() {
    let (mut stack, mut now) = leased_stack();
    let t1 = stack.dns_resolve("example.com", now * 1_000_000).unwrap();
    run_until(&mut stack, &mut now, 2_000, is_dns_done);
    let queries_before = stack.io().dns_queries.len();
    let t2 = stack.dns_resolve("example.com", now * 1_000_000).unwrap();
    let events = run_until(&mut stack, &mut now, 50, is_dns_done);
    assert!(events.contains(&NetEvent::DnsResolved { token: t2, addr: EXAMPLE_ADDR, cached: true }), "{events:?}");
    assert_eq!(stack.io().dns_queries.len(), queries_before, "cache hit must not send a query");
    let _ = t1;
}

#[test]
fn dns_cache_entry_expires() {
    let (mut stack, mut now) = leased_stack();
    stack.dns_resolve("example.com", now * 1_000_000).unwrap();
    run_until(&mut stack, &mut now, 2_000, is_dns_done);
    // Jump past the TTL (poll once at the new time so DHCP timers see it).
    now += DNS_CACHE_TTL_NS / 1_000_000 + 1;
    run_until(&mut stack, &mut now, 5, |_| false);
    let token = stack.dns_resolve("example.com", now * 1_000_000).unwrap();
    let events = run_until(&mut stack, &mut now, 2_000, is_dns_done);
    assert!(
        events.contains(&NetEvent::DnsResolved { token, addr: EXAMPLE_ADDR, cached: false }),
        "expired entry must be looked up again: {events:?}"
    );
}

#[test]
fn dns_nxdomain_reports_failure() {
    let (mut stack, mut now) = leased_stack();
    let token = stack.dns_resolve("no-such-host.invalid", now * 1_000_000).unwrap();
    let events = run_until(&mut stack, &mut now, 2_000, is_dns_done);
    assert!(events.contains(&NetEvent::DnsFailed { token }), "{events:?}");
}

#[test]
fn dns_server_silence_times_out_with_retransmits() {
    let (mut stack, mut now) = leased_stack();
    stack.io_mut().answer_dns = false;
    let token = stack.dns_resolve("example.com", now * 1_000_000).unwrap();
    let events = run_until(&mut stack, &mut now, 30_000, is_dns_done);
    assert!(events.contains(&NetEvent::DnsFailed { token }), "{events:?}");
    assert!(stack.io().dns_queries.len() >= 2, "query must be retransmitted, saw {}", stack.io().dns_queries.len());
}

#[test]
fn dns_before_any_address_is_refused() {
    let mut stack = new_stack_with(AddrMode::Dhcp);
    assert_eq!(stack.dns_resolve("example.com", 0), Err(DnsError::NoServer));
}

#[test]
fn dns_rejects_bad_names_and_limits_concurrent_lookups() {
    let (mut stack, now) = leased_stack();
    let n = now * 1_000_000;
    assert_eq!(stack.dns_resolve("", n), Err(DnsError::InvalidName));
    let long = "a".repeat(DNS_NAME_MAX + 1);
    assert_eq!(stack.dns_resolve(&long, n), Err(DnsError::InvalidName));
    // DNS_SLOTS lookups fit, the next one does not.
    stack.io_mut().answer_dns = false;
    for i in 0..DNS_SLOTS {
        assert!(stack.dns_resolve(&std::format!("host{i}.example"), n).is_ok());
    }
    assert_eq!(stack.dns_resolve("one-too-many.example", n), Err(DnsError::NoFreeSlot));
}

#[test]
fn dns_works_with_a_static_server_too() {
    let mut stack = new_stack();
    let mut now = 0;
    let token = stack.dns_resolve("example.com", 0).unwrap();
    let events = run_until(&mut stack, &mut now, 2_000, is_dns_done);
    assert!(events.contains(&NetEvent::DnsResolved { token, addr: EXAMPLE_ADDR, cached: false }), "{events:?}");
}

// ---------------------------------------------------------------------------
// Phase 2: UDP
// ---------------------------------------------------------------------------

#[test]
fn udp_datagram_round_trip() {
    let mut stack = new_stack();
    let mut now = 0;
    stack.udp_bind(4000).unwrap();
    stack.udp_send(GW_IP, ECHO_PORT, b"hello udp").unwrap();
    run_until(&mut stack, &mut now, 200, |_| false);
    let mut buf = [0u8; 64];
    let d = stack.udp_recv(&mut buf).expect("no echo received");
    assert_eq!((d.src, d.src_port), (GW_IP, ECHO_PORT));
    assert_eq!(&buf[..d.len], b"hello udp");
    assert!(stack.udp_recv(&mut buf).is_none());
}

#[test]
fn udp_rejects_bad_use() {
    let mut stack = new_stack();
    assert_eq!(stack.udp_bind(0), Err(UdpError::Bind));
    stack.udp_bind(4000).unwrap();
    assert_eq!(stack.udp_bind(4001), Err(UdpError::Bind), "already bound");
    assert_eq!(stack.udp_send(GW_IP, 9, &[0u8; UDP_PAYLOAD_MAX + 1]), Err(UdpError::Send));
}

#[test]
fn udp_datagram_larger_than_the_callers_buffer_is_dropped_not_truncated() {
    let mut stack = new_stack();
    let mut now = 0;
    stack.udp_bind(4000).unwrap();
    stack.udp_send(GW_IP, ECHO_PORT, &[7u8; 100]).unwrap();
    run_until(&mut stack, &mut now, 200, |_| false);
    let mut small = [0u8; 10];
    assert!(stack.udp_recv(&mut small).is_none());
}

#[test]
fn no_link_lost_event_before_the_first_lease() {
    let mut stack = new_stack_with(AddrMode::Dhcp);
    let mut now = 0;
    let events = run_until(&mut stack, &mut now, 5_000, is_configured);
    assert!(!events.iter().any(|e| matches!(e, NetEvent::LinkLost)), "spurious LinkLost: {events:?}");
}

// ---------------------------------------------------------------------------
// Link state: cable/Wi-Fi drop and return, DHCP retry
// ---------------------------------------------------------------------------

use crate::status::{AdapterKind, ConnState};

#[test]
fn link_down_drops_the_lease_and_reports_disconnected() {
    let (mut stack, mut now) = leased_stack();
    assert_eq!(stack.conn_state(), ConnState::Connected);
    stack.set_link(false, now * 1_000_000);
    let events = run_until(&mut stack, &mut now, 5, |_| false);
    assert!(events.contains(&NetEvent::LinkLost), "events: {events:?}");
    assert_eq!(stack.conn_state(), ConnState::Disconnected);
    assert_eq!(stack.config(), None);
    let snap = stack.snapshot(OUR_MAC, AdapterKind::Ethernet);
    assert_eq!((snap.adapter, snap.link_up, snap.state, snap.ip), (true, false, ConnState::Disconnected, None));
}

#[test]
fn nothing_is_sent_while_the_link_is_down() {
    let (mut stack, mut now) = leased_stack();
    stack.set_link(false, now * 1_000_000);
    let sent = stack.io().sent.len();
    run_until(&mut stack, &mut now, 30_000, |_| false);
    assert_eq!(stack.io().sent.len(), sent);
}

#[test]
fn link_up_reruns_dhcp_and_connects_again() {
    let (mut stack, mut now) = leased_stack();
    let discovers = stack.io().dhcp_discovers;
    stack.set_link(false, now * 1_000_000);
    run_until(&mut stack, &mut now, 2_000, |_| false);
    stack.set_link(true, now * 1_000_000);
    assert_eq!(stack.conn_state(), ConnState::Connecting);
    let events = run_until(&mut stack, &mut now, 5_000, is_configured);
    assert!(events.iter().any(is_configured), "no new lease after link up");
    assert_eq!(stack.conn_state(), ConnState::Connected);
    assert!(stack.io().dhcp_discovers > discovers, "DHCP was not re-run");
    let snap = stack.snapshot(OUR_MAC, AdapterKind::Ethernet);
    assert_eq!((snap.ip, snap.gateway, snap.dns), (Some((OUR_IP, 24)), Some(GW_IP), Some(DNS_IP)));
}

#[test]
fn link_up_with_a_silent_dhcp_server_keeps_retrying_with_backoff_then_connects() {
    let mut stack = new_stack_with(AddrMode::Dhcp);
    stack.io_mut().answer_dhcp = false;
    let mut now = 0;
    run_until(&mut stack, &mut now, 1_000, |_| false);
    stack.set_link(false, now * 1_000_000);
    stack.set_link(true, now * 1_000_000);
    let before = stack.io().dhcp_discovers;
    // Two minutes of silence: still Connecting, DISCOVER keeps going out.
    run_until(&mut stack, &mut now, 120_000, |_| false);
    assert_eq!(stack.conn_state(), ConnState::Connecting);
    assert!(stack.io().dhcp_discovers >= before + 3, "only {} new DISCOVERs", stack.io().dhcp_discovers - before);
    // The server comes back: the very next restart or retransmit connects.
    stack.io_mut().answer_dhcp = true;
    let events = run_until(&mut stack, &mut now, 70_000, is_configured);
    assert!(events.iter().any(is_configured), "never connected after the server returned");
    assert_eq!(stack.conn_state(), ConnState::Connected);
}

#[test]
fn repeated_link_reports_are_idempotent() {
    let (mut stack, mut now) = leased_stack();
    let discovers = stack.io().dhcp_discovers;
    stack.set_link(true, now * 1_000_000);
    stack.set_link(true, now * 1_000_000);
    run_until(&mut stack, &mut now, 100, |_| false);
    assert_eq!(stack.io().dhcp_discovers, discovers);
    assert_eq!(stack.conn_state(), ConnState::Connected);
}

#[test]
fn static_configuration_is_restored_when_the_link_returns() {
    let mut stack = new_stack();
    let mut now = 0;
    assert_eq!(stack.conn_state(), ConnState::Connected);
    stack.set_link(false, 0);
    assert_eq!(stack.conn_state(), ConnState::Disconnected);
    stack.set_link(true, 1_000_000);
    assert_eq!(stack.conn_state(), ConnState::Connected);
    stack.ping(GW_IP, 1, now * 1_000_000).unwrap();
    let events = run_until(&mut stack, &mut now, 500, is_reply);
    assert!(events.iter().any(is_reply));
}
