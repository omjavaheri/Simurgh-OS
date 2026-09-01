//! ============================================================================
//! netstack
//!
//! Purpose: the user-space network stack. The MVP acceptance target is a
//! single ICMP echo round-trip over virtio-net on QEMU
//! (03-Kernel-Subsystems-Layer.md §5.4). This crate provides the packet
//! parsing/building needed for that — Ethernet + ARP + IPv4 + ICMP — as
//! pure, testable functions; the virtio-net driver binding and the socket
//! API are layered on top.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.3 (user-space
//! TCP/IP, smoltcp-inspired), §5.4 (ICMP echo MVP), §2.3/§5.4.1
//! (kernel-bypass path — control plane in `ipc_protocol::net`).
//!
//! Position in the system: an isolated layer-3 process. Talks to the
//! virtio-net driver (through the Device Manager) for the standard path;
//! the bypass path hands a client direct ring access and then stays out of
//! the data path.
//!
//! `build_arp_request`/`parse_arp_reply`/`build_echo_request`/
//! `parse_echo_reply` are the OUTBOUND-initiating half of the MVP
//! acceptance demo (`kernel_arch_glue`'s own riscv64 net demo, §5.4): this
//! project's QEMU usermode `-netdev user` network cannot be reached FROM
//! the host without a tap/bridge setup this host does not have (a
//! documented environment limitation, same class as the aarch64 UEFI QEMU
//! issue elsewhere in this project's history) — so the demo has the guest
//! resolve and ping ITS OWN gateway (10.0.2.2) instead of waiting for an
//! external ping, exercising the identical parse/build pair symmetrically
//! reversed. `parse_echo_request`/`build_echo_reply` (below) remain the
//! reply-to-an-inbound-ping half, unchanged, and are what a real
//! externally-initiated ping would still need.
//!
//! Safety/invariants: parsers are total and bounds-checked — a truncated
//! or malformed frame yields `None`, never a panic or an out-of-bounds
//! read. The one-complement checksum is computed over borrowed slices with
//! no allocation.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

/// EtherType for IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// IPv4 protocol number for ICMP.
pub const IP_PROTO_ICMP: u8 = 1;
/// ICMP type: echo request.
pub const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP type: echo reply.
pub const ICMP_ECHO_REPLY: u8 = 0;

/// A parsed inbound ICMP echo request, with everything needed to build the
/// reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoRequest {
    /// Source MAC (reply goes back to it).
    pub src_mac: [u8; 6],
    /// Destination MAC we received on (becomes the reply source).
    pub dst_mac: [u8; 6],
    /// Source IPv4 (reply destination).
    pub src_ip: [u8; 4],
    /// Destination IPv4 we received on (reply source).
    pub dst_ip: [u8; 4],
    /// ICMP identifier field (echoed back).
    pub ident: u16,
    /// ICMP sequence field (echoed back).
    pub seq: u16,
    /// ICMP payload (echoed back verbatim).
    pub payload: Vec<u8>,
}

/// Big-endian u16 read, bounds-checked.
fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// The RFC 1071 one's-complement checksum over `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parses an Ethernet frame carrying IPv4/ICMP and, if it is an echo
/// request, returns the data needed to reply. Returns `None` for anything
/// else (wrong ethertype/proto/icmp-type) or a malformed/truncated frame.
///
/// Layout assumed: 14-byte Ethernet header, 20-byte IPv4 header (no
/// options), 8-byte ICMP header, then payload — the shape QEMU's
/// `ping` traffic uses.
pub fn parse_echo_request(frame: &[u8]) -> Option<EchoRequest> {
    if frame.len() < 14 + 20 + 8 {
        return None;
    }
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    dst_mac.copy_from_slice(&frame[0..6]);
    src_mac.copy_from_slice(&frame[6..12]);
    if be16(frame, 12)? != ETHERTYPE_IPV4 {
        return None;
    }

    let ip = &frame[14..];
    let ihl = (ip[0] & 0x0F) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != IP_PROTO_ICMP {
        return None;
    }
    let mut src_ip = [0u8; 4];
    let mut dst_ip = [0u8; 4];
    src_ip.copy_from_slice(&ip[12..16]);
    dst_ip.copy_from_slice(&ip[16..20]);

    let icmp = &ip[ihl..];
    if icmp.len() < 8 || icmp[0] != ICMP_ECHO_REQUEST {
        return None;
    }
    let ident = be16(icmp, 4)?;
    let seq = be16(icmp, 6)?;
    let payload = icmp[8..].to_vec();

    Some(EchoRequest {
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        ident,
        seq,
        payload,
    })
}

/// Builds the Ethernet/IPv4/ICMP frame for the echo reply to `req`.
///
/// Swaps MAC and IP src/dst, sets ICMP type to `ICMP_ECHO_REPLY`, echoes
/// `ident`/`seq`/`payload`, and fills in both checksums.
pub fn build_echo_reply(req: &EchoRequest) -> Vec<u8> {
    let icmp_len = 8 + req.payload.len();
    let ip_total = 20 + icmp_len;
    let mut f = Vec::with_capacity(14 + ip_total);

    // Ethernet: dst = original src, src = original dst.
    f.extend_from_slice(&req.src_mac);
    f.extend_from_slice(&req.dst_mac);
    f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // IPv4 header.
    let ip_start = f.len();
    f.push(0x45); // version 4, IHL 5
    f.push(0x00); // DSCP/ECN
    f.extend_from_slice(&(ip_total as u16).to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes()); // identification
    f.extend_from_slice(&0x4000u16.to_be_bytes()); // flags: DF
    f.push(64); // TTL
    f.push(IP_PROTO_ICMP);
    f.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    f.extend_from_slice(&req.dst_ip); // src = original dst
    f.extend_from_slice(&req.src_ip); // dst = original src
    let ip_csum = checksum(&f[ip_start..ip_start + 20]);
    f[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());

    // ICMP.
    let icmp_start = f.len();
    f.push(ICMP_ECHO_REPLY);
    f.push(0); // code
    f.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    f.extend_from_slice(&req.ident.to_be_bytes());
    f.extend_from_slice(&req.seq.to_be_bytes());
    f.extend_from_slice(&req.payload);
    let icmp_csum = checksum(&f[icmp_start..]);
    f[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    f
}

/// EtherType for ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// ARP hardware type: Ethernet.
const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP operation: request.
const ARP_OP_REQUEST: u16 = 1;
/// ARP operation: reply.
const ARP_OP_REPLY: u16 = 2;
/// Broadcast MAC (ARP requests go here).
pub const MAC_BROADCAST: [u8; 6] = [0xff; 6];

/// Builds an Ethernet+ARP "who has `target_ip`, tell `sender_ip`" request,
/// broadcast (`MAC_BROADCAST`) at the Ethernet layer per ARP convention
/// (RFC 826) — the sender does not yet know the target's MAC, that is the
/// whole point of asking.
pub fn build_arp_request(sender_mac: [u8; 6], sender_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + 28);
    // Ethernet.
    f.extend_from_slice(&MAC_BROADCAST);
    f.extend_from_slice(&sender_mac);
    f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    // ARP (RFC 826): htype, ptype, hlen, plen, oper, sha, spa, tha, tpa.
    f.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    f.push(6); // hlen
    f.push(4); // plen
    f.extend_from_slice(&ARP_OP_REQUEST.to_be_bytes());
    f.extend_from_slice(&sender_mac);
    f.extend_from_slice(&sender_ip);
    f.extend_from_slice(&[0u8; 6]); // tha: unknown, this is what we're asking for
    f.extend_from_slice(&target_ip);
    f
}

/// Parses an inbound Ethernet+ARP reply, returning the sender's MAC if it
/// answers `expected_sender_ip` (the address this driver asked about via
/// `build_arp_request`'s own `target_ip`). Returns `None` for anything
/// else (wrong ethertype/operation/address) or a truncated frame — same
/// total, bounds-checked shape as `parse_echo_request`.
pub fn parse_arp_reply(frame: &[u8], expected_sender_ip: [u8; 4]) -> Option<[u8; 6]> {
    if frame.len() < 14 + 28 {
        return None;
    }
    if be16(frame, 12)? != ETHERTYPE_ARP {
        return None;
    }
    let arp = &frame[14..];
    if be16(arp, 0)? != ARP_HTYPE_ETHERNET || be16(arp, 2)? != ETHERTYPE_IPV4 {
        return None;
    }
    if arp[4] != 6 || arp[5] != 4 {
        return None;
    }
    if be16(arp, 6)? != ARP_OP_REPLY {
        return None;
    }
    if arp[14..18] != expected_sender_ip {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&arp[8..14]);
    Some(sender_mac)
}

/// Builds the Ethernet/IPv4/ICMP frame for an OUTBOUND echo request (the
/// mirror image of `build_echo_reply` — this driver INITIATING a ping,
/// per this module's own doc comment on why the MVP demo pings outward
/// rather than waiting for an inbound one).
#[allow(clippy::too_many_arguments)]
pub fn build_echo_request(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let ip_total = 20 + icmp_len;
    let mut f = Vec::with_capacity(14 + ip_total);

    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    let ip_start = f.len();
    f.push(0x45);
    f.push(0x00);
    f.extend_from_slice(&(ip_total as u16).to_be_bytes());
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&0x4000u16.to_be_bytes());
    f.push(64);
    f.push(IP_PROTO_ICMP);
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&dst_ip);
    let ip_csum = checksum(&f[ip_start..ip_start + 20]);
    f[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());

    let icmp_start = f.len();
    f.push(ICMP_ECHO_REQUEST);
    f.push(0);
    f.extend_from_slice(&0u16.to_be_bytes());
    f.extend_from_slice(&ident.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(payload);
    let icmp_csum = checksum(&f[icmp_start..]);
    f[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_csum.to_be_bytes());

    f
}

/// A parsed inbound ICMP echo reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoReply {
    /// Source IPv4 (who replied).
    pub src_ip: [u8; 4],
    /// ICMP identifier field.
    pub ident: u16,
    /// ICMP sequence field.
    pub seq: u16,
    /// ICMP payload.
    pub payload: Vec<u8>,
}

/// Parses an inbound Ethernet frame carrying IPv4/ICMP echo REPLY (the
/// mirror image of `parse_echo_request`). Returns `None` for anything
/// else or a malformed/truncated frame — same total, bounds-checked shape.
pub fn parse_echo_reply(frame: &[u8]) -> Option<EchoReply> {
    if frame.len() < 14 + 20 + 8 {
        return None;
    }
    if be16(frame, 12)? != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[14..];
    let ihl = (ip[0] & 0x0F) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != IP_PROTO_ICMP {
        return None;
    }
    let mut src_ip = [0u8; 4];
    src_ip.copy_from_slice(&ip[12..16]);

    let icmp = &ip[ihl..];
    if icmp.len() < 8 || icmp[0] != ICMP_ECHO_REPLY {
        return None;
    }
    let ident = be16(icmp, 4)?;
    let seq = be16(icmp, 6)?;
    let payload = icmp[8..].to_vec();

    Some(EchoReply {
        src_ip,
        ident,
        seq,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample_request_frame() -> Vec<u8> {
        let mut f = Vec::new();
        // eth: dst, src, type
        f.extend_from_slice(&[0x52, 0x54, 0, 0, 0, 0x02]); // our mac
        f.extend_from_slice(&[0x52, 0x54, 0, 0, 0, 0x01]); // peer mac
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        // ip: 20 bytes
        let ip_start = f.len();
        f.push(0x45);
        f.push(0);
        f.extend_from_slice(&(20u16 + 8 + 4).to_be_bytes());
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&0x4000u16.to_be_bytes());
        f.push(64);
        f.push(IP_PROTO_ICMP);
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&[10, 0, 0, 1]); // src
        f.extend_from_slice(&[10, 0, 0, 2]); // dst (us)
        let c = checksum(&f[ip_start..ip_start + 20]);
        f[ip_start + 10..ip_start + 12].copy_from_slice(&c.to_be_bytes());
        // icmp echo request + 4-byte payload
        let icmp_start = f.len();
        f.push(ICMP_ECHO_REQUEST);
        f.push(0);
        f.extend_from_slice(&0u16.to_be_bytes());
        f.extend_from_slice(&0x1234u16.to_be_bytes()); // ident
        f.extend_from_slice(&0x0001u16.to_be_bytes()); // seq
        f.extend_from_slice(b"ping");
        let c = checksum(&f[icmp_start..]);
        f[icmp_start + 2..icmp_start + 4].copy_from_slice(&c.to_be_bytes());
        f
    }

    #[test]
    fn parses_echo_request() {
        let req = parse_echo_request(&sample_request_frame()).unwrap();
        assert_eq!(req.src_ip, [10, 0, 0, 1]);
        assert_eq!(req.dst_ip, [10, 0, 0, 2]);
        assert_eq!(req.ident, 0x1234);
        assert_eq!(req.seq, 1);
        assert_eq!(req.payload, b"ping");
    }

    #[test]
    fn reply_swaps_addresses_and_has_valid_checksums() {
        let req = parse_echo_request(&sample_request_frame()).unwrap();
        let reply = build_echo_reply(&req);
        let parsed_back_type = reply[14 + 20];
        assert_eq!(parsed_back_type, ICMP_ECHO_REPLY);
        // ICMP checksum over the reply's ICMP section must be zero.
        assert_eq!(checksum(&reply[14 + 20..]), 0);
        // IP checksum over the reply's IP header must be zero.
        assert_eq!(checksum(&reply[14..14 + 20]), 0);
        // Ethernet dst is the original sender.
        assert_eq!(&reply[0..6], &[0x52, 0x54, 0, 0, 0, 0x01]);
    }

    #[test]
    fn non_icmp_frame_is_ignored() {
        let mut f = sample_request_frame();
        f[14 + 9] = 6; // change IP proto to TCP
        assert_eq!(parse_echo_request(&f), None);
    }

    #[test]
    fn truncated_frame_is_ignored() {
        assert_eq!(parse_echo_request(&[0u8; 10]), None);
    }

    #[test]
    fn checksum_of_known_vector() {
        // Two 16-bit words 0x0001 + 0xF203 -> sum 0xF204 -> ~ = 0x0DFB
        let data = [0x00, 0x01, 0xF2, 0x03];
        assert_eq!(checksum(&data), 0x0DFB);
        let _ = vec![0u8; 0];
    }

    const OUR_MAC: [u8; 6] = [0x52, 0x54, 0, 0, 0, 0x02];
    const GW_MAC: [u8; 6] = [0x52, 0x54, 0, 0, 0, 0x01];
    const OUR_IP: [u8; 4] = [10, 0, 2, 15];
    const GW_IP: [u8; 4] = [10, 0, 2, 2];

    fn sample_arp_reply_frame() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&OUR_MAC); // dst = us
        f.extend_from_slice(&GW_MAC); // src = gateway
        f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        f.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f.push(6);
        f.push(4);
        f.extend_from_slice(&ARP_OP_REPLY.to_be_bytes());
        f.extend_from_slice(&GW_MAC); // sha
        f.extend_from_slice(&GW_IP); // spa
        f.extend_from_slice(&OUR_MAC); // tha
        f.extend_from_slice(&OUR_IP); // tpa
        f
    }

    #[test]
    fn build_arp_request_is_broadcast_and_well_formed() {
        let f = build_arp_request(OUR_MAC, OUR_IP, GW_IP);
        assert_eq!(&f[0..6], &MAC_BROADCAST);
        assert_eq!(&f[6..12], &OUR_MAC);
        assert_eq!(be16(&f, 12), Some(ETHERTYPE_ARP));
        assert_eq!(&f[14 + 8..14 + 14], &OUR_MAC); // sha
        assert_eq!(&f[14 + 14..14 + 18], &OUR_IP); // spa
        assert_eq!(&f[14 + 24..14 + 28], &GW_IP); // tpa
    }

    #[test]
    fn parses_arp_reply_matching_expected_sender() {
        let f = sample_arp_reply_frame();
        let mac = parse_arp_reply(&f, GW_IP).unwrap();
        assert_eq!(mac, GW_MAC);
    }

    #[test]
    fn arp_reply_for_different_ip_is_ignored() {
        let f = sample_arp_reply_frame();
        assert_eq!(parse_arp_reply(&f, [10, 0, 2, 99]), None);
    }

    #[test]
    fn arp_request_frame_is_not_a_reply() {
        let f = build_arp_request(OUR_MAC, OUR_IP, GW_IP);
        assert_eq!(parse_arp_reply(&f, GW_IP), None);
    }

    #[test]
    fn echo_request_round_trips_through_echo_reply() {
        let req = build_echo_request(OUR_MAC, GW_MAC, OUR_IP, GW_IP, 0x1234, 7, b"abcd");
        // `req` is itself a well-formed inbound-shaped echo REQUEST frame
        // (same wire shape `parse_echo_request` already parses for the
        // reply-to-inbound-ping half of this module) — confirms the two
        // builders produce byte-compatible frames before simulating the
        // gateway's own reply below.
        assert!(parse_echo_request(&req).is_some());
        // Build what the gateway would send back: an ICMP echo reply.
        let mut reply = req.clone();
        reply[14 + 20] = ICMP_ECHO_REPLY;
        // Recompute the ICMP checksum after flipping the type byte.
        reply[14 + 20 + 2..14 + 20 + 4].copy_from_slice(&0u16.to_be_bytes());
        let c = checksum(&reply[14 + 20..]);
        reply[14 + 20 + 2..14 + 20 + 4].copy_from_slice(&c.to_be_bytes());

        let parsed = parse_echo_reply(&reply).unwrap();
        assert_eq!(parsed.src_ip, OUR_IP); // src field is unchanged from the request (test doesn't swap IPs)
        assert_eq!(parsed.ident, 0x1234);
        assert_eq!(parsed.seq, 7);
        assert_eq!(parsed.payload, b"abcd");
    }

    #[test]
    fn echo_reply_checksum_is_valid_and_type_correct() {
        let req = build_echo_request(OUR_MAC, GW_MAC, OUR_IP, GW_IP, 1, 1, b"ping");
        assert_eq!(req[14 + 20], ICMP_ECHO_REQUEST);
        assert_eq!(checksum(&req[14 + 20..]), 0);
        assert_eq!(checksum(&req[14..14 + 20]), 0);
    }

    #[test]
    fn truncated_arp_reply_is_ignored() {
        assert_eq!(parse_arp_reply(&[0u8; 10], GW_IP), None);
    }

    #[test]
    fn truncated_echo_reply_is_ignored() {
        assert_eq!(parse_echo_reply(&[0u8; 10]), None);
    }
}
