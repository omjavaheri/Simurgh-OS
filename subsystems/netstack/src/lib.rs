//! ============================================================================
//! netstack
//!
//! Purpose: the user-space network stack. The MVP acceptance target is a
//! single ICMP echo round-trip over virtio-net on QEMU
//! (03-Kernel-Subsystems-Layer.md §5.4). This crate provides the packet
//! parsing/building needed for that — Ethernet + IPv4 + ICMP — as pure,
//! testable functions; the virtio-net driver binding and the socket API
//! are layered on top.
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
}
