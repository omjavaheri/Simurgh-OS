//! ============================================================================
//! ndp_wire.rs
//!
//! Purpose: pure, total frame builders and parsers for IPv6 neighbour
//! discovery (RFC 4861): Router Solicitation, Neighbor Solicitation (including
//! the unspecified-source form used by duplicate address detection), Neighbor
//! Advertisement, and a parser for Router Advertisements with EVERY option
//! (several prefix-information options, RDNSS, MTU, source link-layer
//! address), which smoltcp's own `NdiscRepr` cannot express (it keeps one
//! prefix option and drops RDNSS).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md Section 2.3 (user-
//! space TCP/IP). RFC 4861 (ND), RFC 4862 (SLAAC), RFC 8106 (RDNSS).
//!
//! Position in the system: used by `slaac.rs` (its pure state machine only
//! sees parsed messages) and by `stack.rs` (which puts the frames on the wire
//! and answers ND for loopback). No heap, no syscalls, no `unsafe`.
//!
//! Safety/invariants: every parser is total (`None` on anything malformed,
//! never a panic); every builder returns the frame length and never writes
//! past the buffer it is given (callers pass `MAX_ND_FRAME` bytes).
//! ============================================================================

use smoltcp::wire::{Icmpv6Packet, Ipv6Address};

/// An IPv6 address as 16 network-order bytes.
pub type Ip6 = [u8; 16];
/// An Ethernet address.
pub type Mac = [u8; 6];

/// Ethernet header length.
pub const ETH_LEN: usize = 14;
/// IPv6 header length (no extension headers).
pub const IP6_LEN: usize = 40;
/// Largest ND frame any builder here produces (an NS/NA/RS with options fits
/// in 96 bytes; callers pass a 128-byte buffer).
pub const MAX_ND_FRAME: usize = 128;

/// ICMPv6 message types used here.
pub mod icmp6 {
    /// Echo request.
    pub const ECHO_REQUEST: u8 = 128;
    /// Echo reply.
    pub const ECHO_REPLY: u8 = 129;
    /// Router solicitation.
    pub const ROUTER_SOLICIT: u8 = 133;
    /// Router advertisement.
    pub const ROUTER_ADVERT: u8 = 134;
    /// Neighbor solicitation.
    pub const NEIGHBOR_SOLICIT: u8 = 135;
    /// Neighbor advertisement.
    pub const NEIGHBOR_ADVERT: u8 = 136;
}

/// The unspecified address `::`.
pub const UNSPECIFIED: Ip6 = [0; 16];
/// `::1`.
pub const LOOPBACK: Ip6 = {
    let mut a = [0u8; 16];
    a[15] = 1;
    a
};
/// `ff02::1`, all nodes.
pub const ALL_NODES: Ip6 = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// `ff02::2`, all routers.
pub const ALL_ROUTERS: Ip6 = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

/// `true` for `fe80::/10`.
pub fn is_link_local(a: &Ip6) -> bool {
    a[0] == 0xfe && (a[1] & 0xc0) == 0x80
}

/// `true` for `ff00::/8`.
pub fn is_multicast(a: &Ip6) -> bool {
    a[0] == 0xff
}

/// The solicited-node multicast address `ff02::1:ffXX:XXXX` of `a`.
pub fn solicited_node(a: &Ip6) -> Ip6 {
    let mut m = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 0];
    m[13..16].copy_from_slice(&a[13..16]);
    m
}

/// The Ethernet multicast address `33:33:XX:XX:XX:XX` of an IPv6 multicast
/// address (RFC 2464 section 7).
pub fn multicast_mac(a: &Ip6) -> Mac {
    [0x33, 0x33, a[12], a[13], a[14], a[15]]
}

/// The modified EUI-64 interface identifier of `mac` (RFC 4291 appendix A):
/// insert `ff:fe` in the middle and flip the universal/local bit.
pub fn eui64_iid(mac: &Mac) -> [u8; 8] {
    [mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]]
}

/// `prefix` (first `prefix_len` bits kept, the rest replaced) combined with a
/// 64-bit `iid`; only meaningful for `prefix_len <= 64`.
pub fn addr_from_prefix_iid(prefix: &Ip6, iid: &[u8; 8]) -> Ip6 {
    let mut a = [0u8; 16];
    a[..8].copy_from_slice(&prefix[..8]);
    a[8..].copy_from_slice(iid);
    a
}

/// `true` when the first `len` bits of `a` and `b` agree.
pub fn prefix_matches(a: &Ip6, b: &Ip6, len: u8) -> bool {
    let len = len.min(128) as usize;
    let full = len / 8;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = len % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/// Writes Ethernet + IPv6 headers and the ICMPv6 message `icmp` (checksum
/// filled in) into `buf`; returns the frame length. `hop` is 255 for ND.
/// `None` when `buf` is too small.
pub fn build_icmp6_frame(
    buf: &mut [u8],
    src_mac: &Mac,
    dst_mac: &Mac,
    src_ip: &Ip6,
    dst_ip: &Ip6,
    hop: u8,
    icmp: &[u8],
) -> Option<usize> {
    let total = ETH_LEN + IP6_LEN + icmp.len();
    if buf.len() < total {
        return None;
    }
    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&[0x86, 0xdd]);
    let ip = &mut buf[ETH_LEN..ETH_LEN + IP6_LEN];
    ip[0] = 0x60;
    ip[1..4].fill(0);
    ip[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
    ip[6] = 58; // next header: ICMPv6
    ip[7] = hop;
    ip[8..24].copy_from_slice(src_ip);
    ip[24..40].copy_from_slice(dst_ip);
    let body = &mut buf[ETH_LEN + IP6_LEN..total];
    body.copy_from_slice(icmp);
    let mut pkt = Icmpv6Packet::new_unchecked(&mut body[..]);
    pkt.fill_checksum(&Ipv6Address::from(*src_ip), &Ipv6Address::from(*dst_ip));
    Some(total)
}

/// Neighbor Solicitation for `target`. `src_ip` may be `::` (duplicate
/// address detection): the source link-layer option is then omitted, as RFC
/// 4861 section 7.2.2 requires. Sent to the solicited-node multicast address
/// of `target`.
pub fn build_ns(buf: &mut [u8], src_mac: &Mac, src_ip: &Ip6, target: &Ip6) -> Option<usize> {
    let mut icmp = [0u8; 32];
    icmp[0] = icmp6::NEIGHBOR_SOLICIT;
    icmp[8..24].copy_from_slice(target);
    let mut len = 24;
    if *src_ip != UNSPECIFIED {
        icmp[24] = 1; // option: source link-layer address
        icmp[25] = 1; // length in units of 8 bytes
        icmp[26..32].copy_from_slice(src_mac);
        len = 32;
    }
    let dst_ip = solicited_node(target);
    build_icmp6_frame(buf, src_mac, &multicast_mac(&dst_ip), src_ip, &dst_ip, 255, &icmp[..len])
}

/// Neighbor Advertisement flags (RFC 4861 section 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NaFlags {
    /// R: the sender is a router.
    pub router: bool,
    /// S: sent in response to a solicitation.
    pub solicited: bool,
    /// O: override the cached link-layer address.
    pub override_: bool,
}

/// Neighbor Advertisement for `target` with target link-layer option `tll`.
pub fn build_na(
    buf: &mut [u8],
    src_mac: &Mac,
    dst_mac: &Mac,
    src_ip: &Ip6,
    dst_ip: &Ip6,
    target: &Ip6,
    flags: NaFlags,
    tll: Option<&Mac>,
) -> Option<usize> {
    let mut icmp = [0u8; 32];
    icmp[0] = icmp6::NEIGHBOR_ADVERT;
    icmp[4] = (flags.router as u8) << 7 | (flags.solicited as u8) << 6 | (flags.override_ as u8) << 5;
    icmp[8..24].copy_from_slice(target);
    let mut len = 24;
    if let Some(m) = tll {
        icmp[24] = 2; // option: target link-layer address
        icmp[25] = 1;
        icmp[26..32].copy_from_slice(m);
        len = 32;
    }
    build_icmp6_frame(buf, src_mac, dst_mac, src_ip, dst_ip, 255, &icmp[..len])
}

/// Router Solicitation to `ff02::2`. `src_ip` may be `::` (no source
/// link-layer option then).
pub fn build_rs(buf: &mut [u8], src_mac: &Mac, src_ip: &Ip6) -> Option<usize> {
    let mut icmp = [0u8; 16];
    icmp[0] = icmp6::ROUTER_SOLICIT;
    let mut len = 8;
    if *src_ip != UNSPECIFIED {
        icmp[8] = 1;
        icmp[9] = 1;
        icmp[10..16].copy_from_slice(src_mac);
        len = 16;
    }
    build_icmp6_frame(buf, src_mac, &multicast_mac(&ALL_ROUTERS), src_ip, &ALL_ROUTERS, 255, &icmp[..len])
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// An ICMPv6 message found in an Ethernet frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmp6In<'a> {
    /// Ethernet source address.
    pub src_mac: Mac,
    /// IPv6 source address.
    pub src: Ip6,
    /// IPv6 destination address.
    pub dst: Ip6,
    /// IPv6 hop limit (ND messages must carry 255).
    pub hop: u8,
    /// The ICMPv6 message (type, code, checksum, body).
    pub msg: &'a [u8],
}

/// Extracts the ICMPv6 message of an IPv6 frame with no extension headers
/// and a correct checksum. `None` for anything else.
pub fn parse_icmp6(frame: &[u8]) -> Option<Icmp6In<'_>> {
    if frame.len() < ETH_LEN + IP6_LEN + 4 || frame[12..14] != [0x86, 0xdd] {
        return None;
    }
    let ip = &frame[ETH_LEN..];
    if ip[0] >> 4 != 6 || ip[6] != 58 {
        return None;
    }
    let plen = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    if plen < 4 || IP6_LEN + plen > ip.len() {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&ip[8..24]);
    dst.copy_from_slice(&ip[24..40]);
    let msg = &ip[IP6_LEN..IP6_LEN + plen];
    let pkt = Icmpv6Packet::new_unchecked(msg);
    if !pkt.verify_checksum(&Ipv6Address::from(src), &Ipv6Address::from(dst)) {
        return None;
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    Some(Icmp6In { src_mac, src, dst, hop: ip[7], msg })
}

/// A parsed Neighbor Solicitation or Advertisement body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdTarget {
    /// The target address the message is about.
    pub target: Ip6,
    /// The (source or target) link-layer address option, if present.
    pub lladdr: Option<Mac>,
    /// NA flags (all false for an NS).
    pub flags: NaFlags,
}

/// Parses an NS (type 135) or NA (type 136) ICMPv6 message; validates code 0
/// and that the target is not multicast (RFC 4861 sections 7.1.1, 7.1.2).
pub fn parse_ns_na(msg: &[u8]) -> Option<NdTarget> {
    if msg.len() < 24 || msg[1] != 0 || !(msg[0] == icmp6::NEIGHBOR_SOLICIT || msg[0] == icmp6::NEIGHBOR_ADVERT) {
        return None;
    }
    let mut target = [0u8; 16];
    target.copy_from_slice(&msg[8..24]);
    if is_multicast(&target) {
        return None;
    }
    let want = if msg[0] == icmp6::NEIGHBOR_SOLICIT { 1 } else { 2 };
    let mut lladdr = None;
    for opt in NdOptions::new(&msg[24..]) {
        match opt {
            NdOption::Malformed => return None,
            NdOption::LinkLayer { kind, mac } if kind == want => lladdr = Some(mac),
            _ => {}
        }
    }
    let flags = if msg[0] == icmp6::NEIGHBOR_ADVERT {
        NaFlags { router: msg[4] & 0x80 != 0, solicited: msg[4] & 0x40 != 0, override_: msg[4] & 0x20 != 0 }
    } else {
        NaFlags::default()
    };
    Some(NdTarget { target, lladdr, flags })
}

/// One prefix-information option (RFC 4861 section 4.6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInfo {
    /// Prefix length in bits.
    pub prefix_len: u8,
    /// L flag: the prefix is on-link.
    pub on_link: bool,
    /// A flag: the prefix may be used for autonomous address configuration.
    pub autonomous: bool,
    /// Valid lifetime in seconds (`u32::MAX` = infinite).
    pub valid_s: u32,
    /// Preferred lifetime in seconds (`u32::MAX` = infinite).
    pub preferred_s: u32,
    /// The prefix.
    pub prefix: Ip6,
}

/// One option of an ND message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdOption<'a> {
    /// Source (1) or target (2) link-layer address, Ethernet form.
    LinkLayer {
        /// Option type (1 or 2).
        kind: u8,
        /// The address.
        mac: Mac,
    },
    /// Prefix information.
    Prefix(PrefixInfo),
    /// MTU option.
    Mtu(u32),
    /// Recursive DNS server option (RFC 8106): lifetime and the packed
    /// 16-byte addresses.
    Rdnss {
        /// Seconds the servers stay valid (0 = withdraw).
        lifetime_s: u32,
        /// `n * 16` bytes of addresses.
        addrs: &'a [u8],
    },
    /// Any other well-formed option (route information, DNSSL, ...).
    Other(u8),
    /// A structurally invalid option (zero length or running past the end):
    /// RFC 4861 says the whole message is silently discarded.
    Malformed,
}

/// Iterator over the options of an ND message body.
pub struct NdOptions<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> NdOptions<'a> {
    /// Options start at `body[0]`.
    pub fn new(body: &'a [u8]) -> Self {
        Self { rest: body, done: false }
    }
}

impl<'a> Iterator for NdOptions<'a> {
    type Item = NdOption<'a>;

    fn next(&mut self) -> Option<NdOption<'a>> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        if self.rest.len() < 2 {
            self.done = true;
            return Some(NdOption::Malformed);
        }
        let kind = self.rest[0];
        let len = self.rest[1] as usize * 8;
        if len == 0 || len > self.rest.len() {
            self.done = true;
            return Some(NdOption::Malformed);
        }
        let opt = &self.rest[..len];
        self.rest = &self.rest[len..];
        Some(match kind {
            1 | 2 if len == 8 => {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&opt[2..8]);
                NdOption::LinkLayer { kind, mac }
            }
            3 if len == 32 => {
                let mut prefix = [0u8; 16];
                prefix.copy_from_slice(&opt[16..32]);
                NdOption::Prefix(PrefixInfo {
                    prefix_len: opt[2],
                    on_link: opt[3] & 0x80 != 0,
                    autonomous: opt[3] & 0x40 != 0,
                    valid_s: u32::from_be_bytes([opt[4], opt[5], opt[6], opt[7]]),
                    preferred_s: u32::from_be_bytes([opt[8], opt[9], opt[10], opt[11]]),
                    prefix,
                })
            }
            5 if len == 8 => NdOption::Mtu(u32::from_be_bytes([opt[4], opt[5], opt[6], opt[7]])),
            // RDNSS: type 25, length 1 + 2n units, lifetime at 4..8, addresses after.
            25 if len >= 24 && (len - 8) % 16 == 0 => NdOption::Rdnss {
                lifetime_s: u32::from_be_bytes([opt[4], opt[5], opt[6], opt[7]]),
                addrs: &opt[8..],
            },
            // A known type with a wrong length is malformed (RFC 4861 says to
            // ignore just that option for prefix/MTU; treating it as Other is
            // the lenient, safe reading).
            _ => NdOption::Other(kind),
        })
    }
}

/// A parsed Router Advertisement header (RFC 4861 section 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaHeader<'a> {
    /// Suggested hop limit (0 = unspecified).
    pub cur_hop_limit: u8,
    /// M flag: addresses are available through DHCPv6.
    pub managed: bool,
    /// O flag: other configuration (DNS...) is available through DHCPv6.
    pub other: bool,
    /// Seconds the sender is usable as a default router (0 = not a default router).
    pub router_lifetime_s: u16,
    /// Reachable time, ms (0 = unspecified).
    pub reachable_ms: u32,
    /// Retransmission timer, ms (0 = unspecified).
    pub retrans_ms: u32,
    /// The option bytes (iterate with `NdOptions`).
    pub options: &'a [u8],
}

/// Parses a Router Advertisement message (type 134, code 0, at least the
/// 16-byte fixed part).
pub fn parse_ra(msg: &[u8]) -> Option<RaHeader<'_>> {
    if msg.len() < 16 || msg[0] != icmp6::ROUTER_ADVERT || msg[1] != 0 {
        return None;
    }
    Some(RaHeader {
        cur_hop_limit: msg[4],
        managed: msg[5] & 0x80 != 0,
        other: msg[5] & 0x40 != 0,
        router_lifetime_s: u16::from_be_bytes([msg[6], msg[7]]),
        reachable_ms: u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]),
        retrans_ms: u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]),
        options: &msg[16..],
    })
}

/// Builds a Router Advertisement (used by host tests as the mock router and
/// by nothing else in the image). `prefixes` are emitted as prefix-info
/// options, `rdnss` as one RDNSS option with `rdnss_lifetime_s`.
pub fn build_ra(
    buf: &mut [u8],
    router_mac: &Mac,
    router_ll: &Ip6,
    dst_ip: &Ip6,
    dst_mac: &Mac,
    managed: bool,
    other: bool,
    router_lifetime_s: u16,
    prefixes: &[PrefixInfo],
    rdnss: &[Ip6],
    rdnss_lifetime_s: u32,
) -> Option<usize> {
    let mut icmp = [0u8; 256];
    icmp[0] = icmp6::ROUTER_ADVERT;
    icmp[4] = 64;
    icmp[5] = (managed as u8) << 7 | (other as u8) << 6;
    icmp[6..8].copy_from_slice(&router_lifetime_s.to_be_bytes());
    let mut n = 16;
    icmp[n] = 1;
    icmp[n + 1] = 1;
    icmp[n + 2..n + 8].copy_from_slice(router_mac);
    n += 8;
    for p in prefixes {
        icmp[n] = 3;
        icmp[n + 1] = 4;
        icmp[n + 2] = p.prefix_len;
        icmp[n + 3] = (p.on_link as u8) << 7 | (p.autonomous as u8) << 6;
        icmp[n + 4..n + 8].copy_from_slice(&p.valid_s.to_be_bytes());
        icmp[n + 8..n + 12].copy_from_slice(&p.preferred_s.to_be_bytes());
        icmp[n + 16..n + 32].copy_from_slice(&p.prefix);
        n += 32;
    }
    if !rdnss.is_empty() {
        let units = 1 + 2 * rdnss.len();
        icmp[n] = 25;
        icmp[n + 1] = units as u8;
        icmp[n + 4..n + 8].copy_from_slice(&rdnss_lifetime_s.to_be_bytes());
        for (i, a) in rdnss.iter().enumerate() {
            icmp[n + 8 + 16 * i..n + 24 + 16 * i].copy_from_slice(a);
        }
        n += units * 8;
    }
    build_icmp6_frame(buf, router_mac, dst_mac, router_ll, dst_ip, 255, &icmp[..n])
}

#[cfg(test)]
#[path = "ndp_wire_tests.rs"]
mod tests;
