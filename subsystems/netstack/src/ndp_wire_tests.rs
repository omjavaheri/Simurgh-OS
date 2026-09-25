//! Host tests for `ndp_wire.rs`: builders round-trip through the parsers, the
//! checksums are verified by smoltcp's own implementation, and malformed
//! input is rejected without panicking.

extern crate std;

use super::*;
use std::vec::Vec;

const MAC_A: Mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const MAC_R: Mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

fn ll(iid: u8) -> Ip6 {
    let mut a = [0u8; 16];
    a[0] = 0xfe;
    a[1] = 0x80;
    a[15] = iid;
    a
}

fn global(prefix_byte: u8, iid: u8) -> Ip6 {
    let mut a = [0u8; 16];
    a[0] = 0x20;
    a[1] = 0x01;
    a[2] = prefix_byte;
    a[15] = iid;
    a
}

#[test]
fn solicited_node_and_multicast_mac() {
    let a = [0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55];
    let s = solicited_node(&a);
    assert_eq!(s, [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x33, 0x44, 0x55]);
    assert_eq!(multicast_mac(&s), [0x33, 0x33, 0xff, 0x33, 0x44, 0x55]);
    assert!(is_multicast(&s) && !is_multicast(&a));
    assert!(is_link_local(&ll(1)) && !is_link_local(&a));
    assert!(is_link_local(&[0xfe, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
    assert!(!is_link_local(&[0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])); // fec0::/10 is site-local
}

#[test]
fn eui64_matches_rfc4291_example() {
    // RFC 4291 appendix A: 34-56-78-9A-BC-DE -> 3656:78FF:FE9A:BCDE.
    assert_eq!(eui64_iid(&[0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]), [0x36, 0x56, 0x78, 0xff, 0xfe, 0x9a, 0xbc, 0xde]);
    assert_eq!(eui64_iid(&MAC_A), [0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56]);
}

#[test]
fn prefix_matching_handles_partial_bytes() {
    let a = global(0x12, 1);
    let mut b = a;
    b[15] = 99;
    assert!(prefix_matches(&a, &b, 64));
    b[7] ^= 0x01;
    assert!(!prefix_matches(&a, &b, 64));
    assert!(prefix_matches(&a, &b, 56));
    let mut c = a;
    c[2] ^= 0x10; // bit 20 differs
    assert!(prefix_matches(&a, &c, 19) && !prefix_matches(&a, &c, 20));
    assert!(prefix_matches(&a, &c, 0));
}

#[test]
fn ns_round_trips_with_source_link_layer_option() {
    let mut buf = [0u8; MAX_ND_FRAME];
    let src = ll(0x56);
    let target = ll(0x99);
    let n = build_ns(&mut buf, &MAC_A, &src, &target).unwrap();
    assert_eq!(n, ETH_LEN + IP6_LEN + 32);
    // Destination: solicited-node multicast and its Ethernet form.
    assert_eq!(&buf[0..6], &multicast_mac(&solicited_node(&target)));
    let m = parse_icmp6(&buf[..n]).expect("valid checksum");
    assert_eq!(m.src, src);
    assert_eq!(m.dst, solicited_node(&target));
    assert_eq!(m.hop, 255);
    assert_eq!(m.src_mac, MAC_A);
    let nd = parse_ns_na(m.msg).unwrap();
    assert_eq!(nd.target, target);
    assert_eq!(nd.lladdr, Some(MAC_A));
}

#[test]
fn dad_ns_from_unspecified_has_no_link_layer_option() {
    let mut buf = [0u8; MAX_ND_FRAME];
    let target = ll(0x56);
    let n = build_ns(&mut buf, &MAC_A, &UNSPECIFIED, &target).unwrap();
    assert_eq!(n, ETH_LEN + IP6_LEN + 24);
    let m = parse_icmp6(&buf[..n]).unwrap();
    assert_eq!(m.src, UNSPECIFIED);
    let nd = parse_ns_na(m.msg).unwrap();
    assert_eq!((nd.target, nd.lladdr), (target, None));
}

#[test]
fn na_flags_and_target_option_round_trip() {
    let mut buf = [0u8; MAX_ND_FRAME];
    let flags = NaFlags { router: true, solicited: true, override_: false };
    let n = build_na(&mut buf, &MAC_R, &MAC_A, &ll(2), &ll(0x56), &ll(2), flags, Some(&MAC_R)).unwrap();
    let m = parse_icmp6(&buf[..n]).unwrap();
    let nd = parse_ns_na(m.msg).unwrap();
    assert_eq!(nd.flags, flags);
    assert_eq!(nd.lladdr, Some(MAC_R));
    assert_eq!(nd.target, ll(2));
    let flags2 = NaFlags { router: false, solicited: false, override_: true };
    let n = build_na(&mut buf, &MAC_R, &[0x33, 0x33, 0, 0, 0, 1], &ll(2), &ALL_NODES, &ll(2), flags2, None).unwrap();
    let nd = parse_ns_na(parse_icmp6(&buf[..n]).unwrap().msg).unwrap();
    assert_eq!((nd.flags, nd.lladdr), (flags2, None));
}

#[test]
fn rs_goes_to_all_routers() {
    let mut buf = [0u8; MAX_ND_FRAME];
    let n = build_rs(&mut buf, &MAC_A, &ll(0x56)).unwrap();
    assert_eq!(&buf[0..6], &[0x33, 0x33, 0, 0, 0, 2]);
    let m = parse_icmp6(&buf[..n]).unwrap();
    assert_eq!((m.dst, m.hop, m.msg[0]), (ALL_ROUTERS, 255, icmp6::ROUTER_SOLICIT));
    assert_eq!(m.msg.len(), 16); // with the source link-layer option
    let n = build_rs(&mut buf, &MAC_A, &UNSPECIFIED).unwrap();
    assert_eq!(parse_icmp6(&buf[..n]).unwrap().msg.len(), 8); // without
}

#[test]
fn builders_refuse_small_buffers() {
    let mut tiny = [0u8; 20];
    assert!(build_ns(&mut tiny, &MAC_A, &ll(1), &ll(2)).is_none());
    assert!(build_rs(&mut tiny, &MAC_A, &ll(1)).is_none());
}

#[test]
fn ra_with_two_prefixes_rdnss_and_flags() {
    let p1 = PrefixInfo { prefix_len: 64, on_link: true, autonomous: true, valid_s: 86400, preferred_s: 14400, prefix: global(0x11, 0) };
    let p2 = PrefixInfo { prefix_len: 64, on_link: true, autonomous: false, valid_s: 3600, preferred_s: 1800, prefix: global(0x22, 0) };
    let dns = [global(0x11, 3), global(0x11, 4)];
    let mut buf = [0u8; 512];
    let n = build_ra(&mut buf, &MAC_R, &ll(2), &ALL_NODES, &[0x33, 0x33, 0, 0, 0, 1], true, true, 1800, &[p1, p2], &dns, 600)
        .unwrap();
    let m = parse_icmp6(&buf[..n]).unwrap();
    assert_eq!(m.hop, 255);
    let ra = parse_ra(m.msg).unwrap();
    assert!(ra.managed && ra.other);
    assert_eq!((ra.router_lifetime_s, ra.cur_hop_limit), (1800, 64));
    let opts: Vec<_> = NdOptions::new(ra.options).collect();
    assert_eq!(opts.len(), 4);
    assert_eq!(opts[0], NdOption::LinkLayer { kind: 1, mac: MAC_R });
    assert_eq!(opts[1], NdOption::Prefix(p1));
    assert_eq!(opts[2], NdOption::Prefix(p2));
    match opts[3] {
        NdOption::Rdnss { lifetime_s, addrs } => {
            assert_eq!(lifetime_s, 600);
            assert_eq!(addrs.len(), 32);
            assert_eq!(&addrs[..16], &dns[0]);
            assert_eq!(&addrs[16..], &dns[1]);
        }
        other => panic!("expected RDNSS, got {other:?}"),
    }
}

#[test]
fn ra_flags_off_and_short_message() {
    let mut buf = [0u8; 512];
    let n = build_ra(&mut buf, &MAC_R, &ll(2), &ALL_NODES, &[0x33, 0x33, 0, 0, 0, 1], false, false, 0, &[], &[], 0).unwrap();
    let ra = parse_ra(parse_icmp6(&buf[..n]).unwrap().msg).unwrap();
    assert!(!ra.managed && !ra.other);
    assert_eq!(ra.router_lifetime_s, 0);
    assert!(parse_ra(&[134, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none()); // 15 bytes
    assert!(parse_ra(&[135; 16]).is_none()); // wrong type
    let mut bad_code = [0u8; 16];
    bad_code[0] = 134;
    bad_code[1] = 1;
    assert!(parse_ra(&bad_code).is_none());
}

#[test]
fn malformed_options_are_flagged() {
    // Zero-length option.
    let v: Vec<_> = NdOptions::new(&[1, 0, 0, 0, 0, 0, 0, 0]).collect();
    assert_eq!(v, std::vec![NdOption::Malformed]);
    // Option longer than the buffer.
    let v: Vec<_> = NdOptions::new(&[3, 4, 64, 0xc0, 0, 0, 0, 0]).collect();
    assert_eq!(v, std::vec![NdOption::Malformed]);
    // A trailing single byte.
    let v: Vec<_> = NdOptions::new(&[1]).collect();
    assert_eq!(v, std::vec![NdOption::Malformed]);
    // An NS with a malformed option is discarded as a whole.
    let mut msg = [0u8; 32];
    msg[0] = icmp6::NEIGHBOR_SOLICIT;
    msg[8] = 0x20;
    msg[24] = 1;
    msg[25] = 0;
    assert!(parse_ns_na(&msg).is_none());
    // Unknown option types are tolerated.
    let v: Vec<_> = NdOptions::new(&[99, 1, 0, 0, 0, 0, 0, 0]).collect();
    assert_eq!(v, std::vec![NdOption::Other(99)]);
}

#[test]
fn ns_na_validation_rules() {
    let mut msg = [0u8; 24];
    msg[0] = icmp6::NEIGHBOR_SOLICIT;
    msg[8] = 0xff; // multicast target is invalid
    assert!(parse_ns_na(&msg).is_none());
    msg[8] = 0x20;
    assert!(parse_ns_na(&msg).is_some());
    msg[1] = 1; // code must be zero
    assert!(parse_ns_na(&msg).is_none());
    msg[1] = 0;
    msg[0] = 200;
    assert!(parse_ns_na(&msg).is_none());
    assert!(parse_ns_na(&msg[..23]).is_none());
}

#[test]
fn corrupt_frames_are_rejected() {
    let mut buf = [0u8; MAX_ND_FRAME];
    let n = build_ns(&mut buf, &MAC_A, &ll(1), &ll(2)).unwrap();
    assert!(parse_icmp6(&buf[..n]).is_some());
    // Flipped payload bit -> checksum failure.
    let mut bad = buf;
    bad[n - 1] ^= 0x01;
    assert!(parse_icmp6(&bad[..n]).is_none());
    // Truncated.
    assert!(parse_icmp6(&buf[..n - 1]).is_none());
    assert!(parse_icmp6(&buf[..10]).is_none());
    // IPv4 ethertype.
    let mut v4 = buf;
    v4[12] = 0x08;
    v4[13] = 0x00;
    assert!(parse_icmp6(&v4[..n]).is_none());
    // Extension header (next header != 58) is not parsed by this fast path.
    let mut ext = buf;
    ext[ETH_LEN + 6] = 0;
    assert!(parse_icmp6(&ext[..n]).is_none());
    // Payload length claiming more than is present.
    let mut long = buf;
    long[ETH_LEN + 4] = 0xff;
    assert!(parse_icmp6(&long[..n]).is_none());
}
