//! ============================================================================
//! netstack::status
//!
//! Purpose: the compact, read-only network status record Netstack publishes
//! for the desktop (ui-core) and the pure encode/decode of it. Layout is
//! documented in `docs/internet-plan.md` (section "Network status page").
//!
//! Position in the system: pure logic, no `unsafe`. `subsystem_entry` owns
//! the one shared page and calls [`write_record`]; ui-core has its own
//! mirror of [`decode`] (separate repository, same byte contract).
//!
//! Safety/invariants: the page is a seqlock. The writer makes `seq` odd,
//! writes the fields, then makes it even again; a reader accepts a copy only
//! if `seq` was even and unchanged around the copy. `generation` (`seq / 2`)
//! changes on every published update, so a reader can poll it cheaply.
//! ============================================================================

/// Little-endian u64 at offset 0: ASCII "SIMNET" + layout version 1.
pub const NET_STATUS_MAGIC: u64 = 0x5349_4D4E_4554_0001;
/// Bytes of the record (the mapped page is 4096, the rest is zero).
pub const NET_STATUS_LEN: usize = 48;

/// Offsets inside the page.
pub mod off {
    /// u64 magic.
    pub const MAGIC: usize = 0;
    /// u32 seqlock counter (odd while the writer is inside).
    pub const SEQ: usize = 8;
    /// u8 flags, see `FLAG_*`.
    pub const FLAGS: usize = 12;
    /// u8 connection state, see [`super::ConnState`].
    pub const STATE: usize = 13;
    /// u8 adapter kind, see [`super::AdapterKind`].
    pub const KIND: usize = 14;
    /// u8 prefix length of the IPv4 address.
    pub const PREFIX: usize = 15;
    /// 4 bytes IPv4 address.
    pub const IP: usize = 16;
    /// 4 bytes gateway.
    pub const GATEWAY: usize = 20;
    /// 4 bytes DNS server.
    pub const DNS: usize = 24;
    /// 6 bytes MAC.
    pub const MAC: usize = 28;
}

/// Flag bit 0: an adapter is present.
pub const FLAG_ADAPTER: u8 = 1;
/// Flag bit 1: the link is up.
pub const FLAG_LINK_UP: u8 = 2;
/// Flag bit 2: `ip`/`prefix` are valid.
pub const FLAG_HAS_IP: u8 = 4;
/// Flag bit 3: `gateway` is valid.
pub const FLAG_HAS_GATEWAY: u8 = 8;
/// Flag bit 4: `dns` is valid.
pub const FLAG_HAS_DNS: u8 = 16;

/// What the user should see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// No adapter.
    NoAdapter = 0,
    /// Adapter present, no link (cable/Wi-Fi down).
    Disconnected = 1,
    /// Link up, no address yet (DHCP running / retrying).
    Connecting = 2,
    /// Link up and an address is configured.
    Connected = 3,
}

impl ConnState {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::NoAdapter,
            1 => Self::Disconnected,
            2 => Self::Connecting,
            3 => Self::Connected,
            _ => return None,
        })
    }
}

/// Kind of adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterKind {
    /// Unknown / none.
    None = 0,
    /// Wired Ethernet (virtio-net today).
    Ethernet = 1,
    /// Wi-Fi (no hardware support yet).
    Wifi = 2,
}

impl AdapterKind {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::Ethernet,
            2 => Self::Wifi,
            _ => return None,
        })
    }
}

/// The published status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetStatus {
    /// Adapter present.
    pub adapter: bool,
    /// Link up.
    pub link_up: bool,
    /// State shown to the user.
    pub state: ConnState,
    /// Adapter kind.
    pub kind: AdapterKind,
    /// IPv4 address and prefix length, when configured.
    pub ip: Option<([u8; 4], u8)>,
    /// Default gateway.
    pub gateway: Option<[u8; 4]>,
    /// DNS server.
    pub dns: Option<[u8; 4]>,
    /// Adapter MAC.
    pub mac: [u8; 6],
}

impl NetStatus {
    /// Status of a machine with no adapter.
    pub const NONE: NetStatus = NetStatus {
        adapter: false,
        link_up: false,
        state: ConnState::NoAdapter,
        kind: AdapterKind::None,
        ip: None,
        gateway: None,
        dns: None,
        mac: [0; 6],
    };
}

/// Serialises `s` into `page` (at least [`NET_STATUS_LEN`] bytes) with
/// seqlock value `seq_even` (the even value to end on; the caller bumps
/// it by 2 each publish and writes an odd value first while a concurrent
/// reader could look). Pure: fills a byte array, `subsystem_entry` copies it
/// into the shared page.
pub fn encode(s: &NetStatus, seq_even: u32, out: &mut [u8; NET_STATUS_LEN]) {
    let mut flags = 0u8;
    if s.adapter {
        flags |= FLAG_ADAPTER;
    }
    if s.link_up {
        flags |= FLAG_LINK_UP;
    }
    out[off::MAGIC..off::MAGIC + 8].copy_from_slice(&NET_STATUS_MAGIC.to_le_bytes());
    out[off::SEQ..off::SEQ + 4].copy_from_slice(&seq_even.to_le_bytes());
    out[off::STATE] = s.state as u8;
    out[off::KIND] = s.kind as u8;
    out[off::PREFIX] = 0;
    out[off::IP..off::IP + 12].fill(0);
    if let Some((ip, prefix)) = s.ip {
        flags |= FLAG_HAS_IP;
        out[off::PREFIX] = prefix;
        out[off::IP..off::IP + 4].copy_from_slice(&ip);
    }
    if let Some(g) = s.gateway {
        flags |= FLAG_HAS_GATEWAY;
        out[off::GATEWAY..off::GATEWAY + 4].copy_from_slice(&g);
    }
    if let Some(d) = s.dns {
        flags |= FLAG_HAS_DNS;
        out[off::DNS..off::DNS + 4].copy_from_slice(&d);
    }
    out[off::FLAGS] = flags;
    out[off::MAC..off::MAC + 6].copy_from_slice(&s.mac);
    out[off::MAC + 6..].fill(0);
}

/// Decodes a page copy. Returns `(status, generation)` or `None` for a bad
/// magic, a torn (odd `seq`) copy, or an unknown state/kind byte.
pub fn decode(page: &[u8]) -> Option<(NetStatus, u32)> {
    if page.len() < NET_STATUS_LEN {
        return None;
    }
    if u64::from_le_bytes(page[0..8].try_into().ok()?) != NET_STATUS_MAGIC {
        return None;
    }
    let seq = u32::from_le_bytes(page[off::SEQ..off::SEQ + 4].try_into().ok()?);
    if seq & 1 != 0 {
        return None;
    }
    let flags = page[off::FLAGS];
    let a4 = |o: usize| [page[o], page[o + 1], page[o + 2], page[o + 3]];
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&page[off::MAC..off::MAC + 6]);
    Some((
        NetStatus {
            adapter: flags & FLAG_ADAPTER != 0,
            link_up: flags & FLAG_LINK_UP != 0,
            state: ConnState::from_u8(page[off::STATE])?,
            kind: AdapterKind::from_u8(page[off::KIND])?,
            ip: (flags & FLAG_HAS_IP != 0).then(|| (a4(off::IP), page[off::PREFIX])),
            gateway: (flags & FLAG_HAS_GATEWAY != 0).then(|| a4(off::GATEWAY)),
            dns: (flags & FLAG_HAS_DNS != 0).then(|| a4(off::DNS)),
            mac,
        },
        seq / 2,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NetStatus {
        NetStatus {
            adapter: true,
            link_up: true,
            state: ConnState::Connected,
            kind: AdapterKind::Ethernet,
            ip: Some(([10, 0, 2, 15], 24)),
            gateway: Some([10, 0, 2, 2]),
            dns: Some([10, 0, 2, 3]),
            mac: [0x52, 0x54, 0, 0x12, 0x34, 0x56],
        }
    }

    #[test]
    fn roundtrip_connected() {
        let mut b = [0u8; NET_STATUS_LEN];
        encode(&sample(), 8, &mut b);
        assert_eq!(decode(&b), Some((sample(), 4)));
    }

    #[test]
    fn roundtrip_disconnected_has_no_addresses() {
        let s = NetStatus { link_up: false, state: ConnState::Disconnected, ip: None, gateway: None, dns: None, ..sample() };
        let mut b = [0xFFu8; NET_STATUS_LEN];
        encode(&s, 2, &mut b);
        assert_eq!(decode(&b), Some((s, 1)));
    }

    #[test]
    fn none_status_roundtrips() {
        let mut b = [0u8; NET_STATUS_LEN];
        encode(&NetStatus::NONE, 2, &mut b);
        assert_eq!(decode(&b).unwrap().0, NetStatus::NONE);
    }

    #[test]
    fn rejects_bad_magic_torn_and_unknown_bytes() {
        let mut b = [0u8; NET_STATUS_LEN];
        assert_eq!(decode(&b), None);
        encode(&sample(), 4, &mut b);
        b[off::SEQ] |= 1;
        assert_eq!(decode(&b), None, "odd seq = writer inside");
        encode(&sample(), 4, &mut b);
        b[off::STATE] = 9;
        assert_eq!(decode(&b), None);
        encode(&sample(), 4, &mut b);
        b[off::KIND] = 9;
        assert_eq!(decode(&b), None);
        assert_eq!(decode(&b[..10]), None);
    }

    #[test]
    fn byte_layout_is_stable() {
        let mut b = [0u8; NET_STATUS_LEN];
        encode(&sample(), 6, &mut b);
        assert_eq!(&b[0..8], &0x5349_4D4E_4554_0001u64.to_le_bytes());
        assert_eq!(&b[8..12], &6u32.to_le_bytes());
        assert_eq!(b[12], 1 | 2 | 4 | 8 | 16);
        assert_eq!(b[13], 3);
        assert_eq!(b[14], 1);
        assert_eq!(b[15], 24);
        assert_eq!(&b[16..20], &[10, 0, 2, 15]);
        assert_eq!(&b[20..24], &[10, 0, 2, 2]);
        assert_eq!(&b[24..28], &[10, 0, 2, 3]);
        assert_eq!(&b[28..34], &[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    }
}
