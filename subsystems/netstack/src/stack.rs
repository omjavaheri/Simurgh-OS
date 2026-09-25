//! ============================================================================
//! stack.rs
//!
//! Purpose: the stateful half of Netstack - a TCP/IP stack built on the
//! `smoltcp` crate (`no_std`, no heap) instead of hand-written protocol
//! state machines. This file is the glue between three things: a frame
//! transport (`FrameIo`, implemented over the driver-virtio-net IPC in the
//! process image and by a mock in host tests), smoltcp's `Interface` (ARP
//! cache with retry, IPv4 rx/tx, routing, ICMP echo both directions), and
//! the small event/poll API the Netstack service loop drives.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md Section 2.3
//! (user-space TCP/IP, "smoltcp-inspired") and Section 5.4 (ICMP echo MVP).
//! The stack strategy (smoltcp instead of a hand-written stack) is the
//! owner's decision of 2026-09-25, recorded in `docs/internet-plan.md`
//! (TODO(spec) 1, resolved).
//!
//! Position in the system: used by `subsystem_entry::service_main` (the
//! persistent Netstack service thread) and by host tests. Everything here is
//! architecture-independent; no `cfg(target_arch)` and no syscalls.
//!
//! Safety/invariants: no `unsafe`. No heap: every buffer lives in the
//! caller-supplied `StackStorage`, which must be `'static` because smoltcp's
//! `SocketSet` borrows from it for the lifetime of the stack.
//! ============================================================================

use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dhcpv4, dns, icmp, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    DnsQueryType, EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, IpEndpoint,
    Ipv4Address,
};

use crate::ndp_wire::{self, Ip6, Mac};
use crate::sockets::{
    SocketTable, ICMP_BUF, ICMP_PACKETS, ICMP_SOCKETS, TCP_RX_BUF, TCP_SOCKETS, TCP_TX_BUF, UDP_BUF, UDP_PACKETS,
    UDP_SOCKETS,
};

/// Largest Ethernet frame the driver's buffers hold
/// (`driver_virtio_net::FRAME_MAX`; must stay numerically equal). It is also
/// the interface MTU as smoltcp counts it for Ethernet (frame size including
/// the 14-byte header), so no frame this stack builds can overflow a driver
/// buffer. 1514 = the standard 1500-byte MTU + Ethernet header; the driver has
/// 16-slot queues of these (the old 700-byte / 2-slot MVP limit is gone).
pub const MAX_FRAME: usize = 1514;

/// First DHCP restart delay while the link is up but there is no lease
/// (smoltcp also retransmits DISCOVER by itself); doubles up to the cap.
pub const DHCP_RESTART_FIRST_NS: u64 = 8_000_000_000;
/// Upper bound of the DHCP restart backoff.
pub const DHCP_RESTART_MAX_NS: u64 = 60_000_000_000;

/// How long an echo request may stay unanswered before `PingTimeout` fires.
pub const PING_TIMEOUT_MS: i64 = 1_000;

/// ICMP identifier every echo request from this stack carries. One
/// requester per stack today; the socket layer's raw-ICMP sockets use their
/// own identifiers and cannot bind this one.
pub const PING_IDENT: u16 = 0x5151;

/// Payload every echo request carries (visible in packet captures).
const PING_PAYLOAD: &[u8] = b"simurgh-ping";

// ---------------------------------------------------------------------------
// Frame transport
// ---------------------------------------------------------------------------

/// A source and sink of raw Ethernet frames - the whole contract between the
/// stack and a NIC driver. Deliberately tiny (it mirrors the driver's
/// `SendFrame`/`PollFrame` IPC pair) so every NIC driver added later (Phase
/// 5: e1000, rtl8139) plugs in the same way.
pub trait FrameIo {
    /// Copies one received frame into `buf` and returns its length, or `None`
    /// when nothing is waiting. Must not block: the kernel has no
    /// wait-with-timeout for NIC RX (see `driver-virtio-net`'s module doc).
    fn recv_frame(&mut self, buf: &mut [u8]) -> Option<usize>;
    /// Transmits one frame (at most `MAX_FRAME` bytes). `false` when the
    /// driver refused it; the stack treats that as a lost packet and relies
    /// on protocol retransmission (ARP retry, DHCP/DNS retry, TCP, ...).
    fn send_frame(&mut self, frame: &[u8]) -> bool;
}

/// A fixed ring of whole frames (no heap): the loopback queue and the
/// control-plane tap.
pub struct FrameQueue<const N: usize> {
    data: [[u8; MAX_FRAME]; N],
    lens: [u16; N],
    head: usize,
    count: usize,
}

impl<const N: usize> FrameQueue<N> {
    /// An empty queue (all zero bytes, so it can live in `.bss`).
    pub const fn new() -> Self {
        Self { data: [[0; MAX_FRAME]; N], lens: [0; N], head: 0, count: 0 }
    }

    /// Appends a copy of `frame`; `false` (frame dropped) when full or too big.
    pub fn push(&mut self, frame: &[u8]) -> bool {
        if self.count == N || frame.len() > MAX_FRAME {
            return false;
        }
        let i = (self.head + self.count) % N;
        self.data[i][..frame.len()].copy_from_slice(frame);
        self.lens[i] = frame.len() as u16;
        self.count += 1;
        true
    }

    /// Removes the oldest frame into `buf`, returning its length.
    pub fn pop_into(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let n = (self.lens[self.head] as usize).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.head][..n]);
        self.head = (self.head + 1) % N;
        self.count -= 1;
        Some(n)
    }

    /// Frames queued.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` when nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl<const N: usize> Default for FrameQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// IPv6 addresses the interface can hold besides the two loopbacks and the
/// IPv4 address (8 interface slots in total).
pub const V6_ADDRS: usize = 5;

/// Most `iface.poll` rounds one `NetStack::poll` runs to settle loopback traffic.
pub const LOOP_ROUNDS: usize = 16;

/// Loopback frames waiting to be "received" (127.0.0.1, ::1, own addresses).
pub const LOOP_QUEUE: usize = 16;

/// How often the loopback neighbour entries are re-seeded (they expire after
/// 60 s in smoltcp).
pub const NEIGHBOR_SEED_INTERVAL_NS: u64 = 20_000_000_000;
/// Control-plane frames (ND, DHCPv6) copied aside for the SLAAC/DHCPv6 state
/// machines.
pub const CTL_QUEUE: usize = 6;

/// Ethernet address the loopback pseudo-neighbour answers with (locally
/// administered, never on the wire).
pub const LOOP_MAC: Mac = [0x02, 0x53, 0x4c, 0x4f, 0x4f, 0x50];

/// The host's own addresses as the device layer needs them to decide what
/// never leaves the machine.
#[derive(Clone, Copy, Default)]
pub struct LocalAddrs {
    /// Our Ethernet address.
    pub mac: Mac,
    /// Configured IPv4 address of the LAN interface.
    pub v4: Option<[u8; 4]>,
    /// Configured IPv6 addresses.
    pub v6: [Option<Ip6>; V6_ADDRS],
}

impl LocalAddrs {
    fn is_local_v4(&self, a: &[u8]) -> bool {
        a[0] == 127 || self.v4.map(|v| v[..] == *a).unwrap_or(false)
    }

    fn is_local_v6(&self, a: &[u8]) -> bool {
        a == ndp_wire::LOOPBACK || self.v6.iter().flatten().any(|v| v[..] == *a)
    }
}

/// What to do with a frame the stack wants to transmit.
enum TxRoute {
    /// Put it on the wire.
    Wire,
    /// Deliver it back to ourselves (destination is one of our addresses).
    Loop,
    /// A neighbour-discovery query about one of our own addresses: answer it
    /// locally with this pre-built reply (length in the second field).
    Answer([u8; ndp_wire::MAX_ND_FRAME], usize),
}

/// Decides whether `frame` (as smoltcp built it) is for the wire, for
/// ourselves, or an ND query we must answer. Loopback needs no special
/// interface in smoltcp 0.12: the single Ethernet interface resolves
/// 127.0.0.1/::1 like any on-link neighbour (ARP/NS), the answer comes from
/// here, and frames addressed to ourselves never touch the driver.
fn route_tx(frame: &[u8], local: &LocalAddrs) -> TxRoute {
    if frame.len() < 14 {
        return TxRoute::Wire;
    }
    match [frame[12], frame[13]] {
        // IPv4
        [0x08, 0x00] if frame.len() >= 34 && frame[14] >> 4 == 4 => {
            if local.is_local_v4(&frame[30..34]) || frame[26] == 127 {
                TxRoute::Loop
            } else {
                TxRoute::Wire
            }
        }
        // ARP request for one of our addresses: we are the neighbour.
        [0x08, 0x06] if frame.len() >= 42 && frame[20..22] == [0, 1] && local.is_local_v4(&frame[38..42]) => {
            let mut r = [0u8; ndp_wire::MAX_ND_FRAME];
            r[0..6].copy_from_slice(&local.mac);
            r[6..12].copy_from_slice(&LOOP_MAC);
            r[12..14].copy_from_slice(&[0x08, 0x06]);
            r[14..20].copy_from_slice(&[0, 1, 8, 0, 6, 4]);
            r[20..22].copy_from_slice(&[0, 2]);
            r[22..28].copy_from_slice(&LOOP_MAC);
            r[28..32].copy_from_slice(&frame[38..42]);
            r[32..38].copy_from_slice(&local.mac);
            r[38..42].copy_from_slice(&frame[28..32]);
            TxRoute::Answer(r, 42)
        }
        // IPv6
        [0x86, 0xdd] if frame.len() >= 54 && frame[14] >> 4 == 6 => {
            let (src, dst) = (&frame[22..38], &frame[38..54]);
            // Neighbor solicitation for one of our own addresses.
            if frame[20] == 58 && frame.len() >= 78 && frame[54] == ndp_wire::icmp6::NEIGHBOR_SOLICIT {
                let target = &frame[62..78];
                if local.is_local_v6(target) && src != ndp_wire::UNSPECIFIED {
                    let mut t = [0u8; 16];
                    t.copy_from_slice(target);
                    let mut asker = [0u8; 16];
                    asker.copy_from_slice(src);
                    let mut r = [0u8; ndp_wire::MAX_ND_FRAME];
                    let flags = ndp_wire::NaFlags { router: false, solicited: true, override_: true };
                    if let Some(n) =
                        ndp_wire::build_na(&mut r, &LOOP_MAC, &local.mac, &t, &asker, &t, flags, Some(&LOOP_MAC))
                    {
                        return TxRoute::Answer(r, n);
                    }
                }
            }
            if dst[0] != 0xff && local.is_local_v6(dst) || local.is_local_v6(src) && src == ndp_wire::LOOPBACK {
                TxRoute::Loop
            } else {
                TxRoute::Wire
            }
        }
        _ => TxRoute::Wire,
    }
}

/// `true` for frames the SLAAC/DHCPv6 machines care about: ICMPv6 router/
/// neighbour discovery messages and UDP to/from the DHCPv6 client port.
fn is_control_frame(frame: &[u8]) -> bool {
    if frame.len() < 14 + 40 + 4 || frame[12..14] != [0x86, 0xdd] {
        return false;
    }
    match frame[20] {
        58 => (133..=137).contains(&frame[54]),
        _ => false,
    }
}

/// smoltcp `Device` adapter over a `FrameIo`.
///
/// `receive` first drains the loopback queue, then pulls at most one frame
/// from the transport into `rx` (one staging buffer: the driver's own RX
/// queue is the queue), copying ND messages aside for the SLAAC machine.
/// `transmit` hands out a token that builds the frame on the stack and routes
/// it (`route_tx`) when consumed.
pub struct FrameDevice<IO: FrameIo> {
    io: IO,
    rx: [u8; MAX_FRAME],
    lo: &'static mut FrameQueue<LOOP_QUEUE>,
    ctl: &'static mut FrameQueue<CTL_QUEUE>,
    local: LocalAddrs,
}

impl<IO: FrameIo> FrameDevice<IO> {
    /// Wraps `io`.
    pub fn new(
        io: IO,
        mac: Mac,
        lo: &'static mut FrameQueue<LOOP_QUEUE>,
        ctl: &'static mut FrameQueue<CTL_QUEUE>,
    ) -> Self {
        Self { io, rx: [0; MAX_FRAME], lo, ctl, local: LocalAddrs { mac, ..LocalAddrs::default() } }
    }

    /// Access to the transport (tests inspect their mock through this).
    pub fn io(&self) -> &IO {
        &self.io
    }

    /// Mutable access to the transport.
    pub fn io_mut(&mut self) -> &mut IO {
        &mut self.io
    }

    /// Tells the device layer which addresses are ours.
    pub fn set_local(&mut self, v4: Option<[u8; 4]>, v6: [Option<Ip6>; V6_ADDRS]) {
        self.local.v4 = v4;
        self.local.v6 = v6;
    }

    /// Loopback frames waiting to be received.
    pub fn loop_pending(&self) -> usize {
        self.lo.len()
    }

    /// Queues a frame to be received as if it had arrived from the wire.
    pub fn inject_loopback(&mut self, frame: &[u8]) {
        let _ = self.lo.push(frame);
    }

    /// Our Ethernet address.
    pub fn mac(&self) -> Mac {
        self.local.mac
    }

    /// Takes the oldest control-plane frame (ND message) into `buf`.
    pub fn take_control(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.ctl.pop_into(buf)
    }

    /// Sends a frame built outside smoltcp (RS, DAD NS) straight to the wire.
    pub fn send_raw(&mut self, frame: &[u8]) -> bool {
        self.io.send_frame(frame)
    }
}

/// One received frame, borrowed from the device's staging buffer.
pub struct FrameRxToken<'a> {
    frame: &'a [u8],
}

impl RxToken for FrameRxToken<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.frame)
    }
}

/// Permission to send exactly one frame.
pub struct FrameTxToken<'a, IO: FrameIo> {
    io: &'a mut IO,
    lo: &'a mut FrameQueue<LOOP_QUEUE>,
    local: &'a LocalAddrs,
}

impl<IO: FrameIo> TxToken for FrameTxToken<'_, IO> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        // Frames larger than the driver buffer cannot happen (the capability
        // report below caps the MTU); clamping keeps a logic error from
        // becoming a stack overflow.
        let len = len.min(MAX_FRAME);
        let mut buf = [0u8; MAX_FRAME];
        let result = f(&mut buf[..len]);
        // A refused or dropped frame is a lost packet; the protocols retry.
        match route_tx(&buf[..len], self.local) {
            TxRoute::Wire => {
                let _ = self.io.send_frame(&buf[..len]);
            }
            TxRoute::Loop => {
                // Deliver to ourselves: rewrite the Ethernet header so the
                // interface accepts it as unicast for us.
                buf[0..6].copy_from_slice(&self.local.mac);
                buf[6..12].copy_from_slice(&LOOP_MAC);
                let _ = self.lo.push(&buf[..len]);
            }
            TxRoute::Answer(reply, n) => {
                let _ = self.lo.push(&reply[..n]);
            }
        }
        result
    }
}

impl<IO: FrameIo> Device for FrameDevice<IO> {
    type RxToken<'a>
        = FrameRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = FrameTxToken<'a, IO>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let Self { io, rx, lo, ctl, local } = self;
        let n = match lo.pop_into(&mut rx[..]) {
            Some(n) => n,
            None => {
                let n = io.recv_frame(&mut rx[..])?;
                let n = n.min(MAX_FRAME);
                if is_control_frame(&rx[..n]) {
                    // Full queue: the ND message is dropped; routers repeat
                    // advertisements and the machines retransmit.
                    let _ = ctl.push(&rx[..n]);
                }
                n
            }
        };
        if n == 0 {
            return None;
        }
        Some((FrameRxToken { frame: &rx[..n] }, FrameTxToken { io, lo, local }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let Self { io, lo, local, .. } = self;
        Some(FrameTxToken { io, lo, local })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MAX_FRAME;
        // Checksums stay `Both` (default): the virtio-net driver negotiates
        // no offloads, so the stack computes and verifies every checksum.
        caps
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// smoltcp sockets that are not part of the user socket table: ICMP echo (the
/// stack's own ping), one generic UDP, DNS, DHCPv4, the DHCPv6 client's UDP
/// socket, plus spares.
const SYSTEM_SOCKETS: usize = 8;

/// Number of smoltcp sockets the stack can hold.
const SOCKET_SLOTS: usize = SYSTEM_SOCKETS + TCP_SOCKETS + UDP_SOCKETS + ICMP_SOCKETS;

/// Concurrent DNS lookups (smoltcp query slots) and the owner-visible token
/// space of `dns_resolve`.
pub const DNS_SLOTS: usize = 2;

/// Longest host name `dns_resolve` accepts (the cache keys on it verbatim).
pub const DNS_NAME_MAX: usize = 64;

/// DNS cache entries.
const DNS_CACHE_SLOTS: usize = 4;

/// How long a resolved name stays in the cache. TODO(spec): smoltcp's DNS
/// socket does not expose the record TTL, so this is a fixed compromise
/// instead of the server's value.
pub const DNS_CACHE_TTL_NS: u64 = 300 * 1_000_000_000;

/// Largest UDP payload the generic system UDP socket buffers (one datagram at
/// a time; the user socket table has its own, larger, UDP sockets).
pub const UDP_PAYLOAD_MAX: usize = 512;

/// DHCPv6 datagram buffer of the client's socket.
pub const DHCP6_BUF: usize = 1024;

/// Socket metadata and the small system-socket buffers. Modest in size (it is
/// constructed by value in tests); the big payload buffers are in
/// `StackBuffers`.
pub struct StackStorage {
    sockets: [SocketStorage<'static>; SOCKET_SLOTS],
    icmp_rx_meta: [icmp::PacketMetadata; 4],
    icmp_rx_data: [u8; 512],
    icmp_tx_meta: [icmp::PacketMetadata; 4],
    icmp_tx_data: [u8; 512],
    udp_rx_meta: [udp::PacketMetadata; 4],
    udp_rx_data: [u8; UDP_PAYLOAD_MAX],
    udp_tx_meta: [udp::PacketMetadata; 4],
    udp_tx_data: [u8; UDP_PAYLOAD_MAX],
    dhcp6_rx_meta: [udp::PacketMetadata; 2],
    dhcp6_rx_data: [u8; DHCP6_BUF],
    dhcp6_tx_meta: [udp::PacketMetadata; 2],
    dhcp6_tx_data: [u8; DHCP6_BUF],
    dns_queries: [Option<dns::DnsQuery>; DNS_SLOTS],
    user_udp_rx_meta: [[udp::PacketMetadata; UDP_PACKETS]; UDP_SOCKETS],
    user_udp_tx_meta: [[udp::PacketMetadata; UDP_PACKETS]; UDP_SOCKETS],
    user_icmp_rx_meta: [[icmp::PacketMetadata; ICMP_PACKETS]; ICMP_SOCKETS],
    user_icmp_tx_meta: [[icmp::PacketMetadata; ICMP_PACKETS]; ICMP_SOCKETS],
}

impl StackStorage {
    /// An empty storage block.
    pub const fn new() -> Self {
        Self {
            sockets: [SocketStorage::EMPTY; SOCKET_SLOTS],
            icmp_rx_meta: [icmp::PacketMetadata::EMPTY; 4],
            icmp_rx_data: [0; 512],
            icmp_tx_meta: [icmp::PacketMetadata::EMPTY; 4],
            icmp_tx_data: [0; 512],
            udp_rx_meta: [udp::PacketMetadata::EMPTY; 4],
            udp_rx_data: [0; UDP_PAYLOAD_MAX],
            udp_tx_meta: [udp::PacketMetadata::EMPTY; 4],
            udp_tx_data: [0; UDP_PAYLOAD_MAX],
            dhcp6_rx_meta: [udp::PacketMetadata::EMPTY; 2],
            dhcp6_rx_data: [0; DHCP6_BUF],
            dhcp6_tx_meta: [udp::PacketMetadata::EMPTY; 2],
            dhcp6_tx_data: [0; DHCP6_BUF],
            dns_queries: [const { None }; DNS_SLOTS],
            user_udp_rx_meta: [[udp::PacketMetadata::EMPTY; UDP_PACKETS]; UDP_SOCKETS],
            user_udp_tx_meta: [[udp::PacketMetadata::EMPTY; UDP_PACKETS]; UDP_SOCKETS],
            user_icmp_rx_meta: [[icmp::PacketMetadata::EMPTY; ICMP_PACKETS]; ICMP_SOCKETS],
            user_icmp_tx_meta: [[icmp::PacketMetadata::EMPTY; ICMP_PACKETS]; ICMP_SOCKETS],
        }
    }
}

impl Default for StackStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// The socket payload buffers and frame queues: ONLY zero bytes, so this
/// whole block is `.bss` in the process image (it adds nothing to the ELF).
/// About 1.9 MiB: 16 TCP sockets with 64 KiB receive and 32 KiB send buffers
/// (1.5 MiB), 16 UDP sockets with 8 KiB each way, 4 raw-ICMP sockets, and the
/// loopback/control frame queues.
#[repr(C)]
pub struct StackBuffers {
    tcp_rx: [[u8; TCP_RX_BUF]; TCP_SOCKETS],
    tcp_tx: [[u8; TCP_TX_BUF]; TCP_SOCKETS],
    udp_rx: [[u8; UDP_BUF]; UDP_SOCKETS],
    udp_tx: [[u8; UDP_BUF]; UDP_SOCKETS],
    icmp_rx: [[u8; ICMP_BUF]; ICMP_SOCKETS],
    icmp_tx: [[u8; ICMP_BUF]; ICMP_SOCKETS],
    pub(crate) lo: FrameQueue<LOOP_QUEUE>,
    pub(crate) ctl: FrameQueue<CTL_QUEUE>,
}

impl StackBuffers {
    /// An all-zero buffer block.
    pub const fn new() -> Self {
        Self {
            tcp_rx: [[0; TCP_RX_BUF]; TCP_SOCKETS],
            tcp_tx: [[0; TCP_TX_BUF]; TCP_SOCKETS],
            udp_rx: [[0; UDP_BUF]; UDP_SOCKETS],
            udp_tx: [[0; UDP_BUF]; UDP_SOCKETS],
            icmp_rx: [[0; ICMP_BUF]; ICMP_SOCKETS],
            icmp_tx: [[0; ICMP_BUF]; ICMP_SOCKETS],
            lo: FrameQueue::new(),
            ctl: FrameQueue::new(),
        }
    }
}

impl Default for StackBuffers {
    fn default() -> Self {
        Self::new()
    }
}


// ---------------------------------------------------------------------------
// Configuration and events
// ---------------------------------------------------------------------------

/// How the interface gets its IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrMode {
    /// Fixed address, prefix length, default gateway and (optionally) DNS
    /// server, applied at construction. For networks without DHCP and for
    /// tests; the service does not fall back to it silently.
    Static {
        /// Interface address.
        ip: [u8; 4],
        /// Prefix length (24 for 10.0.2.0/24).
        prefix: u8,
        /// Default gateway.
        gateway: [u8; 4],
        /// DNS server, if any.
        dns: Option<[u8; 4]>,
    },
    /// DHCP client: the interface has no address until a server's ACK
    /// arrives; address, gateway and DNS server then come from the lease.
    /// smoltcp's DHCP socket handles DISCOVER/OFFER/REQUEST/ACK, retransmit
    /// with backoff, lease renewal (T1/T2) and re-discovery on expiry or NAK.
    Dhcp,
}

/// Something the stack tells its owner about. The owner logs it or acts on
/// it; the stack itself has no output channel (it cannot print).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetEvent {
    /// The interface has an address: a static configuration was applied or a
    /// DHCP lease was acquired (or changed at renewal).
    LinkConfigured {
        /// Interface address.
        ip: [u8; 4],
        /// Prefix length.
        prefix: u8,
        /// Default gateway, if any.
        gateway: Option<[u8; 4]>,
        /// First DNS server, if any.
        dns: Option<[u8; 4]>,
        /// `true` when the configuration came from DHCP.
        dhcp: bool,
    },
    /// The DHCP lease was lost (expired or NAKed); the interface has no
    /// address until a new lease arrives.
    LinkLost,
    /// An echo request got its reply.
    PingReply {
        /// Who answered.
        from: [u8; 4],
        /// Sequence number of the request.
        seq: u16,
        /// Round-trip time in microseconds.
        rtt_us: u64,
    },
    /// An echo request went unanswered for `PING_TIMEOUT_MS`.
    PingTimeout {
        /// Sequence number of the request.
        seq: u16,
    },
    /// A name lookup finished successfully.
    DnsResolved {
        /// The token `dns_resolve` returned for this lookup.
        token: u8,
        /// The first IPv4 address of the answer.
        addr: [u8; 4],
        /// `true` when it came from the cache (no packet was sent).
        cached: bool,
    },
    /// A name lookup failed (server unreachable, NXDOMAIN, timeout).
    DnsFailed {
        /// The token `dns_resolve` returned for this lookup.
        token: u8,
    },
}

/// Why `ping` refused to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingError {
    /// A previous request is still outstanding (one at a time for now).
    Busy,
    /// The ICMP transmit buffer is full.
    NoBuffer,
}

/// Why `dns_resolve` refused to start a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// The name is empty, too long (`DNS_NAME_MAX`) or malformed.
    InvalidName,
    /// All `DNS_SLOTS` lookups are in use.
    NoFreeSlot,
    /// No DNS server is known yet (no lease / no static server).
    NoServer,
}

/// Why a UDP call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpError {
    /// The port is 0 or the socket is already bound.
    Bind,
    /// The socket is not bound, or its transmit buffer is full, or the
    /// payload exceeds `UDP_PAYLOAD_MAX`, or there is no route.
    Send,
}

/// One received UDP datagram's metadata (`udp_recv` copies the payload out).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram {
    /// Sender address.
    pub src: [u8; 4],
    /// Sender port.
    pub src_port: u16,
    /// Payload length copied into the caller's buffer.
    pub len: usize,
}

#[derive(Clone, Copy)]
struct OutstandingPing {
    seq: u16,
    sent_ns: u64,
}

/// One in-flight DNS lookup.
#[derive(Clone, Copy)]
struct DnsSlot {
    handle: dns::QueryHandle,
    name: [u8; DNS_NAME_MAX],
    name_len: usize,
}

/// One cached name.
#[derive(Clone, Copy)]
struct DnsCacheEntry {
    name: [u8; DNS_NAME_MAX],
    name_len: usize,
    addr: [u8; 4],
    expires_ns: u64,
}

/// A tiny fixed queue of events raised outside `poll`'s own detection (a
/// cache hit answers at once but is reported by the next `poll`).
const PENDING_EVENTS: usize = 8;

// ---------------------------------------------------------------------------
// The stack
// ---------------------------------------------------------------------------

/// The Netstack: one Ethernet interface with ICMP, UDP, DHCP-client and DNS
/// sockets, and the small API the service loop drives. Call `poll` regularly
/// (it is what moves frames and runs protocol timers); everything else only
/// queues work for the next `poll`.
pub struct NetStack<IO: FrameIo> {
    pub(crate) device: FrameDevice<IO>,
    pub(crate) iface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    icmp: SocketHandle,
    udp: SocketHandle,
    dns: SocketHandle,
    dhcp: Option<SocketHandle>,
    /// UDP socket of the DHCPv6 client (port 546).
    dhcp6: SocketHandle,
    ping: Option<OutstandingPing>,
    dns_slots: [Option<DnsSlot>; DNS_SLOTS],
    dns_cache: [Option<DnsCacheEntry>; DNS_CACHE_SLOTS],
    dns_cache_next: usize,
    pending: [Option<NetEvent>; PENDING_EVENTS],
    /// Cached view of the current lease/config for the API (`ip()` etc.).
    config: Option<NetEvent>,
    /// Physical link state as last reported by the driver (`set_link`).
    link_up: bool,
    /// The static configuration to restore when the link returns.
    static_cfg: Option<([u8; 4], u8, [u8; 4], Option<[u8; 4]>)>,
    /// DHCP restart schedule while the link is up but no lease exists.
    dhcp_retry_at_ns: u64,
    dhcp_backoff_ns: u64,
    /// The user socket table (`sockets.rs`).
    pub(crate) table: SocketTable,
    /// Clock of the last `poll` (the socket layer stamps deadlines with it).
    pub(crate) now_ns: u64,
    /// IPv4 address of the LAN interface (static or leased).
    lan_v4: Option<([u8; 4], u8)>,
    /// IPv6 addresses of the LAN interface (link-local, SLAAC, DHCPv6).
    lan_v6: [Option<(Ip6, u8)>; V6_ADDRS],
    /// When the loopback neighbour entries are next refreshed.
    next_seed_ns: u64,
    /// IPv4 DNS server (DHCP/static).
    dns_v4: Option<[u8; 4]>,
    /// IPv6 DNS servers (RDNSS/DHCPv6).
    dns_v6: [Option<Ip6>; 3],
}

/// Converts the process clock (nanoseconds) to smoltcp's `Instant`.
pub fn instant_from_ns(now_ns: u64) -> Instant {
    Instant::from_micros((now_ns / 1_000) as i64)
}

fn v4(a: [u8; 4]) -> Ipv4Address {
    Ipv4Address::new(a[0], a[1], a[2], a[3])
}

impl<IO: FrameIo> NetStack<IO> {
    /// Builds the stack over `io` with hardware address `mac`.
    pub fn new(
        storage: &'static mut StackStorage,
        bufs: &'static mut StackBuffers,
        io: IO,
        mac: [u8; 6],
        mode: AddrMode,
        now_ns: u64,
    ) -> Self {
        let StackStorage {
            sockets,
            icmp_rx_meta,
            icmp_rx_data,
            icmp_tx_meta,
            icmp_tx_data,
            udp_rx_meta,
            udp_rx_data,
            udp_tx_meta,
            udp_tx_data,
            dhcp6_rx_meta,
            dhcp6_rx_data,
            dhcp6_tx_meta,
            dhcp6_tx_data,
            dns_queries,
            user_udp_rx_meta,
            user_udp_tx_meta,
            user_icmp_rx_meta,
            user_icmp_tx_meta,
        } = storage;
        let StackBuffers { tcp_rx, tcp_tx, udp_rx, udp_tx, icmp_rx, icmp_tx, lo, ctl } = bufs;

        let mut device = FrameDevice::new(io, mac, lo, ctl);
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        // Not cryptographic: seeds smoltcp's source ports, DNS transaction ids
        // and DHCP xid/jitter. Mixing the MAC in keeps two VMs booted at the
        // same instant apart.
        let seed = now_ns ^ u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0x5A, 0xA5]);
        config.random_seed = seed;
        let iface = Interface::new(config, &mut device, instant_from_ns(now_ns));

        let mut socket_set = SocketSet::new(&mut sockets[..]);
        let icmp_socket = icmp::Socket::new(
            icmp::PacketBuffer::new(&mut icmp_rx_meta[..], &mut icmp_rx_data[..]),
            icmp::PacketBuffer::new(&mut icmp_tx_meta[..], &mut icmp_tx_data[..]),
        );
        let icmp = socket_set.add(icmp_socket);
        socket_set.get_mut::<icmp::Socket>(icmp).bind(icmp::Endpoint::Ident(PING_IDENT)).ok();
        let udp_socket = udp::Socket::new(
            udp::PacketBuffer::new(&mut udp_rx_meta[..], &mut udp_rx_data[..]),
            udp::PacketBuffer::new(&mut udp_tx_meta[..], &mut udp_tx_data[..]),
        );
        let udp = socket_set.add(udp_socket);
        let dns = socket_set.add(dns::Socket::new(&[], &mut dns_queries[..]));
        let dhcp = match mode {
            AddrMode::Dhcp => Some(socket_set.add(dhcpv4::Socket::new())),
            AddrMode::Static { .. } => None,
        };
        let dhcp6 = socket_set.add(udp::Socket::new(
            udp::PacketBuffer::new(&mut dhcp6_rx_meta[..], &mut dhcp6_rx_data[..]),
            udp::PacketBuffer::new(&mut dhcp6_tx_meta[..], &mut dhcp6_tx_data[..]),
        ));

        // The user socket pools: every smoltcp socket exists from the start
        // (its buffers are static); the table only hands them out.
        let mut tcp_h = [SocketHandle::default(); TCP_SOCKETS];
        for (h, (rx, tx)) in tcp_h.iter_mut().zip(tcp_rx.iter_mut().zip(tcp_tx.iter_mut())) {
            *h = socket_set.add(tcp::Socket::new(tcp::SocketBuffer::new(&mut rx[..]), tcp::SocketBuffer::new(&mut tx[..])));
        }
        let mut udp_h = [SocketHandle::default(); UDP_SOCKETS];
        let udp_sets = user_udp_rx_meta.iter_mut().zip(user_udp_tx_meta.iter_mut());
        let udp_bufs = udp_rx.iter_mut().zip(udp_tx.iter_mut());
        for (h, ((rxm, txm), (rxd, txd))) in udp_h.iter_mut().zip(udp_sets.zip(udp_bufs)) {
            *h = socket_set.add(udp::Socket::new(
                udp::PacketBuffer::new(&mut rxm[..], &mut rxd[..]),
                udp::PacketBuffer::new(&mut txm[..], &mut txd[..]),
            ));
        }
        let mut icmp_h = [SocketHandle::default(); ICMP_SOCKETS];
        let icmp_sets = user_icmp_rx_meta.iter_mut().zip(user_icmp_tx_meta.iter_mut());
        let icmp_bufs = icmp_rx.iter_mut().zip(icmp_tx.iter_mut());
        for (h, ((rxm, txm), (rxd, txd))) in icmp_h.iter_mut().zip(icmp_sets.zip(icmp_bufs)) {
            *h = socket_set.add(icmp::Socket::new(
                icmp::PacketBuffer::new(&mut rxm[..], &mut rxd[..]),
                icmp::PacketBuffer::new(&mut txm[..], &mut txd[..]),
            ));
        }

        let mut stack = Self {
            device,
            iface,
            sockets: socket_set,
            icmp,
            udp,
            dns,
            dhcp,
            dhcp6,
            ping: None,
            dns_slots: [None; DNS_SLOTS],
            dns_cache: [None; DNS_CACHE_SLOTS],
            dns_cache_next: 0,
            pending: [None; PENDING_EVENTS],
            config: None,
            link_up: true,
            static_cfg: None,
            dhcp_retry_at_ns: now_ns + DHCP_RESTART_FIRST_NS,
            dhcp_backoff_ns: DHCP_RESTART_FIRST_NS,
            table: SocketTable::new(tcp_h, udp_h, icmp_h, seed),
            now_ns,
            lan_v4: None,
            lan_v6: [None; V6_ADDRS],
            next_seed_ns: 0,
            dns_v4: None,
            dns_v6: [None; 3],
        };
        stack.rebuild_addrs();
        if let AddrMode::Static { ip, prefix, gateway, dns } = mode {
            stack.static_cfg = Some((ip, prefix, gateway, dns));
            stack.apply_config(ip, prefix, Some(gateway), dns, false);
        }
        stack
    }

    fn queue_event(&mut self, ev: NetEvent) {
        if let Some(slot) = self.pending.iter_mut().find(|s| s.is_none()) {
            *slot = Some(ev);
        }
        // A full queue drops the event: the owner is not polling at all then.
    }

    /// Rebuilds the interface's address list from the configured state: the
    /// LAN IPv4 address, the IPv6 addresses (link-local, SLAAC, DHCPv6), then
    /// the loopback addresses 127.0.0.1/8 and ::1/128. Order matters for
    /// smoltcp's IPv6 source selection: the loopback goes last so a global or
    /// link-local address is the first candidate. Also tells the device layer
    /// which addresses are ours (frames to them never leave the machine).
    pub(crate) fn rebuild_addrs(&mut self) {
        let v4 = self.lan_v4;
        let v6 = self.lan_v6;
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            if let Some((ip, prefix)) = v4 {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(Ipv4Address::new(ip[0], ip[1], ip[2], ip[3])), prefix));
            }
            for (a, prefix) in v6.iter().flatten() {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(*a)), *prefix));
            }
            let _ = addrs.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8));
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(ndp_wire::LOOPBACK)), 128));
        });
        let mut local6 = [None; V6_ADDRS];
        for (dst, src) in local6.iter_mut().zip(v6.iter()) {
            *dst = src.map(|(a, _)| a);
        }
        self.device.set_local(v4.map(|(ip, _)| ip), local6);
        self.seed_local_neighbors();
    }

    /// Pre-fills smoltcp's neighbour cache with the pseudo-neighbour that
    /// answers for our own addresses (127.0.0.1, ::1, the LAN and IPv6
    /// addresses): an unsolicited ARP reply/neighbor advertisement per address,
    /// looped into the receive path. smoltcp rate-limits neighbour discovery to
    /// one request per second for the whole interface, so without this the first
    /// connection to ::1 right after one to 127.0.0.1 (or to a real host) would
    /// stall for up to a second. The cache flushes on every address change and
    /// entries live 60 s, so this runs after each rebuild and every 20 s.
    pub(crate) fn seed_local_neighbors(&mut self) {
        let mac = self.device_mac();
        let mut targets_v4 = [[127, 0, 0, 1], [0; 4]];
        let mut n4 = 1;
        if let Some((ip, _)) = self.lan_v4 {
            targets_v4[1] = ip;
            n4 = 2;
        }
        for ip in &targets_v4[..n4] {
            let mut r = [0u8; 42];
            r[0..6].copy_from_slice(&mac);
            r[6..12].copy_from_slice(&LOOP_MAC);
            r[12..14].copy_from_slice(&[0x08, 0x06]);
            r[14..20].copy_from_slice(&[0, 1, 8, 0, 6, 4]);
            r[20..22].copy_from_slice(&[0, 2]);
            r[22..28].copy_from_slice(&LOOP_MAC);
            r[28..32].copy_from_slice(ip);
            r[32..38].copy_from_slice(&mac);
            r[38..42].copy_from_slice(ip);
            self.device.inject_loopback(&r);
        }
        let mut addrs6 = [ndp_wire::LOOPBACK; V6_ADDRS + 1];
        let mut n6 = 1;
        for (a, _) in self.lan_v6.iter().flatten() {
            addrs6[n6] = *a;
            n6 += 1;
        }
        for a in &addrs6[..n6] {
            let mut r = [0u8; ndp_wire::MAX_ND_FRAME];
            let flags = ndp_wire::NaFlags { router: false, solicited: false, override_: true };
            if let Some(len) = ndp_wire::build_na(&mut r, &LOOP_MAC, &mac, a, a, a, flags, Some(&LOOP_MAC)) {
                self.device.inject_loopback(&r[..len]);
            }
        }
        self.next_seed_ns = self.now_ns + NEIGHBOR_SEED_INTERVAL_NS;
    }

    fn device_mac(&self) -> Mac {
        self.device.mac()
    }

    /// Installs an address configuration (static or from a lease).
    fn apply_config(&mut self, ip: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>, dns: Option<[u8; 4]>, dhcp: bool) {
        self.lan_v4 = Some((ip, prefix));
        self.rebuild_addrs();
        match gateway {
            Some(gw) => {
                let _ = self.iface.routes_mut().add_default_ipv4_route(v4(gw));
            }
            None => {
                self.iface.routes_mut().remove_default_ipv4_route();
            }
        }
        self.dns_v4 = dns;
        self.refresh_dns_servers();
        let ev = NetEvent::LinkConfigured { ip, prefix, gateway, dns, dhcp };
        self.config = Some(ev);
        self.queue_event(ev);
    }

    /// Drops the IPv4 address configuration (lease lost).
    fn clear_config(&mut self) {
        self.lan_v4 = None;
        self.rebuild_addrs();
        self.iface.routes_mut().remove_default_ipv4_route();
        self.dns_v4 = None;
        self.refresh_dns_servers();
        self.config = None;
        self.queue_event(NetEvent::LinkLost);
    }

    /// Pushes the known DNS servers (IPv4 from DHCP/static, IPv6 from RDNSS/
    /// DHCPv6) into the resolver socket.
    pub(crate) fn refresh_dns_servers(&mut self) {
        let mut servers = [IpAddress::v4(0, 0, 0, 0); 4];
        let mut n = 0;
        if let Some(d) = self.dns_v4 {
            servers[n] = IpAddress::Ipv4(v4(d));
            n += 1;
        }
        for a in self.dns_v6.iter().flatten() {
            if n < servers.len() {
                servers[n] = IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(*a));
                n += 1;
            }
        }
        self.sockets.get_mut::<dns::Socket>(self.dns).update_servers(&servers[..n]);
    }

    /// The current configuration event (`LinkConfigured`), or `None` while the
    /// interface has no address.
    pub fn config(&self) -> Option<NetEvent> {
        self.config
    }

    /// Reports the physical link state (from the driver). Link down drops the
    /// address configuration, outstanding ping/DNS state and DHCP progress and
    /// queues `LinkLost`; link up restarts DHCP at once (or restores a static
    /// configuration). Repeated calls with the same value do nothing.
    pub fn set_link(&mut self, up: bool, now_ns: u64) {
        if up == self.link_up {
            return;
        }
        self.link_up = up;
        if !up {
            self.ping = None;
            self.dns_slots = [None; DNS_SLOTS];
            if self.config.is_some() {
                self.clear_config();
            }
            return;
        }
        self.dhcp_backoff_ns = DHCP_RESTART_FIRST_NS;
        self.dhcp_retry_at_ns = now_ns + DHCP_RESTART_FIRST_NS;
        match self.dhcp {
            Some(h) => self.sockets.get_mut::<dhcpv4::Socket>(h).reset(),
            None => {
                if let Some((ip, prefix, gw, dns)) = self.static_cfg {
                    self.apply_config(ip, prefix, Some(gw), dns, false);
                }
            }
        }
    }

    /// Last reported link state.
    pub fn link_up(&self) -> bool {
        self.link_up
    }

    /// What the user should see: no link -> `Disconnected`; link but no
    /// address -> `Connecting`; address -> `Connected`.
    pub fn conn_state(&self) -> crate::status::ConnState {
        use crate::status::ConnState;
        if !self.link_up {
            ConnState::Disconnected
        } else if self.config.is_some() {
            ConnState::Connected
        } else {
            ConnState::Connecting
        }
    }

    /// The compact status record for the desktop (adapter is present by
    /// definition: a stack only exists over a probed NIC).
    pub fn snapshot(&self, mac: [u8; 6], kind: crate::status::AdapterKind) -> crate::status::NetStatus {
        let (ip, gateway, dns) = match self.config {
            Some(NetEvent::LinkConfigured { ip, prefix, gateway, dns, .. }) => (Some((ip, prefix)), gateway, dns),
            _ => (None, None, None),
        };
        crate::status::NetStatus {
            adapter: true,
            link_up: self.link_up,
            state: self.conn_state(),
            kind,
            ip,
            gateway,
            dns,
            mac,
        }
    }

    /// While the link is up but no lease exists, restarts DHCP on an
    /// exponential schedule (8 s, 16 s, ... capped at 60 s).
    fn dhcp_watchdog(&mut self, now_ns: u64) {
        let Some(h) = self.dhcp else { return };
        if self.config.is_some() {
            self.dhcp_backoff_ns = DHCP_RESTART_FIRST_NS;
            self.dhcp_retry_at_ns = now_ns + DHCP_RESTART_FIRST_NS;
            return;
        }
        if now_ns >= self.dhcp_retry_at_ns {
            self.sockets.get_mut::<dhcpv4::Socket>(h).reset();
            self.dhcp_backoff_ns = (self.dhcp_backoff_ns * 2).min(DHCP_RESTART_MAX_NS);
            self.dhcp_retry_at_ns = now_ns + self.dhcp_backoff_ns;
        }
    }

    /// Access to the transport (host tests only in practice).
    pub fn io(&self) -> &IO {
        self.device.io()
    }

    /// Mutable access to the transport.
    pub fn io_mut(&mut self) -> &mut IO {
        self.device.io_mut()
    }

    // ---- ICMP -------------------------------------------------------------

    /// Queues one ICMP echo request to `dst` with sequence number `seq`. The
    /// frame (and the ARP request for `dst`'s MAC, if needed) leaves on the
    /// next `poll`.
    pub fn ping(&mut self, dst: [u8; 4], seq: u16, now_ns: u64) -> Result<(), PingError> {
        if self.ping.is_some() {
            return Err(PingError::Busy);
        }
        let repr = Icmpv4Repr::EchoRequest { ident: PING_IDENT, seq_no: seq, data: PING_PAYLOAD };
        let checksum = self.device.capabilities().checksum;
        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp);
        let addr = IpAddress::Ipv4(v4(dst));
        let buf = socket.send(repr.buffer_len(), addr).map_err(|_| PingError::NoBuffer)?;
        let mut packet = Icmpv4Packet::new_unchecked(buf);
        repr.emit(&mut packet, &checksum);
        self.ping = Some(OutstandingPing { seq, sent_ns: now_ns });
        Ok(())
    }

    /// Whether an echo request is still waiting for its reply.
    pub fn ping_outstanding(&self) -> bool {
        self.ping.is_some()
    }

    // ---- UDP --------------------------------------------------------------

    /// Binds the generic UDP socket to local `port`. One socket for now; the
    /// socket API of phase 3 hands out one per client.
    pub fn udp_bind(&mut self, port: u16) -> Result<(), UdpError> {
        self.sockets.get_mut::<udp::Socket>(self.udp).bind(port).map_err(|_| UdpError::Bind)
    }

    /// Queues one datagram to `dst:dst_port`; it leaves on the next `poll`.
    pub fn udp_send(&mut self, dst: [u8; 4], dst_port: u16, data: &[u8]) -> Result<(), UdpError> {
        if data.len() > UDP_PAYLOAD_MAX {
            return Err(UdpError::Send);
        }
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(v4(dst)), dst_port);
        self.sockets.get_mut::<udp::Socket>(self.udp).send_slice(data, endpoint).map_err(|_| UdpError::Send)
    }

    /// Copies the oldest received datagram into `buf` (truncating nothing: a
    /// datagram larger than `buf` is dropped and `None` returned).
    pub fn udp_recv(&mut self, buf: &mut [u8]) -> Option<UdpDatagram> {
        let socket = self.sockets.get_mut::<udp::Socket>(self.udp);
        let (len, meta) = socket.recv_slice(buf).ok()?;
        let IpAddress::Ipv4(src) = meta.endpoint.addr else { return None };
        Some(UdpDatagram { src: src.octets(), src_port: meta.endpoint.port, len })
    }

    // ---- DNS --------------------------------------------------------------

    /// Starts resolving `name` (an A record). Returns a token; the outcome
    /// arrives as `DnsResolved`/`DnsFailed` with that token from a later
    /// `poll`. A name in the cache is answered without any packet. smoltcp
    /// retransmits the query and gives up after its own timeout (10 s).
    pub fn dns_resolve(&mut self, name: &str, now_ns: u64) -> Result<u8, DnsError> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() > DNS_NAME_MAX {
            return Err(DnsError::InvalidName);
        }
        let token = self.dns_slots.iter().position(|s| s.is_none()).ok_or(DnsError::NoFreeSlot)?;
        // Cache first.
        for entry in self.dns_cache.iter().flatten() {
            if entry.expires_ns > now_ns && &entry.name[..entry.name_len] == bytes {
                // Reserve the token only for the event's sake: nothing is
                // in flight, so the slot stays free.
                self.queue_event(NetEvent::DnsResolved { token: token as u8, addr: entry.addr, cached: true });
                return Ok(token as u8);
            }
        }
        if self.config.is_none() {
            return Err(DnsError::NoServer);
        }
        let socket = self.sockets.get_mut::<dns::Socket>(self.dns);
        let handle = socket.start_query(self.iface.context(), name, DnsQueryType::A).map_err(|e| match e {
            dns::StartQueryError::NoFreeSlot => DnsError::NoFreeSlot,
            dns::StartQueryError::InvalidName | dns::StartQueryError::NameTooLong => DnsError::InvalidName,
        })?;
        let mut slot = DnsSlot { handle, name: [0; DNS_NAME_MAX], name_len: bytes.len() };
        slot.name[..bytes.len()].copy_from_slice(bytes);
        self.dns_slots[token] = Some(slot);
        Ok(token as u8)
    }

    fn collect_dns(&mut self, now_ns: u64) {
        for token in 0..DNS_SLOTS {
            let Some(slot) = self.dns_slots[token] else { continue };
            let socket = self.sockets.get_mut::<dns::Socket>(self.dns);
            match socket.get_query_result(slot.handle) {
                Err(dns::GetQueryResultError::Pending) => {}
                Err(dns::GetQueryResultError::Failed) => {
                    self.dns_slots[token] = None;
                    self.queue_event(NetEvent::DnsFailed { token: token as u8 });
                }
                Ok(addrs) => {
                    self.dns_slots[token] = None;
                    let first = addrs.iter().filter_map(|a| match *a {
                        IpAddress::Ipv4(v) => Some(v.octets()),
                        IpAddress::Ipv6(_) => None,
                    });
                    match first.into_iter().next() {
                        Some(addr) => {
                            self.dns_cache[self.dns_cache_next] = Some(DnsCacheEntry {
                                name: slot.name,
                                name_len: slot.name_len,
                                addr,
                                expires_ns: now_ns.saturating_add(DNS_CACHE_TTL_NS),
                            });
                            self.dns_cache_next = (self.dns_cache_next + 1) % DNS_CACHE_SLOTS;
                            self.queue_event(NetEvent::DnsResolved { token: token as u8, addr, cached: false });
                        }
                        None => self.queue_event(NetEvent::DnsFailed { token: token as u8 }),
                    }
                }
            }
        }
    }

    // ---- DHCP -------------------------------------------------------------

    fn poll_dhcp(&mut self) {
        let Some(handle) = self.dhcp else { return };
        // Copy everything out of the event before touching `self` again: the
        // `Configured` config borrows the socket.
        enum Change {
            Up { ip: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>, dns: Option<[u8; 4]> },
            Down,
        }
        let change = match self.sockets.get_mut::<dhcpv4::Socket>(handle).poll() {
            None => return,
            Some(dhcpv4::Event::Deconfigured) => Change::Down,
            Some(dhcpv4::Event::Configured(cfg)) => Change::Up {
                ip: cfg.address.address().octets(),
                prefix: cfg.address.prefix_len(),
                gateway: cfg.router.map(|r| r.octets()),
                dns: cfg.dns_servers.first().map(|d| d.octets()),
            },
        };
        match change {
            Change::Up { ip, prefix, gateway, dns } => self.apply_config(ip, prefix, gateway, dns, true),
            // smoltcp reports `Deconfigured` once at start-up too (initial state
            // change); that is not a lost lease.
            Change::Down if self.config.is_some() => self.clear_config(),
            Change::Down => {}
        }
    }

    // ---- polling ----------------------------------------------------------

    /// Runs the stack once: receive queued frames, run protocol timers
    /// (ARP retry, DHCP, DNS retransmit), transmit whatever is due, then
    /// report events through `on_event`. Returns `true` if any socket state
    /// changed (the caller may poll again at once instead of sleeping).
    pub fn poll(&mut self, now_ns: u64, on_event: &mut dyn FnMut(NetEvent)) -> bool {
        if !self.link_up {
            // No link: nothing to send or receive; only report queued events.
            for slot in self.pending.iter_mut() {
                if let Some(ev) = slot.take() {
                    on_event(ev);
                }
            }
            return false;
        }
        self.now_ns = now_ns;
        let now = instant_from_ns(now_ns);
        let moved = self.run_interface(now);
        self.poll_dhcp();
        self.dhcp_watchdog(now_ns);
        self.collect_ping(now_ns);
        self.collect_dns(now_ns);
        self.socket_housekeeping(now_ns);
        if now_ns >= self.next_seed_ns {
            self.seed_local_neighbors();
        }
        // A lease acquired above may let queued datagrams/queries leave now.
        let moved2 = self.run_interface(now);
        for slot in self.pending.iter_mut() {
            if let Some(ev) = slot.take() {
                on_event(ev);
            }
        }
        moved || moved2
    }

    /// Runs smoltcp's interface until loopback traffic has settled: frames a
    /// socket sent to 127.0.0.1/::1/one of our addresses sit in the device's
    /// loop queue and are received by the NEXT round, so a request, its reply
    /// and the ACKs can all complete inside one `poll`. Bounded so a
    /// misbehaving pair of sockets cannot spin forever.
    fn run_interface(&mut self, now: Instant) -> bool {
        let mut moved = false;
        for _ in 0..LOOP_ROUNDS {
            moved |= matches!(
                self.iface.poll(now, &mut self.device, &mut self.sockets),
                PollResult::SocketStateChanged
            );
            if self.device.loop_pending() == 0 {
                break;
            }
        }
        moved
    }

    fn collect_ping(&mut self, now_ns: u64) {
        let now_ms = (now_ns / 1_000_000) as i64;
        let checksum = self.device.capabilities().checksum;
        let mut events = [None, None];
        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp);
        while let Ok((payload, from)) = socket.recv() {
            let IpAddress::Ipv4(from) = from else { continue };
            let Ok(packet) = Icmpv4Packet::new_checked(payload) else { continue };
            let Ok(Icmpv4Repr::EchoReply { ident, seq_no, .. }) = Icmpv4Repr::parse(&packet, &checksum) else {
                continue;
            };
            let Some(out) = self.ping else { continue };
            if ident != PING_IDENT || seq_no != out.seq {
                continue;
            }
            self.ping = None;
            let rtt_us = now_ns.saturating_sub(out.sent_ns) / 1_000;
            events[0] = Some(NetEvent::PingReply { from: from.octets(), seq: seq_no, rtt_us });
        }
        if let Some(out) = self.ping {
            if now_ms - (out.sent_ns / 1_000_000) as i64 >= PING_TIMEOUT_MS {
                self.ping = None;
                events[1] = Some(NetEvent::PingTimeout { seq: out.seq });
            }
        }
        for ev in events.into_iter().flatten() {
            self.queue_event(ev);
        }
    }

    /// Milliseconds until the stack next needs a `poll` (`None` = nothing
    /// scheduled; use the caller's idle interval). Zero while events are
    /// waiting to be reported.
    pub fn poll_delay_ms(&mut self, now_ns: u64) -> Option<u64> {
        if self.pending.iter().any(|e| e.is_some()) || self.device.loop_pending() > 0 {
            return Some(0);
        }
        self.iface.poll_delay(instant_from_ns(now_ns), &self.sockets).map(|d| d.total_millis())
    }
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "sockets_tests.rs"]
pub(crate) mod socket_tests;
