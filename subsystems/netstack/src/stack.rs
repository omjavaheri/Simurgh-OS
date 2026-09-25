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
use smoltcp::socket::{dhcpv4, dns, icmp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    DnsQueryType, EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, IpEndpoint,
    Ipv4Address,
};

/// Largest Ethernet frame the driver's buffers hold
/// (`driver_virtio_net::FRAME_MAX`; must stay numerically equal). It is also
/// the interface MTU as smoltcp counts it for Ethernet (frame size including
/// the 14-byte header), so no frame this stack builds can overflow a driver
/// buffer. TODO(spec): the driver's 700-byte buffers and 2-descriptor queues
/// are an MVP size; TCP (Phase 3) wants full 1514-byte frames and a deeper RX
/// queue - see `docs/internet-plan.md`.
pub const MAX_FRAME: usize = 700;

/// First DHCP restart delay while the link is up but there is no lease
/// (smoltcp also retransmits DISCOVER by itself); doubles up to the cap.
pub const DHCP_RESTART_FIRST_NS: u64 = 8_000_000_000;
/// Upper bound of the DHCP restart backoff.
pub const DHCP_RESTART_MAX_NS: u64 = 60_000_000_000;

/// How long an echo request may stay unanswered before `PingTimeout` fires.
pub const PING_TIMEOUT_MS: i64 = 1_000;

/// ICMP identifier every echo request from this stack carries. One
/// requester per stack today; a real socket API (Phase 3) will hand out
/// identifiers per socket.
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
    /// on protocol retransmission (ARP retry, DHCP/DNS retry, ...).
    fn send_frame(&mut self, frame: &[u8]) -> bool;
}

/// smoltcp `Device` adapter over a `FrameIo`.
///
/// `receive` pulls at most one frame from the transport into `rx` (one
/// staging buffer, no queue: the driver's own RX queue is the queue) and
/// `transmit` hands out a token that builds the frame on the stack and sends
/// it when consumed.
pub struct FrameDevice<IO: FrameIo> {
    io: IO,
    rx: [u8; MAX_FRAME],
}

impl<IO: FrameIo> FrameDevice<IO> {
    /// Wraps `io`.
    pub fn new(io: IO) -> Self {
        Self { io, rx: [0; MAX_FRAME] }
    }

    /// Access to the transport (tests inspect their mock through this).
    pub fn io(&self) -> &IO {
        &self.io
    }

    /// Mutable access to the transport.
    pub fn io_mut(&mut self) -> &mut IO {
        &mut self.io
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
}

impl<IO: FrameIo> TxToken for FrameTxToken<'_, IO> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        // Frames larger than the driver buffer cannot happen (the capability
        // report below caps the MTU); clamping keeps a logic error from
        // becoming a stack overflow.
        let len = len.min(MAX_FRAME);
        let mut buf = [0u8; MAX_FRAME];
        let result = f(&mut buf[..len]);
        // A refused frame is a lost packet; the protocols above retry.
        let _ = self.io.send_frame(&buf[..len]);
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
        let n = self.io.recv_frame(&mut self.rx)?;
        if n == 0 {
            return None;
        }
        let n = n.min(MAX_FRAME);
        Some((FrameRxToken { frame: &self.rx[..n] }, FrameTxToken { io: &mut self.io }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(FrameTxToken { io: &mut self.io })
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

/// Number of smoltcp sockets the stack can hold: ICMP, UDP, DHCP, DNS (+2
/// spare for the socket API of phase 3).
const SOCKET_SLOTS: usize = 6;

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

/// Largest UDP payload the generic UDP socket buffers (one datagram at a
/// time; fits the driver's 700-byte frames).
pub const UDP_PAYLOAD_MAX: usize = 512;

/// All memory the stack uses. No heap: sockets and their buffers are carved
/// out of this one struct, which the caller places in a `static` (the process
/// image) or leaks (host tests).
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
    dns_queries: [Option<dns::DnsQuery>; DNS_SLOTS],
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
            dns_queries: [const { None }; DNS_SLOTS],
        }
    }
}

impl Default for StackStorage {
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
    device: FrameDevice<IO>,
    iface: Interface,
    sockets: SocketSet<'static>,
    icmp: SocketHandle,
    udp: SocketHandle,
    dns: SocketHandle,
    dhcp: Option<SocketHandle>,
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
    pub fn new(storage: &'static mut StackStorage, io: IO, mac: [u8; 6], mode: AddrMode, now_ns: u64) -> Self {
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
            dns_queries,
        } = storage;

        let mut device = FrameDevice::new(io);
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        // Not cryptographic: seeds smoltcp's source ports, DNS transaction ids
        // and DHCP xid/jitter. Mixing the MAC in keeps two VMs booted at the
        // same instant apart.
        config.random_seed = now_ns ^ u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0x5A, 0xA5]);
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

        let mut stack = Self {
            device,
            iface,
            sockets: socket_set,
            icmp,
            udp,
            dns,
            dhcp,
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
        };
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

    /// Installs an address configuration (static or from a lease).
    fn apply_config(&mut self, ip: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>, dns: Option<[u8; 4]>, dhcp: bool) {
        let addr = v4(ip);
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(addr), prefix));
        });
        match gateway {
            Some(gw) => {
                let _ = self.iface.routes_mut().add_default_ipv4_route(v4(gw));
            }
            None => {
                self.iface.routes_mut().remove_default_ipv4_route();
            }
        }
        let dns_socket = self.sockets.get_mut::<dns::Socket>(self.dns);
        match dns {
            Some(d) => dns_socket.update_servers(&[IpAddress::Ipv4(v4(d))]),
            None => dns_socket.update_servers(&[]),
        }
        let ev = NetEvent::LinkConfigured { ip, prefix, gateway, dns, dhcp };
        self.config = Some(ev);
        self.queue_event(ev);
    }

    /// Drops the address configuration (lease lost).
    fn clear_config(&mut self) {
        self.iface.update_ip_addrs(|addrs| addrs.clear());
        self.iface.routes_mut().remove_default_ipv4_route();
        self.sockets.get_mut::<dns::Socket>(self.dns).update_servers(&[]);
        self.config = None;
        self.queue_event(NetEvent::LinkLost);
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
        let IpAddress::Ipv4(src) = meta.endpoint.addr;
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
                    let first = addrs.iter().map(|a| {
                        let IpAddress::Ipv4(v) = *a;
                        v.octets()
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
        let now = instant_from_ns(now_ns);
        let moved = matches!(self.iface.poll(now, &mut self.device, &mut self.sockets), PollResult::SocketStateChanged);
        self.poll_dhcp();
        self.dhcp_watchdog(now_ns);
        self.collect_ping(now_ns);
        self.collect_dns(now_ns);
        // A lease acquired above may let queued datagrams/queries leave now.
        let moved2 =
            matches!(self.iface.poll(now, &mut self.device, &mut self.sockets), PollResult::SocketStateChanged);
        for slot in self.pending.iter_mut() {
            if let Some(ev) = slot.take() {
                on_event(ev);
            }
        }
        moved || moved2
    }

    fn collect_ping(&mut self, now_ns: u64) {
        let now_ms = (now_ns / 1_000_000) as i64;
        let checksum = self.device.capabilities().checksum;
        let mut events = [None, None];
        let socket = self.sockets.get_mut::<icmp::Socket>(self.icmp);
        while let Ok((payload, from)) = socket.recv() {
            let IpAddress::Ipv4(from) = from;
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
        if self.pending.iter().any(|e| e.is_some()) {
            return Some(0);
        }
        self.iface.poll_delay(instant_from_ns(now_ns), &self.sockets).map(|d| d.total_millis())
    }
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;
