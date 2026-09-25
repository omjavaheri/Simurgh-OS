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
use smoltcp::socket::icmp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr, Ipv4Address};

/// Largest Ethernet frame the driver's buffers hold
/// (`driver_virtio_net::FRAME_MAX`; must stay numerically equal). It is also
/// the interface MTU as smoltcp counts it for Ethernet (frame size including
/// the 14-byte header), so no frame this stack builds can overflow a driver
/// buffer. TODO(spec): the driver's 700-byte buffers and 2-descriptor queues
/// are an MVP size; TCP (Phase 3) wants full 1514-byte frames and a deeper RX
/// queue - see `docs/internet-plan.md`.
pub const MAX_FRAME: usize = 700;

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

/// Number of smoltcp sockets the stack can hold.
const SOCKET_SLOTS: usize = 4;

/// All memory the stack uses. No heap: sockets and their buffers are carved
/// out of this one struct, which the caller places in a `static` (the process
/// image) or leaks (host tests).
pub struct StackStorage {
    sockets: [SocketStorage<'static>; SOCKET_SLOTS],
    icmp_rx_meta: [icmp::PacketMetadata; 4],
    icmp_rx_data: [u8; 512],
    icmp_tx_meta: [icmp::PacketMetadata; 4],
    icmp_tx_data: [u8; 512],
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
    /// Fixed address, prefix length and default gateway, applied at
    /// construction. Used until the DHCP client (Phase 2) lands and kept as
    /// the fallback for networks without DHCP.
    Static {
        /// Interface address.
        ip: [u8; 4],
        /// Prefix length (24 for 10.0.2.0/24).
        prefix: u8,
        /// Default gateway.
        gateway: [u8; 4],
    },
}

/// Something the stack tells its owner about. The owner logs it or acts on
/// it; the stack itself has no output channel (it cannot print).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetEvent {
    /// The interface has an address (static configuration applied).
    LinkConfigured {
        /// Interface address.
        ip: [u8; 4],
        /// Prefix length.
        prefix: u8,
        /// Default gateway, if any.
        gateway: Option<[u8; 4]>,
    },
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
}

/// Why `ping` refused to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingError {
    /// A previous request is still outstanding (one at a time for now).
    Busy,
    /// The ICMP transmit buffer is full.
    NoBuffer,
}

#[derive(Clone, Copy)]
struct OutstandingPing {
    seq: u16,
    sent_ns: u64,
}

// ---------------------------------------------------------------------------
// The stack
// ---------------------------------------------------------------------------

/// The Netstack: one Ethernet interface, an ICMP socket, and the small API
/// the service loop drives. Call `poll` regularly (it is what moves frames);
/// everything else only queues work for the next `poll`.
pub struct NetStack<IO: FrameIo> {
    device: FrameDevice<IO>,
    iface: Interface,
    sockets: SocketSet<'static>,
    icmp: SocketHandle,
    ping: Option<OutstandingPing>,
    pending_configured: Option<NetEvent>,
}

/// Converts the process clock (nanoseconds) to smoltcp's `Instant`.
pub fn instant_from_ns(now_ns: u64) -> Instant {
    Instant::from_micros((now_ns / 1_000) as i64)
}

impl<IO: FrameIo> NetStack<IO> {
    /// Builds the stack over `io` with hardware address `mac`.
    pub fn new(storage: &'static mut StackStorage, io: IO, mac: [u8; 6], mode: AddrMode, now_ns: u64) -> Self {
        let StackStorage { sockets, icmp_rx_meta, icmp_rx_data, icmp_tx_meta, icmp_tx_data } = storage;

        let mut device = FrameDevice::new(io);
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        // Not cryptographic: seeds smoltcp's source ports / ARP jitter. Mixing
        // the MAC in keeps two VMs booted at the same instant apart.
        config.random_seed = now_ns ^ u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0x5A, 0xA5]);
        let iface = Interface::new(config, &mut device, instant_from_ns(now_ns));

        let mut socket_set = SocketSet::new(&mut sockets[..]);
        let icmp_socket = icmp::Socket::new(
            icmp::PacketBuffer::new(&mut icmp_rx_meta[..], &mut icmp_rx_data[..]),
            icmp::PacketBuffer::new(&mut icmp_tx_meta[..], &mut icmp_tx_data[..]),
        );
        let icmp = socket_set.add(icmp_socket);
        socket_set.get_mut::<icmp::Socket>(icmp).bind(icmp::Endpoint::Ident(PING_IDENT)).ok();

        let mut stack = Self { device, iface, sockets: socket_set, icmp, ping: None, pending_configured: None };
        stack.apply_mode(mode);
        stack
    }

    fn apply_mode(&mut self, mode: AddrMode) {
        match mode {
            AddrMode::Static { ip, prefix, gateway } => {
                let addr = Ipv4Address::new(ip[0], ip[1], ip[2], ip[3]);
                self.iface.update_ip_addrs(|addrs| {
                    addrs.clear();
                    let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(addr), prefix));
                });
                let gw = Ipv4Address::new(gateway[0], gateway[1], gateway[2], gateway[3]);
                let _ = self.iface.routes_mut().add_default_ipv4_route(gw);
                self.pending_configured =
                    Some(NetEvent::LinkConfigured { ip, prefix, gateway: Some(gateway) });
            }
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
        let addr = IpAddress::Ipv4(Ipv4Address::new(dst[0], dst[1], dst[2], dst[3]));
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

    /// Runs the stack once: receive queued frames, run protocol timers,
    /// transmit whatever is due, then report events through `on_event`.
    /// Returns `true` if any frame moved (the caller may poll again at once
    /// instead of sleeping).
    pub fn poll(&mut self, now_ns: u64, on_event: &mut dyn FnMut(NetEvent)) -> bool {
        if let Some(ev) = self.pending_configured.take() {
            on_event(ev);
        }
        let now = instant_from_ns(now_ns);
        let moved = matches!(self.iface.poll(now, &mut self.device, &mut self.sockets), PollResult::SocketStateChanged);
        self.collect_ping(now_ns, on_event);
        moved
    }

    fn collect_ping(&mut self, now_ns: u64, on_event: &mut dyn FnMut(NetEvent)) {
        let now_ms = (now_ns / 1_000_000) as i64;
        let checksum = self.device.capabilities().checksum;
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
            on_event(NetEvent::PingReply { from: from.octets(), seq: seq_no, rtt_us });
        }
        if let Some(out) = self.ping {
            if now_ms - (out.sent_ns / 1_000_000) as i64 >= PING_TIMEOUT_MS {
                self.ping = None;
                on_event(NetEvent::PingTimeout { seq: out.seq });
            }
        }
    }

    /// Milliseconds until the stack next needs a `poll` (`None` = nothing
    /// scheduled; use the caller's idle interval).
    pub fn poll_delay_ms(&mut self, now_ns: u64) -> Option<u64> {
        self.iface.poll_delay(instant_from_ns(now_ns), &self.sockets).map(|d| d.total_millis())
    }
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;
