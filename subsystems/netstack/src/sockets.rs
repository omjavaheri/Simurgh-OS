//! ============================================================================
//! sockets.rs
//!
//! Purpose: the socket layer of Netstack - a bounded, heap-free table of
//! logical sockets (stream/TCP, datagram/UDP, raw ICMP) on top of smoltcp's
//! sockets, with the operations a BSD-style API needs: open, bind, listen
//! (with a real backlog), accept, connect, send/recv (and sendto/recvfrom),
//! shutdown, close, options and readiness. It is deliberately independent of
//! any transport or IPC: the socket IPC API (a separate task) maps its
//! messages one-to-one onto the `NetStack::sock_*` methods below.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md Section 2.3 (user-
//! space TCP/IP). The capability model of a socket (who may open/bind/listen,
//! and the per-socket rights) is an OPEN design question recorded in
//! `docs/internet-plan.md` (TODO(spec) 4); this file has no security policy.
//!
//! Position in the system: an `impl` block of `NetStack` (stack.rs); the
//! table is polled by `NetStack::poll` (`socket_housekeeping`).
//!
//! Design notes:
//! - All calls are NON-BLOCKING and return `SockError::WouldBlock` when the
//!   operation cannot make progress. Blocking with a timeout (SO_RCVTIMEO,
//!   SO_SNDTIMEO, connect timeout) is the caller's loop over `sock_events`;
//!   the option values live here (`SockOpts`) so one place owns them.
//! - smoltcp has no listen backlog (a listening TCP socket accepts exactly one
//!   connection). A listener with backlog `n` therefore owns `n` smoltcp
//!   sockets in LISTEN on the same port; `accept` hands an established one to
//!   a new logical socket and re-arms a fresh listener in its place.
//! - smoltcp does not check port conflicts; `port_in_use` does (with
//!   SO_REUSEADDR semantics).
//! - Dual-stack: a socket bound to the unspecified address accepts/receives
//!   both IPv4 and IPv6 (smoltcp matches a `None` listen address against
//!   either version). Loopback (127.0.0.1, ::1) is handled by `FrameDevice`.
//! - Sockets are pre-created at start-up (their buffers are static); "opening"
//!   claims a pool slot, "closing" releases it once the TCP connection is
//!   gone (closing connections linger as zombies until then).
//!
//! Safety/invariants: no `unsafe`, no heap. A `SockId` is an index; stale ids
//! are detected because closed slots are marked unused.
//! ============================================================================

use smoltcp::iface::SocketHandle;
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::time::Duration;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Icmpv4Packet, Icmpv6Packet};

use crate::stack::{FrameIo, NetStack};

/// TCP sockets in the pool (each has its own static buffers).
pub const TCP_SOCKETS: usize = 16;
/// UDP sockets in the pool.
pub const UDP_SOCKETS: usize = 16;
/// Raw ICMP sockets in the pool.
pub const ICMP_SOCKETS: usize = 4;
/// Logical sockets the table can hold (open sockets of any kind; accepted
/// connections count too).
pub const MAX_SOCKS: usize = 40;
/// Longest listen backlog (smoltcp sockets a listener may own at once).
pub const MAX_BACKLOG: usize = 4;

/// TCP receive buffer per socket. 64 KiB is the largest window without
/// window scaling; smoltcp negotiates a scale factor for anything above it,
/// so this size already exercises RFC 7323 scaling (factor 1 -> 128 KiB
/// windows are not possible with 64 KiB, but the option is negotiated so the
/// peer's scaled windows are understood).
pub const TCP_RX_BUF: usize = 65_536;
/// TCP send buffer per socket.
pub const TCP_TX_BUF: usize = 32_768;
/// UDP payload buffer (each direction) per socket.
pub const UDP_BUF: usize = 8_192;
/// UDP datagrams buffered (each direction) per socket.
pub const UDP_PACKETS: usize = 8;
/// Raw ICMP payload buffer (each direction) per socket.
pub const ICMP_BUF: usize = 2_048;
/// Raw ICMP messages buffered (each direction) per socket.
pub const ICMP_PACKETS: usize = 4;

/// First ephemeral port (RFC 6335 dynamic range).
pub const EPHEMERAL_FIRST: u16 = 49_152;
/// Connection attempts give up after this long (SYN retransmissions with
/// backoff run inside it).
pub const CONNECT_TIMEOUT_NS: u64 = 20_000_000_000;
/// A closed stream socket whose TCP connection has not ended after this long
/// is aborted so its pool slot is freed.
pub const ZOMBIE_TIMEOUT_NS: u64 = 60_000_000_000;
/// ICMP identifier reserved for the stack's own ping (`stack::PING_IDENT`);
/// user sockets cannot bind it.
const RESERVED_ICMP_IDENT: u16 = crate::stack::PING_IDENT;

/// A socket handle for API callers: an index into the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockId(pub u8);

/// Socket kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockType {
    /// Reliable byte stream (TCP).
    Stream,
    /// Datagrams (UDP).
    Dgram,
    /// ICMP/ICMPv6 messages (raw ICMP): send a message, the stack fills in the
    /// checksum; receive whole messages with their sender.
    RawIcmp,
}

/// Why a socket call failed. Maps 1:1 onto errno-style codes in the IPC layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockError {
    /// No such (open) socket.
    BadSocket,
    /// The operation is not valid in the socket's current state.
    InvalidState,
    /// The operation is not valid for this socket type.
    NotSupported,
    /// No free socket or buffer slot.
    NoBuffers,
    /// The address/port is already bound by another socket.
    AddrInUse,
    /// The address is not one of this host's addresses.
    AddrNotAvailable,
    /// Not connected (stream) or no default peer (datagram).
    NotConnected,
    /// Already connected or connecting.
    AlreadyConnected,
    /// The operation cannot make progress now (try again after `sock_events`).
    WouldBlock,
    /// The peer refused the connection (RST in reply to SYN).
    ConnectionRefused,
    /// The connection was reset by the peer.
    ConnectionReset,
    /// The connection attempt timed out.
    TimedOut,
    /// The message is larger than the socket can carry.
    MessageSize,
    /// No route to the destination or an unusable address.
    Unreachable,
    /// The write side is shut down / the peer is gone.
    BrokenPipe,
    /// Bad argument (port 0 where a port is needed, unspecified peer, ...).
    InvalidArgument,
}

/// Coarse socket state for `sock_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockState {
    /// Freshly opened.
    Unbound,
    /// Bound to a local address/port.
    Bound,
    /// Stream socket accepting connections.
    Listening,
    /// Stream connect in progress.
    Connecting,
    /// Stream connected, or datagram/raw socket with a default peer.
    Connected,
    /// Stream: the peer closed its side (reads drain then return EOF).
    PeerClosed,
    /// The connection ended (reset, refused, timed out); `sock_take_error`
    /// gives the reason.
    Failed,
}

/// What a socket can do right now (poll/select interest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Readiness {
    /// Data (or a datagram) can be read; for a stream also true at EOF.
    pub readable: bool,
    /// Data can be written without blocking.
    pub writable: bool,
    /// A listener has an established connection to accept.
    pub acceptable: bool,
    /// A stream connect has completed (the socket is `Connected`).
    pub connected: bool,
    /// The peer closed or the connection ended.
    pub hangup: bool,
    /// An asynchronous error is pending (`sock_take_error`).
    pub error: bool,
}

/// Socket options (setsockopt/getsockopt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SockOpt {
    /// SO_REUSEADDR: allow binding a port another socket has bound, as long
    /// as neither is listening. Off by default.
    ReuseAddr(bool),
    /// TCP_NODELAY: disable Nagle's algorithm. Off by default.
    NoDelay(bool),
    /// SO_KEEPALIVE with the probe interval in seconds (`None` = off).
    KeepAlive(Option<u32>),
    /// SO_BROADCAST (datagram sockets may send to broadcast addresses). Not
    /// enforced by smoltcp; stored for the API.
    Broadcast(bool),
    /// IP_TTL / IPV6_UNICAST_HOPS (`None` = stack default 64).
    Ttl(Option<u8>),
    /// SO_RCVTIMEO in milliseconds (`None` = wait forever). Applied by the
    /// blocking layer, not here.
    RecvTimeoutMs(Option<u32>),
    /// SO_SNDTIMEO in milliseconds; likewise applied by the blocking layer.
    SendTimeoutMs(Option<u32>),
    /// O_NONBLOCK; likewise a flag for the blocking layer.
    NonBlocking(bool),
    /// TCP user timeout in milliseconds: an established connection with
    /// unacknowledged data is aborted after this long (`None` = never).
    TcpTimeoutMs(Option<u32>),
    /// TCP congestion control.
    Congestion(Congestion),
}

/// TCP congestion control algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    /// No congestion control (window limited only by the peer).
    None,
    /// Reno (RFC 5681).
    Reno,
    /// CUBIC (RFC 8312). The default.
    Cubic,
}

/// The stored option values of one socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockOpts {
    /// SO_REUSEADDR.
    pub reuse_addr: bool,
    /// TCP_NODELAY.
    pub nodelay: bool,
    /// Keep-alive interval, seconds.
    pub keepalive_s: Option<u32>,
    /// SO_BROADCAST.
    pub broadcast: bool,
    /// Hop limit.
    pub ttl: Option<u8>,
    /// SO_RCVTIMEO, ms.
    pub recv_timeout_ms: Option<u32>,
    /// SO_SNDTIMEO, ms.
    pub send_timeout_ms: Option<u32>,
    /// O_NONBLOCK.
    pub nonblocking: bool,
    /// TCP user timeout, ms.
    pub tcp_timeout_ms: Option<u32>,
    /// Congestion control.
    pub congestion: Congestion,
}

impl SockOpts {
    /// Defaults: everything off, CUBIC, blocking.
    pub const DEFAULT: SockOpts = SockOpts {
        reuse_addr: false,
        nodelay: false,
        keepalive_s: None,
        broadcast: false,
        ttl: None,
        recv_timeout_ms: None,
        send_timeout_ms: None,
        nonblocking: false,
        tcp_timeout_ms: None,
        congestion: Congestion::Cubic,
    };

    fn set(&mut self, o: SockOpt) {
        match o {
            SockOpt::ReuseAddr(v) => self.reuse_addr = v,
            SockOpt::NoDelay(v) => self.nodelay = v,
            SockOpt::KeepAlive(v) => self.keepalive_s = v,
            SockOpt::Broadcast(v) => self.broadcast = v,
            SockOpt::Ttl(v) => self.ttl = v,
            SockOpt::RecvTimeoutMs(v) => self.recv_timeout_ms = v,
            SockOpt::SendTimeoutMs(v) => self.send_timeout_ms = v,
            SockOpt::NonBlocking(v) => self.nonblocking = v,
            SockOpt::TcpTimeoutMs(v) => self.tcp_timeout_ms = v,
            SockOpt::Congestion(v) => self.congestion = v,
        }
    }

    /// The current value of the option kind `o` names (its payload ignored).
    pub fn get(&self, o: SockOpt) -> SockOpt {
        match o {
            SockOpt::ReuseAddr(_) => SockOpt::ReuseAddr(self.reuse_addr),
            SockOpt::NoDelay(_) => SockOpt::NoDelay(self.nodelay),
            SockOpt::KeepAlive(_) => SockOpt::KeepAlive(self.keepalive_s),
            SockOpt::Broadcast(_) => SockOpt::Broadcast(self.broadcast),
            SockOpt::Ttl(_) => SockOpt::Ttl(self.ttl),
            SockOpt::RecvTimeoutMs(_) => SockOpt::RecvTimeoutMs(self.recv_timeout_ms),
            SockOpt::SendTimeoutMs(_) => SockOpt::SendTimeoutMs(self.send_timeout_ms),
            SockOpt::NonBlocking(_) => SockOpt::NonBlocking(self.nonblocking),
            SockOpt::TcpTimeoutMs(_) => SockOpt::TcpTimeoutMs(self.tcp_timeout_ms),
            SockOpt::Congestion(_) => SockOpt::Congestion(self.congestion),
        }
    }
}

/// Which half of a stream to shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shutdown {
    /// No more reads (further reads return EOF).
    Read,
    /// No more writes (sends FIN after buffered data).
    Write,
    /// Both.
    Both,
}

/// One received datagram's sender (`sock_recvfrom`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvFrom {
    /// Bytes copied into the caller's buffer.
    pub len: usize,
    /// Sender.
    pub from: IpEndpoint,
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    Fresh,
    Bound,
    Listening,
    Connecting,
    Connected,
    Failed,
}

const NONE: u8 = u8::MAX;

#[derive(Clone, Copy)]
struct Sock {
    used: bool,
    ty: SockType,
    /// Index into the pool of its type (`NONE` for a listener: it owns
    /// `listen_slots` instead).
    pool: u8,
    st: St,
    bound_addr: Option<IpAddress>,
    bound_port: u16,
    peer: Option<IpEndpoint>,
    opts: SockOpts,
    /// TCP pool indices of a listener's smoltcp sockets (`NONE` = empty).
    listen_slots: [u8; MAX_BACKLOG],
    backlog: u8,
    err: Option<SockError>,
    connect_deadline_ns: u64,
    shut_rd: bool,
    /// The connection went through an orderly close (FIN seen or sent), so a
    /// later CLOSED state is a normal end, not a reset.
    clean: bool,
}

impl Sock {
    const EMPTY: Sock = Sock {
        used: false,
        ty: SockType::Stream,
        pool: NONE,
        st: St::Fresh,
        bound_addr: None,
        bound_port: 0,
        peer: None,
        opts: SockOpts::DEFAULT,
        listen_slots: [NONE; MAX_BACKLOG],
        backlog: 0,
        err: None,
        connect_deadline_ns: 0,
        shut_rd: false,
        clean: false,
    };
}

/// Ownership of one pooled smoltcp socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pool {
    Free,
    /// Owned by logical socket `n`.
    Owned(u8),
    /// A listener's smoltcp socket (logical socket `n`).
    Listen(u8),
    /// The logical socket is gone but the TCP connection is still closing.
    Zombie,
}

/// The socket table (all state; the smoltcp sockets themselves live in the
/// stack's `SocketSet`, referenced by handle).
pub struct SocketTable {
    socks: [Sock; MAX_SOCKS],
    tcp_h: [SocketHandle; TCP_SOCKETS],
    tcp_pool: [Pool; TCP_SOCKETS],
    udp_h: [SocketHandle; UDP_SOCKETS],
    udp_pool: [Pool; UDP_SOCKETS],
    icmp_h: [SocketHandle; ICMP_SOCKETS],
    icmp_pool: [Pool; ICMP_SOCKETS],
    /// The identifier each raw-ICMP smoltcp socket was first bound to: smoltcp
    /// has no way to unbind an ICMP socket, so a slot keeps its identifier for
    /// good and is reused by later sockets binding the same one.
    icmp_bound: [Option<u16>; ICMP_SOCKETS],
    /// When a lingering (zombie) TCP socket is force-closed.
    zombie_deadline_ns: [u64; TCP_SOCKETS],
    next_ephemeral: u16,
}

impl SocketTable {
    /// Builds the table over the pre-created smoltcp sockets.
    pub fn new(
        tcp_h: [SocketHandle; TCP_SOCKETS],
        udp_h: [SocketHandle; UDP_SOCKETS],
        icmp_h: [SocketHandle; ICMP_SOCKETS],
        seed: u64,
    ) -> Self {
        Self {
            socks: [Sock::EMPTY; MAX_SOCKS],
            tcp_h,
            tcp_pool: [Pool::Free; TCP_SOCKETS],
            udp_h,
            udp_pool: [Pool::Free; UDP_SOCKETS],
            icmp_h,
            icmp_pool: [Pool::Free; ICMP_SOCKETS],
            icmp_bound: [None; ICMP_SOCKETS],
            zombie_deadline_ns: [0; TCP_SOCKETS],
            next_ephemeral: EPHEMERAL_FIRST + (seed % 16_384) as u16,
        }
    }

    /// Open logical sockets (statistics for the status page).
    pub fn open_count(&self) -> usize {
        self.socks.iter().filter(|s| s.used).count()
    }

    /// Open sockets of one kind.
    pub fn open_count_of(&self, ty: SockType) -> usize {
        self.socks.iter().filter(|s| s.used && s.ty == ty).count()
    }

    fn free_sock(&self) -> Option<u8> {
        self.socks.iter().position(|s| !s.used).map(|i| i as u8)
    }

    fn alloc_tcp(&mut self, owner: u8, listen: bool) -> Option<u8> {
        let i = self.tcp_pool.iter().position(|p| *p == Pool::Free)?;
        self.tcp_pool[i] = if listen { Pool::Listen(owner) } else { Pool::Owned(owner) };
        Some(i as u8)
    }

    fn alloc_pool(&mut self, ty: SockType, owner: u8) -> Option<u8> {
        match ty {
            SockType::Stream => self.alloc_tcp(owner, false),
            SockType::Dgram => {
                let i = self.udp_pool.iter().position(|p| *p == Pool::Free)?;
                self.udp_pool[i] = Pool::Owned(owner);
                Some(i as u8)
            }
            // Raw ICMP claims its smoltcp socket at bind time (see `claim_icmp`).
            SockType::RawIcmp => Some(NONE),
        }
    }

    /// A free raw-ICMP slot for identifier `ident`: one already bound to it, else
    /// one never bound.
    fn claim_icmp(&self, ident: u16) -> Option<u8> {
        let free = |i: usize| self.icmp_pool[i] == Pool::Free;
        (0..ICMP_SOCKETS)
            .find(|&i| free(i) && self.icmp_bound[i] == Some(ident))
            .or_else(|| (0..ICMP_SOCKETS).find(|&i| free(i) && self.icmp_bound[i].is_none()))
            .map(|i| i as u8)
    }

    fn get(&self, id: SockId) -> Result<&Sock, SockError> {
        match self.socks.get(id.0 as usize) {
            Some(s) if s.used => Ok(s),
            _ => Err(SockError::BadSocket),
        }
    }

    fn get_mut(&mut self, id: SockId) -> Result<&mut Sock, SockError> {
        match self.socks.get_mut(id.0 as usize) {
            Some(s) if s.used => Ok(s),
            _ => Err(SockError::BadSocket),
        }
    }

    fn addrs_overlap(a: Option<IpAddress>, b: Option<IpAddress>) -> bool {
        match (a, b) {
            (Some(x), Some(y)) => x == y,
            _ => true,
        }
    }

    /// Is `port` bound by a socket that would conflict with `me` binding
    /// `(addr, port)`? Two sockets may share a port when both set
    /// SO_REUSEADDR and neither listens; accepted/connected sockets never
    /// conflict (they are identified by their 4-tuple, which smoltcp checks).
    fn port_in_use(&self, me: usize, ty: SockType, addr: Option<IpAddress>, port: u16, reuse: bool) -> bool {
        self.socks.iter().enumerate().any(|(i, s)| {
            i != me
                && s.used
                && s.ty == ty
                && s.bound_port == port
                && matches!(s.st, St::Bound | St::Listening | St::Connecting | St::Connected)
                && (s.st == St::Bound || s.st == St::Listening || ty != SockType::Stream)
                && Self::addrs_overlap(s.bound_addr, addr)
                && !(reuse && s.opts.reuse_addr && s.st != St::Listening)
        })
    }

    fn ephemeral_port(&mut self, me: usize, ty: SockType, addr: Option<IpAddress>) -> Option<u16> {
        for _ in 0..(65_536 - EPHEMERAL_FIRST as u32) {
            let p = self.next_ephemeral;
            self.next_ephemeral = if p == u16::MAX { EPHEMERAL_FIRST } else { p + 1 };
            let taken = self.port_in_use(me, ty, addr, p, false)
                // A connected socket's local port is also unavailable for
                // reuse as an ephemeral port while it lives.
                || self.socks.iter().enumerate().any(|(i, s)| i != me && s.used && s.ty == ty && s.bound_port == p);
            if !taken {
                return Some(p);
            }
        }
        None
    }
}

fn is_loopback(a: &IpAddress) -> bool {
    match a {
        IpAddress::Ipv4(v) => v.octets()[0] == 127,
        IpAddress::Ipv6(v) => v.octets() == crate::ndp_wire::LOOPBACK,
    }
}

fn loopback_for(a: &IpAddress) -> IpAddress {
    match a {
        IpAddress::Ipv4(_) => IpAddress::v4(127, 0, 0, 1),
        IpAddress::Ipv6(_) => IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(crate::ndp_wire::LOOPBACK)),
    }
}

fn dur_s(s: u32) -> Duration {
    Duration::from_secs(s as u64)
}

impl<IO: FrameIo> NetStack<IO> {
    fn tcp_sock(&mut self, pool: u8) -> &mut tcp::Socket<'static> {
        let h = self.table.tcp_h[pool as usize];
        self.sockets.get_mut::<tcp::Socket>(h)
    }

    fn udp_sock(&mut self, pool: u8) -> &mut udp::Socket<'static> {
        let h = self.table.udp_h[pool as usize];
        self.sockets.get_mut::<udp::Socket>(h)
    }

    fn icmp_sock(&mut self, pool: u8) -> &mut icmp::Socket<'static> {
        let h = self.table.icmp_h[pool as usize];
        self.sockets.get_mut::<icmp::Socket>(h)
    }

    /// Applies the stored options to a pooled TCP socket.
    fn apply_tcp_opts(&mut self, pool: u8, o: SockOpts) {
        let s = self.tcp_sock(pool);
        s.set_nagle_enabled(!o.nodelay);
        s.set_keep_alive(o.keepalive_s.map(dur_s));
        s.set_hop_limit(o.ttl);
        s.set_timeout(o.tcp_timeout_ms.map(|ms| Duration::from_millis(ms as u64)));
        s.set_congestion_control(match o.congestion {
            Congestion::None => tcp::CongestionControl::None,
            Congestion::Reno => tcp::CongestionControl::Reno,
            Congestion::Cubic => tcp::CongestionControl::Cubic,
        });
        // TCP timestamps (RFC 7323) are deliberately NOT enabled: smoltcp 0.12
        // builds data segments of a full MSS and then adds the 12-byte timestamp
        // option on top, so every full segment exceeds the MTU by 12 bytes and
        // gets IP-fragmented (and the peer's reassembly makes throughput
        // collapse). Without timestamps segments are exactly 1500 bytes. The
        // cost: no RTTM samples on retransmitted data and no PAWS protection.
        // TODO(spec): revisit when smoltcp accounts for options in the MSS.
        s.set_tsval_generator(None);
    }

    fn apply_opts(&mut self, id: SockId) {
        let Ok(s) = self.table.get(id) else { return };
        let (ty, pool, o, slots) = (s.ty, s.pool, s.opts, s.listen_slots);
        match ty {
            SockType::Stream => {
                if pool != NONE {
                    self.apply_tcp_opts(pool, o);
                }
                for p in slots.into_iter().filter(|p| *p != NONE) {
                    self.apply_tcp_opts(p, o);
                }
            }
            SockType::Dgram => {
                if pool != NONE {
                    self.udp_sock(pool).set_hop_limit(o.ttl);
                }
            }
            SockType::RawIcmp => {
                if pool != NONE {
                    self.icmp_sock(pool).set_hop_limit(o.ttl);
                }
            }
        }
    }

    /// True for an address this host answers to: unspecified is handled by
    /// the caller; loopback and every configured address qualify.
    fn is_local_addr(&self, a: &IpAddress) -> bool {
        is_loopback(a) || self.iface.has_ip_addr(*a)
    }

    // ---- lifecycle --------------------------------------------------------

    /// Opens a socket. `NoBuffers` when the table or the pool of that kind
    /// is exhausted.
    pub fn sock_open(&mut self, ty: SockType) -> Result<SockId, SockError> {
        let idx = self.table.free_sock().ok_or(SockError::NoBuffers)?;
        let pool = self.table.alloc_pool(ty, idx).ok_or(SockError::NoBuffers)?;
        self.table.socks[idx as usize] = Sock { used: true, ty, pool, ..Sock::EMPTY };
        // Make sure the pooled smoltcp socket starts clean.
        match ty {
            SockType::Stream => self.tcp_sock(pool).abort(),
            SockType::Dgram => self.udp_sock(pool).close(),
            SockType::RawIcmp => {}
        }
        let id = SockId(idx);
        self.apply_opts(id);
        Ok(id)
    }

    /// Sets an option. Takes effect immediately on the smoltcp socket(s).
    pub fn sock_setopt(&mut self, id: SockId, opt: SockOpt) -> Result<(), SockError> {
        self.table.get_mut(id)?.opts.set(opt);
        self.apply_opts(id);
        Ok(())
    }

    /// Reads an option (`opt`'s payload is ignored, only its kind matters).
    pub fn sock_getopt(&self, id: SockId, opt: SockOpt) -> Result<SockOpt, SockError> {
        Ok(self.table.get(id)?.opts.get(opt))
    }

    /// Binds to `addr` (`None` = any address, both IP versions) and `port`
    /// (`0` = pick an ephemeral port). Returns the port. For raw ICMP sockets
    /// the "port" is the ICMP identifier that replies are matched on.
    pub fn sock_bind(&mut self, id: SockId, addr: Option<IpAddress>, port: u16) -> Result<u16, SockError> {
        let me = id.0 as usize;
        let s = *self.table.get(id)?;
        if s.st != St::Fresh {
            return Err(SockError::InvalidState);
        }
        if let Some(a) = addr {
            if a.is_unspecified() {
                return self.sock_bind(id, None, port);
            }
            if s.ty == SockType::Dgram && (a.is_multicast() || a.is_broadcast()) {
                // Allowed: receiving multicast/broadcast datagrams.
            } else if !self.is_local_addr(&a) {
                return Err(SockError::AddrNotAvailable);
            }
        }
        let port = if port == 0 {
            self.table.ephemeral_port(me, s.ty, addr).ok_or(SockError::NoBuffers)?
        } else {
            port
        };
        if s.ty == SockType::RawIcmp && port == RESERVED_ICMP_IDENT {
            return Err(SockError::AddrInUse);
        }
        if self.table.port_in_use(me, s.ty, addr, port, s.opts.reuse_addr) {
            return Err(SockError::AddrInUse);
        }
        match s.ty {
            SockType::Stream => {}
            SockType::Dgram => {
                self.udp_sock(s.pool).bind(IpListenEndpoint { addr, port }).map_err(|_| SockError::InvalidState)?;
            }
            SockType::RawIcmp => {
                let pool = self.table.claim_icmp(port).ok_or(SockError::NoBuffers)?;
                if self.table.icmp_bound[pool as usize].is_none() {
                    self.icmp_sock(pool).bind(icmp::Endpoint::Ident(port)).map_err(|_| SockError::InvalidState)?;
                    self.table.icmp_bound[pool as usize] = Some(port);
                }
                self.table.icmp_pool[pool as usize] = Pool::Owned(id.0);
                self.table.socks[me].pool = pool;
            }
        }
        let sm = self.table.get_mut(id)?;
        sm.bound_addr = addr;
        sm.bound_port = port;
        sm.st = St::Bound;
        Ok(port)
    }

    /// Binds to an ephemeral port on the unspecified address if not bound yet.
    fn ensure_bound(&mut self, id: SockId) -> Result<(), SockError> {
        if self.table.get(id)?.st == St::Fresh {
            self.sock_bind(id, None, 0)?;
        }
        Ok(())
    }

    /// Starts listening (stream sockets, must be bound). `backlog` (clamped to
    /// `1..=MAX_BACKLOG`) is how many connections may wait to be accepted:
    /// that many smoltcp sockets are put in LISTEN; fewer if the TCP pool is
    /// short (at least one is required).
    pub fn sock_listen(&mut self, id: SockId, backlog: u8) -> Result<(), SockError> {
        let s = *self.table.get(id)?;
        if s.ty != SockType::Stream {
            return Err(SockError::NotSupported);
        }
        if s.st != St::Bound {
            return Err(SockError::InvalidState);
        }
        let want = (backlog as usize).clamp(1, MAX_BACKLOG);
        let ep = IpListenEndpoint { addr: s.bound_addr, port: s.bound_port };
        // The socket's own pool slot becomes the first listen slot.
        let first = s.pool;
        self.table.tcp_pool[first as usize] = Pool::Listen(id.0);
        let mut slots = [NONE; MAX_BACKLOG];
        slots[0] = first;
        for slot in slots.iter_mut().take(want).skip(1) {
            if let Some(p) = self.table.alloc_tcp(id.0, true) {
                *slot = p;
            }
        }
        {
            let sm = self.table.get_mut(id)?;
            sm.pool = NONE;
            sm.listen_slots = slots;
            sm.backlog = want as u8;
            sm.st = St::Listening;
        }
        self.apply_opts(id);
        for p in slots.into_iter().filter(|p| *p != NONE) {
            self.tcp_sock(p).abort();
            self.tcp_sock(p).listen(ep).map_err(|_| SockError::InvalidState)?;
        }
        Ok(())
    }

    /// Takes an established connection off a listener: returns a NEW socket
    /// for it (inheriting the listener's options) and the peer's address.
    /// `WouldBlock` when none is ready.
    pub fn sock_accept(&mut self, id: SockId) -> Result<(SockId, IpEndpoint), SockError> {
        let s = *self.table.get(id)?;
        if s.st != St::Listening {
            return Err(SockError::InvalidState);
        }
        let ready = s.listen_slots.iter().position(|&p| {
            p != NONE
                && matches!(
                    self.sockets.get::<tcp::Socket>(self.table.tcp_h[p as usize]).state(),
                    tcp::State::Established | tcp::State::CloseWait | tcp::State::LastAck | tcp::State::FinWait1
                        | tcp::State::FinWait2 | tcp::State::Closing
                )
        });
        let Some(slot_i) = ready else { return Err(SockError::WouldBlock) };
        let child = self.table.free_sock().ok_or(SockError::NoBuffers)?;
        let pool = s.listen_slots[slot_i];
        let (local, remote) = {
            let t = self.tcp_sock(pool);
            (t.local_endpoint(), t.remote_endpoint())
        };
        let remote = remote.ok_or(SockError::InvalidState)?;
        self.table.tcp_pool[pool as usize] = Pool::Owned(child);
        self.table.socks[child as usize] = Sock {
            used: true,
            ty: SockType::Stream,
            pool,
            st: St::Connected,
            bound_addr: local.map(|e| e.addr),
            bound_port: local.map(|e| e.port).unwrap_or(s.bound_port),
            peer: Some(remote),
            opts: s.opts,
            ..Sock::EMPTY
        };
        self.table.socks[id.0 as usize].listen_slots[slot_i] = NONE;
        // Re-arm the listener with a fresh smoltcp socket.
        self.rearm_listener(id);
        Ok((SockId(child), remote))
    }

    /// Fills empty listen slots of listener `id` (up to its backlog) and
    /// re-listens on slots whose connection died before `accept`.
    fn rearm_listener(&mut self, id: SockId) {
        let Ok(s) = self.table.get(id).copied() else { return };
        if s.st != St::Listening {
            return;
        }
        let ep = IpListenEndpoint { addr: s.bound_addr, port: s.bound_port };
        for i in 0..s.backlog as usize {
            let cur = self.table.socks[id.0 as usize].listen_slots[i];
            if cur == NONE {
                if let Some(p) = self.table.alloc_tcp(id.0, true) {
                    self.table.socks[id.0 as usize].listen_slots[i] = p;
                    self.apply_tcp_opts(p, s.opts);
                    self.tcp_sock(p).abort();
                    let _ = self.tcp_sock(p).listen(ep);
                }
            } else if self.tcp_sock(cur).state() == tcp::State::Closed {
                // A half-open or established connection died before accept.
                let _ = self.tcp_sock(cur).listen(ep);
            }
        }
    }

    /// Starts a connection (stream) or sets the default peer (datagram/raw).
    /// For a stream the call returns at once; the socket is `Connecting` and
    /// becomes `Connected` (or `Failed`) as `poll` runs - watch
    /// `sock_events().connected`.
    pub fn sock_connect(&mut self, id: SockId, remote: IpEndpoint, now_ns: u64) -> Result<(), SockError> {
        let s = *self.table.get(id)?;
        if remote.addr.is_unspecified() || remote.port == 0 && s.ty != SockType::RawIcmp {
            return Err(SockError::InvalidArgument);
        }
        match s.ty {
            SockType::Stream => {
                match s.st {
                    St::Connecting | St::Connected => return Err(SockError::AlreadyConnected),
                    St::Listening | St::Failed => return Err(SockError::InvalidState),
                    _ => {}
                }
                self.ensure_bound(id)?;
                let s = *self.table.get(id)?;
                // Loopback destinations must use the loopback address as the
                // source, or the reply would be routed out of the wire.
                let local_addr = if is_loopback(&remote.addr) {
                    Some(loopback_for(&remote.addr))
                } else {
                    s.bound_addr
                };
                let local = IpListenEndpoint { addr: local_addr, port: s.bound_port };
                self.apply_tcp_opts(s.pool, s.opts);
                let cx = self.iface.context();
                let h = self.table.tcp_h[s.pool as usize];
                let sock = self.sockets.get_mut::<tcp::Socket>(h);
                sock.abort();
                sock.connect(cx, remote, local).map_err(|_| SockError::Unreachable)?;
                let sm = self.table.get_mut(id)?;
                sm.peer = Some(remote);
                sm.st = St::Connecting;
                sm.err = None;
                sm.connect_deadline_ns = now_ns + CONNECT_TIMEOUT_NS;
                Ok(())
            }
            SockType::Dgram | SockType::RawIcmp => {
                self.ensure_bound(id)?;
                let sm = self.table.get_mut(id)?;
                sm.peer = Some(remote);
                sm.st = St::Connected;
                Ok(())
            }
        }
    }

    /// Brings the logical state of a stream socket in line with its smoltcp
    /// socket (`Connecting` -> `Connected`/`Failed`, `Connected` -> `Failed`
    /// on reset).
    fn refresh(&mut self, id: SockId) {
        let Ok(s) = self.table.get(id).copied() else { return };
        if s.ty != SockType::Stream || s.pool == NONE {
            return;
        }
        let state = self.tcp_sock(s.pool).state();
        let sm = &mut self.table.socks[id.0 as usize];
        match (s.st, state) {
            (St::Connecting, tcp::State::Established | tcp::State::CloseWait) => sm.st = St::Connected,
            (St::Connecting, tcp::State::Closed) => {
                sm.st = St::Failed;
                if sm.err.is_none() {
                    sm.err = Some(SockError::ConnectionRefused);
                }
            }
            (St::Connected, tcp::State::Closed) => {
                // smoltcp has no separate RST flag: a socket that reaches
                // CLOSED without ever passing through an orderly-close state
                // (`clean`) was reset (or timed out).
                if !sm.clean && sm.err.is_none() {
                    sm.err = Some(SockError::ConnectionReset);
                }
                sm.st = St::Failed;
            }
            _ => {}
        }
        if matches!(
            state,
            tcp::State::CloseWait
                | tcp::State::LastAck
                | tcp::State::Closing
                | tcp::State::TimeWait
                | tcp::State::FinWait1
                | tcp::State::FinWait2
        ) {
            sm.clean = true;
        }
    }

    // ---- data -------------------------------------------------------------

    /// Sends on a connected socket. Stream: queues as many bytes as fit and
    /// returns the count (`WouldBlock` when the buffer is full). Datagram/raw:
    /// sends to the default peer (`NotConnected` if none).
    pub fn sock_send(&mut self, id: SockId, data: &[u8]) -> Result<usize, SockError> {
        self.refresh(id);
        let s = *self.table.get(id)?;
        match s.ty {
            SockType::Stream => {
                if let Some(e) = s.err {
                    return Err(e);
                }
                match s.st {
                    St::Connected => {}
                    St::Connecting => return Err(SockError::WouldBlock),
                    St::Failed => return Err(SockError::BrokenPipe),
                    _ => return Err(SockError::NotConnected),
                }
                if data.is_empty() {
                    return Ok(0);
                }
                let t = self.tcp_sock(s.pool);
                match t.send_slice(data) {
                    Ok(0) => Err(SockError::WouldBlock),
                    Ok(n) => Ok(n),
                    Err(_) => Err(SockError::BrokenPipe),
                }
            }
            SockType::Dgram | SockType::RawIcmp => {
                let peer = s.peer.ok_or(SockError::NotConnected)?;
                self.sock_sendto(id, data, peer)?;
                Ok(data.len())
            }
        }
    }

    /// Sends one datagram (or raw ICMP message) to `to`. An unbound socket is
    /// bound to an ephemeral port first.
    pub fn sock_sendto(&mut self, id: SockId, data: &[u8], to: IpEndpoint) -> Result<(), SockError> {
        let s = *self.table.get(id)?;
        match s.ty {
            SockType::Stream => Err(SockError::NotSupported),
            SockType::Dgram => {
                self.ensure_bound(id)?;
                let s = *self.table.get(id)?;
                if to.port == 0 || to.addr.is_unspecified() {
                    return Err(SockError::InvalidArgument);
                }
                if data.len() > UDP_BUF {
                    return Err(SockError::MessageSize);
                }
                let mut meta = udp::UdpMetadata::from(to);
                if is_loopback(&to.addr) {
                    meta.local_address = Some(loopback_for(&to.addr));
                }
                self.udp_sock(s.pool).send_slice(data, meta).map_err(|e| match e {
                    udp::SendError::BufferFull => SockError::WouldBlock,
                    udp::SendError::Unaddressable => SockError::Unreachable,
                })
            }
            SockType::RawIcmp => {
                self.ensure_bound(id)?;
                let s = *self.table.get(id)?;
                self.icmp_send(s.pool, data, to.addr)
            }
        }
    }

    /// Queues an ICMP/ICMPv6 message: copies `msg` and fixes its checksum
    /// (ICMPv4: over the message; ICMPv6: with the pseudo-header of the source
    /// address the stack will use).
    fn icmp_send(&mut self, pool: u8, msg: &[u8], dst: IpAddress) -> Result<(), SockError> {
        if msg.len() < 8 {
            return Err(SockError::InvalidArgument);
        }
        if msg.len() > ICMP_BUF {
            return Err(SockError::MessageSize);
        }
        let src6 = match dst {
            IpAddress::Ipv6(d) => Some(self.iface.get_source_address_ipv6(&d)),
            IpAddress::Ipv4(_) => None,
        };
        let sock = self.icmp_sock(pool);
        let buf = sock.send(msg.len(), dst).map_err(|e| match e {
            icmp::SendError::BufferFull => SockError::WouldBlock,
            icmp::SendError::Unaddressable => SockError::Unreachable,
        })?;
        buf.copy_from_slice(msg);
        match (dst, src6) {
            (IpAddress::Ipv4(_), _) => Icmpv4Packet::new_unchecked(&mut buf[..]).fill_checksum(),
            (IpAddress::Ipv6(d), Some(src)) => Icmpv6Packet::new_unchecked(&mut buf[..]).fill_checksum(&src, &d),
            _ => {}
        }
        Ok(())
    }

    /// Receives into `buf`. Stream: returns the bytes read; `Ok(0)` means
    /// end of stream (peer closed and all data read); `WouldBlock` when there
    /// is nothing yet. Datagram/raw: one message (truncated to `buf`).
    pub fn sock_recv(&mut self, id: SockId, buf: &mut [u8]) -> Result<usize, SockError> {
        Ok(self.sock_recvfrom(id, buf)?.len)
    }

    /// Like `sock_recv` but also reports the sender (a stream's peer).
    pub fn sock_recvfrom(&mut self, id: SockId, buf: &mut [u8]) -> Result<RecvFrom, SockError> {
        self.refresh(id);
        let s = *self.table.get(id)?;
        match s.ty {
            SockType::Stream => {
                let peer = s.peer.ok_or(SockError::NotConnected)?;
                if s.shut_rd {
                    return Ok(RecvFrom { len: 0, from: peer });
                }
                match s.st {
                    St::Connected | St::Failed | St::Connecting => {}
                    _ => return Err(SockError::NotConnected),
                }
                if s.st == St::Connecting {
                    return Err(SockError::WouldBlock);
                }
                let t = self.tcp_sock(s.pool);
                match t.recv_slice(buf) {
                    Ok(0) if buf.is_empty() => Ok(RecvFrom { len: 0, from: peer }),
                    Ok(0) => Err(SockError::WouldBlock),
                    Ok(n) => Ok(RecvFrom { len: n, from: peer }),
                    // Finished: the peer closed and everything was read.
                    Err(tcp::RecvError::Finished) => Ok(RecvFrom { len: 0, from: peer }),
                    Err(tcp::RecvError::InvalidState) => match s.err {
                        Some(e) => Err(e),
                        None => Err(SockError::NotConnected),
                    },
                }
            }
            SockType::Dgram => {
                if s.st == St::Fresh {
                    return Err(SockError::InvalidState);
                }
                match self.udp_sock(s.pool).recv_slice(buf) {
                    Ok((len, meta)) => Ok(RecvFrom { len, from: meta.endpoint }),
                    Err(udp::RecvError::Exhausted) => Err(SockError::WouldBlock),
                    Err(udp::RecvError::Truncated) => Err(SockError::MessageSize),
                }
            }
            SockType::RawIcmp => {
                if s.st == St::Fresh {
                    return Err(SockError::InvalidState);
                }
                match self.icmp_sock(s.pool).recv_slice(buf) {
                    Ok((len, addr)) => Ok(RecvFrom { len, from: IpEndpoint::new(addr, 0) }),
                    Err(icmp::RecvError::Exhausted) => Err(SockError::WouldBlock),
                    Err(icmp::RecvError::Truncated) => Err(SockError::MessageSize),
                }
            }
        }
    }

    /// Shuts down one or both directions of a stream.
    pub fn sock_shutdown(&mut self, id: SockId, how: Shutdown) -> Result<(), SockError> {
        self.refresh(id);
        let s = *self.table.get(id)?;
        if s.ty != SockType::Stream {
            return Err(SockError::NotSupported);
        }
        if !matches!(s.st, St::Connected | St::Failed) {
            return Err(SockError::NotConnected);
        }
        if matches!(how, Shutdown::Write | Shutdown::Both) {
            self.tcp_sock(s.pool).close();
            self.table.get_mut(id)?.clean = true;
        }
        if matches!(how, Shutdown::Read | Shutdown::Both) {
            self.table.get_mut(id)?.shut_rd = true;
        }
        Ok(())
    }

    /// Closes the socket. A stream connection is closed gracefully (FIN after
    /// buffered data; the smoltcp socket lingers until the handshake ends, up
    /// to its own timers); a listener aborts its pending connections.
    pub fn sock_close(&mut self, id: SockId) -> Result<(), SockError> {
        let s = *self.table.get(id)?;
        match s.ty {
            SockType::Stream => {
                if s.st == St::Listening {
                    for p in s.listen_slots.into_iter().filter(|p| *p != NONE) {
                        self.tcp_sock(p).abort();
                        self.table.tcp_pool[p as usize] = Pool::Free;
                    }
                } else if s.pool != NONE {
                    let unread = self.tcp_sock(s.pool).recv_queue() > 0;
                    let state = self.tcp_sock(s.pool).state();
                    if unread || matches!(state, tcp::State::SynSent | tcp::State::SynReceived | tcp::State::Closed) {
                        // Unread data or a half-open attempt: reset (RFC 1122
                        // 4.2.2.13 permits it) and free the slot at once.
                        self.tcp_sock(s.pool).abort();
                        self.table.tcp_pool[s.pool as usize] = Pool::Free;
                    } else {
                        self.tcp_sock(s.pool).close();
                        self.table.tcp_pool[s.pool as usize] = Pool::Zombie;
                        self.table.zombie_deadline_ns[s.pool as usize] = self.now_ns + ZOMBIE_TIMEOUT_NS;
                    }
                }
            }
            SockType::Dgram => {
                self.udp_sock(s.pool).close();
                self.table.udp_pool[s.pool as usize] = Pool::Free;
            }
            SockType::RawIcmp => {
                if s.pool != NONE {
                    // Drop anything still queued so the next owner starts clean.
                    let mut scratch = [0u8; 64];
                    while self.icmp_sock(s.pool).recv_slice(&mut scratch).is_ok() {}
                    self.table.icmp_pool[s.pool as usize] = Pool::Free;
                }
            }
        }
        self.table.socks[id.0 as usize] = Sock::EMPTY;
        Ok(())
    }

    // ---- queries ----------------------------------------------------------

    /// Coarse state (after syncing with the TCP state machine).
    pub fn sock_state(&mut self, id: SockId) -> Result<SockState, SockError> {
        self.refresh(id);
        let s = *self.table.get(id)?;
        Ok(match s.st {
            St::Fresh => SockState::Unbound,
            St::Bound => SockState::Bound,
            St::Listening => SockState::Listening,
            St::Connecting => SockState::Connecting,
            St::Failed => SockState::Failed,
            St::Connected => {
                if s.ty == SockType::Stream && !self.tcp_sock(s.pool).may_recv() {
                    SockState::PeerClosed
                } else {
                    SockState::Connected
                }
            }
        })
    }

    /// Poll/select interest.
    pub fn sock_events(&mut self, id: SockId) -> Result<Readiness, SockError> {
        self.refresh(id);
        let s = *self.table.get(id)?;
        let mut r = Readiness { error: s.err.is_some(), ..Readiness::default() };
        match s.ty {
            SockType::Stream => match s.st {
                St::Listening => {
                    r.acceptable = s.listen_slots.iter().any(|&p| {
                        p != NONE
                            && matches!(
                                self.sockets.get::<tcp::Socket>(self.table.tcp_h[p as usize]).state(),
                                tcp::State::Established | tcp::State::CloseWait | tcp::State::LastAck
                                    | tcp::State::FinWait1 | tcp::State::FinWait2 | tcp::State::Closing
                            )
                    });
                    r.readable = r.acceptable;
                }
                St::Connected | St::Failed | St::Connecting => {
                    let t = self.tcp_sock(s.pool);
                    let (can_recv, may_recv, can_send) = (t.can_recv(), t.may_recv(), t.can_send());
                    r.connected = s.st == St::Connected;
                    r.readable = can_recv || !may_recv && s.st != St::Connecting || s.shut_rd;
                    r.writable = can_send;
                    r.hangup = !may_recv && s.st != St::Connecting || s.st == St::Failed;
                    if s.st == St::Failed {
                        r.readable = true;
                        r.writable = true;
                        r.connected = false;
                    }
                }
                _ => {}
            },
            SockType::Dgram => {
                if s.st != St::Fresh {
                    let u = self.udp_sock(s.pool);
                    r.readable = u.can_recv();
                    r.writable = u.can_send();
                } else {
                    r.writable = true;
                }
                r.connected = s.st == St::Connected;
            }
            SockType::RawIcmp => {
                if s.st != St::Fresh {
                    let i = self.icmp_sock(s.pool);
                    r.readable = i.can_recv();
                    r.writable = i.can_send();
                } else {
                    r.writable = true;
                }
                r.connected = s.st == St::Connected;
            }
        }
        Ok(r)
    }

    /// Returns and clears the pending asynchronous error (SO_ERROR).
    pub fn sock_take_error(&mut self, id: SockId) -> Result<Option<SockError>, SockError> {
        self.refresh(id);
        Ok(self.table.get_mut(id)?.err.take())
    }

    /// Local endpoint (address may be unspecified when bound to "any").
    pub fn sock_local(&mut self, id: SockId) -> Result<Option<IpEndpoint>, SockError> {
        let s = *self.table.get(id)?;
        if s.ty == SockType::Stream && s.pool != NONE && s.st != St::Fresh && s.st != St::Bound {
            if let Some(e) = self.tcp_sock(s.pool).local_endpoint() {
                return Ok(Some(e));
            }
        }
        if s.st == St::Fresh {
            return Ok(None);
        }
        Ok(Some(IpEndpoint::new(
            s.bound_addr.unwrap_or(if matches!(s.peer.map(|p| p.addr), Some(IpAddress::Ipv6(_))) {
                IpAddress::Ipv6(smoltcp::wire::Ipv6Address::UNSPECIFIED)
            } else {
                IpAddress::v4(0, 0, 0, 0)
            }),
            s.bound_port,
        )))
    }

    /// Peer endpoint (connected stream, or a datagram socket's default peer).
    pub fn sock_peer(&self, id: SockId) -> Result<Option<IpEndpoint>, SockError> {
        Ok(self.table.get(id)?.peer)
    }

    /// Bytes waiting to be read (stream) / 0.
    pub fn sock_recv_queue(&mut self, id: SockId) -> Result<usize, SockError> {
        let s = *self.table.get(id)?;
        if s.ty == SockType::Stream && s.pool != NONE {
            Ok(self.tcp_sock(s.pool).recv_queue())
        } else {
            Ok(0)
        }
    }

    /// Bytes queued but not yet acknowledged (stream) / 0.
    pub fn sock_send_queue(&mut self, id: SockId) -> Result<usize, SockError> {
        let s = *self.table.get(id)?;
        if s.ty == SockType::Stream && s.pool != NONE {
            Ok(self.tcp_sock(s.pool).send_queue())
        } else {
            Ok(0)
        }
    }

    /// Open sockets, by kind (for the status page and tests).
    pub fn sock_counts(&self) -> (usize, usize, usize) {
        (
            self.table.open_count_of(SockType::Stream),
            self.table.open_count_of(SockType::Dgram),
            self.table.open_count_of(SockType::RawIcmp),
        )
    }

    // ---- housekeeping -----------------------------------------------------

    /// Periodic table maintenance, called from `poll`: times out connection attempts, re-arms listeners and
    /// releases pooled TCP sockets whose connections are gone.
    pub(crate) fn socket_housekeeping(&mut self, now_ns: u64) {
        for i in 0..MAX_SOCKS {
            let s = self.table.socks[i];
            if !s.used || s.ty != SockType::Stream {
                continue;
            }
            let id = SockId(i as u8);
            match s.st {
                St::Listening => self.rearm_listener(id),
                St::Connecting => {
                    self.refresh(id);
                    if self.table.socks[i].st == St::Connecting && now_ns >= s.connect_deadline_ns {
                        self.tcp_sock(s.pool).abort();
                        let sm = &mut self.table.socks[i];
                        sm.st = St::Failed;
                        sm.err = Some(SockError::TimedOut);
                    }
                }
                St::Connected => self.refresh(id),
                _ => {}
            }
        }
        // Reap zombies: a closed connection frees its pool slot when smoltcp
        // is done with it; TIME-WAIT is cut short (this stack never reuses a
        // 4-tuple within the wait: ephemeral ports rotate).
        for p in 0..TCP_SOCKETS {
            if self.table.tcp_pool[p] == Pool::Zombie {
                let st = self.tcp_sock(p as u8).state();
                // A peer that never finishes its side (FIN-WAIT-2 has no timer
                // in smoltcp) must not pin the slot forever.
                if matches!(st, tcp::State::Closed | tcp::State::TimeWait) || now_ns >= self.table.zombie_deadline_ns[p] {
                    self.tcp_sock(p as u8).abort();
                    self.table.tcp_pool[p] = Pool::Free;
                }
            }
        }
    }
}

#[cfg(test)]
impl<IO: FrameIo> NetStack<IO> {
    /// Test hook: the TCP pool index behind a stream socket.
    pub(crate) fn table_pool_of(&self, id: SockId) -> u8 {
        self.table.socks[id.0 as usize].pool
    }

    /// Test hook: the smoltcp handle of TCP pool slot `pool`.
    pub(crate) fn table_tcp_handle(&self, pool: u8) -> SocketHandle {
        self.table.tcp_h[pool as usize]
    }
}

#[cfg(test)]
impl<IO: FrameIo> NetStack<IO> {
    /// Test hook: aborts the smoltcp socket behind a stream socket (RST).
    pub(crate) fn table_abort_for_test(&mut self, id: SockId) {
        let pool = self.table.socks[id.0 as usize].pool;
        self.tcp_sock(pool).abort();
    }
}
