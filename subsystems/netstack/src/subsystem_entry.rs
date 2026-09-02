//! ============================================================================
//! subsystem_entry.rs — riscv64 / x86_64 / aarch64
//!
//! Note on this file's ONE architecture-conditional piece: same narrow,
//! documented exception `device-manager::subsystem_entry`'s and
//! `driver-virtio-net::subsystem_entry`'s own file headers explain —
//! `raw_syscall`'s job is issuing the raw syscall INSTRUCTION itself
//! (`ecall`/`int 0x80`/`svc #0`), an unavoidable ISA detail. Every other
//! line in this file is architecture-generic.
//!
//! Purpose: the FIRST subsystem process in this codebase that is an IPC
//! CLIENT of another U-mode process, not a server — `kernel_arch_glue`
//! previously drove `driver-virtio-net`'s own ARP-resolve/ICMP-echo demo
//! directly (its own doc comment on that file called this out as a
//! known MVP shortcut); this file is what replaces it: a real Netstack
//! process that issues genuine `sys::IPC_CALL`s (`SyscallOp::Call`,
//! `kernel_arch_glue::p2_ipc_call`'s own dispatch arm — already fully
//! generic, "whichever process issued this ecall, calling whichever cap
//! slot `a0` names": no new kernel-side opcode was needed for this).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.3 (Netstack
//! talks to the network device through a driver process + a capability
//! scoped to it — this file is that leg becoming real), §5.4 (ICMP echo
//! MVP acceptance demo).
//!
//! Position in the system: `kernel_arch_glue::spawn_netstack_service`
//! spawns this process via `spawn_process_from_elf`, AFTER `spawn_
//! virtio_net_driver` has already spawned + switched to the driver once
//! (so the driver has already reached its own first `Recv` by the time
//! this process's own first `IPC_CALL` needs the fast path — same
//! ordering rationale `spawn_virtio_blk_driver`'s own doc comment gives
//! for its own driver-vs-caller race). This process is granted a
//! DERIVED COPY of the driver's own `Endpoint` capability (landing at
//! slot 0), and has the driver's own RX and TX `SharedRegion`s pre-
//! mapped directly into ITS OWN address space (trusted bootstrap, same
//! "kernel-arch-glue builds the page table directly, no `Map` ceremony"
//! pattern every other subsystem spawn in this codebase already uses) —
//! see `driver_virtio_net::layout`'s own doc comment for the byte
//! layout inside them; this file duplicates the handful of offsets it
//! needs as local constants (`BUFFER_OFFSET`/`MESSAGE_OFFSET`/
//! `MAC_OFFSET`/`VIRTIO_NET_HDR_LEN`, "must stay numerically equal to
//! driver_virtio_net::layout::*") rather than taking on a cross-driver
//! crate dependency, matching this project's established "small numeric
//! constants duplicated with a sync comment" convention for VAs/offsets
//! everywhere else in this file's own sibling `subsystem_entry.rs`
//! files. A THIRD region — this process's own, freshly retyped, private
//! `SharedRegion` — carries the ARP/ICMP verdict `kernel_arch_glue::
//! netstack_status` reads back directly (physical pointer, kernel-side
//! — same "peek the shared region directly, no protocol field needed"
//! pattern `drv_net_probe_result`'s own MAC read already used before
//! this session, now relocated here).
//!
//! Safety/invariants: unlike `device-manager::subsystem_entry` (whose
//! `#[link_section = ".user_text"]` code shares a binary with kernel
//! `.text`), this file compiles into `netstack-bin`'s OWN fully separate
//! ELF image — every byte of it is `U=1`, so ordinary function calls
//! (including `alloc`-using ones — `crate::build_arp_request` et al.
//! return `alloc::vec::Vec`) are completely safe here.
//! ============================================================================

use alloc::vec::Vec;
use ipc_protocol::codec::{decode_driver_response, decode_net_bypass_request, encode_driver_request, encode_net_bypass_response};
use ipc_protocol::driver::DriverErrorCode;
use ipc_protocol::{DirectNicHandle, DriverRequest, DriverResponse, NetBypassRequest, NetBypassResponse};
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_CALL`
/// — see this file's own module doc comment for why this generic
/// opcode, not a new one, is exactly what this process needs.
const IPC_CALL: usize = 42;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_RECV`
/// — `park`'s own doc comment on why this process issues one of these in
/// a real loop, serving kernel-bypass requests, once its own ARP/ICMP
/// demo is done.
const IPC_RECV: usize = 43;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`
/// — `park`'s own real `Recv`/`Reply` server loop uses this to answer
/// each `NetBypassRequest` it receives.
const IPC_REPLY: usize = 44;

/// This process's own capability slot for the (derived-copy) driver
/// `Endpoint` — `kernel_arch_glue::spawn_netstack_service`'s own first
/// (and only) grant into this process's fresh, otherwise-empty cap
/// space, so it deterministically lands at slot 0 (same reasoning every
/// other subsystem's own `*_ENDPOINT_CAP`/`DRV_ENDPOINT_CAP` constant
/// doc comment already gives).
const DRV_ENDPOINT_CAP: usize = 0;

/// This process's own capability slot for the "bypass" `Endpoint` —
/// `kernel_arch_glue::spawn_netstack_service`'s own SECOND grant, slot
/// 1. Originally granted purely as a "park" target (an Endpoint nobody
/// held a capability to `Call`, so a blocking `Recv` on it always hands
/// control back to root — see `park`'s own doc comment on why that
/// matters); now DOUBLES as the real kernel-bypass networking control
/// plane's own server endpoint (03-Kernel-Subsystems-Layer.md §2.3/
/// §5.4.1) — `kernel_arch_glue::net_bypass_request_call` is the one
/// caller that DOES hold (a derived copy of) this capability, granted
/// alongside the driver endpoint at the SAME spawn time. `park`'s own
/// loop serves both roles identically: nothing pending yet -> blocks,
/// falls back to root exactly as before; a real `NetBypassRequest`
/// arrives later -> handled, replied to, loop continues.
const BYPASS_ENDPOINT_CAP: usize = 1;

/// VA the driver's own RX `SharedRegion` is pre-mapped at in THIS
/// process's own address space — must stay numerically equal to
/// `kernel_arch_glue::NETSTACK_DRV_RX_VA`. Carries the `DriverRequest`/
/// `DriverResponse` `SmallMessage` marshaling area (`MESSAGE_OFFSET`
/// below) and, once a frame is received, the frame bytes themselves
/// (`BUFFER_OFFSET`) — same region the driver's own `subsystem_entry.rs`
/// reads/writes on the other side.
const DRV_RX_VA: usize = 0xD870_0000;
/// VA the driver's own TX `SharedRegion` is pre-mapped at — must stay
/// numerically equal to `kernel_arch_glue::NETSTACK_DRV_TX_VA`. This
/// process writes the OUTBOUND frame bytes (ARP request, then ICMP echo
/// request) here before each `SendFrame` call.
const DRV_TX_VA: usize = 0xD880_0000;
/// VA this process's own private status `SharedRegion` is mapped at —
/// must stay numerically equal to `kernel_arch_glue::NETSTACK_STATUS_VA`.
/// `kernel_arch_glue::netstack_status` reads it back directly (physical
/// pointer, kernel-side) once this process has written a terminal
/// verdict — see `write_status`'s own doc comment for the exact layout.
const STATUS_VA: usize = 0xD890_0000;
/// VA the kernel-bypass control-plane's own shared message page is
/// mapped at in THIS process's own address space — must stay numerically
/// equal to `kernel_arch_glue::NETSTACK_BYPASS_SHARED_VA`. A SEPARATE
/// page from `DRV_RX_VA` (which only ever carries `DriverRequest`/
/// `DriverResponse` messages, this process's own OUTGOING protocol as a
/// client of the driver) — this one carries `NetBypassRequest`/
/// `NetBypassResponse` messages, this process's own INCOMING protocol as
/// a server for whichever process asks for direct NIC access (03-
/// Kernel-Subsystems-Layer.md §2.3/§5.4.1).
const BYPASS_SHARED_VA: usize = 0xD8A0_0000;
/// Mirrors `driver_virtio_net::QUEUE_SIZE` — the real number of
/// descriptors in each of the driver's two virtqueues, reported verbatim
/// in `NetBypassResponse::Granted::ring_len` (a genuinely known, fixed
/// MVP value, not a placeholder — unlike `rx_ring_cap`/`tx_ring_cap`
/// below, which this process does not resolve — see `handle_bypass_
/// request`'s own doc comment).
const DRV_QUEUE_SIZE: u32 = 2;

/// `driver_virtio_net::layout::MAC_OFFSET` — must stay numerically
/// equal. The negotiated device MAC, written by the driver's own
/// `do_probe` before this process is ever spawned (`kernel_arch_glue::
/// spawn_netstack_service`'s own doc comment on why that ordering is
/// guaranteed).
const MAC_OFFSET: usize = 8;
/// `driver_virtio_net::layout::BUFFER_OFFSET` — must stay numerically
/// equal.
const BUFFER_OFFSET: usize = 256;
/// `driver_virtio_net::layout::MESSAGE_OFFSET` — must stay numerically
/// equal.
const MESSAGE_OFFSET: usize = 1024;
/// `driver_virtio_net::VIRTIO_NET_HDR_LEN` — must stay numerically
/// equal (the 12-byte `virtio_net_hdr_v1` every frame buffer is
/// prefixed with — see that constant's own doc comment for the real
/// off-by-2 bug this project already found and fixed once).
const VIRTIO_NET_HDR_LEN: usize = 12;
/// `driver_virtio_net::FRAME_MAX` — must stay numerically equal. Bounds
/// this file's own local frame-copy buffer (`poll_frame`'s own stack
/// array).
const FRAME_MAX: usize = 700;

/// This demo's own fixed guest IPv4 address — same value `kernel_arch_
/// glue`'s own (now-removed) `NET_DEMO_OUR_IP` used, kept identical so
/// this extraction changes WHERE the demo runs, not WHAT it does.
/// QEMU's own `-netdev user` (SLIRP) NATs any packet whose source falls
/// in its default `10.0.2.0/24` subnet regardless of DHCP.
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
/// The gateway this demo resolves via ARP then pings — SLIRP's own
/// fixed default gateway address.
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
/// Fixed ICMP identifier for this demo's own echo request/reply pair.
const ICMP_IDENT: u16 = 0x5151;
/// Fixed ICMP sequence number.
const ICMP_SEQ: u16 = 1;
/// Fixed ICMP payload — SLIRP echoes it back verbatim (plus Ethernet
/// minimum-frame-size zero padding — `poll_frame`'s own prefix-match
/// comparison accounts for this, same reasoning `kernel_arch_glue`'s own
/// removed `drv_net_ping_poll_result` doc comment documented in full).
const ICMP_PAYLOAD: &[u8] = b"simurgh-ping";

/// Bounded retry count for each `PollFrame` loop (ARP, then separately
/// ICMP) — same value and same "a network reply may never arrive, this
/// bounds the wait by ATTEMPT COUNT, not wall-clock time" rationale
/// `kernel_arch_glue`'s own (now-removed) `net_demo_riscv64` used for
/// its own `MAX_NET_POLL_ATTEMPTS`. Living HERE now (inside the actual
/// retry loop, in real Rust) rather than split across a `.user_text`
/// retry loop driving two separate ecalls per attempt is the whole
/// point of this extraction — same number of attempts, far fewer
/// syscalls per attempt (one `IPC_CALL` here vs. `DRV_NET_ARP_POLL` +
/// `DRV_NET_ARP_POLL_RESULT` there).
const MAX_POLL_ATTEMPTS: u32 = 5_000;

/// # Safety
/// `ecall` from U-mode traps to the kernel's S-mode handler, which
/// preserves every register except `a0`. `#[inline(never)]`: the same
/// real, QEMU-found LLVM-codegen bug `fs-native::subsystem_entry::
/// raw_syscall`'s own doc comment documents in full.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
unsafe fn raw_syscall(a7: usize, a0: usize, a1: usize) -> usize {
    let ret;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") a7,
            inlateout("a0") a0 => ret,
            in("a1") a1,
            options(nostack),
        );
    }
    ret
}

/// See `fs_native::subsystem_entry::raw_syscall2`'s own doc comment —
/// needed here (unlike this file's original client-only shape) now that
/// `park` doubles as a real `Recv`/`Reply` server for kernel-bypass
/// networking's own control plane (03-Kernel-Subsystems-Layer.md §2.3/
/// §5.4.1).
#[cfg(target_arch = "riscv64")]
#[inline(never)]
unsafe fn raw_syscall2(a7: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") a7,
            inlateout("a0") a0 => r0,
            inlateout("a1") a1 => r1,
            options(nostack),
        );
    }
    (r0, r1)
}

/// # Safety
/// `int 0x80` from Ring 3 traps to `hal_x86_64::cpu`'s dedicated DPL-3
/// gate, which preserves every register except `rax`/`rsi`.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn raw_syscall(a7: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") a7 => ret,
            in("rdi") a0,
            in("rsi") a1,
            options(nostack),
        );
    }
    ret
}

/// See the riscv64 `raw_syscall2`'s own doc comment.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn raw_syscall2(a7: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1): (usize, usize);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") a7 => r0,
            in("rdi") a0,
            inlateout("rsi") a1 => r1,
            options(nostack),
        );
    }
    (r0, r1)
}

/// # Safety
/// `svc #0` from EL0 traps to `hal_arm64::cpu`'s shared EL0-synchronous
/// vector, which preserves every register except `x0`/`x1`.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe fn raw_syscall(a7: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") a7,
            inlateout("x0") a0 => ret,
            in("x1") a1,
        );
    }
    ret
}

/// See the riscv64 `raw_syscall2`'s own doc comment.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe fn raw_syscall2(a7: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1): (usize, usize);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") a7,
            inlateout("x0") a0 => r0,
            inlateout("x1") a1 => r1,
        );
    }
    (r0, r1)
}

/// Host-build stand-in (none of the three `#[cfg(target_arch = ...)]`
/// blocks above match a non-`{riscv64,x86_64,aarch64}` host, which is
/// never the case for this project's own CI/dev hosts today, but kept
/// for forward-compatibility, matching every other subsystem's own
/// identical stand-in). `subsystem_main` is never called from a host
/// test (there is no live kernel to `ecall` into), so this body is
/// unreachable in practice.
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall(_a7: usize, _a0: usize, _a1: usize) -> usize {
    unreachable!("netstack's subsystem_main never runs on a host build")
}

/// Host-build stand-in — see `raw_syscall`'s own identical stand-in doc
/// comment.
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall2(_a7: usize, _a0: usize, _a1: usize) -> (usize, usize) {
    unreachable!("netstack's subsystem_main never runs on a host build")
}

// Same stack-slot-reuse miscompilation `fs-native::subsystem_entry`'s own
// `zero!()` macro documents in full — kept here too, at every `raw_
// syscall` call site, as the same defense-in-depth every other
// subsystem's own entry point already applies.
macro_rules! zero {
    () => {{
        let mut v: usize = 0;
        // SAFETY: a no-op asm block (`v` is read back unchanged) — its
        // only purpose is defeating the stack-slot-reuse miscompilation
        // above. Forwarded from the enclosing `unsafe` block at every
        // call site.
        core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
        v
    }};
}

/// Reads the driver's own negotiated MAC — written by its `do_probe`
/// before this process was ever spawned (this file's own module doc
/// comment on why that ordering is guaranteed).
///
/// # Safety
/// `DRV_RX_VA` must already be mapped (true from process entry onward —
/// `kernel_arch_glue::spawn_netstack_service`'s own pre-map).
unsafe fn read_driver_mac() -> [u8; 6] {
    let mut mac = [0u8; 6];
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let base = (DRV_RX_VA + MAC_OFFSET) as *const u8;
        for (i, b) in mac.iter_mut().enumerate() {
            *b = base.add(i).read_volatile();
        }
    }
    mac
}

/// Writes `msg` into the RX region's own message-marshaling area — the
/// driver's own `subsystem_entry.rs::read_shared_message` reads from
/// this exact offset on the other side.
///
/// # Safety
/// Same contract as `read_driver_mac`.
unsafe fn write_shared_message(msg: &SmallMessage) {
    let base = (DRV_RX_VA + MESSAGE_OFFSET) as *mut u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Reads back the driver's own `DriverResponse` — the driver's own
/// `write_shared_message` (called from `IPC_REPLY`'s handler) writes to
/// this exact offset before waking this process.
///
/// # Safety
/// Same contract as `read_driver_mac`.
unsafe fn read_shared_message() -> SmallMessage {
    let base = (DRV_RX_VA + MESSAGE_OFFSET) as *const u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// Reads the `SmallMessage` a bypass-requesting client wrote into the
/// kernel-bypass control-plane's own shared page — same fixed layout as
/// `read_shared_message`, just a SEPARATE page (`BYPASS_SHARED_VA`'s own
/// doc comment on why).
///
/// # Safety
/// `BYPASS_SHARED_VA` must already be mapped (true from process entry
/// onward — `kernel_arch_glue::spawn_netstack_service`'s own pre-map).
unsafe fn read_bypass_message() -> SmallMessage {
    let base = BYPASS_SHARED_VA as *const u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// Writes `msg` into the kernel-bypass control-plane's own shared page
/// for the caller to read back after `IPC_REPLY` wakes it — same fixed
/// layout as `read_bypass_message`.
///
/// # Safety
/// Same contract as `read_bypass_message`.
unsafe fn write_bypass_message(msg: &SmallMessage) {
    let base = BYPASS_SHARED_VA as *mut u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Handles one REAL `NetBypassRequest` — the kernel-bypass networking
/// control plane's own server-side logic (03-Kernel-Subsystems-Layer.md
/// §2.3/§5.4.1). This MVP never checks a real per-client "bypass
/// capability" (§2.3's own text names the layer-4 Security Broker as the
/// real issuer of that — out of this repo's own scope, `03-Kernel-
/// Subsystems-Layer.md`'s own module doc comment) and always grants —
/// same "one demo, one hardcoded scenario, no real per-connection
/// resolution yet" simplification `compositor::subsystem_entry::handle_
/// request`'s own doc comment already establishes for `buffer_cap`.
/// `rx_ring_cap`/`tx_ring_cap` in the reply are informational
/// placeholders (`0`) for the SAME reason `shared_cap`/`buffer_cap` are
/// never resolved elsewhere in this codebase — the REAL capability grant
/// and region mapping into the requesting client's own address space is
/// performed by `kernel_arch_glue::net_bypass_request_call` itself (the
/// TRUSTED glue driving this very round trip), not by this process,
/// exactly mirroring how `spawn_netstack_service`'s own trusted-
/// bootstrap mapping needs no `Map` ceremony from Netstack itself either.
fn handle_bypass_request(req: NetBypassRequest) -> NetBypassResponse {
    match req {
        NetBypassRequest::RequestDirectNic { nic_id: _ } => NetBypassResponse::Granted {
            handle: DirectNicHandle(1),
            rx_ring_cap: 0,
            tx_ring_cap: 0,
            ring_len: DRV_QUEUE_SIZE,
        },
        NetBypassRequest::Release { handle: _ } => NetBypassResponse::Released,
        NetBypassRequest::RelayFrame => {
            // SAFETY: `stage_frame_for_tx`'s own contract (this
            // process's own TX region is mapped from process entry
            // onward, per `spawn_netstack_service`'s own doc comment);
            // `call_driver`'s own contract (`DRV_ENDPOINT_CAP` likewise
            // already granted). Stages a fixed, recognizable demo frame
            // — the SAME shape `kernel_arch_glue::net_bypass_direct_
            // send`'s own bypass frame uses, so the two paths' own
            // measured latencies are comparing like-for-like work
            // (03-Kernel-Subsystems-Layer.md §5.4.1's own "bypass is
            // ≥30-40% faster than the standard path" claim).
            unsafe {
                let mut frame = [0u8; 64];
                frame[0..6].fill(0xFF); // dest MAC = broadcast
                frame[6..12].fill(0xB9); // src MAC = fixed sentinel bytes
                frame[12] = 0xFF;
                frame[13] = 0xFF; // ethertype 0xFFFF — deliberately unassigned
                frame[14..].fill(0xB5); // recognizable payload pattern
                stage_frame_for_tx(&frame);
                match call_driver(&DriverRequest::SendFrame { len: frame.len() as u32 }) {
                    Some(DriverResponse::FrameSent) => NetBypassResponse::Relayed,
                    _ => NetBypassResponse::Denied,
                }
            }
        }
    }
}

/// One real `Call` to the driver's own `Endpoint` — sends `req`, blocks
/// (a genuine `SyscallOp::Call`, transparent to this ecall's own return)
/// until the driver `Reply`s, and returns the decoded `DriverResponse`.
/// `None` only on a decode failure (a malformed reply, never expected in
/// practice — the driver's own `encode_driver_response` output is
/// always well-formed).
///
/// # Safety
/// Same contract as `read_driver_mac`; `DRV_ENDPOINT_CAP` must already
/// be granted (true from process entry onward).
unsafe fn call_driver(req: &DriverRequest) -> Option<DriverResponse> {
    let msg = encode_driver_request(req);
    // SAFETY: forwarded from this function's own contract.
    unsafe { write_shared_message(&msg) };
    // SAFETY: `raw_syscall`'s own contract. `IPC_CALL` blocks this
    // thread until the driver's own `IPC_REPLY` wakes it — see this
    // file's own module doc comment.
    unsafe { raw_syscall(IPC_CALL, DRV_ENDPOINT_CAP, zero!()) };
    // SAFETY: forwarded from this function's own contract — the reply
    // is already in place by the time `raw_syscall` above returns.
    let reply_msg = unsafe { read_shared_message() };
    decode_driver_response(&reply_msg).ok()
}

/// Copies `len` bytes starting at `DRV_RX_VA + BUFFER_OFFSET +
/// VIRTIO_NET_HDR_LEN` into a fresh `Vec` — the frame `PollFrame`'s own
/// `FrameReceived { len }` response reports as waiting. `len` is
/// trusted (bounded by `FRAME_MAX`, the driver's own fixed buffer size,
/// which `VirtioNet::poll_rx` never exceeds).
///
/// # Safety
/// Same contract as `read_driver_mac`.
unsafe fn copy_received_frame(len: usize) -> Vec<u8> {
    let len = len.min(FRAME_MAX);
    let mut buf = Vec::with_capacity(len);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let base = (DRV_RX_VA + BUFFER_OFFSET + VIRTIO_NET_HDR_LEN) as *const u8;
        for i in 0..len {
            buf.push(base.add(i).read_volatile());
        }
    }
    buf
}

/// Writes `frame`'s own bytes at `DRV_TX_VA + BUFFER_OFFSET +
/// VIRTIO_NET_HDR_LEN` — `driver_virtio_net::VirtioNet::submit_tx_
/// request`'s own contract ("the caller already placed the data") on
/// the other side of the `SendFrame` IPC call.
///
/// # Safety
/// Same contract as `read_driver_mac`; `frame.len() <= FRAME_MAX`.
unsafe fn stage_frame_for_tx(frame: &[u8]) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let base = (DRV_TX_VA + BUFFER_OFFSET + VIRTIO_NET_HDR_LEN) as *mut u8;
        core::ptr::copy_nonoverlapping(frame.as_ptr(), base, frame.len());
    }
}

/// Sends `frame` (already built by the caller) via one `SendFrame` Call,
/// then polls (bounded, `MAX_POLL_ATTEMPTS`) for a reply, running
/// `parse` on each `FrameReceived` frame's own bytes until it returns
/// `Some` or the attempts run out. This is the whole "extraction": what
/// used to be a `.user_text` retry loop issuing TWO separate ecalls per
/// attempt (`DRV_NET_*_POLL` + `_RESULT`) against `kernel_arch_glue`'s
/// own physical-memory peeking is now one real `IPC_CALL` per attempt,
/// with `parse` running as REAL Rust against a REAL `Vec` this process
/// itself owns.
///
/// # Safety
/// Same contract as `call_driver`; `frame.len() <= FRAME_MAX`.
unsafe fn send_then_poll<T>(frame: &[u8], mut parse: impl FnMut(&[u8]) -> Option<T>) -> Option<T> {
    // SAFETY: forwarded from this function's own contract.
    unsafe { stage_frame_for_tx(frame) };
    match unsafe { call_driver(&DriverRequest::SendFrame { len: frame.len() as u32 }) } {
        Some(DriverResponse::FrameSent) => {}
        _ => return None,
    }
    for _ in 0..MAX_POLL_ATTEMPTS {
        match unsafe { call_driver(&DriverRequest::PollFrame) } {
            Some(DriverResponse::FrameReceived { len }) => {
                let bytes = unsafe { copy_received_frame(len as usize) };
                if let Some(v) = parse(&bytes) {
                    return Some(v);
                }
                // Not the reply we're waiting for (or unrelated
                // background traffic) — keep polling, same "one
                // interrupt/frame arrival is not proof it's THIS
                // request's own answer" reasoning `driver_virtio_blk::
                // VirtioBlk::completion_pending`'s own doc comment
                // documents for the interrupt-driven case.
            }
            Some(DriverResponse::Failed { code: DriverErrorCode::NoData }) => {}
            _ => return None,
        }
    }
    None
}

/// This process's own private status `SharedRegion` layout — see this
/// file's own module doc comment. `+0`: a `u8` verdict (`0` = still
/// running/not reached this point, `1` = ARP failed, `2` = ARP resolved
/// but ping failed/mismatched, `3` = ARP resolved AND ping matched —
/// full success). `+8..14`: the resolved gateway MAC (six bytes), valid
/// once the verdict is `>= 2`.
fn write_status(verdict: u8, gw_mac: Option<[u8; 6]>) {
    // SAFETY: `STATUS_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::spawn_netstack_service`,
    // before this process is ever scheduled.
    unsafe {
        (STATUS_VA as *mut u8).write_volatile(verdict);
        if let Some(mac) = gw_mac {
            let base = (STATUS_VA + 8) as *mut u8;
            for (i, b) in mac.iter().enumerate() {
                base.add(i).write_volatile(*b);
            }
        }
    }
}

/// The Netstack process's own entry point. Runs the ARP-resolve-then-
/// ICMP-echo MVP demo (03-Kernel-Subsystems-Layer.md §5.4) exactly once,
/// driving `driver-virtio-net` over real IPC throughout, then reports
/// the verdict via `write_status` and calls `park` — which, despite its
/// name, is where this process's SECOND real role begins: serving the
/// kernel-bypass networking control plane (§2.3/§5.4.1) forever on
/// `BYPASS_ENDPOINT_CAP`. A real Netstack would ALSO loop serving
/// `FsRequest`-style application traffic on some THIRD endpoint — not
/// yet built, still future scope.
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    // SAFETY: `DRV_RX_VA` is mapped by the time this process's first
    // instruction ever runs (this file's own module doc comment).
    let our_mac = unsafe { read_driver_mac() };

    let arp_request = crate::build_arp_request(our_mac, OUR_IP, GATEWAY_IP);
    // SAFETY: `call_driver`'s own contract; `arp_request.len() <=
    // FRAME_MAX` (42 bytes, this crate's own fixed ARP frame size).
    let gw_mac = unsafe {
        send_then_poll(&arp_request, |frame| crate::parse_arp_reply(frame, GATEWAY_IP))
    };

    let Some(gw_mac) = gw_mac else {
        write_status(1, None);
        park();
    };

    let echo_request =
        crate::build_echo_request(our_mac, gw_mac, OUR_IP, GATEWAY_IP, ICMP_IDENT, ICMP_SEQ, ICMP_PAYLOAD);
    // SAFETY: `call_driver`'s own contract; `echo_request.len() <=
    // FRAME_MAX`.
    let matched = unsafe {
        send_then_poll(&echo_request, |frame| {
            let reply = crate::parse_echo_reply(frame)?;
            // Prefix match, not exact-length: Ethernet's own 60-byte
            // minimum frame size pads this demo's own short request with
            // trailing zeros before SLIRP ever sees it, and SLIRP echoes
            // the padding right back — same reasoning `kernel_arch_glue`'s
            // own (removed) `drv_net_ping_poll_result` doc comment
            // documented in full.
            let payload_matches =
                reply.payload.len() >= ICMP_PAYLOAD.len() && &reply.payload[..ICMP_PAYLOAD.len()] == ICMP_PAYLOAD;
            (reply.ident == ICMP_IDENT && reply.seq == ICMP_SEQ && payload_matches).then_some(())
        })
    };

    write_status(if matched.is_some() { 3 } else { 2 }, Some(gw_mac));
    park();
}

/// Blocks on `BYPASS_ENDPOINT_CAP`, then serves REAL `NetBypassRequest`s
/// on it forever (03-Kernel-Subsystems-Layer.md §2.3/§5.4.1) — this
/// MVP's demo has no OTHER work left for this process once the ARP/ICMP
/// verdict is written (this function's own caller's doc comment), but
/// the kernel-bypass control plane is real work, not idle parking. `!`
/// return type: never actually returns, matching `subsystem_main`'s own
/// signature.
///
/// **Real starvation bug found via QEMU, originally fixed here (the
/// mechanism this function's own loop below still relies on)**: a plain
/// busy spin left this process holding the CPU (and `cr3`) forever once
/// done, with NO ecall ever issued again — but `kernel_arch_glue::
/// kstate()`'s `caller` (root), suspended mid-`NET_DEMO_START` since the
/// original spawn switch, can only ever resume via `p2_ipc_recv`'s own
/// hardcoded "switch to root" fallback, which fires ONLY when some
/// thread issues a REAL blocking `Recv` that finds nothing pending. A
/// silent spin loop never does that, so root's own `NET_STATUS_POLL`
/// retry loop never got scheduled again after the initial spawn switch.
/// `BYPASS_ENDPOINT_CAP` (slot 1, granted by `spawn_netstack_service`)
/// was originally granted PURELY as a park target for this reason —
/// blocking `Recv` on it (this function's very first iteration, before
/// any real client exists yet to `Call` it) hands control back to root
/// via that SAME fallback, and since `write_status` (this function's
/// every caller) already ran by then, root's very next poll attempt
/// reads the real, final verdict instead of racing an unfinished one.
/// Every iteration AFTER that first one serves a genuine, later `Call`
/// from a real kernel-bypass client (`kernel_arch_glue::net_bypass_
/// request_call`) — the SAME Endpoint, now also doing real work.
///
/// # Safety
/// `BYPASS_ENDPOINT_CAP` and `BYPASS_SHARED_VA` are both granted/mapped
/// into this process's cap space/address space before its first
/// instruction ever runs (`spawn_netstack_service`'s own doc comment).
fn park() -> ! {
    loop {
        // SAFETY: `raw_syscall2`'s own contract. Blocks until a real
        // `Call` arrives — the FIRST time, nobody holds a capability to
        // make one yet, so this hands control back to root via `p2_ipc_
        // recv`'s own fallback (this function's own doc comment); every
        // later iteration serves a genuine kernel-bypass request.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, BYPASS_ENDPOINT_CAP, zero!()) };
        // SAFETY: `read_bypass_message`'s own contract.
        let req_msg = unsafe { read_bypass_message() };
        let resp = match decode_net_bypass_request(&req_msg) {
            Ok(req) => handle_bypass_request(req),
            Err(_) => NetBypassResponse::Denied,
        };
        // SAFETY: `write_bypass_message`'s own contract.
        unsafe { write_bypass_message(&encode_net_bypass_response(&resp)) };
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success (see its own doc comment) — the loop
        // continues here only on the (unreachable in practice) error
        // case, matching every other real IPC server in this codebase.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}
