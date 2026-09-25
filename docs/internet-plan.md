# Plan: real internet access from Simurgh

Status: survey of 2026-09-25 (read-only, no code run). Branch `fix/33-fix`.
Spec basis: `MD/03-Kernel-Subsystems-Layer.md` section 2.3 (user-space TCP/IP,
smoltcp-style) and section 5.4 (ICMP echo MVP).

## 1. Current state

| Area | State | Evidence / tested how |
|---|---|---|
| `netstack` crate (`subsystems/netstack/src/lib.rs`, ~530 lines) | Pure, total packet functions only: Ethernet, ARP request/reply parse+build, IPv4, ICMP echo request/reply build+parse, RFC1071 checksum. No state, no timers, no routing table, no sockets. | Host unit tests (about 20 across netstack and virtio-net libs) |
| `netstack` process (`subsystem_entry.rs`, ~720 lines) | An IPC *client* of the NIC driver. Runs one fixed demo: ARP-resolve gateway 10.0.2.2, then one ICMP echo, writes the verdict to a shared page. Not a server; no other process can call it. | QEMU boot demo (all three architectures), pass marker read via `netstack_status` |
| `driver-virtio-net` (~1800 lines) | virtio 1.x, negotiates only VERSION_1 + MAC. mmio (riscv64) and PCI-modern (x86_64/aarch64). Queues rx1/tx1. IRQ-driven TX completion; RX is a non-blocking poll (`PollFrame`) by design because the kernel has no Wait-with-timeout. No offloads, no mergeable buffers, no multiqueue, no link-status handling. | QEMU with `-device virtio-net-pci`; README says the separately spawned driver was not always seen reaching probe inside 240 s (scheduling capacity) |
| `ipc-protocol` net messages (`net.rs`) | Only the kernel-bypass control plane (`RequestDirectNic`, `Release`, `RelayFrame`) plus `DriverRequest::{SendFrame,PollFrame}` for the driver. **No socket messages at all** (the file says they are out of scope for the MVP). | Codec round-trip host tests |
| ARP / IPv4 / ICMP | Builders and parsers only. No ARP cache, no fragmentation/reassembly, no routing. | see above |
| DHCP, DNS, UDP, TCP, TLS | **Absent.** No code, no smoltcp/rustls dependency. | grep of the repo |
| Loopback, interface config | Absent. 10.0.2.15 and gateway 10.0.2.2 are hardcoded in the demo. | |
| Consumers | `simurgh-store`: placeholder network client with a simulated delay; README says no real TCP/IP or DNS exists. `simurgh-diagnostics`: network sender explicitly out of scope, no kernel IPC edge. `simurgh-native-sdk`, `simurgh-posix-compat`: no socket surface. Compositor: no Network/Settings window. | READMEs |
| QEMU launch | `simurgh-run.ps1` (line ~200) and the `ui*-drive.ps1`, `simurgh-boot-timeline.ps1`, `simurgh-login-test.ps1`, `simurgh-mouse-bench.ps1` scripts all pass `-net none`, so the desktop boots with no NIC. The ping demo only runs where a test attaches `-device virtio-net-pci` ad hoc. | scripts |

Bottom line: Simurgh can today do one ARP plus one ICMP round trip with the
QEMU gateway in a scripted demo. It has no usable network: no IP
configuration, no UDP/TCP, no name resolution, no API for other processes.

### Note: known issue "desktop stops after the virtio-blk probe"
Not fixed here. From the code and README: the log stops right after
`driver-virtio-blk ... probe() succeeded=true`, before ui-core spawns, inside
the demo-time virtio-blk read/write round trip (root task <-> driver;
`kernel/kernel/src/main.rs`, steps 7b/7c). NVMe does not hit it, and an older
pre-Devices image hits it too. Likely cause: the round trip blocks on a `Wait`
for a completion notification that never arrives on x86_64 with a raw-disk
virtio-blk (lost or misrouted MSI-X, or the driver thread not scheduled after
the probe report). First checks: MSI-X/vector programming in
`wire_virtio_pci_transport`, and whether the demo can use a bounded wait so the
desktop still spawns. This matters here because virtio-net uses the same PCI
wiring (`wire_virtio_pci_transport_net`) and may hit the same wall, so validate
a desktop boot with only virtio-net attached first.

## 2. QEMU test setup for real internet

Use user-mode networking (no admin rights needed on Windows):

    -netdev user,id=n0 -device virtio-net-pci,netdev=n0,disable-legacy=on

The guest sees DHCP server/gateway 10.0.2.2, DNS forwarder 10.0.2.3, guest
address 10.0.2.15, and NAT to the host's real internet. Points to plan around:
- QEMU answers pings to 10.0.2.2 itself, but pings to real hosts (8.8.8.8)
  usually do NOT work from a Windows host (no raw ICMP socket). Use DNS and TCP
  connects as the reachability tests, not external ping.
- Change needed: add a `-Net` switch (default off, keeping current behaviour
  and test timings) to `simurgh-run.ps1` that replaces `-net none` with the two
  options above; same for the ui/drive scripts that want it. About 20 lines.
  Keep the fault-isolation suite on `-net none`. These scripts live in the
  workspace root, which is not a git repo, so this change is tracked outside
  the repos.
- Test targets: 10.0.2.2 (ARP + ping), 10.0.2.3 (DNS for `example.com`),
  `http://example.com/` (port 80), later `https://example.com/`. Offline-safe
  variant: a host-side `python -m http.server` reached from the guest at
  10.0.2.2:PORT (the host alias), so CI does not depend on the internet.

## 3. Phases

Sizes are rough effort in this codebase's style (heavily documented,
cross-arch), counted in focused work sessions.

### Phase 0 - prerequisites (1-2 sessions)
- Add the `-Net` switch; confirm the desktop boots with virtio-net attached.
- Understand/decouple the virtio-blk desktop hang enough that attaching a
  virtio PCI device does not stop the boot.
- Decide the stack strategy (TODO(spec) 1) before Phase 2.
Acceptance: desktop boots to ui-core with `-Net`; serial shows the virtio-net
probe succeeded and the NIC in the hardware manifest.

### Phase 1 - Ethernet, ARP, IPv4, ICMP as a real service (3-4 sessions)
- Turn netstack into a persistent event loop: RX poll with backoff, ARP cache
  with timeout/retry, IPv4 rx/tx, routing (on-link vs gateway), ICMP echo in
  both directions, static IP config (10.0.2.15/24, gw 10.0.2.2).
- Driver: real MAC read, link-status bit, RX buffer refill under load.
Acceptance: under QEMU user-net, Simurgh pings 10.0.2.2 five times with
sequence numbers and RTTs on serial. Host tests: ARP cache, checksum vectors,
IPv4 header edge cases, malformed frames. Fault-isolation suite unchanged.

### Phase 2 - UDP, DHCP client, DNS resolver (3 sessions)
- Minimal UDP, DHCP DISCOVER/OFFER/REQUEST/ACK with lease and renewal, DNS A
  resolver with cache, retry and timeout using the DHCP-provided server.
- Needs a monotonic timer source (TODO(spec) 2).
Acceptance: the guest obtains address/gateway/DNS via DHCP with no hardcoded
values, then resolves `example.com`; both logged on serial. Host tests with
recorded DHCP/DNS packets.

### Phase 3 - TCP, socket API, plain HTTP (8-12 sessions, the biggest piece)
- TCP: state machine, 3-way handshake, sequence/ack, retransmission timer with
  RTO estimation, sliding window and window advertisement, MSS, small
  out-of-order buffer, FIN/RST close and TIME_WAIT, pseudo-header checksum,
  ephemeral ports, Reno-style congestion control. Loopback interface.
- Socket API over IPC: new `ipc_protocol::net` socket request/response
  messages (Open, Bind, Connect, Listen, Accept, Send, Recv, Close, SetOpt,
  Resolve). A socket is a capability with rights (connect/listen/send/recv)
  issued via the Security Broker; bulk data moves through a per-socket
  `SharedRegion` ring rather than 6-word small messages. Blocking recv needs a
  timeout-capable wait (TODO(spec) 3).
- Alternative to hand-writing: vendor `smoltcp` (no_std; DHCP, DNS, TCP, UDP,
  ICMP, loopback). See TODO(spec) 1.
Acceptance: a test app opens a socket via IPC, resolves `example.com`, connects
to port 80, sends `GET / HTTP/1.0`, and prints the status line on serial. Also
a loopback echo test, and a 1 MB download from a host-side server, checksummed,
with induced frame loss (drop frames in the driver under a test flag) to
exercise retransmit and windowing.

### Phase 4 - TLS / HTTPS (4-8 sessions)
Feasibility: `rustls` works with `alloc` and a `no_std` crypto provider
(default features off, e.g. a RustCrypto-based provider); `embedded-tls`
(client-only, TLS 1.3 only, no_std, small) is lighter but has narrower cipher
and certificate-validation coverage. Simurgh must first supply: a wall clock
(certificate validity; RTC read or NTP), an entropy source (RNG syscall or a
virtio-rng driver, currently absent), a root CA store (e.g. from
`simurgh-store` or a signed blob), and enough heap in the hosting process.
Recommendation: TLS as a library inside the client (or a separate `tls-service`),
not inside netstack, to keep the stack small. No dependency is added by this plan.
Acceptance: HTTPS GET of `https://example.com/` with chain and hostname
validation, plus a negative test that a wrong hostname or a bad-time cert is
rejected.

### Phase 5 - more NICs for other VMs (3-5 sessions each)
- Harden virtio-net: legacy/transitional device IDs, mergeable RX buffers,
  checksum offload.
- Intel e1000 first (QEMU option, VirtualBox and VMware compatible), then
  rtl8139 as a cheap fallback; vmxnet3 optional. Hyper-V uses synthetic
  VMBus/netvsc, a separate large item, skip early.
- Needs a NIC-driver trait shared with virtio-net (`SendFrame/PollFrame` is a
  good base) and PCI BAR + DMA support in driver-framework.
Acceptance: the Phase 3 HTTP test passes with `-device e1000` and on a
VirtualBox default NIC; the NIC is picked from the hardware manifest.

### Phase 6 - USB xHCI and USB NICs (10+ sessions)
xHCI host controller driver (rings, slots, enumeration, hubs) is a prerequisite
for any USB device; then a CDC-ECM/NCM or RTL8152 class driver. Also unlocks USB
keyboard/mouse/storage.
Acceptance: `-device qemu-xhci -device usb-net,netdev=n0` gets DHCP and HTTP.

### Phase 7 - Wi-Fi (very large, 20+ sessions, hardware-dependent)
Needs vendor firmware blobs (redistribution licensing), a chipset driver (Intel
iwlwifi is huge; USB dongles are more approachable after Phase 6), an 802.11
MAC layer with scan/auth/association, a WPA2/WPA3 supplicant (AES, SAE), and
regulatory handling. Not testable in stock QEMU; needs real hardware or
passthrough. Do last.
Acceptance: scan lists SSIDs, connect to a WPA2 network, DHCP, HTTPS GET.

## 4. Desktop side
- After Phase 2: a Network window (Settings/tray) showing link state, MAC,
  IPv4, gateway, DNS, lease age, DHCP status, via a read-only status IPC from
  netstack guarded by a status-read capability.
- After Phase 3: a "connectivity check" action (DNS + TCP connect result).
- After Phase 7: Wi-Fi scan list and connect dialog; passwords handled by the
  account manager / secret store, never the compositor.
- Apps: `simurgh-store` swaps its placeholder client for real sockets after
  Phase 3/4; `simurgh-diagnostics` gains a real network sender;
  `simurgh-native-sdk` and `simurgh-posix-compat` get socket wrappers
  (`socket/connect/send/recv`, `getaddrinfo`) mapped to the IPC socket API.

## 5. Dependencies and order
Phase 0 -> 1 -> 2 -> 3 -> 4. Phases 5 and 6 need Phase 3 to validate but can run
in parallel with 4. Phase 7 needs 6 (or PCIe Wi-Fi work) and 3. The desktop
Network window needs Phase 2. A monotonic timer, an RNG and a wall clock are
cross-cutting prerequisites (Phases 2 and 4).

## 6. Open design questions

- TODO(spec) 1 (RESOLVED 2026-09-25: use smoltcp): Hand-written TCP/IP versus vendoring `smoltcp` (spec section
  2.3 says "Fuchsia Netstack or smoltcp-inspired"). Vendoring saves months but
  adds a dependency that must fit the repo charter and the "nothing above the
  HAL is architecture-specific" rule. Needs Omid's decision before Phase 2.
- TODO(spec) 2 (RESOLVED: `NOW_NS` syscall, see section 8): Which clock/timer source a layer-3 service uses for
  retransmit and lease timers (no timer syscall observed).
- TODO(spec) 3 (sleeping RESOLVED by `NOTIF_WAIT_TIMEOUT`; RX notification still open): A timeout-capable Wait or timer notification in the kernel,
  needed for blocking recv and for RX without polling (currently deliberately
  absent, see the driver-virtio-net module comment).
- TODO(spec) 4: Socket capability model: rights, who mints them (Security
  Broker vs Netstack), per-profile policy, interaction with the kernel-bypass
  `DirectNicHandle` path.
- TODO(spec) 5: Socket data path: shared ring per socket vs copy in IPC;
  buffer sizing and backpressure.
- TODO(spec) 6: Is IPv6 in scope? (Plan assumes IPv4 only.)
- TODO(spec) 7: TLS placement and root CA store ownership; RNG source.
- TODO(spec) 8: Hyper-V (netvsc) and VMware (vmxnet3) in scope?
- TODO(spec) 9: Which repo owns the network settings UI, and which capability
  lets it change IP settings.

## 7. Recommended first step
Phase 0 plus the Phase 1 core: add the `-Net` option, get a desktop boot with
virtio-net attached, then make netstack a persistent service that pings
10.0.2.2 repeatedly. It is small, exercises the whole driver path, and is the
foundation for everything else. Decide TODO(spec) 1 before starting Phase 2.

## 8. Progress (updated as phases land)

Branch `feat/net-smoltcp` (from `fix/33-fix`). Owner decision of 2026-09-25:
use the `smoltcp` crate (no_std) for TCP/IP instead of hand-writing it
(TODO(spec) 1 below is resolved by this).

| Phase | Status | Evidence |
|---|---|---|
| 0 - `-Net` switch, desktop boots with virtio-net | done (2026-09-25) | `simurgh-run.ps1 -Desktop` (now with the NIC by default, `-NoNet` opts out) boots to ui-core; serial: `driver-virtio-net (U-mode, x86_64): real VirtioNet::probe() succeeded=true`, then `ui-core ... self_check ... ok=true` |
| 1 - persistent netstack on smoltcp: ARP, IPv4, ICMP | done on x86_64 (2026-09-25) | desktop image with `-Net`: `netstack: link up: 10.0.2.15/24 gateway 10.0.2.2`, then `netstack: ping reply from 10.0.2.2: seq=1..11 time=..ms`; 11 new host tests |
| 2 - UDP, DHCP client, DNS resolver | done on x86_64 (2026-09-25) | desktop image with `-Net`: `netstack: link up (DHCP lease): address 10.0.2.15/24 gateway 10.0.2.2 dns 10.0.2.3`, `netstack: dns: example.com resolved to 104.20.23.154`, later lookups `(from cache)`; 18 more host tests (42 in netstack) |
| 3+ | not started | - |

Phase 0 notes:
- `-Net` lives in the workspace-root `simurgh-run.ps1` (not a git repo). It
  replaces `-net none` with `-netdev user,id=n0 -device
  virtio-net-pci,netdev=n0,disable-legacy=on` (riscv64: `virtio-net-device`,
  the mmio transport this driver speaks there). Default stays `-net none`.
  Two extra parameters, `-OsDir` and `-RunDir`, let a second checkout boot
  side by side with the main one without sharing images or logs.
- `disable-legacy=on` is kept from section 2: the driver negotiates only
  VERSION_1, so the transitional (legacy-capable) personality of the device
  gains nothing.

Phase 1 notes (2026-09-25):
- Stack: `smoltcp` 0.12 from crates.io like the other external crates (normal
  registry dependency, `Cargo.lock` is gitignored in this repo; no vendor
  folder exists). `default-features = false`, features `proto-ipv4`,
  `medium-ethernet`, `socket-icmp`; no `alloc` (all buffers are one static
  `StackStorage`). Builds for all three custom targets; the stack itself has no
  `cfg(target_arch)`.
- Structure: `subsystems/netstack/src/stack.rs` (`FrameIo` transport trait,
  smoltcp `Device` adapter, `NetStack`), `stack_tests.rs` (host tests against a
  mock LAN), `subsystem_entry.rs` (`DriverIo` = `FrameIo` over the existing
  `SendFrame`/`PollFrame` IPC and shared pages; the smallest thing that works,
  no driver change).
- Service shape: a SECOND thread of the Netstack process, started by
  `kernel_arch_glue::netstack_start_service` at the end of the desktop boot
  sequence (desktop image only; the demo image is unchanged). It sleeps between
  polls with `NOTIF_WAIT_TIMEOUT` on a private never-signalled notification and
  reads `NOW_NS`. Logs use a new `NET_LOG` syscall (text read from Netstack's
  own status page). This answers the survey's "no timer syscall observed":
  `NOW_NS` (monotonic ns) and `NOTIF_WAIT_TIMEOUT` (2 ms granularity, added
  2026-09-24) exist, so TODO(spec) 2 is resolved and TODO(spec) 3 is resolved
  for sleeping; only a NIC receive notification (no polling) stays open.
- Evidence (x86_64 desktop image, `-Net`, serial):
  `netstack: link up: 10.0.2.15/24 gateway 10.0.2.2` and repeated
  `netstack: ping reply from 10.0.2.2: seq=N time=..ms` (seq 1..11 in one run).
- Findings worth knowing:
  - The blocking ARP/ICMP boot demo is racy on the desktop image (and, less
    often, on the demo image, also without this work): the driver's TX-complete
    wait can yield to root mid-demo. The desktop image now skips it.
  - `p2_ipc_recv` returned at once when nothing else was Ready; the boot
    sequence only worked because of "phantom" Ready threads. Desktop image now
    hands off to root in that case (the demo image keeps the old behaviour).
  - The IRQ trampoline read the INTx ISR window, mapped under only three
    processes; with MSI-X on it is skipped (an MSI-X interrupt needs no ack).
  - The kernel clock seems to run faster than wall time under WHPX (the 30 s
    heartbeat ping showed up much more often than every 30 wall seconds), so
    the RTT figures are in kernel time, not calibrated wall time. Not
    investigated.
- Not done (gaps): link-status bit and RX refill under load in the driver; the
  driver's 700-byte buffers and 2-descriptor queues (fine for ICMP/UDP/DNS/DHCP,
  too small for TCP: TODO(spec) at `stack::MAX_FRAME`); riscv64/aarch64 were
  only compile-checked (no QEMU run of the service); the service does not start
  on the demo image.

Phase 2 notes (2026-09-25):
- smoltcp features added: `proto-dhcpv4`, `proto-dns`, `socket-udp`,
  `socket-dhcpv4`, `socket-dns`. Still no heap: the UDP buffers, the DNS
  query slots and the socket table are all in `StackStorage`.
- The service now starts in `AddrMode::Dhcp`: no address, gateway or DNS
  server is hard-coded any more. Address, gateway and DNS come from the lease
  (smoltcp's DHCP socket does DISCOVER/OFFER/REQUEST/ACK, retransmit,
  renewal at T1/T2 and re-discovery on expiry/NAK); `NetEvent::LinkConfigured`
  / `LinkLost` report it. The static mode stays for tests and DHCP-less
  networks but the service never falls back to it silently.
- `NetStack::dns_resolve(name)` -> token; `DnsResolved`/`DnsFailed` events.
  smoltcp retransmits and times out (10 s) by itself. On top of it: a 4-entry
  name cache. TODO(spec): smoltcp does not expose record TTLs, so entries
  live a fixed `DNS_CACHE_TTL_NS` (300 s) instead of the server's TTL.
- `udp_bind`/`udp_send`/`udp_recv`: one generic UDP socket (single datagram
  buffered each way, 512-byte payload). It is what a future socket API builds
  on; DHCP and DNS use smoltcp's own sockets.
- Evidence (x86_64 desktop image, QEMU user-net, real internet behind it):
  address/gateway/DNS from DHCP, then `example.com` resolved through
  10.0.2.3 to a real public address, with the repeat lookups served from the
  cache. Host tests use a mock LAN with recorded-style DHCP/DNS packets built
  in the test (DISCOVER/OFFER/REQUEST/ACK, renewal, lease expiry, DHCP
  silence, A record, NXDOMAIN, DNS silence with retransmit, cache hit and
  expiry, bad names, slot limit, UDP echo).
- Gaps / open: riscv64 and aarch64 only compile (netstack image builds; no
  QEMU run of the service); the service starts on the desktop image only;
  `-Net` with the demo image still runs the old, sometimes racy blocking
  ARP/ICMP demo; the guest clock question from phase 1 (kernel time vs wall
  time under WHPX) still affects how DHCP/DNS timeouts map to wall seconds.
- Next: phase 3 (TCP, socket API over IPC, plain HTTP). smoltcp's `socket-tcp`
  is one feature away; the real work is the IPC socket protocol and the
  capability model (TODO(spec) 4/5), the driver buffer size (700-byte frames,
  2-descriptor queues), and a NIC RX notification instead of polling.

### Link state and the network status page (2026-09-25)

Owner requirement: the network icon (desktop tray and login screen) shows the
REAL state, an interrupted link shows as disconnected, and the system keeps
retrying and reconnects on its own. Wi-Fi hardware support does not exist yet,
so this is implemented and tested on the virtio-net link ("cable").

Data flow: virtio config `status` -> driver -> Netstack -> status page -> ui-core.

1. Driver (`driver-virtio-net`): negotiates `VIRTIO_NET_F_STATUS` (bit 16) when
   offered and reads `virtio_net_config::status` bit 0 (`LINK_UP`). Without the
   feature the link is assumed up. The reading is published in the RX region
   header (`LINK_VALID_OFFSET` 14, `LINK_UP_OFFSET` 15) at probe and on every
   `PollFrame`. No config-change interrupt is used: Netstack polls at least
   every 10 ms, so a link change is seen within one poll (poll, not IRQ).
2. Netstack: `NetStack::set_link(up, now)`. Link down drops the lease and
   address, clears the outstanding ping and DNS slots, queues `LinkLost`, and
   the stack stops transmitting/receiving. Link up restarts DHCP at once (or
   restores a static configuration). While the link is up and no lease exists a
   watchdog restarts DHCP on an exponential schedule (8 s, 16 s, ... capped at
   60 s; smoltcp also retransmits DISCOVER itself). The service thread pokes the
   driver with a `PollFrame` while the link is down, since the stack does not
   poll it then. State: `conn_state()` = Disconnected (no link) / Connecting
   (link, no address) / Connected. "No adapter" is the absence of the page.
3. Status page: ONE 4 KiB frame carved on first use by the kernel
   (`kernel_arch_glue::net_info_frame`), mapped read-write into the Netstack
   process (`NETSTACK_NETINFO_VA` 0xD8C0_0000) and read-only (`R | U`) into
   ui-core only at `UI_CORE_NET_INFO_VA` = `0xD8B0_3000` (right after the two
   device-list pages). A machine without a NIC never starts Netstack, so the
   page stays zero and ui-core reads "no adapter". x86_64 only for the ui-core
   mapping (same as the machine-id/device-list pages).

   Little-endian, 48 bytes used (`netstack::status`):

   | Offset | Size | Field |
   |---|---|---|
   | 0 | u64 | magic `0x5349_4D4E_4554_0001` ("SIMNET" + layout 1); wrong magic = no adapter |
   | 8 | u32 | seqlock counter: odd while Netstack writes, even when stable; `seq / 2` is the generation |
   | 12 | u8 | flags: 1 adapter present, 2 link up, 4 IPv4 valid, 8 gateway valid, 16 DNS valid |
   | 13 | u8 | state: 0 no adapter, 1 disconnected, 2 connecting, 3 connected |
   | 14 | u8 | kind: 0 none, 1 Ethernet, 2 Wi-Fi |
   | 15 | u8 | IPv4 prefix length |
   | 16 / 20 / 24 | 4 bytes each | IPv4 address / gateway / DNS server |
   | 28 | 6 bytes | MAC |

   A reader copies the 48 bytes and drops the copy if `seq` is odd or changed.
   ui-core reads it once per loop iteration (48 bytes and a compare) and only
   redraws when the generation changes; while "connecting" the icon animates
   (amber, arcs appear one by one).

   TODO(spec): who may read this page is decided by kernel code that maps it
   into ui-core only, not by a capability (same open question as machine-id
   TODO-5). Wi-Fi: the record already has `kind = 2`; scanning, SSIDs, keys and
   roaming need their own design.
4. ui-core: `netinfo.rs` decodes the page; the tray icon and the login-screen
   icon share one drawing (`tray::draw_icon`): no adapter = dim with a red
   slash, disconnected = dim with a red exclamation mark, connecting = amber
   animated, connected = normal. The flyout (click) shows state, address,
   gateway, DNS and MAC; on the login screen it opens above the icon and has no
   "Open Settings" row.
5. `simurgh-run.ps1 -Desktop` and `simurgh-login-test.ps1` now attach the
   virtio NIC by default (`-NoNet` opts out); the demo image keeps `-net none`.

Evidence (x86_64, WHPX, desktop image, QEMU HMP `set_link n0 off|on` where
`n0` is the `-netdev` id): boot shows connected `10.0.2.15/24` on the tray and
the login icon (flyout: Ethernet, 10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3,
MAC 52:54:00:12:34:56); after `set_link n0 off` both icons show disconnected
within a few seconds (red exclamation, flyout "Network: disconnected"); after
`set_link n0 on` DHCP runs again and both return to connected. Serial:

```
netstack: link up (DHCP lease): address 10.0.2.15/24 gateway 10.0.2.2 dns 10.0.2.3
netstack: link down: cable/Wi-Fi lost, will keep retrying
netstack: link down: DHCP lease lost, waiting for a new one
netstack: link up: restarting DHCP
netstack: link up (DHCP lease): address 10.0.2.15/24 gateway 10.0.2.2 dns 10.0.2.3
```

Without a NIC (`-net none`) the icon reads "no adapter". Host tests: 11
netstack (status encode/decode, link down/up, silent DHCP with backoff,
idempotence, static restore, no traffic while down) and 7 ui-core (page decode,
state mapping, watcher, login icon states and flyout).

Gaps: the "connecting" state was not caught in a screenshot (DHCP completes in
about a second on QEMU user networking; it is covered by host tests); the
driver reports the link by polling, not by the config-change interrupt;
riscv64/aarch64 only compile; no Wi-Fi hardware.
