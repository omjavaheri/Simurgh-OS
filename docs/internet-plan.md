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

- TODO(spec) 1: Hand-written TCP/IP versus vendoring `smoltcp` (spec section
  2.3 says "Fuchsia Netstack or smoltcp-inspired"). Vendoring saves months but
  adds a dependency that must fit the repo charter and the "nothing above the
  HAL is architecture-specific" rule. Needs Omid's decision before Phase 2.
- TODO(spec) 2: Which clock/timer source a layer-3 service uses for
  retransmit and lease timers (no timer syscall observed).
- TODO(spec) 3: A timeout-capable Wait or timer notification in the kernel,
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
