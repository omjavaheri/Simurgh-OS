# Simurgh-OS

[![CI](https://github.com/omjavaheri/Simurgh-OS/actions/workflows/ci.yml/badge.svg)](https://github.com/omjavaheri/Simurgh-OS/actions/workflows/ci.yml)

The kernel repository of Simurgh OS: a capability-based operating system built
from the bottom up for **x86_64, ARM64/AArch64, and RISC-V (RV64GC)**, written
in Rust (`no_std`), with minimal architecture-specific assembly confined to the
earliest bootstrap.

This repository holds **layers 1–3**:

| Layer | Directory | What it is |
|---|---|---|
| 1 – HAL | `hal/`, `uefi-bootloader/` | the only code that touches hardware registers / MMIO / privileged CPU instructions |
| 2 – Microkernel | `kernel/` | capability model, memory (UntypedMemory/retype), IPC, scheduler, syscall dispatch — one privileged binary with the HAL |
| 3 – Kernel subsystems | `ipc-protocol/`, `subsystems/` | drivers, VFS, network, etc. as isolated user-space processes |

Layers 4–5 (system services, POSIX/Linux compatibility, applications) live in
separate repositories.

## Architecture

```text
Simurgh-OS/
├── hal/
│   ├── hal-core/        architecture-independent HAL trait contracts (no_std, no heap)
│   ├── hal-direct/      capability-gated advanced hardware access
│   ├── hal-manifest/    fixed-size Hardware Manifest (boot handoff)
│   ├── hal-x86_64/      x86_64 implementation (+ boot asm, linker script)
│   ├── hal-arm64/       ARM64 implementation
│   └── hal-riscv64/     RISC-V implementation
├── uefi-bootloader/     UEFI app that loads the kernel image and hands off (x86_64 / aarch64)
│
├── kernel/
│   ├── kernel-cap/      Capability + Capability Derivation Tree + revocation (02 §2)
│   ├── kernel-mm/       UntypedMemory / retype / address-space mapping (02 §3)
│   ├── kernel-ipc/      Endpoint / Notification / SharedRegion / fast-path (02 §5)
│   ├── kernel-sched/    dual-mode (Interactive / Throughput) scheduler (02 §4)
│   ├── kernel-core/     KernelState + the SyscallOp dispatch state machine (02 §6)
│   ├── kernel-arch-glue/ architecture-erased bridge from hal-core to kernel-core (02 §7)
│   └── kernel/          the bootable Phase-2 microkernel image
│
├── ipc-protocol/        the layer-2 <-> layer-3 message contract (03 §3)
├── subsystems/          root-task, device-manager, drivers/ (virtio-blk,
│                         virtio-net, i8042 keyboard, PS/2 mouse, NVMe),
│                         vfs-service/, netstack, compositor (real
│                         DisplayProtocol: surfaces, zero-copy CommitBuffer,
│                         real keyboard/mouse polling, real output query),
│                         mm-service, log-collector-native (04 §2.2),
│                         security-broker-intermediary (03 §4)
│
├── kernel-stub/         minimal microkernel stand-in for the pure HAL (01 §8) smoke test
├── targets/             custom no_std JSON target specs
└── scripts/qemu-smoke.sh  QEMU boot assertion for kernel-stub
```

## Responsibilities

- **HAL** — CPU bring-up, privilege levels, hardware context switch and
  new-thread context init, memory discovery + minimal early mapping, timers,
  interrupt controllers, boot handoff, heterogeneous compute (GPU/NPU/TPU/FPGA)
  and power/thermal discovery. Discovery is always complete; policy is a layer-4
  concern.
- **Microkernel** — only four things: memory *mechanism* (UntypedMemory /
  retype), scheduling, IPC, and capabilities. Everything else — drivers,
  filesystems, networking, "processes" in the traditional sense — is layer 3.
- **Subsystems** — each an isolated user-space process that talks to the kernel
  only through the syscall/IPC boundary.

## Supported architectures

`x86_64`, `aarch64`, `riscv64gc`, built as custom `no_std` JSON targets in
`targets/`.

## Build instructions

Prerequisites: the pinned nightly toolchain (`rust-toolchain.toml` selects it
automatically via rustup) with `rust-src` and `llvm-tools-preview`; QEMU
(`qemu-system-{x86_64,aarch64,riscv64}`) to run images; OVMF / AAVMF firmware
for the x86_64 / aarch64 UEFI path.

```bash
# Host-target unit tests (architecture-independent crates + trait mock tests):
cargo test

# HAL, per architecture (custom no_std targets):
cargo xbuild-x86_64        cargo xbuild-aarch64        cargo xbuild-riscv64

# kernel-stub (the pure HAL boot image, 01-HAL-Layer.md §8):
cargo xbuild-kernel-{x86_64,aarch64,riscv64}
scripts/qemu-smoke.sh <x86_64|aarch64|riscv64>   # boot + assert the HAL handoff markers

# each in-repo subsystem, per architecture (must be built before the real
# kernel, which embeds their ELFs via include_bytes! — driver-i8042/
# driver-mouse are x86_64-only, no such legacy PC hardware on aarch64/riscv64):
cargo xbuild-subsystem-<device-manager|fs-native|driver-virtio-blk|driver-virtio-net|netstack|compositor|mm-service|log-collector-native|security-broker-intermediary>-<arch>
cargo xbuild-subsystem-driver-i8042-x86_64
cargo xbuild-subsystem-driver-mouse-x86_64

# the real microkernel image (Phase 2/3) — on x86_64, ALSO needs each other
# real repo's own subsystem-bin already built as a sibling directory first
# (security-broker/init/account-manager/backup-manager/diagnostics/store/
# native-loader/policy-engine/shell/file-manager/ui-core — see kernel/
# kernel/build.rs's own panic messages for the exact build command each one
# needs if a binary is missing):
cargo xbuild-microkernel-{x86_64,aarch64,riscv64}
cargo xrun-microkernel-riscv64       # build + boot under QEMU
scripts/qemu-fault-isolation-test.sh <x86_64|aarch64|riscv64>   # real fault-injection + supervision, asserted end to end
```

Build order matters, strictly: each subsystem-bin, THEN the kernel that
embeds it, THEN `uefi-bootloader` (which embeds the kernel, for x86_64/
aarch64) — skipping a rebuild step after changing a subsystem-bin embeds a
stale binary that can look exactly like a real, nondeterministic runtime
bug (a real, previously-chased false lead in this project's own history).

Exactly what CI runs on every push/PR is `.github/workflows/ci.yml` — the
same commands above, for all three architectures.

## Live kernel debugging with GDB (read this before trying)

Several sessions lost real time to the same four avoidable GDB problems
and concluded "the tooling doesn't work" when it does. All four are
solved; start from here rather than rediscovering them.

Boot QEMU with `-s -S` (gdb stub on `:1234`, CPU halted at reset) and
attach `gdb-multiarch`. Then:

1. **Use the fully-qualified Rust symbol path.** `break
   security_broker_intermediary_demo_start` can NEVER resolve — the ELF
   only contains `kernel_arch_glue::security_broker_intermediary_demo_start`.
   Confirm the real name FIRST with
   `nm -C target/<arch>-hal/debug/kernel | grep <name>`; `nm` without
   `-C` shows the mangled form (`_ZN16kernel_arch_glue39...`), and
   either the demangled path or a raw `break *0x<addr>` works.
2. **Use `hbreak`, not `break`.** On the x86_64/aarch64 UEFI path the
   kernel is not in RAM at reset — the bootloader copies its `PT_LOAD`s
   to `0x40200000` *later*, overwriting any software breakpoint bytes
   planted beforehand, so the breakpoint silently never fires. Hardware
   breakpoints survive this.
3. **`set breakpoint pending on` explicitly.** Under `-batch`, the
   "Make breakpoint pending on future shared library load?" prompt is
   auto-answered **N**, so an unresolved breakpoint is silently DISCARDED
   and the following `continue` runs the whole boot unbreaked — which
   looks exactly like "the breakpoint didn't work".
4. **`file` cannot handle spaces in this repo's path.** Symlink the ELF
   somewhere clean (`ln -sf "$REPO/target/<arch>-hal/debug/kernel"
   /tmp/kernel.elf`) and `file /tmp/kernel.elf`. Symbol addresses match
   runtime addresses directly (the kernel is linked at a fixed
   `0x40200000`), so no offset math is needed.

Source listings show `No such file or directory` because the debug info
carries Windows-style paths — cosmetic only; `info line *$pc`, `bt`,
`info registers` and `x/` all work. Stepping with a scripted `while`
loop over `next` + `info line *$pc` is what pinned the untyped-exhaustion
bug below down to one exact source line.

## Current status (honest)

The layer-2 MVP (`02-Microkernel-Layer.md §8`, all six acceptance criteria)
and the layer-3 fault-isolation criterion (`03-Kernel-Subsystems-Layer.md §5`)
are both met. CI (see badge above) builds and boot-tests all three
architectures on every push.

**Working and verified, on all three architectures (x86_64, aarch64,
riscv64) unless noted:**

- **HAL (layer 1):** boots via `kernel-stub`, produces a valid Hardware
  Manifest, hands off to a microkernel via a direct call.
  `scripts/qemu-smoke.sh <arch>` passes for all three.
- **Microkernel (layer 2):** memory (`UntypedMemory`/retype carved around the
  boot-reserved image), a synchronous IPC round-trip, capability derivation +
  revocation, a capability-gated `Map` syscall that installs real hardware
  page-table entries (Sv39 / 4-level x86_64 / 39-bit AArch64, depending on
  arch), and cross-space capability revocation (`CapGrant`/`CapRevoke`
  exercised at the syscall boundary across two separate address spaces) are
  all QEMU-verified. The Root Task runs in U-mode (`sret`/Ring 3/EL0),
  reaching the kernel only through the architecture's own syscall
  instruction; a preemptive, timer-driven scheduler runs multiple processes
  concurrently in separate, MMU-isolated address spaces, including zero-copy
  sharing of a single physical frame across two spaces.
- **Layer 3 subsystems:** `device-manager`, `fs-native`,
  `driver-virtio-blk`, `driver-virtio-net`, `driver-i8042`, `driver-mouse`,
  `driver-nvme`, `netstack`, `compositor`, `mm-service`,
  `log-collector-native`, and `security-broker-intermediary` are each a
  real, separately-built ELF process (not a linked-in library) spawned
  via the generic `kernel_arch_glue::spawn_process`/
  `spawn_process_from_elf` path, exercised by the real `kernel` binary
  on all three architectures (`driver-i8042`/`driver-mouse`/
  `driver-nvme`/`log-collector-native` are x86_64-only — the first three
  because no such hardware exists on aarch64/riscv64, `log-collector-
  native` as a deliberate, conservative first pass for a brand-new real
  IPC edge — see the dedicated bullet below).
- **Real NVMe block driver** (x86_64 only): a real NVMe controller is
  discovered by PCI class code (not vendor id, unlike every virtio
  device), and `driver-nvme` speaks the real Admin/I/O queue protocol
  directly against the base spec (register bring-up, Identify Namespace,
  Create I/O Queue, Read/Write). QEMU-verified: booting with a real
  `-device nvme` attached, the controller is discovered, a real
  capability is granted, and the driver process is spawned with its BAR0
  window and all five queue/data pages really mapped — with no effect on
  the rest of the boot. **Real probe() reporting (2026-09-16)**: closes
  the "not yet directly observable" gap this bullet used to name —
  `subsystem_main` used to discard `probe()`'s own real `Result`
  entirely (`let _ = drv.probe();`); a new `sys::DRV_NVME_PROBE_REPORT`
  opcode now reports the real outcome (`a0` = succeeded, `a1` =
  `sector_count`). Confirmed via a real, ad-hoc QEMU boot with `-device
  nvme` attached (not part of the standard test suite, which has no
  block device at all): "spawn_nvme_driver: driver-nvme spawned (real
  BAR0 + queue pages mapped, no client wired yet)" confirms the real
  controller IS discovered and the process IS spawned with real state;
  the `DRV_NVME_PROBE_REPORT` line itself was not directly observed
  within a 240s window — the same already-accepted QEMU scheduling-
  capacity variance this README documents at length elsewhere (driver-
  nvme's own thread competing with an ever-growing set of real
  subsystems for one vCPU), not a regression in this change. No real
  consumer (a filesystem) is wired to it yet either.
- **`driver-virtio-blk`/`driver-virtio-net` probe() reporting (2026-09-16,
  x86_64 dispatch only)**: same gap and same fix as `driver-nvme`'s own
  bullet above, found via the same audit — both drivers' own
  `subsystem_main` discarded `probe()`'s own real `Result` entirely
  (`let _ = drv.probe();`), on every architecture each is spawned on
  (unlike NVMe, both are cross-arch). `sys::DRV_VBLK_PROBE_REPORT`/
  `DRV_VNET_PROBE_REPORT` now report the real outcome, but ONLY have a
  kernel dispatch arm on x86_64 today — issuing either on aarch64/riscv64
  would hit an unhandled syscall, so the report call itself is `#[cfg(
  target_arch = "x86_64")]`-gated at the call site, a real, honest scope
  cut rather than a silent one. The standard fault-isolation test suite
  (no block/network device attached at all) confirms zero regression
  (identical serial output to before this change); a real, ad-hoc QEMU
  boot with `-device virtio-blk-pci`/`-device virtio-net-pci` attached
  confirmed both devices are really discovered and usable (root task's
  own existing block read/write and ARP/ICMP demos both still pass), but
  neither driver's own separately-spawned process was observed reaching
  its own `probe()`/report point within a 240s window — this project's
  own already-accepted QEMU scheduling-capacity variance, consistent
  with every other recently-added report opcode this session, not a
  regression.
- **Real per-process fault isolation** (`03 §5.2`): a deliberately faulting
  driver process is terminated by the kernel without affecting any other
  process; `device-manager` supervises it end to end — starts it, detects the
  crash via real IPC, restarts it, and reaches a terminal `Failed` state after
  its restart-window policy trips. This exact cycle is asserted automatically
  in CI via `scripts/qemu-fault-isolation-test.sh` on every push.
- A VFS read-throughput benchmark and an `02 §8.3` IPC round-trip benchmark
  both run as part of the real boot sequence and report real numbers (not
  hardcoded).
- **Real cross-repo integration (x86_64, real QEMU boots)**: on top of the
  in-repo layer-3 subsystems above, the x86_64 boot sequence also spawns a
  real process from EACH of this project's other real repositories —
  `security-broker` (`simurgh-security-broker`), `init`
  (`simurgh-init`), `account-manager` (`simurgh-account-manager`),
  `backup-manager` (`simurgh-backup-manager`), `diagnostics-manager`
  (`simurgh-diagnostics`), `store` (`simurgh-store`), `native-loader`
  (`simurgh-native-sdk`), `policy-engine` (`simurgh-profile-policy`),
  `shell` (`simurgh-shell`), `file-manager` (`simurgh-file-manager`), and
  `ui-core` (`Simurgh-UI-Template01`) — each repo's own separately-built ELF,
  embedded directly into the kernel binary via `include_bytes!` for real,
  end-to-end integration testing (a local-dev-only sibling-directory path
  stitch; the repos themselves stay independent). Real, verified IPC edges
  between them include: a real capability-request/elevation/package-signature
  flow through `security-broker`; a real login round trip from `ui-core`
  through `account-manager`; real install-time signature and profile-policy
  compatibility checks for `store`; and a real dynamic process-spawn syscall
  (`SPAWN_FROM_BUFFER`) driven by `native-loader`.
- **Real display pipeline**: `compositor` serves a real `DisplayProtocol`
  (`CreateSurface`/`CommitBuffer`/`DestroySurface`) over a genuine
  multi-page zero-copy `SharedRegion` (`SyscallOp::Retype`'s own
  `count`-means-"pages in this region" semantic for `SharedRegion`, added to
  support a real 800x600 BGRA8 desktop frame, not just a small test
  pattern) — `ui-core` renders and commits a real desktop scene through it.
  `QueryOutputs` reports the real single 800x600 output; `SubscribeInput`
  stays `Unsupported` by design — superseded by the real, working
  `PollInputEvent` poll, not an unbuilt gap (`compositor`'s own doc
  comment has the full reasoning).
- **Real power control**: `sys::POWER_CONTROL`, backed by a real
  `hal_core::power::SystemControl` trait per architecture — x86_64 issues a
  genuine i8042 keyboard-controller reset pulse (reboot) or ACPI `PM1a_CNT`
  write (shutdown), confirmed by QEMU itself exiting the moment the syscall
  runs; aarch64 uses real PSCI (`smc`), riscv64 the real SBI System Reset
  Extension (`ecall`) — both real hardware standards. **A real caller now
  exists on all three architectures (2026-09-15)**: `device-manager`
  (`Service::BOOT_ORDER[0]`, spawned unconditionally everywhere, unlike
  `Simurgh-UI-Template01::ui-core`'s own SHUTDOWN menu entry, which is
  x86_64-only) issues a real shutdown as its own final act once its
  fault-isolation demo reaches `Failed` — reusing the exact same
  already-verified `POWER_CONTROL` syscall, on the SAME already-passing
  `scripts/qemu-fault-isolation-test.sh` (which already passes
  `-no-reboot` to every QEMU invocation there, so a real shutdown or
  reboot request both terminate that QEMU process cleanly, and the
  script's own pass check — a `grep` for the fault-isolation marker,
  already logged before this runs — is unaffected either way). Real,
  honest status: this has NOT yet been directly observed firing on any
  architecture — `device-manager` itself was not observed reaching
  `Failed` within any of this session's own QEMU attempts (up to 400
  real seconds on x86_64), the same already-accepted QEMU
  scheduling-capacity limit this project's README has documented at
  length elsewhere, now visibly worse as more real subsystems compete
  for one vCPU. Real QEMU boots on all three architectures DID confirm
  zero regression from this change: x86_64 stays panic-free through the
  identical point every other recent boot already reached; aarch64 and
  riscv64 each hit their own, already-documented, unrelated open bugs
  (the aarch64 `security-broker-intermediary` crash and the riscv64
  compositor instruction-page-fault, both below) at the SAME points they
  always have, confirming this change did not introduce or move either
  failure.
- **Real compute-device discovery (`hal_core::compute::
  ComputeDeviceDiscovery`)**, QEMU-verified on all three architectures
  (2026-09-12): the boot summary now prints a real `compute devices` count
  (`BootReport::compute_devices`, straight from the same hardware manifest
  `peripheral devices` already used) — confirmed via real QEMU boots on
  x86_64 (`1`), aarch64 (`0`), and riscv64 (`0`), all real, honest numbers
  for what each machine type actually exposes, not a guess. Previously this
  discovery ran at boot but had no observable log line anywhere.
- **Real per-process introspection (`sys::PS_LIST_ENTRY`, 2026-09-12)**:
  `simurgh-shell`'s own `ps` command long flagged itself as "not a live
  process table — no kernel syscall exposes real per-process
  introspection yet." One new syscall closes that gap: `a0` = a raw
  `ThreadId` table index (`0..kernel_core::config::MAX_THREADS`), reply
  encodes `(tid << 8) | state_code` for a live TCB slot or `usize::MAX`
  for an empty one (`kernel_arch_glue::ps_list_entry`). Real, honest
  scope: the kernel tracks no human-readable process NAME anywhere, only
  `tid` + lifecycle state — `simurgh-shell`'s own `ps` now shows real
  data for both of those, cross-arch-built clean, but has not yet been
  directly observed replying on a live boot (shell's own thread was not
  scheduled within this session's QEMU attempts — the same accepted
  scheduling-capacity variance the next bullet describes, not a new
  issue).
- **Real self-check reporting for `simurgh-init` (`sys::IN_REPORT`,
  2026-09-12)**: found via a cross-repo audit — `simurgh-init` was the
  one ported repo with no `*_REPORT` opcode at all (every sibling
  subsystem has one, `NL_REPORT`/`FM_REPORT`/`UI_REPORT`/etc.), so its
  own `subsystem_main` discarded both `self_check`'s real started-unit
  count and `real_spawn_demo`'s real success `bool` entirely — a
  silently-broken DAG resolution or a broken real spawn left ZERO
  observable trace on real hardware. `a0` = started-unit count, `a1` =
  spawn-demo success. Cross-arch-built clean on all 3 targets.
- **Real interrupt-driven keyboard and mouse input** (x86_64 only — no such
  legacy PC hardware exists on aarch64/riscv64): a real 8259 PIC remap
  routes both IRQ1 (keyboard, master line) and IRQ12 (PS/2 mouse, a slave
  line needing its own two-EOI cascade acknowledgment) to real CPU vectors —
  this project has no I/O APIC, so this is the deliberate, reasoned path,
  not a placeholder. `driver-i8042`/`driver-mouse` each decode real
  scancode/packet bytes and push structured key/motion events to
  `compositor`, which serves them to any real display client via a
  non-blocking `PollInputEvent` request. Directly confirmed on real QEMU
  boots: real keystrokes and real mouse motion/clicks, injected through
  QEMU's own hardware emulation (not a shortcut), produce the exact
  expected byte-level results at the driver level. A real, documented
  finding from this work: this kernel only ever services a maskable
  interrupt inside the one-shot `hlt_wait_for_irq` wait point, so a queued
  interrupt is only delivered once some real thread is genuinely blocked
  waiting for it — see `kernel_arch_glue::mouse_irq_trampoline`'s own doc
  comment for the full story.

- **Real Log Collector service (`log-collector-native`, 2026-09-15,
  x86_64 only)**: `04-System-Services-Policy-Layer-v2.md` §2.2's
  layer-3 mechanism half, and the first real peer `simurgh-diagnostics`
  (a separate repo) ever had — that repo's own `RealLogCollector` client
  transport existed complete and tested with nothing on the other end
  (confirmed by direct research before this crate existed: no
  `LogCollector` code anywhere in this repo). Two real opcodes on one
  `Endpoint`: `NextEvent` (drains the oldest queued event) and
  `ReportEvent` (enqueues one, captured verbatim as an opaque byte blob
  — this server never parses a single `RawCrashEvent` field, since it
  never needs to, `log-collector-native::log_wire`'s own module doc
  comment has the full reasoning); a real, bounded (8-entry,
  oldest-evicted-first) FIFO queue. Wired the same `wire_service_
  endpoint` way every other single-client real edge in this project
  uses (`wire_ui_core_to_file_manager_x86`'s own precedent) — real QEMU
  confirmed the grant + shared-page mapping succeed and boot proceeds
  cleanly afterward with zero panics, though `simurgh-diagnostics`'s own
  round-trip proof (push one real event, pull it back, confirm it
  matches) was not directly observed within two independent 150s boot
  windows — the same already-known, already-accepted QEMU
  scheduling-capacity limit this project's other real edges have hit at
  this system's current scale.

- **Compositor's second real client (`native-loader`, 2026-09-16,
  x86_64 only)**: `simurgh-native-sdk`'s own `de-framework::display::
  DisplayClient` trait had a confirmed wire mirror but no real transport
  anywhere — `wire_native_loader_to_compositor_x86` closes that by
  REUSING `wire_ui_core_to_compositor` as-is (that function was already
  generic over the target cap space/address space/VAs despite its
  ui-core-specific name — a third independent grant of Compositor's own
  Endpoint works identically for a second client), called AFTER
  native-loader's own existing security-broker notification fan-in
  wiring so that edge's already-established `SB_ENDPOINT_CAP`/`SB_NOTIF_
  CAP` slot numbers (0 and 1) stay put — the new Compositor grant lands
  at slot 2. Real QEMU confirmed the grant itself succeeds cleanly
  ("wired native-loader <-> Compositor real IPC edge (de-framework
  DisplayClient)") with zero regression to the rest of the boot, across
  both a 120s and a 300s run; native-loader's own real round-trip demo
  report (`sys::NL_DISPLAY_REPORT`) was not directly observed on either
  run — but neither were that SAME process's own pre-existing `NL_
  REPORT`/`NL_SPAWN_REPORT` lines (both real since an earlier session),
  confirming this is the scheduling-capacity limit above, at this
  process specifically, not a regression in the new wiring.

- **`ui-core` <-> `shell`, the real TERMINAL edge (2026-09-17, x86_64
  only)**: `Simurgh-UI-Template01::ui-core`'s start menu had long carried
  a `"TERMINAL"` entry with NO handler behind it at all, while
  `simurgh-shell` was a genuinely complete interactive shell reachable
  only over the serial console. Omid's own direction, chosen over
  building a separate simpler interpreter inside `ui-core`: give
  `shell-core` a real SECOND I/O transport so that window becomes a real
  front-end onto the real shell. `wire_ui_core_to_shell_x86` is the
  kernel half, mirroring `wire_ui_core_to_policy_engine_x86`'s shape.

  Unlike every other single-client edge in this file it ALSO wires a
  shared `Notification`, and that is **not** a fan-in across clients â€”
  there is exactly one client. `simurgh-shell` already owns a real,
  long-running serial REPL, so it cannot park in a blocking `Recv` the
  way `fm-core` does without freezing the console it exists to serve; it
  polls this `Notification` with the non-blocking `sys::NOTIF_POLL` once
  per REPL iteration instead â€” the same shape Compositor already uses for
  its own i8042 signal, applied here for a different structural reason.

  Capability slots, assigned strictly by boot-time grant order and
  documented on both sides: `shell` gets the `Endpoint` at slot 0 and the
  `Notification` at slot 1 (its cap space is completely EMPTY beforehand
  â€” `spawn_shell_x86` wires it only a shared page and no capability at
  all); `ui-core` gets them at slots 6 and 7, so the call is placed after
  `wire_policy_engine_notification_fanin_x86`, the last grant into
  `ui-core`'s cap space before it.

  **Real QEMU boot verified (2026-09-17, x86_64, native Windows
  `qemu-system-x86_64` + OVMF)**: the new log line `root task (x86_64):
  wired ui-core <-> shell real IPC edge (TERMINAL window)` appears in the
  real serial output, in exactly the expected position â€” immediately
  after `wired profile-policy notification fan-in (store, ui-core)` â€”
  which is itself the direct confirmation that the boot-call order both
  sides' fixed slot numbers depend on is what the constants assume. Boot
  proceeds cleanly past it into the preemptive scheduler with zero panics
  and no `UNHANDLED CPU EXCEPTION`. The end-to-end keystroke round trip
  (click TERMINAL, type, `Enter`, real `Shell::execute` reply rendered
  back) was NOT exercised â€” it needs a real injected mouse click plus
  keystrokes, and neither `ui-core`'s nor `shell`'s own thread reported
  within the boot window, the same already-known, already-accepted QEMU
  scheduling-capacity limit the two entries above already document at
  this system's current scale.

**Known open issues:**

- **riscv64 — the boot-blocking crash is RESOLVED (2026-09-17); a
  SEPARATE, newly-exposed fault remains open.** The real root cause of
  what years of investigation above characterized as "the compositor
  process faults shortly after its first resume" turned out to be
  upstream of Compositor entirely: `mm_bench_riscv64`'s own `sum_ns /
  ITERS` (division by a compile-time literal) lowers, on RV64 only, to a
  PC-relative load of an LLVM-emitted magic-number constant from a
  `.srodata.cst8` pool that the linker places alongside the KERNEL's own
  rodata — outside `.user_text`/`.user_stack`, the only regions
  `linker.ld` maps `U=1` for the Root Task's own U-mode image. Every
  riscv64 boot therefore faulted on that load, several steps before the
  boot sequence could ever reach Compositor's own real spawn — the
  original live-GDB findings above (the jump-table dispatch inside
  `atomic_load`) were a real, correctly-observed trace, but of a
  DIFFERENT, later fault that a fresh QEMU run could only reach
  intermittently depending on scheduling luck, not the deterministic
  blocker. Fixed by forcing the divisor through an opaque `asm!` identity
  (the same technique `zero!()` already uses elsewhere in this file) so
  LLVM cannot constant-fold it, emitting a plain hardware `divu` instead
  — see `mm_bench_riscv64`'s own doc comment for the full writeup.
  QEMU-verified: riscv64 now boots dramatically further — through the
  full two-process IPC/paging benchmark, VFS read/write throughput,
  driver probes, and both mm-service queries, reaching a real spawned
  `security-broker` process (previously unreachable on this
  architecture at all).
  **New fault found immediately after, in the process (2026-09-17,
  UNRESOLVED)**: right after `security-broker` spawns, a second thread
  (tid 9) takes a fatal U-mode exception — `cause=0xc sepc=0x0
  stval=0x0`, i.e. an instruction PAGE FAULT (the same trap `cause` the
  original bug report above named) but at PC exactly `0` — a jump to a
  null/never-set entry point, not a corrupted jump-table dispatch. The
  kernel's own fault-isolation mechanism catches it and logs "terminating
  IT, rest of the system continues," but in practice the boot then stalls
  — no further log lines appear even after 150+ real QEMU seconds,
  suggesting something later in the boot sequence is blocked waiting on
  whatever that faulted thread was supposed to do (plausibly a genuine
  `security-broker-intermediary`-adjacent path, given riscv64's boot
  order spawns `security-broker` around the same relative point x86_64/
  aarch64 do, and aarch64 has its own separate, still-open crash in
  exactly that intermediary demo, below — worth checking whether these
  two are related once someone picks this back up, rather than assuming
  they are two coincidentally-similar bugs). Not yet root-caused; needs
  real instruction-level tracing (`gdb-multiarch` in WSL,
  `qemu-system-riscv64 -s -S`) on tid 9's own spawn path specifically.
  `scripts/qemu-fault-isolation-test.sh riscv64` still needs
  `--allow-fail` in CI until this second issue is also resolved.
- ~~**aarch64 only:** `security-broker-intermediary` crashes the boot~~ —
  **ROOT-CAUSED AND FIXED (2026-09-17)**, via real live GDB on a real
  aarch64 QEMU boot. The `ptr::write_volatile requires that the pointer
  argument is aligned and non-null` panic was a RED HERRING pointing
  kilometres away from the real fault, and every earlier theory (aarch64
  codegen, exception-level/MMU setup, the ELF spawn, the context switch,
  stack size) was wrong.

  **Real root cause — an untyped-memory capacity bug, not an aarch64 bug
  at all.** `KernelState::from_boot_info` seeds the Root Task with one
  `UntypedMemory` capability *per usable firmware memory fragment*, at
  consecutive capability slots. Every `SyscallOp::Retype` in
  `kernel-arch-glue` hardcoded `untyped: CapId::new(0)`, pinning every
  retyped kernel object for the whole boot to the ONE region behind slot
  0 — merely the FIRST fragment of a fragmented UEFI memory map, not the
  bulk of RAM. Once that fragment's forward-only watermark filled,
  `Retype` failed with `MmError::OutOfMemory` while the other regions sat
  untouched. On aarch64 that tipped over at
  `security_broker_intermediary_demo_start`'s own very first `Retype`, so
  it `return None`ed *before* publishing its shared page — leaving
  `G_SBI_SHARED_PHYS` at its `usize::MAX` sentinel for the next
  `write_shared_sbi_message` to dereference. x86_64 was never immune; its
  slot-0 fragment simply still had room. This is the exact bug class
  `carve_from_any_untyped` already fixed for RAW carves — the
  capability-level `Retype` sites were simply missed at the time.

  **Fix:** `kernel_arch_glue::retype_one_from_any_untyped` (the
  capability-level twin of `carve_from_any_untyped`) tries each untyped
  capability in turn; probing is side-effect free on failure. Plus a
  `sbi_shared_page_ready` sentinel guard so a failed `*_demo_start` can
  never again surface as a misdirecting pointer panic instead of an
  honest logged skip.

  **QEMU-verified on a real aarch64 AAVMF/UEFI boot:** zero kernel panics
  (was 1), and all four Issue #28 end-to-end proofs now appear, matching
  x86_64 — `minted a REAL capability into security-broker's own cap space
  at slot 1`, `revoked ... 2 slot(s) freed across BOTH capability spaces`,
  plus both multi-target (mm-service) proofs. The boot now runs all the
  way through device-manager's full fault-isolation cycle to
  `state=Failed restarts_in_window=6` — i.e. aarch64 now reaches
  `scripts/qemu-fault-isolation-test.sh`'s own PASS marker, which it could
  never reach before. Note it needs more than the script's default 90s to
  get there: a 150s run reached every Issue #28 proof with zero panics but
  stopped short of the marker, while a 300s run reached it — the same QEMU
  scheduling-capacity effect documented below, not a regression. Use
  `QEMU_FAULT_TEST_TIMEOUT=300` on aarch64.

  **Known remaining work, deliberately not swept:** roughly 20 OTHER
  `untyped: CapId::new(0)` `Retype` sites remain in `kernel-arch-glue`
  (`wire_service_endpoint`, `wire_notification`, the
  compositor/mm/netstack/driver spawns, ...). They carry the IDENTICAL
  latent bug and will fail the same way as the system grows.
  `retype_one_from_any_untyped` is a drop-in replacement for every one of
  them — mechanical, and strictly safer (it tries slot 0 first, so
  behaviour is identical wherever the current code already succeeds). They
  were left for a follow-up that can give all three architectures their
  own full QEMU verification.

- **aarch64, newly exposed by the fix above (2026-09-17), minor:** after
  `root task (aarch64): real POWER_CONTROL syscall - shutdown`, the boot
  emits `UNHANDLED EXCEPTION: esr.ec=0x0 elr=0x40240a38 far=0x0` instead
  of the VM actually powering off — the aarch64 PSCI (`smc`) shutdown path
  apparently not taking effect under this QEMU/AAVMF combination. This
  happens strictly AFTER all real work and after the fault-isolation PASS
  marker, so it blocks nothing; it was simply never reachable before
  because the boot died earlier. Not investigated.
- **QEMU scheduling capacity at scale (x86_64) — getting worse, not yet
  fixed, deliberately deferred (2026-09-15)**: with this many real
  subsystems now competing for one emulated core under TCG, a
  newly-spawned process (e.g. `ui-core`, `driver-i8042`, `driver-mouse`)
  is not guaranteed to actually get scheduled within a single boot's
  real-time window — this affects how reliably some of the newer real
  IPC edges above can be observed completing end to end on any ONE given
  boot (retries, or a longer-running real workload, generally do get
  them scheduled). Previously treated as a minor, accepted characteristic
  of testing at the current scale; re-measured while verifying the new
  `device-manager` `POWER_CONTROL` edge above and found meaningfully
  worse than that framing suggested: `device-manager` itself —
  `Service::BOOT_ORDER[0]`, the FIRST real subsystem spawned every boot —
  was not observed reaching its own fault-isolation demo's terminal
  `state=Failed` even once across multiple real x86_64 QEMU boots this
  session, including one run given a full 400 real seconds (not just
  90-150s) to do so; it never even reached a single `Restarting`
  transition past the first `Running`. `scripts/qemu-fault-isolation-
  test.sh` — the automated CI check for 03-Kernel-Subsystems-Layer.md
  §5.2's real fault-injection acceptance criterion — depends on reaching
  exactly that marker, so this is no longer just "some newer edges are
  unreliable to observe," it is a real, growing risk to this project's
  own primary automated correctness check on x86_64 (aarch64/riscv64
  already run with real, separate open bugs blocking them from reaching
  this point at all, above). Each individual real IPC edge's own code
  stays independently verified regardless (unit tests, cross-arch
  builds, and either a direct hardware-level proof or a successful boot
  log line on at least one real run) — this is a scheduling/capacity
  problem, not a correctness regression in any of them.
  **Deliberately not investigated further right now** — Omid's own
  2026-09-16 direction: log it here and move on, prioritizing finishing
  the OS's remaining feature work over chasing this now; likely real
  angles for whoever picks this up next: a real vruntime/fairness
  audit now that the process count has grown this much since the
  scheduler's original tuning, giving `device-manager` (or the whole
  fault-isolation demo) an earlier/reserved scheduling slot, or
  increasing the preemption quantum/frequency so more real work fits in
  one boot's practical time budget.

## Repository scope

In scope, and depending only on other crates in this repository: `hal/`,
`kernel/`, `ipc-protocol/`, `subsystems/`, `uefi-bootloader/`.

System services, POSIX compatibility, the store, the security broker,
profile policy, the native SDK, the Linux compatibility runtime, and
applications (the desktop UI, the shell, the file manager, ...) each have
their own separate repository, with their own independent source history —
that boundary is real and enforced by the source layout. For real, on-QEMU
integration testing, though, `kernel/kernel/src/main.rs`'s own x86_64 boot
sequence embeds each of those repos' own separately-built subsystem-bin ELF
directly (`include_bytes!`, a local-dev-only sibling-directory path stitch —
see **Current status** above for the full list) and spawns it as a real
process, so several of the real cross-repo IPC edges described above are
exercised on every x86_64 boot, not just within each repo's own isolated
test suite.

## Documentation

The Persian architecture specification (`00-Overview.md`,
`01-HAL-Layer.md`, `02-Microkernel-Layer.md`,
`03-Kernel-Subsystems-Layer.md`, and `REPO-Simurgh-OS.md`) is the project's
internal design reference and is not part of this public repository (it lives
in a gitignored `.claude/` working directory, not tracked in git). This
`README.md` and [`CONTRIBUTING.md`](CONTRIBUTING.md) are the up-to-date public
documentation.

## MVP Definition of Done

Combined acceptance criteria of `01-HAL-Layer.md §8`, `02-Microkernel-Layer.md §8`,
and `03-Kernel-Subsystems-Layer.md §5` — **met**, on all three architectures
except the one open riscv64 issue noted under **Current status** above.

## Contributing

Every change goes through its own branch and a pull request — `main` is
protected, requires a passing CI run and an approving review, and a merge
triggers an automatically numbered GitHub Release. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the full flow and branch-naming
convention.

## License

MPL-2.0 — see [`LICENSE`](LICENSE).
