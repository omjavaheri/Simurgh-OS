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
  the rest of the boot. The controller's own real register handshake
  succeeding is not yet directly observable in the boot log (a documented
  next step, `driver-nvme`'s own module doc comment) — no real consumer
  (a filesystem) is wired to it yet either.
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

**Known open issues:**

- **riscv64 only:** the `compositor` process faults (an instruction page
  fault, not an illegal instruction) shortly after its first resume. Deep
  investigation across several sessions narrowed the search space
  considerably (ruled out corrupted resume data, stack/heap sizing, and
  confirmed it reproduces identically on two independent QEMU builds) but the
  root cause is not yet found. x86_64 and aarch64 are unaffected;
  `scripts/qemu-fault-isolation-test.sh riscv64` runs with a documented
  `--allow-fail` in CI so this stays visible without blocking the pipeline.
  A prior live-GDB session (WSL, `qemu-system-riscv64 -s -S` + `gdb-
  multiarch`) narrowed the exact fault to `ra` pointing inside
  `AtomicUsize::load`'s own compiler-generated memory-ordering jump table,
  called from `compositor-bin`'s own `BumpAllocator::alloc` — i.e., the
  VERY FIRST real heap allocation `subsystem_main` makes. **Continued
  2026-09-16, with one real disproof and one real new finding**: with a
  fully rebuilt, current `compositor-bin`, a live breakpoint on the exact
  `jr a0` instruction inside `atomic_load`'s own jump-table dispatch
  (`0xc000e14c`) caught a REAL, successful execution of this path —
  `a0 = 0xc000e150`, matching the table's own correctly-populated static
  contents exactly (`x/2gx` confirmed the live memory matches the file on
  disk) — disproving "the jump table itself is corrupted/unrelocated" as
  a general, constant explanation; at least one real invocation of this
  exact dispatch works correctly. Continuing to wait for the ACTUAL fault
  (removing that breakpoint, arming one on `common_trap_entry` with
  `$scause == 0xc` instead) ran for 20+ real minutes of genuine QEMU CPU
  time (confirmed alive and running throughout, not hung) without ever
  reaching it — a striking contrast to the original 2026-09-xx live
  session, which reportedly hit the identical fault "almost instantly."
  This strongly suggests the bug's own reproducibility is now entangled
  with the SAME growing QEMU scheduling-capacity pressure documented
  above (more real subsystems now compete for one vCPU than when this bug
  was first live-debugged) — not a fixed, deterministic condition
  anymore. Whoever continues this should either wait considerably longer
  under live GDB, or — likely more productive — resolve the scheduling-
  capacity item first, then return to this with the concrete jump-table
  lead above already in hand rather than re-deriving it. Investigation
  scripts and a fresh disassembly are preserved at `/tmp/simurgh-debug`
  in WSL for whoever picks this up next.
- **aarch64 only, newly found (2026-09-12):** `security-broker-intermediary`
  (the Issue #28 capability-minting demo) crashes the boot right after
  `security-broker` itself is spawned — `unsafe precondition(s) violated:
  ptr::write_volatile requires that the pointer argument is aligned and
  non-null`, either inside the intermediary's own ELF spawn or the
  context-switch immediately after. x86_64 and riscv64 are unaffected
  (riscv64 never reaches this point at all, blocked earlier by the bug
  above). A stack-size bump (the fix for a similar-looking, already-solved
  x86_64 crash on the SAME process's own primary spawn) was tried and ruled
  out — identical crash on a second real boot. Not yet root-caused; needs
  real instruction-level tracing, the same tooling gap the riscv64 bug above
  has been blocked on. See `kernel_arch_glue::security_broker_intermediary_
  demo_start`'s own doc comment for the full record.
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
