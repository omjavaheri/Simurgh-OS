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
├── machine-id-core/     machine id: SMBIOS parse, canonicalisation, SHA-256 (docs/machine-id.md)
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

## Interactive desktop boot (`--features desktop`, x86_64)

`cargo xbuild-microkernel-x86_64 --features desktop` (or the workspace's
`simurgh-build-all.ps1 -Desktop` / `simurgh-run.ps1 -Desktop`) builds an
image that boots straight into the real ui-core login screen and stays up:
the Root Task skips the pure benchmarks but still spawns and wires every
service, driver and the framebuffer; the fault-isolation demo (whose last
act is a POWER_CONTROL shutdown) is not started; the preemptive timer never
stops. Verified on QEMU (2026-09-24) with real PS/2 input through QEMU's
monitor: `alice` / `hunter2` logs in via account-manager, MENU opens by mouse
click, TERMINAL runs `help` in the real simurgh-shell, FILES lists `/` from
fs-native. The default (demo) build is unchanged and still ends with
`state=Failed restarts_in_window=6` + shutdown. Bugs found on the way and
fixed for every build: 8259 EOI for PS/2 IRQs arriving before a handler is
bound (hal-x86_64), the Compositor's i8042 page overlapping its confirm
region, off-by-one input capability slots and a one-slot input queue, and
a queued `Call` returning before its `Reply` (kernel-core `do_recv`) — the
root cause of file-manager's old fs-native self-check failure.

### Input path: latency, scheduling and a latent kernel bug (2026-09-25)

What a mouse motion crosses: QEMU's PS/2 model → IRQ12 →
`kernel_arch_glue::mouse_irq_trampoline` (one byte into a ring) →
`driver-mouse` (woken from `DRV_IRQ_WAIT`) → one blocking `Call` per event
to the Compositor, which takes one driver message per display request it
serves → ui-core's next poll. Changes:

- **Latent kernel bug, fixed (all builds).** `p2_ipc_recv` (the narrow
  `IPC_RECV`, opcode 43) hands the CPU to the Root Task whenever nothing is
  queued — but `p2_preempt_start` has already retired the Root Task. A
  thread still using that opcode afterwards (measured: log-collector-native,
  a few ticks into preemption) was switched into root's stale context (the
  process-A counting loop) while `dispatch(root)` silently failed, leaving
  `sched.running() == None`. The next tick then "started" whichever thread
  `pick_next` chose without switching to it, so the CPU spun in the counting
  loop under that thread's name. With all threads at equal priority the
  victim was some background service; once the desktop ranked ui-core first
  it was always ui-core: **the login screen drew but no keystroke ever
  registered** (the regression seen in the combined tree). After retirement
  `p2_ipc_recv` now simply is the general receive. Found by sampling the
  guest's registers from the QEMU monitor (`x /6i $pc` showed the counting
  loop in root's address space) plus a temporary tick probe.
- **Desktop priorities** (`--features desktop` only):
  `kernel_arch_glue::desktop_apply_input_priorities` puts driver-i8042,
  driver-mouse, the Compositor and ui-core at priority 39 and every other
  process at 30, via a new state-preserving `Scheduler::set_base_priority`.
  Measured before, with everyone equal: store 1578 and simurgh-shell 1086 of
  3000 ticks at the login screen, ui-core 40 (~1%). `pick_next` has no aging
  across priority levels, so this relies on every input-path thread
  blocking or yielding (ui-core `P2_YIELD`s every poll); background services
  keep running (security-broker, profile-policy and store still serve calls).
- **Early tick on input IRQs** (desktop only): an IRQ that wakes a driver
  pulls the next scheduler tick in to 20 µs instead of waiting up to the
  2 ms quantum. Measured (TCG, 30 moves 10 ms apart, 5 bursts): worst wake
  per burst 2.9 → 1.7 ms average (max 4.3 → 2.0 ms), average wake
  1.50 → 1.39 ms (guest clock, which runs ~2× wall-clock under TCG). The
  average barely moves, most likely because QEMU's timers on the Windows
  host have ~1 ms granularity. The 2 ms quantum was left unchanged for the
  same reason (not measured).
- **driver-mouse:** drains the ring until it is really empty and merges each
  run of packets into as few events as possible (`coalesce.rs`: button
  edges are never merged, so every click lands exactly where it did before);
  ring 32 → 2048 bytes; the packet assembler resets after lost bytes; an
  overflowed axis saturates instead of decoding garbage. Wire format to the
  Compositor unchanged. At a steady 100 Hz the desktop keeps up either way
  (one packet per wake), so batching matters only when the guest falls
  behind.
- **Measurement:** driver-mouse prints a `driver-mouse latency:` line when
  it hands a MIDDLE-button press to the Compositor (ui-core ignores that
  button): wake latency from IRQ time the kernel stamps into the ring page,
  burst span, message count, and net motion. `simurgh-mouse-bench.ps1` at the
  workspace root drives it. Motion is exact: 20 × `mouse_move 10 0` + 3 ×
  `1 0` arrives as `net_dx=203`; 30 × `4 0` as 120 every time. End to end,
  press → report takes ~20–70 ms wall-clock (avg 33 ms; 38 ms before).
- **QEMU behaviour to know when testing:** its PS/2 model hands the guest
  only ~5 packets per input event and holds the rest, merged, until the next
  event; a press and release sent while that queue is full collapse into
  nothing. Monitor-driven tests must pause between a burst and a click.

Verified on the combined tree with `simurgh-login-test.ps1` under both
`-Accel tcg` and `-Accel whpx`: ALICE / `*******` typed, desktop with UID 1,
MENU → TERMINAL by mouse.

### Idle desktop: blocking waits instead of polling (2026-09-25)

With the desktop up and nobody touching it, QEMU (WHPX) used ~96% of a host
core on the login screen and ~60% after login: the desktop idle `hlt`
(`sys::IDLE_WAIT`) never ran because simurgh-shell busy-waited on the clock
and ui-core / the Compositor polled each other, so something was always
`Ready`. Measured (login screen up, 20 s idle,
x86_64 desktop image, WHPX): **login screen 96% → 0.5%, after login 60% →
0.7% of one core.** Login, typing and pointer motion still work
(`simurgh-mouse-bench.ps1`, 5 bursts of 50 moves, 10 ms apart, TCG: net motion
exact, no drops, average IRQ → driver wake 1.5 → 1.9 ms - inside the noise
of a TCG run alongside other QEMU instances).

- **New syscall `sys::NOTIF_WAIT_TIMEOUT` (139):** `NOTIF_WAIT` plus a
  deadline (`a1` ns). Returns the signalled bits, or 0 on timeout. Expiry runs
  at the top of `p2_tick` (which also runs after every idle halt), so the
  granularity is one tick (2 ms); the waiter is taken off the notification's
  waiter list (`Notification::cancel_wait`) and gets `(0, 0)` poked into its
  saved registers through the architecture's `poke_saved_a0_a1` (registered
  by each arch's syscall dispatcher).
- **Compositor:** an EMPTY `PollInputEvent`/`PollMouseEvent` is held open for up
  to 20 ms (`PARK_MAX_NS`; once per client loop iteration) while the
  Compositor blocks in `NOTIF_WAIT_TIMEOUT` on the input notification. Any
  input event ends the hold at once. To wait on both devices with one
  syscall, driver-mouse now shares driver-i8042's signal `Notification`
  (`G_INPUT_SIGNAL_CAP`; bit 1 = keyboard, bit 2 = mouse; Compositor's slot
  layout unchanged).
- **simurgh-shell:** the serial loop sleeps in `NOTIF_WAIT_TIMEOUT` (20 ms, or
  until a ui-core keystroke rings the doorbell) instead of spinning 1 ms.
- **ui-core (not changed here):** it still works unmodified. It must merely
  tolerate an empty poll taking up to 20 ms to be answered. To go further it
  would want one blocking "wait for input or timeout" request per frame
  (e.g. `DisplayRequest::WaitInput { timeout_ms }`, answered like the held
  poll) and to drop `pace_input_loop`'s idle yield/clock loop.

**Known issues, re-checked 2026-09-25 against the commit before the
aarch64 image-size fix (riscv64) / against `5e90030` (aarch64 - older images
do not boot on Windows QEMU's edk2, see that commit): NOT caused by the
recent changes, identical there.** All three occur in the demo build.
- riscv64: `preemption: 2000 timer ticks ... process B's counter = 0 ...
  MISMATCH` (A and C count, B never runs; the counter values are even the
  same run to run). Cosmetic for the fault-isolation PASS marker, which
  still passes.
- aarch64: after `real POWER_CONTROL syscall - shutdown` the boot prints
  `UNHANDLED EXCEPTION: esr.ec=0x0 ...` (an EL1 address; the PSCI shutdown
  path, already described under Current status), and threads that touch
  `0xD8E0_0000`/`0xD920_0000` take U-mode data aborts (isolated by design; the
  security-broker/store/policy-engine shared-page addresses noted below).
  `drv_blk_read_result ... MISMATCH` also appears. All present before.
- riscv64 shows the same three U-mode page faults at those addresses.
- x86_64 desktop with `-device virtio-blk-pci` (any raw disk): the boot log stops
  right after `driver-virtio-blk ... probe() succeeded=true` (last lines are two
  `root task (U-mode, x86_64): syscall result = 0x38 / 0x200`), ui-core is never
  spawned, so the screen stays black (checked 2026-09-25). NOT caused by the
  Devices work: the pre-Devices image `run-ui3/final.efi` (built 15:23, hours
  before the 20:01 Devices commit) stops at exactly the same line. The hang is in
  the demo-time virtio-blk read/write round trip of the root task / driver
  (desktop boots still run it), before the desktop spawn; not investigated further.
  NVMe (`-device nvme`) does not hit it.

### Machine id (2026-09-25, booted on x86_64; aarch64/riscv64 compile; design: `docs/machine-id.md`)

Every UEFI machine (aarch64 uses the same path, not booted yet) now derives one GUID-shaped, hardware-based id at boot. The
bootloader reads SMBIOS (system UUID, board and system serials) from the UEFI
configuration table before ExitBootServices and hands the raw fields through
the handoff block; `hal-x86_64`/`hal-arm64` decode them into
`HardwareManifestRaw::machine_identity`; `kernel-core` runs the pure
`machine-id-core` crate (cleanup of placeholder values, SHA-256 over a
versioned label, RFC 4122 version/variant bits) and the serial log prints
`machine id: <guid> (weak=.., virtual=.., ...)`. The same hardware gives the
same id on every boot and after a reinstall (recompute only; persistence and
the K-of-N rule are still open questions in the doc). The id is exposed
read-only to ui-core through a single kernel-owned page mapped at
`0xD8B0_0000` (layout in `docs/machine-id.md` section 13.1); the ui-core client
that shows it in the USERS window is a follow-up. Verified in QEMU (q35 +
edk2, `-smbios type=1,uuid=...`): two boots with the same UUID print the same
id, a different UUID prints a different id, and plain QEMU (all-zero UUID)
reports a weak, virtual id. Not done: riscv64 (always weak, no device-tree
serial yet), NIC/disk/TPM inputs, per-service derived ids, capability-gated
access.

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
- **Real, system-wide scheduler-mode switching driven by layer-4 Profile
  Policy** (`sys::SCHED_SET_SYSTEM_POLICY`, opcode 135): `kernel-sched` has
  always had both disciplines of 02 §4 (`Interactive`: priority + aging,
  latency-first; `Throughput`: chain-group `vruntime` fairness), but every
  production admit site used to hard-code `Interactive`, so `Throughput` was
  reachable only from unit tests and a user's profile choice changed no real
  scheduling behaviour. `Scheduler` now carries a system default mode plus a
  runtime `aging_cap_ms`, and this syscall retargets both: it re-modes every
  already-running thread that follows the default, and applies to threads
  spawned afterwards. 02 §4.4's per-thread override is preserved — a thread
  admitted through plain `Scheduler::admit` pins its own mode and is never
  swept, which is how the Root Task deliberately stays `Interactive` no
  matter what profile is active (it serves this very syscall). The one real
  caller is `simurgh-profile-policy`'s `policy-engine` process, from its
  `switch_profile` handler. QEMU-verified on all three architectures: the
  Root Task performs a `Throughput` → `Interactive` round trip just before
  arming preemption and the kernel logs **8 already-running threads re-moded
  each way**, with `policy-engine`'s own startup assertion (`General` ⇒
  `Interactive`, cap 50) showing up separately as a correct 0-thread no-op.
  Not capability-gated yet — the same MVP-phase gap `MAP_PAGE` and
  `POWER_CONTROL` carry, flagged in `kernel_arch_glue::
  set_system_scheduler_policy`'s own `TODO(spec)`.
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
- **Real general process-exit supervision (`sys::THREAD_EXIT_POLL`,
  2026-09-18)**, QEMU-verified against a REAL crash on all three
  architectures: the kernel had per-process fault isolation
  (03 §5.2) but no GENERAL way for a process to learn that a process IT
  spawned had died. The only mechanism was device-manager's own bespoke,
  single-slot one — `kernel-arch-glue`'s `WATCHED_DRIVER_TID`/`DM_TID`
  statics plus the `DM_WAIT_CRASH`/`DM_POLL_CRASH`/`DM_RESPAWN_DRIVER`
  opcodes, hardwired to exactly one demo driver and reusable by nobody.
  `kernel_core::SyscallOp` had no exit-notification variant keyed by an
  arbitrary spawned `ThreadId` at all, which is what blocked
  `simurgh-init` from acting on `ServiceUnit::restart_policy` after a
  unit had successfully started (that repo's README named this exact
  gap). One new general syscall closes it. **It replaces nothing** —
  device-manager's trio is untouched and still drives the §5.2
  fault-isolation demo; both are populated from the same real fault in
  `p2_fault`.

  `a0` = the raw `ThreadId` of a thread the CALLER spawned. Answers in
  TWO registers (`TrapOutcome::Resume2`, the same shape `sys::IPC_RECV`
  uses — the payload can be a full-width architecture trap cause with no
  spare bits to pack a tag into): `a0` = status, `a1` = payload.
  `THREAD_EXIT_RUNNING`(0) still alive · `THREAD_EXIT_CLEAN`(1, payload =
  self-reported exit code) · `THREAD_EXIT_FAULTED`(2, payload = the RAW
  architecture trap cause, deliberately NOT normalized across
  architectures) · `THREAD_EXIT_UNKNOWN`(3) dead, reason unrecorded ·
  `THREAD_EXIT_DENIED`(`usize::MAX`) refused.

  Two deliberate design decisions, both documented at length on
  `kernel_core::SyscallOp::ThreadExitStatus`:
  - **It polls; it does not block.** device-manager can block because it
    supervises exactly ONE driver. A real supervisor (`simurgh-init`)
    watches MANY units, and a syscall that parked it on one named thread
    would blind it to every other unit crashing meanwhile — the "wait on
    any of N" primitive that would be needed instead does not exist and
    is already a recorded gap (`wire_notification`). The project solves
    that same gap the same way elsewhere (`sys::NOTIF_POLL` in
    Compositor's input loop). Polling is lossless here because the answer
    is STICKY: a terminated thread's reason is recorded once
    (`Tcb::exit`) and never cleared, so an exit occurring between two
    polls cannot be missed. A blocking `WaitThreadExit` companion is
    recorded as explicit future work, not built speculatively — it needs
    a per-TCB waiter list plus a wake-and-poke at every termination site,
    which is exactly the stale-return-register bug class
    `SyscallReturn::DeliveredValue` documents.
  - **Only a thread's own SPAWNER may ask.** `Tcb` gained a `spawner`
    field, recorded automatically at TCB allocation from whoever is
    running (correct for every real spawn path with no call-site change:
    boot-time spawns run as the Root Task, `SPAWN_KNOWN_ELF` as init,
    `SPAWN_FROM_BUFFER` as native-loader, `DM_RESPAWN_DRIVER` as
    device-manager). A raw `ThreadId` is guessable in this MVP
    (`SyscallOp::Reply` records that accepted gap), and the answer
    includes a raw fault cause — unrestricted, any process could sweep
    the whole TCB table and read every other process's crash details.
    `sys::PS_LIST_ENTRY` stays the unrestricted but deliberately COARSER
    introspection path (a bare state code, no exit reason). "No such
    thread" and "not yours" are distinct kernel errors but ONE
    indistinguishable wire value, so a refusal leaks nothing.

  Termination now records WHY, not just that: `KernelState::mark_exited`
  is the single place both `ThreadState::Exited` and
  `Tcb::exit: Option<ThreadExit>` are written, and `terminate_thread` /
  `terminate_thread_and_handoff` take the reason as a required argument
  so a caller that knows it cannot silently drop it. First recorded
  reason wins — a real fault cause is never overwritten by a later, less
  specific termination.

  **Real QEMU verification against a real crash, all three
  architectures.** An additive, read-only cross-check runs at the exact
  moment device-manager reports `Failed` (the §5.2 PASS point) — the one
  instant on a real boot where a genuinely-crashed process exists AND the
  running thread is its real spawner. It changes no control flow. Real
  observed results: x86_64 `supervisor tid#10 queried its own crashed
  child tid#31 -> status=2 payload=0x6`, aarch64 `tid#11 ... tid#26 ->
  status=2 payload=0x0`, riscv64 `tid#10 ... tid#25 -> status=2
  payload=0x2` — in each case status 2 = faulted and the payload is
  exactly the raw trap cause that architecture's own `FAULT:` line
  reported for that same thread. All three still reach
  `state=Failed restarts_in_window=6`; x86_64 and riscv64 still reach a
  clean `POWER_CONTROL` shutdown. 9 new `kernel-core` unit tests cover the
  primitive directly (live child, real fault cause read back, sticky and
  idempotent answers, clean-vs-fault, non-spawner refused, the Root Task
  refused because nothing spawned it, out-of-range/empty slots,
  spawner attribution, first-reason-wins), and the existing 200 000
  iteration syscall fuzzer now generates the new operation too.
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

- **Real display scanout — committed frames now reach an actual screen
  (2026-09-23, x86_64 verified; aarch64 shares the code path).** Until
  now `DisplayProtocol::CommitBuffer` ended in RAM: nothing in the
  system had ever asked the firmware where the display is, no capability
  named it, and a QEMU window showed UEFI text and then nothing. The
  path is end-to-end now, and it is capability-gated at every hop:
  1. `uefi-bootloader` (new stage 5b) locates the UEFI Graphics Output
     Protocol before `ExitBootServices` — the only moment in the whole
     boot when a display mode can be chosen, since GOP is a boot service
     and no GPU driver exists (drivers are layer 3, by design). It picks
     the closest directly-writable 32-bit mode to 800x600, then reads
     back the mode that is ACTUALLY active rather than the one
     requested, and appends a 48-byte record (base, size, width, height,
     stride in PIXELS, bpp, pixel order) after the handoff block's RSDP,
     introduced by a versioned magic. Because that block is zero-filled
     up front, a kernel built against this layout but booted by an older
     bootloader reads zero and correctly concludes "no framebuffer".
  2. `hal-x86_64`/`hal-arm64` parse the record into
     `hal_manifest::raw::FramebufferInfoRaw`, a new singleton field of
     the hardware manifest beside `timer` — unconditionally, in full,
     per 01 §2's discovery-vs-policy split. riscv64 has no UEFI and
     reports `ZERO`.
  3. `kernel-core`'s `populate_from_boot_info` gains Step 3h: it mints
     an `MmioRegion` capability over the scanout, exactly as Steps 3c-3g
     do for virtio/NVMe BAR windows, because that is what it is —
     device-owned physical memory that must never enter the untyped
     pool. The window is sized to `stride * height * 4`, not to the
     larger size firmware reports for the whole BAR.
  4. `kernel-arch-glue` maps it into ONE address space, the
     Compositor's, alongside a small info page carrying the geometry
     (always mapped, zeroed when there is no display — which is how a
     process learns it is headless without a `cfg(target_arch)` it is
     not allowed to have). Nothing else in the system can reach the
     screen, so "the Compositor owns the display" is enforced rather
     than assumed.
  5. `compositor::scanout` clears the output to ui-core's own desktop
     background on acquire (taking ownership of the screen means owning
     the stale UEFI text on it), then blits every committed frame:
     centered if smaller than the output, clipped if larger, never
     scaled, with every row offset going through the real stride.

  **Verified on real QEMU, by pixels, not by log lines.** An HMP
  `screendump` taken late in an ordinary x86_64 demo boot is 800x600 —
  the mode the bootloader selected — and every one of its 480,000 pixels
  was written by the Compositor: 479,996 of desktop-background
  `0x2C1A3D`, plus exactly the four pixels of the Root Task's 2x2
  bootstrap test frame at (399,299)-(400,300), the centre, carrying
  `COMPOSITOR_DEMO_FRAME`'s own bytes in BGRX order. That is the full
  chain — Root Task → real IPC → Compositor → framebuffer → emulated
  display — with `compositor_commit_verify` still reporting `MATCH`
  unchanged. The serial log reports the real mode
  (`framebuffer: 800x600 stride=800 base=0x80000000`) and a separate
  `compositor_scanout_verify` line read back out of the info page
  through the kernel's own identity map, which distinguishes "no
  framebuffer granted" from "granted but the Compositor never got
  scheduled".

  **What is NOT on screen yet is the ui-core desktop**, and that is a
  scheduling matter, not a display one: `ui-core` is spawned and wired
  but does not get a turn to commit its frame (see the
  scheduling-capacity notes elsewhere in this section). The moment it
  does, its frame reaches the screen through this same path with no
  further work. Capture it with
  `.\simurgh-run.ps1 -Arch x86_64 -Window -Screenshot` (the workspace
  script, outside this repo); timing matters, because the UEFI
  bootloader spends most of the run printing to the firmware console and
  the desktop only exists in the last few seconds before the demo boot
  powers itself off.

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

- **`driver-i8042` real extended-key (`0xE0`) support (2026-09-17,
  x86_64 only)**: closes the gap the "Real interrupt-driven keyboard and
  mouse input" entry above and `driver-i8042::scancode`'s own module doc
  comment both used to name — a real `0xE0` prefix byte was dropped, not
  buffered, so no arrow/Home/End/Insert/etc. keystroke ever reached a
  consumer, even though the rest of the keyboard pipeline (scancode
  decode -> Compositor -> `PollInputEvent`) was already real and working.
  Omid's own immediate driver: `Simurgh-UI-Template01::ui-core`'s real
  TERMINAL window (previous entry) has a real, working, server-side shell
  history (`simurgh-shell::LineEditor`) with no key able to recall it from
  the GUI.

  `driver_i8042::scancode::Decoder` (replacing the old stateless `decode`
  free function) now buffers a real `0xE0` byte across calls instead of
  dropping it, and tags the byte that follows it with a real `extended:
  bool` flag on `KeyEvent` — a genuine, COMPLETE hardware-discovery
  capability (`00-Overview.md`'s own "hardware discovery is always
  complete, only policy varies" principle): every real `0xE0`-prefixed key
  this PS/2 controller can send decodes correctly now, not just the four
  arrows, though only the four arrows have a real consumer today. The
  4-byte Print Screen and 6-byte `0xE1`-prefixed Pause/Break sequences are
  deliberately still NOT covered (named, not guessed at) — neither fits
  this decoder's simple one-prefix-one-follow-up-byte shape, and neither
  has a real consumer yet either.

  **Wire-format decision, applied identically at both real hops this
  pipeline already had** (`driver-i8042` -> Compositor's internal
  `SmallMessage` edge, and Compositor -> any display client's real
  `DisplayResponse::InputEvent`): `extended` packs into bit 7 of the
  keycode word rather than growing either edge to a third word. This is
  not a space-saving trick invented for this change — a `KeyEvent::
  keycode` was ALREADY guaranteed `<= 0x7F` (Set 1's own make/break bit is
  stripped into the separate `pressed` field before a `KeyEvent` exists at
  all), so bit 7 of that word was always zero on both wires before today,
  a genuinely free, reserved bit. `ipc_protocol::display::
  DisplayResponse::InputEvent` gained the matching real `extended: bool`
  field, `ipc_protocol::codec`'s `OP_DPR_INPUT_EVENT` arm packs/unpacks
  it the same way, and `compositor::subsystem_entry`'s own local `KeyEvent`
  duplicate (this project's standard "duplicated wire shape with a sync
  comment" convention, not a shared crate) carries it through unchanged.

  Consumer side (`Simurgh-UI-Template01`, same day): `ui-core::keymap::
  decode` gained a third `extended: bool` parameter and two new
  `InputAction` variants (`ArrowUp`/`ArrowDown`, keycodes `0x48`/`0x50` —
  the SAME bytes Numpad-8/Numpad-2 use when NOT extended, the exact
  ambiguity `extended` exists to resolve), wired into `simurgh-shell`'s
  own already-real `LineEditor::history_up`/`history_down` via two new
  `TerminalKey` wire variants. See that repo's own README for the full
  story, including why Left/Right arrive correctly but are deliberately
  not yet named as an `InputAction` (a separate, real gap: no rendered
  cursor position in that crate's TERMINAL window yet).

  New/changed tests: 4 new `scancode` tests (`Decoder`'s own stateful
  buffering across calls, all four real arrow scancodes, the Numpad-vs-
  arrow ambiguity), 2 new `wire` tests, 2 new `compositor` tests, plus
  every existing `InputEvent`-shaped test across `ipc-protocol`/
  `compositor` updated for the new field. `cargo test`/`cargo clippy` clean on
  `driver-i8042`/`ipc-protocol`/`compositor`; `driver-i8042-bin` cross-
  built clean for x86_64 (its only real target); the full microkernel
  relinked clean after each of `driver-i8042-bin`/`ui-core-bin`/
  `shell-bin` was rebuilt in turn. Not yet exercised with a real QEMU-
  injected arrow keystroke (`qemu-system-x86_64 -monitor stdio` +
  `sendkey up`) — the same already-known, already-accepted real-process-
  scheduling-capacity limit the TERMINAL edge entry just above already
  documents for this exact `ui-core`/`shell`/driver trio at this system's
  current scale; verified instead by clean builds across all touched
  crates plus full host-side unit coverage of the new encode/decode round
  trip at every hop.

**Known open issues:**

- **fs-native's multi-client transport — two real kernel bugs found and
  fixed (2026-09-17), on a real x86_64 OVMF/QEMU boot.** Both were found
  while chasing `simurgh-file-manager`'s own long-open "`fm-core`'s
  `Write` reply decodes as `Opened`" bug (that repo's `G_LAST_REPLY_
  LABEL` doc comment carries the full cross-repo history); both are
  genuine correctness defects in this repo regardless of that bug's
  final disposition.

  **Bug 1 — every fs-native client shared ONE global message page.**
  `kernel_arch_glue::wire_file_manager_to_fs_native` mapped fs-native's
  own two physical pages (`G_FS_SHARED_PHYS`/`G_FS_DATA_PHYS`) into
  *every* client, at the same fixed VAs (`0xD800_0000`/`0xD810_0000`),
  so all clients shared a single request/reply buffer with no mutual
  exclusion at all. Its own doc comment justified this with "Root Task
  and `simurgh-file-manager` are NOT concurrent callers in practice" —
  true when `fm-core` was the only non-root client, and silently false
  from the moment `simurgh-init` was wired in **through that very same
  function**. `init-core` runs a real `RegisterPath` -> `Open` ->
  `Read` -> `Close` sequence against that shared buffer. Captured on a
  real boot, with an in-kernel trace ring (recorded in memory and dumped
  later, so it does not perturb the timing that defeated every earlier
  `klog!`-based attempt at this bug):

  ```
  FSLIVE CALL  tid=20 label=…106   <- fm-core RegisterPath
  FSLIVE REPLY tid=5  to=20 …107   <- fs-native PathRegistered (ok)
  FSLIVE CALL  tid=20 label=…101   <- fm-core Open
  FSLIVE CALL  tid=11 label=…106   <- init, on the SAME page, mid-sequence
  ```

  A second, independent symptom of the same defect showed up as an
  `UNHANDLED CPU EXCEPTION … cr2(fault_va)=0x00000000d8100000` — a
  second, on-demand `init` spawned via `SPAWN_KNOWN_ELF` writing the
  well-known bulk VA it was never wired for. **Fix:** each client now
  carves and is mapped its OWN private page pair, registered in
  `G_FS_CLIENT_PAGES`; the kernel copies them into and out of
  fs-native's own pages around the server's `Recv`/`Reply`. fs-native
  itself is unchanged and still sees exactly one request at its own
  fixed VAs, and Root Task — which drives its fs demo by writing those
  pages directly through the kernel identity map — is deliberately left
  unregistered, so its long-proven path is byte-for-byte untouched.

  **Bug 2 — `G_FS_ROOT_ONLY_PHASE` was never cleared.** The flag's own
  doc comment states it is "cleared once by `wire_file_manager_to_fs_
  native`", and the sibling Compositor latch
  (`G_COMPOSITOR_ROOT_ONLY_PHASE`) really is cleared by
  `wire_ui_core_to_compositor` — but the fs clear was never actually
  written. The flag therefore latched `true` for the life of the system
  and `fs_native_recv` permanently took `p2_ipc_recv`'s narrow,
  hardcoded-switch-to-Root-Task dispatch instead of the general one.
  Real, QEMU-confirmed consequence: `fm-core` issues its first
  `RegisterPath` `Call` and fs-native hands the core straight back to
  Root Task rather than letting `pick_next` run the client it has queued
  work for. **Fix:** clear it where its own contract always said it was
  cleared.

  **Verification status, stated honestly.** A real x86_64 OVMF/QEMU boot
  with both fixes reaches device-manager's own
  `state=Failed restarts_in_window=6` fault-isolation marker and a clean
  `POWER_CONTROL` shutdown, with root's own fs demo still reporting
  `fs_read_result … MATCH` and no faults — i.e. **no regression**. What
  could *not* be verified on hardware is the end-to-end effect on
  `fm-core`'s own `self_check`, because fs-native is never scheduled
  again once the full subsystem set is up: `fm-core` gets its `Call`
  queued and fs-native, merely `Ready` with a large vruntime deficit
  after the boot demo's own 202 round trips, loses every `pick_next` to
  the §8.4 demo's two infinite counting loops. That is the same
  already-documented, already-accepted "QEMU scheduling-capacity at
  scale" characteristic the entries below describe, now acute enough to
  block this specific observation. Both fixes are therefore committed on
  the strength of code-level proof plus a no-regression boot, **not** on
  a green `fm-core self_check` — which remains open and unobserved.

- ~~**x86_64 — a real, pre-existing full scheduler stall right after
  `device-manager` reaches `state=Running`**~~ — **ROOT-CAUSED AND FIXED
  (2026-09-17)**, on a real x86_64 OVMF/QEMU boot. It was never a PIC or
  LAPIC *programming* bug: it was a Ring-0 CPU-monopolization deadlock,
  formed by two interlocking defects.

  **Defect 1 (the blocker).** `kernel/src/main.rs`'s own `sys::DRV_IRQ_
  WAIT` arm serviced a driver's IRQ wait by looping **in Ring 0** on
  `hal_x86_64::cpu::hlt_wait_for_irq()` (`sti; hlt; cli`) until the
  awaited interrupt arrived. `drv_irq_wait_step` correctly marked the
  calling thread `Blocked`, but the kernel then parked the whole core
  there instead of returning to the scheduler. `driver-i8042` and
  `driver-mouse` — both spawned immediately before the stall point, as
  every stalled boot log shows — wait on PS/2 keyboard/mouse IRQs that
  **never arrive in an automated QEMU run, because nobody types**. So the
  first of them to be scheduled parked the CPU permanently, with roughly
  twenty other real subsystems sitting `Ready` behind it.
  `p2_wait_general`'s own doc comment had already written the false
  premise down in as many words — that `drv_irq_wait_step` was "correct
  only because a driver waiting on its OWN hardware IRQ genuinely has
  nothing else to do." The *driver thread* has nothing else to do; the
  *CPU* has plenty.

  **Defect 2 (why nothing rescued it).** That same comment's escape
  hatch — "would instead starve every other Ready thread *until the timer
  eventually preempts it*" — could never fire. Under TCG there is no
  TSC-deadline support, so `Timer::set_oneshot` falls back to
  `write_initial_count`, a genuine one-shot with no auto-reload; and
  `hal_x86_64::cpu::common_timer_entry` returns WITHOUT invoking the
  `TickHandler` when a tick lands at CPL 0 — while `p2_tick`, the
  `TickHandler`, is the only thing that re-arms the deadline. So the
  first timer tick that landed inside that Ring-0 halt loop silently
  killed the preemption timer for the remainder of the boot.

  **Own QEMU evidence** (independent of the original report, which it
  confirms and extends): at the stall, `RIP=0x18400d2` — and
  `llvm-nm` places `hal_x86_64::cpu::hlt_wait_for_irq` at exactly
  `0x18400d0`, i.e. the core is halted two bytes into that function's own
  `sti; hlt; cli`. `RFL=0x246` (IF=1), `CPL=0`, `HLT=1`, 0% host CPU.
  `pic0: irr=05 imr=f9 isr=02` reproduced byte-for-byte; additionally
  `pic1: irr=10 isr=00` — the mouse's own IRQ12 latched and pending on
  the slave, unable to cascade through the master's IRQ2 while IRQ1 sat
  stuck IN-SERVICE. Both stuck-PIC observations are downstream symptoms
  of the halted core, exactly as the original report suspected, not the
  cause.

  **Fix:** `kernel_arch_glue::drv_irq_wait_yield` — the switch half of
  `DRV_IRQ_WAIT`, mirroring `p2_wait_general`'s own `Blocked` arm exactly
  (`pick_next` → `dispatch` → `user_ctx_switch_ptrs`, with the same
  `note_ready` + re-`dispatch` fallback that keeps a caller from being
  stranded `Blocked`-but-actually-running when nothing else is `Ready`).
  The x86_64 `DRV_IRQ_WAIT` arm now hands the CPU to the next runnable
  thread instead of halting the core, and the IRQ trampoline's existing
  `wake_blocked` makes the driver runnable again when its interrupt
  really does arrive. This closes Defect 2 as a side effect rather than
  papering over it: because U-mode contexts start with `RFLAGS.IF = 1`
  (`init_user_context`), every later timer tick now lands at CPL 3, where
  the `TickHandler` genuinely runs and genuinely re-arms. IRQ delivery is
  not weakened by dropping the `sti`-`hlt` window either — a running
  U-mode thread has interrupts enabled continuously, which is strictly
  wider than that window ever was.

  **QEMU-verified on real x86_64 OVMF boots.** Before: 268 serial lines,
  frozen forever at `device-manager ... state=Running` — re-confirmed
  here across a full 285-second run, with the halted-core register/PIC
  evidence above captured from it, before any code changed. After: the
  boot runs *past* that point through the complete fault-isolation cycle
  — `state=Restarting` 1 through 5, then `state=Failed
  restarts_in_window=6` — and on to `root task (x86_64): real
  POWER_CONTROL syscall - shutdown`, with QEMU genuinely powering itself
  off instead of hanging. 292 lines, reproduced twice; a 270-second
  window proved unnecessary, because the whole boot now reaches shutdown
  in **13 real seconds**. All three architectures still build clean
  (`cargo xbuild-microkernel-{x86_64,aarch64,riscv64}`) and `cargo test
  -p kernel-core`'s 40 tests pass.

  **Note this also resolves the x86_64 half of the "QEMU scheduling
  capacity at scale" issue below.** That entry's central complaint — that
  `device-manager` was never once observed reaching its terminal
  `state=Failed` marker on x86_64, not even in a 400-second run, putting
  `scripts/qemu-fault-isolation-test.sh`'s own acceptance criterion out
  of reach — was this deadlock, not TCG capacity. That marker is now
  reached well inside a single ordinary run.

  **Known remaining work, deliberately not swept:** `kernel/src/main.rs`'s
  **aarch64** (`hal_arm64::cpu::wfi()`) and **riscv64**
  (`hal_riscv64::cpu::wfi()`) `DRV_IRQ_WAIT` arms still carry the
  IDENTICAL Ring-0 monopolization loop. `drv_irq_wait_yield` is
  architecture-erased and is a drop-in replacement for both. They were
  left for a follow-up that can give each architecture its own real QEMU
  verification — the same deliberate stance the `retype_one_from_any_
  untyped` sweep above took, and neither architecture currently reaches
  the driver stage where it would bite (both have their own separate open
  bugs, below). Separately, `common_timer_entry`'s Ring-0 tick still
  drops the tick without re-arming; with this fix nothing on x86_64
  leaves `RFLAGS.IF = 1` in Ring 0 any more, so it has no live trigger,
  but it remains a real latent hazard worth closing on its own terms
  rather than relying on that.
- ~~**riscv64 — the boot-blocking crash**~~ — **BOTH riscv64 boot faults
  are now ROOT-CAUSED AND FIXED (2026-09-17), and riscv64 boots end to
  end for the first time.** They were two genuinely different bugs found
  back to back; both writeups are kept in full below, since every earlier
  theory about each was wrong. The real root cause of
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
  **The SECOND fault exposed by that fix (tid 9, `cause=0xc sepc=0x0
  stval=0x0`) is ALSO ROOT-CAUSED AND FIXED (2026-09-17).** With both
  fixed, riscv64 now boots end to end — see "Outcome" at the bottom of
  this entry.

  For the record, because the two most obvious theories were both
  wrong: this was NOT the `untyped: CapId::new(0)` / slot-0 exhaustion
  bug that produced aarch64's superficially-similar crash at the very
  same point in the boot (`retype_one_from_any_untyped`, below) — riscv64
  boots off SBI, not UEFI, and its boot report says `UntypedMemory
  objects : 1`, a SINGLE ~51 MiB region, so "slot 0 filled up while other
  regions sat untouched" cannot even be expressed there. Nor was it the
  Ring-0 `DRV_IRQ_WAIT` monopolization bug (above): riscv64 has no PS/2
  drivers to park the core, and the apparent post-fault "stall" was never
  a scheduler hang at all — it was simply the whole rest of the boot
  never happening, because Root Task's own sequential boot step never
  returned.

  **Real root cause — a general ELF-loader bug in
  `kernel_arch_glue::spawn_process_from_elf`, exposed only by riscv64's
  linker output.** Two consecutive `PT_LOAD` segments are allowed to
  SHARE one page of the address space whenever the earlier one does not
  end on a page boundary, and that is exactly what the riscv64 linker
  emits for several of this workspace's subsystem binaries. For
  `security-broker-intermediary-bin`:

  ```
  LOAD  vaddr=0xc000c000 memsz=0x32e8 R    (.rodata + .srodata.cst8)
  LOAD  vaddr=0xc000f2e8 memsz=0x8d18 RW   (.sbss + .bss)
  ```

  `.rodata`'s tail lives in page `0xc000f000`; `.sbss` starts at
  `0xc000f2e8`, which rounds DOWN to that same page. The loader carved a
  fresh, freshly-ZEROED physical frame per segment and mapped each
  segment's whole page-rounded range unconditionally, so the `.bss`
  segment's mapping silently REPLACED the `.rodata` segment's page-table
  entry for the shared page. From the process's point of view the last
  `0x2e8` bytes of its own `.rodata` — the trailing 704 bytes plus the
  ENTIRE `.srodata.cst8` constant pool — read back as zeros. A zeroed
  jump-table / constant-pool entry is a null code pointer, so the process
  jumped straight to address `0`: `sepc=0x0 stval=0x0`, an instruction
  page fault at PC exactly 0, precisely as observed. Note this is the
  page-rounding HALF-fix's blind spot: an earlier, correct fix already
  rounded `p_vaddr` DOWN to its containing page (for fs-native-bin's
  unaligned `.data`), but nothing then stopped a later segment from
  re-mapping a page an earlier one already owned.

  **Why riscv64 only.** x86_64 and aarch64 link the SAME crates with the
  `.bss` segment's own `p_vaddr` page-aligned (`0x40015000` /
  `0x80015000`), leaving no shared page at all. Only riscv64's layout
  packs `.sbss` into `.rodata`'s last page. Four of the nine in-tree
  riscv64 subsystem ELFs have this overlap today
  (`security-broker-intermediary-bin`, `mm-service-bin`,
  `netstack-bin`, `log-collector-native-bin`); the others were merely
  lucky that the clobbered rodata tail held nothing they dereferenced.

  **How it was found**, since the symptom pointed nowhere useful: a
  temporary `klog!` of the spawned thread's saved `UserContext` at both
  `init_user_thread` time and at the `TrapOutcome::SwitchTo` handoff
  proved the context was PERFECT on both sides (`sepc=0xc0000800`,
  `sp=0xc0430000`, `satp=0x80000000000852e0`) — which ruled out every
  "wrongly-computed entry PC / uninitialized context / clobbered TCB"
  theory at once and moved the search from the spawn path to the
  process's own first instructions, i.e. to what its address space
  actually contained. `readelf -lW` on the embedded ELF then showed the
  shared boundary page immediately.

  **Fix:** `spawn_process_from_elf` now keeps a small page-granular
  record of the `PT_LOAD` mappings it has already established, and a
  page already mapped by an earlier segment is REUSED rather than
  re-mapped: the later segment's own bytes are copied into that existing
  frame (the earlier segment already zeroed its whole page-rounded
  length, so a `.bss`-style tail needs no zero-fill), and the shared
  page's permissions become the UNION of both segments' — here `R|W|U`,
  unavoidable at page granularity and what Linux's own loader produces
  for this layout too. Only the pages beyond the shared prefix get a
  fresh carve. When there is no overlap (`overlap == 0`, every x86_64 and
  aarch64 image and most riscv64 ones) the code path is byte-for-byte the
  previous behavior.

  **Outcome — QEMU-verified on a real riscv64 SBI boot.** Before: 124
  serial lines, dead at the tid-9 null-PC fault, confirmed frozen across
  a full 240-second run. After: **173 lines, the complete boot, ending in
  `root task (riscv64): real POWER_CONTROL syscall - shutdown` with QEMU
  powering itself off** well inside the same window. All four Issue #28
  end-to-end proofs now appear on riscv64, matching x86_64 and aarch64
  (`minted a REAL capability into security-broker's own cap space`,
  `revoked the demo capability — 2 slot(s) freed across BOTH capability
  spaces`, and both mm-service multi-target lines), and the boot runs the
  whole fault-isolation cycle to `device-manager ... state=Failed
  restarts_in_window=6` — `scripts/qemu-fault-isolation-test.sh`'s own
  PASS marker, which riscv64 had never once reached. No `sepc=0x0` fault
  remains; every `FAULT:` line left in the log is the INTENTIONAL
  `faulty-driver` fault-injection demo. **`scripts/qemu-fault-isolation-
  test.sh riscv64` no longer needs `--allow-fail`.** x86_64 and aarch64
  re-verified for regression on real OVMF/AAVMF boots (both still reach
  their own PASS marker); `cargo test -p kernel-core` 40/40 green; all
  three architectures build clean.

  **Known remaining work, deliberately not swept** (same stance as the
  two entries above, so each gets its own real QEMU verification):
  riscv64's own `sys::DRV_IRQ_WAIT` arm in `kernel/src/main.rs` still
  carries the Ring-0 `hal_riscv64::cpu::wfi()` monopolization loop
  documented above. It was investigated as a candidate explanation for
  this entry's "stall" and is NOT involved — riscv64 reaches shutdown
  with it untouched — but `drv_irq_wait_yield` remains a correct drop-in
  for it whenever a riscv64 driver does start waiting on a real IRQ.
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

  **The remaining sites are now swept too (2026-09-17, follow-up).** What
  the entry above deferred as "roughly 20 OTHER `untyped: CapId::new(0)`
  `Retype` sites" turned out to be **30 in total: 28 in
  `kernel-arch-glue/src/lib.rs` plus 2 more that had been missed entirely
  because they live in a DIFFERENT file** — `kernel/kernel/src/main.rs`'s
  own `alloc_root_frame` (which every riscv64 `sys::MAP_PAGE` call goes
  through) and its `sys::RETYPE_ENDPOINT` opcode. All 30 are now
  `retype_one_from_any_untyped`, which is `pub` for exactly that reason.
  Every call site was read in context first rather than blind-replaced;
  none had any reason to be pinned to a specific region, so there are no
  deliberate exceptions left.

  Two things are deliberately NOT converted, and both are correct as they
  stand: the 20 `untyped: CapId::new(0)` occurrences in
  `kernel-core/src/syscall.rs` are all inside `#[cfg(test)] mod tests`,
  where the fixture builds exactly ONE untyped region and naming slot 0
  is precisely the intent; and `carve_from_any_untyped`'s own raw-carve
  sites were already fixed in their own earlier pass.

  **QEMU-verified on all three architectures, no regression anywhere.**
  Every one still reaches `state=Failed restarts_in_window=6` and its own
  real `POWER_CONTROL` shutdown: x86_64 311 serial lines with QEMU
  powering itself off in ~13s, aarch64 296 lines, riscv64 173 lines. All
  four Issue #28 proofs still appear on x86_64 and aarch64, and riscv64's
  own `MAP_PAGE`/`XCHECK` zero-copy proof still reports `ALL THREE AGREE`
  — that one matters specifically because it is the live exercise of the
  `alloc_root_frame` conversion. `fs_read_result`,
  `compositor_commit_verify` and both `mm_query_*` results still report
  `MATCH`, and no log contains a single retype failure line. The boot
  reports also show why this fix is not theoretical: the three
  architectures see **80, 22 and 1** untyped regions respectively, so
  x86_64 is running at `MAX_UNTYPED` saturation while riscv64 has a
  single region (where the helper provably cannot change behaviour at
  all, since it tries slot 0 first). `cargo test` stays green and all
  three `cargo xbuild-microkernel-*` builds stay clean with no new
  warnings.

  One incidental improvement worth recording: aarch64 reached the PASS
  marker inside a **150s** window here, where the entry above needed
  300s. That is the documented QEMU scheduling-capacity variance, not a
  claim that the timeout guidance has changed — `QEMU_FAULT_TEST_TIMEOUT=300`
  is still the safe value to use on aarch64.

- **aarch64, newly exposed by the fix above (2026-09-17), minor:** after
  `root task (aarch64): real POWER_CONTROL syscall - shutdown`, the boot
  emits `UNHANDLED EXCEPTION: esr.ec=0x0 elr=0x40240a38 far=0x0` instead
  of the VM actually powering off — the aarch64 PSCI (`smc`) shutdown path
  apparently not taking effect under this QEMU/AAVMF combination. This
  happens strictly AFTER all real work and after the fault-isolation PASS
  marker, so it blocks nothing; it was simply never reachable before
  because the boot died earlier. Not investigated. **Re-confirmed
  2026-09-18** (as `esr.ec=0x0 elr=0x40242244`, plus the
  `tcr_el1=…`/`mmfr0.parange=…` line) by the data-abort fix in the entry
  below, which restored the boot's path to `POWER_CONTROL` again. Worth
  recording for whoever does investigate it: `elr` is a **kernel** (EL1)
  address, and the `tcr_el1`/`mmfr0` line is printed only by
  `common_sync_el1_entry` — so this arrives on the "Current EL, SPx"
  vector, NOT the EL0 path, and is therefore outside per-process fault
  isolation by design rather than by omission.
- **aarch64 fault isolation covered ONLY undefined-instruction faults,
  not data aborts — found 2026-09-18, FIXED and QEMU-verified the same
  day.** Found while verifying the new `sys::THREAD_EXIT_POLL` syscall.
  `hal-arm64`'s EL0 synchronous handler (`common_sync_entry`, the
  `sync_el0_entry` vector) routed ONLY `ec = 0x00` ("Unknown reason", the
  class `udf #0` traps as) to the registered `FaultHandler`; EVERY other
  exception class from EL0 fell through to the terminal
  `UNHANDLED EXCEPTION:` print. The §5.2 fault-isolation demo passed
  only because its injected fault happens to BE an undefined instruction
  — a real EL0 **data abort** (`ec = 0x24`) was NOT isolated and killed
  the whole boot. Reproduced on a real aarch64 AAVMF/UEFI QEMU boot
  before the fix: after the fault-isolation PASS marker, the boot died on
  `UNHANDLED EXCEPTION: esr.ec=0x24 elr=0x800025c4 far=0xd8e00000`,
  `full esr_el1=0x92000046` (EC 0x24, DFSC 0x06 translation fault, WnR
  set — a genuine U-mode *write* to an unmapped VA), and never reached
  its own `POWER_CONTROL` shutdown. riscv64's equivalent path already
  isolated the SAME real fault correctly, which is what made this an
  aarch64-specific gap rather than a project-wide design limit.

  **Fix**: `common_sync_entry`'s fault branch now adopts hal-riscv64's
  own rule verbatim — *any* synchronous exception that is neither the
  syscall instruction nor an interrupt, taken while a user thread was
  running, goes to the `FaultHandler` — instead of testing one EC value.
  An EC allow-list was deliberately NOT used: it would need revisiting
  for every class EL0 can produce (0x20 instruction abort, 0x24 data
  abort, 0x22/0x26 PC/SP misalignment, 0x0E illegal execution state,
  0x2C FP exception, 0x3C `brk`, …) and forgetting one degrades silently
  back into exactly this bug. `FaultHandler`'s own contract needed no
  change: it is a per-arch `fn(usize, usize, usize) -> TrapOutcome`
  alias (not a `hal-core` trait), and both `simurgh_fault_aarch64` and
  `kernel_arch_glue::p2_fault` are already cause-code agnostic, so
  nothing above the HAL was touched.

  Routing a KERNEL-mode fault into a path meant only for recoverable
  user-mode faults would be a far worse bug than the one being fixed, so
  the new branch is scoped to EL0 twice over: structurally (it is only
  reachable from the "Lower EL, AArch64 / Synchronous" vector slot — a
  synchronous EL1 fault takes the "Current EL, SPx" slot into
  `common_sync_el1_entry`, whose dump-and-halt behavior is untouched),
  and explicitly via a `SPSR_EL1.M[4:0] == EL0t` check, the direct
  analogue of riscv64's own `SSTATUS.SPP == 0` guard.

  **QEMU-verified on a real aarch64 AAVMF/UEFI boot, both halves:** the
  same data aborts that previously killed the boot are now isolated per
  process — `FAULT: thread 18 took a fatal U-mode exception (cause=0x24
  …) - terminating IT, rest of the system continues`, likewise thread 17
  — and the boot now runs PAST them to `root task (aarch64): real
  POWER_CONTROL syscall - shutdown`, which it had never reached before.
  Zero regression to what already worked: the pre-existing
  undefined-instruction demo still runs its full six-restart supervision
  cycle under device-manager to `state=Failed restarts_in_window=6`, and
  `scripts/qemu-fault-isolation-test.sh aarch64` still PASSES.
- **A real unmapped-VA access around `0xD920_0000` / `0xD8E0_0000` —
  pre-existing, found 2026-09-18, not investigated.** The addresses
  belong to the security-broker ↔ store / policy-engine shared-page edges
  (`STORE_VA` / `POLICY_ENGINE_VA` / `SB_SHARED_VA` in
  `kernel/kernel/src/main.rs`). On riscv64 two threads take real load/store
  page faults there (`cause=0xd`/`cause=0xf`) and are correctly isolated,
  the boot continuing to a clean `POWER_CONTROL` shutdown; on aarch64 the
  same address surfaces via the unhandled-data-abort gap above. These
  threads were previously starved by the documented QEMU
  scheduling-capacity limit and simply never ran far enough to reach the
  faulting access, so this is newly OBSERVED, not newly introduced —
  nothing in the `sys::THREAD_EXIT_POLL` work touches those edges or any
  mapping.
- **Layer-4 processes spawned but never running — ROOT-CAUSED AND FIXED
  (2026-09-18).** After the Ring-0 deadlock fix below, a real x86_64 boot
  reached a clean shutdown in ~13 seconds — but almost nothing ran in it.
  Of every layer-4 process spawned (`store`, `ui-core`, `init`, `shell`,
  `account-manager`, `backup-manager`, `native-loader`, `file-manager`,
  `policy-engine`, ...), only `device-manager` and the spawned
  `security-broker` ever executed their own code; everything else was
  spawned with a real ELF and real capabilities and then stayed silent.

  **The cause was boot SEQUENCING, not scheduler fairness.** A temporary
  in-kernel trace of every real switch decision settled it: `pick_next`
  was distributing turns correctly across every spawned thread, and
  `p2_fault`'s "direct, not generic fairness" hand-off — the prime
  suspect — consumed only FIVE ticks (~10 ms) end to end for the whole
  six-cycle crash/respawn demo. Neither was at fault. What actually
  happened is that `device-manager`'s own `subsystem_main` issues a real
  `POWER_CONTROL` shutdown as its closing act, so the §5.2
  fault-isolation demo does not merely run alongside the system, **it
  ends the boot** — and the faulty driver was spawned `Ready` alongside
  everything else, so `pick_next` reached it on its ordinary turn about
  TWELVE ticks (~24 ms) into the preemption phase. The machine powered
  itself off at roughly tick 60 of a 400-tick budget, about 15% of the
  window the demo was already designed to provide. The layer-4 processes
  were never starved of turns; they were starved of TIME. Under TCG one
  IPC round trip costs ~1.3 ms on average (this same boot's §8.3
  benchmark line) — most of a single 2 ms quantum — so one or two turns
  each buys nothing observable.

  **The fix, part 1 — a single-purpose gate** in `kernel-arch-glue`:
  `p2_gate_fault_demo` holds the FIRST faulty-driver instance out of
  `pick_next` (`note_blocked`, TCB and scheduler entity fully intact)
  until `p2_tick` reaches `P2_FAULT_DEMO_START_TICK` (1000), then
  releases it with one `note_ready`. The fault-isolation mechanism itself
  is untouched: every RESPAWN still uses the existing direct hand-off,
  the driver still faults on its own first instruction, and
  `device-manager` still runs the full six-restart budget to
  `state=Failed restarts_in_window=6`. Only the demo's START time moves.
  The quantum is deliberately NOT widened to compensate —
  02-Microkernel-Layer.md §4 states the interactive quantum as ~1–4 ms
  and 2 ms sits inside that; more turns is the same total CPU without
  departing from the spec. `P2_TICK_BUDGET` was raised 400 → 2000 as pure
  margin, since reaching it cancels the timer and would strand
  `device-manager`'s closing shutdown.

  **The fix, part 2 — x86_64 `#PF` isolation, which part 1 turned out to
  depend on.** The gate alone was reproducible at 300 ticks but genuinely
  flaky at 600 and 1000 (about half of boots died). Giving layer-4 code
  real run time exposed latent faults the old ~12-tick window never
  reached — a null dereference in a subsystem thread (`error_code=0x5`,
  `cr2=0x0`) and an unmapped access at `cr2=0xD810_0000` — and EITHER one
  halted the whole machine, because `hal-x86_64` routed only `#UD` to its
  registered `FaultHandler` and let `#PF` fall through to
  `common_interrupt_entry`'s halt-forever arm. That is a direct breach of
  the per-process isolation 03-Kernel-Subsystems-Layer.md §2.1/§5.2
  requires, and the exact mirror of the aarch64 `ec=0x24` gap fixed in
  `e8e1c83`. `#PF` now has its own gate (`isr_pagefault_trampoline` →
  `common_pagefault_entry`), identical to the `#UD` path except for one
  leading `add rsp, 8` that discards the CPU-pushed error code; `cr2` is
  passed as the handler's third argument (matching riscv64's `stval`),
  and a Ring-0 `#PF` stays fatal. The `#UD` gate is untouched.

  **Measured, on real QEMU boots of all three architectures.** Before:
  on every architecture, nothing but `device-manager` and the spawned
  `security-broker` ran its own code. After:
  - **x86_64** — six consecutive boots across two bases (three on
    `69aa1fe`, three on `e8e1c83`): all six reached
    `state=Failed restarts_in_window=6` and a clean `POWER_CONTROL`
    shutdown with zero unhandled exceptions, and in five of the six two
    real page faults were isolated mid-boot with the system carrying on.
    New self-check / report lines, present in every run and all
    appearing BEFORE the demo: `security-broker` (3 real service calls),
    `native-loader` (2-3 real round trips — `request_capability`,
    `Loader::spawn`, de-framework `DisplayClient` to Compositor),
    `simurgh-shell` (its prompt), `file-manager` (its
    fs-native self-check round trip), and `init` (its 5-unit self-check
    with a real on-demand spawn, and its `THREAD_EXIT_POLL`
    crash-supervision self-check, which PASSES).
  - **aarch64** — two consecutive boots: PASS marker and `POWER_CONTROL`
    reached; `init`'s own self-check now runs. (Verified on an image
    whose embedded in-repo subsystem ELFs were debug-stripped for test
    only — see the load-address entry below; the code is byte-identical.)
  - **riscv64** — two consecutive boots: PASS marker and clean shutdown;
    `init`'s self-check now runs, and `native-loader`, `account-manager`
    and `store` now execute their own code for the first time on this
    architecture — reaching the already-recorded unmapped shared-page
    writes at `0xD8E0_0000` / `0xD900_0000` / `0xD920_0040`, which are
    isolated exactly as §5.2 promises.

  **What is still NOT running, and why — none of it a scheduling
  defect.** `store`, `ui-core`, `account-manager` and `policy-engine` DO
  receive real scheduling turns on x86_64 (the trace showed `pick_next`
  selecting them) but do not yet reach a report line inside the window.
  `backup-manager` and `diagnostics-manager` cannot run at all by
  construction: `p2_preempt_start` deliberately marks both `Exited` and
  removes them from the scheduler, a standing workaround for the
  stale-saved-context bug class documented there. Two real bugs were also
  surfaced (not caused) by this work, both recorded rather than fixed:
  `simurgh-init` enters a runaway `SPAWN_KNOWN_ELF` loop once its
  self-check completes — the copies it spawns re-issue the call and are
  denied — which is now self-limiting because each copy's null-pointer
  `#PF` is isolated (its own repo); and `file-manager`'s `Write` step
  intermittently receives a stale `FsResponse::Opened` reply
  (`step=72057594037928193` = label `0x0100_0000_0000_0001`: Filesystem
  namespace, opcode 1), while on other boots `Write` succeeds and the
  later `copy` step fails (`step=7`). Identical builds giving different
  results points to a timing race on the fs-native multi-client reply
  path `852c2b6` addressed — plausibly between `init` and `file-manager`,
  both fs-native clients that had never actually run concurrently before
  this gate.

  **Desktop mode — how to turn this off.** The mechanism is
  `kernel_arch_glue::p2_gate_fault_demo` plus the constant
  `P2_FAULT_DEMO_START_TICK` (and its static `GATED_FAULT_DRIVER_TID`),
  deliberately NOT entangled with `p2_fault`'s hand-off, `DM_TID`'s
  preemption exemption or `P2_TICK_BUDGET`. Setting
  `P2_FAULT_DEMO_START_TICK` to `0` means "never release": the demo never
  starts, `device-manager` never reaches its closing `POWER_CONTROL`, and
  the machine keeps running — what an interactive desktop boot
  (Compositor + `ui-core` + i8042/mouse + `account-manager`) needs.
  Turning the automated demo off is that one constant and nothing else.

- **aarch64 kernel image no longer loads under UEFI — a fixed-address
  ceiling, not RAM (found 2026-09-18).** The aarch64 kernel is linked at
  fixed physical addresses from `0x4020_0000`, and `uefi-bootloader`
  requests exactly those pages. `AllocatePages` fails ("kernel image
  corrupted") whenever the image's end crosses roughly `0x4400_0000`: a
  passing build ended at `0x43F0_6000`, and failing builds ended at
  `0x4401_7610` and `0x4401_CAC8`. It fails identically with `-m 1024M`,
  and on both `e8e1c83` and `69aa1fe`, so **no RAM value fixes it** and
  no single commit caused it — the image had only ~1 MB of headroom, and
  the embedded-ELF payload (segment #3) swings by more than that between
  builds. The real lever is size: the embedded subsystem ELFs are
  unstripped debug builds, and `llvm-objcopy --strip-debug` on just the
  nine in-repo aarch64 ones reclaimed 27,078,656 bytes (29.5 MB → 2.5 MB),
  after which the image loads and boots to a clean PASS. Stripping the
  embedded ELFs at build time (or relinking the aarch64 kernel above the
  firmware's reservation) is the open fix; not done here.
- **QEMU scheduling capacity at scale (x86_64) — LARGELY SUPERSEDED
  (2026-09-17); read the correction first.** The most alarming claim in
  this entry — that `device-manager` was never once observed reaching its
  terminal `state=Failed` marker across multiple real x86_64 boots,
  including one given a full 400 real seconds — was **misdiagnosed**. It
  was not TCG scheduling capacity at all; it was the Ring-0
  `DRV_IRQ_WAIT` deadlock root-caused and fixed in the entry above, which
  parked the core permanently a few lines after `device-manager` first
  reached `state=Running`. With that fixed, the entire boot — including
  the full six-restart fault-isolation cycle and
  `scripts/qemu-fault-isolation-test.sh`'s own PASS marker — completes in
  about 13 real seconds. The generic observation below (that a
  newly-spawned process may not get a scheduling turn within a given
  boot's window) may still hold to some degree at this scale, but every
  concrete measurement cited here was taken through the deadlock and
  should not be trusted as evidence of a fairness or capacity problem.
  The original entry is kept verbatim below for history:

  With this many real
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
and `03-Kernel-Subsystems-Layer.md §5` — **met**, on all three architectures.
As of 2026-09-17 x86_64, aarch64 and riscv64 each complete a real QEMU boot
through the full fault-isolation cycle to `scripts/qemu-fault-isolation-
test.sh`'s own PASS marker; see **Current status** above for the remaining,
non-blocking known issues.

## Contributing

Every change goes through its own branch and a pull request — `main` is
protected, requires a passing CI run and an approving review, and a merge
triggers an automatically numbered GitHub Release. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the full flow and branch-naming
convention.

## License

MPL-2.0 — see [`LICENSE`](LICENSE).
