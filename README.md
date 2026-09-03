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
├── subsystems/          root-task, device-manager, drivers/, vfs-service/, netstack, compositor, mm-service (03 §4)
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

# each subsystem, per architecture (must be built before the real kernel,
# which embeds their ELFs via include_bytes!):
cargo xbuild-subsystem-<device-manager|fs-native|driver-virtio-blk|driver-virtio-net|netstack|compositor|mm-service>-<arch>

# the real microkernel image (Phase 2/3):
cargo xbuild-microkernel-{x86_64,aarch64,riscv64}
cargo xrun-microkernel-riscv64       # build + boot under QEMU
scripts/qemu-fault-isolation-test.sh <x86_64|aarch64|riscv64>   # real fault-injection + supervision, asserted end to end
```

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
  `driver-virtio-blk`, `driver-virtio-net`, `netstack`, `compositor`, and
  `mm-service` are each a real, separately-built ELF process (not a linked-in
  library) spawned via the generic `kernel_arch_glue::spawn_process`/
  `spawn_process_from_elf` path, exercised by the real `kernel` binary on all
  three architectures.
- **Real per-process fault isolation** (`03 §5.2`): a deliberately faulting
  driver process is terminated by the kernel without affecting any other
  process; `device-manager` supervises it end to end — starts it, detects the
  crash via real IPC, restarts it, and reaches a terminal `Failed` state after
  its restart-window policy trips. This exact cycle is asserted automatically
  in CI via `scripts/qemu-fault-isolation-test.sh` on every push.
- A VFS read-throughput benchmark and an `02 §8.3` IPC round-trip benchmark
  both run as part of the real boot sequence and report real numbers (not
  hardcoded).

**Known open issue:**

- **riscv64 only:** the `compositor` process faults (an instruction page
  fault, not an illegal instruction) shortly after its first resume. Deep
  investigation across several sessions narrowed the search space
  considerably (ruled out corrupted resume data, stack/heap sizing, and
  confirmed it reproduces identically on two independent QEMU builds) but the
  root cause is not yet found. x86_64 and aarch64 are unaffected;
  `scripts/qemu-fault-isolation-test.sh riscv64` runs with a documented
  `--allow-fail` in CI so this stays visible without blocking the pipeline.

## Repository scope

In scope: `hal/`, `kernel/`, `ipc-protocol/`, `subsystems/`, `uefi-bootloader/`.
Crates here depend only on other crates in this repository.

Out of scope (separate repositories): system services, POSIX compatibility, the
package manager, the security broker, profile policy, the native SDK, the Linux
compatibility runtime, and applications.

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
