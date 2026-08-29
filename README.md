# Simurgh-OS

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
├── subsystems/          root-task, device-manager, drivers/, vfs-service/, netstack, mm-service (03 §4)
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
scripts/qemu-smoke.sh riscv64        # boot + assert the HAL handoff markers

# the real microkernel image (Phase 2):
cargo xbuild-microkernel-{x86_64,aarch64,riscv64}
cargo xrun-microkernel-riscv64       # build + boot under QEMU
```

## Current status (honest)

**Working and verified:**

- Whole workspace compiles for all three architectures. ~262 host unit tests pass.
- **HAL (layer 1):** boots on QEMU for all three architectures via `kernel-stub`;
  produces a valid Hardware Manifest (CPU cores, ≥1 memory region, live timer);
  hands control to a microkernel via a direct call. `HalInterface` (the
  architecture-erased boundary) provides `context_switch`, `init_context`,
  `enter_user`, `now_ns`, cpu id / feature bits. `scripts/qemu-smoke.sh riscv64`
  passes.
- **Microkernel (layer 2)** — verified end to end **on riscv64 only**:
  - HAL → kernel handoff and creation of the first `UntypedMemory` objects
    (carved around the kernel image / boot-reserved ranges of usable RAM) —
    `02-Microkernel-Layer.md §8.1`.
  - The Root Task runs, retypes an `Endpoint` and a second thread, and completes
    a synchronous IPC round-trip — `§8.2`.
  - Capability revocation: revoking a CDT node frees its whole derived subtree
    and leaves the parent intact — `§8.5`.
  - The user/kernel privilege boundary: the Root Task is dropped to U-mode via
    `sret` and reaches the kernel only through `ecall`, routed through the HAL
    trap vector to a registered S-mode syscall handler — `02 §0`.
  - MMU-enforced isolation: the Root Task's code and stack live in their own
    `.user_text` / `.user_stack` pages, mapped `U=1` while the kernel stays
    `U=0`, and Sv39 paging stays active while it runs — `02 §0`, `01 §3.2`.
  - The `Map` syscall installs a genuine Sv39 leaf in the Root Task's live page
    table (not just the software model); mapping a second virtual address onto
    the same frame and reading a value written through the first is served by
    the MMU — the intra-address-space half of `§5.2` / `§8.4`.
  - Zero-copy across isolation boundaries: the kernel builds two independent
    Sv39 page tables that map one physical frame at different virtual
    addresses, and a write through one table is visible through the other after
    a `satp` switch — the kernel-mechanism half of `§8.4`.
- **Layer 3:** `ipc-protocol` (message contract + FsRequest codec) and every
  `subsystems/*` crate build and unit-test their pure service logic (mount-table
  routing, an in-memory filesystem, ICMP echo build/parse, the driver-restart
  policy, the OOM victim policy, the root-task boot-memory plan).

**Not yet implemented:**

- A capability-gated `Map` (`§6` wants a `Frame` + `PageTable` capability; the
  MVP path picks the frame in-kernel and acts on the Root Task's space
  directly), and `kernel-mm::AddressSpace::map` itself driving `map_range` so
  the software model and the hardware table cannot drift.
- `02 §8.3` (`ipc_call` fast-path benchmark); `§8.4` as a *cross-process*
  proof — two U-mode threads running concurrently in separate address spaces
  that share a frame (the kernel-side mechanism is done; this needs a HAL
  primitive that can resume a user context); `§8.6` (syscall fuzzing).
- Preemptive scheduling (no timer-tick / IRQ routing into the kernel yet).
- All of `03-Kernel-Subsystems-Layer.md §5`: no subsystem runs as a real process
  yet (they are libraries pending the process-load path).
- x86_64 / aarch64 boot of the *real* microkernel — those still boot
  `kernel-stub`; the UEFI bootloader currently embeds `kernel-stub`, not `kernel`.
- CI.

## Repository scope

In scope: `hal/`, `kernel/`, `ipc-protocol/`, `subsystems/`, `uefi-bootloader/`.
Crates here depend only on other crates in this repository.

Out of scope (separate repositories): system services, POSIX compatibility, the
package manager, the security broker, profile policy, the native SDK, the Linux
compatibility runtime, and applications.

## Documentation

The architecture specification (Persian) lives in `.claude/` in this working
tree: `00-Overview.md`, `01-HAL-Layer.md`, `02-Microkernel-Layer.md`,
`03-Kernel-Subsystems-Layer.md`, plus `CONTRIBUTING.md` and `REPO-Simurgh-OS.md`.

## MVP Definition of Done

Combined acceptance criteria of `01-HAL-Layer.md §8`, `02-Microkernel-Layer.md §8`,
and `03-Kernel-Subsystems-Layer.md §5`. Progress against them is summarised under
**Current status** above.

## License

MPL-2.0 — see [`LICENSE`](LICENSE).
