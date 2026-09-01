//! ============================================================================
//! subsystem_entry.rs — riscv64 / x86_64 / aarch64
//!
//! Note on this file's ONE architecture-conditional piece: the crate-
//! level invariant is "no `#[cfg(target_arch)]` in `kernel/` or
//! `subsystems/`" (everything architecture-specific belongs in the
//! `hal-<arch>` crates or the final binary), and `raw_syscall` below
//! is a pre-existing, narrow exception to it — this function's ONLY
//! job is to issue the raw syscall INSTRUCTION itself (`ecall`/
//! `int 0x80`/`svc #0`), which is unavoidably an ISA detail no
//! `hal-core` abstraction covers (it runs entirely in U-mode, on the
//! OTHER side of the kernel/user boundary those crates model). Kept
//! to this one function, gated per architecture, with every other
//! line in this file (the `Supervised` state-machine driving logic)
//! staying genuinely architecture-generic.
//!
//! Purpose: Device Manager's real process entry point. Runs `Supervised`
//! against REAL crashes of a REAL driver process — blocking on the
//! kernel's own per-thread fault-isolation mechanism instead of scripting
//! a synthetic crash loop — reporting every transition via `ecall`: the
//! actual 03-Kernel-Subsystems-Layer.md §5.2 acceptance test ("inject a
//! panic in a driver, prove Device Manager restarts it, rest of the
//! system unaffected"), automated end-to-end.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (restart
//! policy), §5.2 (the acceptance test itself). IMPLEMENTATION-PLAN.md's
//! "real IPC-driven supervision" follow-up to the fault-isolation
//! milestone (`hal_riscv64::cpu::FaultHandler` / `KernelState::
//! terminate_thread` / `kernel_arch_glue::p2_fault`).
//!
//! Position in the system: `kernel-arch-glue::spawn_process` maps this
//! function's containing page range (`.user_text`, shared with every
//! other demo process in this MVP — see that function's doc comment on
//! why there is no separate subsystem binary/loader yet) at `U=1 R+X`
//! into a FRESH address space and gives it a fresh `ThreadId`, admitted
//! into the SAME preemptive scheduler loop the other demo processes run
//! in (`kernel/src/main.rs`'s `p2_preempt_start`). `root-task::plan_boot`
//! decides that Device Manager is the first service to launch
//! (`Service::BOOT_ORDER[0]`); `kernel/src/main.rs`'s `spawn_faulty_driver`
//! launches the actual crashing driver process this file waits on, via
//! `kernel_arch_glue::{p2_dm_wait_crash, p2_poll_crash}` (`DM_WAIT_CRASH`/
//! `DM_POLL_CRASH` ecalls) and requests its restart via `DM_RESPAWN_DRIVER`.
//!
//! Safety/invariants: every `Supervised` method this file calls is
//! `#[inline(always)]` (see their doc comments) — this function must
//! never contain a `call` instruction into anything outside `.user_text`,
//! or U-mode would fault fetching from a `U=0` page the instant it tried.
//! No heap: `Supervised` is a plain `Copy` struct on this function's own
//! (real, mapped) stack.
//! ============================================================================

use crate::{DriverState, Supervised};

/// The `ecall` opcode this file uses to report one `Supervised` state
/// transition to the kernel. Not part of `kernel_core::SyscallOp` (the
/// real, capability-gated syscall surface) — this is the same kind of
/// raw, demo-scoped ABI number `kernel/src/main.rs`'s `sys` module
/// already uses for `P2_YIELD`/`P2_REPORT_A`/etc.; that module's
/// `DM_REPORT` constant must stay numerically equal to this one.
///
/// `a0` = the new `DriverState`'s discriminant (`Starting`=0,
/// `Running`=1, `Restarting`=2, `Failed`=3); `a1` = `restarts_in_window`
/// at that point.
const DM_REPORT: usize = 30;

/// Blocks until the driver process `kernel_arch_glue::p2_watch_driver`
/// currently names takes a fatal exception (or returns immediately if
/// that already happened). Must stay numerically equal to
/// `kernel/src/main.rs`'s `sys::DM_WAIT_CRASH`.
const DM_WAIT_CRASH: usize = 31;
/// Consumes and returns (via `a0`) the pending crash's raw `scause` value.
/// Must stay numerically equal to `sys::DM_POLL_CRASH`.
const DM_POLL_CRASH: usize = 32;
/// Asks the kernel to spawn a fresh instance of the faulty-driver demo
/// process (the automatic-restart half of §5.2). Must stay numerically
/// equal to `sys::DM_RESPAWN_DRIVER`.
const DM_RESPAWN_DRIVER: usize = 33;

/// # Safety
/// `ecall` from U-mode traps to the kernel's S-mode handler, which
/// preserves every register except `a0`. No memory access happens here —
/// only register-in/register-out; this crate's own `[[bin]]` (`device-
/// manager-bin`) is a fully separate, self-contained ELF image (every
/// byte of it U=1 — see that crate's own doc comment), so there is no
/// "calling into non-executable kernel .text" precondition here the way
/// `kernel/src/main.rs`'s own `.user_text` demo code has to worry about.
///
/// Returns whatever the kernel wrote back into `a0` (`0` for opcodes that
/// carry no return value, e.g. `DM_REPORT`).
///
/// `#[inline(never)]`: a real, QEMU-found bug — see `kernel/src/
/// main.rs`'s riscv64 `raw_syscall`'s own extensive doc comment. Under
/// this project's pinned nightly, LLVM produced incorrect codegen for
/// multiple sequential calls to an `#[inline(always)]` function
/// wrapping an asm block that can switch threads; a real (non-inlined)
/// function call sidesteps it by using the standard calling convention,
/// which already treats `a0`-`a7` as fully clobbered.
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

/// # Safety
/// `int 0x80` from Ring 3 traps to `hal_x86_64::cpu`'s dedicated DPL-3
/// gate, which preserves every register except `rax` — this project's
/// own convention (see `hal_x86_64::cpu::SyscallHandler`'s doc comment):
/// `rax` = opcode (`a7`), `rdi` = `a0`, `rsi` = `a1`. Same register-only
/// contract as the riscv64 variant above.
///
/// `#[inline(never)]` — see the riscv64 variant's own doc comment.
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

/// # Safety
/// `svc #0` from EL0 traps to `hal_arm64::cpu`'s shared EL0-synchronous
/// vector, which preserves every register except `x0` — this project's
/// own convention (see `hal_arm64::cpu::SyscallHandler`'s doc comment):
/// `x8` = opcode (`a7`), `x0` = `a0`, `x1` = `a1`. Same register-only
/// contract as the riscv64/x86_64 variants above.
///
/// `#[inline(never)]` — see the riscv64 variant's own doc comment.
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

/// Reports one state transition: `a0` = discriminant, `a1` = restart
/// count. `DriverState as usize` is a plain fieldless-enum cast — always
/// valid in Rust, no `unsafe` needed for the cast itself.
#[inline(always)]
fn report(state: DriverState, restarts_in_window: u32) {
    // SAFETY: see `raw_syscall`'s own contract.
    unsafe { raw_syscall(DM_REPORT, state as usize, restarts_in_window as usize) };
}

/// Blocks for the watched driver's death, then returns the crash's raw
/// `scause` value — the two ecalls always used as a pair (`DM_WAIT_CRASH`
/// then `DM_POLL_CRASH`), kept separate at the ABI level so a crash that
/// arrives before this function ever waits is not lost (see
/// `kernel_arch_glue::p2_dm_wait_crash`'s doc comment).
#[inline(always)]
fn wait_for_crash() -> usize {
    // SAFETY: see `raw_syscall`'s own contract.
    unsafe { raw_syscall(DM_WAIT_CRASH, 0, 0) };
    // SAFETY: see `raw_syscall`'s own contract.
    unsafe { raw_syscall(DM_POLL_CRASH, 0, 0) }
}

/// Asks the kernel to respawn the driver process — the automatic-restart
/// half of §5.2. This ecall does not return promptly: the kernel spawns
/// the fresh driver thread and immediately hands the CPU to it directly
/// (`kernel_arch_glue::p2_dm_handoff_to_driver`), not back to THIS
/// thread — control only returns here once the new driver has (almost
/// certainly instantly) crashed and the kernel's crash-notify hand-off
/// switches back. This deliberately never depends on the ordinary
/// fairness scheduler or the demo's preemption timer to make progress.
#[inline(always)]
fn respawn_driver() {
    // SAFETY: see `raw_syscall`'s own contract.
    unsafe { raw_syscall(DM_RESPAWN_DRIVER, 0, 0) };
}

/// Device Manager's process entry point. Drives `Supervised`'s REAL logic
/// (not reimplemented here) off REAL crashes of the REAL driver process
/// `kernel/src/main.rs` spawned (`spawn_faulty_driver`): probe-ok, then
/// block for each actual death, respawn, repeat — until the restart
/// budget is exhausted and the driver is parked `Failed` — exercising
/// every state `DriverState` defines against genuine kernel-level fault
/// isolation, not a script. Reports each transition, then spins forever
/// once `Failed` (this process's work is done; matches every other demo
/// process's "nothing switches back into a finished script, so just
/// idle" convention — it stays `Ready` and keeps taking its share of
/// preemption ticks harmlessly).
#[link_section = ".user_text"]
pub extern "C" fn subsystem_main() -> ! {
    let mut sv = Supervised::new();
    report(sv.state, sv.restarts_in_window); // Starting

    sv.on_probe_ok();
    report(sv.state, sv.restarts_in_window); // Running

    // A fixed, deterministic time source (this function makes no ecall
    // that reads the real clock) — only the RELATIVE spacing matters to
    // `on_crash`'s window-decay check, and each iteration here corresponds
    // to one REAL crash, well inside one window, so every one counts
    // toward the same budget.
    let mut now_ns: u64 = 1_000;
    loop {
        let _scause = wait_for_crash(); // blocks for the REAL driver death
        let st = sv.on_crash(now_ns);
        report(st, sv.restarts_in_window);
        if st == DriverState::Failed {
            break;
        }
        sv.on_respawn();
        respawn_driver(); // the REAL automatic restart
        now_ns += 1_000;
    }

    loop {
        core::hint::spin_loop();
    }
}
