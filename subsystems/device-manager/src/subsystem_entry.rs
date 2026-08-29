//! ============================================================================
//! subsystem_entry.rs — riscv64
//!
//! Purpose: Device Manager's real process entry point. Runs `Supervised`
//! through a scripted probe/crash/respawn lifecycle, reporting every
//! transition to the kernel via `ecall` — proof that a `subsystems/*`
//! crate's own restart-policy logic executes correctly as a genuinely
//! isolated U-mode process, not just in a host `#[cfg(test)]`.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (restart
//! policy), §5.2 (the eventual acceptance test: a REAL driver crash →
//! automatic restart — this entry point scripts the SAME state machine
//! without a real driver to crash on yet, since none is wired to IPC).
//! IMPLEMENTATION-PLAN.md's "subsystems as processes" follow-up.
//!
//! Position in the system: `kernel-arch-glue::spawn_process` maps this
//! function's containing page range (`.user_text`, shared with every
//! other demo process in this MVP — see that function's doc comment on
//! why there is no separate subsystem binary/loader yet) at `U=1 R+X`
//! into a FRESH address space and gives it a fresh `ThreadId`, admitted
//! into the SAME preemptive scheduler loop the other demo processes run
//! in (`kernel/src/main.rs`'s `p2_preempt_start`). `root-task::plan_boot`
//! decides that Device Manager is the first service to launch
//! (`Service::BOOT_ORDER[0]`).
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

/// # Safety
/// `ecall` from U-mode traps to the kernel's S-mode handler, which
/// preserves every register except `a0`. No memory access happens here —
/// only register-in/register-out, so there is no mapped-page precondition
/// beyond `.user_text` itself already being executable.
#[inline(always)]
unsafe fn raw_syscall(a7: usize, a0: usize, a1: usize) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") a7,
            in("a0") a0,
            in("a1") a1,
            lateout("a0") _,
            options(nostack),
        );
    }
}

/// Reports one state transition: `a0` = discriminant, `a1` = restart
/// count. `DriverState as usize` is a plain fieldless-enum cast — always
/// valid in Rust, no `unsafe` needed for the cast itself.
#[inline(always)]
fn report(state: DriverState, restarts_in_window: u32) {
    // SAFETY: see `raw_syscall`'s own contract.
    unsafe { raw_syscall(DM_REPORT, state as usize, restarts_in_window as usize) };
}

/// Device Manager's process entry point. Scripts a driver lifecycle
/// against `Supervised`'s REAL logic (not reimplemented here): probe-ok,
/// then repeated crashes until the restart budget is exhausted and the
/// driver is parked `Failed` — exercising every state `DriverState`
/// defines. Reports each transition, then spins forever (this process's
/// work is done; matches every other demo process's "nothing switches
/// back into a finished script, so just idle" convention — it stays
/// `Ready` and keeps taking its share of preemption ticks harmlessly).
#[link_section = ".user_text"]
pub extern "C" fn subsystem_main() -> ! {
    let mut sv = Supervised::new();
    report(sv.state, sv.restarts_in_window); // Starting

    sv.on_probe_ok();
    report(sv.state, sv.restarts_in_window); // Running

    // A fixed, deterministic time source (this function makes no ecall
    // that reads the real clock) — only the RELATIVE spacing matters to
    // `on_crash`'s window-decay check, and these are all well inside one
    // window, so every crash here counts toward the same budget.
    let mut now_ns: u64 = 1_000;
    loop {
        let st = sv.on_crash(now_ns);
        report(st, sv.restarts_in_window);
        if st == DriverState::Failed {
            break;
        }
        sv.on_respawn();
        now_ns += 1_000;
    }

    loop {
        core::hint::spin_loop();
    }
}
