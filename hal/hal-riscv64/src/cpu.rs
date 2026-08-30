//! ============================================================================
//! cpu.rs — RISC-V (RV64GC)
//!
//! Implements `hal_core::cpu::CpuAbstraction<RISCV64_CONTEXT_BYTES>`
//! for RISC-V, per 01-HAL-Layer.md section 3.1. Mirrors hal-x86_64/
//! hal-arm64's cpu.rs structure — differences below are purely
//! architectural:
//!
//!   - Feature detection: the `misa` CSR (Machine ISA register) reports
//!     which standard extensions are present, BUT `misa` is only
//!     readable from M-mode on many implementations — since this
//!     project's kernel runs in S-mode (per boot.S's module docs, SBI
//!     already completed the M-mode boot stage before handoff), this
//!     file cannot read `misa` directly. Instead, feature presence is
//!     derived from what `targets/riscv64gc-hal.json` already
//!     guarantees at COMPILE TIME (RV64GC = IMAFDC, per that target
//!     file's own doc comment) plus an SBI-mediated query
//!     (`sbi_probe_extension`) for anything SBI itself can report
//!     (e.g. vendor-specific extensions). This is a fundamentally
//!     different detection MODEL than x86_64's CPUID or ARM64's
//!     ID_AA64*_EL1 registers, both of which are freely readable at
//!     the kernel's own privilege level.
//!   - Exception/Interrupt vector: `stvec` (Supervisor Trap Vector
//!     base address register) — RISC-V's single-entry-point trap model
//!     is simpler than both x86_64's 256-entry IDT and ARM64's
//!     16-entry VBAR_EL1 table: EVERY trap (synchronous exception,
//!     interrupt) enters at the SAME address, and Rust code
//!     disambiguates by reading the `scause` CSR after entry.
//!   - Privilege levels: M-mode (boot-time only, already exited by the
//!     time this crate's Rust code runs) / S-mode (kernel) / U-mode
//!     (user) — RISC-V's M-mode is NOT reachable again from S-mode
//!     without a trap back into SBI (an `ecall`), unlike ARM64 where
//!     EL2 remains a normal target this project's own code could
//!     theoretically drop back into; RISC-V's M-mode is therefore
//!     mapped onto `PrivilegeLevel::Monitor` but, like x86_64,
//!     `set_privilege_level` declines it — the mechanism to reach
//!     M-mode functionality from S-mode is an SBI call, not a
//!     privilege transition this trait's context_switch model applies
//!     to at all.
//! ============================================================================

use core::cell::Cell;
use core::mem::size_of;

use hal_core::cpu::{CpuAbstraction, CpuContext, CpuFeatureFlags, PrivilegeLevel};
use hal_core::error::HalError;

use crate::RISCV64_CONTEXT_BYTES;

// ============================================================================
// Feature flags — compile-time RV64GC baseline + SBI extension probing
// ============================================================================

/// SBI Base extension ID (per the SBI spec, always extension ID
/// 0x10), used for `sbi_probe_extension` below — the one SBI call this
/// file needs regardless of which other extensions exist.
const SBI_EXT_BASE: usize = 0x10;
const SBI_BASE_PROBE_EXTENSION: usize = 3;

/// Issues an `ecall` into SBI (the standard RISC-V supervisor-to-
/// machine-mode call mechanism — the S-mode equivalent of a syscall,
/// but targeting firmware instead of an OS). Per the SBI calling
/// convention: a7 = extension ID, a6 = function ID, a0/a1 = arguments,
/// a0 = error code on return, a1 = value on return.
#[cfg(not(target_os = "none"))]
fn sbi_call(_ext: usize, _func: usize, _arg0: usize) -> (isize, usize) {
    // Host (`cargo test`) stub — no SBI firmware off the bare-metal
    // target. `(0, 0)` reads back as "call succeeded, extension absent",
    // the benign answer for the probe paths that reach here. Unit tests
    // never construct `Cpu`, so this is only here so the crate compiles.
    (0, 0)
}

#[cfg(target_os = "none")]
fn sbi_call(ext: usize, func: usize, arg0: usize) -> (isize, usize) {
    let (error, value): (isize, usize);
    // SAFETY: `ecall` from S-mode to SBI is the standard, well-defined
    // RISC-V supervisor-mode-to-firmware call mechanism (per the SBI
    // spec) — every extension/function ID this file uses (SBI Base
    // extension, Probe Extension function) is part of the SBI Base
    // extension, which the spec REQUIRES every SBI implementation to
    // support, so this call cannot target a genuinely unimplemented
    // firmware surface.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") ext,
            in("a6") func,
            inlateout("a0") arg0 => error,
            lateout("a1") value,
        );
    }
    (error, value)
}

/// Probes whether SBI extension `ext_id` is implemented by this
/// platform's SBI firmware. Returns `true` if the extension ID is
/// non-zero in the returned value (per SBI Base extension spec,
/// function 3 "Probe Extension").
fn sbi_probe_extension(ext_id: usize) -> bool {
    let (error, value) = sbi_call(SBI_EXT_BASE, SBI_BASE_PROBE_EXTENSION, ext_id);
    error == 0 && value != 0
}

/// SBI TIME extension ID (per the SBI spec) — probed here (not in
/// timer.rs) because feature detection as a whole is this file's
/// responsibility; `timer.rs` reads the RESULT of this probe via
/// `Cpu::sbi_time_extension_present()` below, mirroring how
/// hal-x86_64's timer.rs consumes cpu.rs's CPUID-derived capabilities
/// indirectly rather than re-probing itself.
const SBI_EXT_TIME: usize = 0x54494D45; // "TIME" as an ASCII-encoded ID, per the SBI spec

/// Detects feature flags. Unlike x86_64/ARM64's register-read-based
/// detection, this is mostly a COMPILE-TIME fact (RV64GC, guaranteed
/// by targets/riscv64gc-hal.json) plus the one SBI-mediated runtime
/// check this file actually needs (TIME extension presence, since
/// timer.rs's oneshot mechanism depends on it entirely — see
/// timer.rs's module docs).
pub fn detect_feature_flags() -> CpuFeatureFlags {
    // RV64GC = IMAFDC (Integer, Multiply/Divide, Atomic, Float,
    // Double, Compressed) — guaranteed present by this crate's target
    // file, so these bits are set unconditionally rather than probed:
    // there is no RUNTIME question of "is this feature present" the
    // way there is on x86_64 (which supports many possible CPU
    // generations) — this crate simply does not compile for, or run
    // on, a non-RV64GC-compliant core.
    let mut flags = CpuFeatureFlags::SIMD_128 // "V" vector baseline is
        // NOT part of RVGC (it's a separate, optional extension) —
        // SIMD_128 here instead represents the D (double) + F (float)
        // extensions' 128-bit-aggregate register file width (32 x
        // 64-bit FP registers), the closest RV64GC-guaranteed
        // equivalent to "some form of wide register file for
        // numeric work" that hal-core's coarse-grained flag set
        // anticipates — a deliberate approximation, documented here
        // rather than silently assumed.
        | CpuFeatureFlags::WIDE_ATOMICS; // "A" extension, guaranteed by RV64GC

    // Scalable Vector: RISC-V's "V" extension (distinct from RVGC) —
    // not part of this project's guaranteed baseline; would require a
    // runtime `misa`-equivalent check this file cannot perform from
    // S-mode (per module docs) without an SBI extension specifically
    // for CSR proxying, which is not part of the SBI Base extension
    // this file relies on. Left unset — a tracked follow-up if/when a
    // target platform's SBI implementation exposes vector-extension
    // presence through some other standard channel.

    if sbi_probe_extension(SBI_EXT_TIME) {
        // Not a CpuFeatureFlags bit on its own (hal-core has no
        // "has working timer" flag — that's what
        // TimerAbstraction::supports_tickless is for), but recorded
        // here as this file's single point of SBI extension probing;
        // `Cpu::sbi_time_extension_present()` exposes the boolean
        // itself for timer.rs to consume directly.
    }

    flags |= CpuFeatureFlags::PERF_COUNTERS; // RISC-V's hpmcounter
    // CSRs (cycle, time, instret, and hpmcounter3-31) are part of the
    // base Zicntr/Zihpm extensions, present on every RV64GC core per
    // the profile this project targets.

    flags
}

// ============================================================================
// Supervisor Trap Vector (stvec) — section 3.1's uniform Interrupt/
// Exception Vector Table requirement
// ============================================================================

// RISC-V's trap model: ALL traps (synchronous exceptions AND
// interrupts) enter at ONE address (stvec, in "Direct" mode — this
// project does not use "Vectored" mode, which would require a full
// jump table and offers little benefit at this project's current
// interrupt volume). Rust-side code disambiguates via the `scause`
// CSR, which encodes both the trap's cause code AND whether it was an
// interrupt (top bit set) or an exception (top bit clear).
#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .section .text
    .global trap_entry
    .align 4  // stvec's low 2 bits must be zero in Direct mode; 4-byte
              // alignment satisfies this trivially, matching the
              // natural instruction alignment RV64GC already requires.

    trap_entry:
        // Save all 31 general-purpose registers (x1/ra through x31;
        // x0 is hardwired zero and never needs saving) to the stack.
        // Mirrors cpu.rs's isr_common_trampoline (x86_64) /
        // irq_exception_entry (ARM64) structurally.
        addi sp, sp, -248
        sd x1,  0(sp)
        sd x2,  8(sp)   // note: x2 is sp itself; saved for context-dump
                        // completeness even though it's redundant with
                        // the stack pointer used to perform this save
        sd x3,  16(sp)
        sd x4,  24(sp)
        sd x5,  32(sp)
        sd x6,  40(sp)
        sd x7,  48(sp)
        sd x8,  56(sp)
        sd x9,  64(sp)
        sd x10, 72(sp)
        sd x11, 80(sp)
        sd x12, 88(sp)
        sd x13, 96(sp)
        sd x14, 104(sp)
        sd x15, 112(sp)
        sd x16, 120(sp)
        sd x17, 128(sp)
        sd x18, 136(sp)
        sd x19, 144(sp)
        sd x20, 152(sp)
        sd x21, 160(sp)
        sd x22, 168(sp)
        sd x23, 176(sp)
        sd x24, 184(sp)
        sd x25, 192(sp)
        sd x26, 200(sp)
        sd x27, 208(sp)
        sd x28, 216(sp)
        sd x29, 224(sp)
        sd x30, 232(sp)
        sd x31, 240(sp)

        // Pass the saved-register frame (= current sp) as the first
        // argument. `common_trap_entry` may write the saved a0 slot
        // (72(sp)) to deliver a syscall return value before the restore
        // below reloads it.
        mv a0, sp
        call common_trap_entry

        ld x1,  0(sp)
        ld x3,  16(sp)
        ld x4,  24(sp)
        ld x5,  32(sp)
        ld x6,  40(sp)
        ld x7,  48(sp)
        ld x8,  56(sp)
        ld x9,  64(sp)
        ld x10, 72(sp)
        ld x11, 80(sp)
        ld x12, 88(sp)
        ld x13, 96(sp)
        ld x14, 104(sp)
        ld x15, 112(sp)
        ld x16, 120(sp)
        ld x17, 128(sp)
        ld x18, 136(sp)
        ld x19, 144(sp)
        ld x20, 152(sp)
        ld x21, 160(sp)
        ld x22, 168(sp)
        ld x23, 176(sp)
        ld x24, 184(sp)
        ld x25, 192(sp)
        ld x26, 200(sp)
        ld x27, 208(sp)
        ld x28, 216(sp)
        ld x29, 224(sp)
        ld x30, 232(sp)
        ld x31, 240(sp)
        addi sp, sp, 248
        sret
    "#
);

/// Saved integer register file laid out by `trap_entry` on the stack:
/// `regs[i]` holds `x(i+1)` (x0 is hardwired zero and never saved), so
/// `regs[9]` is `a0`/`x10`, `regs[16]` is `a7`/`x17`, etc.
#[repr(C)]
pub struct TrapFrame {
    /// x1..x31, in order.
    pub regs: [u64; 31],
}

#[cfg(target_os = "none")]
impl TrapFrame {
    const A0: usize = 9; // x10
    const A7: usize = 16; // x17
}

/// What the trap handler should do after the microkernel's syscall
/// handler has run.
///
/// The `SwitchTo` variant is what makes cooperative *process* hand-off
/// possible (02-Microkernel-Layer.md §8.4): the handler cannot itself
/// change which U-mode thread is on the CPU — only the trap vector,
/// which owns the interrupted register frame, can. So the handler
/// returns its decision and the trap vector executes it.
pub enum TrapOutcome {
    /// Return to the trapping thread, placing `.0` in its `a0`, and
    /// advance `sepc` past the 4-byte `ecall`. The ordinary syscall
    /// return.
    Resume(usize),
    /// Same as `Resume`, but also places `.1` in `a1` — for a syscall
    /// whose result genuinely does not fit in one register (e.g. `Recv`
    /// returning both the sender's `ThreadId` and the message label —
    /// see `kernel/src/main.rs`'s `IPC_RECV` demo opcode). A separate
    /// variant rather than widening `Resume` itself: every OTHER
    /// existing caller only ever has one value to return, and this
    /// keeps them untouched.
    Resume2(usize, usize),
    /// Serialise the trapping thread's full U-mode context (every GPR,
    /// `sepc` advanced past the `ecall`, `sstatus`, `satp`) into the
    /// `HAL_USER_CONTEXT_BYTES` blob at `save`, then restore the blob at
    /// `into` and `sret` into it — a different U-mode thread, in general
    /// a different address space. Both pointers are kernel-owned,
    /// 8-byte-aligned `hal_core::UserContext` storage.
    SwitchTo {
        /// Where to write the outgoing thread's snapshot.
        save: *mut u8,
        /// The incoming thread's context to resume.
        into: *const u8,
    },
    /// The trapping thread has been TERMINATED by the microkernel (a
    /// fatal U-mode exception — 03-Kernel-Subsystems-Layer.md §2.1/§5.2's
    /// per-process fault isolation) — deliberately does NOT save its
    /// context first: a terminated thread never resumes, so there is
    /// nothing worth snapshotting (unlike `SwitchTo`, which switches
    /// AWAY from a thread that is still alive and Ready). Just restores
    /// `into` and `sret`s into it.
    Terminate {
        /// The next thread's context to resume.
        into: *const u8,
    },
}

/// Signature of the S-mode handler the microkernel registers for an
/// `ecall` from U-mode: raw `(a7, a0, a1, a2, a3, a4)`, returning a
/// `TrapOutcome` telling the trap vector how to resume.
pub type SyscallHandler = fn(usize, usize, usize, usize, usize, usize) -> TrapOutcome;

/// Signature of the handler the microkernel registers for a supervisor
/// timer interrupt taken **while a U-mode thread was running** — the
/// preemptive scheduler's entry point (02-Microkernel-Layer.md §4). It
/// takes no arguments (the trap vector owns the interrupted frame) and
/// returns a `TrapOutcome`: `Resume` to let the current thread keep its
/// quantum, or `SwitchTo` to preempt it. The handler is responsible for
/// re-arming (or cancelling) the timer via `HalInterface`.
pub type TickHandler = fn() -> TrapOutcome;

/// Signature of the handler the microkernel registers for a synchronous
/// exception (illegal instruction, page/access fault, etc. — anything
/// that is neither an `ecall` nor an interrupt) taken **while a U-mode
/// thread was running**. Per-process fault isolation
/// (03-Kernel-Subsystems-Layer.md §2.1/§5.2): a driver crash must kill
/// only that ONE process, not the whole system. `(cause_code, sepc,
/// stval)` are the raw `scause`/`sepc`/`stval` values, for logging —
/// which thread faulted is the kernel's own `kernel_sched::Scheduler::
/// running()` bookkeeping, not something this signature needs to carry.
/// Always expected to return `TrapOutcome::Terminate` in practice (the
/// faulting thread cannot safely resume), though `Resume`/`SwitchTo`
/// remain valid if a future policy wants to retry or reschedule instead.
pub type FaultHandler = fn(usize, usize, usize) -> TrapOutcome;

#[cfg(target_os = "none")]
static mut SYSCALL_HANDLER: Option<SyscallHandler> = None;

#[cfg(target_os = "none")]
static mut TICK_HANDLER: Option<TickHandler> = None;

#[cfg(target_os = "none")]
static mut FAULT_HANDLER: Option<FaultHandler> = None;

/// Registers the handler `common_trap_entry` calls for an `ecall` from
/// U-mode. The microkernel calls this once during boot, before it drops
/// any process to user mode — analogous to hal-core's timer / IRQ
/// callback registration. A binary that links `hal-riscv64` but never
/// runs user code (e.g. `kernel-stub`) simply never registers one, and an
/// unexpected U-mode `ecall` then falls through to the fatal-trap dump.
#[cfg(target_os = "none")]
pub fn set_syscall_handler(handler: SyscallHandler) {
    // SAFETY: single-core boot; set exactly once before any U-mode `ecall`
    // can be taken.
    unsafe {
        core::ptr::addr_of_mut!(SYSCALL_HANDLER).write(Some(handler));
    }
}

/// Registers the preemptive-scheduler tick handler `common_trap_entry`
/// calls when a supervisor timer interrupt lands on a running U-mode
/// thread. Set once during boot. Until it is set (and the kernel arms a
/// deadline via `HalInterface::arm_timer`), timer interrupts do nothing
/// beyond the arch-internal dispatch — so `kernel-stub`, which registers
/// no handler and never enters U-mode, is unaffected.
#[cfg(target_os = "none")]
pub fn set_tick_handler(handler: TickHandler) {
    // SAFETY: single-core boot; set exactly once before the timer is
    // armed and before any drop to U-mode.
    unsafe {
        core::ptr::addr_of_mut!(TICK_HANDLER).write(Some(handler));
    }
}

/// Registers the handler `common_trap_entry` calls for a synchronous
/// exception taken from U-mode that is not an `ecall`. Set once during
/// boot, before any drop to U-mode. Until it is set, a U-mode exception
/// falls through to the fatal system-halt dump — same "no handler, no
/// behavior change" contract as `set_syscall_handler`/`set_tick_handler`,
/// so `kernel-stub` (which never registers one) is unaffected.
#[cfg(target_os = "none")]
pub fn set_fault_handler(handler: FaultHandler) {
    // SAFETY: single-core boot; set exactly once before any drop to
    // U-mode.
    unsafe {
        core::ptr::addr_of_mut!(FAULT_HANDLER).write(Some(handler));
    }
}

/// Called from `trap_entry`'s assembly trampoline with `frame` pointing
/// at the saved register file. Reads `scause` to disambiguate interrupt
/// vs. exception; routes an `ecall` from U-mode (cause 8) to
/// `simurgh_syscall` and advances `sepc` past it; dispatches interrupts
/// to `interrupt.rs`; dumps and halts on anything else.
#[cfg(not(target_os = "none"))]
#[no_mangle]
extern "C" fn common_trap_entry(_frame: *mut TrapFrame) {
    // Host (`cargo test`) stub — reached only from the bare-metal
    // `trap_entry` trampoline, which is not linked off the bare-metal
    // target.
}

/// RISC-V `scause` code for "environment call from U-mode".
#[cfg(target_os = "none")]
const CAUSE_ECALL_FROM_U: usize = 8;

/// RISC-V `scause` interrupt code for the supervisor timer interrupt
/// (the interrupt bit is already masked off by `common_trap_entry`).
#[cfg(target_os = "none")]
const CAUSE_TIMER_INTERRUPT: usize = 5;

/// `sstatus.SPP` — 0 when the trap came from U-mode.
#[cfg(target_os = "none")]
const SSTATUS_SPP_BIT: usize = 1 << 8;

#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn common_trap_entry(frame: *mut TrapFrame) {
    let (scause, sepc, stval): (usize, usize, usize);
    // SAFETY: reading scause/sepc/stval has no preconditions inside a
    // trap handler, which `trap_entry` guarantees this runs inside of.
    unsafe {
        core::arch::asm!("csrr {}, scause", out(reg) scause);
        core::arch::asm!("csrr {}, sepc", out(reg) sepc);
        core::arch::asm!("csrr {}, stval", out(reg) stval);
    }

    // Top bit set = interrupt; clear = synchronous exception. Per the
    // RISC-V privileged spec's scause encoding (section 4.1.8).
    let is_interrupt = (scause as isize) < 0;
    let cause_code = scause & !(1 << (usize::BITS - 1));

    if is_interrupt {
        crate::interrupt::dispatch_current_interrupt(cause_code as u32);

        // Preemption: a supervisor timer interrupt that landed on a
        // running U-mode thread is the microkernel's cue to run its
        // scheduler (02-Microkernel-Layer.md §4). The tick handler
        // decides; the trap vector (which owns the interrupted frame)
        // executes the switch, exactly like the `ecall` `SwitchTo` path
        // — but resuming AT `sepc` (the preempted instruction), not
        // `sepc + 4`.
        if cause_code == CAUSE_TIMER_INTERRUPT {
            let sstatus: usize;
            // SAFETY: `csrr sstatus` has no preconditions in a trap
            // handler.
            unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) sstatus) };
            let from_user = (sstatus & SSTATUS_SPP_BIT) == 0;
            if from_user {
                // SAFETY: single-core; `TICK_HANDLER` is only written by
                // `set_tick_handler` during boot, before the timer is
                // armed.
                let handler = unsafe { core::ptr::addr_of!(TICK_HANDLER).read() };
                if let Some(h) = handler {
                    match h() {
                        TrapOutcome::Resume(_) | TrapOutcome::Resume2(_, _) => return,
                        TrapOutcome::SwitchTo { save, into } => {
                            // SAFETY: `save` / `into` are kernel-owned
                            // aligned `HAL_USER_CONTEXT_BYTES` blobs.
                            // Snapshot the preempted thread at `sepc`
                            // exactly, then never return.
                            let f = unsafe { &mut *frame };
                            unsafe {
                                save_trap_frame_as_user_context(
                                    f,
                                    sepc,
                                    save as *mut RiscvUserContext,
                                );
                                restore_user_and_sret(into as *const RiscvUserContext);
                            }
                        }
                        TrapOutcome::Terminate { into } => {
                            // Not the normal path for a timer tick, but
                            // the type is shared with the fault-isolation
                            // path below, so this arm must exist. No
                            // save: the preempted thread is being
                            // terminated, not merely switched out.
                            // SAFETY: `into` is a kernel-owned, 8-byte-
                            // aligned `HAL_USER_CONTEXT_BYTES` blob.
                            unsafe { restore_user_and_sret(into as *const RiscvUserContext) };
                        }
                    }
                }
            }
        }
        return;
    }

    if cause_code == CAUSE_ECALL_FROM_U {
        // SAFETY: `frame` is the on-stack register file `trap_entry`
        // just saved; valid for this call, with no other live reference.
        let f = unsafe { &mut *frame };
        // SAFETY: single-core; `SYSCALL_HANDLER` is only written by
        // `set_syscall_handler` during boot, before any U-mode `ecall`.
        let handler = unsafe { core::ptr::addr_of!(SYSCALL_HANDLER).read() };
        let outcome = match handler {
            Some(h) => h(
                f.regs[TrapFrame::A7] as usize,
                f.regs[TrapFrame::A0] as usize,
                f.regs[TrapFrame::A0 + 1] as usize,
                f.regs[TrapFrame::A0 + 2] as usize,
                f.regs[TrapFrame::A0 + 3] as usize,
                f.regs[TrapFrame::A0 + 4] as usize,
            ),
            None => {
                trap_diag(cause_code, sepc, stval);
                halt_on_unexpected_exception();
            }
        };
        match outcome {
            TrapOutcome::Resume(ret) => {
                f.regs[TrapFrame::A0] = ret as u64;
                // Resume at the instruction after the 4-byte `ecall`.
                // SAFETY: writing sepc is valid within a trap handler.
                unsafe { core::arch::asm!("csrw sepc, {}", in(reg) sepc + 4) };
                return;
            }
            TrapOutcome::Resume2(a0, a1) => {
                f.regs[TrapFrame::A0] = a0 as u64;
                f.regs[TrapFrame::A0 + 1] = a1 as u64;
                // SAFETY: writing sepc is valid within a trap handler.
                unsafe { core::arch::asm!("csrw sepc, {}", in(reg) sepc + 4) };
                return;
            }
            TrapOutcome::SwitchTo { save, into } => {
                // SAFETY: `save` / `into` are kernel-owned, 8-byte-
                // aligned `HAL_USER_CONTEXT_BYTES` blobs (the trampoline
                // / `UserContext` contract). Snapshot the outgoing
                // thread — resuming AFTER its `ecall` — then never
                // return: `restore_user_and_sret` abandons this trap
                // frame's stack and `sret`s into the incoming thread.
                unsafe {
                    save_trap_frame_as_user_context(
                        f,
                        sepc + 4,
                        save as *mut RiscvUserContext,
                    );
                    restore_user_and_sret(into as *const RiscvUserContext);
                }
            }
            TrapOutcome::Terminate { into } => {
                // Not the normal path for an `ecall` (a syscall handler
                // "terminating" the caller mid-syscall is unusual, but
                // the type is shared with the exception-fault path
                // below, so this arm must exist). No save: this trap
                // frame is simply abandoned, same as any other
                // terminated thread.
                // SAFETY: `into` is a kernel-owned, 8-byte-aligned
                // `HAL_USER_CONTEXT_BYTES` blob.
                unsafe { restore_user_and_sret(into as *const RiscvUserContext) };
            }
        }
    }

    // A synchronous exception that is neither an `ecall` nor (handled
    // above) a timer interrupt. If it came from a U-mode thread and the
    // microkernel registered a fault handler, this is per-process fault
    // isolation (03-Kernel-Subsystems-Layer.md §2.1/§5.2): terminate
    // THAT thread and switch to whatever else is runnable, rather than
    // halting the whole system. An S-mode fault (the kernel's own bug)
    // or no registered handler (e.g. `kernel-stub`) keeps the original,
    // unconditional system-halt behavior — a kernel-mode fault is
    // genuinely fatal for this MVP.
    let sstatus_now: usize;
    // SAFETY: `csrr sstatus` has no preconditions in a trap handler.
    unsafe { core::arch::asm!("csrr {}, sstatus", out(reg) sstatus_now) };
    let from_user = (sstatus_now & SSTATUS_SPP_BIT) == 0;
    if from_user {
        // SAFETY: single-core; `FAULT_HANDLER` is only written by
        // `set_fault_handler` during boot, before any drop to U-mode.
        let handler = unsafe { core::ptr::addr_of!(FAULT_HANDLER).read() };
        if let Some(h) = handler {
            match h(cause_code, sepc, stval) {
                TrapOutcome::Resume(_) | TrapOutcome::Resume2(_, _) => return,
                TrapOutcome::SwitchTo { save, into } => {
                    // SAFETY: `frame` is the on-stack register file
                    // `trap_entry` just saved; valid here, no other live
                    // reference (the `ecall` branch above already
                    // returned by this point). `save`/`into` as the
                    // `ecall` `SwitchTo` arm above.
                    let f = unsafe { &mut *frame };
                    unsafe {
                        save_trap_frame_as_user_context(f, sepc, save as *mut RiscvUserContext);
                        restore_user_and_sret(into as *const RiscvUserContext);
                    }
                }
                TrapOutcome::Terminate { into } => {
                    // The expected outcome: the faulting thread is dead,
                    // its trap frame abandoned, no save.
                    // SAFETY: `into` is a kernel-owned, 8-byte-aligned
                    // `HAL_USER_CONTEXT_BYTES` blob.
                    unsafe { restore_user_and_sret(into as *const RiscvUserContext) };
                }
            }
        }
    }

    trap_diag(cause_code, sepc, stval);
    halt_on_unexpected_exception();
}

/// Minimal MMIO dump of an unexpected trap over QEMU virt's NS16550
/// (0x1000_0000) so a fault is visible instead of a silent hang. Only
/// used on the bare-metal target's fatal path.
#[cfg(target_os = "none")]
fn trap_diag(cause_code: usize, sepc: usize, stval: usize) {
    const UART_THR: usize = 0x1000_0000;
    const UART_LSR: usize = 0x1000_0005;
    fn putb(b: u8) {
        // SAFETY: fixed, OpenSBI-accessible NS16550 MMIO; poll THRE then
        // write THR.
        unsafe {
            while core::ptr::read_volatile(UART_LSR as *const u8) & 0x20 == 0 {}
            core::ptr::write_volatile(UART_THR as *mut u8, b);
        }
    }
    fn puts(s: &str) {
        for b in s.bytes() {
            putb(b);
        }
    }
    fn puthex(mut v: usize) {
        puts("0x");
        let mut started = false;
        for i in (0..16).rev() {
            let nib = ((v >> (i * 4)) & 0xF) as u8;
            if nib != 0 || started || i == 0 {
                started = true;
                putb(if nib < 10 { b'0' + nib } else { b'a' + nib - 10 });
            }
        }
        let _ = &mut v;
    }
    puts("\r\nUNHANDLED TRAP: scause=");
    puthex(cause_code);
    puts(" sepc=");
    puthex(sepc);
    puts(" stval=");
    puthex(stval);
    puts("\r\n");
}

fn halt_on_unexpected_exception() -> ! {
    loop {
        // SAFETY: `wfi` is the standard, side-effect-free halt — same
        // terminal-state justification as every other architecture's
        // equivalent unexpected-trap handling. On a host (`cargo test`)
        // build there is no `wfi`; the bare `loop {}` is an equivalent
        // (if busy) terminal state, and no test reaches this path.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Loads `stvec` to point at `trap_entry`, in Direct mode (low 2 bits
/// = 0b00).
///
/// # Safety
/// Must only be called once per hart, before this hart relies on any
/// trap (including timer/external interrupts) being handled correctly.
#[cfg(not(target_os = "none"))]
unsafe fn load_stvec() {
    // Host (`cargo test`) stub — no `stvec` / trap vector off the
    // bare-metal target.
}

#[cfg(target_os = "none")]
unsafe fn load_stvec() {
    unsafe extern "C" {
        static trap_entry: u8;
    }
    // SAFETY: `trap_entry`'s address is a `'static`, 4-byte-aligned
    // code label emitted by the global_asm! block above — `stvec` has
    // no further preconditions in Direct mode beyond this alignment.
    unsafe {
        let addr = &trap_entry as *const u8 as usize;
        core::arch::asm!("csrw stvec, {}", in(reg) addr);
    }
}

// ============================================================================
// Saved hardware context layout (matches RISCV64_CONTEXT_BYTES = 160)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Riscv64Context {
    // Callee-saved integer registers per the RISC-V ELF psABI: s0/s1
    // (x8/x9), s2-s11 (x18-x27).
    s0: u64, s1: u64,
    s2: u64, s3: u64, s4: u64, s5: u64, s6: u64, s7: u64,
    s8: u64, s9: u64, s10: u64, s11: u64,
    ra: u64,  // x1, used as the resume PC on restore
    sp: u64,  // x2
    // Address space root: satp (Supervisor Address Translation and
    // Protection register) — RISC-V's equivalent of x86_64's CR3 /
    // ARM64's TTBR0_EL1.
    satp: u64,
    sstatus: u64, // privilege/interrupt-enable state to restore
    tp: u64,      // x4, thread-local storage base per RISC-V ELF psABI
    // Padding to RISCV64_CONTEXT_BYTES (160): 17 live u64 fields = 136
    // bytes, + 3 reserved slots = 160. Matches the other two
    // architectures' "round the context size up for headroom" convention
    // (see RISCV64_CONTEXT_BYTES's doc comment in lib.rs).
    _reserved: [u64; 3],
}

const _: () = {
    assert!(size_of::<Riscv64Context>() == RISCV64_CONTEXT_BYTES);
};

// ============================================================================
// Saved U-mode context layout (matches hal_core::HAL_USER_CONTEXT_BYTES = 320)
//
// Unlike `Riscv64Context` (callee-saved only, resumed with `jr` for the
// kernel-to-kernel cooperative path), a suspended U-mode thread is
// snapshotted from an arbitrary trap point, so every integer register has
// to survive the round trip, plus the CSRs `sret` consumes: `sepc` (where
// to resume), `sstatus` (SPP/SPIE — privilege + interrupt-enable to
// restore), and `satp` (which address space the thread runs in). This is
// the concrete form behind `hal_core::UserContext`.
// ============================================================================

/// `regs[i]` holds `x(i+1)` (x0 is hardwired zero, never stored): `regs[0]`
/// = `x1`/`ra`, `regs[1]` = `x2`/`sp`, `regs[9]` = `x10`/`a0`, `regs[16]` =
/// `x17`/`a7`, `regs[30]` = `x31`/`t6`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RiscvUserContext {
    /// x1..x31, in order.
    regs: [u64; 31],
    /// Resume program counter in U-mode.
    sepc: u64,
    /// Privilege / interrupt-enable snapshot (`sret` restores SIE from
    /// SPIE and the privilege level from SPP).
    sstatus: u64,
    /// Address-space root (`satp`) the thread executes under.
    satp: u64,
    /// Padding to `HAL_USER_CONTEXT_BYTES`: 34 live u64 = 272, + 6 = 320.
    _reserved: [u64; 6],
}

const _: () = {
    assert!(size_of::<RiscvUserContext>() == hal_core::HAL_USER_CONTEXT_BYTES);
};

/// Overwrites a SAVED (not currently executing) `UserContext` blob's
/// `a0`/`a1` fields directly — for a thread being woken via a direct
/// `TrapOutcome::SwitchTo` hand-off (not its own trap resuming, which
/// goes through `Resume`/`Resume2` above instead): the target's a0/a1
/// still hold whatever it originally trapped in WITH (its OWN syscall's
/// input arguments), and the kernel-core-level delivery it is being
/// woken for (e.g. `kernel_core::syscall::do_send`'s `Call` fast path
/// delivering into an already-blocked `Recv`er) needs its RESULT
/// placed there instead before the switch runs — mirrors `kernel/src/
/// main.rs`'s own `IPC_RECV` demo opcode, which is the reason this
/// exists.
///
/// # Safety
/// `ctx` must point at a valid, currently-not-executing
/// `HAL_USER_CONTEXT_BYTES` blob (the same contract `TrapOutcome::
/// SwitchTo`'s `into` pointer carries) — typically a TCB's own
/// `user_context` storage, reached BEFORE the actual switch into it.
pub unsafe fn poke_saved_a0_a1(ctx: *mut u8, a0: usize, a1: usize) {
    // SAFETY: forwarded from this function's own contract; `ctx` is
    // `HAL_USER_CONTEXT_BYTES`-sized and 8-byte-aligned per that
    // contract, matching `RiscvUserContext`'s own size/alignment (see
    // the `const _` assertion just above).
    let c = unsafe { &mut *(ctx as *mut RiscvUserContext) };
    // `regs[9]`/`regs[10]` = `x10`/`x11` = `a0`/`a1` — see
    // `RiscvUserContext`'s own doc comment (not `TrapFrame::A0`, which
    // is only defined `#[cfg(target_os = "none")]` and this function
    // must compile on host too, for `hal-riscv64`'s own test suite).
    c.regs[9] = a0 as u64;
    c.regs[10] = a1 as u64;
}

/// SPP is `sstatus` bit 8 (Supervisor Previous Privilege): 0 = the trap
/// that will be returned from via `sret` came from U-mode, so `sret`
/// drops to U-mode. Only consumed on the bare-metal target (the host
/// `init_user_context` path takes a fixed `sstatus`).
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
const SSTATUS_SPP: u64 = 1 << 8;
/// SPIE is `sstatus` bit 5 (Supervisor Previous Interrupt Enable): `sret`
/// copies it back into SIE. Set it so the resumed thread runs with
/// S-mode interrupt delivery in the state it should be (harmless today —
/// nothing is routed to S-mode yet).
const SSTATUS_SPIE: u64 = 1 << 5;

/// Restores a full `RiscvUserContext` and `sret`s into U-mode. Never
/// returns. Shared by `resume_user` (first entry, from an
/// `init_user_context` blob) and the trap handler's process hand-off
/// path (from a blob it just serialised out of a trap frame).
///
/// # Safety
/// `blob` must point at a valid, resumable `RiscvUserContext` whose
/// `satp` names an address space that maps this core's trap vector and
/// the identity-mapped low RAM `blob` itself lives in. Interrupts must be
/// masked. Never returns, so it does not restore the caller's frame — a
/// non-hand-off caller's stack frame is simply abandoned.
#[cfg(target_os = "none")]
unsafe fn restore_user_and_sret(blob: *const RiscvUserContext) -> ! {
    // SAFETY: contract above. `t6` carries the blob base for the whole
    // sequence; CSRs are written first (using `t5` as scratch, which is
    // then given its real value by the GPR restore), then x1..x30, then
    // `t6`/x31 loads its own final value from its slot last, then `sret`.
    unsafe {
        core::arch::asm!(
            "ld  t5, 256(t6)",   // sstatus
            "csrw sstatus, t5",
            "ld  t5, 248(t6)",   // sepc
            "csrw sepc, t5",
            "ld  t5, 264(t6)",   // satp
            "csrw satp, t5",
            "sfence.vma",
            "ld  x1,  0(t6)",
            "ld  x2,  8(t6)",
            "ld  x3,  16(t6)",
            "ld  x4,  24(t6)",
            "ld  x5,  32(t6)",
            "ld  x6,  40(t6)",
            "ld  x7,  48(t6)",
            "ld  x8,  56(t6)",
            "ld  x9,  64(t6)",
            "ld  x10, 72(t6)",
            "ld  x11, 80(t6)",
            "ld  x12, 88(t6)",
            "ld  x13, 96(t6)",
            "ld  x14, 104(t6)",
            "ld  x15, 112(t6)",
            "ld  x16, 120(t6)",
            "ld  x17, 128(t6)",
            "ld  x18, 136(t6)",
            "ld  x19, 144(t6)",
            "ld  x20, 152(t6)",
            "ld  x21, 160(t6)",
            "ld  x22, 168(t6)",
            "ld  x23, 176(t6)",
            "ld  x24, 184(t6)",
            "ld  x25, 192(t6)",
            "ld  x26, 200(t6)",
            "ld  x27, 208(t6)",
            "ld  x28, 216(t6)",
            "ld  x29, 224(t6)",
            "ld  x30, 232(t6)",
            "ld  x31, 240(t6)",
            "sret",
            in("t6") blob,
            options(noreturn),
        );
    }
}

/// Serialises an interrupted U-mode trap frame into a `RiscvUserContext`
/// so it can be `restore_user_and_sret`'d later. `resume_sepc` is where
/// the thread should continue (the trap handler passes `sepc + 4` so a
/// suspended `ecall` does not re-execute). Captures the *live* `sstatus`
/// and `satp`, which for a trap taken from U-mode already describe the
/// thread's own privilege state and address space.
///
/// # Safety
/// `dst` must point at valid, writable `HAL_USER_CONTEXT_BYTES`-sized,
/// 8-byte-aligned storage.
#[cfg(target_os = "none")]
unsafe fn save_trap_frame_as_user_context(
    frame: &TrapFrame,
    resume_sepc: usize,
    dst: *mut RiscvUserContext,
) {
    let (sstatus, satp): (u64, u64);
    // SAFETY: reading sstatus/satp has no preconditions in S-mode.
    unsafe {
        core::arch::asm!("csrr {}, sstatus", out(reg) sstatus);
        core::arch::asm!("csrr {}, satp", out(reg) satp);
    }
    // SAFETY: `dst` is valid writable storage of the matching size /
    // alignment per this function's contract.
    unsafe {
        (*dst).regs = frame.regs; // regs[i] == x(i+1) in both layouts
        // `trap_entry` saves x2 (sp) into the frame AFTER `addi sp, sp,
        // -248`, so `frame.regs[1]` is 248 bytes below the thread's real
        // stack pointer. The pre-trap sp is exactly one `TrapFrame`
        // above `frame` itself — restore THAT, or the resumed thread's
        // stack-relative accesses land in the abandoned trap frame.
        (*dst).regs[1] =
            frame as *const TrapFrame as u64 + core::mem::size_of::<TrapFrame>() as u64;
        (*dst).sepc = resume_sepc as u64;
        (*dst).sstatus = sstatus;
        (*dst).satp = satp;
        (*dst)._reserved = [0; 6];
    }
}

// ============================================================================
// Cpu — CpuAbstraction<RISCV64_CONTEXT_BYTES> implementation
// ============================================================================

pub struct Cpu {
    feature_flags: Cell<CpuFeatureFlags>,
    hart_id: usize,
    sbi_time_extension_present: bool,
}

impl Cpu {
    /// `hart_id` is passed down from `boot.S` via
    /// `hal_riscv64_rust_entry` (lib.rs) — unlike x86_64/ARM64, where
    /// the core id is read from a hardware register
    /// (APIC ID / MPIDR_EL1) AFTER Rust code starts, RISC-V's SBI boot
    /// protocol hands the hart id directly as a boot parameter, so
    /// there is nothing to separately "detect" here.
    pub fn new(hart_id: usize) -> Self {
        let sbi_time_extension_present = sbi_probe_extension(SBI_EXT_TIME);
        let feature_flags = Cell::new(detect_feature_flags());
        Self { feature_flags, hart_id, sbi_time_extension_present }
    }

    /// Mirrors hal-x86_64/hal-arm64's `mark_iommu_capable`: IOPMP
    /// presence (RISC-V's IOMMU equivalent, section 3.2) is discovered
    /// via Device Tree by `memory.rs`, not via any CPU-local register,
    /// so it is folded in after the fact.
    pub fn mark_iommu_capable(&self, present: bool) {
        let mut flags = self.feature_flags.get();
        flags.set(CpuFeatureFlags::IOMMU_CAPABLE, present);
        self.feature_flags.set(flags);
    }

    /// Consumed by `timer.rs`, per this file's module docs on why SBI
    /// extension probing is centralized here.
    pub fn sbi_time_extension_present(&self) -> bool {
        self.sbi_time_extension_present
    }

    /// Same MVP-phase single-hart scope as the other two
    /// architectures' `detected_core_count` — real multi-hart
    /// enumeration requires parsing the Device Tree's `cpus` node, a
    /// tracked follow-up alongside memory.rs's DT parsing scope.
    fn detected_core_count(&self) -> usize {
        1
    }
}

impl CpuAbstraction<{ crate::RISCV64_CONTEXT_BYTES }> for Cpu {
    fn core_count(&self) -> usize {
        self.detected_core_count()
    }

    fn current_core_id(&self) -> usize {
        self.hart_id
    }

    fn feature_flags(&self) -> CpuFeatureFlags {
        self.feature_flags.get()
    }

    unsafe fn context_switch(
        &self,
        from: &mut CpuContext<{ crate::RISCV64_CONTEXT_BYTES }>,
        to: &CpuContext<{ crate::RISCV64_CONTEXT_BYTES }>,
    ) {
        // SAFETY: same reasoning as the other two architectures'
        // context_switch — buffer size/alignment matches
        // Riscv64Context exactly (see the `const _` assertion above),
        // and this trait method's own safety contract (hal-core/src/
        // cpu.rs) guarantees valid, non-aliasing, previously-saved-or-
        // freshly-initialized contexts.
        let from_ctx = unsafe { &mut *(from.as_bytes_mut().as_mut_ptr() as *mut Riscv64Context) };
        let to_ctx = unsafe { &*(to.as_bytes().as_ptr() as *const Riscv64Context) };

        // Host (`cargo test`) build: a real register save/restore cannot
        // run off the bare-metal target, and no unit test drives an
        // actual context switch (they assert the context *layout* only).
        #[cfg(not(target_os = "none"))]
        {
            let _ = (from_ctx, to_ctx);
            unreachable!("context_switch is bare-metal only (host test build)");
        }

        // SAFETY: hardware register save/restore this trait method
        // exists to perform; preconditions (interrupts masked,
        // non-aliasing contexts, valid to_ctx) are the caller's
        // responsibility per the trait's own safety documentation.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!(
                "sd s0,  0x00({from_ptr})",
                "sd s1,  0x08({from_ptr})",
                "sd s2,  0x10({from_ptr})",
                "sd s3,  0x18({from_ptr})",
                "sd s4,  0x20({from_ptr})",
                "sd s5,  0x28({from_ptr})",
                "sd s6,  0x30({from_ptr})",
                "sd s7,  0x38({from_ptr})",
                "sd s8,  0x40({from_ptr})",
                "sd s9,  0x48({from_ptr})",
                "sd s10, 0x50({from_ptr})",
                "sd s11, 0x58({from_ptr})",
                "sd sp,  0x68({from_ptr})",
                "csrr t0, satp",
                "sd t0,  0x70({from_ptr})",
                // Capture resume point: label 1 below.
                "la t0, 1f",
                "sd t0,  0x60({from_ptr})", // overwrite saved-ra slot with resume addr

                "ld t0,  0x70({to_ptr})",
                "csrw satp, t0",
                "sfence.vma",
                "ld sp,  0x68({to_ptr})",
                "ld s0,  0x00({to_ptr})",
                "ld s1,  0x08({to_ptr})",
                "ld s2,  0x10({to_ptr})",
                "ld s3,  0x18({to_ptr})",
                "ld s4,  0x20({to_ptr})",
                "ld s5,  0x28({to_ptr})",
                "ld s6,  0x30({to_ptr})",
                "ld s7,  0x38({to_ptr})",
                "ld s8,  0x40({to_ptr})",
                "ld s9,  0x48({to_ptr})",
                "ld s10, 0x50({to_ptr})",
                "ld s11, 0x58({to_ptr})",
                "ld t0,  0x60({to_ptr})",
                "jr t0",

                "1:",
                from_ptr = in(reg) from_ctx as *mut Riscv64Context,
                to_ptr = in(reg) to_ctx as *const Riscv64Context,
                out("t0") _,
            );
        }
    }

    fn init_context(
        &self,
        context: &mut CpuContext<{ crate::RISCV64_CONTEXT_BYTES }>,
        entry: usize,
        stack_top: usize,
    ) {
        // SAFETY: a `[u8; RISCV64_CONTEXT_BYTES]` buffer is layout-
        // compatible with `Riscv64Context` (`#[repr(C)]`, size asserted
        // by the `const _` above). Zeroing then setting the three fields
        // the `context_switch` restore path actually consumes for a
        // fresh thread: `ra` (jumped to via `jr`), `sp`, and `satp`.
        let ctx = unsafe {
            &mut *(context.as_bytes_mut().as_mut_ptr() as *mut Riscv64Context)
        };
        *ctx = Riscv64Context::default();
        ctx.ra = entry as u64;
        ctx.sp = stack_top as u64;

        #[cfg(target_os = "none")]
        {
            // SAFETY: `csrr satp` is always valid to execute in S-mode;
            // the new thread runs in this same address space for now.
            let satp: u64;
            unsafe { core::arch::asm!("csrr {0}, satp", out(reg) satp) };
            ctx.satp = satp;
        }
        #[cfg(not(target_os = "none"))]
        {
            ctx.satp = 0;
        }
    }

    #[cfg(target_os = "none")]
    fn map_ram_identity(&self, root_frame: usize, bytes_gib: usize, user_accessible: bool) {
        let root = root_frame as *mut u64;
        // SAFETY: `root_frame` is a caller-guaranteed page-aligned,
        // writable physical frame; paging is still off (satp == 0). Zero
        // the root, then install one 1 GiB identity LEAF per GiB (root
        // index == VA[38:30] == the GiB number). `map_range` can add finer
        // mappings only for a VA whose GiB slot is still empty (not a
        // gigapage leaf) — callers put per-process pages in a GiB above
        // `bytes_gib`.
        unsafe {
            for i in 0..512 {
                root.add(i).write_volatile(0);
            }
            let mut flags = riscv_sv39::V | riscv_sv39::R | riscv_sv39::W
                | riscv_sv39::X | riscv_sv39::A | riscv_sv39::D;
            if user_accessible {
                flags |= riscv_sv39::U;
            }
            for gib in 0..bytes_gib.min(512) {
                // ppn = (gib * 1 GiB) >> 12 == gib << 18; pte = ppn << 10 | flags.
                root.add(gib).write_volatile(((gib as u64) << 28) | flags);
            }
        }
    }

    #[cfg(target_os = "none")]
    fn activate_address_space(&self, root_frame: usize) {
        // satp (Sv39): mode = 8 in bits [63:60], ASID = 0, PPN = root >> 12.
        // `root_frame == 0` is the sentinel for "disable paging" (satp = 0,
        // Bare mode) — used to return to flat physical addressing.
        let satp = if root_frame == 0 {
            0u64
        } else {
            (8u64 << 60) | ((root_frame as u64) >> 12)
        };
        // SAFETY: `root_frame` is a caller-guaranteed valid Sv39 root that
        // maps at least all memory this core executes from and touches
        // next. `sfence.vma` around the `satp` write flushes stale
        // entries; `csrs sstatus, SUM` lets S-mode reach U=1 pages (needed
        // once the kernel dereferences user pointers from a trap).
        unsafe {
            core::arch::asm!(
                "sfence.vma",
                "csrw satp, {satp}",
                "sfence.vma",
                "li   {t}, 1 << 18",   // sstatus.SUM
                "csrs sstatus, {t}",
                satp = in(reg) satp,
                t = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }

    #[cfg(target_os = "none")]
    fn flush_tlb(&self) {
        // SAFETY: `sfence.vma` with no rs1/rs2 (x0, x0) flushes every
        // address-translation cache entry for the current ASID space on
        // this hart. It has no preconditions in S-mode and no effect
        // beyond the flush — the microkernel issues it after `map_range`
        // has walked new leaves into the active Sv39 table so a
        // subsequent access (or the U-mode task's first touch of the new
        // page) does not hit a stale negative entry.
        unsafe {
            core::arch::asm!("sfence.vma", options(nostack, preserves_flags));
        }
    }

    #[cfg(target_os = "none")]
    fn map_range(
        &self,
        root_frame: usize,
        vaddr: usize,
        paddr: usize,
        len: usize,
        perm_bits: usize,
        pool_base: usize,
        pool_len: usize,
    ) -> u32 {
        riscv_sv39::map_range(root_frame, vaddr, paddr, len, perm_bits, pool_base, pool_len)
    }

    #[cfg(target_os = "none")]
    fn enter_user(&self, entry: usize, stack_top: usize) -> ! {
        // The sstatus bit masks are passed as inputs (not built with `li`
        // into a scratch register) because `options(noreturn)` forbids
        // asm outputs/clobbers, and we must not risk the assembler
        // picking `sp`/`ra` for a `{}` operand — `in(reg)` operands are
        // always compiler-allocated GPRs other than those.
        let clear_spp: usize = 1 << 8; // sstatus.SPP
        let set_spie: usize = 1 << 5; // sstatus.SPIE

        // SAFETY: a one-way `sret` into U-mode: clears SPP so the sret
        // targets U-mode, sets SPIE, points sepc at `entry`, installs
        // `stack_top` as sp. Interrupts are routed nowhere in S-mode yet,
        // so enabling SIE via SPIE is harmless. Never returns.
        unsafe {
            core::arch::asm!(
                "csrc sstatus, {clr}",
                "csrs sstatus, {set}",
                "csrw sepc, {entry}",
                "mv   sp, {sp}",
                "sret",
                clr = in(reg) clear_spp,
                set = in(reg) set_spie,
                entry = in(reg) entry,
                sp = in(reg) stack_top,
                options(noreturn),
            );
        }
    }

    fn init_user_context(
        &self,
        context: &mut hal_core::UserContext,
        entry: usize,
        stack_top: usize,
        root_frame: usize,
    ) {
        // SAFETY: `hal_core::UserContext` is `#[repr(C, align(8))]` over
        // exactly `[u8; HAL_USER_CONTEXT_BYTES]` and `RiscvUserContext`
        // is `#[repr(C)]` of that same asserted size — so the buffer IS
        // a valid `RiscvUserContext`.
        let ctx = unsafe {
            &mut *(context.as_bytes_mut().as_mut_ptr() as *mut RiscvUserContext)
        };
        *ctx = RiscvUserContext::default();
        ctx.regs[1] = stack_top as u64; // x2 = sp
        ctx.sepc = entry as u64;

        // satp: Sv39 mode 8, ASID 0, PPN = root_frame >> 12. `root_frame
        // == 0` means "keep whatever is active" — read it back so the
        // first `resume_user` does not clobber the live translation.
        ctx.satp = if root_frame != 0 {
            (8u64 << 60) | ((root_frame as u64) >> 12)
        } else {
            #[cfg(target_os = "none")]
            {
                let satp: u64;
                // SAFETY: `csrr satp` is always valid in S-mode.
                unsafe { core::arch::asm!("csrr {0}, satp", out(reg) satp) };
                satp
            }
            #[cfg(not(target_os = "none"))]
            {
                0
            }
        };

        // sstatus for a fresh U-mode entry: start from the live value so
        // fields like SUM are preserved, then force SPP = 0 (so `sret`
        // targets U-mode) and SPIE = 1.
        #[cfg(target_os = "none")]
        {
            let sstatus: u64;
            // SAFETY: `csrr sstatus` is always valid in S-mode.
            unsafe { core::arch::asm!("csrr {0}, sstatus", out(reg) sstatus) };
            ctx.sstatus = (sstatus & !SSTATUS_SPP) | SSTATUS_SPIE;
        }
        #[cfg(not(target_os = "none"))]
        {
            ctx.sstatus = SSTATUS_SPIE;
        }
    }

    #[cfg(target_os = "none")]
    unsafe fn resume_user(&self, context: &hal_core::UserContext) -> ! {
        // SAFETY: the buffer is a valid `RiscvUserContext` (see
        // `init_user_context`); the resumable-context + interrupts-masked
        // obligations are this method's documented caller contract.
        let blob = context.as_bytes().as_ptr() as *const RiscvUserContext;
        unsafe { restore_user_and_sret(blob) }
    }

    #[cfg(not(target_os = "none"))]
    unsafe fn resume_user(&self, context: &hal_core::UserContext) -> ! {
        let _ = context;
        unreachable!("resume_user is bare-metal only (host test build)");
    }

    fn set_privilege_level(&self, level: PrivilegeLevel) -> Result<(), HalError> {
        match level {
            // RISC-V's M-mode (mapped to Monitor) is not reachable via
            // a privilege-level primitive at all from S-mode — the
            // ONLY way back into M-mode is an `ecall` (an SBI call),
            // which is a completely different mechanism (a synchronous
            // trap, not a context restore) than what this trait's
            // context_switch model provides. Same declined-Monitor
            // outcome as x86_64, for an architecturally different
            // reason than ARM64's "we choose not to" — here it is
            // genuinely "the mechanism this trait models does not
            // apply".
            PrivilegeLevel::Monitor => Err(HalError::UnsupportedPrivilegeLevel),
            // Same reasoning as the other two architectures:
            // Kernel/User is encoded in the target context's sstatus
            // field (Riscv64Context::sstatus, specifically the SPP —
            // Supervisor Previous Privilege — bit), applied only as
            // part of context_switch's restore path via `sret`, never
            // as a standalone operation.
            PrivilegeLevel::Kernel | PrivilegeLevel::User => Ok(()),
        }
    }

    fn bootstrap_current_core(&self) -> Result<(), HalError> {
        // SAFETY: called once per hart, before any trap (interrupt or
        // exception) can be taken on this hart — boot.S never enables
        // interrupts (sstatus.SIE stays clear from SBI's S-mode entry
        // state through this point).
        unsafe {
            load_stvec();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_feature_flags_always_reports_rv64gc_baseline() {
        let flags = detect_feature_flags();
        assert!(flags.contains(CpuFeatureFlags::WIDE_ATOMICS));
        assert!(flags.contains(CpuFeatureFlags::PERF_COUNTERS));
    }

    #[test]
    fn riscv64_context_matches_declared_size() {
        assert_eq!(size_of::<Riscv64Context>(), RISCV64_CONTEXT_BYTES);
    }

    #[test]
    fn scause_top_bit_distinguishes_interrupt_from_exception() {
        let interrupt_scause: usize = 1 << (usize::BITS - 1) | 5; // e.g. timer interrupt
        let exception_scause: usize = 12; // e.g. instruction page fault

        assert!((interrupt_scause as isize) < 0);
        assert!((exception_scause as isize) >= 0);
    }

    #[test]
    fn cause_code_masks_out_interrupt_bit() {
        let scause: usize = (1 << (usize::BITS - 1)) | 5;
        let cause_code = scause & !(1 << (usize::BITS - 1));
        assert_eq!(cause_code, 5);
    }
}
// ============================================================================
// Sv39 page-table helpers
//
// Bare-metal only. `map_ram_identity` / `activate_address_space` (above) plus
// `map_range` here are the whole page-table surface the microkernel drives
// through `hal_core::HalInterface`. Sv39 (RISC-V privileged spec section 4.4):
// three 9-bit VPN levels, 4 KiB pages, 2 MiB / 1 GiB superpages when the leaf
// sits at level 1 / level 0.
// ============================================================================
#[cfg(target_os = "none")]
pub(crate) mod riscv_sv39 {
    /// PTE valid bit.
    pub const V: u64 = 1 << 0;
    /// PTE readable bit.
    pub const R: u64 = 1 << 1;
    /// PTE writable bit.
    pub const W: u64 = 1 << 2;
    /// PTE executable bit.
    pub const X: u64 = 1 << 3;
    /// PTE user-accessible bit.
    pub const U: u64 = 1 << 4;
    /// PTE accessed bit (pre-set so no hardware A/D fault is taken).
    pub const A: u64 = 1 << 6;
    /// PTE dirty bit (pre-set — see `A`).
    pub const D: u64 = 1 << 7;

    /// Maps `[vaddr, vaddr + len)` -> `[paddr, ...)` at 4 KiB granularity in
    /// the Sv39 table rooted at `root_frame`, allocating any missing L1 / L0
    /// tables from the pre-zeroed frame pool at `[pool_base, pool_base +
    /// pool_len * 4096)`. `perm_bits` is `R=1 | W=2 | X=4 | U=8`.
    ///
    /// Returns the number of pool frames consumed, or `u32::MAX` on error
    /// (misaligned args, a superpage leaf already covering the range, or the
    /// pool running out).
    ///
    /// # Preconditions
    /// Paging is off (`satp == 0`) so every physical address here is directly
    /// addressable; the pool frames are zeroed; single core.
    pub fn map_range(
        root_frame: usize,
        vaddr: usize,
        paddr: usize,
        len: usize,
        perm_bits: usize,
        pool_base: usize,
        pool_len: usize,
    ) -> u32 {
        if root_frame == 0 || len == 0 || ((vaddr | paddr | len) & 0xFFF) != 0 {
            return u32::MAX;
        }
        let leaf = V | A | D
            | if perm_bits & 1 != 0 { R } else { 0 }
            | if perm_bits & 2 != 0 { W } else { 0 }
            | if perm_bits & 4 != 0 { X } else { 0 }
            | if perm_bits & 8 != 0 { U } else { 0 };

        let mut used = 0usize;
        let pages = len / 4096;
        for p in 0..pages {
            let va = vaddr + p * 4096;
            let pa = paddr + p * 4096;
            let (vpn2, vpn1, vpn0) = ((va >> 30) & 0x1FF, (va >> 21) & 0x1FF, (va >> 12) & 0x1FF);

            // Descend / build L1.
            // SAFETY: precondition — `root_frame` points at a writable,
            // page-aligned frame; paging is off.
            let l1 = unsafe {
                let slot = (root_frame as *mut u64).add(vpn2);
                let e = slot.read_volatile();
                if e & V == 0 {
                    if used >= pool_len {
                        return u32::MAX;
                    }
                    let t = pool_base + used * 4096;
                    used += 1;
                    slot.write_volatile(((t as u64 >> 12) << 10) | V);
                    t
                } else if e & (R | W | X) != 0 {
                    return u32::MAX; // a 1 GiB leaf already covers this VA
                } else {
                    (((e >> 10) & ((1 << 44) - 1)) << 12) as usize
                }
            };

            // Descend / build L0.
            // SAFETY: `l1` is a valid page-table frame just resolved above.
            let l0 = unsafe {
                let slot = (l1 as *mut u64).add(vpn1);
                let e = slot.read_volatile();
                if e & V == 0 {
                    if used >= pool_len {
                        return u32::MAX;
                    }
                    let t = pool_base + used * 4096;
                    used += 1;
                    slot.write_volatile(((t as u64 >> 12) << 10) | V);
                    t
                } else if e & (R | W | X) != 0 {
                    return u32::MAX; // a 2 MiB leaf already covers this VA
                } else {
                    (((e >> 10) & ((1 << 44) - 1)) << 12) as usize
                }
            };

            // Install the 4 KiB leaf.
            // SAFETY: `l0` is a valid page-table frame just resolved above.
            unsafe {
                (l0 as *mut u64)
                    .add(vpn0)
                    .write_volatile(((pa as u64 >> 12) << 10) | leaf);
            }
        }
        used as u32
    }
}
