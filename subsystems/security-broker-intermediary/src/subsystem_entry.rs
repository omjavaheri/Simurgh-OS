//! ============================================================================
//! subsystem_entry.rs — riscv64 / x86_64 / aarch64
//!
//! Note on this file's ONE architecture-conditional piece: same narrow,
//! documented exception `fs_native::subsystem_entry`'s own file header
//! explains — `raw_syscall`/`raw_syscall2`'s job is issuing the raw
//! syscall INSTRUCTION itself (`ecall`/`int 0x80`/`svc #0`), an
//! unavoidable ISA detail. Every other line in this file is
//! architecture-generic.
//!
//! Purpose: the intermediary's real process entry point. Serves the REAL
//! `ipc_protocol::security::{SecurityRequest, SecurityResponse}` wire
//! protocol over the REAL `SyscallOp::Call/Recv/Reply` mechanism, and —
//! the entire point of Issue #28 — issues the REAL `SyscallOp::CapGrant`/
//! `CapRevoke` syscalls itself (via the raw `CAP_GRANT`/`CAP_REVOKE`
//! opcodes `kernel/src/main.rs` newly exposes, see that file's own `mod
//! sys` doc comments) on the Security Broker's behalf.
//!
//! Architecture reference: `ipc-protocol/src/security.rs`;
//! `kernel_arch_glue::cap_grant`/`cap_revoke`'s own doc comments (why this
//! is the first — and by design the ONLY — U-mode process meant to issue
//! those syscalls).
//!
//! Position in the system: `kernel_arch_glue::
//! security_broker_intermediary_demo_start` spawns this process via
//! `spawn_process_from_elf` — its own isolated address space and
//! capability space, granted exactly THREE capabilities at fixed,
//! deterministic slots (see that function's own doc comment for why each
//! slot number is guaranteed):
//! - slot 0 (`SBI_ENDPOINT_CAP`): this process's own `Endpoint`.
//! - slot 1 (`SBI_TARGET_SECURITY_BROKER_CAP`): a `ThreadControlBlock`
//!   capability for the already-spawned `security-broker` process — the
//!   ONE destination this demo wires up
//!   (`security_broker_intermediary::Intermediary::register_target`'s own
//!   boot-time mapping, `target_service == 0`, resolves here).
//! - slot 2: a demo "resource" `Endpoint` — the `cap` a
//!   `SecurityRequest::CapGrant` names to copy, standing in for whatever
//!   real resource a real `MintSpec` would grant (out of this crate's
//!   scope).
//!
//! Plus one fixed VA, `SHARED_VA` (the small `SmallMessage` marshaling
//! page) — no bulk-data region needed (unlike `fs_native`/`compositor`):
//! `SecurityRequest`/`SecurityResponse` are plain integer fields that fit
//! entirely in one `SmallMessage`.
//!
//! Safety/invariants: unlike `device-manager::subsystem_entry` (whose
//! `#[link_section = ".user_text"]` code shares a binary with kernel
//! `.text`), this file compiles into `security-broker-intermediary-bin`'s
//! OWN fully separate ELF image — every byte of it is `U=1`, so ordinary
//! function calls (into `ipc_protocol::codec`, `alloc`) are completely
//! safe here.
//! ============================================================================

use crate::Intermediary;
use ipc_protocol::codec::{decode_security_request, encode_security_response};
use ipc_protocol::security::SecurityErrorCode;
use ipc_protocol::{SecurityRequest, SecurityResponse};
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_RECV`.
const IPC_RECV: usize = 43;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`.
const IPC_REPLY: usize = 44;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::CAP_GRANT`
/// — see that constant's own doc comment for the `a0`/`a1` packing this
/// file's own `issue_cap_grant` builds.
const CAP_GRANT: usize = 94;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::
/// CAP_REVOKE`.
const CAP_REVOKE: usize = 95;

/// This process's own capability slot for the Endpoint — `kernel_arch_
/// glue::security_broker_intermediary_demo_start`'s own first grant into
/// this process's fresh, otherwise-empty capability space, so it
/// deterministically lands at slot 0 (same reasoning every other
/// subsystem's own `*_ENDPOINT_CAP` constant doc comment already gives).
const SBI_ENDPOINT_CAP: usize = 0;

/// This process's own capability slot for security-broker's TCB
/// capability — the SECOND grant into this process's cap space (see this
/// file's own module doc comment).
const SECURITY_BROKER_TCB_CAP_SLOT: u32 = 1;

/// `target_service` value that resolves to `SECURITY_BROKER_TCB_CAP_SLOT`
/// — must stay numerically equal to `kernel_arch_glue::
/// SBI_TARGET_SECURITY_BROKER`.
const TARGET_SECURITY_BROKER: u32 = 0;

/// This process's own capability slot for mm-service's TCB capability —
/// the SECOND real target (Root Task's own `kernel_arch_glue::
/// security_broker_intermediary_demo_start` grants this only when
/// mm-service was already spawned by the time it runs; see that
/// function's own slot 4/5 doc comment) — proves `target_service`
/// resolution generalizes beyond the one `SECURITY_BROKER_TCB_CAP_SLOT`
/// case.
const MM_SERVICE_TCB_CAP_SLOT: u32 = 4;

/// `target_service` value that resolves to `MM_SERVICE_TCB_CAP_SLOT` —
/// must stay numerically equal to `kernel_arch_glue::
/// SBI_TARGET_MM_SERVICE`.
const TARGET_MM_SERVICE: u32 = 1;

/// VA the shared message page is mapped at in THIS process's own address
/// space — must stay numerically equal to `kernel_arch_glue::
/// SBI_SHARED_VA`.
const SHARED_VA: usize = 0xD8B0_0000;

/// # Safety
/// `ecall` from U-mode traps to the kernel's S-mode handler, which
/// preserves every register except `a0`. `#[inline(never)]` — see
/// `fs_native::subsystem_entry::raw_syscall`'s own doc comment for the
/// real, QEMU-found LLVM-codegen bug this works around.
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

/// See `fs_native::subsystem_entry::raw_syscall2`'s own doc comment.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
unsafe fn raw_syscall2(a7: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") a7,
            inlateout("a0") a0 => r0,
            inlateout("a1") a1 => r1,
            options(nostack),
        );
    }
    (r0, r1)
}

/// # Safety
/// `int 0x80` from Ring 3 traps to `hal_x86_64::cpu`'s dedicated DPL-3
/// gate, which preserves every register except `rax`/`rsi`.
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

/// See `fs_native::subsystem_entry::raw_syscall2`'s own doc comment.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
unsafe fn raw_syscall2(a7: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1): (usize, usize);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") a7 => r0,
            in("rdi") a0,
            inlateout("rsi") a1 => r1,
            options(nostack),
        );
    }
    (r0, r1)
}

/// # Safety
/// `svc #0` from EL0 traps to `hal_arm64::cpu`'s shared EL0-synchronous
/// vector, which preserves every register except `x0`/`x1`.
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

/// See `fs_native::subsystem_entry::raw_syscall2`'s own doc comment.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
unsafe fn raw_syscall2(a7: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1): (usize, usize);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") a7,
            inlateout("x0") a0 => r0,
            inlateout("x1") a1 => r1,
        );
    }
    (r0, r1)
}

/// Host-build stand-in — see `netstack::subsystem_entry`'s own identical
/// stand-in doc comment for why this is unreachable in practice.
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall(_a7: usize, _a0: usize, _a1: usize) -> usize {
    unreachable!("security-broker-intermediary's subsystem_main never runs on a host build")
}

/// Host-build stand-in — see `raw_syscall`'s own identical stand-in doc
/// comment.
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall2(_a7: usize, _a0: usize, _a1: usize) -> (usize, usize) {
    unreachable!("security-broker-intermediary's subsystem_main never runs on a host build")
}

/// Reads the `SmallMessage` the caller wrote into the shared message
/// page — same fixed layout `kernel_arch_glue::write_shared_sbi_message`
/// uses on the other side.
fn read_shared_message() -> SmallMessage {
    let base = SHARED_VA as *const u64;
    // SAFETY: `SHARED_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::
    // security_broker_intermediary_demo_start`, before this process is
    // ever scheduled.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// Writes `msg` into the shared message page for the caller to read back
/// after `IPC_REPLY` wakes it — same fixed layout as `read_shared_
/// message`.
fn write_shared_message(msg: &SmallMessage) {
    let base = SHARED_VA as *mut u64;
    // SAFETY: same contract as `read_shared_message`.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Issues the REAL `SyscallOp::CapGrant` (via the raw `CAP_GRANT` opcode)
/// for `cap` (a slot in THIS process's own capability space — the
/// resource named by the request) into `target_thread_slot` (also THIS
/// process's own space — a `ThreadControlBlock` capability naming the
/// destination), narrowed to `rights`. Packs `cap`/`rights` into one
/// register exactly as `kernel/src/main.rs`'s `sys::CAP_GRANT` doc
/// comment specifies. Returns the new slot in the destination's own cap
/// space, or `usize::MAX` on failure.
fn issue_cap_grant(target_thread_slot: u32, cap: u32, rights: u32) -> usize {
    let packed = cap as usize | ((rights as usize) << 32);
    // SAFETY: `raw_syscall`'s own contract; `CAP_GRANT`'s calling
    // convention (`kernel/src/main.rs`'s `mod sys` doc comment) is
    // exactly `(target_thread, cap | rights << 32)`.
    unsafe { raw_syscall(CAP_GRANT, target_thread_slot as usize, packed) }
}

/// Issues the REAL `SyscallOp::CapRevoke` (via the raw `CAP_REVOKE`
/// opcode) for `cap` (a slot in THIS process's own capability space).
/// Returns the number of slots freed, or `usize::MAX` on failure.
fn issue_cap_revoke(cap: u32) -> usize {
    // SAFETY: `raw_syscall`'s own contract.
    unsafe { raw_syscall(CAP_REVOKE, cap as usize, 0) }
}

/// Handles one REAL `SecurityRequest`, resolving `target_service`/`cap`
/// through `intermediary`'s own boot-time mapping and issuing the real
/// kernel syscall — see this file's own module doc comment for the full
/// rationale.
fn handle_request(intermediary: &Intermediary, req: SecurityRequest) -> SecurityResponse {
    match req {
        SecurityRequest::CapGrant { target_service, cap, rights } => {
            match intermediary.resolve_target(target_service) {
                Ok(target_thread_slot) => {
                    let dst = issue_cap_grant(target_thread_slot, cap, rights);
                    if dst == usize::MAX {
                        SecurityResponse::Error { code: SecurityErrorCode::KernelRejected }
                    } else {
                        SecurityResponse::Granted { dst: dst as u32 }
                    }
                }
                Err(_) => SecurityResponse::Error { code: SecurityErrorCode::UnknownService },
            }
        }
        SecurityRequest::CapRevoke { cap } => {
            let freed = issue_cap_revoke(cap);
            if freed == usize::MAX {
                SecurityResponse::Error { code: SecurityErrorCode::KernelRejected }
            } else {
                SecurityResponse::Revoked { freed: freed as u32 }
            }
        }
    }
}

/// The intermediary process's own entry point. Populates the boot-time
/// `target_service` mapping this demo wires up (see this file's own
/// module doc comment for why slot 1 is deterministic), then serves REAL
/// `SecurityRequest`s forever: `Recv` (blocks until a real `Call`
/// arrives), decode, resolve + issue the real syscall, encode, `Reply`
/// (always switches away on success — see `Reply`'s own doc comment in
/// `kernel_core::syscall`).
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut intermediary = Intermediary::new();
    intermediary.register_target(TARGET_SECURITY_BROKER, SECURITY_BROKER_TCB_CAP_SLOT);
    // Registered unconditionally: if `security_broker_intermediary_
    // demo_start` skipped slot 3/4 (mm-service was not spawned yet — its
    // own doc comment), `target_service == TARGET_MM_SERVICE` simply
    // resolves to a slot that was never actually granted a TCB
    // capability, and the real `CAP_GRANT` syscall fails with
    // `KernelRejected` (a bad-cap error), not a hang — the SAME honest
    // failure mode `resolve_target` already produces for any genuinely
    // unregistered `target_service`.
    intermediary.register_target(TARGET_MM_SERVICE, MM_SERVICE_TCB_CAP_SLOT);

    // Same stack-slot-reuse miscompilation `fs_native::subsystem_entry::
    // subsystem_main`'s own identical loop hits (full investigation in
    // that function's own doc comment) — the same defense-in-depth every
    // other subsystem's own entry point already applies.
    macro_rules! zero {
        () => {{
            let mut v: usize = 0;
            // SAFETY: a no-op asm block (`v` is read back unchanged) —
            // its only purpose is defeating the stack-slot-reuse
            // miscompilation above.
            core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
            v
        }};
    }

    loop {
        // SAFETY: `raw_syscall2`'s own contract.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, SBI_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_security_request(&req_msg) {
            Ok(req) => handle_request(&intermediary, req),
            Err(_) => SecurityResponse::Error {
                code: SecurityErrorCode::Unsupported,
            },
        };
        write_shared_message(&encode_security_response(&resp));
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success (see its own doc comment) — the loop
        // continues here only on the (unreachable in practice) error
        // case, matching every other subsystem's own identical loop.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}
