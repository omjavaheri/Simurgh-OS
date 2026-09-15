//! ============================================================================
//! subsystem_entry.rs — riscv64 / x86_64 / aarch64
//!
//! Note on this file's ONE architecture-conditional piece: same narrow,
//! documented exception `mm_service::subsystem_entry`'s own file header
//! explains — `raw_syscall`/`raw_syscall2`'s job is issuing the raw
//! syscall INSTRUCTION itself (`ecall`/`int 0x80`/`svc #0`), an
//! unavoidable ISA detail. Every other line in this file is
//! architecture-generic.
//!
//! Purpose: log-collector-native's real process entry point. Serves the
//! real [`crate::log_wire`] protocol over the real `SyscallOp::Call/
//! Recv/Reply` mechanism (02-Microkernel-Layer.md §5.3/§8.3) — the SAME
//! real-IPC-server shape `fs_native`/`compositor`/`mm_service` already
//! established.
//!
//! Architecture reference: 04-System-Services-Policy-Layer-v2.md §2.2.
//!
//! Position in the system: `kernel_arch_glue::log_collector_demo_start`
//! spawns this process via `spawn_process_from_elf` — its own isolated
//! address space and capability space, granted exactly one capability
//! (an `Endpoint`, landing at slot 0) plus ONE fixed VA pre-mapped
//! directly (trusted bootstrap, no `Map` ceremony): [`SHARED_VA`], the
//! `SmallMessage` marshaling page PLUS its own bulk region
//! ([`crate::log_wire::BULK_OFFSET`] bytes into the SAME page — this
//! protocol's bulk payload, unlike `mm_service`'s, does not fit in one
//! `SmallMessage`'s own 6 words, same reasoning `fs_native`/`compositor`
//! already give for their own bulk regions).
//!
//! Safety/invariants: unlike `device-manager::subsystem_entry` (whose
//! `#[link_section = ".user_text"]` code shares a binary with kernel
//! `.text`), this file compiles into `log-collector-native-bin`'s OWN
//! fully separate ELF image — every byte of it is `U=1`, so ordinary
//! function calls (into `alloc`, `crate::EventQueue`) are completely
//! safe here.
//! ============================================================================

use crate::log_wire::{self, LcRequest};
use crate::EventQueue;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_RECV`.
const IPC_RECV: usize = 43;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`.
const IPC_REPLY: usize = 44;

/// This process's own capability slot for the Endpoint — `kernel_arch_
/// glue::log_collector_demo_start`'s own first (and only) grant into
/// this process's fresh, otherwise-empty capability space, so it
/// deterministically lands at slot 0 (same reasoning every other
/// subsystem's own `*_ENDPOINT_CAP` constant doc comment already gives).
const LC_ENDPOINT_CAP: usize = 0;

/// VA the shared message+bulk page is mapped at in THIS process's own
/// address space — must stay numerically equal to `kernel_arch_glue::
/// LOG_COLLECTOR_SHARED_VA`, and matches `simurgh-diagnostics::
/// diagnostics-manager::subsystem_entry::LC_SHARED_VA`'s own
/// already-fixed value (that repo's own client code chose it before
/// this server existed — this side simply confirms it, same convention
/// `log_wire`'s own module doc comment already establishes for the wire
/// bytes themselves).
const SHARED_VA: usize = 0xD940_0000;

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
    unreachable!("log-collector-native's subsystem_main never runs on a host build")
}

/// Host-build stand-in — see `raw_syscall`'s own identical stand-in doc
/// comment.
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall2(_a7: usize, _a0: usize, _a1: usize) -> (usize, usize) {
    unreachable!("log-collector-native's subsystem_main never runs on a host build")
}

/// Reads the `SmallMessage` HEADER the caller wrote into the shared
/// page's own `0..56` bytes — same fixed layout every other real-IPC
/// server in this project uses.
fn read_shared_message() -> kernel_ipc::SmallMessage {
    let base = SHARED_VA as *const u64;
    // SAFETY: `SHARED_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::log_collector_demo_start`,
    // before this process is ever scheduled.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        kernel_ipc::SmallMessage::from_words(label, &words).unwrap_or(kernel_ipc::SmallMessage::new(label))
    }
}

/// Writes `msg` into the shared message page for the caller to read back
/// after `IPC_REPLY` wakes it — same fixed layout as
/// [`read_shared_message`].
fn write_shared_message(msg: &kernel_ipc::SmallMessage) {
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

/// Reads the bulk region (`ReportEvent`'s own real payload — the caller
/// already wrote it there before issuing the `Call`) as one opaque
/// [`log_wire::EventBlob`].
fn read_bulk() -> log_wire::EventBlob {
    let base = (SHARED_VA + log_wire::BULK_OFFSET) as *const u8;
    let mut blob = [0u8; log_wire::BULK_TOTAL_SIZE];
    // SAFETY: same page/contract as `read_shared_message`; `BULK_OFFSET`
    // + `BULK_TOTAL_SIZE` stays well inside the one real 4096-byte page
    // this process is granted (64 + 320 = 384 < 4096).
    unsafe {
        core::ptr::copy_nonoverlapping(base, blob.as_mut_ptr(), log_wire::BULK_TOTAL_SIZE);
    }
    blob
}

/// Writes `blob` into the bulk region — `NextEvent`'s own real payload,
/// for the caller to read back after `IPC_REPLY` wakes it.
fn write_bulk(blob: &log_wire::EventBlob) {
    let base = (SHARED_VA + log_wire::BULK_OFFSET) as *mut u8;
    // SAFETY: same contract as `read_bulk`.
    unsafe {
        core::ptr::copy_nonoverlapping(blob.as_ptr(), base, log_wire::BULK_TOTAL_SIZE);
    }
}

/// Handles one real request against `queue`, driving the REAL, bounded
/// FIFO [`EventQueue`] this process owns for its own lifetime.
fn handle_request(queue: &mut EventQueue, req: LcRequest) -> kernel_ipc::SmallMessage {
    match req {
        LcRequest::NextEvent => match queue.pop() {
            Some(blob) => {
                write_bulk(&blob);
                log_wire::encode_event_response()
            }
            None => log_wire::encode_none_response(),
        },
        LcRequest::ReportEvent => {
            queue.push(read_bulk());
            log_wire::encode_ack_response()
        }
    }
}

/// log-collector-native's own entry point. Serves real requests forever:
/// `Recv` (blocks until a real `Call` arrives), decode, dispatch against
/// the real [`EventQueue`], encode, `Reply` (always switches away on
/// success — see `Reply`'s own doc comment in `kernel_core::syscall`).
/// A malformed/unrecognized request (`log_wire::decode_request` returns
/// `None`) replies `NoEvent` — this project's "tolerant of a bad peer,
/// never panic" convention every other real IPC server here already
/// follows (`mm_service::subsystem_entry::subsystem_main`'s own
/// `MmResponse::Error` fallback is the identical precedent, just with a
/// differently-shaped error reply since this protocol has none of its
/// own).
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut queue = EventQueue::new();

    // Same real, QEMU-found stack-slot-reuse miscompilation every other
    // real IPC server's own identical loop hits (full investigation in
    // `fs_native::subsystem_entry::subsystem_main`'s own doc comment) —
    // the same defense-in-depth every other subsystem's own entry point
    // already applies.
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
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, LC_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match log_wire::decode_request(&req_msg) {
            Some(req) => handle_request(&mut queue, req),
            None => log_wire::encode_none_response(),
        };
        write_shared_message(&resp);
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success (see its own doc comment) — the loop
        // continues here only on the (unreachable in practice) error
        // case, matching every other subsystem's own identical loop.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}
