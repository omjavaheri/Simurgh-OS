//! ============================================================================
//! subsystem_entry.rs — riscv64 / x86_64 / aarch64
//!
//! Note on this file's ONE architecture-conditional piece: same narrow,
//! documented exception `compositor::subsystem_entry`'s own file header
//! explains — `raw_syscall`/`raw_syscall2`'s job is issuing the raw
//! syscall INSTRUCTION itself (`ecall`/`int 0x80`/`svc #0`), an
//! unavoidable ISA detail. Every other line in this file is
//! architecture-generic.
//!
//! Purpose: mm-service's real process entry point. Serves the REAL
//! `ipc_protocol::mm::{MmRequest,MmResponse}` wire protocol over the
//! REAL `SyscallOp::Call/Recv/Reply` mechanism (02-Microkernel-Layer.md
//! §5.3/§8.3), driving a genuine `mm_service::MemRegistry` — the SAME
//! real-IPC-server shape `fs_native`/`compositor` already established
//! (03-Kernel-Subsystems-Layer.md §2.5).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.5 (the OOM
//! victim-selection policy this MVP wire protocol covers — swap and CXL
//! unified-memory coordination are `// TODO(omid)` in `mm_service`'s own
//! doc comment, out of scope here too).
//!
//! Position in the system: `kernel_arch_glue::mm_demo_start` spawns this
//! process via `spawn_process_from_elf` — its own isolated address space
//! and capability space, granted exactly one capability (an `Endpoint`,
//! landing at slot 0) plus ONE fixed VA pre-mapped directly (trusted
//! bootstrap, no `Map` ceremony): `SHARED_VA`, the small `SmallMessage`
//! marshaling page. Unlike `fs_native`/`compositor`, this protocol never
//! needs a SECOND bulk-data `SharedRegion` — every `MmRequest`/
//! `MmResponse` field fits inside the message itself (§5.2's "zero-copy,
//! not the message" rule only applies to genuinely bulk data; a
//! thread id + a byte count is not that).
//!
//! Safety/invariants: unlike `device-manager::subsystem_entry` (whose
//! `#[link_section = ".user_text"]` code shares a binary with kernel
//! `.text`), this file compiles into `mm-service-bin`'s OWN fully
//! separate ELF image — every byte of it is `U=1`, so ordinary function
//! calls (into `ipc_protocol::codec`, `mm_service::MemRegistry`, `alloc`)
//! are completely safe here.
//! ============================================================================

use crate::{MemRegistry, ProcMemInfo, ReclaimClass as ServiceReclaimClass};
use ipc_protocol::codec::{decode_mm_request, encode_mm_response};
use ipc_protocol::mm::{MmErrorCode, ReclaimClass as WireReclaimClass};
use ipc_protocol::{MmRequest, MmResponse};
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_RECV`.
const IPC_RECV: usize = 43;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`.
const IPC_REPLY: usize = 44;

/// This process's own capability slot for the Endpoint — `kernel_arch_
/// glue::mm_demo_start`'s own first (and only) grant into this
/// process's fresh, otherwise-empty capability space, so it
/// deterministically lands at slot 0 (same reasoning every other
/// subsystem's own `*_ENDPOINT_CAP` constant doc comment already gives).
const MM_ENDPOINT_CAP: usize = 0;

/// VA the shared message page is mapped at in THIS process's own address
/// space — must stay numerically equal to `kernel_arch_glue::MM_SHARED_
/// VA`.
const SHARED_VA: usize = 0xD870_0000;

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
    unreachable!("mm-service's subsystem_main never runs on a host build")
}

/// Host-build stand-in — see `raw_syscall`'s own identical stand-in doc
/// comment.
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall2(_a7: usize, _a0: usize, _a1: usize) -> (usize, usize) {
    unreachable!("mm-service's subsystem_main never runs on a host build")
}

/// Reads the `SmallMessage` the caller wrote into the shared message
/// page — same fixed 56-byte layout `kernel_arch_glue::write_shared_mm_
/// message` uses on the other side.
fn read_shared_message() -> SmallMessage {
    let base = SHARED_VA as *const u64;
    // SAFETY: `SHARED_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::mm_demo_start`, before this
    // process is ever scheduled.
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

/// Wire `ReclaimClass` -> this crate's own `ReclaimClass` (`ipc_
/// protocol::mm`'s own doc comment on why the two stay separate types).
fn from_wire_class(c: WireReclaimClass) -> ServiceReclaimClass {
    match c {
        WireReclaimClass::Protected => ServiceReclaimClass::Protected,
        WireReclaimClass::Normal => ServiceReclaimClass::Normal,
        WireReclaimClass::Sacrificial => ServiceReclaimClass::Sacrificial,
    }
}

/// Handles one REAL `MmRequest`, driving a REAL `MemRegistry`.
fn handle_request(reg: &mut MemRegistry, req: MmRequest) -> MmResponse {
    match req {
        MmRequest::Register {
            thread,
            resident_bytes,
            class,
        } => {
            reg.upsert(ProcMemInfo {
                thread,
                resident_bytes,
                class: from_wire_class(class),
            });
            MmResponse::Registered
        }
        MmRequest::Unregister { thread } => {
            reg.remove(thread);
            MmResponse::Unregistered
        }
        MmRequest::QueryVictim => MmResponse::Victim {
            thread: reg.oom_victim().unwrap_or(u32::MAX),
        },
        MmRequest::QueryTotalResident => MmResponse::TotalResident {
            bytes: reg.total_resident(),
        },
    }
}

/// mm-service's own entry point. Serves REAL `MmRequest`s forever: `Recv`
/// (blocks until a real `Call` arrives), decode, dispatch to the real
/// `MemRegistry`, encode, `Reply` (always switches away on success — see
/// `Reply`'s own doc comment in `kernel_core::syscall`).
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut reg = MemRegistry::new();

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
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, MM_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_mm_request(&req_msg) {
            Ok(req) => handle_request(&mut reg, req),
            Err(_) => MmResponse::Error {
                code: MmErrorCode::Unsupported,
            },
        };
        write_shared_message(&encode_mm_response(&resp));
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success (see its own doc comment) — the loop
        // continues here only on the (unreachable in practice) error
        // case, matching every other subsystem's own identical loop.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}
