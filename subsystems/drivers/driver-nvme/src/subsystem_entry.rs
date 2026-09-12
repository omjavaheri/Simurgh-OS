//! ============================================================================
//! subsystem_entry.rs — x86_64 only
//!
//! Note on this file's ONE architecture-conditional piece: same narrow,
//! documented exception `driver_virtio_blk::subsystem_entry`'s own file
//! header explains — `raw_syscall`/`raw_syscall2`'s job is issuing the
//! raw syscall INSTRUCTION itself (`int 0x80`), an unavoidable ISA
//! detail. This crate is x86_64-only (`Cargo.toml`'s own doc comment),
//! so unlike `driver_virtio_blk::subsystem_entry`, there is no
//! riscv64/aarch64 variant to keep in sync — a host-build stand-in
//! (unreachable in practice) covers every other target the same way
//! `driver-i8042::subsystem_entry` already does.
//!
//! Purpose: the NVMe driver's real process entry point. Serves
//! `ipc_protocol::{DriverRequest,DriverResponse}` over the real
//! `SyscallOp::Call/Recv/Reply` mechanism, driving a genuine
//! `driver_nvme::Nvme` — mirrors `driver_virtio_blk::subsystem_entry`'s
//! own IPC-serving shape exactly, `Nvme` in place of `VirtioBlk`.
//!
//! Position in the system: `kernel_arch_glue::spawn_nvme_driver` spawns
//! this process via `spawn_process_from_elf`, grants it an `Endpoint` at
//! slot 0 (every other real driver's own "first grant into an empty cap
//! space" convention), and pre-maps a real BAR0 MMIO window plus five
//! page-sized `SharedRegion`s (admin SQ/CQ, I/O SQ/CQ, one shared
//! Identify/I/O data buffer) at the exact VAs below — see that
//! function's own doc comment for its real, honest scope: it spawns a
//! real process that runs its own real `probe()`, but nothing calls
//! into its `Endpoint` yet (no other real subsystem in this codebase
//! talks to an NVMe device today), so it simply idles in `subsystem_
//! main`'s own `Recv` loop once `probe()` returns.
//! ============================================================================

use driver_framework::DeviceDriver;
use ipc_protocol::codec::{decode_driver_request, encode_driver_response};
use ipc_protocol::driver::DriverErrorCode;
use ipc_protocol::DriverResponse;
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_RECV`.
const IPC_RECV: usize = 43;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`.
const IPC_REPLY: usize = 44;

/// This process's own capability slot for its `Endpoint` — the first
/// grant into a fresh, otherwise-empty cap space (every other real
/// driver's own `*_ENDPOINT_CAP = 0` convention).
const DRV_ENDPOINT_CAP: usize = 0;

/// VA the controller's own BAR0 register window would be mapped at —
/// see this file's own module doc comment on why this is a DESIGN
/// constant today, not yet backed by a real grant.
const DRV_NVME_BAR0_VA: usize = 0xD840_0000;
/// VA the admin submission queue page would be mapped at.
const DRV_NVME_ADMIN_SQ_VA: usize = 0xD841_0000;
/// VA the admin completion queue page would be mapped at.
const DRV_NVME_ADMIN_CQ_VA: usize = 0xD842_0000;
/// VA the I/O submission queue page would be mapped at.
const DRV_NVME_IO_SQ_VA: usize = 0xD843_0000;
/// VA the I/O completion queue page would be mapped at.
const DRV_NVME_IO_CQ_VA: usize = 0xD844_0000;
/// VA the shared Identify/I/O data buffer page would be mapped at.
const DRV_NVME_DATA_VA: usize = 0xD845_0000;
/// VA the `DriverRequest`/`DriverResponse` `SmallMessage` marshaling
/// page would be mapped at — a dedicated page (unlike `driver_virtio_
/// blk`, which reuses part of its one queue page): this driver's own
/// five regions above are each already a full page on their own, so
/// there is no "spare tail" to reuse the way a single combined virtqueue
/// page has.
const DRV_NVME_MSG_VA: usize = 0xD846_0000;

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

/// See `driver_virtio_blk::subsystem_entry::raw_syscall2`'s own doc
/// comment.
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

/// Host-build stand-in — see `driver-i8042::subsystem_entry::raw_
/// syscall`'s own identical stand-in doc comment for why this is
/// unreachable in practice (this crate is x86_64-only, `Cargo.toml`'s
/// own doc comment).
#[cfg(not(target_arch = "x86_64"))]
#[inline(never)]
unsafe fn raw_syscall(_a7: usize, _a0: usize, _a1: usize) -> usize {
    unreachable!("driver-nvme's subsystem_main never runs on a non-x86_64 build")
}

/// Host-build stand-in — see `raw_syscall`'s own identical stand-in doc
/// comment.
#[cfg(not(target_arch = "x86_64"))]
#[inline(never)]
unsafe fn raw_syscall2(_a7: usize, _a0: usize, _a1: usize) -> (usize, usize) {
    unreachable!("driver-nvme's subsystem_main never runs on a non-x86_64 build")
}

/// Reads the `DriverRequest` `SmallMessage` the caller wrote at
/// `DRV_NVME_MSG_VA`.
fn read_shared_message() -> SmallMessage {
    let base = DRV_NVME_MSG_VA as *const u64;
    // SAFETY: `DRV_NVME_MSG_VA` is expected to be mapped `U=1 R+W` in
    // this process's own address space before it is ever scheduled —
    // same contract every other real driver's own `read_shared_message`
    // already documents (this file's own module doc comment on the
    // not-yet-real spawn path).
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// Writes `msg` into the shared message page — same contract as
/// `read_shared_message`.
fn write_shared_message(msg: &SmallMessage) {
    let base = DRV_NVME_MSG_VA as *mut u64;
    // SAFETY: same contract as `read_shared_message`.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

// Same stack-slot-reuse miscompilation `driver_virtio_blk::subsystem_
// entry`'s own `zero!()` macro documents in full — kept here as the same
// defense-in-depth every other subsystem's own entry point already
// applies.
macro_rules! zero {
    () => {{
        let mut v: usize = 0;
        // SAFETY: a no-op asm block (`v` is read back unchanged) — its
        // only purpose is defeating the stack-slot-reuse miscompilation
        // above. Forwarded from the enclosing `unsafe` block at every
        // call site.
        core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
        v
    }};
}

/// The NVMe driver's process entry point. Runs `probe()` exactly once
/// against the (design-stage, not-yet-really-granted — this file's own
/// module doc comment) BAR0/queue regions, then serves REAL
/// `DriverRequest`s forever: `Recv`, decode, dispatch to the real
/// `Nvme`, encode, `Reply`.
///
/// If `probe()` fails (today, ALWAYS — no real capability grant exists
/// yet), every request this process ever receives is answered `Failed {
/// code: ProbeFailed }`, the same graceful "still answers IPC, never
/// hangs a caller" behavior `driver_virtio_blk::subsystem_entry::
/// subsystem_main`'s own doc comment describes for its own identical
/// case.
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut drv = driver_nvme_instance();
    let _ = drv.probe();

    loop {
        // SAFETY: `raw_syscall2`'s own contract.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, DRV_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_driver_request(&req_msg) {
            Ok(req) => drv.handle_request(req),
            Err(_) => DriverResponse::Failed {
                code: DriverErrorCode::Unsupported,
            },
        };
        write_shared_message(&encode_driver_response(&resp));
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success — the loop continues here only on
        // the (unreachable in practice) error case.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}

fn driver_nvme_instance() -> crate::Nvme {
    crate::Nvme::new(
        DRV_NVME_BAR0_VA,
        DRV_NVME_ADMIN_SQ_VA,
        DRV_NVME_ADMIN_CQ_VA,
        DRV_NVME_IO_SQ_VA,
        DRV_NVME_IO_CQ_VA,
        DRV_NVME_DATA_VA,
    )
}
