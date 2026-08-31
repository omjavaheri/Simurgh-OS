//! ============================================================================
//! subsystem_entry.rs — riscv64 / x86_64 / aarch64
//!
//! Note on this file's ONE architecture-conditional piece: same narrow,
//! documented exception `device-manager::subsystem_entry`'s and
//! `fs-native::subsystem_entry`'s own file headers explain —
//! `raw_syscall`/`raw_syscall2`'s job is issuing the raw syscall
//! INSTRUCTION itself (`ecall`/`int 0x80`/`svc #0`), an unavoidable ISA
//! detail. Every other line in this file is architecture-generic.
//!
//! Purpose: the virtio-blk driver's real process entry point. Serves
//! `ipc_protocol::{DriverRequest,DriverResponse}` over the real
//! `SyscallOp::Call/Recv/Reply` mechanism, driving a genuine
//! `driver_virtio_blk::VirtioBlk` against real, mapped virtio-mmio
//! hardware — mirroring `fs-native::subsystem_entry`'s own IPC-serving
//! shape exactly, but with `VirtioBlk` in place of `MemFs`.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (driver
//! process model), §5.1 (virtio-blk on QEMU is the named acceptance
//! device).
//!
//! Position in the system: `kernel_arch_glue::spawn_virtio_blk_driver`
//! spawns this process via `spawn_process_from_elf` — its own isolated
//! address space and capability space. It is granted exactly one
//! capability (an `Endpoint`, landing at slot 0 — see
//! `kernel_arch_glue::grant_cap_into`'s own doc comment for why that
//! slot number is deterministic) and has two regions pre-mapped directly
//! into its address space before its first instruction ever runs: the
//! virtio-mmio transport window (`DRV_MMIO_VA`) and its virtqueue/data
//! `SharedRegion` (`DRV_QUEUE_VA`) — see `driver_virtio_blk::layout`'s
//! own doc comment for the byte layout inside the latter, including the
//! `DriverRequest`/`DriverResponse` `SmallMessage` marshaling area this
//! file's own `read_shared_message`/`write_shared_message` use (reusing
//! the SAME region rather than requesting a third capability grant).
//!
//! Safety/invariants: unlike `device-manager::subsystem_entry` (whose
//! `#[link_section = ".user_text"]` code shares a binary with kernel
//! `.text`), this file compiles into `driver-virtio-blk-bin`'s OWN fully
//! separate ELF image — every byte of it is `U=1`, so ordinary function
//! calls are completely safe here. No `#[link_section]`/
//! `#[inline(always)]` discipline is needed for that reason.
//! ============================================================================

use driver_framework::DeviceDriver;
use ipc_protocol::codec::{decode_driver_request, encode_driver_response};
use ipc_protocol::driver::DriverErrorCode;
use ipc_protocol::{DriverRequest, DriverResponse};
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_RECV`.
const IPC_RECV: usize = 43;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`.
const IPC_REPLY: usize = 44;
/// Must stay numerically equal to `kernel/src/main.rs`'s
/// `sys::DRV_IRQ_WAIT` — the real interrupt-driven wait for a
/// just-submitted request to complete (see this file's own
/// `handle_io`).
const DRV_IRQ_WAIT: usize = 63;

/// The endpoint capability's slot in THIS process's own capability
/// space — see `fs-native::subsystem_entry::FS_ENDPOINT_CAP`'s own doc
/// comment on why this is a compile-time constant, not a runtime lookup.
const DRV_ENDPOINT_CAP: usize = 0;

/// The `Notification` capability's slot in THIS process's own
/// capability space — the SECOND grant `kernel_arch_glue::spawn_
/// virtio_blk_driver` makes into this process's fresh cap space (the
/// endpoint above is the first, at slot 0), already bound to the
/// device's own IRQ line via `IrqBind` before this process's first
/// instruction ever runs.
const DRV_NOTIF_CAP: usize = 1;

/// VA the virtio-mmio transport window is mapped at in THIS process's
/// own address space — must stay numerically equal to
/// `kernel_arch_glue::DRV_MMIO_VA`.
const DRV_MMIO_VA: usize = 0xD820_0000;

/// VA the virtqueue/data `SharedRegion` is mapped at in THIS process's
/// own address space — must stay numerically equal to
/// `kernel_arch_glue::DRV_QUEUE_VA`. See `driver_virtio_blk::layout`'s
/// own doc comment for the byte layout inside it, including the
/// `MESSAGE_OFFSET` this file's own `read_shared_message`/
/// `write_shared_message` use.
const DRV_QUEUE_VA: usize = 0xD830_0000;

/// # Safety
/// `ecall` from U-mode traps to the kernel's S-mode handler, which
/// preserves every register except `a0`. `#[inline(never)]`: the same
/// real, QEMU-found LLVM-codegen bug `fs-native::subsystem_entry::
/// raw_syscall`'s own doc comment documents in full.
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

/// See `fs-native::subsystem_entry::raw_syscall2`'s own doc comment.
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

/// See `fs-native::subsystem_entry::raw_syscall2`'s own doc comment.
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

/// See `fs-native::subsystem_entry::raw_syscall2`'s own doc comment.
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

/// Reads the `DriverRequest` `SmallMessage` the caller wrote at
/// `DRV_QUEUE_VA + crate::layout::MESSAGE_OFFSET` — same
/// fixed 56-byte layout `kernel_arch_glue`'s own `write_shared_drv_
/// message` uses on the other side.
fn read_shared_message() -> SmallMessage {
    let base = (DRV_QUEUE_VA + crate::layout::MESSAGE_OFFSET) as *const u64;
    // SAFETY: `DRV_QUEUE_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::spawn_virtio_blk_driver`,
    // before this process is ever scheduled.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// Writes `msg` into the shared message area for the caller to read
/// back after `IPC_REPLY` wakes it — same fixed layout as
/// `read_shared_message`.
fn write_shared_message(msg: &SmallMessage) {
    let base = (DRV_QUEUE_VA + crate::layout::MESSAGE_OFFSET) as *mut u64;
    // SAFETY: same contract as `read_shared_message`.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

// Same stack-slot-reuse miscompilation `fs-native::subsystem_entry`'s
// own `zero!()` macro documents in full (this crate's own `[profile.
// dev.package.driver-virtio-blk] opt-level = 2` override — Cargo.toml
// — already fixes a CONFIRMED instance of it in `VirtioBlk::wait_for_
// completion`'s bounded loop; `zero!()` is kept here too, at every
// `raw_syscall`/`raw_syscall2` call site, as the same defense-in-depth
// every other subsystem's own entry point already applies for exactly
// this class of bug). Module-scope (not `subsystem_main`-local) so
// `handle_io` below can use it too. Every call site is already inside
// an `unsafe` block (the enclosing `raw_syscall`/`raw_syscall2` call),
// so — matching `fs-native::subsystem_entry`'s own `zero!()` exactly —
// this macro does NOT wrap its own `asm!` in a redundant nested
// `unsafe` block.
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

/// Real interrupt-driven wait for a just-submitted request to complete
/// — issues `DRV_IRQ_WAIT` (`SyscallOp::Wait` on the `Notification`
/// this process's own `IrqBind` capability grant already bound to the
/// device's IRQ line). The kernel side (`kernel/src/main.rs`'s own
/// riscv64 `DRV_IRQ_WAIT` dispatch arm) genuinely idles the core
/// (`hal_riscv64::cpu::wfi`) until the interrupt fires, so THIS single
/// ecall only ever returns once completion is real — no polling loop
/// needed here, unlike `VirtioBlk::wait_for_completion`'s own busy-poll
/// alternative.
///
/// `#[inline(never)]` — same rationale as `raw_syscall`'s own doc
/// comment.
#[inline(never)]
unsafe fn wait_for_irq() -> u64 {
    // SAFETY: `raw_syscall`'s own contract; the return value here is a
    // plain `usize` (the notification's signal bits) — `raw_syscall`'s
    // own `usize` return type already covers the one bit this driver
    // ever sets (`virtio_blk_irq_trampoline` signals `1`).
    unsafe { raw_syscall(DRV_IRQ_WAIT, DRV_NOTIF_CAP, zero!()) as u64 }
}

/// Drives one real `ReadBlocks`/`WriteBlocks` request through the
/// REAL interrupt-driven completion path — `drv.handle_request` is
/// deliberately NOT called for these two request kinds (see this
/// crate's own module doc comment on why: only this file can issue
/// the actual `Wait` ecall in between submission and completion, so
/// the orchestration has to live here, not inside `VirtioBlk` itself).
/// Reuses `VirtioBlk::validate_io`'s own bounds-checking (the SAME
/// logic `handle_request`'s own arms apply) so the two paths never
/// drift apart on what counts as a valid request.
fn handle_io(drv: &mut crate::VirtioBlk, kind: crate::BlkReqType, lba: u64, sector_count: u32) -> DriverResponse {
    if !drv.is_ready() {
        return DriverResponse::Failed { code: DriverErrorCode::ProbeFailed };
    }
    if let Err(code) = drv.validate_io(sector_count, lba) {
        return DriverResponse::Failed { code };
    }
    // SAFETY: `drv.is_ready()` (checked above) means `probe` already
    // mapped both regions — `submit_request`'s own contract.
    unsafe { drv.submit_request(kind, lba, crate::VirtioBlk::SECTOR_SIZE as usize) };
    // SAFETY: `raw_syscall`'s own contract (forwarded via `wait_for_irq`).
    unsafe { wait_for_irq() };
    // SAFETY: same contract as `submit_request` — the real interrupt
    // already fired (`wait_for_irq` only returns once it has), so a
    // completion is genuinely ready to read.
    let status = unsafe { drv.ack_completion() };
    if status == 0 {
        DriverResponse::Completed { sectors: 1 }
    } else {
        DriverResponse::Failed { code: DriverErrorCode::DeviceIo }
    }
}

/// The virtio-blk driver's process entry point. Runs `probe()` exactly
/// once (`DeviceDriver::probe`'s own doc comment: "Called once, right
/// after the process starts") against the real, pre-mapped virtio-mmio
/// window, then serves REAL `DriverRequest`s forever: `Recv` (blocks
/// until a real `Call` arrives), decode, dispatch to the real
/// `VirtioBlk` (`ReadBlocks`/`WriteBlocks` via `handle_io`'s own real
/// interrupt-driven path, everything else via `handle_request`
/// directly), encode, `Reply`.
///
/// If `probe()` fails (e.g. no Block device was actually discovered at
/// boot — `kernel_arch_glue::spawn_virtio_blk_driver`'s own doc comment
/// on when it declines to spawn this process at all covers the more
/// common "never even reaches here" case), every request this process
/// ever receives is answered `Failed { code: ProbeFailed }` — the
/// process still runs and answers IPC (so a client waiting on `Call`
/// never hangs), it simply never becomes ready.
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut drv = crate::VirtioBlk::new(DRV_MMIO_VA, DRV_QUEUE_VA);
    let _ = drv.probe();

    loop {
        // SAFETY: `raw_syscall2`'s own contract.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, DRV_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_driver_request(&req_msg) {
            Ok(DriverRequest::ReadBlocks { lba, sector_count, .. }) => {
                handle_io(&mut drv, crate::BlkReqType::In, lba, sector_count)
            }
            Ok(DriverRequest::WriteBlocks { lba, sector_count, .. }) => {
                handle_io(&mut drv, crate::BlkReqType::Out, lba, sector_count)
            }
            Ok(req) => drv.handle_request(req),
            Err(_) => DriverResponse::Failed {
                code: DriverErrorCode::Unsupported,
            },
        };
        write_shared_message(&encode_driver_response(&resp));
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success (see its own doc comment in
        // `kernel_core::syscall::SyscallOp::Reply`) — the loop continues
        // here only on the (unreachable in practice) error case.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}
