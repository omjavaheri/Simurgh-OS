//! ============================================================================
//! subsystem_entry.rs — riscv64 / aarch64 / x86_64
//!
//! Note on this file's ONE architecture-conditional piece: same narrow,
//! documented exception `driver-virtio-blk::subsystem_entry`'s own file
//! header explains — `raw_syscall`/`raw_syscall2`'s job is issuing the raw
//! syscall INSTRUCTION itself (`ecall`/`svc #0`/`int 0x80`), an unavoidable
//! ISA detail. Every other line in this file is architecture-generic.
//!
//! Purpose: the virtio-net driver's real process entry point. Serves
//! `ipc_protocol::{DriverRequest,DriverResponse}` over the real
//! `SyscallOp::Call/Recv/Reply` mechanism, driving a genuine `driver_
//! virtio_net::VirtioNet` against real, mapped virtio hardware (either
//! transport — `new_driver_for_this_transport`'s own doc comment) —
//! mirroring `driver-virtio-blk::subsystem_entry`'s own IPC-serving shape,
//! but `SendFrame`/`PollFrame` in place of `ReadBlocks`/`WriteBlocks`
//! (both driven directly here rather than through `VirtioNet::handle_
//! request`, same split rationale: only this file knows the REAL frame
//! length/bytes already staged in the shared region by the caller).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (driver
//! process model), §2.3/§5.4 (virtio-net on QEMU is the Netstack ICMP
//! echo MVP's acceptance device).
//!
//! Position in the system: `kernel_arch_glue::spawn_virtio_net_driver`
//! spawns this process via `spawn_process_from_elf` — its own isolated
//! address space and capability space. It is granted exactly one
//! capability (an `Endpoint`, landing at slot 0) and has regions pre-
//! mapped directly into its address space before its first instruction
//! ever runs: for `Transport::Mmio` (riscv64), the virtio-mmio transport
//! window (`DRV_MMIO_VA`); for `Transport::Pci` (aarch64/x86_64), nothing
//! at that VA at all — the PCI capability windows are resolved instead
//! into the RX region's own `layout::PCI_INFO_OFFSET` header block. Both
//! transports ALSO get the RX queue's own `SharedRegion` (`DRV_RX_VA` —
//! ALSO carries the negotiated MAC, the PCI info block, and the
//! `DriverRequest`/`DriverResponse` marshaling area, see `driver_virtio_
//! net::layout`'s own doc comment) and the TX queue's own `SharedRegion`
//! (`DRV_TX_VA`).
//!
//! Safety/invariants: unlike `device-manager::subsystem_entry`, this file
//! compiles into `driver-virtio-net-bin`'s OWN fully separate ELF image —
//! every byte of it is `U=1`, so ordinary function calls are completely
//! safe here. No `#[link_section]`/`#[inline(always)]` discipline is
//! needed for that reason.
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

/// The endpoint capability's slot in THIS process's own capability
/// space — see `fs-native::subsystem_entry::FS_ENDPOINT_CAP`'s own doc
/// comment on why this is a compile-time constant, not a runtime lookup.
const DRV_ENDPOINT_CAP: usize = 0;

/// VA the virtio-mmio transport window is mapped at in THIS process's own
/// address space — must stay numerically equal to `kernel_arch_glue::
/// DRV_NET_MMIO_VA`.
const DRV_MMIO_VA: usize = 0xD840_0000;
/// VA the RX queue's own `SharedRegion` is mapped at — must stay
/// numerically equal to `kernel_arch_glue::DRV_NET_RX_VA`. Also carries
/// the message-marshaling area (`driver_virtio_net::layout::
/// MESSAGE_OFFSET`) this file's own `read_shared_message`/`write_shared_
/// message` use.
const DRV_RX_VA: usize = 0xD850_0000;
/// VA the TX queue's own `SharedRegion` is mapped at — must stay
/// numerically equal to `kernel_arch_glue::DRV_NET_TX_VA`.
const DRV_TX_VA: usize = 0xD860_0000;

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

/// Host-build stand-in (none of the three `#[cfg(target_arch = ...)]`
/// blocks above match a non-`{riscv64,x86_64,aarch64}` host, which is
/// never the case for this project's own CI/dev hosts today, but kept for
/// forward-compatibility, matching `driver-virtio-blk::subsystem_entry`'s
/// own identical stand-in). `subsystem_main` is never called from a host
/// test (there is no live kernel to `ecall` into), so this body is
/// unreachable in practice.
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall(_a7: usize, _a0: usize, _a1: usize) -> usize {
    unreachable!("driver-virtio-net's subsystem_main never runs on a host build")
}

/// See `raw_syscall`'s own doc comment (host-build stand-in).
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall2(_a7: usize, _a0: usize, _a1: usize) -> (usize, usize) {
    unreachable!("driver-virtio-net's subsystem_main never runs on a host build")
}

/// Reads the `DriverRequest` `SmallMessage` the caller wrote at
/// `DRV_RX_VA + driver_virtio_net::layout::MESSAGE_OFFSET` — same fixed
/// 56-byte layout `kernel_arch_glue`'s own `write_shared_net_message`
/// uses on the other side.
fn read_shared_message() -> SmallMessage {
    let base = (DRV_RX_VA + crate::layout::MESSAGE_OFFSET) as *const u64;
    // SAFETY: `DRV_RX_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::spawn_virtio_net_driver`,
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

/// Writes `msg` into the shared message area for the caller to read back
/// after `IPC_REPLY` wakes it — same fixed layout as `read_shared_
/// message`.
fn write_shared_message(msg: &SmallMessage) {
    let base = (DRV_RX_VA + crate::layout::MESSAGE_OFFSET) as *mut u64;
    // SAFETY: same contract as `read_shared_message`.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

// Same stack-slot-reuse miscompilation `fs-native::subsystem_entry`'s own
// `zero!()` macro documents in full — kept here too, at every `raw_
// syscall`/`raw_syscall2` call site, as the same defense-in-depth every
// other subsystem's own entry point already applies.
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

/// Handles a `SendFrame { len }` request: the frame bytes are ALREADY
/// staged (by `kernel_arch_glue`'s own demo, before issuing the `Call`)
/// at `DRV_TX_VA + driver_virtio_net::layout::BUFFER_OFFSET + VIRTIO_NET_
/// HDR_LEN` — see `VirtioNet::submit_tx`'s own doc comment for why this
/// avoids a same-address copy.
fn handle_send_frame(drv: &mut crate::VirtioNet, len: u32) -> DriverResponse {
    if !drv.is_ready() {
        return DriverResponse::Failed { code: DriverErrorCode::ProbeFailed };
    }
    if len as usize > crate::FRAME_MAX {
        return DriverResponse::Failed { code: DriverErrorCode::Unsupported };
    }
    // SAFETY: `drv.is_ready()` (checked above) means `probe` already
    // mapped every region and set up both queues; the frame bytes are
    // staged per this function's own doc comment (the caller's
    // responsibility, matching `driver_virtio_blk::subsystem_entry`'s own
    // `handle_io` trust boundary for `WriteBlocks`' pre-staged data).
    if unsafe { drv.submit_tx(len as usize) } {
        DriverResponse::FrameSent
    } else {
        DriverResponse::Failed { code: DriverErrorCode::DeviceIo }
    }
}

/// Handles a `PollFrame` request: one non-blocking check of the RX queue
/// — see `VirtioNet::poll_rx`'s own doc comment.
fn handle_poll_frame(drv: &mut crate::VirtioNet) -> DriverResponse {
    if !drv.is_ready() {
        return DriverResponse::Failed { code: DriverErrorCode::ProbeFailed };
    }
    // SAFETY: `drv.is_ready()` (checked above) means `probe` already
    // mapped every region and set up both queues.
    match unsafe { drv.poll_rx() } {
        Some(len) => DriverResponse::FrameReceived { len },
        None => DriverResponse::Failed { code: DriverErrorCode::NoData },
    }
}

/// Constructs the right `VirtioNet` for whichever transport this process
/// was actually granted — read from the RX region's own `transport_kind`
/// header word (`driver_virtio_net::layout::PCI_INFO_OFFSET`'s own doc
/// comment for the full field layout; `kernel_arch_glue`'s own spawn-time
/// PCI capability-list walk populates it for `Transport::Pci`, or leaves
/// it `0` for `Transport::Mmio`, in which case `DRV_MMIO_VA` — pre-mapped
/// the same trusted way regardless — is used directly). Mirrors `driver_
/// virtio_blk::subsystem_entry::new_driver_for_this_transport` exactly.
fn new_driver_for_this_transport() -> crate::VirtioNet {
    // SAFETY: `DRV_RX_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::spawn_virtio_net_driver`,
    // before this process is ever scheduled.
    let transport_kind =
        unsafe { ((DRV_RX_VA + crate::layout::PCI_INFO_OFFSET) as *const u64).read_volatile() };
    if transport_kind == 0 {
        return crate::VirtioNet::new(DRV_MMIO_VA, DRV_RX_VA, DRV_TX_VA);
    }
    // SAFETY: same contract as the `transport_kind` read above; each
    // field is a `u64` at a fixed offset within the same info block.
    let read_u64_at = |field_offset: usize| unsafe {
        ((DRV_RX_VA + crate::layout::PCI_INFO_OFFSET + field_offset) as *const u64).read_volatile()
    };
    let common_cfg_va = read_u64_at(8) as usize;
    let notify_cfg_va = read_u64_at(16) as usize;
    let notify_off_multiplier = read_u64_at(24) as u32;
    let isr_cfg_va = read_u64_at(32) as usize;
    let device_cfg_va = read_u64_at(40) as usize;
    crate::VirtioNet::new_pci(
        common_cfg_va,
        notify_cfg_va,
        notify_off_multiplier,
        isr_cfg_va,
        device_cfg_va,
        DRV_RX_VA,
        DRV_TX_VA,
    )
}

/// The virtio-net driver's process entry point. Runs `probe()` exactly
/// once against the real, pre-mapped virtio-mmio window, then serves REAL
/// `DriverRequest`s forever: `Recv` (blocks until a real `Call` arrives),
/// decode, dispatch (`SendFrame`/`PollFrame` via the real hardware path
/// above, everything else via `VirtioNet::handle_request` directly, which
/// always answers `Unsupported`/`Ready` for those — see its own doc
/// comment), encode, `Reply`.
///
/// If `probe()` fails (e.g. no Network device was actually discovered at
/// boot), every request answers `Failed { code: ProbeFailed }` — mirrors
/// `driver-virtio-blk::subsystem_entry::subsystem_main`'s own documented
/// behavior exactly.
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut drv = new_driver_for_this_transport();
    let _ = drv.probe();

    loop {
        // SAFETY: `raw_syscall2`'s own contract.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, DRV_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_driver_request(&req_msg) {
            Ok(DriverRequest::SendFrame { len }) => handle_send_frame(&mut drv, len),
            Ok(DriverRequest::PollFrame) => handle_poll_frame(&mut drv),
            Ok(req) => drv.handle_request(req),
            Err(_) => DriverResponse::Failed {
                code: DriverErrorCode::Unsupported,
            },
        };
        write_shared_message(&encode_driver_response(&resp));
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success — the loop continues here only on the
        // (unreachable in practice) error case.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}
