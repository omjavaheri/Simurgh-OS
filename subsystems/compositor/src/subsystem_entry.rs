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
//! Purpose: the Compositor's real process entry point. Serves the REAL
//! `ipc_protocol::display::{DisplayRequest,DisplayResponse}` wire
//! protocol over the REAL `SyscallOp::Call/Recv/Reply` mechanism
//! (02-Microkernel-Layer.md §5.3/§8.3), driving a genuine
//! `compositor::Compositor` surface table — the SAME real-IPC-server
//! shape `fs_native::subsystem_entry` already established for fs-native
//! (03-Kernel-Subsystems-Layer.md §2.4, §5.4.2).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.4
//! (Compositor Service), §5.4.2 (MVP acceptance: a client creates a
//! surface, commits a buffer, and it is shown zero-copy — headless/file
//! output explicitly allowed for the MVP, so this process's own
//! "display" is proving the SAME physical frame is dereferenceable on
//! both ends, not driving real GPU scanout hardware, which does not
//! exist in this codebase yet).
//!
//! Position in the system: `kernel_arch_glue::compositor_demo_start`
//! spawns this process via `spawn_process_from_elf` — its own isolated
//! address space and capability space, granted exactly one capability
//! (an `Endpoint`, landing at slot 0 — see `grant_cap_into`'s own doc
//! comment for why that slot number is deterministic) plus THREE fixed
//! VAs pre-mapped directly (trusted bootstrap, no `Map` ceremony, same
//! pattern every other subsystem spawn in this codebase already uses):
//! `SHARED_VA` (the small `SmallMessage` marshaling page), `FB_VA` (the
//! committed frame's own pixel bytes — zero-copy, never carried through
//! the message, §5.2), and `CONFIRM_VA` (this process's own private
//! region it copies the frame bytes it actually read INTO, so `kernel_
//! arch_glue::compositor_commit_verify` can peek it directly afterward
//! and prove this process genuinely dereferenced `FB_VA`, not just that
//! the round trip completed — same "kernel peeks a shared region
//! directly, no protocol field needed" pattern `netstack::subsystem_
//! entry`'s own `STATUS_VA` already established).
//!
//! Safety/invariants: unlike `device-manager::subsystem_entry` (whose
//! `#[link_section = ".user_text"]` code shares a binary with kernel
//! `.text`), this file compiles into `compositor-bin`'s OWN fully
//! separate ELF image — every byte of it is `U=1`, so ordinary function
//! calls (into `ipc_protocol::codec`, `compositor::Compositor`, `alloc`)
//! are completely safe here.
//! ============================================================================

use crate::Compositor;
use ipc_protocol::codec::{decode_display_request, encode_display_response};
use ipc_protocol::display::DisplayErrorCode;
use ipc_protocol::{DisplayRequest, DisplayResponse, SurfaceHandle};
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_RECV`.
const IPC_RECV: usize = 43;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`.
const IPC_REPLY: usize = 44;

/// This process's own capability slot for the Endpoint — `kernel_arch_
/// glue::compositor_demo_start`'s own first (and only) grant into this
/// process's fresh, otherwise-empty capability space, so it
/// deterministically lands at slot 0 (same reasoning every other
/// subsystem's own `*_ENDPOINT_CAP` constant doc comment already gives).
const COMPOSITOR_ENDPOINT_CAP: usize = 0;

/// VA the shared message page is mapped at in THIS process's own address
/// space — must stay numerically equal to `kernel_arch_glue::
/// COMPOSITOR_SHARED_VA`.
const SHARED_VA: usize = 0xD840_0000;

/// VA the committed frame's own pixel bytes are mapped at — must stay
/// numerically equal to `kernel_arch_glue::COMPOSITOR_FB_VA`. Real
/// `CommitBuffer` bytes travel here, never through the `SmallMessage` at
/// `SHARED_VA` (03-Kernel-Subsystems-Layer.md §5.2's own "zero-copy, not
/// the message" rule).
const FB_VA: usize = 0xD850_0000;

/// VA this process's own private "confirm" region is mapped at — must
/// stay numerically equal to `kernel_arch_glue::COMPOSITOR_CONFIRM_VA`.
/// See this file's own module doc comment for why it exists.
const CONFIRM_VA: usize = 0xD860_0000;

/// Cap on a committed frame's own byte length (`width * height * 4`,
/// packed BGRA8) — one page, same size and rationale as `fs_native::
/// subsystem_entry::FS_DATA_LEN`: `FB_VA`/`CONFIRM_VA` are each exactly
/// one mapped page, so a request naming a `len` larger than this is
/// rejected rather than reading/writing past them.
const FRAME_MAX: u32 = 4096;

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
    unreachable!("compositor's subsystem_main never runs on a host build")
}

/// Host-build stand-in — see `raw_syscall`'s own identical stand-in doc
/// comment.
#[cfg(not(any(target_arch = "riscv64", target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(never)]
unsafe fn raw_syscall2(_a7: usize, _a0: usize, _a1: usize) -> (usize, usize) {
    unreachable!("compositor's subsystem_main never runs on a host build")
}

/// Reads the `SmallMessage` the caller wrote into the shared message
/// page — same fixed 56-byte layout `kernel_arch_glue::write_shared_
/// compositor_message` uses on the other side.
fn read_shared_message() -> SmallMessage {
    let base = SHARED_VA as *const u64;
    // SAFETY: `SHARED_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::compositor_demo_start`, before
    // this process is ever scheduled.
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

/// Copies `len` bytes from the committed frame (`FB_VA`) into this
/// process's own private confirm region (`CONFIRM_VA`) — this file's own
/// module doc comment on why: proves this process genuinely
/// dereferenced the shared frame, for `kernel_arch_glue::compositor_
/// commit_verify` to check afterward. `len` is trusted (bounded by
/// `FRAME_MAX`, checked before this is ever called).
fn copy_frame_to_confirm(len: u32) {
    // SAFETY: `FB_VA`/`CONFIRM_VA` are both mapped `U=1 R+W` in this
    // process's own address space by `compositor_demo_start`; `len <=
    // FRAME_MAX` (each mapped page's own size) is checked by the caller.
    unsafe {
        core::ptr::copy_nonoverlapping(FB_VA as *const u8, CONFIRM_VA as *mut u8, len as usize);
    }
}

/// Handles one REAL `DisplayRequest`, driving a REAL `Compositor` surface
/// table. `CommitBuffer`'s own `buffer_cap` (the WIRE protocol's own
/// "client capability slot" field) is intentionally never resolved here
/// — this MVP demo has exactly ONE client, ONE shared frame buffer, at a
/// well-known fixed VA both sides already agree on, the SAME
/// simplification `fs_native::subsystem_entry::handle_request`'s own doc
/// comment already makes for `shared_cap`. Real per-connection
/// capability resolution is a later `feat:` follow-up, not a correctness
/// gap in what IS wired here.
fn handle_request(comp: &mut Compositor, req: DisplayRequest) -> DisplayResponse {
    match req {
        DisplayRequest::CreateSurface => DisplayResponse::SurfaceCreated {
            surface: SurfaceHandle(comp.create_surface()),
        },
        DisplayRequest::CommitBuffer {
            surface,
            buffer_cap: _,
            width,
            height,
        } => {
            let len = width.saturating_mul(height).saturating_mul(4);
            if len > FRAME_MAX {
                return DisplayResponse::Error {
                    code: DisplayErrorCode::BadBuffer,
                };
            }
            match comp.commit_buffer(surface.0, width, height) {
                Ok(()) => {
                    copy_frame_to_confirm(len);
                    DisplayResponse::Committed
                }
                Err(_) => DisplayResponse::Error {
                    code: DisplayErrorCode::BadSurface,
                },
            }
        }
        DisplayRequest::DestroySurface { surface } => match comp.destroy_surface(surface.0) {
            Ok(()) => DisplayResponse::Destroyed,
            Err(_) => DisplayResponse::Error {
                code: DisplayErrorCode::BadSurface,
            },
        },
        // Not yet built — `03-Kernel-Subsystems-Layer.md` §2.4's own
        // `input_event_stream` needs a real `Notification`-based async
        // delivery path (matching driver-virtio-net's own interrupt-
        // driven TX completion in shape), and `output_topology` needs a
        // real output source once one exists; neither is required by
        // §5.4.2's own MVP acceptance bar (create surface, commit a
        // buffer, show it zero-copy). Reported as `Unsupported` rather
        // than silently faked data, matching this project's own "an
        // honest gap beats a guessed answer" convention.
        DisplayRequest::SubscribeInput | DisplayRequest::QueryOutputs => DisplayResponse::Error {
            code: DisplayErrorCode::Unsupported,
        },
    }
}

/// The Compositor process's own entry point. Serves REAL
/// `DisplayRequest`s forever: `Recv` (blocks until a real `Call`
/// arrives), decode, dispatch to the real `Compositor`, encode, `Reply`
/// (always switches away on success — see `Reply`'s own doc comment in
/// `kernel_core::syscall`).
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut comp = Compositor::new();

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
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, COMPOSITOR_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_display_request(&req_msg) {
            Ok(req) => handle_request(&mut comp, req),
            Err(_) => DisplayResponse::Error {
                code: DisplayErrorCode::Unsupported,
            },
        };
        write_shared_message(&encode_display_response(&resp));
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success (see its own doc comment) — the loop
        // continues here only on the (unreachable in practice) error
        // case, matching every other subsystem's own identical loop.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}
