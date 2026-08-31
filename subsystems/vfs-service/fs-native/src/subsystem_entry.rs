//! ============================================================================
//! subsystem_entry.rs — riscv64 / x86_64 / aarch64
//!
//! Note on this file's ONE architecture-conditional piece: same narrow,
//! documented exception `device-manager::subsystem_entry`'s own file
//! header explains — `raw_syscall`/`raw_syscall2`'s job is issuing the
//! raw syscall INSTRUCTION itself (`ecall`/`int 0x80`/`svc #0`), an
//! unavoidable ISA detail. Every other line in this file is
//! architecture-generic.
//!
//! Purpose: fs-native's real process entry point. Serves the REAL
//! `ipc_protocol::fs::{FsRequest,FsResponse}` wire protocol over the
//! REAL `SyscallOp::Call/Recv/Reply` mechanism (02-Microkernel-Layer.md
//! §5.3/§8.3), driving a genuine `fs_native::MemFs` — the first
//! subsystem process this project has wired to the real IPC fast path
//! (as opposed to `device-manager`'s own demo-scoped raw ecalls, or the
//! generic `umode_ipc_server*`'s dummy `0xC0FFEE` payload).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.2 (fs-native
//! as a separate service), §5.3 (MVP acceptance: mount + basic
//! read/write over IPC — Open/Stat/Close/Read/Write are all real and
//! wired; Read/Write's bulk bytes travel through a genuine
//! `SharedRegion` capability, per §5.2's zero-copy design — see
//! `handle_request`'s own doc comment for the one MVP simplification
//! still deferred: real per-connection `shared_cap` resolution).
//!
//! Position in the system: `kernel_arch_glue::fs_demo_start` spawns this
//! process via `spawn_process_from_elf` — its OWN isolated address space
//! and capability space, NOT sharing the Root Task's the way the
//! in-kernel IPC demo server does. It is granted exactly one capability
//! (an `Endpoint`, landing at slot 0 in its own fresh capability space —
//! see `kernel_arch_glue::grant_cap_into`'s own doc comment for why that
//! slot number is deterministic) and one page of memory shared with the
//! kernel's own identity map, at a fixed VA, carrying the real
//! `SmallMessage` payload raw ecall registers cannot fit.
//!
//! Safety/invariants: unlike `device-manager::subsystem_entry` (whose
//! `#[link_section = ".user_text"]` code shares a binary with kernel
//! `.text` and so must never call an un-inlined function outside that
//! section), this file compiles into `fs-native-bin`'s OWN fully
//! separate ELF image — every byte of it is `U=1`, so ordinary function
//! calls (into `ipc_protocol::codec`, `fs_native::MemFs`, `alloc`) are
//! completely safe here. No `#[link_section]`/`#[inline(always)]`
//! discipline is needed for that reason.
//! ============================================================================

use crate::MemFs;
use ipc_protocol::codec::{decode_fs_request, encode_fs_response};
use ipc_protocol::fs::FsErrorCode;
use ipc_protocol::{FileHandle, FsRequest, FsResponse, PathId};
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_RECV`
/// (see that constant's own doc comment — the real `SyscallOp::Recv`).
const IPC_RECV: usize = 43;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`.
const IPC_REPLY: usize = 44;

/// The endpoint capability's slot in THIS process's own capability
/// space. Not discovered at runtime (unlike the in-kernel IPC demo's
/// `IPC_ENDPOINT_CAP` opcode) — `kernel_arch_glue::fs_demo_start` grants
/// fs-native exactly ONE capability into its otherwise-empty, freshly
/// allocated capability space, and a brand-new `CapTable`'s free list
/// always starts at slot 0 (see `grant_cap_into`'s own doc comment), so
/// this is a compile-time constant, not a value to look up.
const FS_ENDPOINT_CAP: usize = 0;

/// VA the shared fs page is mapped at in THIS process's own address
/// space — must stay numerically equal to `kernel_arch_glue::
/// FS_SHARED_VA`.
const FS_SHARED_VA: usize = 0xD800_0000;

/// VA the shared BULK DATA region is mapped at in THIS process's own
/// address space — must stay numerically equal to `kernel_arch_glue::
/// FS_DATA_VA`. Real `Read`/`Write` bytes travel here, never through the
/// `SmallMessage` at `FS_SHARED_VA` (03-Kernel-Subsystems-Layer.md §5.2's
/// own "zero-copy, not the message" rule).
const FS_DATA_VA: usize = 0xD810_0000;

/// Size of the shared data region, in bytes — matches
/// `kernel_mm::object_size_bytes(KernelObjectType::SharedRegion)` (one
/// page for this MVP). `Read`/`Write` requests naming a `len` larger than
/// this are rejected with `BadSharedRegion` rather than reading/writing
/// past the mapped page.
const FS_DATA_LEN: u32 = 4096;

/// # Safety
/// `ecall` from U-mode traps to the kernel's S-mode handler, which
/// preserves every register except `a0`.
///
/// `#[inline(never)]`: a real, QEMU-found bug — see `kernel/src/
/// main.rs`'s riscv64 `raw_syscall`'s own extensive doc comment. Under
/// this project's pinned nightly, LLVM produced incorrect codegen for
/// multiple sequential calls to an `#[inline(always)]` function
/// wrapping an asm block that can switch threads (this crate's own
/// `subsystem_main` issues exactly that pattern — `IPC_RECV` then, on
/// the next loop iteration, `IPC_REPLY`); a real (non-inlined) function
/// call sidesteps it via the standard calling convention, which already
/// treats `a0`-`a7` as fully clobbered. No `#[link_section]` needed
/// here (unlike `kernel/src/main.rs`'s own `.user_text` variant) — see
/// this file's own header doc comment on why.
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

/// Like `raw_syscall`, but also reads back `a1` — needed for `IPC_RECV`,
/// whose result (the sender's `ThreadId`, plus a label this file
/// ignores — the real payload lives in the shared fs page) does not fit
/// in one register.
///
/// `#[inline(never)]` — see `raw_syscall`'s own doc comment.
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
/// gate, which preserves every register except `rax`/`rsi` (this
/// project's own convention).
///
/// `#[inline(never)]` — see the riscv64 `raw_syscall`'s own doc comment.
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

/// See the riscv64 `raw_syscall2`'s own doc comment.
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
/// vector, which preserves every register except `x0`/`x1` (this
/// project's own convention).
///
/// `#[inline(never)]` — see the riscv64 `raw_syscall`'s own doc comment.
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

/// See the riscv64 `raw_syscall2`'s own doc comment.
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

/// Reads the `SmallMessage` (label + up to 6 data words, zero-padded)
/// the caller wrote into the shared fs page — same fixed 56-byte layout
/// `kernel_arch_glue::write_shared_fs_message` uses on the other side.
fn read_shared_message() -> SmallMessage {
    let base = FS_SHARED_VA as *const u64;
    // SAFETY: `FS_SHARED_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::fs_demo_start`, before this
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

/// Writes `msg` into the shared fs page for the caller to read back
/// after `IPC_REPLY` wakes it — same fixed layout as `read_shared_
/// message`.
fn write_shared_message(msg: &SmallMessage) {
    let base = FS_SHARED_VA as *mut u64;
    // SAFETY: same contract as `read_shared_message`.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Maps this MVP demo's one registered `PathId` to a real path string.
/// A stand-in for the VFS Router's own `RegisterPath` mechanism (not
/// built yet — see `ipc_protocol::fs`'s own module doc comment on why
/// `PathId` is not an inlined string) — fs-native pre-seeds exactly one
/// well-known file at boot, so `PathId(0)` is the only valid id.
fn resolve_path(id: PathId) -> Option<&'static str> {
    if id.0 == 0 {
        Some("/greeting")
    } else {
        None
    }
}

/// Maps a `fs_native::FsError` to the wire protocol's own `FsErrorCode`.
fn error_code(e: crate::FsError) -> FsErrorCode {
    match e {
        crate::FsError::NotFound => FsErrorCode::NotFound,
        crate::FsError::BadHandle => FsErrorCode::BadHandle,
        crate::FsError::TooLarge => FsErrorCode::Io,
        crate::FsError::Denied => FsErrorCode::Denied,
    }
}

/// Handles one REAL `FsRequest`, driving a REAL `MemFs`. `Read`/`Write`'s
/// bulk bytes travel through the real `SharedRegion` `kernel_arch_glue::
/// fs_demo_start` maps at `FS_DATA_VA` (03-Kernel-Subsystems-Layer.md
/// §5.2's own zero-copy design) — `shared_cap` itself (the WIRE
/// protocol's own "client capability slot" field) is intentionally never
/// resolved here: this MVP demo has exactly ONE client, ONE shared
/// region, at a well-known fixed VA both sides already agree on, the
/// SAME simplification `resolve_path`'s own `PathId(0)`-only precedent
/// already makes for paths. Real per-connection capability resolution
/// (looking up an arbitrary CLIENT-side slot number against fs-native's
/// OWN cap space) is a VFS-Router-level concern, not yet built — a later
/// `feat:` follow-up, not a correctness gap in what IS wired here.
fn handle_request(fs: &mut MemFs, req: FsRequest) -> FsResponse {
    match req {
        FsRequest::Open { path, flags } => match resolve_path(path) {
            Some(p) => {
                match fs.open(p, flags.contains(ipc_protocol::OpenFlags::WRITE), flags.contains(ipc_protocol::OpenFlags::CREATE)) {
                    Ok(h) => FsResponse::Opened {
                        handle: FileHandle(h.0),
                    },
                    Err(e) => FsResponse::Error { code: error_code(e) },
                }
            }
            None => FsResponse::Error {
                code: FsErrorCode::BadPath,
            },
        },
        FsRequest::Stat { path } => match resolve_path(path) {
            Some(p) => match fs.open(p, false, false) {
                Ok(h) => {
                    let size = fs.size(h).unwrap_or(0);
                    let _ = fs.close(h);
                    FsResponse::Stat { size, is_dir: false }
                }
                Err(e) => FsResponse::Error { code: error_code(e) },
            },
            None => FsResponse::Error {
                code: FsErrorCode::BadPath,
            },
        },
        FsRequest::Close { handle } => match fs.close(crate::Handle(handle.0)) {
            Ok(()) => FsResponse::Closed,
            Err(e) => FsResponse::Error { code: error_code(e) },
        },
        FsRequest::Read { handle, offset, len, shared_cap: _ } => {
            if len > FS_DATA_LEN {
                return FsResponse::Error {
                    code: FsErrorCode::BadSharedRegion,
                };
            }
            // SAFETY: `FS_DATA_VA` is mapped `U=1 R+W` in this process's
            // own address space by `kernel_arch_glue::fs_demo_start`,
            // before this process is ever scheduled; `len <=
            // FS_DATA_LEN` (the mapped page's own size) just checked.
            let buf = unsafe { core::slice::from_raw_parts_mut(FS_DATA_VA as *mut u8, len as usize) };
            match fs.read(crate::Handle(handle.0), offset, buf) {
                Ok(bytes) => FsResponse::Read { bytes: bytes as u32 },
                Err(e) => FsResponse::Error { code: error_code(e) },
            }
        }
        FsRequest::Write { handle, offset, len, shared_cap: _ } => {
            if len > FS_DATA_LEN {
                return FsResponse::Error {
                    code: FsErrorCode::BadSharedRegion,
                };
            }
            // SAFETY: same contract as `Read`'s own slice above.
            let buf = unsafe { core::slice::from_raw_parts(FS_DATA_VA as *const u8, len as usize) };
            match fs.write(crate::Handle(handle.0), offset, buf) {
                Ok(bytes) => FsResponse::Written { bytes: bytes as u32 },
                Err(e) => FsResponse::Error { code: error_code(e) },
            }
        }
    }
}

/// fs-native's process entry point. Pre-seeds one real file (matching
/// every other demo process's own "start from a known, self-initialized
/// state" convention — device-manager's `Supervised::new()`, the P2
/// demo's own sentinel writes), then serves REAL `FsRequest`s forever:
/// `Recv` (blocks until a real `Call` arrives), decode, dispatch to the
/// real `MemFs`, encode, `Reply` (always switches away on success — see
/// `Reply`'s own doc comment in `kernel_core::syscall`).
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut fs = MemFs::new();
    // SAFETY: no memory access beyond `fs`'s own heap allocations —
    // `create`/`open`/`write`/`close` are pure Rust, no `unsafe` needed
    // here at all (unlike `device-manager::subsystem_entry`, this
    // process's own code is never `.user_text`-constrained — see this
    // file's own doc comment).
    fs.create("/greeting");
    if let Ok(h) = fs.open("/greeting", true, false) {
        let _ = fs.write(h, 0, b"hello from fs-native");
        let _ = fs.close(h);
    }

    // Same stack-slot-reuse miscompilation `kernel/src/main.rs`'s
    // `umode_root` hit (full investigation in its own doc comment): this
    // project's pinned nightly (`nightly-2025-01-15`) at `-O0` can reuse
    // ONE stack slot for a literal argument across multiple sequential
    // calls within one function that issues many `raw_syscall`/
    // `raw_syscall2` calls — exactly this loop's own shape (`IPC_RECV`
    // then `IPC_REPLY`, repeated). `#[inline(never)]` on `raw_syscall`/
    // `raw_syscall2` alone was proven insufficient for `umode_root`'s own
    // case; the reliable fix is forcing every literal argument through a
    // real `asm!` so LLVM must freshly materialize it rather than reuse
    // a stale slot — `core::hint::black_box`/`core::ptr::read_volatile`
    // do NOT work here (both compile to real, non-inlined function calls
    // under this build).
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
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, FS_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_fs_request(&req_msg) {
            Ok(req) => handle_request(&mut fs, req),
            Err(_) => FsResponse::Error {
                code: FsErrorCode::Unsupported,
            },
        };
        write_shared_message(&encode_fs_response(&resp));
        // SAFETY: `raw_syscall`'s own contract. `IPC_REPLY` always
        // switches away on success (see its own doc comment) — the
        // loop continues here only on the (unreachable in practice)
        // error case, matching `umode_ipc_server`'s own convention.
        unsafe { raw_syscall(IPC_REPLY, from, zero!()) };
    }
}
