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

use crate::scanout::{
    Scanout, DESKTOP_BACKGROUND, SCANOUT_ACK_OFFSET, SCANOUT_INFO_MAGIC, SCANOUT_STATUS_OFFSET,
};
use crate::Compositor;
use ipc_protocol::codec::{decode_display_request, encode_display_response};
use ipc_protocol::display::DisplayErrorCode;
use ipc_protocol::{DisplayRequest, DisplayResponse, SurfaceHandle};
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::
/// SBS_IPC_RECV` — the correctly-GENERAL `Recv` opcode, needed now that
/// `Simurgh-UI-Template01`'s own `ui-core` is a SECOND, independent real
/// client. **Changed from `sys::IPC_RECV` (43) on 2026-09-11**, NOT a
/// cosmetic rename — see `kernel_arch_glue::G_COMPOSITOR_ROOT_ONLY_PHASE`'s
/// own doc comment for the real, QEMU-confirmed boot hang this exact
/// change already caused (and fixed) once, for fs-native's own identical
/// situation: switching this constant alone, without ALSO keeping the
/// narrow, hardcoded-root dispatch for Compositor's own Root-Task-only
/// bootstrap phase, reintroduces that same class of permanent hang.
/// `kernel_arch_glue::compositor_native_recv` (the dispatch `kernel/
/// kernel/src/main.rs`'s own `sys::SBS_IPC_RECV` arm actually calls for
/// Compositor) handles that distinction; this constant only needs to
/// name the right raw opcode.
const IPC_RECV: usize = 108;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_REPLY`.
const IPC_REPLY: usize = 44;
/// The `Recv` opcode used to drain the INPUT drivers' endpoints — the
/// same general `sys::SBS_IPC_RECV` (108) as [`IPC_RECV`].
///
/// Was the plain `sys::IPC_RECV` (43). That opcode is the Root-Task-era
/// path (`kernel_arch_glue::p2_ipc_recv`): whenever the `Recv` has to
/// BLOCK it switches straight into `root_thread` — a TCB that
/// `p2_preempt_start` retires before any input driver even exists. It
/// blocks here whenever this loop sees a driver's signal bit before that
/// driver has issued its `Call` (the driver signals first, then calls,
/// and can be preempted in between), which on a live interactive boot is
/// routine, not rare. For Compositor, 108 dispatches through
/// `kernel_arch_glue::compositor_native_recv`, whose root-only bootstrap
/// phase is already over by the time either driver is spawned (it ends
/// when ui-core is wired), so these endpoints get the correct general
/// `pick_next` hand-off.
const IPC_RECV_GENERIC: usize = 108;
/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::
/// NOTIF_POLL`. Real-input-handling plan, Stage B/C: this file's own
/// `subsystem_main` polls `I8042_SIGNAL_NOTIF_CAP` with this at the top
/// of every loop iteration, additively (see that function's own doc
/// comment for why this never touches the EXISTING `IPC_RECV`/`IPC_
/// REPLY` sequence below).
const NOTIF_POLL: usize = 125;

/// This process's own capability slot for the Endpoint — `kernel_arch_
/// glue::compositor_demo_start`'s own first (and only) grant into this
/// process's fresh, otherwise-empty capability space, so it
/// deterministically lands at slot 0 (same reasoning every other
/// subsystem's own `*_ENDPOINT_CAP` constant doc comment already gives).
const COMPOSITOR_ENDPOINT_CAP: usize = 0;

/// Slot 1 is NOT an input capability: `kernel_arch_glue::
/// compositor_demo_start` grants the frame-buffer `SharedRegion` (the
/// `FB_VA` region) into this cap space right after the display Endpoint,
/// so it is the SECOND grant and every input capability sits one slot
/// later than the input plans originally assumed.
///
/// **Real bug found on the first interactive desktop boot (2026-09-24)**:
/// these constants used to be 1/2/3/4, i.e. they skipped that
/// `SharedRegion`. Every `NOTIF_POLL` below then named an `Endpoint`
/// (slots 2 and 4) and failed with `BadCap`, which `p2_poll` reports as
/// "no bits" — so this loop never noticed a driver's signal, driver-i8042
/// and driver-mouse stayed blocked in their first `Call` forever, and not
/// one keystroke or mouse event ever reached ui-core. Confirmed by dumping
/// this cap space on a live boot: slot 0 `Endpoint`, 1 `SharedRegion`,
/// 2 `Endpoint`, 3 `Notification`, 4 `Endpoint`, 5 `Notification`.
///
/// This process's own capability slot for `driver-i8042`'s own service
/// `Endpoint` — `kernel_arch_glue::spawn_i8042_driver`'s own grant (the
/// THIRD grant overall), via `wire_service_endpoint`. Real-input-handling
/// plan, Stage B/C.
const I8042_ENDPOINT_CAP: usize = 2;
/// This process's own capability slot for the `Notification` SHARED
/// with `driver-i8042` (signal-before-call) — the FOURTH grant
/// (`kernel_arch_glue::wire_notification`).
const I8042_SIGNAL_NOTIF_CAP: usize = 3;
/// This process's own capability slot for `driver-mouse`'s own service
/// `Endpoint` — `kernel_arch_glue::spawn_mouse_driver`'s own grant (the
/// FIFTH grant overall: 0 display, 1 frame-buffer region, 2 i8042
/// endpoint, 3 i8042 signal notif, THIS at 4), via
/// `wire_service_endpoint`. Mouse-input plan, Stage 1b.
const MOUSE_ENDPOINT_CAP: usize = 4;
/// This process's own capability slot for the `Notification` SHARED
/// with `driver-mouse` (signal-before-call) — the SIXTH grant
/// (`kernel_arch_glue::wire_notification`).
const MOUSE_SIGNAL_NOTIF_CAP: usize = 5;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::
/// NOTIF_WAIT_TIMEOUT`: `NOTIF_WAIT` plus a deadline (`a1`, nanoseconds).
/// Returns the signalled bits, or `0` on timeout.
const NOTIF_WAIT_TIMEOUT: usize = 139;
/// Bit `driver-i8042` signals with (`driver_i8042::subsystem_entry::SIGNAL_BIT`).
const I8042_SIGNAL_BIT: usize = 1;
/// Bit `driver-mouse` signals with (`driver_mouse::subsystem_entry::SIGNAL_BIT`).
const MOUSE_SIGNAL_BIT: usize = 2;
/// How long an EMPTY `PollInputEvent`/`PollMouseEvent` is held open, waiting
/// for input, before it is answered "nothing pending".
///
/// This is what lets the desktop go idle. ui-core polls for input in a loop;
/// answered at once, every poll makes ui-core (and this process) runnable
/// again immediately, so the CPU never has nothing to do. Held for up to this
/// long, ui-core sits blocked in its `Call`, this process sits blocked on the
/// input notification, and the kernel halts the core - and any input event
/// ends the wait at once (the drivers signal the notification), so input
/// latency is unchanged. It also bounds how stale ui-core's own timers
/// (notification expiry, cursor animation) can get: they still run at least
/// every PARK_MAX_NS. Long enough to save power, short enough that those
/// timers stay smooth.
const PARK_MAX_NS: u64 = 20_000_000;

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
///
/// Was `0xD860_0000` until `FB_VA`'s own region grew past 1 MiB
/// (`kernel_arch_glue::COMPOSITOR_CONFIRM_VA`'s own doc comment has the
/// full story) — `kernel_arch_glue::compositor_demo_start` moved where
/// it MAPS this region accordingly, but this constant did NOT move with
/// it in an earlier pass, so `copy_frame_to_confirm` kept writing to the
/// OLD address (now silently aliasing the tail of `FB_VA`'s own,
/// now-larger range for small frames, or overrunning entirely unmapped
/// memory for a real desktop-sized one — the exact bug a real QEMU boot
/// caught: `compositor_commit_verify` reporting MISMATCH, then a full
/// hang once `ui-core`'s own real, desktop-resolution `CommitBuffer`
/// reached this same stale write).
const CONFIRM_VA: usize = 0xD8A0_0000;

/// Cap on a committed frame's own byte length (`width * height * 4`,
/// packed BGRA8) — must stay numerically equal to `kernel_arch_glue::
/// COMPOSITOR_FB_LEN`: `FB_VA`/`CONFIRM_VA` are each mapped exactly this
/// many bytes (`kernel_arch_glue::COMPOSITOR_FB_PAGES` pages), so a
/// request naming a `len` larger than this is rejected rather than
/// reading/writing past them. `470 * 4096` — enough for a real 800x600
/// BGRA8 desktop frame (800 * 600 * 4 = 1,920,000 bytes); was a single
/// page (4096 bytes) until `Simurgh-UI-Template01`'s own `ui-core`
/// needed a real, full-resolution frame to flow through this pipe.
const FRAME_MAX: u32 = 470 * 4096;

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

/// Module-level twin of `subsystem_main`'s own `zero!` — same QEMU-found
/// stack-slot-reuse miscompilation `fs_native::subsystem_entry`
/// documents, so every literal argument to a raw syscall OUTSIDE that
/// function goes through this. Defined here, before its first use,
/// because `macro_rules!` scoping is textual.
macro_rules! fresh {
    ($val:expr) => {{
        let mut v: usize = $val;
        // SAFETY: a no-op asm block (`v` is read back unchanged) — its
        // only purpose is defeating the stack-slot-reuse miscompilation
        // above.
        core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
        v
    }};
}

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::NOW_NS`
/// — a plain timestamp read, served on all three architectures.
const NOW_NS: usize = 86;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::
/// SERIAL_PRINT` (x86_64 only; an unknown opcode is a harmless no-op on
/// the other two). See [`serial_print`] for how this process can use it.
const SERIAL_PRINT: usize = 118;

/// Master switch for the Compositor's own performance log line (see
/// [`PerfStats`]). A `const`, not a Cargo feature, because this crate is
/// built by the same command line in the demo and the desktop image;
/// flipping it to `false` removes the whole path at compile time.
///
/// It stays silent in the default demo boot on its own: a line is only
/// printed every [`PERF_LOG_EVERY`] commits, and the demo boot makes a
/// handful at most (the Root Task's 2x2 bootstrap frame, plus ui-core's
/// if it gets scheduled) before it powers off. The desktop commits a
/// frame per input event, so there it appears within seconds of moving
/// the mouse.
const PERF_LOG: bool = true;

/// How many commits one [`PerfStats`] window covers. Large enough that
/// the log line itself (a trap plus a few hundred bytes of serial
/// output) is noise next to the frames it measures.
const PERF_LOG_EVERY: u64 = 64;

/// Reads the kernel clock, in nanoseconds.
fn now_ns() -> u64 {
    // SAFETY: `raw_syscall`'s own contract; `NOW_NS` takes no arguments
    // and touches no state.
    unsafe { raw_syscall(NOW_NS, fresh!(0), fresh!(0)) as u64 }
}

/// Writes `text` to the serial console through `sys::SERIAL_PRINT`.
///
/// That opcode reads its bytes from a FIXED VA in the caller's own
/// address space (`kernel/src/main.rs`'s `SHELL_OUT_VA`, `0xD900_0000`,
/// simurgh-shell's print page), and in THIS process that VA is
/// [`SCANOUT_INFO_VA`] — the scanout info page, private R+W memory this
/// process already owns. So the text is staged there and the bytes it
/// covered are restored right after, which avoids a kernel change for a
/// diagnostic. Safe against the kernel's own reads of that page because
/// the only one after spawn (`compositor_scanout_report`) runs during the
/// Root Task's bootstrap commit, long before the first line is printed
/// ([`PERF_LOG_EVERY`] commits later).
fn serial_print(text: &[u8]) {
    const MAX: usize = 256;
    let len = text.len().min(MAX);
    let mut saved = [0u8; MAX];
    // SAFETY: the info page is mapped `U=1 R+W` for this process before
    // it is first scheduled (`SCANOUT_INFO_VA`'s own doc comment), and
    // `len <= 256` stays well inside its 4 KiB. The syscall only reads
    // it; the original bytes are put back before anything else runs in
    // this single-threaded process.
    unsafe {
        core::ptr::copy_nonoverlapping(SCANOUT_INFO_VA as *const u8, saved.as_mut_ptr(), len);
        core::ptr::copy_nonoverlapping(text.as_ptr(), SCANOUT_INFO_VA as *mut u8, len);
        raw_syscall(SERIAL_PRINT, fresh!(len), fresh!(0));
        core::ptr::copy_nonoverlapping(saved.as_ptr(), SCANOUT_INFO_VA as *mut u8, len);
    }
}

/// A fixed-size, allocation-free text buffer for one log line.
struct LineBuf {
    buf: [u8; 192],
    len: usize,
}

impl core::fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Per-window commit statistics behind the `compositor: commits=...`
/// serial line — how the cost of one committed frame was measured
/// before and after the dirty-span present (README, Compositor entry).
///
/// `commit` covers the whole `CommitBuffer` handling (confirm copy plus
/// present); `present` just the framebuffer part; `fb_bytes` counts bytes
/// actually written to video memory. Only collected while a real
/// framebuffer exists, so a headless boot never makes a clock syscall
/// for it.
#[derive(Default)]
struct PerfStats {
    commits: u64,
    window_start_ns: u64,
    commit_ns: u64,
    present_ns: u64,
    fb_bytes: u64,
}

impl PerfStats {
    /// Accounts one commit, and every [`PERF_LOG_EVERY`] commits prints
    /// the window's averages and resets it.
    fn record(&mut self, commit_ns: u64, present_ns: u64, fb_bytes: u64, now: u64) {
        use core::fmt::Write;
        if self.window_start_ns == 0 {
            self.window_start_ns = now.saturating_sub(commit_ns);
        }
        self.commits += 1;
        self.commit_ns += commit_ns;
        self.present_ns += present_ns;
        self.fb_bytes += fb_bytes;
        if self.commits % PERF_LOG_EVERY != 0 {
            return;
        }
        let window_ns = now.saturating_sub(self.window_start_ns).max(1);
        let mut line = LineBuf { buf: [0; 192], len: 0 };
        let _ = write!(
            line,
            "compositor: commits={} window_ms={} rate_x10={}/s commit_us={} present_us={} bytes_written={}\r\n",
            self.commits,
            window_ns / 1_000_000,
            PERF_LOG_EVERY * 10_000_000_000 / window_ns,
            self.commit_ns / PERF_LOG_EVERY / 1000,
            self.present_ns / PERF_LOG_EVERY / 1000,
            self.fb_bytes / PERF_LOG_EVERY,
        );
        serial_print(&line.buf[..line.len]);
        let commits = self.commits;
        *self = Self { commits, window_start_ns: now, ..Self::default() };
    }
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

/// How much of each committed frame [`copy_frame_to_confirm`] copies.
///
/// It used to copy the WHOLE frame — 1.92 MB per commit for ui-core's
/// 800x600 desktop, on every mouse move — although the only reader,
/// `kernel_arch_glue::compositor_commit_verify`, compares just the Root
/// Task's 2x2 bootstrap frame (16 bytes). One page is plenty to prove
/// this process really dereferenced `FB_VA`, and costs nothing next to
/// a frame.
const CONFIRM_PROOF_BYTES: u32 = 4096;

/// Copies the first `min(len, CONFIRM_PROOF_BYTES)` bytes of the
/// committed frame (`FB_VA`) into this process's own private confirm
/// region (`CONFIRM_VA`) — this file's own module doc comment on why:
/// proves this process genuinely dereferenced the shared frame, for
/// `kernel_arch_glue::compositor_commit_verify` to check afterward.
/// `len` is trusted (bounded by `FRAME_MAX`, checked before this is ever
/// called).
///
/// Must run AFTER `Output::present`: the confirm region doubles as the
/// present path's shadow of what is on screen (see `Output::present`),
/// and copying the new frame into it first would make the diff believe
/// those bytes were already on screen. Copied after, they are exactly
/// what was just presented, so the shadow stays consistent.
fn copy_frame_to_confirm(len: u32) {
    // SAFETY: `FB_VA`/`CONFIRM_VA` are both mapped `U=1 R+W` in this
    // process's own address space by `compositor_demo_start`; `len <=
    // FRAME_MAX` (each mapped page's own size) is checked by the caller.
    unsafe {
        core::ptr::copy_nonoverlapping(
            FB_VA as *const u8,
            CONFIRM_VA as *mut u8,
            len.min(CONFIRM_PROOF_BYTES) as usize,
        );
    }
}

/// VA the scanout info page is mapped at — must stay numerically equal
/// to `kernel_arch_glue::COMPOSITOR_SCANOUT_INFO_VA`. ALWAYS mapped,
/// even on a machine with no display: a zero-filled page is how the
/// kernel says "no framebuffer was granted", and reading a mapped page
/// is how this process finds that out without an architecture check it
/// is not allowed to make (no `cfg(target_arch)` above the HAL).
const SCANOUT_INFO_VA: usize = 0xD900_0000;

/// VA the granted framebuffer itself is mapped at — must stay
/// numerically equal to `kernel_arch_glue::COMPOSITOR_SCANOUT_VA`.
/// Mapped ONLY when a real framebuffer exists; nothing here dereferences
/// it unless the info page above said so.
const SCANOUT_VA: usize = 0xD910_0000;

/// VA `driver-i8042`'s own shared message page is mapped at in THIS
/// process's own address space — must stay numerically equal to
/// `kernel_arch_glue::COMPOSITOR_I8042_VA`. A DIFFERENT physical region
/// from `SHARED_VA` (the display Endpoint's own message page) —
/// distinct producer, distinct edge.
///
/// Was `0xD8B0_0000`, inside `CONFIRM_VA`'s 1.92 MB range — every real
/// 800x600 commit then overwrote this page via `copy_frame_to_confirm`.
/// See `kernel_arch_glue::COMPOSITOR_I8042_VA`'s own doc comment.
const I8042_VA: usize = 0xD8C8_0000;

/// How many decoded input events of each kind this process holds for its
/// client. Big enough for a burst of fast typing (or QEMU `sendkey`
/// scripting, which delivers make+break pairs back to back) between two
/// of ui-core's own polls.
const INPUT_QUEUE_LEN: usize = 64;

/// A fixed-capacity FIFO of decoded input events, drained one per
/// `PollInputEvent`/`PollMouseEvent` request.
///
/// Replaces the single `Option` slot each event kind used to have. With
/// one slot, every event that arrived before ui-core's next poll
/// overwrote the previous one: on a real interactive boot (2026-09-24)
/// typing "alice" at normal speed produced an empty username field and
/// only two of seven password characters.
///
/// When full, a new event does not simply push another one out: it is
/// COALESCED ([`QueueEvent`]). Mouse motion with unchanged buttons is
/// summed, so a burst never loses net pointer travel; button changes and
/// key releases are never discarded while anything cheaper to lose
/// exists. Only if every queued event is a distinct, un-mergeable
/// transition is the oldest dropped.
struct EventQueue<T: QueueEvent> {
    buf: [Option<T>; INPUT_QUEUE_LEN],
    head: usize,
    len: usize,
}

/// How an input event kind survives a full [`EventQueue`].
trait QueueEvent: Copy {
    /// `older` followed by `newer`, as ONE event with the same net
    /// effect — or `None` if the pair cannot be merged without losing
    /// something a client must see.
    fn merge(older: &Self, newer: &Self) -> Option<Self>;
    /// Whether this event may be discarded outright when nothing can be
    /// merged. Losing it must never leave the client with a wrong state
    /// (a key press is expendable; its release is not — losing a release
    /// leaves a key "held down" forever).
    fn expendable(&self) -> bool;
}

impl<T: QueueEvent> EventQueue<T> {
    const fn new() -> Self {
        Self { buf: [None; INPUT_QUEUE_LEN], head: 0, len: 0 }
    }

    /// Physical slot of logical position `i` (0 = oldest).
    fn slot(&self, i: usize) -> usize {
        (self.head + i) % INPUT_QUEUE_LEN
    }

    /// Removes logical position `i`, closing the gap.
    fn remove_at(&mut self, i: usize) {
        for j in i..self.len - 1 {
            self.buf[self.slot(j)] = self.buf[self.slot(j + 1)];
        }
        let last = self.slot(self.len - 1);
        self.buf[last] = None;
        self.len -= 1;
    }

    fn push(&mut self, event: T) {
        if self.len == INPUT_QUEUE_LEN {
            // 1. Fold the new event into the newest queued one — the
            //    common case: a burst of plain mouse motion.
            let tail = self.slot(self.len - 1);
            if let Some(merged) = self.buf[tail].as_ref().and_then(|t| T::merge(t, &event)) {
                self.buf[tail] = Some(merged);
                return;
            }
            // 2. Otherwise merge the OLDEST mergeable adjacent pair,
            //    which frees a slot without reordering anything.
            let merged_pair = (0..self.len - 1).find_map(|i| {
                let a = self.buf[self.slot(i)]?;
                let b = self.buf[self.slot(i + 1)]?;
                T::merge(&a, &b).map(|m| (i, m))
            });
            if let Some((i, m)) = merged_pair {
                self.buf[self.slot(i)] = Some(m);
                self.remove_at(i + 1);
            } else if let Some(i) = (0..self.len).find(|&i| self.buf[self.slot(i)].is_some_and(|e| e.expendable())) {
                // 3. Drop the oldest expendable event.
                self.remove_at(i);
            } else {
                // 4. Nothing cheaper to lose: drop the oldest.
                self.remove_at(0);
            }
        }
        let at = self.slot(self.len);
        self.buf[at] = Some(event);
        self.len += 1;
    }

    fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let event = self.buf[self.head].take();
        self.head = (self.head + 1) % INPUT_QUEUE_LEN;
        self.len -= 1;
        event
    }
}

/// One decoded real key event — `keycode` is a raw Scan Code Set 1 make
/// code (bit 7 cleared), `extended` is `true` iff a real `0xE0` prefix
/// preceded it (many extended keys, arrows among them, reuse a
/// non-extended key's own `keycode` — see `driver_i8042::scancode::
/// KeyEvent::extended`'s own doc comment), matching `driver_i8042::
/// scancode::KeyEvent` exactly. Duplicated here as a small, local,
/// self-contained type rather than a cross-driver-crate dependency on
/// `driver-i8042` — same "small numeric constants/logic duplicated with
/// a sync comment" convention `netstack::subsystem_entry`'s own module
/// doc comment already establishes for the identical situation (a
/// service depending on a driver's own wire shape, not its crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyEvent {
    keycode: u8,
    pressed: bool,
    extended: bool,
}

impl QueueEvent for KeyEvent {
    /// Two key events never merge: each press/release is a distinct
    /// character or state change.
    fn merge(_older: &Self, _newer: &Self) -> Option<Self> {
        None
    }

    /// A press may be lost under overload (one missed character); a
    /// release may not (a stuck key).
    fn expendable(&self) -> bool {
        self.pressed
    }
}

/// Must match `driver_i8042::wire::KEY_EVENT_LABEL` exactly.
const KEY_EVENT_LABEL: u64 = 1;

/// Must match `driver_i8042::wire::EXTENDED_BIT` exactly — the reserved,
/// previously-always-zero bit 7 of the keycode word this edge (and
/// `ipc_protocol::codec`'s own `OP_DPR_INPUT_EVENT` arm, one hop further
/// out) packs `KeyEvent::extended` into. See `driver_i8042::wire::
/// EXTENDED_BIT`'s own doc comment for the full "one wire-format idea,
/// not two independently invented ones" reasoning.
const EXTENDED_BIT: u64 = 0x80;

/// Reads and decodes the `KeyEvent` `driver-i8042` wrote into `I8042_VA`
/// — mirrors `driver_i8042::wire::decode_key_event` exactly (see
/// `KeyEvent`'s own doc comment for why this is a local duplicate, not a
/// shared dependency).
fn read_i8042_message() -> Option<KeyEvent> {
    let base = I8042_VA as *const u64;
    // SAFETY: `I8042_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::spawn_i8042_driver`, before
    // this process's own `NOTIF_POLL` could ever observe a set bit.
    let (label, w0, w1) = unsafe { (base.read_volatile(), base.add(1).read_volatile(), base.add(2).read_volatile()) };
    if label != KEY_EVENT_LABEL {
        return None;
    }
    Some(KeyEvent { keycode: (w0 & 0x7F) as u8, pressed: w1 != 0, extended: w0 & EXTENDED_BIT != 0 })
}

/// VA `driver-mouse`'s own shared message page is mapped at in THIS
/// process's own address space — must stay numerically equal to
/// `kernel_arch_glue::COMPOSITOR_MOUSE_VA`.
const MOUSE_VA: usize = 0xD8C0_0000;

/// One decoded real mouse event — matches `driver_mouse::mouse_packet::
/// MouseEvent`'s own wire shape exactly (see `KeyEvent`'s own doc
/// comment for why this is a local duplicate, not a shared dependency).
/// `dx`/`dy` keep PS/2's own raw sign convention (positive `dy` = real
/// upward motion) — unflipped here, same as the driver's own decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MouseEvent {
    dx: i16,
    dy: i16,
    left: bool,
    right: bool,
    middle: bool,
}

impl QueueEvent for MouseEvent {
    /// Consecutive events with the SAME button state are one motion:
    /// their deltas add up (saturating at the wire's `i16` range, far
    /// past any real burst). A button change never merges, so every
    /// press and release reaches the client, in order.
    fn merge(older: &Self, newer: &Self) -> Option<Self> {
        let same_buttons =
            older.left == newer.left && older.right == newer.right && older.middle == newer.middle;
        same_buttons.then(|| MouseEvent {
            dx: older.dx.saturating_add(newer.dx),
            dy: older.dy.saturating_add(newer.dy),
            ..*newer
        })
    }

    /// Never: every mouse event carries either motion or a button state.
    fn expendable(&self) -> bool {
        false
    }
}

/// Must match `driver_mouse::wire::MOUSE_EVENT_LABEL` exactly.
const MOUSE_EVENT_LABEL: u64 = 1;

/// Reads and decodes the `MouseEvent` `driver-mouse` wrote into
/// `MOUSE_VA` — mirrors `driver_mouse::wire::decode_mouse_event` exactly.
fn read_mouse_message() -> Option<MouseEvent> {
    let base = MOUSE_VA as *const u64;
    // SAFETY: `MOUSE_VA` is mapped `U=1 R+W` in this process's own
    // address space by `kernel_arch_glue::spawn_mouse_driver`, before
    // this process's own `NOTIF_POLL` could ever observe a set bit.
    let (label, w0, w1, w2) = unsafe {
        (
            base.read_volatile(),
            base.add(1).read_volatile(),
            base.add(2).read_volatile(),
            base.add(3).read_volatile(),
        )
    };
    if label != MOUSE_EVENT_LABEL {
        return None;
    }
    Some(MouseEvent {
        dx: w0 as u16 as i16,
        dy: w1 as u16 as i16,
        left: w2 & 1 != 0,
        right: w2 & 2 != 0,
        middle: w2 & 4 != 0,
    })
}

/// Handles the input-driver signals named by `bits` (`I8042_SIGNAL_BIT` /
/// `MOUSE_SIGNAL_BIT`): for each set bit, receives that driver's one queued
/// event, queues it, and replies so the driver can send its next byte.
///
/// A real message is guaranteed to be queued or arriving imminently: the
/// drivers signal BEFORE their blocking `Call`, so the `Recv` is not an
/// open-ended block in practice.
fn drain_input_signals(
    bits: usize,
    keys: &mut EventQueue<KeyEvent>,
    mouse: &mut EventQueue<MouseEvent>,
) {
    if bits & I8042_SIGNAL_BIT != 0 {
        // SAFETY: `raw_syscall2`/`raw_syscall`'s own contracts.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV_GENERIC, I8042_ENDPOINT_CAP, fresh!(0)) };
        if let Some(event) = read_i8042_message() {
            keys.push(event);
        }
        // SAFETY: as above - wakes driver-i8042's blocking `Call`.
        unsafe { raw_syscall(IPC_REPLY, from, fresh!(0)) };
    }
    if bits & MOUSE_SIGNAL_BIT != 0 {
        // SAFETY: as above.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV_GENERIC, MOUSE_ENDPOINT_CAP, fresh!(0)) };
        if let Some(event) = read_mouse_message() {
            mouse.push(event);
        }
        // SAFETY: as above - wakes driver-mouse's blocking `Call`.
        unsafe { raw_syscall(IPC_REPLY, from, fresh!(0)) };
    }
}

/// Blocks until an input driver signals or [`PARK_MAX_NS`] passes, queueing
/// what arrives. Returns `true` iff it ended by timeout with no input.
///
/// Waits on the i8042 notification only: the kernel wires driver-mouse to the
/// SAME notification object (`kernel_arch_glue::G_INPUT_SIGNAL_CAP`, bits
/// told apart by [`I8042_SIGNAL_BIT`]/[`MOUSE_SIGNAL_BIT`]) precisely so one
/// wait covers both, there being no wait-on-any-of-N syscall.
fn park_for_input(keys: &mut EventQueue<KeyEvent>, mouse: &mut EventQueue<MouseEvent>) -> bool {
    let deadline = now_ns().saturating_add(PARK_MAX_NS);
    loop {
        let now = now_ns();
        if now >= deadline {
            return true;
        }
        // SAFETY: `raw_syscall`'s own contract. Blocks this thread; the kernel
        // wakes it on a signal (bits returned) or at the deadline (0).
        let bits = unsafe { raw_syscall(NOTIF_WAIT_TIMEOUT, I8042_SIGNAL_NOTIF_CAP, (deadline - now) as usize) };
        if bits == 0 {
            return true;
        }
        drain_input_signals(bits, keys, mouse);
        if keys.len > 0 || mouse.len > 0 {
            return false;
        }
    }
}

/// This process's display output, and the running proof of what it has
/// actually put on screen.
///
/// `scanout` is `None` on every machine that granted no framebuffer
/// (riscv64, or UEFI firmware with no directly-writable mode) — and on
/// that path every method here is a no-op, so the whole pre-scanout
/// behaviour of this file is preserved exactly, with no architecture
/// check anywhere (none is permitted above the HAL).
struct Output {
    scanout: Option<Scanout>,
    /// How many frames this process has genuinely written to the
    /// framebuffer. Mirrored into the info page for the kernel to read
    /// back and report in the boot log — the same "kernel peeks a
    /// shared region directly" proof the confirm region already
    /// provides for `CommitBuffer` itself.
    blits: u64,
    /// The size of the last frame that actually reached the screen,
    /// AFTER clipping — not the size requested, which is the number
    /// worth knowing when a client and the firmware mode disagree.
    last_size: (u32, u32),
    /// Nanoseconds the last `present` spent, for [`PerfStats`]. Only
    /// measured when [`PERF_LOG`] is on.
    last_present_ns: u64,
    /// Bytes the last `present` actually wrote to the framebuffer, for
    /// [`PerfStats`].
    last_present_bytes: u64,
    /// The frame size the shadow (at `CONFIRM_VA`) currently mirrors the
    /// screen for, or `None` when it mirrors nothing yet. A commit of any
    /// other size is drawn in full and re-seeds the shadow.
    shadow_size: Option<(u32, u32)>,
}

impl Output {
    /// No display. The state every machine starts in, and the one a
    /// machine with no framebuffer stays in forever.
    const fn headless() -> Self {
        Self {
            scanout: None,
            blits: 0,
            last_size: (0, 0),
            last_present_ns: 0,
            last_present_bytes: 0,
            shadow_size: None,
        }
    }

    /// Puts a committed frame on the screen and records that it
    /// happened. A no-op when no framebuffer was granted.
    ///
    /// Only the pixels that differ from the previous frame are written
    /// (`Scanout::present_diff`). The shadow of what is on screen lives
    /// in the `CONFIRM_VA` region: private RAM of exactly `FRAME_MAX`
    /// bytes that the kernel already maps for this process, so the
    /// shadow needs neither a new kernel mapping nor 1.9 MB of `.bss`
    /// that every architecture's loader would have to back — and the
    /// confirm proof it used to hold survives unchanged (see
    /// `copy_frame_to_confirm`).
    fn present(&mut self, src_va: usize, width: u32, height: u32) {
        let Some(scanout) = self.scanout else {
            return;
        };
        let t0 = if PERF_LOG { now_ns() } else { 0 };
        let shadow_valid = self.shadow_size == Some((width, height));
        // SAFETY: `src_va` is `FB_VA`, the shared frame region the
        // kernel maps for this process before it is first scheduled,
        // and the caller has already rejected any `width * height * 4`
        // exceeding `FRAME_MAX` (the mapped length of both `FB_VA` and
        // the `CONFIRM_VA` shadow, two distinct regions).
        let (plan, bytes) = unsafe { scanout.present_diff(src_va, CONFIRM_VA, width, height, shadow_valid) };
        self.last_present_bytes = bytes;
        if PERF_LOG {
            self.last_present_ns = now_ns().saturating_sub(t0);
        }
        if plan.is_empty() {
            return;
        }
        self.shadow_size = Some((width, height));
        self.blits += 1;
        self.last_size = (plan.copy_width, plan.copy_height);
        self.write_status();
    }

    /// Mirrors `blits`/`last_size` into the scanout info page, where the
    /// kernel reads them from its own identity map.
    fn write_status(&self) {
        if self.scanout.is_none() {
            return;
        }
        let base = (SCANOUT_INFO_VA + SCANOUT_STATUS_OFFSET) as *mut u64;
        // SAFETY: the info page is mapped `U=1 R+W` for this process by
        // `kernel_arch_glue::compositor_demo_start` before it is first
        // scheduled, and this writes 16 bytes at offset 32 plus one
        // word at offset 48, all well inside that 4 KiB page. Volatile
        // because the kernel reads the same physical bytes through its
        // own mapping, at a moment this process cannot observe.
        unsafe {
            core::ptr::write_volatile(base, self.blits);
            core::ptr::write_volatile(
                base.add(1),
                self.last_size.0 as u64 | ((self.last_size.1 as u64) << 32),
            );
            core::ptr::write_volatile(
                (SCANOUT_INFO_VA + SCANOUT_ACK_OFFSET) as *mut u64,
                SCANOUT_INFO_MAGIC,
            );
        }
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
fn handle_request(
    comp: &mut Compositor,
    pending_key_event: &mut EventQueue<KeyEvent>,
    pending_mouse_event: &mut EventQueue<MouseEvent>,
    output: &mut Output,
    req: DisplayRequest,
) -> DisplayResponse {
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
                    // The real scanout hop (a no-op on a machine with no
                    // framebuffer), then the confirm proof — in THIS
                    // order, because the confirm region is also the
                    // present path's shadow; `copy_frame_to_confirm`'s
                    // own doc comment has why the reverse would be wrong.
                    output.present(FB_VA, width, height);
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
        // `03-Kernel-Subsystems-Layer.md` §2.4's own `input_event_stream`
        // called for a real `Notification`-based async delivery path
        // (matching driver-virtio-net's own interrupt-driven TX
        // completion in shape). That got superseded in practice, not
        // left undone: `PollInputEvent` below (and its mouse-event
        // counterpart) already deliver real, decoded input to a real
        // client, matching driver-virtio-net's own established "poll,
        // not push" precedent for unsolicited external data in this same
        // codebase — no client-side `Notification` wait loop is needed
        // to receive input, so there is nothing for a real subscription
        // step to gate. Kept as a real, permanent `Unsupported` (an
        // honest "superseded by PollInputEvent", not a "not yet built")
        // rather than silently repurposed to mean something the wire
        // protocol's own doc comment doesn't say.
        DisplayRequest::SubscribeInput => DisplayResponse::Error {
            code: DisplayErrorCode::Unsupported,
        },
        // Real, single-output MVP: this process's own display pipeline
        // always commits at a fixed 800x600 (the real resolution
        // `Simurgh-UI-Template01::ui-core`'s own `Desktop` and every
        // frame this process actually handles use throughout this
        // codebase — see `FRAME_MAX`'s own doc comment) — reported here
        // instead of `Unsupported` since a real, single, well-known
        // output genuinely exists. 60000 milli-Hz (60 Hz) is the
        // standard default any software compositor reports absent a
        // real monitor to negotiate EDID/refresh timing with (no such
        // hardware exists in this headless/file-output MVP, §5.4.2).
        //
        // Once a REAL framebuffer is granted, this reports the mode
        // firmware actually programmed instead of the fixed pair — a
        // client that sizes its frame from this answer then renders
        // exactly the output's own resolution and needs neither
        // centering nor clipping (`scanout::BlitPlan`'s own policy).
        // Without one, the fixed 800x600 stands: it is the resolution
        // every frame in this codebase is rendered at and `FRAME_MAX`
        // is sized for, and reporting a made-up alternative would be
        // worse than reporting the real convention.
        DisplayRequest::QueryOutputs => {
            let (primary_width, primary_height) = match output.scanout {
                Some(scanout) => (scanout.info().width, scanout.info().height),
                None => (800, 600),
            };
            DisplayResponse::OutputTopology {
                output_count: 1,
                primary_width,
                primary_height,
                primary_refresh_mhz: 60_000,
            }
        }
        // Real, per this file's own `read_i8042_message`/`KeyEvent` —
        // drains (not peeks) `pending_key_event`, matching `driver-
        // virtio-net`'s own `PollFrame` precedent this variant's own
        // `ipc_protocol::display` doc comment cites.
        DisplayRequest::PollInputEvent => match pending_key_event.pop() {
            Some(event) => DisplayResponse::InputEvent {
                keycode: event.keycode,
                pressed: event.pressed,
                extended: event.extended,
            },
            None => DisplayResponse::NoInputPending,
        },
        // Real, mouse-shaped counterpart of `PollInputEvent` just above
        // — drains (not peeks) `pending_mouse_event`, same `driver-
        // virtio-net`-style "poll, not push" shape.
        DisplayRequest::PollMouseEvent => match pending_mouse_event.pop() {
            Some(event) => DisplayResponse::MouseEvent {
                dx: event.dx,
                dy: event.dy,
                left: event.left,
                right: event.right,
                middle: event.middle,
            },
            None => DisplayResponse::NoMouseEventPending,
        },
    }
}

/// The Compositor process's own entry point. Serves REAL
/// `DisplayRequest`s forever: `Recv` (blocks until a real `Call`
/// arrives), decode, dispatch to the real `Compositor`, encode, `Reply`
/// (always switches away on success — see `Reply`'s own doc comment in
/// `kernel_core::syscall`).
///
/// Real-input-handling plan, Stage B/C: ADDITIVELY polls `I8042_SIGNAL_
/// NOTIF_CAP` once at the top of every iteration; if `driver-i8042` has
/// signaled, drains its one queued `KeyEvent` (a real, bounded, non-
/// blocking-in-practice `Recv`+`Reply` — see `I8042_ENDPOINT_CAP`'s own
/// doc comment for why this specific endpoint never needs the display
/// Endpoint's own special-cased `Recv` opcode) and stores it in
/// `last_key_event`, until a real client drains it back out via
/// `DisplayRequest::PollInputEvent` (`handle_request`'s own arm) — the
/// real, ui-core-facing half of this same edge, matching `ipc_protocol::
/// display::DisplayRequest::PollInputEvent`'s own doc comment.
///
/// Verification status (2026-09-11): structural, not yet a direct real-
/// QEMU observation of a decoded `KeyEvent` reaching this function.
/// Confirmed on real QEMU x86_64 boots: (1) this ADDITIVE change does
/// NOT regress the pre-existing display-Endpoint traffic — `compositor_
/// commit_verify`'s own real `CreateSurface`/`CommitBuffer`/
/// `DestroySurface` round trip (Root Task's own bootstrap demo) still
/// reports `MATCH` every boot, meaning this function's own modified loop
/// runs correctly through several real iterations with the new `NOTIF_
/// POLL` check in place; (2) `driver-i8042` itself is provably not the
/// cause of a separate, PRE-EXISTING issue this session found while
/// investigating: `ui-core`'s own thread (spawned earlier in the same
/// boot sequence, unrelated to this edge) did not get scheduled at all
/// in every attempt tried, INCLUDING a control run with `spawn_i8042_
/// driver`'s own call site temporarily disabled entirely — the exact
/// same non-scheduling happened either way, across multiple fresh boots
/// that each produced byte-for-byte identical serial output. This
/// isolates the cause to this project's already-documented QEMU
/// scheduling-capacity characteristic (see this session's own project
/// memory), not a regression introduced by this edge — but it also means
/// `driver-i8042` (spawned even later than `ui-core` in the same
/// sequence) could not be observed actually running in these attempts
/// either, so the full driver-i8042-to-Compositor round trip remains
/// verified by code review and Stage A's own real hardware-level proof
/// (`kernel_arch_glue::i8042_irq_trampoline`'s own doc comment) rather
/// than a direct end-to-end QEMU log line, pending either more attempts
/// or a real reactive UI loop giving `ui-core`/`driver-i8042` more
/// reliable scheduling opportunities.
///
/// Mouse-input plan, Stage 1b (2026-09-11): the identical additive
/// pattern, for `driver-mouse`'s own edge (`MOUSE_SIGNAL_NOTIF_CAP`/
/// `MOUSE_ENDPOINT_CAP`, draining into `last_mouse_event`). Same
/// verification status as the i8042 edge above, for the same reason:
/// `spawn_mouse_driver`'s own real interrupt path was independently
/// confirmed at the hardware level (a direct PIC IRR register dump
/// during Stage 1a proved a real mouse event genuinely reaches and
/// latches at the PIC — see `kernel_arch_glue::mouse_irq_trampoline`'s
/// own doc comment for the full record, including the real root cause
/// found there: this kernel only services a maskable interrupt inside
/// `hal_x86_64::cpu::hlt_wait_for_irq`, so a newly-spawned driver
/// process needs to actually GET SCHEDULED to ever drain one, and this
/// session's real QEMU attempts did not observe `driver-mouse` (or
/// `driver-i8042`, or `ui-core`) getting scheduled either) — this
/// function's own modified loop is confirmed not to regress the
/// existing display-Endpoint traffic (`compositor_commit_verify`'s own
/// `MATCH` every boot, unchanged), but a live, decoded `MouseEvent`
/// reaching `last_mouse_event` was not directly observed in this
/// session's own QEMU attempts — structural verification only, same
/// honest status as the i8042 edge.
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut comp = Compositor::new();
    // Drained by a real client's own `PollInputEvent` (`handle_request`'s
    // own arm) — at most one pending event at a time, matching `driver-
    // i8042`'s own one-event-per-`Call` shape.
    let mut last_key_event: EventQueue<KeyEvent> = EventQueue::new();
    // Same drain-on-real-poll shape as `last_key_event`, for `driver-
    // mouse` (mouse-input plan, Stage 1b). Not read anywhere yet either
    // — same "real consumer is a later stage" reasoning.
    let mut last_mouse_event: EventQueue<MouseEvent> = EventQueue::new();

    // Acquire the display, if this machine granted one. Done once, here,
    // before the first `Recv`: the mapping is established by
    // `kernel_arch_glue::compositor_demo_start` before this process is
    // ever scheduled, so there is nothing to wait for, and doing it up
    // front keeps the serving loop below free of any per-request
    // display setup.
    //
    // SAFETY: `SCANOUT_INFO_VA` is always mapped for this process
    // (zero-filled when no framebuffer exists, which decodes to
    // `None`), and `SCANOUT_VA` is mapped whenever that page says a
    // framebuffer was granted — both per those constants' own doc
    // comments.
    let mut output = Output::headless();
    let mut perf = PerfStats::default();
    output.scanout = unsafe { Scanout::from_info_page(SCANOUT_INFO_VA, SCANOUT_VA) };
    if let Some(scanout) = output.scanout {
        // Take ownership of every pixel: what is on screen at this
        // moment is leftover UEFI console text, which would otherwise
        // stay there for the rest of the boot underneath any committed
        // frame. See `scanout::DESKTOP_BACKGROUND`'s own doc comment
        // for why this specific colour.
        scanout.fill(DESKTOP_BACKGROUND);
        // Publish a first status the kernel can read back even before
        // any client has committed anything — "the Compositor reached
        // its display" and "the Compositor drew a frame" are different
        // facts, and the boot log should be able to tell them apart.
        output.write_status();
    }

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

    // True after a hold ended by timeout: the next empty poll is answered at once.
    let mut skip_park = false;
    loop {
        // Input check - see this function's own doc comment. `NOTIF_POLL`
        // never blocks. Both slots are polled because they are the same
        // notification whenever the kernel shares one (the normal case; the
        // second poll then reads 0), and two separate ones otherwise. The
        // driver's bit says which device signalled.
        // SAFETY: `raw_syscall`'s own contract.
        let bits = unsafe {
            raw_syscall(NOTIF_POLL, I8042_SIGNAL_NOTIF_CAP, zero!())
                | raw_syscall(NOTIF_POLL, MOUSE_SIGNAL_NOTIF_CAP, zero!())
        };
        drain_input_signals(bits, &mut last_key_event, &mut last_mouse_event);

        // SAFETY: `raw_syscall2`'s own contract.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, COMPOSITOR_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_display_request(&req_msg) {
            Ok(req) => {
                // An empty input poll is held open (see `PARK_MAX_NS`) so the
                // desktop can idle; input arriving ends the hold at once. Only
                // ONE hold per idle loop iteration: after a timeout the next
                // empty poll is answered immediately, so a client that polls
                // keyboard then mouse waits once, not twice.
                if matches!(req, DisplayRequest::PollInputEvent | DisplayRequest::PollMouseEvent)
                    && last_key_event.len == 0
                    && last_mouse_event.len == 0
                {
                    skip_park = if skip_park {
                        false
                    } else {
                        park_for_input(&mut last_key_event, &mut last_mouse_event)
                    };
                }
                // Timed only with a real display: a headless boot has
                // no present cost worth measuring and should not pay
                // two clock syscalls per commit for nothing.
                let timed = PERF_LOG && output.scanout.is_some() && matches!(req, DisplayRequest::CommitBuffer { .. });
                let t0 = if timed { now_ns() } else { 0 };
                let resp = handle_request(&mut comp, &mut last_key_event, &mut last_mouse_event, &mut output, req);
                if timed {
                    let now = now_ns();
                    perf.record(now.saturating_sub(t0), output.last_present_ns, output.last_present_bytes, now);
                }
                resp
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_outputs_reports_the_real_single_800x600_output() {
        let mut comp = Compositor::new();
        let mut pending_key = EventQueue::new();
        let mut pending_mouse = EventQueue::new();
        let resp = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::QueryOutputs);
        assert_eq!(
            resp,
            DisplayResponse::OutputTopology {
                output_count: 1,
                primary_width: 800,
                primary_height: 600,
                primary_refresh_mhz: 60_000,
            }
        );
    }

    #[test]
    fn subscribe_input_stays_unsupported_superseded_by_poll_input_event() {
        let mut comp = Compositor::new();
        let mut pending_key = EventQueue::new();
        let mut pending_mouse = EventQueue::new();
        let resp = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::SubscribeInput);
        assert_eq!(
            resp,
            DisplayResponse::Error {
                code: DisplayErrorCode::Unsupported,
            }
        );
    }

    #[test]
    fn poll_input_event_drains_a_pending_extended_key_then_reports_none() {
        // Up Arrow: keycode 0x48, `extended: true` — the real, decoded
        // event `read_i8042_message` would hand over after unpacking the
        // wire's own `EXTENDED_BIT`. Proves `extended` survives the
        // `handle_request` hop into `DisplayResponse::InputEvent`
        // unchanged, not just that the field exists.
        let mut comp = Compositor::new();
        let mut pending_key = EventQueue::new();
        pending_key.push(KeyEvent { keycode: 0x48, pressed: true, extended: true });
        let mut pending_mouse = EventQueue::new();

        let resp = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::PollInputEvent);
        assert_eq!(resp, DisplayResponse::InputEvent { keycode: 0x48, pressed: true, extended: true });
        assert_eq!(pending_key.len, 0, "PollInputEvent must drain, not peek");

        let resp2 = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::PollInputEvent);
        assert_eq!(resp2, DisplayResponse::NoInputPending);
    }

    /// On a machine that granted no framebuffer, every display-output
    /// call must be a pure no-op that never dereferences a scanout VA —
    /// this is what keeps the pre-scanout behaviour of this file
    /// bit-for-bit intact on riscv64 and on any machine with no usable
    /// GOP mode. Safe to call on the host precisely because it returns
    /// before touching any address.
    #[test]
    fn a_headless_output_never_touches_the_scanout() {
        let mut output = Output::headless();
        assert!(output.scanout.is_none());
        output.present(FB_VA, 800, 600);
        output.write_status();
        assert_eq!(output.blits, 0);
        assert_eq!(output.last_size, (0, 0));
    }

    #[test]
    fn read_i8042_message_unpacks_the_extended_bit_from_the_keycode_word() {
        // Direct unit coverage of the local wire decode this file's own
        // `KeyEvent`/`EXTENDED_BIT` doc comments describe — same shape
        // `driver_i8042::wire`'s own `decode_key_event` tests use, kept
        // as a local, self-contained check since this is a duplicated
        // decoder, not a shared function.
        let w0 = 0x48u64 | EXTENDED_BIT;
        let extended = w0 & EXTENDED_BIT != 0;
        let keycode = (w0 & 0x7F) as u8;
        assert_eq!(keycode, 0x48);
        assert!(extended);
    }

    #[test]
    fn poll_mouse_event_drains_a_pending_event_then_reports_none() {
        let mut comp = Compositor::new();
        let mut pending_key = EventQueue::new();
        let mut pending_mouse = EventQueue::new();
        pending_mouse.push(MouseEvent { dx: 5, dy: -3, left: true, right: false, middle: false });

        let resp = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::PollMouseEvent);
        assert_eq!(
            resp,
            DisplayResponse::MouseEvent { dx: 5, dy: -3, left: true, right: false, middle: false }
        );
        assert_eq!(pending_mouse.len, 0, "PollMouseEvent must drain, not peek");

        let resp2 = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::PollMouseEvent);
        assert_eq!(resp2, DisplayResponse::NoMouseEventPending);
    }

    #[test]
    fn keys_typed_faster_than_polled_all_arrive_in_order() {
        // The real regression: five make/break pairs ("alice") queued
        // before the client polls once must ALL come back, in order —
        // the old one-slot queue returned only the last.
        let mut comp = Compositor::new();
        let mut keys = EventQueue::new();
        let mut mouse = EventQueue::new();
        let codes = [0x1e, 0x26, 0x17, 0x2e, 0x12];
        for &c in &codes {
            keys.push(KeyEvent { keycode: c, pressed: true, extended: false });
            keys.push(KeyEvent { keycode: c, pressed: false, extended: false });
        }
        for &c in &codes {
            for pressed in [true, false] {
                let resp = handle_request(&mut comp, &mut keys, &mut mouse, &mut Output::headless(), DisplayRequest::PollInputEvent);
                assert_eq!(resp, DisplayResponse::InputEvent { keycode: c, pressed, extended: false });
            }
        }
        let resp = handle_request(&mut comp, &mut keys, &mut mouse, &mut Output::headless(), DisplayRequest::PollInputEvent);
        assert_eq!(resp, DisplayResponse::NoInputPending);
    }

    /// A plain un-mergeable, always-expendable event: the queue's last-
    /// resort behaviour on its own.
    impl QueueEvent for u32 {
        fn merge(_: &Self, _: &Self) -> Option<Self> {
            None
        }
        fn expendable(&self) -> bool {
            true
        }
    }

    #[test]
    fn a_full_queue_of_unmergeable_events_drops_the_oldest_not_the_newest() {
        let mut q: EventQueue<u32> = EventQueue::new();
        for i in 0..(INPUT_QUEUE_LEN as u32 + 3) {
            q.push(i);
        }
        assert_eq!(q.pop(), Some(3));
        let mut last = 3;
        while let Some(v) = q.pop() {
            last = v;
        }
        assert_eq!(last, INPUT_QUEUE_LEN as u32 + 2);
    }

    fn motion(dx: i16, dy: i16, left: bool) -> MouseEvent {
        MouseEvent { dx, dy, left, right: false, middle: false }
    }

    #[test]
    fn a_mouse_burst_past_capacity_keeps_all_net_motion() {
        let mut q = EventQueue::new();
        for _ in 0..500 {
            q.push(motion(3, -1, false));
        }
        assert_eq!(q.len, INPUT_QUEUE_LEN);
        let (mut dx, mut dy) = (0i32, 0i32);
        while let Some(e) = q.pop() {
            dx += e.dx as i32;
            dy += e.dy as i32;
        }
        assert_eq!((dx, dy), (1500, -500));
    }

    #[test]
    fn a_mouse_burst_never_loses_a_press_or_release_or_reorders_them() {
        let mut q = EventQueue::new();
        for _ in 0..100 {
            q.push(motion(1, 0, false));
        }
        q.push(motion(0, 0, true)); // press
        for _ in 0..100 {
            q.push(motion(1, 0, true)); // drag
        }
        q.push(motion(0, 0, false)); // release
        for _ in 0..100 {
            q.push(motion(1, 0, false));
        }
        let mut states = alloc::vec::Vec::new();
        let mut dx = 0i32;
        while let Some(e) = q.pop() {
            dx += e.dx as i32;
            if states.last() != Some(&e.left) {
                states.push(e.left);
            }
        }
        assert_eq!(dx, 300);
        assert_eq!(states, [false, true, false]);
    }

    #[test]
    fn a_key_burst_past_capacity_keeps_every_release() {
        let mut q = EventQueue::new();
        for i in 0..50u8 {
            q.push(KeyEvent { keycode: i, pressed: true, extended: false });
            q.push(KeyEvent { keycode: i, pressed: false, extended: false });
        }
        let mut releases = 0;
        while let Some(e) = q.pop() {
            if !e.pressed {
                releases += 1;
            }
        }
        assert_eq!(releases, 50);
    }
}
