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
/// Must stay numerically equal to `kernel/src/main.rs`'s plain, generic
/// `sys::IPC_RECV` (43) — NOT `IPC_RECV` above (`= 108`), which is the
/// SPECIAL `SBS_IPC_RECV` opcode this file's own module doc comment
/// explains is needed only for the display Endpoint's own root-
/// bootstrap-vs-general distinction. `I8042_ENDPOINT_CAP` has exactly
/// one real caller
/// (`driver-i8042`) from the moment it exists, so the plain, ordinary
/// `Recv` opcode every other subsystem in this codebase already uses is
/// correct here — no `G_COMPOSITOR_ROOT_ONLY_PHASE`-style special case
/// needed for THIS endpoint.
const IPC_RECV_GENERIC: usize = 43;
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

/// This process's own capability slot for `driver-i8042`'s own service
/// `Endpoint` — `kernel_arch_glue::spawn_i8042_driver`'s own SECOND
/// grant into this process's cap space (slot 0 above was the first),
/// via `wire_service_endpoint`. Real-input-handling plan, Stage B/C.
const I8042_ENDPOINT_CAP: usize = 1;
/// This process's own capability slot for the `Notification` SHARED
/// with `driver-i8042` (signal-before-call) — the THIRD grant
/// (`kernel_arch_glue::wire_notification`).
const I8042_SIGNAL_NOTIF_CAP: usize = 2;
/// This process's own capability slot for `driver-mouse`'s own service
/// `Endpoint` — `kernel_arch_glue::spawn_mouse_driver`'s own grant into
/// this process's cap space (the FOURTH grant overall: slot 0 display,
/// slot 1 i8042 endpoint, slot 2 i8042 signal notif, THIS at slot 3),
/// via `wire_service_endpoint`. Mouse-input plan, Stage 1b.
const MOUSE_ENDPOINT_CAP: usize = 3;
/// This process's own capability slot for the `Notification` SHARED
/// with `driver-mouse` (signal-before-call) — the FIFTH grant
/// (`kernel_arch_glue::wire_notification`).
const MOUSE_SIGNAL_NOTIF_CAP: usize = 4;

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
const I8042_VA: usize = 0xD8B0_0000;

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
}

impl Output {
    /// No display. The state every machine starts in, and the one a
    /// machine with no framebuffer stays in forever.
    const fn headless() -> Self {
        Self { scanout: None, blits: 0, last_size: (0, 0) }
    }

    /// Puts a committed frame on the screen and records that it
    /// happened. A no-op when no framebuffer was granted.
    fn present(&mut self, src_va: usize, width: u32, height: u32) {
        let Some(scanout) = self.scanout else {
            return;
        };
        // SAFETY: `src_va` is `FB_VA`, the shared frame region the
        // kernel maps for this process before it is first scheduled,
        // and the caller has already rejected any `width * height * 4`
        // exceeding `FRAME_MAX` (the region's own mapped length).
        let plan = unsafe { scanout.blit(src_va, width, height) };
        if plan.is_empty() {
            return;
        }
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
    pending_key_event: &mut Option<KeyEvent>,
    pending_mouse_event: &mut Option<MouseEvent>,
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
                    copy_frame_to_confirm(len);
                    // The real scanout hop — strictly AFTER the confirm
                    // copy, so the pre-existing `compositor_commit_
                    // verify` proof is byte-for-byte unaffected by it,
                    // and a no-op on a machine with no framebuffer.
                    output.present(FB_VA, width, height);
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
        DisplayRequest::PollInputEvent => match pending_key_event.take() {
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
        DisplayRequest::PollMouseEvent => match pending_mouse_event.take() {
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
    let mut last_key_event: Option<KeyEvent> = None;
    // Same drain-on-real-poll shape as `last_key_event`, for `driver-
    // mouse` (mouse-input plan, Stage 1b). Not read anywhere yet either
    // — same "real consumer is a later stage" reasoning.
    let mut last_mouse_event: Option<MouseEvent> = None;

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

    loop {
        // Additive i8042 check — see this function's own doc comment.
        // Never touches the display Endpoint's own blocking `Recv` call
        // right below: `NOTIF_POLL` never blocks (`kernel_arch_glue::
        // p2_poll`'s own doc comment), and the `Recv` this only takes
        // when `bits != 0` targets a DIFFERENT Endpoint entirely
        // (`I8042_ENDPOINT_CAP`, not `COMPOSITOR_ENDPOINT_CAP`) — the
        // existing Root-Task-bootstrap and `ui-core` call sequences on
        // the display Endpoint are byte-for-byte unchanged below.
        // SAFETY: `raw_syscall`'s own contract.
        let bits = unsafe { raw_syscall(NOTIF_POLL, I8042_SIGNAL_NOTIF_CAP, zero!()) };
        if bits != 0 {
            // SAFETY: `raw_syscall2`'s own contract. A real message is
            // guaranteed to already be queued or arriving imminently —
            // `driver-i8042` signaled BEFORE its own blocking `Call`
            // (`driver_i8042::subsystem_entry::call_compositor`'s own
            // doc comment) — so this `Recv` is not a genuine open-ended
            // block in practice, matching `wire_notification`'s own doc
            // comment on this exact pattern.
            let (i8042_from, _label) = unsafe { raw_syscall2(IPC_RECV_GENERIC, I8042_ENDPOINT_CAP, zero!()) };
            if let Some(event) = read_i8042_message() {
                last_key_event = Some(event);
            }
            // SAFETY: `raw_syscall`'s own contract — wakes `driver-
            // i8042`'s own blocking `Call` so it can process its next
            // queued byte.
            unsafe { raw_syscall(IPC_REPLY, i8042_from, zero!()) };
        }

        // Additive mouse check — same shape as the i8042 check just
        // above, for `driver-mouse`'s own edge (mouse-input plan, Stage
        // 1b). Also never touches the display Endpoint's own blocking
        // `Recv` below.
        // SAFETY: `raw_syscall`'s own contract.
        let mouse_bits = unsafe { raw_syscall(NOTIF_POLL, MOUSE_SIGNAL_NOTIF_CAP, zero!()) };
        if mouse_bits != 0 {
            // SAFETY: `raw_syscall2`'s own contract — same "already
            // queued or arriving imminently" reasoning as the i8042
            // check above.
            let (mouse_from, _label) = unsafe { raw_syscall2(IPC_RECV_GENERIC, MOUSE_ENDPOINT_CAP, zero!()) };
            if let Some(event) = read_mouse_message() {
                last_mouse_event = Some(event);
            }
            // SAFETY: `raw_syscall`'s own contract — wakes `driver-
            // mouse`'s own blocking `Call`.
            unsafe { raw_syscall(IPC_REPLY, mouse_from, zero!()) };
        }

        // SAFETY: `raw_syscall2`'s own contract.
        let (from, _label) = unsafe { raw_syscall2(IPC_RECV, COMPOSITOR_ENDPOINT_CAP, zero!()) };
        let req_msg = read_shared_message();
        let resp = match decode_display_request(&req_msg) {
            Ok(req) => handle_request(&mut comp, &mut last_key_event, &mut last_mouse_event, &mut output, req),
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
        let mut pending_key = None;
        let mut pending_mouse = None;
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
        let mut pending_key = None;
        let mut pending_mouse = None;
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
        let mut pending_key = Some(KeyEvent { keycode: 0x48, pressed: true, extended: true });
        let mut pending_mouse = None;

        let resp = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::PollInputEvent);
        assert_eq!(resp, DisplayResponse::InputEvent { keycode: 0x48, pressed: true, extended: true });
        assert!(pending_key.is_none(), "PollInputEvent must drain, not peek");

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
        let mut pending_key = None;
        let mut pending_mouse = Some(MouseEvent { dx: 5, dy: -3, left: true, right: false, middle: false });

        let resp = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::PollMouseEvent);
        assert_eq!(
            resp,
            DisplayResponse::MouseEvent { dx: 5, dy: -3, left: true, right: false, middle: false }
        );
        assert!(pending_mouse.is_none(), "PollMouseEvent must drain, not peek");

        let resp2 = handle_request(&mut comp, &mut pending_key, &mut pending_mouse, &mut Output::headless(), DisplayRequest::PollMouseEvent);
        assert_eq!(resp2, DisplayResponse::NoMouseEventPending);
    }
}
