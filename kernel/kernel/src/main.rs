//! ============================================================================
//! kernel  (binary)
//!
//! Purpose: the real bootable Simurgh microkernel image. Receives the HAL
//! handoff (`hal_core::HalInterface` + `hal_core::BootInfo`) via the fixed
//! `extern "Rust" fn kernel_main` symbol the `hal-<arch>` entry code calls
//! (01-HAL-Layer.md §0), runs microkernel bring-up through
//! `kernel_arch_glue::run` (build the first `UntypedMemory` objects + the
//! Root Task — 02-Microkernel-Layer.md §8.1), prints the boot report over
//! serial, and halts.
//!
//! Architecture reference: 02-Microkernel-Layer.md §8.1/§8.2; 01-HAL-Layer.md
//! §0 (HAL and the microkernel share one privileged binary; handoff is a
//! direct Rust call).
//!
//! Position in the system: the workspace's second `[[bin]]` (alongside
//! `kernel-stub`, which stays the pure HAL smoke test). Built per
//! architecture against `targets/*.json`; links exactly one `hal-<arch>`
//! crate (selected by `target_arch` in Cargo.toml) for `_start`, the boot
//! assembly, the linker script, and — being the final binary — the single
//! `#[panic_handler]`.
//!
//! Safety/invariants: the serial backends here are boot-diagnostics only,
//! identical in scope to `kernel-stub`'s; they are not real drivers.
//! ============================================================================

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::fmt::Write;
use core::panic::PanicInfo;

use hal_core::BootInfo;

// ----------------------------------------------------------------------------
// A minimal global allocator — boot-time only, for the Root Task's OWN
// policy code (`root_task::plan_boot` returns a `Vec<MemoryGrant>`).
// `kernel/*` itself stays heap-free by design (IMPLEMENTATION-PLAN.md D1);
// this exists ONLY because `root-task` — a layer-3, user-space process —
// genuinely has a heap "once it retypes some untyped memory" per that
// crate's own docs, and this binary is presently the vehicle that runs its
// boot-time planning in-kernel (MVP, before a real per-process heap wired
// through `UntypedMemory` exists). A bump allocator with no reclaim is
// deliberate and sufficient: the handful of small, short-lived boot-time
// allocations this binary makes are never freed anyway.
// ----------------------------------------------------------------------------

const BOOT_HEAP_BYTES: usize = 64 * 1024;

/// Backing storage for the bump allocator below. `.bss`, zeroed by the
/// loader — never read before being written by an allocation.
static mut BOOT_HEAP: [u8; BOOT_HEAP_BYTES] = [0; BOOT_HEAP_BYTES];

struct BumpAllocator {
    /// Byte offset of the next free slot in `BOOT_HEAP`. `AtomicUsize`
    /// purely so `alloc` can take `&self` (the `GlobalAlloc` contract) —
    /// this binary is single-core, so `Relaxed` ordering is all a bump
    /// pointer needs.
    offset: core::sync::atomic::AtomicUsize,
}

// SAFETY: `alloc`'s only memory access is through `BOOT_HEAP.as_mut_ptr()`
// at an offset this same call reserved via the atomic bump (never handed
// out to two callers — single-core, and the compare-exchange below is the
// sole writer of `offset`); `dealloc` touches nothing.
unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        use core::sync::atomic::Ordering;
        let (align, size) = (layout.align(), layout.size());
        loop {
            let cur = self.offset.load(Ordering::Relaxed);
            let aligned = (cur + align - 1) & !(align - 1);
            let Some(new_offset) = aligned.checked_add(size) else {
                return core::ptr::null_mut();
            };
            if new_offset > BOOT_HEAP_BYTES {
                return core::ptr::null_mut();
            }
            if self
                .offset
                .compare_exchange(cur, new_offset, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                // SAFETY: `aligned + size <= BOOT_HEAP_BYTES`, just checked;
                // `aligned` is a multiple of `align` by construction.
                return unsafe { core::ptr::addr_of_mut!(BOOT_HEAP).cast::<u8>().add(aligned) };
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // No reclaim — see this section's module-level doc comment.
    }
}

#[global_allocator]
static BOOT_ALLOCATOR: BumpAllocator = BumpAllocator {
    offset: core::sync::atomic::AtomicUsize::new(0),
};

// Link-only: pull in this architecture's boot assembly / `_start` /
// panic-handler-adjacent code via its `hal-<arch>` crate. Never referenced
// by type — `kernel_main` depends solely on the architecture-erased
// `hal_core::HalInterface`.
#[cfg(target_arch = "aarch64")]
use hal_arm64 as _;
#[cfg(target_arch = "riscv64")]
use hal_riscv64 as _;
#[cfg(target_arch = "x86_64")]
use hal_x86_64 as _;

/// `device-manager-bin`'s separately-built, statically-linked ELF image
/// for THIS architecture (see that crate's own doc comment —
/// "subsystems as processes" packaging, IMPLEMENTATION-PLAN.md
/// follow-up), baked into THIS binary's own `.rodata` at compile time.
/// `DEVICE_MANAGER_ELF_PATH` is set by `build.rs` after locating the
/// file built via `cargo xbuild-subsystem-device-manager-<arch>` —
/// same pattern `uefi-bootloader/src/main.rs` already uses for its own
/// embedded kernel image. One `static` for all three architectures:
/// `build.rs` selects the right pre-built artifact per `target_arch`,
/// so this line never needs a `cfg`.
static DEVICE_MANAGER_ELF: &[u8] = include_bytes!(env!("DEVICE_MANAGER_ELF_PATH"));

/// `fs-native-bin`'s own separately-built ELF image — same packaging as
/// `DEVICE_MANAGER_ELF` (see its own doc comment), the second real
/// subsystem process (03-Kernel-Subsystems-Layer.md §2.2/§5.3).
static FS_NATIVE_ELF: &[u8] = include_bytes!(env!("FS_NATIVE_ELF_PATH"));

// ----------------------------------------------------------------------------
// Minimal serial output, per architecture — identical scope to
// kernel-stub's backends (boot diagnostics only, not a driver).
// ----------------------------------------------------------------------------

struct SerialWriter;

#[cfg(target_arch = "x86_64")]
mod backend {
    //! x86_64: UART 16550 on COM1 via I/O ports.
    const COM1_PORT: u16 = 0x3F8;

    pub fn init() {
        // SAFETY: standard 16550 bring-up on COM1's fixed ISA port range,
        // universally safe on every x86_64 QEMU machine this project
        // targets — same sequence as kernel-stub's backend.
        unsafe {
            out_byte(COM1_PORT + 1, 0x00);
            out_byte(COM1_PORT + 3, 0x80);
            out_byte(COM1_PORT + 0, 0x03);
            out_byte(COM1_PORT + 1, 0x00);
            out_byte(COM1_PORT + 3, 0x03);
            out_byte(COM1_PORT + 2, 0xC7);
            out_byte(COM1_PORT + 4, 0x0B);
        }
    }

    pub fn write_byte(byte: u8) {
        // SAFETY: polling LSR bit 5 before writing THR is the standard
        // 16550 transmit sequence.
        unsafe {
            while in_byte(COM1_PORT + 5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            out_byte(COM1_PORT, byte);
        }
    }

    /// # Safety
    /// `port` must be a valid I/O port; every call site targets COM1.
    unsafe fn out_byte(port: u16, value: u8) {
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value);
        }
    }

    /// # Safety
    /// Same contract as `out_byte`.
    unsafe fn in_byte(port: u16) -> u8 {
        let value: u8;
        unsafe {
            core::arch::asm!("in al, dx", in("dx") port, out("al") value);
        }
        value
    }
}

#[cfg(target_arch = "aarch64")]
mod backend {
    //! ARM64: PL011 UART via MMIO at QEMU virt's documented default base.
    const PL011_BASE: u64 = 0x0900_0000;
    const PL011_DR: u64 = 0x000;
    const PL011_FR: u64 = 0x018;
    const PL011_FR_TXFF: u32 = 1 << 5;

    pub fn init() {
        // QEMU's virt PL011 starts enabled for polled transmit; nothing to
        // do here (same rationale as kernel-stub's backend).
    }

    pub fn write_byte(byte: u8) {
        // SAFETY: PL011_BASE is QEMU virt's fixed, documented PL011 MMIO
        // base; poll FR.TXFF before writing DR — the standard PL011
        // polled-transmit sequence. Covered by hal-arm64's boot-time
        // identity map for this MVP phase.
        unsafe {
            while (core::ptr::read_volatile((PL011_BASE + PL011_FR) as *const u32) & PL011_FR_TXFF)
                != 0
            {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile((PL011_BASE + PL011_DR) as *mut u32, byte as u32);
        }
    }
}

#[cfg(target_arch = "riscv64")]
mod backend {
    //! RISC-V: NS16550 UART via MMIO at QEMU virt's documented base
    //! (0x1000_0000). Deliberately NOT the SBI console `ecall` used by
    //! `kernel-stub`: once the microkernel runs a U-mode Root Task, an
    //! `ecall` from S-mode would trap to M-mode (SBI) while every U-mode
    //! `ecall` traps to *our* S-mode handler — mixing the two consoles
    //! is confusing and couples the kernel's own logging to firmware.
    //! MMIO polled transmit has neither problem and matches the ARM64
    //! backend's shape.
    const UART_BASE: usize = 0x1000_0000;
    const UART_THR: usize = 0x0; // transmit holding register
    const UART_LSR: usize = 0x5; // line status register
    const LSR_THRE: u8 = 1 << 5; // transmit-holding-register empty

    pub fn init() {
        // QEMU's NS16550 starts usable for polled transmit; no line-
        // control / baud programming needed for this diagnostics path.
    }

    pub fn write_byte(byte: u8) {
        // SAFETY: `UART_BASE` is QEMU virt's fixed, documented NS16550
        // MMIO base; OpenSBI leaves S/U with R/W access to it (PMP
        // region 07 in the boot log). Poll LSR.THRE before writing THR —
        // the standard 16550 polled-transmit sequence.
        unsafe {
            while core::ptr::read_volatile((UART_BASE + UART_LSR) as *const u8) & LSR_THRE == 0 {
                core::hint::spin_loop();
            }
            core::ptr::write_volatile((UART_BASE + UART_THR) as *mut u8, byte);
        }
    }
}

impl SerialWriter {
    fn init() {
        backend::init();
    }
}

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            backend::write_byte(byte);
        }
        Ok(())
    }
}

/// The logger `kernel-arch-glue` calls for Root Task / scheduler output.
fn serial_log(args: core::fmt::Arguments<'_>) {
    let mut s = SerialWriter;
    let _ = s.write_fmt(args);
}

// ----------------------------------------------------------------------------
// User-space (layer 3) Root Task + the syscall the trap handler routes to.
//
// This is the arch-specific bottom of the syscall ABI — `ecall` on RISC-V,
// analogous instructions on the others — so it lives here in the final
// binary (which is already `#[cfg(target_arch)]`-gated throughout), not in
// the architecture-erased `kernel-arch-glue`.
// ----------------------------------------------------------------------------

/// Syscall selectors (a7 on RISC-V; `rax` on x86_64; `x8` on AArch64).
/// riscv64, x86_64, and aarch64 all now run a U-mode/EL0 Root Task and
/// wire a trap handler; most of these opcodes below (everything past
/// `ALIVE`/`REPORT`) are riscv64-only demo machinery the other two
/// don't use yet.
#[cfg(any(
    target_arch = "riscv64",
    target_arch = "x86_64",
    target_arch = "aarch64"
))]
mod sys {
    /// Write `a1` bytes of UTF-8 at address `a0` to the kernel log.
    pub const DEBUG_LOG: usize = 0;
    /// Retype one `Endpoint` from the Root Task's first `UntypedMemory`
    /// capability; returns the new capability slot.
    pub const RETYPE_ENDPOINT: usize = 1;
    /// Map one fresh page at `a0` = virtual address. The kernel allocates
    /// a real physical frame from the Root Task's `UntypedMemory`, walks a
    /// genuine Sv39 leaf (`R+W+U`) for it into the Root Task's **live**
    /// page table, records it in the software `AddressSpace` model too,
    /// and returns the physical address it chose (`usize::MAX` on error).
    ///
    /// MVP: still not capability-gated per `02-Microkernel-Layer.md §6`
    /// (a real `Map` takes a `Frame` + `PageTable` capability); the frame
    /// is picked by the kernel rather than named by the caller. What is
    /// now real: the hardware mapping and `satp`.
    pub const MAP_PAGE: usize = 2;
    /// Translate `a0` = virtual address through the Root Task's address
    /// space (software model); returns the physical address, or
    /// `usize::MAX` if unmapped.
    pub const TRANSLATE: usize = 3;
    /// Map a second virtual address `a0` onto the SAME physical frame the
    /// most recent `MAP_PAGE` returned — an intra-address-space alias, the
    /// zero-copy shared-memory primitive of `02-Microkernel-Layer.md
    /// §5.2 / §8.4`. Real Sv39 leaf + model update. Returns 0 /
    /// `usize::MAX`. `a1` is ignored (the frame is kernel-tracked so a
    /// bogus physical address cannot be smuggled in).
    pub const MAP_ALIAS: usize = 4;
    /// No arguments — the kernel logs a fixed "Root Task alive under
    /// paging" line. Used by the isolated U-mode entry, which carries no
    /// string literals of its own.
    pub const ALIVE: usize = 9;
    /// `a0` = a value the kernel should echo into the log (used to report
    /// a `TRANSLATE` result from code that cannot format it itself).
    pub const REPORT: usize = 10;
    /// Cross-check a shared frame: `a0` = the physical address `MAP_PAGE`
    /// returned, `a1` = the value the Root Task read back through the
    /// alias VA. The kernel reads the SAME physical frame through its own
    /// identity map and logs whether all three views agree — the
    /// hardware-level proof behind `02-Microkernel-Layer.md §8.4`
    /// (zero-copy shared memory).
    pub const XCHECK: usize = 11;

    // -- Two-process zero-copy proof (02-Microkernel-Layer.md §8.4) --
    //
    // Cooperative hand-off between two U-mode threads living in two
    // MMU-isolated Sv39 address spaces that share exactly one physical
    // frame (mapped at a different VA in each). The kernel side is
    // `kernel_arch_glue::{p2_yield, p2_report_a, p2_report_b}`.

    /// No arguments. The calling U-mode thread is suspended (full context
    /// saved) and the *other* process is resumed in its own address
    /// space — `TrapOutcome::SwitchTo`. First `P2_YIELD` runs process A
    /// -> B; the second (from B) runs B -> A.
    pub const P2_YIELD: usize = 20;
    /// `a0` = the value process A re-read through its VA of the shared
    /// frame after process B ran. The kernel logs the final A->B->A
    /// round-trip verdict.
    pub const P2_REPORT_A: usize = 21;
    /// `a0` = the value process B read through its VA of the shared frame
    /// (which process A wrote before the first hand-off).
    pub const P2_REPORT_B: usize = 22;
    /// No arguments. The cooperative §8.4 round-trip is done — the kernel
    /// arms the supervisor timer so from here the two processes are
    /// switched by PREEMPTION (02-Microkernel-Layer.md §4), not an
    /// explicit `P2_YIELD`. Both then run unbounded counting loops.
    pub const P2_PREEMPT_START: usize = 23;

    /// `device-manager::subsystem_entry`'s state-transition report — the
    /// first REAL `subsystems/*` crate's own logic running as a spawned
    /// isolated process, not this demo's own code. Must stay numerically
    /// equal to `device_manager::subsystem_entry::DM_REPORT` (that
    /// module's own doc comment says so too — no shared protocol crate
    /// for this demo-scoped raw ABI number, same as every other opcode
    /// above). `a0` = `DriverState` discriminant, `a1` =
    /// `restarts_in_window`.
    pub const DM_REPORT: usize = 30;

    // Real IPC-driven driver supervision (03-Kernel-Subsystems-Layer.md
    // §5.2's actual acceptance test): device-manager reacts to a REAL
    // crash of `umode_faulty_driver`, not its own timer. Kernel side is
    // `kernel_arch_glue::{p2_watch_driver, p2_dm_wait_crash,
    // p2_poll_crash}` and `spawn_faulty_driver`'s respawn path.

    /// No arguments. Blocks the calling thread until the driver process
    /// `kernel_arch_glue::p2_watch_driver` currently names takes a fatal
    /// exception, or returns immediately if that already happened before
    /// this call. The caller must follow up with `DM_POLL_CRASH` to
    /// consume the crash's raw trap value.
    pub const DM_WAIT_CRASH: usize = 31;
    /// No arguments. Consumes and returns (via `a0`) the pending crash's
    /// raw `scause` value recorded by `DM_WAIT_CRASH`'s wake, or `0` if
    /// none is pending.
    pub const DM_POLL_CRASH: usize = 32;
    /// No arguments. Spawns a fresh instance of the faulty-driver demo
    /// process — the automatic-restart half of §5.2 — and re-arms
    /// `p2_watch_driver` on its new `ThreadId` (a respawned driver is a
    /// brand-new thread, not the dead one coming back).
    pub const DM_RESPAWN_DRIVER: usize = 33;

    // -- Real U-mode Call/Recv/Reply demo (02-Microkernel-Layer.md
    //    §5.1/§8.2) — unlike EVERY opcode above, these route through the
    //    REAL `kernel_core::SyscallOp::{Call,Recv,Reply}` IPC surface
    //    (`kernel_arch_glue::{p2_ipc_demo_start,p2_ipc_call,p2_ipc_recv,
    //    p2_ipc_reply}`), not ad-hoc kernel-side bookkeeping — the
    //    concrete thing the still-pending register-only IPC fast path
    //    (`kernel_ipc::fastpath`'s own doc comment) needs a genuine trap
    //    boundary to attach to and be verified against. --

    /// No arguments. Creates the demo's shared endpoint and spawns the
    /// SERVER thread (`umode_ipc_server`), then switches straight to it.
    /// The value this returns in `a0` once the caller resumes (later,
    /// after the server's own first `IPC_RECV` switches back) is
    /// meaningless — follow up with `IPC_ENDPOINT_CAP`.
    pub const IPC_DEMO_START: usize = 40;
    /// No arguments. Returns the demo endpoint's capability slot (set by
    /// `IPC_DEMO_START`) — both the client and the server call this to
    /// learn it independently; a fresh thread has no other way to learn
    /// a value computed during someone ELSE's own execution.
    pub const IPC_ENDPOINT_CAP: usize = 41;
    /// `a0` = endpoint capability slot, `a1` = request label. A REAL
    /// `SyscallOp::Call` — always blocks (per that op's own semantics)
    /// until replied to, then returns the reply label in `a0`.
    pub const IPC_CALL: usize = 42;
    /// `a0` = endpoint capability slot. A REAL `SyscallOp::Recv` —
    /// returns `(from_thread_id, label)` in `(a0, a1)` (needs
    /// `raw_syscall2`, not the ordinary single-value `raw_syscall`).
    pub const IPC_RECV: usize = 43;
    /// `a0` = the `ThreadId` `IPC_RECV` returned as `from`, `a1` = reply
    /// label. A REAL `SyscallOp::Reply` — always switches away (per that
    /// op's own semantics); the value in `a0` if this ever DID return
    /// (an error case only) is meaningless.
    pub const IPC_REPLY: usize = 44;

    // -- fs-native: the REAL FsRequest/FsResponse wire protocol over the
    //    REAL Call/Recv/Reply mechanism above (03-Kernel-Subsystems-
    //    Layer.md §2.2/§5.3) — unlike every opcode above, `.user_text`
    //    code passes only plain integers here; the real `ipc_protocol`
    //    encoding/decoding happens kernel-side, in `kernel_arch_glue`
    //    (see its own module-level doc comment on why calling
    //    `ipc_protocol::codec` directly from `.user_text` would be
    //    unsafe). --

    /// No arguments. Spawns fs-native as a genuinely isolated process
    /// (its own address + capability space, own separately-built ELF —
    /// unlike the demo IPC server's `IPC_DEMO_START`, which shares the
    /// caller's own spaces) and grants it a capability to a fresh
    /// endpoint. Returns the endpoint's capability slot IN THE CALLER's
    /// own capability space (fs-native's own copy always lands at slot
    /// 0 in ITS space — see `kernel_arch_glue::grant_cap_into`'s own
    /// doc comment for why that is deterministic, so fs-native needs no
    /// equivalent of `IPC_ENDPOINT_CAP` to discover it).
    pub const FS_DEMO_START: usize = 45;
    /// `a0` = a registered `PathId` (this MVP demo only ever registers
    /// `PathId(0)` = `/greeting`, pre-seeded by fs-native at boot),
    /// `a1` = `ipc_protocol::fs::OpenFlags` bits. Builds a REAL
    /// `FsRequest::Open`, marshals it through the shared fs page, and
    /// issues a REAL `Call` — always blocks until fs-native replies.
    pub const FS_OPEN: usize = 46;
    /// No arguments. Reads back the REAL `FsResponse` fs-native's
    /// `Reply` just wrote into the shared fs page (call this AFTER
    /// `FS_OPEN` returns, i.e. after being woken by the reply). Returns
    /// the new handle in `a0`, or `usize::MAX` on any error.
    pub const FS_OPEN_RESULT: usize = 47;
    /// `a0` = a registered `PathId`. Builds a REAL `FsRequest::Stat`.
    pub const FS_STAT: usize = 48;
    /// No arguments. Returns the file's REAL size in `a0`, or
    /// `usize::MAX` on any error.
    pub const FS_STAT_RESULT: usize = 49;
    /// `a0` = a handle `FS_OPEN_RESULT` returned. Builds a REAL
    /// `FsRequest::Close`.
    pub const FS_CLOSE: usize = 50;
    /// No arguments. Returns `1` in `a0` for a real `Closed`, `0`
    /// otherwise.
    pub const FS_CLOSE_RESULT: usize = 51;
    /// `a0` = a handle `FS_OPEN_RESULT` returned. Writes a fixed MVP test
    /// payload (`kernel_arch_glue::FS_DEMO_WRITE_DATA`) into the shared
    /// data region, then builds a REAL `FsRequest::Write` at offset 0.
    pub const FS_WRITE: usize = 52;
    /// No arguments. Returns the REAL byte count written in `a0`, or
    /// `usize::MAX` on any error.
    pub const FS_WRITE_RESULT: usize = 53;
    /// `a0` = a handle, `a1` = length to read. Builds a REAL
    /// `FsRequest::Read` at offset 0.
    pub const FS_READ: usize = 54;
    /// No arguments. Returns the REAL byte count read in `a0` (and logs
    /// a MATCH/MISMATCH verdict against the `FS_WRITE` payload — see
    /// `kernel_arch_glue::fs_read_result`'s own doc comment), or
    /// `usize::MAX` on any error.
    pub const FS_READ_RESULT: usize = 55;
}

#[cfg(target_arch = "riscv64")]
#[inline(never)]
#[link_section = ".user_text"]
unsafe fn raw_syscall(a7: usize, a0: usize, a1: usize) -> usize {
    let ret;
    // SAFETY: `ecall` from U-mode traps to our S-mode handler. For an
    // ORDINARY (non-switching) opcode this preserves every register
    // except a0.
    //
    // **Real, deep bug found via QEMU** (this session's fs-native demo
    // — the FIRST code to ever issue multiple `raw_syscall`s in a row
    // after a SWITCHING opcode, e.g. right after `IPC_CALL`): a
    // sequence like `raw_syscall(sys::IPC_CALL, ep, 0xC0FFEE);
    // raw_syscall(sys::FS_DEMO_START, 0, 0);` kept observing a1 = a
    // STALE value (the earlier call's own delivered reply data, then —
    // after various fix attempts — other garbage, including what looked
    // like a raw `satp` value) instead of the literal `0` the SECOND
    // call actually passed, for EVERY later `raw_syscall` in the same
    // function, not just the one right after the switch. Two things
    // were tried and did NOT fully fix it on their own: (1) declaring
    // `a1` `inlateout` instead of a plain `in()` operand (correct in
    // principle — it tells the compiler the asm may change `a1`, so it
    // should stop assuming a cached value survives across the ecall —
    // but the observed garbage value changed shape with each variant of
    // this fix rather than disappearing, meaning something deeper was
    // wrong); (2) explicitly re-verified `TrapFrame::A0` extraction and
    // the fast-path restore's own register offsets in `hal-riscv64`
    // (both correct, matching `RiscvUserContext`'s real field layout —
    // ruled out as the cause). What actually fixed it: `#[inline(never)]`
    // (plus `#[link_section = ".user_text"]`, mandatory once NOT
    // inlined, so this function stays in the U=1-mapped range rather
    // than landing in ordinary U=0 kernel `.text` — see `spawn_process`'s
    // own doc comment on why a call from `.user_text` into anything
    // else would fault). With `#[inline(always)]` (this function's
    // original attribute, used successfully by every OTHER opcode in
    // this project until now), LLVM under this project's pinned nightly
    // (`nightly-2025-01-15`) was producing genuinely incorrect codegen
    // for the specific combination of "inline asm with an `ecall` that
    // can switch threads" + "multiple sequential calls to the SAME
    // `#[inline(always)]` function within one large, deeply-nested
    // caller (`umode_root`)" — forcibly inlining every call site let
    // some value-tracking optimization conflate `a1`'s value ACROSS
    // call sites that must be treated as fully opaque (since the asm's
    // OWN visible side effect — a full thread switch — can change
    // ANY register the compiler didn't explicitly account for). A real
    // function call boundary (this fix) uses RISC-V's own standard
    // calling convention instead, which the compiler already treats as
    // fully clobbering `a0`-`a7` — sidestepping the bug entirely rather
    // than trying to out-annotate it. `inlateout("a1")` is kept below
    // anyway (harmless, and correct in its own right).
    let mut a1 = a1;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") a7,
            inlateout("a0") a0 => ret,
            inlateout("a1") a1,
            options(nostack),
        );
    }
    let _ = a1;
    ret
}

/// Like `raw_syscall`, but also reads back `a1` — for `IPC_RECV`, the
/// ONE opcode whose result genuinely does not fit in a single register
/// (see `TrapOutcome::Resume2`'s own doc comment). Every OTHER opcode's
/// single-value convention is `raw_syscall`'s exact `in("a1") a1`
/// (write-only from this function's perspective, discarding whatever
/// ends up there) — this is a narrow exception, not a change to the
/// general syscall ABI.
///
/// `#[inline(never)]` for the SAME reason as `raw_syscall` — see that
/// function's own extensive doc comment on the real, QEMU-found
/// miscompilation this avoids. This function's own `a1` was ALREADY
/// `inlateout` (needed for its real second return value), so it was
/// never directly OBSERVED to exhibit the bug — but the same "multiple
/// `#[inline(always)]` calls to an asm-with-a-switch function in one
/// large caller" shape applies here too, so it gets the identical fix
/// for consistency and defense-in-depth, not because it was proven
/// broken on its own.
#[cfg(target_arch = "riscv64")]
#[inline(never)]
#[link_section = ".user_text"]
unsafe fn raw_syscall2(a7: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1);
    // SAFETY: same contract as `raw_syscall` — `ecall` preserves every
    // register except a0/a1 for this opcode specifically.
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

/// The real Call/Recv/Reply demo's endpoint capability slot, set once by
/// `IPC_DEMO_START`'s handler and read by `IPC_ENDPOINT_CAP` — both the
/// client (`umode_root`) and the server (`umode_ipc_server`) call the
/// latter to learn it independently, since the server (a fresh thread)
/// has no other way to learn a value computed during the client's own
/// earlier execution.
#[cfg(target_arch = "riscv64")]
static mut G_IPC_EP: u32 = 0;

/// fs-native's endpoint capability slot IN THE CALLER's (root's) own
/// capability space, set once by `FS_DEMO_START`'s handler and read by
/// every later `FS_OPEN`/`FS_STAT`/`FS_CLOSE` handler — kept server-
/// side (unlike `G_IPC_EP`, which BOTH client and server independently
/// discover) since fs-native's own copy is a fixed, hardcoded constant
/// in its own process (`FS_ENDPOINT_CAP` in `subsystem_entry.rs`), not
/// something it needs to learn from the caller at all.
#[cfg(target_arch = "riscv64")]
static mut G_FS_EP: u32 = 0;

/// The user-space Root Task entry. Linked into `.user_text` (its own
/// U=1 R+X pages at VMA 0xC000_0000, per hal-riscv64's linker.ld) and run
/// in U-mode under Sv39 paging by `kernel-arch-glue::enter`.
///
/// Deliberately self-contained — every arg is an immediate or comes back
/// in a register — so the code is correct at its linked VA no matter
/// where the loader placed the LMA copy, and `.user_text` carries no
/// relocations to data in kernel `.rodata`. Any human-readable output is
/// produced by the kernel (`sys::ALIVE`, `sys::REPORT`).
#[cfg(target_arch = "riscv64")]
#[link_section = ".user_text"]
extern "C" fn umode_root() -> ! {
    // SAFETY: `ecall` from U-mode traps to our S-mode handler, which
    // preserves every register except a0. The two direct memory accesses
    // below go through pages the kernel maps `U=1 R+W` in response to our
    // `MAP_PAGE` / `MAP_ALIAS` calls; they are written as inline `sw`/`lw`
    // so `.user_text` stays free of calls into kernel `.text` and of any
    // relocation.
    unsafe {
        raw_syscall(sys::ALIVE, 0, 0);
        let _cap = raw_syscall(sys::RETYPE_ENDPOINT, 0, 0);

        // 1. Ask the kernel to back VA 0xD000_0000 with a real frame
        //    (genuine Sv39 leaf, U=1 R+W). `pa` is the physical address it
        //    picked.
        let pa = raw_syscall(sys::MAP_PAGE, 0xD000_0000, 0);

        // 2. Store a sentinel THROUGH the virtual address. This completes
        //    only if the PTE is real and user-writable; otherwise it
        //    faults into the kernel trap handler.
        core::arch::asm!(
            "li {t}, 0x5eed",
            "sw {t}, 0({va})",
            va = in(reg) 0xD000_0000usize,
            t = out(reg) _,
            options(nostack),
        );

        // 3. Map a SECOND VA onto the same physical frame and read the
        //    sentinel back through it — zero-copy aliasing, MMU-enforced.
        raw_syscall(sys::MAP_ALIAS, 0xD000_1000, 0);
        let via_alias: usize;
        core::arch::asm!(
            "lw {out}, 0({va})",
            va = in(reg) 0xD000_1000usize,
            out = out(reg) via_alias,
            options(nostack, readonly),
        );

        // 4. Have the kernel read the frame directly and confirm all
        //    three views agree.
        raw_syscall(sys::XCHECK, pa, via_alias);

        // 5. Two-process zero-copy proof (02-Microkernel-Layer.md §8.4).
        //    `kernel-arch-glue::enter` has already mapped ONE physical
        //    frame into BOTH this address space (at 0xC004_0000) and the
        //    isolated space B (at a different VA). Write a sentinel
        //    through our VA, then `P2_YIELD` — the kernel snapshots this
        //    thread and resumes process B in space B.
        core::arch::asm!(
            "li {t}, 0xC0DE",
            "sw {t}, 0({va})",
            va = in(reg) 0xC004_0000usize,
            t = out(reg) _,
            options(nostack),
        );
        raw_syscall(sys::P2_YIELD, 0, 0);

        // 6. Resumed here after process B ran. Re-read our VA: process B
        //    wrote 0xB00B through ITS mapping of the same frame, in a
        //    different address space, with no copy.
        let after: usize;
        core::arch::asm!(
            "lw {out}, 0({va})",
            va = in(reg) 0xC004_0000usize,
            out = out(reg) after,
            options(nostack, readonly),
        );
        raw_syscall(sys::P2_REPORT_A, after, 0);

        // 7. Real Call/Recv/Reply demo (02-Microkernel-Layer.md
        //    §5.1/§8.2) — unlike everything above (all ad-hoc raw
        //    opcodes), this exercises the REAL `kernel_core::SyscallOp`
        //    IPC surface through a genuine trap boundary (see
        //    `sys::IPC_DEMO_START`'s own doc comment: the concrete thing
        //    the still-pending register-only IPC fast path needs to
        //    attach to). `IPC_DEMO_START` spawns the server
        //    (`umode_ipc_server`) and switches straight to it; we resume
        //    here once the server's own first `IPC_RECV` finds nothing
        //    queued yet and switches back — exactly like step 5's
        //    `P2_YIELD` above, just through the real IPC opcodes instead
        //    of the demo-specific ones.
        raw_syscall(sys::IPC_DEMO_START, 0, 0);
        let ipc_ep = raw_syscall(sys::IPC_ENDPOINT_CAP, 0, 0);
        let ipc_reply = raw_syscall(sys::IPC_CALL, ipc_ep, 0xC0FFEE);
        raw_syscall(sys::REPORT, ipc_reply, 0);

        // 7b. fs-native: the REAL FsRequest/FsResponse wire protocol,
        //     over the SAME real Call/Recv/Reply mechanism, driving a
        //     REAL isolated process's REAL MemFs (03-Kernel-Subsystems-
        //     Layer.md §2.2/§5.3) — the first time this project's IPC
        //     fast path drives a genuine subsystem's own logic, not
        //     just a demo payload. Open the pre-seeded `/greeting`
        //     (PathId 0), Stat it (confirms real content-length),
        //     Close it — all three round-trip through fs-native's own
        //     isolated process and back.
        // `zero()` forces a FRESH materialization of the literal `0` at
        // every call site — **real, deep bug found via QEMU** (this
        // session's fs-native demo): LLVM's own stack-slot allocation
        // for this function, at `-O0` under this project's pinned
        // nightly, was reusing ONE stack slot across TWO logically-
        // different values — the literal `0` many `raw_syscall` calls
        // pass as an argument, AND `ipc_reply`'s own computed value
        // (`0xc0ffef`) a few lines above — apparently believing
        // (incorrectly) that once `ipc_reply`'s own live range ended,
        // the slot could be reused for later "0" arguments WITHOUT
        // actually re-writing it, leaving `ipc_reply`'s stale value in
        // place. Confirmed via disassembly: the `FS_OPEN` call site
        // loaded its own "0" argument via `ld a2, 0x30(sp); mv a1, a2`
        // from the EXACT same stack offset several EARLIER "0"
        // arguments also used — `#[inline(never)]` (kept anyway, for
        // the separate class of bug it fixes — see `raw_syscall`'s own
        // doc comment) did NOT prevent this, since the miscompilation
        // is entirely within `umode_root`'s OWN stack-slot allocation,
        // independent of whether `raw_syscall` itself is inlined. TWO
        // OTHER fixes were tried and BOTH made things WORSE in the same
        // new way: `core::hint::black_box` and `core::ptr::
        // read_volatile` are both real, un-inlined function calls under
        // this `-O0` build (`read_volatile` even includes a UB-check
        // call) — landing in ordinary kernel `.text`, so calling either
        // from `.user_text` faults immediately (confirmed via
        // disassembly: the fault PC was exactly `core::ptr::
        // read_volatile`'s own compiled body). A raw inline `asm!("",
        // ...)` block is NEVER a function call — it is always emitted
        // directly at the call site — so it is the only form of "treat
        // this value as opaque" that is safe to use here.
        macro_rules! zero {
            () => {{
                let mut v: usize = 0;
                // SAFETY: a no-op asm block with no real instructions —
                // its only purpose is the `inout` operand, which forces
                // the compiler to treat `v` as unknown/possibly-changed
                // after this point, so it cannot fold or reuse a stale
                // stack slot for the value used below.
                core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
                v
            }};
        }
        raw_syscall(sys::FS_DEMO_START, zero!(), zero!());
        raw_syscall(sys::FS_OPEN, zero!(), zero!() | 2); // path=0 ("/greeting"), flags=WRITE (real Write demo below needs it)
        let fs_handle = raw_syscall(sys::FS_OPEN_RESULT, zero!(), zero!());
        raw_syscall(sys::REPORT, fs_handle, zero!());
        raw_syscall(sys::FS_STAT, zero!(), zero!()); // path=0
        let fs_size = raw_syscall(sys::FS_STAT_RESULT, zero!(), zero!());
        raw_syscall(sys::REPORT, fs_size, zero!());
        raw_syscall(sys::FS_WRITE, fs_handle, zero!());
        let fs_written = raw_syscall(sys::FS_WRITE_RESULT, zero!(), zero!());
        raw_syscall(sys::REPORT, fs_written, zero!());
        raw_syscall(sys::FS_READ, fs_handle, fs_written);
        let fs_read = raw_syscall(sys::FS_READ_RESULT, zero!(), zero!());
        raw_syscall(sys::REPORT, fs_read, zero!());
        raw_syscall(sys::FS_CLOSE, fs_handle, zero!());
        let fs_closed = raw_syscall(sys::FS_CLOSE_RESULT, zero!(), zero!());
        raw_syscall(sys::REPORT, fs_closed, zero!());

        // 8. Preemption phase (02-Microkernel-Layer.md §4). Ask the
        //    kernel to arm the supervisor timer, then loop forever
        //    bumping this process's private counter word in the shared
        //    frame (offset +8). From here NO `P2_YIELD` is issued — the
        //    timer interrupt alone switches between this process and the
        //    worker. Hand-written `lw`/`addi`/`sw` (NOT
        //    `core::ptr::*_volatile`, which a debug build compiles to a
        //    call into kernel `.text` that U-mode cannot execute) so
        //    `.user_text` stays call- and relocation-free.
        raw_syscall(sys::P2_PREEMPT_START, 0, 0);
        core::arch::asm!(
            "2:",
            "lw   t0, 0(t1)",
            "addi t0, t0, 1",
            "sw   t0, 0(t1)",
            "j    2b",
            in("t1") 0xC004_0008usize,
            options(noreturn),
        );
    }
}

/// The SECOND user-space process (02-Microkernel-Layer.md §8.4). Linked
/// into the same `.user_text` pages as `umode_root` but run in its OWN
/// isolated Sv39 address space (space B) on its own stack by
/// `kernel-arch-glue::enter`. Reads the shared frame through space B's VA
/// (0xC020_0000), reports what it saw, writes its own sentinel back, and
/// hands the core to process A. Self-contained: immediates only, no
/// relocations, any human-readable output produced by the kernel.
#[cfg(target_arch = "riscv64")]
#[link_section = ".user_text"]
extern "C" fn umode_worker() -> ! {
    // SAFETY: `ecall` traps to our S-mode handler; the `lw`/`sw` go
    // through 0xC020_0000, which `enter` mapped `U=1 R+W` onto the shared
    // physical frame in space B's page table.
    unsafe {
        // 1. Read what process A wrote (0xC0DE) through space A's VA —
        //    seen here via space B's independent mapping of the frame.
        let seen: usize;
        core::arch::asm!(
            "lw {out}, 0({va})",
            va = in(reg) 0xC020_0000usize,
            out = out(reg) seen,
            options(nostack, readonly),
        );
        raw_syscall(sys::P2_REPORT_B, seen, 0);

        // 2. Write our own sentinel back through space B's VA.
        core::arch::asm!(
            "li {t}, 0xB00B",
            "sw {t}, 0({va})",
            va = in(reg) 0xC020_0000usize,
            t = out(reg) _,
            options(nostack),
        );

        // 3. Hand the core back to process A for its final §8.4 check.
        raw_syscall(sys::P2_YIELD, 0, 0);

        // 4. Resumed here (either by that hand-off's partner, or — once
        //    process A calls P2_PREEMPT_START — by a timer tick). Loop
        //    forever bumping this process's private counter word in the
        //    shared frame (offset +12), issuing NO `P2_YIELD`. If the
        //    kernel's tick handler is switching us in and out this
        //    counter climbs; if it were not, it would stay 0. Inline
        //    `lw`/`addi`/`sw` for the same reason as `umode_root`'s loop.
        core::arch::asm!(
            "2:",
            "lw   t0, 0(t1)",
            "addi t0, t0, 1",
            "sw   t0, 0(t1)",
            "j    2b",
            in("t1") 0xC020_000Cusize,
            options(noreturn),
        );
    }
}

/// A THIRD user-space process, spawned via `kernel_arch_glue::
/// spawn_process` (the generic path, not `umode_root`/`umode_worker`'s
/// hand-written A/B setup) into its OWN isolated Sv39 address space AND
/// its OWN capability space — proof that process creation generalizes
/// beyond the fixed two-process §8.4 proof (a step toward
/// 03-Kernel-Subsystems-Layer.md §5's subsystems-as-processes). Shares
/// `.user_text` with the other two (no separate subsystem binary yet).
///
/// Needs no endpoint/IPC of its own for this demo — it just bumps a
/// private counter word at a fixed low address inside its OWN stack
/// region (safe because this loop pushes no stack frame: pure register
/// ops, so nothing else ever touches that address). `kernel-arch-glue`
/// reads the SAME word later through the kernel's own identity map,
/// using the physical address `spawn_process` returned, not this VA.
#[cfg(target_arch = "riscv64")]
#[link_section = ".user_text"]
extern "C" fn umode_subsystem() -> ! {
    // SAFETY: `t1` addresses the low end of this process's own `U=1 R+W`
    // stack mapping (`kernel_arch_glue::spawn_process` set it up); pure
    // register ops, no stack frame, no relocation.
    unsafe {
        core::arch::asm!(
            "2:",
            "lw   t0, 0(t1)",
            "addi t0, t0, 1",
            "sw   t0, 0(t1)",
            "j    2b",
            in("t1") 0xC030_0000usize,
            options(noreturn),
        );
    }
}

/// The real Call/Recv/Reply demo's SERVER (02-Microkernel-Layer.md
/// §5.1/§8.2 — see `sys::IPC_DEMO_START`'s own doc comment). Spawned by
/// `kernel_arch_glue::p2_ipc_demo_start`, sharing `umode_root`'s OWN
/// address space (not a separate isolated one — this demo is about the
/// IPC mechanism itself, not process isolation, which is already proven
/// elsewhere by process B / process C / device-manager). Blocks in
/// `IPC_RECV`, replies with `label + 1` once a request arrives, then
/// parks — its one job is done (a single round trip is enough to prove
/// the real trap boundary works; looping this into a timed benchmark
/// the way §8.3's in-kernel one already does is a natural follow-up,
/// not attempted here).
#[cfg(target_arch = "riscv64")]
#[link_section = ".user_text"]
extern "C" fn umode_ipc_server() -> ! {
    // SAFETY: `ecall` traps to our S-mode handler; pure register ops, no
    // stack frame, no relocation — same convention every other
    // `.user_text` function here follows.
    unsafe {
        let ep = raw_syscall(sys::IPC_ENDPOINT_CAP, 0, 0);
        let (from, label) = raw_syscall2(sys::IPC_RECV, ep, 0);
        raw_syscall(sys::IPC_REPLY, from, label.wrapping_add(1));
        // `IPC_REPLY` always switches away on success (see its own doc
        // comment) — unreachable in that case; this is the fallback for
        // the error case (a malformed `from`, say), so this thread
        // parks instead of running off the end of the function.
        core::arch::asm!("2:", "j 2b", options(noreturn));
    }
}

/// Process A's preemptive-phase counting loop, run by a FRESH thread
/// `kernel_arch_glue::p2_preempt_start` spawns to share root's own
/// address space (not `umode_root` continuing to run itself — see that
/// function's doc comment on why root's own vruntime-loaded TCB is
/// retired instead of reused). Bumps the SAME counter word `umode_root`
/// would have (`P2_VA_A_CONST + 8`), since it runs in the SAME space A.
#[cfg(target_arch = "riscv64")]
#[link_section = ".user_text"]
extern "C" fn umode_a_loop() -> ! {
    // SAFETY: `t1` addresses `0xC004_0008`, mapped `U=1 R+W` in space A by
    // `enter`/`umode_root`'s own setup; pure register ops, no stack frame.
    unsafe {
        core::arch::asm!(
            "2:",
            "lw   t0, 0(t1)",
            "addi t0, t0, 1",
            "sw   t0, 0(t1)",
            "j    2b",
            in("t1") 0xC004_0008usize,
            options(noreturn),
        );
    }
}

/// Deliberately-crashing "driver" process — the 03-Kernel-Subsystems-
/// Layer.md §5.2 acceptance-test demo: "inject a panic in a driver,
/// prove the rest of the system is unaffected". Executes an illegal
/// instruction the instant it is scheduled, taking a synchronous U-mode
/// exception (scause=2) that `hal_riscv64`'s trap vector routes to the
/// registered `FaultHandler` (`simurgh_fault` -> `kernel_arch_glue::
/// p2_fault` -> `KernelState::terminate_thread`) instead of halting the
/// system — proving per-thread fault isolation end-to-end, not just at
/// the unit-test level (`kernel-core`'s `terminate_thread` tests already
/// cover the state-machine in isolation).
#[cfg(target_arch = "riscv64")]
#[link_section = ".user_text"]
extern "C" fn umode_faulty_driver() -> ! {
    // SAFETY: `.word 0` is not a valid RV64GC instruction encoding —
    // deliberately triggers an illegal-instruction exception, which is
    // the entire point of this process. `options(noreturn)` is honest:
    // control never falls through this instruction (the thread is
    // terminated by the fault handler and never resumed).
    unsafe {
        core::arch::asm!(".word 0", options(noreturn));
    }
}

/// Placeholder U-mode entry for architectures whose real-kernel boot is
/// not yet wired (none currently — riscv64, x86_64, and aarch64 all
/// have their own `umode_root_*` below; kept for forward-compatibility
/// with a future fourth architecture).
#[cfg(not(any(
    target_arch = "riscv64",
    target_arch = "x86_64",
    target_arch = "aarch64"
)))]
extern "C" fn umode_root() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// # Safety
/// `int 0x80` from Ring 3 traps to the dedicated DPL-3 gate
/// (`hal_x86_64::cpu`'s `isr_syscall_trampoline`), which preserves every
/// register except `rax` (the return value) — this project's own
/// convention (see `hal_x86_64::cpu::SyscallHandler`'s doc comment):
/// `rax` = opcode, `rdi` = a0, `rsi` = a1.
///
/// `#[inline(never)]` (+ mandatory `#[link_section = ".user_text"]`,
/// since a non-inlined function must stay in the U=1-mapped range
/// itself): see riscv64's own `raw_syscall`'s extensive doc comment for
/// the real, QEMU-found miscompilation this avoids — LLVM under this
/// project's pinned nightly produced incorrect codegen for multiple
/// sequential calls to an `#[inline(always)]` function wrapping an asm
/// block that can switch threads (this specific x86_64 arm was not
/// independently exercised/observed broken, but gets the identical
/// preventive fix for consistency).
#[cfg(target_arch = "x86_64")]
#[inline(never)]
#[link_section = ".user_text"]
unsafe fn raw_syscall_x86(opcode: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") opcode => ret,
            in("rdi") a0,
            in("rsi") a1,
            options(nostack),
        );
    }
    ret
}

/// Like `raw_syscall_x86`, but also reads back `rsi` — for `IPC_RECV`,
/// the ONE opcode whose result genuinely does not fit in a single
/// register (see `hal_x86_64::cpu::TrapOutcome::Resume2`'s own doc
/// comment). Mirrors riscv64's own `raw_syscall2` exactly, just with
/// `rsi` (this project's own `a1` register on x86_64) in place of `a1`.
///
/// # Safety
/// Same contract as `raw_syscall_x86` — `int 0x80` preserves every
/// register except `rax`/`rsi` for this opcode specifically.
///
/// `#[inline(never)]` — see `raw_syscall_x86`'s own doc comment.
#[cfg(target_arch = "x86_64")]
#[inline(never)]
#[link_section = ".user_text"]
unsafe fn raw_syscall2_x86(opcode: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1): (usize, usize);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") opcode => r0,
            in("rdi") a0,
            inlateout("rsi") a1 => r1,
            options(nostack),
        );
    }
    (r0, r1)
}

/// The real Call/Recv/Reply demo's endpoint capability slot, set once by
/// `IPC_DEMO_START`'s handler and read by `IPC_ENDPOINT_CAP` — both the
/// client (`umode_root_x86`) and the server (`umode_ipc_server_x86`)
/// call the latter to learn it independently. Mirrors riscv64's own
/// `G_IPC_EP` exactly.
#[cfg(target_arch = "x86_64")]
static mut G_IPC_EP_X86: u32 = 0;

/// fs-native's endpoint capability slot in the caller's (root's) own
/// capability space — mirrors riscv64's own `G_FS_EP` exactly (see that
/// static's own doc comment).
#[cfg(target_arch = "x86_64")]
static mut G_FS_EP_X86: u32 = 0;

/// The x86_64 Root Task entry. Linked into `.user_text` (its own
/// `U=1` `R+X` pages at the linked VMA, per hal-x86_64's linker.ld) and
/// run in Ring 3 by `kernel-arch-glue::enter`. Extends the original
/// minimal ALIVE/REPORT proof with the cooperative two-process §8.4
/// round-trip (mirroring riscv64's own `umode_root` steps 5-6 exactly —
/// steps 1-4 there, MAP_PAGE/MAP_ALIAS/XCHECK, are riscv64-only demo
/// machinery this milestone does not need: real paging correctness was
/// already proven independently via `x86_64_paging_selftest`, entirely
/// in Ring 0). Deliberately still self-contained: every VA is an
/// immediate, matching riscv64's own "`.user_text` stays relocation-
/// free" discipline.
#[cfg(target_arch = "x86_64")]
#[link_section = ".user_text"]
extern "C" fn umode_root_x86() -> ! {
    // SAFETY: see `raw_syscall_x86`'s own contract. The memory accesses
    // below go through `P2_VA_A_CONST` (0xC0040000, a `kernel-arch-
    // glue`-owned constant — see `setup_two_process`), which `enter`
    // maps `U=1 R+W` onto the frame shared with process B.
    unsafe {
        raw_syscall_x86(sys::ALIVE, 0, 0);
        raw_syscall_x86(sys::REPORT, 0x5eed_5eed, 0);

        // 1. Write a sentinel through OUR mapping of the shared frame,
        //    then `P2_YIELD` — the kernel snapshots this thread and
        //    resumes process B in its own isolated space.
        core::arch::asm!(
            "mov dword ptr [{va}], 0xC0DE",
            va = in(reg) 0xC004_0000u64,
            options(nostack),
        );
        raw_syscall_x86(sys::P2_YIELD, 0, 0);

        // 2. Resumed here after process B ran. Re-read our VA: process B
        //    wrote 0xB00B through ITS OWN mapping of the same frame, in
        //    a different address space, with no copy.
        let after: usize;
        core::arch::asm!(
            "mov {out:e}, dword ptr [{va}]",
            va = in(reg) 0xC004_0000u64,
            out = out(reg) after,
            options(nostack, readonly),
        );
        raw_syscall_x86(sys::P2_REPORT_A, after, 0);

        // 3. Real Call/Recv/Reply demo (02-Microkernel-Layer.md
        //    §5.1/§8.2) — unlike everything above (all ad-hoc raw
        //    opcodes), this exercises the REAL `kernel_core::SyscallOp`
        //    IPC surface through a genuine trap boundary. Mirrors
        //    riscv64's own `umode_root` step 7 exactly: `IPC_DEMO_START`
        //    spawns the server (`umode_ipc_server_x86`) and switches
        //    straight to it; we resume here once the server's own first
        //    `IPC_RECV` finds nothing queued yet and switches back.
        raw_syscall_x86(sys::IPC_DEMO_START, 0, 0);
        let ipc_ep = raw_syscall_x86(sys::IPC_ENDPOINT_CAP, 0, 0);
        let ipc_reply = raw_syscall_x86(sys::IPC_CALL, ipc_ep, 0xC0FFEE);
        raw_syscall_x86(sys::REPORT, ipc_reply, 0);

        // 7b. fs-native: the REAL FsRequest/FsResponse wire protocol,
        //     over the SAME real Call/Recv/Reply mechanism, driving a
        //     REAL isolated process's REAL MemFs (03-Kernel-Subsystems-
        //     Layer.md §2.2/§5.3) — mirrors riscv64's own `umode_root`
        //     step 7b exactly (see its own doc comment). `zero!()`:
        //     same stack-slot-reuse miscompilation riscv64's own comment
        //     documents in full — not independently observed broken on
        //     this arch, but applied for the identical preventive
        //     reason `#[inline(never)]` was applied to `raw_syscall_x86`
        //     itself (both are defense against the SAME LLVM `-O0`
        //     behavior, which is a compiler/optimization-level property,
        //     not an ISA one).
        macro_rules! zero {
            () => {{
                let mut v: usize = 0;
                // SAFETY: a no-op asm block — see riscv64's own
                // `umode_root`'s identical macro for the full rationale.
                core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
                v
            }};
        }
        raw_syscall_x86(sys::FS_DEMO_START, zero!(), zero!());
        raw_syscall_x86(sys::FS_OPEN, zero!(), zero!() | 2); // path=0 ("/greeting"), flags=WRITE (real Write demo below needs it)
        let fs_handle = raw_syscall_x86(sys::FS_OPEN_RESULT, zero!(), zero!());
        raw_syscall_x86(sys::REPORT, fs_handle, zero!());
        raw_syscall_x86(sys::FS_STAT, zero!(), zero!()); // path=0
        let fs_size = raw_syscall_x86(sys::FS_STAT_RESULT, zero!(), zero!());
        raw_syscall_x86(sys::REPORT, fs_size, zero!());
        raw_syscall_x86(sys::FS_WRITE, fs_handle, zero!());
        let fs_written = raw_syscall_x86(sys::FS_WRITE_RESULT, zero!(), zero!());
        raw_syscall_x86(sys::REPORT, fs_written, zero!());
        raw_syscall_x86(sys::FS_READ, fs_handle, fs_written);
        let fs_read = raw_syscall_x86(sys::FS_READ_RESULT, zero!(), zero!());
        raw_syscall_x86(sys::REPORT, fs_read, zero!());
        raw_syscall_x86(sys::FS_CLOSE, fs_handle, zero!());
        let fs_closed = raw_syscall_x86(sys::FS_CLOSE_RESULT, zero!(), zero!());
        raw_syscall_x86(sys::REPORT, fs_closed, zero!());

        // 8. Preemption phase (02-Microkernel-Layer.md §4). Ask the
        //    kernel to arm the LAPIC timer, then loop forever bumping
        //    this process's private counter word in the shared frame
        //    (offset +8). From here NO `P2_YIELD` is issued — the timer
        //    interrupt alone switches between this process and the
        //    worker. In practice `kernel_arch_glue::p2_preempt_start`
        //    always switches AWAY to a fresh thread sharing this same
        //    address space before this `int 0x80` ever returns (see its
        //    own doc comment on why root's own vruntime-loaded TCB is
        //    retired rather than reused) — this loop is the fallback
        //    for the rare case that spawn fails, mirroring riscv64's/
        //    aarch64's own identical tail exactly.
        raw_syscall_x86(sys::P2_PREEMPT_START, 0, 0);
        // Address in a HARDCODED `ecx` (loaded once, up front), data in
        // hardcoded `eax` — two DISTINCT physical registers, neither
        // left to the compiler's own choice. **Two real bugs found via
        // QEMU** (this session's x86_64 preemption work), in order:
        // 1. The original `va = in(reg) ...` let the compiler pick ANY
        //    register for `{va}`, with nothing reserving `eax` (already
        //    hardcoded as the DATA register in `add eax, 1`) against
        //    being that same choice — it picked `rax`, so `mov eax,
        //    [{va}]` clobbered the address with the just-loaded data
        //    before `mov [{va}], eax` ran, writing the counter's VALUE
        //    to whatever address that value looked like (Ring-3 `#PF`,
        //    error_code=0x7, cr2=0x1, on this loop's very first
        //    iteration — deterministic, not QEMU-timing luck).
        // 2. Switching to `va = const` (substituting the address
        //    directly as a `[disp32]` memory operand, no register at
        //    all) traded that for a SECOND bug: x86-64's base-less
        //    `[disp32]` addressing form SIGN-EXTENDS the 32-bit
        //    displacement to 64 bits, and `0xC0040008`'s high bit is
        //    set — the CPU actually faulted on `0xffffffffC0040008`
        //    (confirmed via this session's own `cr2` exception dump).
        //    Loading the same immediate into a register with `mov
        //    ecx, imm32` instead ZERO-extends (every 32-bit `mov` into
        //    a GPR clears the upper 32 bits on x86-64), giving the
        //    correct unsigned address with no sign-extension trap.
        core::arch::asm!(
            "mov ecx, {va}",
            "2:",
            "mov eax, dword ptr [rcx]",
            "add eax, 1",
            "mov dword ptr [rcx], eax",
            "jmp 2b",
            va = const 0xC004_0008u32,
            options(noreturn),
        );
    }
}

/// The SECOND user-space process (02-Microkernel-Layer.md §8.4). Linked
/// into the same `.user_text` pages as `umode_root_x86` but run in its
/// OWN isolated address space (space B) on its own stack by
/// `kernel-arch-glue::setup_two_process`. Mirrors hal-riscv64's
/// `umode_worker` steps 1-4 exactly, including the preemptive-phase
/// counting-loop tail.
#[cfg(target_arch = "x86_64")]
#[link_section = ".user_text"]
extern "C" fn umode_worker_x86() -> ! {
    // SAFETY: `int 0x80` traps to our dedicated DPL-3 gate; the memory
    // accesses go through `P2_VA_B_CONST` (0xC0200000), which `enter`
    // maps `U=1 R+W` onto the SAME physical frame as A's own
    // `P2_VA_A_CONST` mapping, at a different VA in this isolated space.
    unsafe {
        let seen: usize;
        core::arch::asm!(
            "mov {out:e}, dword ptr [{va}]",
            va = in(reg) 0xC020_0000u64,
            out = out(reg) seen,
            options(nostack, readonly),
        );
        raw_syscall_x86(sys::P2_REPORT_B, seen, 0);

        core::arch::asm!(
            "mov dword ptr [{va}], 0xB00B",
            va = in(reg) 0xC020_0000u64,
            options(nostack),
        );

        // 3. Hand the core back to process A for its final §8.4 check.
        raw_syscall_x86(sys::P2_YIELD, 0, 0);

        // 4. Resumed here (either by that hand-off's partner, or — once
        //    process A calls P2_PREEMPT_START — by a timer tick). Loop
        //    forever bumping this process's private counter word in the
        //    shared frame (offset +12), issuing NO further `P2_YIELD`.
        // Hardcoded `ecx` (address) + `eax` (data) — see `umode_root_x86`'s
        // tail loop for the two register/sign-extension bugs this avoids.
        core::arch::asm!(
            "mov ecx, {va}",
            "2:",
            "mov eax, dword ptr [rcx]",
            "add eax, 1",
            "mov dword ptr [rcx], eax",
            "jmp 2b",
            va = const 0xC020_000Cu32,
            options(noreturn),
        );
    }
}

/// A THIRD user-space process, spawned via `kernel_arch_glue::
/// spawn_process` (the generic path, not `umode_root_x86`/`umode_
/// worker_x86`'s hand-written A/B setup) into its OWN isolated address
/// space AND its OWN capability space — proof that process creation
/// generalizes beyond the fixed two-process §8.4 proof. Mirrors
/// riscv64's `umode_subsystem`/aarch64's `umode_subsystem_aarch64`
/// exactly: bumps a private counter word at a fixed low address inside
/// its OWN stack region (safe because this loop pushes no stack frame —
/// pure register ops).
#[cfg(target_arch = "x86_64")]
#[link_section = ".user_text"]
extern "C" fn umode_subsystem_x86() -> ! {
    // SAFETY: the address is the low end of this process's own `U=1
    // R+W` stack mapping (`kernel_arch_glue::spawn_process` set it up);
    // pure register ops, no stack frame, no relocation.
    unsafe {
        // Hardcoded `ecx` (address) + `eax` (data) — see `umode_root_x86`'s
        // tail loop for the two register/sign-extension bugs this avoids.
        core::arch::asm!(
            "mov ecx, {va}",
            "2:",
            "mov eax, dword ptr [rcx]",
            "add eax, 1",
            "mov dword ptr [rcx], eax",
            "jmp 2b",
            va = const 0xC030_0000u32,
            options(noreturn),
        );
    }
}

/// Process A's preemptive-phase counting loop, run by a FRESH thread
/// `kernel_arch_glue::p2_preempt_start` spawns to share root's own
/// address space (not `umode_root_x86` continuing to run itself — see
/// that function's doc comment on why root's own vruntime-loaded TCB is
/// retired instead of reused). Bumps the SAME counter word `umode_
/// root_x86` would have (`P2_VA_A_CONST + 8`), since it runs in the
/// SAME space A. Mirrors riscv64's `umode_a_loop`/aarch64's `umode_
/// a_loop_aarch64` exactly.
#[cfg(target_arch = "x86_64")]
#[link_section = ".user_text"]
extern "C" fn umode_a_loop_x86() -> ! {
    // SAFETY: the address is mapped `U=1 R+W` in space A by `enter`/
    // `umode_root_x86`'s own setup; pure register ops, no stack frame.
    unsafe {
        // Hardcoded `ecx` (address) + `eax` (data) — see `umode_root_x86`'s
        // tail loop for the two register/sign-extension bugs this avoids
        // (this exact function is where the first of the two was
        // originally found, via QEMU).
        core::arch::asm!(
            "mov ecx, {va}",
            "2:",
            "mov eax, dword ptr [rcx]",
            "add eax, 1",
            "mov dword ptr [rcx], eax",
            "jmp 2b",
            va = const 0xC004_0008u32,
            options(noreturn),
        );
    }
}

/// Deliberately-crashing "driver" process — the 03-Kernel-Subsystems-
/// Layer.md §5.2 acceptance-test demo: "inject a panic in a driver,
/// prove the rest of the system is unaffected". Executes `ud2`
/// (Invalid Opcode, `#UD`) the instant it is scheduled, taking a
/// synchronous Ring-3 exception that `hal_x86_64`'s dedicated fault
/// trampoline routes to the registered `FaultHandler`
/// (`simurgh_fault_x86` -> `kernel_arch_glue::p2_fault` ->
/// `KernelState::terminate_thread`/`terminate_thread_and_handoff`)
/// instead of halting the system — mirrors hal-riscv64's
/// `umode_faulty_driver` (`.word 0`) exactly, just with x86_64's own
/// ISA-guaranteed-invalid encoding.
#[cfg(target_arch = "x86_64")]
#[link_section = ".user_text"]
extern "C" fn umode_faulty_driver_x86() -> ! {
    // SAFETY: `ud2` is not a valid instruction encoding by design —
    // deliberately triggers `#UD`, the entire point of this process.
    // `options(noreturn)` is honest: control never falls through (the
    // thread is terminated by the fault handler and never resumes).
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}

/// The real Call/Recv/Reply demo's SERVER (02-Microkernel-Layer.md
/// §5.1/§8.2 — see `sys::IPC_DEMO_START`'s own doc comment). Spawned by
/// `kernel_arch_glue::p2_ipc_demo_start`, sharing `umode_root_x86`'s OWN
/// address space. Mirrors riscv64's own `umode_ipc_server` exactly.
#[cfg(target_arch = "x86_64")]
#[link_section = ".user_text"]
extern "C" fn umode_ipc_server_x86() -> ! {
    // SAFETY: `int 0x80` traps to our dedicated DPL-3 gate; pure
    // register ops, no stack frame, no relocation — same convention
    // every other `.user_text` function here follows.
    unsafe {
        let ep = raw_syscall_x86(sys::IPC_ENDPOINT_CAP, 0, 0);
        let (from, label) = raw_syscall2_x86(sys::IPC_RECV, ep, 0);
        raw_syscall_x86(sys::IPC_REPLY, from, label.wrapping_add(1));
        // `IPC_REPLY` always switches away on success (see its own doc
        // comment) — unreachable in that case; this is the fallback for
        // the error case, so this thread parks instead of running off
        // the end of the function.
        core::arch::asm!("2:", "jmp 2b", options(noreturn));
    }
}

/// The syscall handler `hal_x86_64::cpu`'s dedicated `int 0x80`
/// trampoline calls for a syscall from U-mode. Runs at Ring 0.
#[cfg(target_arch = "x86_64")]
fn simurgh_syscall_x86(a7: usize, a0: usize, a1: usize) -> hal_x86_64::cpu::TrapOutcome {
    use hal_x86_64::cpu::TrapOutcome;

    // Two-process hand-off / device-manager supervision arms resolve to
    // a non-`Resume` outcome — mirrors `simurgh_syscall`'s (riscv64)
    // own dispatch order exactly.
    match a7 {
        sys::P2_YIELD => {
            return match kernel_arch_glue::p2_yield() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::P2_REPORT_A => {
            kernel_arch_glue::p2_report_a(a0);
            return TrapOutcome::Resume(0);
        }
        // Real Call/Recv/Reply demo (see `sys::IPC_DEMO_START`'s own doc
        // comment) — mirrors `simurgh_syscall` (riscv64)'s own IPC arms
        // exactly, including using `kstate().sched.running()` (not the
        // hardcoded root thread every OTHER opcode here uses) since
        // IPC_RECV/IPC_REPLY are called by the server thread too.
        sys::IPC_DEMO_START => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_demo_start(hal, caller, umode_ipc_server_x86 as usize) {
                Some((ep, save, into)) => {
                    // SAFETY: single-core; only this arm writes
                    // G_IPC_EP_X86, before either the client or the
                    // server can read it.
                    unsafe { core::ptr::addr_of_mut!(G_IPC_EP_X86).write(ep) };
                    TrapOutcome::SwitchTo { save, into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        sys::IPC_ENDPOINT_CAP => {
            // SAFETY: single-core; written once by IPC_DEMO_START before
            // either caller of this opcode can run.
            return TrapOutcome::Resume(unsafe { core::ptr::addr_of!(G_IPC_EP_X86).read() } as usize);
        }
        sys::IPC_CALL => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_call(hal, caller, a0 as u32, a1 as u64) {
                Some(sw) => {
                    if let Some((p0, p1)) = sw.poke {
                        // SAFETY: `sw.into` is a kernel-owned, currently
                        // not-executing `HAL_USER_CONTEXT_BYTES` blob —
                        // `p2_ipc_call`'s own contract.
                        unsafe { hal_x86_64::cpu::poke_saved_a0_a1(sw.into as *mut u8, p0, p1) };
                    }
                    // The L4-style register-only fast path
                    // (02-Microkernel-Layer.md §5.3/§8.3) — see
                    // `hal_x86_64::cpu::TrapOutcome::SwitchToFast`'s own
                    // doc comment for exactly which registers this skips
                    // and why it is safe to.
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        sys::IPC_RECV => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_recv(hal, caller, a0 as u32) {
                Some(kernel_arch_glue::IpcRecvOutcome::Immediate { from, label }) => {
                    TrapOutcome::Resume2(from, label)
                }
                Some(kernel_arch_glue::IpcRecvOutcome::Switch(sw)) => {
                    // `poke` is always `None` here — WE are the one
                    // blocking (nothing to poke into our own trap; the
                    // ordinary `Resume`/`Resume2` path handles that),
                    // not being woken via a direct hand-off.
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume2(0, 0),
            };
        }
        sys::IPC_REPLY => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_reply(hal, caller, a0 as u32, a1 as u64) {
                Some(sw) => {
                    if let Some((p0, p1)) = sw.poke {
                        // SAFETY: same contract as IPC_CALL's own poke
                        // above.
                        unsafe { hal_x86_64::cpu::poke_saved_a0_a1(sw.into as *mut u8, p0, p1) };
                    }
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        // fs-native: the REAL FsRequest/FsResponse wire protocol — see
        // riscv64's own identical arms (this file's `sys::FS_DEMO_START`
        // doc comment) for the full rationale. Always called by root in
        // this demo, so `kstate().root_thread` is correct here, unlike
        // the generic IPC arms above (which the SERVER thread also
        // calls).
        sys::FS_DEMO_START => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            return match kernel_arch_glue::fs_demo_start(hal, caller, FS_NATIVE_ELF, elf_loader::machine::EM_X86_64) {
                Some((ep, save, into)) => {
                    // SAFETY: single-core; only this arm writes
                    // G_FS_EP_X86, before any later FS_OPEN/FS_STAT/
                    // FS_CLOSE call.
                    unsafe { core::ptr::addr_of_mut!(G_FS_EP_X86).write(ep) };
                    TrapOutcome::SwitchTo { save, into }
                }
                None => TrapOutcome::Resume(usize::MAX),
            };
        }
        sys::FS_OPEN => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: single-core; written once by FS_DEMO_START, before
            // any FS_OPEN call.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_X86).read() };
            return match kernel_arch_glue::fs_open_call(hal, caller, ep, a0 as u32, a1 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_OPEN_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_open_result());
        }
        sys::FS_STAT => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_X86).read() };
            return match kernel_arch_glue::fs_stat_call(hal, caller, ep, a0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_STAT_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_stat_result());
        }
        sys::FS_CLOSE => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_X86).read() };
            return match kernel_arch_glue::fs_close_call(hal, caller, ep, a0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_CLOSE_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_close_result());
        }
        sys::FS_WRITE => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_X86).read() };
            return match kernel_arch_glue::fs_write_call(hal, caller, ep, a0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_WRITE_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_write_result());
        }
        sys::FS_READ => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_X86).read() };
            return match kernel_arch_glue::fs_read_call(hal, caller, ep, a0 as u32, a1 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_READ_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_read_result());
        }
        sys::P2_PREEMPT_START => {
            // The cooperative §8.4 round-trip is done; spawn the fault-
            // isolation demo (03-Kernel-Subsystems-Layer.md §5.2) and
            // arm the preemptive scheduler (02-Microkernel-Layer.md §4)
            // together, right here — mirrors `simurgh_syscall`
            // (riscv64)'s and `simurgh_syscall_aarch64`'s own
            // `P2_PREEMPT_START` arms exactly: device-manager and the
            // faulty driver simply join the SAME timer-driven round-
            // robin `p2_preempt_start`/`p2_tick` establish for A/B/C,
            // rather than needing an explicit hand-off — `p2_fault`'s
            // existing unconditional hand-off-to-`DM_TID` logic
            // (already proven on riscv64 AND aarch64) takes over the
            // instant the driver is scheduled and faults.
            spawn_device_manager_x86(kernel_arch_glue::khal());
            let _ = spawn_faulty_driver_x86(kernel_arch_glue::khal());
            return match kernel_arch_glue::p2_preempt_start() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::P2_REPORT_B => {
            kernel_arch_glue::p2_report_b(a0);
            return TrapOutcome::Resume(0);
        }
        sys::DM_REPORT => {
            let name = match a0 {
                0 => "Starting",
                1 => "Running",
                2 => "Restarting",
                3 => "Failed",
                _ => "?",
            };
            kernel_arch_glue::log(format_args!(
                "device-manager (U-mode, isolated subsystem process, x86_64): state={name} restarts_in_window={a1}\r\n"
            ));
            if a0 == 3 {
                kernel_arch_glue::p2_dm_supervision_done();
            }
            return TrapOutcome::Resume(0);
        }
        sys::DM_WAIT_CRASH => {
            return match kernel_arch_glue::p2_dm_wait_crash() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::DM_POLL_CRASH => {
            return TrapOutcome::Resume(kernel_arch_glue::p2_poll_crash());
        }
        sys::DM_RESPAWN_DRIVER => {
            return match spawn_faulty_driver_x86(kernel_arch_glue::khal()) {
                Some(new_tid) => match kernel_arch_glue::p2_dm_handoff_to_driver(new_tid) {
                    Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                    None => TrapOutcome::Resume(0),
                },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::ALIVE => {
            kernel_arch_glue::log(format_args!(
                "root task (U-mode, x86_64, Ring 3): alive, made an int 0x80 syscall from U=1 pages\r\n"
            ));
        }
        sys::REPORT => {
            kernel_arch_glue::log(format_args!(
                "root task (U-mode, x86_64): syscall result = {:#x}\r\n",
                a0
            ));
        }
        _ => {}
    }
    TrapOutcome::Resume(0)
}

/// The per-process fault-isolation handler `hal_x86_64::cpu`'s
/// dedicated `#UD` trampoline calls for a Ring-3 exception (registered
/// via `hal_x86_64::cpu::set_fault_handler`) — 03-Kernel-Subsystems-
/// Layer.md §2.1/§5.2. Mirrors riscv64's own `simurgh_fault` exactly:
/// delegates to `kernel-arch-glue`, which terminates the faulting
/// thread (or hands off directly to device-manager if it was the
/// watched driver) and picks whatever else is runnable.
#[cfg(target_arch = "x86_64")]
fn simurgh_fault_x86(vector: usize, rip: usize, _reserved: usize) -> hal_x86_64::cpu::TrapOutcome {
    use hal_x86_64::cpu::TrapOutcome;
    match kernel_arch_glue::p2_fault(vector, rip, 0) {
        Some(into) => TrapOutcome::Terminate { into },
        None => TrapOutcome::Resume(0),
    }
}

/// The preemptive-scheduler tick handler `hal_x86_64::cpu`'s dedicated
/// LAPIC-timer trampoline calls for the timer interrupt landing on a
/// running Ring-3 thread (registered via `hal_x86_64::cpu::
/// set_tick_handler`) — 02-Microkernel-Layer.md §4. Delegates the
/// round-robin decision to `kernel-arch-glue`; `Some((save, into))`
/// preempts, `None` lets the current thread keep running. Mirrors
/// `simurgh_tick` (riscv64) / `simurgh_tick_aarch64` exactly.
#[cfg(target_arch = "x86_64")]
fn simurgh_tick_x86() -> hal_x86_64::cpu::TrapOutcome {
    use hal_x86_64::cpu::TrapOutcome;
    match kernel_arch_glue::p2_tick() {
        Some((save, into)) => TrapOutcome::SwitchTo { save, into },
        None => TrapOutcome::Resume(0),
    }
}

// Linker symbols for the x86_64 user (layer-3) Root Task image — see
// hal-x86_64/src/linker.ld's `.user_text` / `.user_stack` sections.
#[cfg(target_arch = "x86_64")]
unsafe extern "C" {
    static __user_text_start: u8;
    static __user_text_end: u8;
    static __user_text_lma: u8;
    static __user_stack_start: u8;
    static __user_stack_end: u8;
    static __user_stack_lma: u8;
}

/// Reads the `.user_*` linker symbols into the descriptor `enter` needs to
/// map the Root Task's pages `U=1` before dropping to Ring 3.
#[cfg(target_arch = "x86_64")]
fn user_image() -> kernel_arch_glue::UserImage {
    let sym = |s: &u8| s as *const u8 as usize;
    // SAFETY: these are linker-defined addresses, taken by reference only,
    // never dereferenced — the standard idiom for consuming linker script
    // symbols.
    unsafe {
        kernel_arch_glue::UserImage {
            text_vma: sym(&__user_text_start),
            text_lma: sym(&__user_text_lma),
            text_len: sym(&__user_text_end) - sym(&__user_text_start),
            stack_vma: sym(&__user_stack_start),
            stack_lma: sym(&__user_stack_lma),
            stack_len: sym(&__user_stack_end) - sym(&__user_stack_start),
            entry_vma: umode_root_x86 as usize,
            worker_entry_vma: umode_worker_x86 as usize,
            subsystem_entry_vma: umode_subsystem_x86 as usize,
            a_loop_entry_vma: umode_a_loop_x86 as usize,
        }
    }
}

/// Mirrors riscv64's own `spawn_device_manager` exactly (see its doc
/// comment), minus the `root_task::plan_boot` narration, which is
/// architecture-independent and already exercised there — no need to
/// duplicate proving the SAME in-kernel logic runs correctly twice.
/// Launches Device Manager — `Service::BOOT_ORDER[0]` — as a genuinely
/// isolated process from its OWN separately-built ELF image
/// (`kernel_arch_glue::spawn_process_from_elf` — see that function's
/// and `device-manager-bin`'s own doc comments), the SAME mechanism
/// riscv64 uses. Called once, right after the cooperative §8.4
/// round-trip completes (`sys::P2_REPORT_A`) — there is no preemption
/// loop for it to "join" yet on this architecture, so the caller must
/// explicitly hand off to it (or to the faulty driver) afterward.
#[cfg(target_arch = "x86_64")]
fn spawn_device_manager_x86(hal: &hal_core::HalInterface) {
    let k = kernel_arch_glue::kstate();
    let total = k.total_untyped_bytes();
    match root_task::plan_boot(total) {
        Ok(plan) => {
            kernel_arch_glue::log(format_args!(
                "root task (x86_64): plan_boot({} bytes) - root reserve {} bytes, {} service grant(s), {} bytes free\r\n",
                total, plan.root_reserve_bytes, plan.grants.len(), plan.free_bytes
            ));
        }
        Err(e) => {
            kernel_arch_glue::log(format_args!(
                "root task (x86_64): plan_boot failed: {:?} - device-manager not spawned\r\n",
                e
            ));
            return;
        }
    }

    const DM_STACK_VMA: usize = 0xC040_0000;
    const DM_STACK_LEN: usize = 4096 * 16;
    match kernel_arch_glue::spawn_process_from_elf(
        hal,
        k,
        DEVICE_MANAGER_ELF,
        elf_loader::machine::EM_X86_64,
        DM_STACK_VMA,
        DM_STACK_LEN,
    ) {
        Some((tid, _cap_space, _stack_phys)) => {
            kernel_arch_glue::p2_register_device_manager(tid);
            kernel_arch_glue::log(format_args!(
                "root task (x86_64): spawned device-manager (tid {}) from its OWN separately-built ELF image\r\n",
                tid.as_u32()
            ));
        }
        None => kernel_arch_glue::log(format_args!(
            "root task (x86_64): device-manager spawn skipped (out of resources)\r\n"
        )),
    }
}

/// Spawns `umode_faulty_driver_x86` (see its doc comment) via the SAME
/// generic `kernel_arch_glue::spawn_process` path as device-manager.
/// Mirrors riscv64's own `spawn_faulty_driver` exactly.
#[cfg(target_arch = "x86_64")]
fn spawn_faulty_driver_x86(hal: &hal_core::HalInterface) -> Option<kernel_cap::ThreadId> {
    let k = kernel_arch_glue::kstate();
    let user = user_image();
    const FAULTY_STACK_VMA: usize = 0xC050_0000;
    const FAULTY_STACK_LEN: usize = 4096 * 4;
    match kernel_arch_glue::spawn_process(
        hal,
        k,
        user.text_vma,
        user.text_lma,
        user.text_len,
        FAULTY_STACK_VMA,
        FAULTY_STACK_LEN,
        umode_faulty_driver_x86 as usize,
    ) {
        Some((tid, _cap_space, _stack_phys)) => {
            kernel_arch_glue::p2_watch_driver(tid);
            kernel_arch_glue::log(format_args!(
                "root task (x86_64): spawned faulty-driver (tid {}) - it will fault on its first instruction (fault-isolation demo, 03 5.2)\r\n",
                tid.as_u32()
            ));
            Some(tid)
        }
        None => {
            kernel_arch_glue::log(format_args!(
                "root task (x86_64): faulty-driver spawn skipped (out of resources)\r\n"
            ));
            None
        }
    }
}

/// # Safety
/// `svc #0` from EL0 traps to the shared EL0-synchronous vector
/// (`hal_arm64::cpu`'s `sync_el0_entry`), which preserves every register
/// except `x0` (the return value) — this project's own convention (see
/// `hal_arm64::cpu::SyscallHandler`'s doc comment): `x8` = opcode,
/// `x0`/`x1` = a0/a1.
///
/// `#[inline(never)]` (+ mandatory `#[link_section = ".user_text"]`):
/// see riscv64's own `raw_syscall`'s extensive doc comment for the
/// real, QEMU-found miscompilation this avoids (not independently
/// exercised/observed broken on aarch64, but gets the identical
/// preventive fix for consistency).
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[link_section = ".user_text"]
unsafe fn raw_syscall_aarch64(opcode: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") opcode,
            inlateout("x0") a0 => ret,
            in("x1") a1,
        );
    }
    ret
}

/// Like `raw_syscall_aarch64`, but also reads back `x1` — for
/// `IPC_RECV`, the ONE opcode whose result genuinely does not fit in a
/// single register (see `hal_arm64::cpu::TrapOutcome::Resume2`'s own
/// doc comment). Mirrors riscv64's `raw_syscall2`/x86_64's
/// `raw_syscall2_x86` exactly, just with `x1` (this project's own `a1`
/// register on aarch64) in place of `a1`.
///
/// # Safety
/// Same contract as `raw_syscall_aarch64` — `svc #0` preserves every
/// register except `x0`/`x1` for this opcode specifically.
///
/// `#[inline(never)]` — see `raw_syscall_aarch64`'s own doc comment.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[link_section = ".user_text"]
unsafe fn raw_syscall2_aarch64(opcode: usize, a0: usize, a1: usize) -> (usize, usize) {
    let (r0, r1): (usize, usize);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") opcode,
            inlateout("x0") a0 => r0,
            inlateout("x1") a1 => r1,
        );
    }
    (r0, r1)
}

/// The real Call/Recv/Reply demo's endpoint capability slot, set once by
/// `IPC_DEMO_START`'s handler and read by `IPC_ENDPOINT_CAP` — both the
/// client (`umode_root_aarch64`) and the server
/// (`umode_ipc_server_aarch64`) call the latter to learn it
/// independently. Mirrors riscv64's `G_IPC_EP`/x86_64's `G_IPC_EP_X86`
/// exactly.
#[cfg(target_arch = "aarch64")]
static mut G_IPC_EP_AARCH64: u32 = 0;

/// fs-native's endpoint capability slot in the caller's (root's) own
/// capability space — mirrors riscv64's own `G_FS_EP`/x86_64's
/// `G_FS_EP_X86` exactly (see `G_FS_EP`'s own doc comment).
#[cfg(target_arch = "aarch64")]
static mut G_FS_EP_AARCH64: u32 = 0;

/// The aarch64 Root Task entry. Linked into `.user_text` (its own
/// `AP_USER` `R+X` pages at the linked VMA, per hal-arm64's linker.ld)
/// and run at EL0 by `kernel-arch-glue::enter`. Extends the original
/// minimal ALIVE/REPORT proof with the cooperative two-process §8.4
/// round-trip — mirrors `umode_root_x86`'s own steps 5-6 exactly (see
/// its doc comment for why riscv64's steps 1-4, MAP_PAGE/MAP_ALIAS/
/// XCHECK, are skipped here too: real paging correctness was already
/// proven independently by the aarch64 paging milestone).
#[cfg(target_arch = "aarch64")]
#[link_section = ".user_text"]
extern "C" fn umode_root_aarch64() -> ! {
    // SAFETY: see `raw_syscall_aarch64`'s own contract. The memory
    // accesses below go through `P2_VA_A_CONST` (0xC0040000, a
    // `kernel-arch-glue`-owned constant — see `setup_two_process`),
    // which `enter` maps `AP_USER R+W` onto the frame shared with
    // process B.
    unsafe {
        raw_syscall_aarch64(sys::ALIVE, 0, 0);
        raw_syscall_aarch64(sys::REPORT, 0x5eed_5eed, 0);

        // 1. Write a sentinel through OUR mapping of the shared frame,
        //    then `P2_YIELD` — the kernel snapshots this thread and
        //    resumes process B in its own isolated space.
        core::arch::asm!(
            "str {val:w}, [{va}]",
            va = in(reg) 0xC004_0000u64,
            val = in(reg) 0xC0DEu32,
            options(nostack),
        );
        raw_syscall_aarch64(sys::P2_YIELD, 0, 0);

        // 2. Resumed here after process B ran. Re-read our VA: process B
        //    wrote 0xB00B through ITS OWN mapping of the same frame, in
        //    a different address space, with no copy.
        let after: usize;
        core::arch::asm!(
            "ldr {out:w}, [{va}]",
            va = in(reg) 0xC004_0000u64,
            out = out(reg) after,
            options(nostack, readonly),
        );
        raw_syscall_aarch64(sys::P2_REPORT_A, after, 0);

        // 3. Real Call/Recv/Reply demo (02-Microkernel-Layer.md
        //    §5.1/§8.2) — unlike everything above (all ad-hoc raw
        //    opcodes), this exercises the REAL `kernel_core::SyscallOp`
        //    IPC surface through a genuine trap boundary. Mirrors
        //    `umode_root`'s (riscv64) own step 7 / `umode_root_x86`'s
        //    own step 3 exactly: `IPC_DEMO_START` spawns the server
        //    (`umode_ipc_server_aarch64`) and switches straight to it;
        //    we resume here once the server's own first `IPC_RECV`
        //    finds nothing queued yet and switches back.
        raw_syscall_aarch64(sys::IPC_DEMO_START, 0, 0);
        let ipc_ep = raw_syscall_aarch64(sys::IPC_ENDPOINT_CAP, 0, 0);
        let ipc_reply = raw_syscall_aarch64(sys::IPC_CALL, ipc_ep, 0xC0FFEE);
        raw_syscall_aarch64(sys::REPORT, ipc_reply, 0);

        // 7b. fs-native: the REAL FsRequest/FsResponse wire protocol,
        //     over the SAME real Call/Recv/Reply mechanism, driving a
        //     REAL isolated process's REAL MemFs (03-Kernel-Subsystems-
        //     Layer.md §2.2/§5.3) — mirrors riscv64's own `umode_root`
        //     step 7b / x86_64's own step 7b exactly (see their doc
        //     comments). `zero!()`: same stack-slot-reuse miscompilation
        //     those doc comments document in full — not independently
        //     observed broken on this arch, but applied for the
        //     identical preventive reason `#[inline(never)]` was applied
        //     to `raw_syscall_aarch64` itself.
        macro_rules! zero {
            () => {{
                let mut v: usize = 0;
                // SAFETY: a no-op asm block — see riscv64's own
                // `umode_root`'s identical macro for the full rationale.
                core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
                v
            }};
        }
        raw_syscall_aarch64(sys::FS_DEMO_START, zero!(), zero!());
        raw_syscall_aarch64(sys::FS_OPEN, zero!(), zero!() | 2); // path=0 ("/greeting"), flags=WRITE (real Write demo below needs it)
        let fs_handle = raw_syscall_aarch64(sys::FS_OPEN_RESULT, zero!(), zero!());
        raw_syscall_aarch64(sys::REPORT, fs_handle, zero!());
        raw_syscall_aarch64(sys::FS_STAT, zero!(), zero!()); // path=0
        let fs_size = raw_syscall_aarch64(sys::FS_STAT_RESULT, zero!(), zero!());
        raw_syscall_aarch64(sys::REPORT, fs_size, zero!());
        raw_syscall_aarch64(sys::FS_WRITE, fs_handle, zero!());
        let fs_written = raw_syscall_aarch64(sys::FS_WRITE_RESULT, zero!(), zero!());
        raw_syscall_aarch64(sys::REPORT, fs_written, zero!());
        raw_syscall_aarch64(sys::FS_READ, fs_handle, fs_written);
        let fs_read = raw_syscall_aarch64(sys::FS_READ_RESULT, zero!(), zero!());
        raw_syscall_aarch64(sys::REPORT, fs_read, zero!());
        raw_syscall_aarch64(sys::FS_CLOSE, fs_handle, zero!());
        let fs_closed = raw_syscall_aarch64(sys::FS_CLOSE_RESULT, zero!(), zero!());
        raw_syscall_aarch64(sys::REPORT, fs_closed, zero!());

        // 8. Preemption phase (02-Microkernel-Layer.md §4). Ask the
        //    kernel to arm the timer PPI, then loop forever bumping this
        //    process's private counter word in the shared frame (offset
        //    +8). From here NO `P2_YIELD` is issued — the timer
        //    interrupt alone switches between this process and the
        //    worker. In practice `kernel_arch_glue::p2_preempt_start`
        //    always switches AWAY to a fresh thread sharing this same
        //    address space before this `svc` ever returns (see its own
        //    doc comment on why root's own vruntime-loaded TCB is
        //    retired rather than reused) — this loop is the fallback
        //    for the rare case that spawn fails, mirroring `umode_root_
        //    x86`'s own identical tail exactly.
        raw_syscall_aarch64(sys::P2_PREEMPT_START, 0, 0);
        core::arch::asm!(
            "2:",
            "ldr w9, [{va}]",
            "add w9, w9, #1",
            "str w9, [{va}]",
            "b 2b",
            va = in(reg) 0xC004_0008u64,
            options(noreturn),
        );
    }
}

/// The SECOND user-space process (02-Microkernel-Layer.md §8.4). Linked
/// into the same `.user_text` pages as `umode_root_aarch64` but run in
/// its OWN isolated address space (space B) on its own stack by
/// `kernel-arch-glue::setup_two_process`. Mirrors `umode_worker_x86`'s
/// steps 1-4 exactly, including the preemptive-phase counting-loop tail.
#[cfg(target_arch = "aarch64")]
#[link_section = ".user_text"]
extern "C" fn umode_worker_aarch64() -> ! {
    // SAFETY: `svc #0` traps to the shared EL0-synchronous vector; the
    // memory accesses go through `P2_VA_B_CONST` (0xC0200000), which
    // `enter` maps `AP_USER R+W` onto the SAME physical frame as A's own
    // `P2_VA_A_CONST` mapping, at a different VA in this isolated space.
    unsafe {
        let seen: usize;
        core::arch::asm!(
            "ldr {out:w}, [{va}]",
            va = in(reg) 0xC020_0000u64,
            out = out(reg) seen,
            options(nostack, readonly),
        );
        raw_syscall_aarch64(sys::P2_REPORT_B, seen, 0);

        core::arch::asm!(
            "str {val:w}, [{va}]",
            va = in(reg) 0xC020_0000u64,
            val = in(reg) 0xB00Bu32,
            options(nostack),
        );

        // 3. Hand the core back to process A for its final §8.4 check.
        raw_syscall_aarch64(sys::P2_YIELD, 0, 0);

        // 4. Resumed here (either by that hand-off's partner, or — once
        //    process A calls P2_PREEMPT_START — by a timer tick). Loop
        //    forever bumping this process's private counter word in the
        //    shared frame (offset +12), issuing NO further `P2_YIELD`.
        core::arch::asm!(
            "2:",
            "ldr w9, [{va}]",
            "add w9, w9, #1",
            "str w9, [{va}]",
            "b 2b",
            va = in(reg) 0xC020_000Cu64,
            options(noreturn),
        );
    }
}

/// A THIRD user-space process, spawned via `kernel_arch_glue::
/// spawn_process` (the generic path, not `umode_root_aarch64`/
/// `umode_worker_aarch64`'s hand-written A/B setup) into its OWN
/// isolated address space AND its OWN capability space — proof that
/// process creation generalizes beyond the fixed two-process §8.4
/// proof. Mirrors `umode_subsystem`/`umode_subsystem_x86` exactly:
/// bumps a private counter word at a fixed low address inside its OWN
/// stack region (safe because this loop pushes no stack frame — pure
/// register ops).
#[cfg(target_arch = "aarch64")]
#[link_section = ".user_text"]
extern "C" fn umode_subsystem_aarch64() -> ! {
    // SAFETY: the address is the low end of this process's own `AP_USER
    // R+W` stack mapping (`kernel_arch_glue::spawn_process` set it up);
    // pure register ops, no stack frame, no relocation.
    unsafe {
        core::arch::asm!(
            "2:",
            "ldr w9, [{va}]",
            "add w9, w9, #1",
            "str w9, [{va}]",
            "b 2b",
            va = in(reg) 0xC030_0000u64,
            options(noreturn),
        );
    }
}

/// Process A's preemptive-phase counting loop, run by a FRESH thread
/// `kernel_arch_glue::p2_preempt_start` spawns to share root's own
/// address space (not `umode_root_aarch64` continuing to run itself —
/// see that function's doc comment on why root's own vruntime-loaded
/// TCB is retired instead of reused). Bumps the SAME counter word
/// `umode_root_aarch64` would have (`P2_VA_A_CONST + 8`), since it runs
/// in the SAME space A. Mirrors `umode_a_loop`/`umode_a_loop_x86`
/// exactly.
#[cfg(target_arch = "aarch64")]
#[link_section = ".user_text"]
extern "C" fn umode_a_loop_aarch64() -> ! {
    // SAFETY: the address is mapped `AP_USER R+W` in space A by `enter`/
    // `umode_root_aarch64`'s own setup; pure register ops, no stack
    // frame.
    unsafe {
        core::arch::asm!(
            "2:",
            "ldr w9, [{va}]",
            "add w9, w9, #1",
            "str w9, [{va}]",
            "b 2b",
            va = in(reg) 0xC004_0008u64,
            options(noreturn),
        );
    }
}

/// Deliberately-crashing "driver" process — the 03-Kernel-Subsystems-
/// Layer.md §5.2 acceptance-test demo. Executes `udf #0` (Permanently
/// Undefined) the instant it is scheduled, taking a synchronous EL0
/// exception (`ESR_EL1.EC` = 0x00, "Unknown reason") that `hal_arm64`'s
/// shared EL0-synchronous vector routes to the registered
/// `FaultHandler` (`simurgh_fault_aarch64` -> `kernel_arch_glue::
/// p2_fault` -> `KernelState::terminate_thread`/
/// `terminate_thread_and_handoff`) instead of halting the system —
/// mirrors `umode_faulty_driver_x86` (`ud2`) exactly, just with
/// aarch64's own ISA-guaranteed-undefined encoding.
#[cfg(target_arch = "aarch64")]
#[link_section = ".user_text"]
extern "C" fn umode_faulty_driver_aarch64() -> ! {
    // SAFETY: `udf #0` is not a valid instruction to EXECUTE (it is
    // reserved specifically as "always undefined") — deliberately
    // triggers a synchronous exception, the entire point of this
    // process. `options(noreturn)` is honest: control never falls
    // through (the thread is terminated by the fault handler and never
    // resumes).
    unsafe {
        core::arch::asm!("udf #0", options(noreturn));
    }
}

/// The real Call/Recv/Reply demo's SERVER (02-Microkernel-Layer.md
/// §5.1/§8.2 — see `sys::IPC_DEMO_START`'s own doc comment). Spawned by
/// `kernel_arch_glue::p2_ipc_demo_start`, sharing `umode_root_aarch64`'s
/// OWN address space. Mirrors riscv64's `umode_ipc_server`/x86_64's
/// `umode_ipc_server_x86` exactly.
#[cfg(target_arch = "aarch64")]
#[link_section = ".user_text"]
extern "C" fn umode_ipc_server_aarch64() -> ! {
    // SAFETY: `svc #0` traps to the shared EL0-synchronous vector; pure
    // register ops, no stack frame, no relocation — same convention
    // every other `.user_text` function here follows.
    unsafe {
        let ep = raw_syscall_aarch64(sys::IPC_ENDPOINT_CAP, 0, 0);
        let (from, label) = raw_syscall2_aarch64(sys::IPC_RECV, ep, 0);
        raw_syscall_aarch64(sys::IPC_REPLY, from, label.wrapping_add(1));
        // `IPC_REPLY` always switches away on success (see its own doc
        // comment) — unreachable in that case; this is the fallback for
        // the error case, so this thread parks instead of running off
        // the end of the function.
        core::arch::asm!("2:", "b 2b", options(noreturn));
    }
}

/// The syscall handler `hal_arm64::cpu`'s shared EL0-synchronous vector
/// calls for a `svc` from EL0. Runs at EL1.
#[cfg(target_arch = "aarch64")]
fn simurgh_syscall_aarch64(x8: usize, x0: usize, x1: usize) -> hal_arm64::cpu::TrapOutcome {
    use hal_arm64::cpu::TrapOutcome;

    // Two-process hand-off / device-manager supervision arms resolve to
    // a non-`Resume` outcome — mirrors `simurgh_syscall_x86`'s own
    // dispatch order exactly.
    match x8 {
        sys::P2_YIELD => {
            return match kernel_arch_glue::p2_yield() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::P2_REPORT_A => {
            kernel_arch_glue::p2_report_a(x0);
            return TrapOutcome::Resume(0);
        }
        // Real Call/Recv/Reply demo (see `sys::IPC_DEMO_START`'s own doc
        // comment) — mirrors `simurgh_syscall` (riscv64)'s / `simurgh_
        // syscall_x86`'s own IPC arms exactly, including using
        // `kstate().sched.running()` (not the hardcoded root thread
        // every OTHER opcode here uses) since IPC_RECV/IPC_REPLY are
        // called by the server thread too.
        sys::IPC_DEMO_START => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_demo_start(hal, caller, umode_ipc_server_aarch64 as usize) {
                Some((ep, save, into)) => {
                    // SAFETY: single-core; only this arm writes
                    // G_IPC_EP_AARCH64, before either the client or the
                    // server can read it.
                    unsafe { core::ptr::addr_of_mut!(G_IPC_EP_AARCH64).write(ep) };
                    TrapOutcome::SwitchTo { save, into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        sys::IPC_ENDPOINT_CAP => {
            // SAFETY: single-core; written once by IPC_DEMO_START before
            // either caller of this opcode can run.
            return TrapOutcome::Resume(unsafe { core::ptr::addr_of!(G_IPC_EP_AARCH64).read() } as usize);
        }
        sys::IPC_CALL => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_call(hal, caller, x0 as u32, x1 as u64) {
                Some(sw) => {
                    if let Some((p0, p1)) = sw.poke {
                        // SAFETY: `sw.into` is a kernel-owned, currently
                        // not-executing `HAL_USER_CONTEXT_BYTES` blob —
                        // `p2_ipc_call`'s own contract.
                        unsafe { hal_arm64::cpu::poke_saved_a0_a1(sw.into as *mut u8, p0, p1) };
                    }
                    // The L4-style register-only fast path
                    // (02-Microkernel-Layer.md §5.3/§8.3) — see
                    // `hal_arm64::cpu::TrapOutcome::SwitchToFast`'s own
                    // doc comment for exactly which registers this skips
                    // and why it is safe to.
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        sys::IPC_RECV => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_recv(hal, caller, x0 as u32) {
                Some(kernel_arch_glue::IpcRecvOutcome::Immediate { from, label }) => {
                    TrapOutcome::Resume2(from, label)
                }
                Some(kernel_arch_glue::IpcRecvOutcome::Switch(sw)) => {
                    // `poke` is always `None` here — WE are the one
                    // blocking (nothing to poke into our own trap; the
                    // ordinary `Resume`/`Resume2` path handles that),
                    // not being woken via a direct hand-off.
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume2(0, 0),
            };
        }
        sys::IPC_REPLY => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_reply(hal, caller, x0 as u32, x1 as u64) {
                Some(sw) => {
                    if let Some((p0, p1)) = sw.poke {
                        // SAFETY: same contract as IPC_CALL's own poke
                        // above.
                        unsafe { hal_arm64::cpu::poke_saved_a0_a1(sw.into as *mut u8, p0, p1) };
                    }
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        // fs-native: the REAL FsRequest/FsResponse wire protocol — see
        // riscv64's own identical arms (this file's `sys::FS_DEMO_START`
        // doc comment) for the full rationale. Always called by root in
        // this demo, so `kstate().root_thread` is correct here, unlike
        // the generic IPC arms above (which the SERVER thread also
        // calls).
        sys::FS_DEMO_START => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            return match kernel_arch_glue::fs_demo_start(hal, caller, FS_NATIVE_ELF, elf_loader::machine::EM_AARCH64) {
                Some((ep, save, into)) => {
                    // SAFETY: single-core; only this arm writes
                    // G_FS_EP_AARCH64, before any later FS_OPEN/FS_STAT/
                    // FS_CLOSE call.
                    unsafe { core::ptr::addr_of_mut!(G_FS_EP_AARCH64).write(ep) };
                    TrapOutcome::SwitchTo { save, into }
                }
                None => TrapOutcome::Resume(usize::MAX),
            };
        }
        sys::FS_OPEN => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: single-core; written once by FS_DEMO_START, before
            // any FS_OPEN call.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_AARCH64).read() };
            return match kernel_arch_glue::fs_open_call(hal, caller, ep, x0 as u32, x1 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_OPEN_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_open_result());
        }
        sys::FS_STAT => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_AARCH64).read() };
            return match kernel_arch_glue::fs_stat_call(hal, caller, ep, x0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_STAT_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_stat_result());
        }
        sys::FS_CLOSE => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_AARCH64).read() };
            return match kernel_arch_glue::fs_close_call(hal, caller, ep, x0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_CLOSE_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_close_result());
        }
        sys::FS_WRITE => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_AARCH64).read() };
            return match kernel_arch_glue::fs_write_call(hal, caller, ep, x0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_WRITE_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_write_result());
        }
        sys::FS_READ => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP_AARCH64).read() };
            return match kernel_arch_glue::fs_read_call(hal, caller, ep, x0 as u32, x1 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_READ_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_read_result());
        }
        sys::P2_PREEMPT_START => {
            // The cooperative §8.4 round-trip is done; spawn the fault-
            // isolation demo (03-Kernel-Subsystems-Layer.md §5.2) and
            // arm the preemptive scheduler (02-Microkernel-Layer.md §4)
            // together, right here — mirrors `simurgh_syscall`
            // (riscv64)'s own `P2_PREEMPT_START` arm exactly: device-
            // manager and the faulty driver simply join the SAME
            // timer-driven round-robin `p2_preempt_start`/`p2_tick`
            // establish for A/B/C, rather than needing an explicit
            // hand-off — `p2_fault`'s existing unconditional hand-off-
            // to-`DM_TID` logic (already proven on riscv64 AND aarch64)
            // takes over the instant the driver is scheduled and faults.
            spawn_device_manager_aarch64(kernel_arch_glue::khal());
            let _ = spawn_faulty_driver_aarch64(kernel_arch_glue::khal());
            return match kernel_arch_glue::p2_preempt_start() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::P2_REPORT_B => {
            kernel_arch_glue::p2_report_b(x0);
            return TrapOutcome::Resume(0);
        }
        sys::DM_REPORT => {
            let name = match x0 {
                0 => "Starting",
                1 => "Running",
                2 => "Restarting",
                3 => "Failed",
                _ => "?",
            };
            kernel_arch_glue::log(format_args!(
                "device-manager (U-mode, isolated subsystem process, aarch64): state={name} restarts_in_window={x1}\r\n"
            ));
            if x0 == 3 {
                kernel_arch_glue::p2_dm_supervision_done();
            }
            return TrapOutcome::Resume(0);
        }
        sys::DM_WAIT_CRASH => {
            return match kernel_arch_glue::p2_dm_wait_crash() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::DM_POLL_CRASH => {
            return TrapOutcome::Resume(kernel_arch_glue::p2_poll_crash());
        }
        sys::DM_RESPAWN_DRIVER => {
            return match spawn_faulty_driver_aarch64(kernel_arch_glue::khal()) {
                Some(new_tid) => match kernel_arch_glue::p2_dm_handoff_to_driver(new_tid) {
                    Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                    None => TrapOutcome::Resume(0),
                },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::ALIVE => {
            kernel_arch_glue::log(format_args!(
                "root task (U-mode, aarch64, EL0): alive, made a svc syscall from AP_USER pages\r\n"
            ));
        }
        sys::REPORT => {
            kernel_arch_glue::log(format_args!(
                "root task (U-mode, aarch64): syscall result = {:#x}\r\n",
                x0
            ));
        }
        _ => {}
    }
    TrapOutcome::Resume(0)
}

/// The per-process fault-isolation handler `hal_arm64::cpu`'s shared
/// EL0-synchronous vector calls for a fatal EL0 exception that is not a
/// `svc` (registered via `hal_arm64::cpu::set_fault_handler`) —
/// 03-Kernel-Subsystems-Layer.md §2.1/§5.2. Mirrors
/// `simurgh_fault_x86`/riscv64's `simurgh_fault` exactly: delegates to
/// `kernel-arch-glue`, which terminates the faulting thread (or hands
/// off directly to device-manager if it was the watched driver) and
/// picks whatever else is runnable.
#[cfg(target_arch = "aarch64")]
fn simurgh_fault_aarch64(ec: usize, elr: usize, _far: usize) -> hal_arm64::cpu::TrapOutcome {
    use hal_arm64::cpu::TrapOutcome;
    match kernel_arch_glue::p2_fault(ec, elr, 0) {
        Some(into) => TrapOutcome::Terminate { into },
        None => TrapOutcome::Resume(0),
    }
}

/// The preemptive-scheduler tick handler `hal_arm64::cpu`'s shared EL0
/// IRQ vector calls for the timer PPI landing on a running U-mode
/// thread (registered via `hal_arm64::cpu::set_tick_handler`) —
/// 02-Microkernel-Layer.md §4. Delegates the round-robin decision to
/// `kernel-arch-glue`; `Some((save, into))` preempts, `None` lets the
/// current thread keep running. Mirrors `simurgh_tick` (riscv64)
/// exactly.
#[cfg(target_arch = "aarch64")]
fn simurgh_tick_aarch64() -> hal_arm64::cpu::TrapOutcome {
    use hal_arm64::cpu::TrapOutcome;
    match kernel_arch_glue::p2_tick() {
        Some((save, into)) => TrapOutcome::SwitchTo { save, into },
        None => TrapOutcome::Resume(0),
    }
}

/// Mirrors `spawn_device_manager_x86`/riscv64's `spawn_device_manager`
/// exactly (see either's doc comment). Launches Device Manager —
/// `Service::BOOT_ORDER[0]` — as a genuinely isolated process from its
/// OWN separately-built ELF image (`kernel_arch_glue::
/// spawn_process_from_elf`), the SAME mechanism the other two
/// architectures use. Called once, right after the cooperative §8.4
/// round-trip completes (`sys::P2_REPORT_A`).
#[cfg(target_arch = "aarch64")]
fn spawn_device_manager_aarch64(hal: &hal_core::HalInterface) {
    let k = kernel_arch_glue::kstate();
    let total = k.total_untyped_bytes();
    match root_task::plan_boot(total) {
        Ok(plan) => {
            kernel_arch_glue::log(format_args!(
                "root task (aarch64): plan_boot({} bytes) - root reserve {} bytes, {} service grant(s), {} bytes free\r\n",
                total, plan.root_reserve_bytes, plan.grants.len(), plan.free_bytes
            ));
        }
        Err(e) => {
            kernel_arch_glue::log(format_args!(
                "root task (aarch64): plan_boot failed: {:?} - device-manager not spawned\r\n",
                e
            ));
            return;
        }
    }

    const DM_STACK_VMA: usize = 0xC040_0000;
    const DM_STACK_LEN: usize = 4096 * 16;
    match kernel_arch_glue::spawn_process_from_elf(
        hal,
        k,
        DEVICE_MANAGER_ELF,
        elf_loader::machine::EM_AARCH64,
        DM_STACK_VMA,
        DM_STACK_LEN,
    ) {
        Some((tid, _cap_space, _stack_phys)) => {
            kernel_arch_glue::p2_register_device_manager(tid);
            kernel_arch_glue::log(format_args!(
                "root task (aarch64): spawned device-manager (tid {}) from its OWN separately-built ELF image\r\n",
                tid.as_u32()
            ));
        }
        None => kernel_arch_glue::log(format_args!(
            "root task (aarch64): device-manager spawn skipped (out of resources)\r\n"
        )),
    }
}

/// Spawns `umode_faulty_driver_aarch64` (see its doc comment) via the
/// SAME generic `kernel_arch_glue::spawn_process` path as
/// device-manager. Mirrors `spawn_faulty_driver_x86`/riscv64's
/// `spawn_faulty_driver` exactly.
#[cfg(target_arch = "aarch64")]
fn spawn_faulty_driver_aarch64(hal: &hal_core::HalInterface) -> Option<kernel_cap::ThreadId> {
    let k = kernel_arch_glue::kstate();
    let user = user_image();
    const FAULTY_STACK_VMA: usize = 0xC050_0000;
    const FAULTY_STACK_LEN: usize = 4096 * 4;
    match kernel_arch_glue::spawn_process(
        hal,
        k,
        user.text_vma,
        user.text_lma,
        user.text_len,
        FAULTY_STACK_VMA,
        FAULTY_STACK_LEN,
        umode_faulty_driver_aarch64 as usize,
    ) {
        Some((tid, _cap_space, _stack_phys)) => {
            kernel_arch_glue::p2_watch_driver(tid);
            kernel_arch_glue::log(format_args!(
                "root task (aarch64): spawned faulty-driver (tid {}) - it will fault on its first instruction (fault-isolation demo, 03 5.2)\r\n",
                tid.as_u32()
            ));
            Some(tid)
        }
        None => {
            kernel_arch_glue::log(format_args!(
                "root task (aarch64): faulty-driver spawn skipped (out of resources)\r\n"
            ));
            None
        }
    }
}

// Linker symbols for the aarch64 user (layer-3) Root Task image — see
// hal-arm64/src/linker.ld's `.user_text` / `.user_stack` sections.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    static __user_text_start: u8;
    static __user_text_end: u8;
    static __user_text_lma: u8;
    static __user_stack_start: u8;
    static __user_stack_end: u8;
    static __user_stack_lma: u8;
}

/// Reads the `.user_*` linker symbols into the descriptor `enter` needs to
/// map the Root Task's pages `AP_USER` before dropping to EL0.
#[cfg(target_arch = "aarch64")]
fn user_image() -> kernel_arch_glue::UserImage {
    let sym = |s: &u8| s as *const u8 as usize;
    // SAFETY: these are linker-defined addresses, taken by reference only,
    // never dereferenced — the standard idiom for consuming linker script
    // symbols.
    unsafe {
        kernel_arch_glue::UserImage {
            text_vma: sym(&__user_text_start),
            text_lma: sym(&__user_text_lma),
            text_len: sym(&__user_text_end) - sym(&__user_text_start),
            stack_vma: sym(&__user_stack_start),
            stack_lma: sym(&__user_stack_lma),
            stack_len: sym(&__user_stack_end) - sym(&__user_stack_start),
            entry_vma: umode_root_aarch64 as usize,
            worker_entry_vma: umode_worker_aarch64 as usize,
            subsystem_entry_vma: umode_subsystem_aarch64 as usize,
            a_loop_entry_vma: umode_a_loop_aarch64 as usize,
        }
    }
}

/// Physical address of the frame the most recent `MAP_PAGE` handed the
/// Root Task (for `XCHECK`'s kernel-side cross-check read).
#[cfg(target_arch = "riscv64")]
static mut LAST_MAPPED_FRAME: usize = 0;
/// The Frame capability (an `UntypedMemory` cap) the most recent
/// `MAP_PAGE` retyped. `MAP_ALIAS` maps this SAME capability at a second
/// VA — real capability-gated aliasing (`do_map` resolves it exactly like
/// the first `Map` did), not a kernel-side "trust the last physical
/// address" shortcut: a caller can never smuggle in an arbitrary
/// physical address, only a capability it actually holds.
#[cfg(target_arch = "riscv64")]
static mut LAST_MAPPED_FRAME_CAP: u32 = 0;

/// Retypes one page-sized `Untyped` object from the Root Task's first
/// `UntypedMemory` capability, returning both the new Frame capability
/// (for `SyscallOp::Map`'s `frame` argument) and its physical base (for
/// `XCHECK`'s kernel-side read — `Map` itself does not hand this back).
/// `None` if the retype or the cap lookup fails.
#[cfg(target_arch = "riscv64")]
fn alloc_root_frame(
    k: &mut kernel_core::KernelState,
    hal: &hal_core::HalInterface,
) -> Option<(kernel_cap::CapId, usize)> {
    use kernel_core::{SyscallOp, SyscallReturn};
    use kernel_mm::KernelObjectType;

    let cap = match k.dispatch(
        k.root_thread,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: kernel_cap::CapId::new(0),
            target_type: KernelObjectType::Untyped,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    let uid = kernel_cap::UntypedId::new(
        k.cap_space(k.root_cap_space)
            .and_then(|t| t.lookup(cap))
            .map(|c| c.object.id.as_u32())?,
    );
    let phys = k.untyped_mut(uid)?.base().as_usize();
    Some((cap, phys))
}

/// Real x86_64 paging, proven the same way hal-riscv64's OWN first Sv39
/// milestone was: build a fresh, hardware-real page table via the
/// generic `HalInterface` (not this crate's own early-boot identity
/// map — see `hal_x86_64::memory`'s module doc comment on that being a
/// SEPARATE, pre-`kernel_main` table), activate it, `map_range` one
/// fresh 4 KiB page at a VA no identity leaf covers, write a sentinel
/// through that VA, and cross-check it against the SAME physical frame
/// read through its (still-identity-mapped) own address — proving the
/// VA the walker just built genuinely translates to that physical page,
/// not merely "whatever `map_range` happened to write is what comes
/// back". No U-mode / `.user_text` / syscall boundary yet — see
/// IMPLEMENTATION-PLAN.md for that follow-up (this session's own
/// `map_ram_identity`/`map_range`/`activate_address_space`/`flush_tlb`
/// implementations are the piece it is gated on).
///
/// Runs before `kernel_arch_glue::enter` (which still parks — no user
/// image on this architecture yet); this function's own new page table
/// stays active afterward (x86_64 cannot return to a "no paging" state
/// the way riscv64's Bare-mode sentinel does — see
/// `Cpu::activate_address_space`'s doc comment), which is harmless: it
/// identity-maps everything the kernel itself needs, same as the
/// bootloader's own table did.
#[cfg(target_arch = "x86_64")]
fn x86_64_paging_selftest(hal: &hal_core::HalInterface, k: &mut kernel_core::KernelState) {
    let carve = |k: &mut kernel_core::KernelState, align: u64, bytes: u64| {
        k.untyped_mut(kernel_cap::UntypedId::new(0))
            .and_then(|u| u.alloc(align, bytes).ok())
            .map(|p| p.as_usize())
    };

    // `root_pt`: 3 CONTIGUOUS pages — PML4, its companion PDPT, and a
    // dedicated PD table for the Local APIC's own identity leaf (see
    // `hal_x86_64::cpu::x86_64_paging`'s module doc comment, `map_ram_
    // identity`'s own, on why every `root_frame` needs this THIRD page
    // now — this call site was a REAL, QEMU-confirmed gap this
    // session's preemption work found: still carving only 2 pages here
    // after `map_ram_identity` grew a third-page precondition silently
    // corrupted `pool` below, the exact "sp_b overwritten while building
    // sp_a's table" class of bug this file's own `two_space` comment
    // already documents for a DIFFERENT call site). `pool`: PD/PT
    // levels `map_range` builds below that PDPT — one of each is enough
    // for a single 4 KiB test page.
    let (Some(root_pt), Some(pool), Some(test_phys)) = (
        carve(k, 4096, 4096 * 3),
        carve(k, 4096, 4096 * 2),
        carve(k, 4096, 4096),
    ) else {
        kernel_arch_glue::log(format_args!(
            "x86_64: paging self-test skipped (out of untyped RAM)\r\n"
        ));
        return;
    };
    // SAFETY: fresh untyped RAM, identity-addressable (this core's
    // bootloader-built table is still active); single-core. `map_range`
    // needs the pool pre-zeroed; the test frame starts clean too.
    unsafe {
        core::ptr::write_bytes(pool as *mut u8, 0, 4096 * 2);
        core::ptr::write_bytes(test_phys as *mut u8, 0, 4096);
    }

    hal.map_ram_identity(root_pt, 3, false);
    // A VA in GiB 3 (0xC000_0000) — deliberately ABOVE the 3 GiB
    // `map_ram_identity` just identity-mapped, so its PDPT slot is still
    // absent and `map_range` must walk/allocate PD + PT for it, exactly
    // like the fine-grained mappings a real per-process address space
    // needs (`.user_text` etc., once that follow-up lands).
    const TEST_VA: usize = 0xC000_0000;
    let n = hal.map_range(root_pt, TEST_VA, test_phys, 4096, 1 | 2, pool, 2);
    if n == u32::MAX {
        kernel_arch_glue::log(format_args!("x86_64: paging self-test FAILED (map_range error)\r\n"));
        return;
    }
    hal.activate_address_space(root_pt);
    hal.flush_tlb();

    // SAFETY: `TEST_VA` was just mapped R+W by `map_range`, backed by
    // `test_phys` — writing through it and reading `test_phys` back
    // through its own (still identity-mapped, GiB 0-2) VA proves the
    // walker's translation is genuinely correct, not merely "whatever
    // was written comes back through the same pointer".
    let (via_va, via_identity) = unsafe {
        core::ptr::write_volatile(TEST_VA as *mut u32, 0x5eed_5eed);
        (
            core::ptr::read_volatile(TEST_VA as *const u32),
            core::ptr::read_volatile(test_phys as *const u32),
        )
    };
    kernel_arch_glue::log(format_args!(
        "x86_64: MMU read/write self-test - wrote {:#x} at VA {:#x}, read back {:#x}, kernel sees {:#x} at PA {:#x} -> {}\r\n",
        0x5eed_5eed_u32,
        TEST_VA,
        via_va,
        via_identity,
        test_phys,
        if via_va == 0x5eed_5eed && via_identity == 0x5eed_5eed {
            "OK"
        } else {
            "MISMATCH"
        }
    ));
}

/// The syscall handler the HAL trap vector calls for an `ecall` from
/// U-mode (registered via `hal_riscv64::set_syscall_handler`). Runs at
/// S-mode privilege.
#[cfg(target_arch = "riscv64")]
fn simurgh_syscall(
    a7: usize,
    a0: usize,
    a1: usize,
    _a2: usize,
    _a3: usize,
    _a4: usize,
) -> hal_riscv64::cpu::TrapOutcome {
    use hal_riscv64::cpu::TrapOutcome;
    use kernel_core::{SyscallOp, SyscallReturn};
    use kernel_mm::KernelObjectType;

    // Two-process hand-off / reporting arms resolve to a non-`Resume`
    // outcome or run before the object-model borrow below.
    match a7 {
        sys::P2_YIELD => {
            return match kernel_arch_glue::p2_yield() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::P2_REPORT_A => {
            kernel_arch_glue::p2_report_a(a0);
            return TrapOutcome::Resume(0);
        }
        sys::P2_REPORT_B => {
            kernel_arch_glue::p2_report_b(a0);
            return TrapOutcome::Resume(0);
        }
        sys::P2_PREEMPT_START => {
            spawn_device_manager(kernel_arch_glue::khal());
            let _ = spawn_faulty_driver(kernel_arch_glue::khal());
            return match kernel_arch_glue::p2_preempt_start() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::DM_REPORT => {
            let name = match a0 {
                0 => "Starting",
                1 => "Running",
                2 => "Restarting",
                3 => "Failed",
                _ => "?",
            };
            kernel_arch_glue::log(format_args!(
                "device-manager (U-mode, isolated subsystem process): state={name} restarts_in_window={a1}\r\n"
            ));
            if a0 == 3 {
                // `Failed`: device-manager has given up and drops into
                // its own "spin forever" idle (matches every other demo
                // process's convention) — it will never again call
                // `DM_WAIT_CRASH`/`DM_RESPAWN_DRIVER`, so it must stop
                // being exempt from ordinary preemption (`p2_tick`'s
                // `DM_TID` check), or it would monopolize the CPU forever
                // and starve A/B/C's own fairness demo. A real bug hit
                // via QEMU: `s_timer` fired ~12500 times in a tight
                // re-arm loop with zero forward progress once
                // device-manager's exemption outlived its purpose.
                kernel_arch_glue::p2_dm_supervision_done();
            }
            return TrapOutcome::Resume(0);
        }
        sys::DM_WAIT_CRASH => {
            return match kernel_arch_glue::p2_dm_wait_crash() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::DM_POLL_CRASH => {
            return TrapOutcome::Resume(kernel_arch_glue::p2_poll_crash());
        }
        sys::DM_RESPAWN_DRIVER => {
            return match spawn_faulty_driver(kernel_arch_glue::khal()) {
                Some(new_tid) => match kernel_arch_glue::p2_dm_handoff_to_driver(new_tid) {
                    Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                    None => TrapOutcome::Resume(0),
                },
                None => TrapOutcome::Resume(0),
            };
        }
        // Real Call/Recv/Reply demo (see `sys::IPC_DEMO_START`'s own doc
        // comment) — every arm here calls `kernel_arch_glue::kstate().
        // sched.running()` for "who trapped", not the hardcoded `root`
        // every OTHER opcode above uses: those are only ever called BY
        // root in this demo, but IPC_RECV/IPC_REPLY are called by the
        // SERVER thread too.
        sys::IPC_DEMO_START => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_demo_start(hal, caller, umode_ipc_server as usize) {
                Some((ep, save, into)) => {
                    // SAFETY: single-core; only this arm writes G_IPC_EP,
                    // before either the client or the server can read it.
                    unsafe { core::ptr::addr_of_mut!(G_IPC_EP).write(ep) };
                    TrapOutcome::SwitchTo { save, into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        sys::IPC_ENDPOINT_CAP => {
            // SAFETY: single-core; written once by IPC_DEMO_START before
            // either caller of this opcode can run.
            return TrapOutcome::Resume(unsafe { core::ptr::addr_of!(G_IPC_EP).read() } as usize);
        }
        sys::IPC_CALL => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_call(hal, caller, a0 as u32, a1 as u64) {
                Some(sw) => {
                    if let Some((p0, p1)) = sw.poke {
                        // SAFETY: `sw.into` is a kernel-owned, currently
                        // not-executing `HAL_USER_CONTEXT_BYTES` blob —
                        // `p2_ipc_call`'s own contract.
                        unsafe { hal_riscv64::cpu::poke_saved_a0_a1(sw.into as *mut u8, p0, p1) };
                    }
                    // The L4-style register-only fast path
                    // (02-Microkernel-Layer.md §5.3/§8.3) — see
                    // `hal_riscv64::cpu::TrapOutcome::SwitchToFast`'s own
                    // doc comment for exactly which registers this skips
                    // and why it is safe to.
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        sys::IPC_RECV => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_recv(hal, caller, a0 as u32) {
                Some(kernel_arch_glue::IpcRecvOutcome::Immediate { from, label }) => {
                    TrapOutcome::Resume2(from, label)
                }
                Some(kernel_arch_glue::IpcRecvOutcome::Switch(sw)) => {
                    // `poke` is always `None` here — WE are the one
                    // blocking (nothing to poke into our own trap; the
                    // ordinary `Resume`/`Resume2` path handles that),
                    // not being woken via a direct hand-off.
                    // The L4-style register-only fast path
                    // (02-Microkernel-Layer.md §5.3/§8.3) — see
                    // `hal_riscv64::cpu::TrapOutcome::SwitchToFast`'s own
                    // doc comment for exactly which registers this skips
                    // and why it is safe to.
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume2(0, 0),
            };
        }
        sys::IPC_REPLY => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate()
                .sched
                .running()
                .unwrap_or(kernel_arch_glue::kstate().root_thread);
            return match kernel_arch_glue::p2_ipc_reply(hal, caller, a0 as u32, a1 as u64) {
                Some(sw) => {
                    if let Some((p0, p1)) = sw.poke {
                        // SAFETY: same contract as IPC_CALL's own poke
                        // above.
                        unsafe { hal_riscv64::cpu::poke_saved_a0_a1(sw.into as *mut u8, p0, p1) };
                    }
                    // The L4-style register-only fast path
                    // (02-Microkernel-Layer.md §5.3/§8.3) — see
                    // `hal_riscv64::cpu::TrapOutcome::SwitchToFast`'s own
                    // doc comment for exactly which registers this skips
                    // and why it is safe to.
                    TrapOutcome::SwitchToFast { save: sw.save, into: sw.into }
                }
                None => TrapOutcome::Resume(0),
            };
        }
        // fs-native: the REAL FsRequest/FsResponse wire protocol (see
        // `sys::FS_DEMO_START`'s own doc comment) — always called by
        // root in this demo, so `kstate().root_thread` (not `sched.
        // running()`) is correct here, unlike the generic IPC arms
        // above (which the SERVER thread also calls).
        sys::FS_DEMO_START => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            return match kernel_arch_glue::fs_demo_start(hal, caller, FS_NATIVE_ELF, elf_loader::machine::EM_RISCV) {
                Some((ep, save, into)) => {
                    // SAFETY: single-core; only this arm writes G_FS_EP,
                    // before any later FS_OPEN/FS_STAT/FS_CLOSE call.
                    unsafe { core::ptr::addr_of_mut!(G_FS_EP).write(ep) };
                    TrapOutcome::SwitchTo { save, into }
                }
                None => TrapOutcome::Resume(usize::MAX),
            };
        }
        sys::FS_OPEN => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: single-core; written once by FS_DEMO_START, before
            // any FS_OPEN call.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP).read() };
            return match kernel_arch_glue::fs_open_call(hal, caller, ep, a0 as u32, a1 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_OPEN_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_open_result());
        }
        sys::FS_STAT => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP).read() };
            return match kernel_arch_glue::fs_stat_call(hal, caller, ep, a0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_STAT_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_stat_result());
        }
        sys::FS_CLOSE => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP).read() };
            return match kernel_arch_glue::fs_close_call(hal, caller, ep, a0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_CLOSE_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_close_result());
        }
        sys::FS_WRITE => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP).read() };
            return match kernel_arch_glue::fs_write_call(hal, caller, ep, a0 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_WRITE_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_write_result());
        }
        sys::FS_READ => {
            let hal = kernel_arch_glue::khal();
            let caller = kernel_arch_glue::kstate().root_thread;
            // SAFETY: same contract as FS_OPEN's own read.
            let ep = unsafe { core::ptr::addr_of!(G_FS_EP).read() };
            return match kernel_arch_glue::fs_read_call(hal, caller, ep, a0 as u32, a1 as u32) {
                Some(sw) => TrapOutcome::SwitchToFast { save: sw.save, into: sw.into },
                None => TrapOutcome::Resume(0),
            };
        }
        sys::FS_READ_RESULT => {
            return TrapOutcome::Resume(kernel_arch_glue::fs_read_result());
        }
        _ => {}
    }

    let k = kernel_arch_glue::kstate();
    let hal = kernel_arch_glue::khal();
    let root = k.root_thread;

    let ret: usize = match a7 {
        sys::DEBUG_LOG => {
            // SAFETY: MVP single-address-space (satp=0). `a0..a0+a1` is a
            // byte range in the shared address space; treat invalid UTF-8
            // leniently. A real kernel validates the pointer against the
            // caller's address space first.
            let bytes = unsafe { core::slice::from_raw_parts(a0 as *const u8, a1) };
            let text = core::str::from_utf8(bytes).unwrap_or("<non-utf8>");
            kernel_arch_glue::log(format_args!("{}", text));
            0
        }
        sys::RETYPE_ENDPOINT => {
            match k.dispatch(
                root,
                hal.now_ns(),
                SyscallOp::Retype {
                    untyped: kernel_cap::CapId::new(0),
                    target_type: KernelObjectType::Endpoint,
                    count: 1,
                },
                hal,
            ) {
                Ok(SyscallReturn::NewCaps { cap, .. }) => cap.as_u32() as usize,
                _ => usize::MAX,
            }
        }
        sys::MAP_PAGE => {
            // Retype a real Frame (Untyped) capability, then the REAL,
            // capability-gated `Map` syscall: `do_map` resolves
            // `page_table` (WRITE) and `frame` (rights matching `perms`),
            // records the software-model mapping, AND walks a genuine
            // Sv39 leaf into the LIVE page table (the map pool `enter`
            // installed makes this real, not just a model update).
            let (frame_cap, frame_phys) = match alloc_root_frame(k, hal) {
                Some(f) => f,
                None => return TrapOutcome::Resume(usize::MAX),
            };
            match k.dispatch(
                root,
                hal.now_ns(),
                SyscallOp::Map {
                    page_table: k.root_page_table_cap,
                    frame: frame_cap,
                    vaddr: hal_core::VirtAddr::new(a0),
                    perms: hal_core::MapPermissions::KERNEL_DATA,
                },
                hal,
            ) {
                Ok(SyscallReturn::Mapped) => {}
                _ => return TrapOutcome::Resume(usize::MAX),
            }
            // SAFETY: single-core syscall path; only written here.
            unsafe {
                core::ptr::addr_of_mut!(LAST_MAPPED_FRAME).write(frame_phys);
                core::ptr::addr_of_mut!(LAST_MAPPED_FRAME_CAP).write(frame_cap.as_u32());
            }
            frame_phys
        }
        sys::MAP_ALIAS => {
            // SAFETY: single-core; set by the last MAP_PAGE.
            let (frame_phys, frame_cap) = unsafe {
                (
                    core::ptr::addr_of!(LAST_MAPPED_FRAME).read(),
                    kernel_cap::CapId::new(core::ptr::addr_of!(LAST_MAPPED_FRAME_CAP).read()),
                )
            };
            if frame_phys == 0 {
                return TrapOutcome::Resume(usize::MAX);
            }
            // Map the SAME Frame capability at a second VA — the
            // capability-gated form of the alias: the kernel does not
            // pick or trust a bare physical address, `do_map` resolves
            // `frame_cap` exactly like the first `Map` did.
            match k.dispatch(
                root,
                hal.now_ns(),
                SyscallOp::Map {
                    page_table: k.root_page_table_cap,
                    frame: frame_cap,
                    vaddr: hal_core::VirtAddr::new(a0),
                    perms: hal_core::MapPermissions::KERNEL_DATA,
                },
                hal,
            ) {
                Ok(SyscallReturn::Mapped) => {}
                _ => return TrapOutcome::Resume(usize::MAX),
            }
            0
        }
        sys::TRANSLATE => match k
            .addr_space_mut(k.root_addr_space)
            .and_then(|s| s.translate(hal_core::VirtAddr::new(a0)))
        {
            Some((pa, _perms)) => pa.as_usize(),
            None => usize::MAX,
        },
        sys::ALIVE => {
            kernel_arch_glue::log(format_args!(
                "root task (U-mode, ISOLATED under Sv39): alive, made an ecall from U=1 pages\r\n"
            ));
            0
        }
        sys::REPORT => {
            kernel_arch_glue::log(format_args!(
                "root task (U-mode): ecall result = {:#x}\r\n",
                a0
            ));
            0
        }
        sys::XCHECK => {
            // `a0` = the physical frame MAP_PAGE returned; `a1` = the u32
            // the Root Task read back through the alias VA. Read the same
            // frame through the kernel's own identity map and report
            // whether the U-mode write, the alias read, and the kernel
            // view all agree.
            // SAFETY: `a0` is a frame the kernel just allocated from
            // untyped and identity-maps `U=0` in the active table; a u32
            // read from it is valid and non-aliasing here.
            let at_phys = unsafe { core::ptr::read_volatile(a0 as *const u32) } as usize;
            let expected = unsafe { core::ptr::addr_of!(LAST_MAPPED_FRAME).read() };
            let ok = at_phys == a1 && a1 == 0x5EED && a0 == expected;
            kernel_arch_glue::log(format_args!(
                "root task (U-mode): zero-copy proof - U-mode wrote {:#x} at VA 0xd0000000, read {:#x} at alias VA 0xd0001000; kernel reads {:#x} at PA {:#x} -> {}\r\n",
                0x5EED_usize,
                a1,
                at_phys,
                a0,
                if ok { "ALL THREE AGREE" } else { "MISMATCH" }
            ));
            0
        }
        _ => usize::MAX,
    };
    TrapOutcome::Resume(ret)
}

/// The preemptive-scheduler tick handler the HAL trap vector calls for a
/// supervisor timer interrupt taken on a running U-mode thread
/// (registered via `hal_riscv64::cpu::set_tick_handler`). Delegates the
/// round-robin decision to `kernel-arch-glue`; `Some((save, into))`
/// preempts, `None` lets the current thread keep running.
#[cfg(target_arch = "riscv64")]
fn simurgh_tick() -> hal_riscv64::cpu::TrapOutcome {
    use hal_riscv64::cpu::TrapOutcome;
    match kernel_arch_glue::p2_tick() {
        Some((save, into)) => TrapOutcome::SwitchTo { save, into },
        None => TrapOutcome::Resume(0),
    }
}

/// The per-process fault-isolation handler the HAL trap vector calls for
/// a synchronous exception taken from a running U-mode thread that is
/// not an `ecall` (registered via `hal_riscv64::cpu::set_fault_handler`)
/// — 03-Kernel-Subsystems-Layer.md §2.1/§5.2. Delegates to
/// `kernel-arch-glue`, which terminates the faulting thread and picks
/// whatever else is runnable; `Some(into)` resumes it, `None` means
/// nothing else was runnable (fatal — the trap vector falls through to
/// the system-halt dump in that case).
#[cfg(target_arch = "riscv64")]
fn simurgh_fault(cause_code: usize, sepc: usize, stval: usize) -> hal_riscv64::cpu::TrapOutcome {
    use hal_riscv64::cpu::TrapOutcome;
    match kernel_arch_glue::p2_fault(cause_code, sepc, stval) {
        Some(into) => TrapOutcome::Terminate { into },
        None => TrapOutcome::Resume(0),
    }
}

// Linker symbols for the user (layer-3) Root Task image — see
// hal-riscv64/src/linker.ld's `.user_text` / `.user_stack` sections.
#[cfg(target_arch = "riscv64")]
unsafe extern "C" {
    static __user_text_start: u8;
    static __user_text_end: u8;
    static __user_text_lma: u8;
    static __user_stack_start: u8;
    static __user_stack_end: u8;
    static __user_stack_lma: u8;
}

/// Reads the `.user_*` linker symbols into the descriptor `enter` needs to
/// map the Root Task's pages `U=1` before dropping to U-mode.
#[cfg(target_arch = "riscv64")]
fn user_image() -> kernel_arch_glue::UserImage {
    let sym = |s: &u8| s as *const u8 as usize;
    // SAFETY: these are linker-defined addresses, taken by reference only,
    // never dereferenced — the standard idiom for consuming linker script
    // symbols.
    unsafe {
        kernel_arch_glue::UserImage {
            text_vma: sym(&__user_text_start),
            text_lma: sym(&__user_text_lma),
            text_len: sym(&__user_text_end) - sym(&__user_text_start),
            stack_vma: sym(&__user_stack_start),
            stack_lma: sym(&__user_stack_lma),
            stack_len: sym(&__user_stack_end) - sym(&__user_stack_start),
            entry_vma: umode_root as usize,
            worker_entry_vma: umode_worker as usize,
            subsystem_entry_vma: umode_subsystem as usize,
            a_loop_entry_vma: umode_a_loop as usize,
        }
    }
}

/// Layer-3 subsystems as processes (IMPLEMENTATION-PLAN.md follow-up):
/// runs `root-task`'s REAL `plan_boot` (not a re-derived shortcut) and
/// launches Device Manager — `Service::BOOT_ORDER[0]` — as a genuinely
/// isolated process via the SAME generic `kernel_arch_glue::spawn_process`
/// that spawns this demo's own process C, so it joins the SAME
/// preemption loop. Called once, from the `P2_PREEMPT_START` ecall
/// handler (the same transition point process C joins at, and for the
/// same reason: `plan_boot`'s in-kernel computation touches nothing
/// U-mode-visible, so its timing relative to the cooperative phase
/// doesn't matter, but doing it here keeps every "who else joins the
/// preemption loop" decision in one place).
#[cfg(target_arch = "riscv64")]
fn spawn_device_manager(hal: &hal_core::HalInterface) {
    let k = kernel_arch_glue::kstate();

    // The Root Task's own untyped total stands in for "RAM this boot has
    // to plan with" at this MVP stage (a real Root Task would sum every
    // `UntypedMemory` capability it holds, not just query the kernel
    // directly like this).
    let total = k.total_untyped_bytes();
    match root_task::plan_boot(total) {
        Ok(plan) => {
            kernel_arch_glue::log(format_args!(
                "root task: plan_boot({} bytes) - root reserve {} bytes, {} service grant(s), {} bytes free\r\n",
                total,
                plan.root_reserve_bytes,
                plan.grants.len(),
                plan.free_bytes
            ));
            for g in plan.grants.iter() {
                kernel_arch_glue::log(format_args!(
                    "root task: plan_boot grant - {:?}: {} bytes\r\n",
                    g.service, g.bytes
                ));
            }
        }
        Err(e) => {
            kernel_arch_glue::log(format_args!(
                "root task: plan_boot failed: {:?} - device-manager not spawned\r\n",
                e
            ));
            return;
        }
    }

    // Device Manager is BOOT_ORDER[0] — launch it for real, from its OWN
    // separately-built ELF image (`device-manager-bin`, embedded via
    // `DEVICE_MANAGER_ELF` below — see `spawn_process_from_elf`'s doc
    // comment for how this differs from `spawn_process`'s "shares the
    // kernel's own `.user_text`" approach every other demo process here
    // still uses) on its OWN fresh stack/address space/capability space.
    const DM_STACK_VMA: usize = 0xC040_0000;
    // 64 KiB, not the 16 KiB every other spawned demo process uses:
    // device-manager's own ecall handlers (`DM_RESPAWN_DRIVER`) now call
    // BACK INTO `spawn_process` itself, on device-manager's OWN stack (an
    // `ecall`'s handler runs on the caller's stack — see `raw_syscall`'s
    // doc comment) — and `kernel`/`kernel-arch-glue`'s unoptimized (`dev`
    // profile, no per-package `opt-level` override unlike `device-manager`
    // itself) call chain into `spawn_process` needs real headroom.
    // **Bug found via QEMU** (`-d int`): with the old 16 KiB, the very
    // first `DM_RESPAWN_DRIVER` overflowed BELOW `DM_STACK_VMA` (unmapped)
    // — `trap_entry`'s own prologue then faulted pushing the NEXT trap
    // frame onto the now-invalid `sp`, an infinite recursive-trap storm
    // (millions of `store_page_fault`/`fault_store` entries at
    // `trap_entry`'s first instruction, `tval` walking down from just
    // below `DM_STACK_VMA` in exact `sizeof(TrapFrame)`=248-byte steps).
    const DM_STACK_LEN: usize = 4096 * 16;
    match kernel_arch_glue::spawn_process_from_elf(
        hal,
        k,
        DEVICE_MANAGER_ELF,
        elf_loader::machine::EM_RISCV,
        DM_STACK_VMA,
        DM_STACK_LEN,
    ) {
        Some((tid, _cap_space, _stack_phys)) => {
            kernel_arch_glue::p2_register_device_manager(tid);
            kernel_arch_glue::log(format_args!(
                "root task: spawned device-manager (tid {}) from its OWN separately-built ELF image, joining the preemption loop\r\n",
                tid.as_u32()
            ));
        }
        None => kernel_arch_glue::log(format_args!(
            "root task: device-manager spawn skipped (out of resources)\r\n"
        )),
    }
}

/// Spawns `umode_faulty_driver` (see its doc comment) via the SAME
/// generic `kernel_arch_glue::spawn_process` path as device-manager, so
/// it joins the same preemption loop and its crash can be observed
/// happening concurrently with the rest of the demo — the real §5.2
/// proof point is that A/B/C and device-manager are unaffected by it.
/// Returns the new thread's id (or `None` if spawning failed) so a
/// respawn caller (`sys::DM_RESPAWN_DRIVER`) can hand off to it directly.
#[cfg(target_arch = "riscv64")]
fn spawn_faulty_driver(hal: &hal_core::HalInterface) -> Option<kernel_cap::ThreadId> {
    let k = kernel_arch_glue::kstate();
    let user = user_image();
    const FAULTY_STACK_VMA: usize = 0xC050_0000;
    const FAULTY_STACK_LEN: usize = 4096 * 4;
    match kernel_arch_glue::spawn_process(
        hal,
        k,
        user.text_vma,
        user.text_lma,
        user.text_len,
        FAULTY_STACK_VMA,
        FAULTY_STACK_LEN,
        umode_faulty_driver as usize,
    ) {
        Some((tid, _cap_space, _stack_phys)) => {
            kernel_arch_glue::p2_watch_driver(tid);
            kernel_arch_glue::log(format_args!(
                "root task: spawned faulty-driver (tid {}) - it will fault on its first instruction (fault-isolation demo, 03 5.2)\r\n",
                tid.as_u32()
            ));
            Some(tid)
        }
        None => {
            kernel_arch_glue::log(format_args!(
                "root task: faulty-driver spawn skipped (out of resources)\r\n"
            ));
            None
        }
    }
}

// ----------------------------------------------------------------------------
// kernel_main — architecture-independent body
// ----------------------------------------------------------------------------

#[no_mangle]
pub extern "Rust" fn kernel_main(hal: hal_core::HalInterface, boot_info: BootInfo) -> ! {
    // `hal` arrives BY VALUE, so it would otherwise live in THIS
    // function's own stack frame for the rest of boot — `kernel_main`
    // never returns, so every downstream `&hal` reference (`enter`'s own
    // `G_HAL` included) stays validly pointing at it for as long as
    // nothing EVER writes back over that stack region. That held for
    // riscv64/x86_64 (SP only ever descends further) and for aarch64
    // before `hal_arm64::cpu::restore_user_and_eret`'s own SP-reset fix
    // (see its doc comment for the full story) — but once a `SwitchTo`/
    // `Terminate` there resets SP_EL1 to a fixed top-of-stack baseline
    // on every process switch, LATER exception handling reuses and
    // overwrites this exact memory, corrupting `hal`'s own bytes the
    // moment a deep-enough call chain reaches them (root-caused via
    // bisection: `G_HAL`'s own stored POINTER survives, since it is
    // itself a separate, genuinely-static 8-byte slot, but
    // dereferencing THROUGH it — e.g. `hal.now_ns()`'s indirect call
    // via a function-pointer field of the now-corrupted `HalInterface`
    // bytes — silently jumps to garbage). Moving `hal` into `.bss` here
    // (mirrors `KernelState::init_global`'s own "no stack temporary"
    // rationale) makes it immune regardless of what any architecture's
    // own SP does afterward. (`boot_info: &BootInfo` is NOT similarly
    // hazardous — `enter` only reads through it locally, never storing
    // the pointer past its own call.)
    static mut HAL_STORAGE: core::mem::MaybeUninit<hal_core::HalInterface> =
        core::mem::MaybeUninit::uninit();
    // SAFETY: single-core boot, `kernel_main` runs exactly once, before
    // this static is read anywhere else. `addr_of_mut!`/`addr_of!` avoid
    // forming an intermediate `&mut`/`&` to the `static mut` itself,
    // matching `KernelState::init_global`'s own idiom.
    let hal: &'static hal_core::HalInterface = unsafe {
        core::ptr::addr_of_mut!(HAL_STORAGE)
            .cast::<hal_core::HalInterface>()
            .write(hal);
        &*core::ptr::addr_of!(HAL_STORAGE).cast::<hal_core::HalInterface>()
    };
    SerialWriter::init();
    let mut s = SerialWriter;

    let _ = writeln!(s, "|======================================================================|");
    let _ = writeln!(s, "|   Simurgh Operating System - Microkernel (Phase 2)  v0.1.0            |");
    let _ = writeln!(s, "|======================================================================|");

    match kernel_arch_glue::build(hal, &boot_info, serial_log) {
        Ok((report, state)) => {
            let _ = writeln!(s, "boot protocol            : {:?}", report.protocol);
            let _ = writeln!(s, "cpu cores (HalInterface) : {}", report.cpu_cores);
            let _ = writeln!(s, "timer frequency          : {} Hz", report.timer_hz);
            let _ = writeln!(s, "UntypedMemory objects    : {}", report.untyped_objects);
            let _ = writeln!(
                s,
                "total untyped memory     : {} bytes",
                report.total_untyped_bytes
            );
            let _ = writeln!(s, "root task thread id      : {}", report.root_thread);
            let _ = writeln!(s, "first scheduled thread   : {:?}", report.first_scheduled);
            let _ = writeln!(s, "KernelState built: OK");
            let _ = writeln!(s, "----------------------------------------------------------------------");
            let _ = writeln!(s, "handing control to the Root Task...");
            // Register the S-mode syscall handler the HAL trap vector
            // invokes for an `ecall` from U-mode, the tick handler it
            // invokes for a supervisor timer interrupt on a U-mode thread,
            // and the fault handler it invokes for any other synchronous
            // exception taken from U-mode (03-Kernel-Subsystems-Layer.md
            // §2.1/§5.2 per-process fault isolation).
            #[cfg(target_arch = "riscv64")]
            hal_riscv64::cpu::set_syscall_handler(simurgh_syscall);
            #[cfg(target_arch = "riscv64")]
            hal_riscv64::cpu::set_tick_handler(simurgh_tick);
            #[cfg(target_arch = "riscv64")]
            hal_riscv64::cpu::set_fault_handler(simurgh_fault);
            // Real x86_64 paging self-test (see its own doc comment) —
            // an independent, kernel-mode-only sanity check that stays
            // useful even now that `enter` below ALSO does real paging
            // (for the Root Task's own, separate address space): if the
            // U-mode path below ever regresses, this narrows whether
            // paging itself or the U-mode/syscall boundary specifically
            // is at fault.
            #[cfg(target_arch = "x86_64")]
            x86_64_paging_selftest(hal, state);
            // Register the syscall handler `hal_x86_64::cpu`'s
            // dedicated `int 0x80` (DPL 3) trampoline calls.
            #[cfg(target_arch = "x86_64")]
            hal_x86_64::cpu::set_syscall_handler(simurgh_syscall_x86);
            // Register the per-process fault-isolation handler
            // `hal_x86_64::cpu`'s dedicated `#UD` trampoline calls
            // (03-Kernel-Subsystems-Layer.md §2.1/§5.2).
            #[cfg(target_arch = "x86_64")]
            hal_x86_64::cpu::set_fault_handler(simurgh_fault_x86);
            // Register the preemptive-scheduler tick handler
            // `hal_x86_64::cpu`'s dedicated LAPIC-timer trampoline calls
            // (02-Microkernel-Layer.md §4).
            #[cfg(target_arch = "x86_64")]
            hal_x86_64::cpu::set_tick_handler(simurgh_tick_x86);
            // Register the syscall handler `hal_arm64::cpu`'s shared
            // EL0-synchronous vector calls.
            #[cfg(target_arch = "aarch64")]
            hal_arm64::cpu::set_syscall_handler(simurgh_syscall_aarch64);
            // Register the per-process fault-isolation handler the SAME
            // shared vector calls for a fatal EL0 exception that is not
            // a `svc` (03-Kernel-Subsystems-Layer.md §2.1/§5.2).
            #[cfg(target_arch = "aarch64")]
            hal_arm64::cpu::set_fault_handler(simurgh_fault_aarch64);
            // Register the preemptive-scheduler tick handler the SAME
            // shared EL0 IRQ vector calls for the timer PPI landing on a
            // running U-mode thread (02-Microkernel-Layer.md §4).
            #[cfg(target_arch = "aarch64")]
            hal_arm64::cpu::set_tick_handler(simurgh_tick_aarch64);
            // Never returns: runs the in-kernel demo, then (riscv64/
            // x86_64/aarch64) maps the user image U=1/AP_USER, activates
            // paging, and drops the Root Task to U-mode/EL0 isolated.
            #[cfg(target_arch = "riscv64")]
            {
                kernel_arch_glue::enter(hal, state, user_image(), &boot_info)
            }
            #[cfg(target_arch = "x86_64")]
            {
                kernel_arch_glue::enter(hal, state, user_image(), &boot_info)
            }
            #[cfg(target_arch = "aarch64")]
            {
                kernel_arch_glue::enter(hal, state, user_image(), &boot_info)
            }
            #[cfg(not(any(
                target_arch = "riscv64",
                target_arch = "x86_64",
                target_arch = "aarch64"
            )))]
            {
                kernel_arch_glue::enter(hal, state, kernel_arch_glue::UserImage::EMPTY, &boot_info)
            }
        }
        Err(e) => {
            let _ = writeln!(s, "kernel bring-up FAILED: {e:?}");
            halt_forever()
        }
    }
}

// ----------------------------------------------------------------------------
// Halt — architecture-specific instruction, identical structure
// ----------------------------------------------------------------------------

fn halt_forever() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: cli+hlt is the standard x86_64 terminal halt.
        unsafe {
            core::arch::asm!("cli");
            core::arch::asm!("hlt");
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: masking DAIF then wfi is the standard AArch64 terminal halt.
        unsafe {
            core::arch::asm!("msr daifset, #0xF");
            core::arch::asm!("wfi");
        }
        #[cfg(target_arch = "riscv64")]
        // SAFETY: clearing SIE then wfi is the standard RISC-V terminal halt.
        unsafe {
            core::arch::asm!("csrci sstatus, 0x2");
            core::arch::asm!("wfi");
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    SerialWriter::init();
    let mut s = SerialWriter;
    let _ = writeln!(s, "KERNEL PANIC: {info}");
    halt_forever();
}
