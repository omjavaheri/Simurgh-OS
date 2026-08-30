//! ============================================================================
//! kernel-arch-glue
//!
//! Purpose: the small amount of code that sits between `hal-core` (layer 1)
//! and `kernel-core` (layer 2). It:
//!   1. `build` - takes the HAL handoff (`HalInterface` + `BootInfo`),
//!      validates it, and builds the initial `KernelState` (first
//!      `UntypedMemory` objects + the Root Task - 02-Microkernel-Layer.md
//!      §8.1);
//!   2. `enter` - seeds the Root Task's register context (entry point +
//!      stack) via the HAL and performs the first `context_switch` into
//!      it, so the Root Task actually starts executing.
//!
//! It is written only against hal-core's architecture-ERASED surface, so
//! it holds no `#[cfg(target_arch)]` and names no architecture crate
//! (00-Overview.md principle 5; REPO-Simurgh-OS.md §8).
//!
//! Architecture reference: 02-Microkernel-Layer.md §0 (HAL↔kernel is a
//! direct call), §7 (this crate bridges hal-core traits to kernel-core),
//! §8.1/§8.2 (boot acceptance: first `UntypedMemory` objects; a running
//! Root Task); 01-HAL-Layer.md §0.
//!
//! MVP boundary: the Root Task here runs IN-KERNEL (same privilege, and it
//! reaches the kernel by calling `KernelState::dispatch` directly rather
//! than through an `ecall`/trap). That is a documented stepping stone —
//! the real user/kernel privilege split and the syscall trap boundary
//! (02-Microkernel-Layer.md §0, the layer-2↔layer-3 border) are the next
//! milestone. What this milestone proves: the HAL→kernel→Root-Task control
//! transfer and the object model both work on real hardware.
//!
//! Safety/invariants: `build`/`enter` run exactly once, on the boot core,
//! before anything else. The `static` scratch (Root Task stack, the
//! `KernelState`/`HalInterface`/logger pointers) is only touched from that
//! single-core boot path.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

use core::fmt::Arguments;
use hal_core::{BootInfo, HalInterface, MapPermissions, VirtAddr};
use kernel_cap::{CapId, CapabilityRights, ThreadId};
use kernel_core::{KernelInitError, KernelState, PreemptStep, SyscallOp, SyscallReturn, ThreadState};
use kernel_ipc::SmallMessage;
use kernel_mm::KernelObjectType;

/// Per-thread stack size (64 KiB - the same figure the arch boot stacks
/// use). Lives in `.bss`, 16-byte aligned per every target ABI.
pub const THREAD_STACK_SIZE: usize = 64 * 1024;

/// 16-byte-aligned backing storage for one thread stack. The bytes are
/// only ever addressed (never read as a value), hence `dead_code`.
#[repr(align(16))]
#[allow(dead_code)]
struct Aligned([u8; THREAD_STACK_SIZE]);

// Single-core boot scratch. Written once before the corresponding switch,
// read on the other stack. (The U-mode Root Task's own stack is
// `.user_stack` in the final binary, not here — see `UserImage`.)
static mut THREAD2_STACK: Aligned = Aligned([0; THREAD_STACK_SIZE]);
static mut THREAD3_STACK: Aligned = Aligned([0; THREAD_STACK_SIZE]);
/// The real-trap-boundary IPC demo's SERVER thread (`p2_ipc_demo_start`,
/// `IPC_DEMO_START` — a genuine U-mode `Call`/`Recv`/`Reply` round trip,
/// unlike every OTHER demo process, which uses ad-hoc raw opcodes, not
/// the real `kernel_core::SyscallOp` IPC surface).
static mut THREAD_IPC_SERVER_STACK: Aligned = Aligned([0; THREAD_STACK_SIZE]);
static mut G_STATE: *mut KernelState = core::ptr::null_mut();
static mut G_HAL: *const HalInterface = core::ptr::null();
/// How many GiB `map_ram_identity` covers for the kernel's OWN image —
/// computed once by `enter` (see that function's own doc comment) and
/// read by every LATER `map_ram_identity` call (`setup_two_process`'s
/// space B, `spawn_process`'s per-process spaces), so they all agree
/// with space A's own identity map on where it's safe to place
/// `.user_text`/`.user_stack`. `3` is a safe pre-`enter` default (matches
/// every use before this session's x86_64 work, when the constant really
/// was hardcoded to 3).
static mut G_BYTES_GIB: usize = 3;
static mut G_LOG: Option<fn(Arguments<'_>)> = None;
// The runtime `Map` syscall's hardware page-table pool used to live here
// (arch-glue-owned globals `map_user_page` drew from); it is now
// `KernelState::install_map_pool` / `map_pool_remaining` — plain integer
// bookkeeping owned by `kernel-core`, consumed by `syscall::do_map`
// itself, so a capability-gated `Map` and the hardware walk are the same
// syscall instead of two parallel mechanisms. `enter` still carves and
// zeroes the pool's physical memory (kernel-core never touches raw
// memory), then hands it to `KernelState` with one `install_map_pool` call.
// Set by `root_task_main` before it starts thread 2, so `thread2_main`
// knows its own thread id, the endpoint capability to `Send` on, and the
// Root Task's thread id to hand control back to. `G_T3` is the same idea
// for the §8.3 benchmark thread (`bench_thread_main`), started later on
// the same endpoint/root — `G_EP`/`G_ROOT` are reused unchanged.
static mut G_T2: u32 = 0;
static mut G_T3: u32 = 0;
static mut G_EP: u32 = 0;
static mut G_ROOT: u32 = 0;

/// Iterations for the `§8.3` IPC round-trip micro-benchmark below. Kept
/// small enough that a QEMU/TCG boot (which single-steps every
/// instruction, unlike real silicon) finishes in a reasonable time, while
/// still large enough to average out the first couple of iterations'
/// cold-cache noise.
const IPC_BENCH_ITERATIONS: u32 = 200;

// ---------------------------------------------------------------------------
// Two-process proof (02-Microkernel-Layer.md §8.4 zero-copy + §4 preemption).
//
// `enter` builds a SECOND, fully isolated Sv39 address space with its own
// U-mode thread (a real `kernel-core` TCB — its saved U-mode context lives
// in `Tcb::user_context`, and `kernel-sched` round-robins the two), and
// maps ONE physical frame into both spaces at different virtual addresses.
// First a cooperative round-trip (`P2_YIELD` ecall) proves the frame is
// genuinely shared with no copy across the MMU boundary; then
// `P2_PREEMPT_START` arms the timer and the two threads run counting loops
// switched by the timer interrupt alone (`p2_tick` -> `KernelState::
// preempt_tick`).
//
// A THIRD process (space C) is then spawned via the GENERIC `spawn_process`
// helper below — not the hand-written A/B setup — and joins the SAME
// preemption loop with no changes to `p2_tick`/`preempt_tick`/`pick_next`:
// admitting any thread via `init_user_thread` is enough for `kernel-sched`
// to round-robin it. This is the proof that the mechanism generalizes
// beyond exactly two hardcoded processes (a step toward
// 03-Kernel-Subsystems-Layer.md §5's subsystems-as-processes).
// ---------------------------------------------------------------------------

/// Physical frame shared by both address spaces.
static mut P2_SHARED_PHYS: usize = 0;
/// Virtual address the shared frame is mapped at in space A / space B.
static mut P2_VA_A: usize = 0;
static mut P2_VA_B: usize = 0;
/// What process B reported reading through its VA (set by `p2_report_b`).
static mut P2_B_SAW: usize = 0;
/// Supervisor-timer ticks seen since `p2_preempt_start` armed the timer.
static mut P2_TICKS: u32 = 0;
/// Physical address of process C's private counter word (see
/// `spawn_process` / `PROC_C_ENTRY`), or `0` if it was never spawned
/// (e.g. `spawn_process` ran out of untyped RAM — the demo then falls
/// back to reporting just A/B, unaffected).
static mut P3_COUNTER_PHYS: usize = 0;
/// `.user_text`'s vma/lma/len and process C's entry point, stashed by
/// `setup_two_process` for `p2_preempt_start` to spawn it from — see
/// that function's doc comment for why the spawn is deferred this late.
static mut G_TEXT_VMA: usize = 0;
static mut G_TEXT_LMA: usize = 0;
static mut G_TEXT_LEN: usize = 0;
static mut G_SUBSYS_ENTRY: usize = 0;
/// Process A's entry point for the FRESH, vruntime-zero thread
/// `p2_preempt_start` hands the counting loop to — see that function's
/// doc comment for why root's own (heavily-run) TCB is not reused here.
static mut G_A_LOOP_ENTRY: usize = 0;
/// Stack pointer that fresh thread starts with — reusing the SAME VA
/// root's own U-mode stack already ends at (still `U=1 R+W` mapped in
/// space A); safe because the loop is pure register ops and never
/// pushes a frame, so nothing about the stack's prior contents matters.
static mut G_A_STACK_TOP: usize = 0;

/// The sentinel process A writes before the first hand-off, and the one
/// process B writes back. Kept here so the kernel-side cross-check and
/// the U-mode `sw` immediates cannot drift (the U-mode code hard-codes
/// the same values as bare immediates — see `kernel/src/main.rs`).
const P2_A_SENTINEL: usize = 0xC0DE;
const P2_B_SENTINEL: usize = 0xB00B;

// ---------------------------------------------------------------------------
// Real IPC-driven driver supervision demo (03-Kernel-Subsystems-Layer.md
// §5.2's actual acceptance test: device-manager reacts to a REAL driver
// crash, not its own timer). Device Manager blocks on `p2_dm_wait_crash`;
// `p2_fault` hands off DIRECTLY to it (`KernelState::
// terminate_thread_and_handoff`, not the generic fairness-driven
// `terminate_thread`) when the WATCHED driver thread specifically is the
// one that faulted, handing over the raw trap values via `PENDING_CRASH`
// (consumed by `p2_poll_crash`) — the same sticky signal-then-poll shape
// as `kernel_ipc::Notification`, just realized on this demo's own raw
// -ecall ABI instead of the general capability-checked syscall path
// (that path's own Send/Recv/Call blocking semantics are a separate,
// still-unresolved design question — see IMPLEMENTATION-PLAN.md).
//
// The hand-off targets device-manager's OWN, PERMANENT `ThreadId`
// (`DM_TID`) UNCONDITIONALLY, not "whichever thread most recently called
// `p2_dm_wait_crash` and is registered as blocked" — two real QEMU-found
// bugs converge on why: (1) device-manager's own vruntime (real
// wall-clock nanoseconds under QEMU/TCG for each genuine `spawn_process`
// respawn it does) can exceed the demo's long-running A/B/C counting
// loops', so a plain fairness-driven `pick_next` can starve it forever
// right after an ordinary wake; (2) with the 40-tick preemption timer
// STILL armed (the crash/restart cycle and that timer run concurrently),
// device-manager can be preempted by an ORDINARY timer tick — not
// `block_thread` — between one respawn and its next `DM_WAIT_CRASH`
// call, leaving no "registered waiter" for `p2_fault` to find even
// though device-manager is unambiguously who should run next. Both
// collapse to the same fix: always target `DM_TID` directly. This is
// safe unconditionally because device-manager can never itself be
// `self.sched.running()` at the exact instant some OTHER thread (the
// driver) traps — single-core, only one thread runs at a time — so it is
// always either `Ready` or `Blocked`, and `dispatch()` accepts either.
static mut WATCHED_DRIVER_TID: Option<ThreadId> = None;
/// The most recent watched-driver crash's raw trap values
/// (cause_code/sepc/stval), set by `p2_fault` and consumed by
/// `p2_poll_crash`. Sticky exactly like `kernel_ipc::Notification`'s
/// signal word: a crash that happens before device-manager gets around to
/// waiting is not lost.
static mut PENDING_CRASH: Option<(usize, usize, usize)> = None;
/// Device Manager's own, PERMANENT `ThreadId` (it is spawned once and
/// never respawned — only the driver is), recorded by `p2_register_
/// device_manager` right after `spawn_device_manager` succeeds. See the
/// section doc comment above for why `p2_fault` targets this
/// unconditionally rather than tracking "is device-manager currently
/// blocked".
static mut DM_TID: Option<ThreadId> = None;

/// Per-thread quantum for the preemption demo. 2 ms at QEMU virt's
/// 10 MHz timebase is 20 000 ticks — long enough that each process's
/// counting loop makes visible progress, short enough that the whole
/// demo finishes well inside a QEMU smoke run.
const P2_QUANTUM_NS: u64 = 2_000_000;
/// Stop preempting after this many ticks and report. Both counters
/// non-zero proves both processes ran with NO cooperative `P2_YIELD`.
const P2_TICK_BUDGET: u32 = 40;
/// Byte offsets into the shared frame each process bumps in its counting
/// loop — distinct words (the frame is ONE physical page aliased into
/// both spaces), clear of the `0`/`4` area the §8.4 round-trip used.
const P2_COUNTER_A_OFF: usize = 8;
const P2_COUNTER_B_OFF: usize = 12;

/// Routes a formatted line to the logger the boot binary installed via
/// `build`. A no-op if none was installed. Used by `klog!`.
pub fn log(args: Arguments<'_>) {
    // SAFETY: `G_LOG` is set once in `build` before any `log` call and
    // never mutated afterward; single-core.
    if let Some(f) = unsafe { core::ptr::addr_of!(G_LOG).read() } {
        f(args);
    }
}

/// `writeln!`-style logging through the boot binary's serial writer.
#[macro_export]
macro_rules! klog {
    ($($arg:tt)*) => { $crate::log(core::format_args!($($arg)*)) };
}

/// A summary of what `build` produced, for the boot binary to print over
/// serial (02-Microkernel-Layer.md §8.1 acceptance evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootReport {
    /// Boot protocol HAL reported (UEFI vs SBI+DT).
    pub protocol: hal_core::BootProtocol,
    /// Logical CPU cores, from the HAL interface.
    pub cpu_cores: usize,
    /// Monotonic timer frequency (Hz), from the HAL interface.
    pub timer_hz: u64,
    /// Number of `UntypedMemory` objects seeded for the Root Task.
    pub untyped_objects: u32,
    /// Total physical bytes those untyped objects cover.
    pub total_untyped_bytes: u64,
    /// The Root Task's thread id (raw).
    pub root_thread: u32,
    /// The thread the scheduler would run first (should be the Root Task).
    pub first_scheduled: Option<u32>,
}

/// Errors from `build`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunError {
    /// `BootInfo::validate` failed, or `KernelState::from_boot_info` did.
    Init(KernelInitError),
}

impl From<KernelInitError> for RunError {
    fn from(e: KernelInitError) -> Self {
        RunError::Init(e)
    }
}

/// Builds the initial kernel state from the HAL handoff and installs the
/// serial logger.
///
/// Steps: `BootInfo::validate` → `KernelState::init_global` (creates the
/// first `UntypedMemory` objects and the Root Task - 02-Microkernel-Layer.md
/// §8.1) → assemble a `BootReport`.
///
/// Returns the report plus a `'static` handle to the kernel state for
/// `enter` to drive. Does NOT start the Root Task (that is `enter`).
pub fn build(
    hal: &HalInterface,
    boot: &BootInfo,
    logger: fn(Arguments<'_>),
) -> Result<(BootReport, &'static mut KernelState), RunError> {
    // SAFETY: single-core boot, called once, before any `log` call.
    unsafe { core::ptr::addr_of_mut!(G_LOG).write(Some(logger)) };

    boot.validate()
        .map_err(|_| RunError::Init(KernelInitError::BadBootInfo))?;

    let state = KernelState::init_global(boot)?;
    let first_scheduled = state.sched.pick_next(hal.now_ns()).map(|t| t.as_u32());

    let report = BootReport {
        protocol: boot.protocol,
        cpu_cores: hal.core_count(),
        timer_hz: hal.frequency_hz(),
        untyped_objects: state.untyped_count,
        total_untyped_bytes: state.total_untyped_bytes(),
        root_thread: state.root_thread.as_u32(),
        first_scheduled,
    };
    Ok((report, state))
}

/// Where the final binary's user (layer-3) Root Task image lives: its
/// `.user_text` and `.user_stack` regions, each as a `(vma, lma, len)`
/// triple (linked for a virtual address, loaded at a physical address
/// inside the kernel image), plus the U-mode entry point's virtual
/// address. `enter` maps these `U=1` and drops to U-mode under paging.
/// `EMPTY` (all zero) means "this architecture has no user image yet" —
/// `enter` then just parks after the in-kernel demo.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserImage {
    /// `.user_text` virtual base.
    pub text_vma: usize,
    /// `.user_text` physical (load) base.
    pub text_lma: usize,
    /// `.user_text` byte length.
    pub text_len: usize,
    /// `.user_stack` virtual base.
    pub stack_vma: usize,
    /// `.user_stack` physical (load) base.
    pub stack_lma: usize,
    /// `.user_stack` byte length.
    pub stack_len: usize,
    /// Virtual address to begin U-mode execution at (inside `.user_text`).
    pub entry_vma: usize,
    /// Virtual address of the SECOND process's entry point (also inside
    /// `.user_text` — the two U-mode threads share the same code pages,
    /// different stacks and address spaces). `0` = no second process on
    /// this architecture, so `enter` runs only the single-process path.
    pub worker_entry_vma: usize,
    /// Virtual address of a THIRD process's entry point (again inside
    /// `.user_text`), spawned via the generic `spawn_process` — proof
    /// that address-space + capability-space + scheduler admission is a
    /// reusable mechanism, not hardcoded to exactly two processes. `0` =
    /// skip spawning it (e.g. no `worker_entry_vma` either, or this
    /// architecture has no user image at all).
    pub subsystem_entry_vma: usize,
    /// Virtual address of process A's counting-loop-only entry point
    /// (again inside `.user_text`) — a FRESH `vruntime = 0` thread
    /// `p2_preempt_start` spawns, sharing root's OWN address space and
    /// capability space, to take over the preemptive phase (see that
    /// function's doc comment for why root's own TCB isn't reused for
    /// it). `0` = skip (falls back to letting root's own TCB keep running
    /// — possibly starved for the reason documented there).
    pub a_loop_entry_vma: usize,
}

impl UserImage {
    /// No user image (non-riscv64 for now).
    pub const EMPTY: Self = Self {
        text_vma: 0,
        text_lma: 0,
        text_len: 0,
        stack_vma: 0,
        stack_lma: 0,
        stack_len: 0,
        entry_vma: 0,
        worker_entry_vma: 0,
        subsystem_entry_vma: 0,
        a_loop_entry_vma: 0,
    };
}

/// Runs the boot sequence and never returns:
///   1. stash the kernel-state / HAL pointers for later syscall handling;
///   2. run `inkernel_demo` (the in-kernel §8.1/§8.2/§8.5 milestones —
///      direct `dispatch` + `context_switch`, same privilege);
///   3. if a `user` image is present: build a page table (kernel
///      identity `U=0`, the `.user_*` pages `U=1`), activate paging, and
///      drop the Root Task to U-mode. From there it is a real, MMU-
///      isolated layer-3 process reaching the kernel only through a
///      syscall trap.
pub fn enter(
    hal: &HalInterface,
    state: &'static mut KernelState,
    user: UserImage,
    boot_info: &BootInfo,
) -> ! {
    // SAFETY: single-core boot, called once, right after `build`.
    unsafe {
        core::ptr::addr_of_mut!(G_STATE).write(state as *mut KernelState);
        core::ptr::addr_of_mut!(G_HAL).write(hal as *const HalInterface);
    }

    // How many GiB `map_ram_identity` must cover to keep the KERNEL'S OWN
    // currently-executing image mapped once this table activates —
    // computed generically from `BootInfo` (never a hardcoded per-
    // architecture constant): riscv64's image sits at ~0x8020_0000+
    // (needs 3 GiB); x86_64's tiny, low (`KERNEL_LMA_BASE = 0x0020_0000`)
    // image needs only 1. `.user_text`/`.user_stack` then land in the
    // FIRST GiB slot this leaves free (GiB `bytes_gib` itself) — each
    // architecture's own linker.ld picks its `.user_text` VMA to match
    // (0xC000_0000 = GiB 3 for riscv64, 0x4000_0000 = GiB 1 for x86_64;
    // see hal-x86_64/linker.ld's own doc comment on why x86_64 can't
    // reuse riscv64's GiB 3 — its `code-model: "kernel"` target requires
    // every symbol address to fit a sign-extended 32-bit value, true for
    // GiB 0-1 but not GiB 2-3).
    const GIB: u64 = 1024 * 1024 * 1024;
    let bytes_gib = ((boot_info.kernel_image_phys_end / GIB) + 1) as usize;
    // SAFETY: single-core boot; only read by `setup_two_process`/
    // `spawn_process`, both called later, after this write.
    unsafe {
        core::ptr::addr_of_mut!(G_BYTES_GIB).write(bytes_gib);
    }

    inkernel_demo(state, hal);

    if user.text_len == 0 {
        klog!("no user image for this architecture yet - halting after the in-kernel demo\r\n");
        park();
    }

    let root = state.root_thread;
    if let Some(tcb) = state.tcb_mut(root) {
        tcb.entry = VirtAddr::new(user.entry_vma);
        tcb.state = ThreadState::Runnable;
    }

    // Build the Root Task's address space (must run AFTER `inkernel_demo`,
    // whose context switches carry satp == 0):
    //   - kernel RAM/MMIO: the low 3 GiB, 1 GiB identity leaves, U = 0
    //     (S-mode executes the trap handler / drivers; U-mode cannot).
    //   - `.user_text`: `U=1 R+X` at its linked VMA (an otherwise-empty
    //     Sv39 GiB slot, so `map_range` needs no superpage split).
    //   - `.user_stack`: `U=1 R+W`.
    // Then activate paging and drop to U-mode WITHOUT deactivating — the
    // Root Task runs isolated.
    // 2 CONTIGUOUS pages, not 1: some architectures' `root_frame`
    // convention needs more than a single page for their page-table
    // root (x86_64: CR3 always points at a PML4, which needs a
    // companion PDPT at `root_frame + 4096`, PLUS a THIRD page at
    // `root_frame + 8192` — a dedicated PD table for the Local APIC's
    // own identity leaf, added this session alongside the preemption
    // work's timer ISR (see `hal_x86_64::cpu`'s `x86_64_paging` module
    // doc comment, `map_ram_identity`'s own, for why: every process's
    // page table needs the xAPIC MMIO region reachable, not just the
    // low `bytes_gib` range). Harmless on Sv39/AArch64, which only ever
    // use the first page — carving uniformly here keeps this crate free
    // of `#[cfg(target_arch)]`.
    let root_pt = state
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 3).ok());
    let pool = state
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * POOL_FRAMES as u64).ok());
    // (POOL_FRAMES is usize; `as u64` above for the allocator API.)

    let (root_pt, pool) = match (root_pt, pool) {
        (Some(r), Some(p)) => (r.as_usize(), p.as_usize()),
        _ => {
            klog!("could not allocate page-table frames - halting\r\n");
            park();
        }
    };
    // The Root Task's software-model address space was created back in
    // `populate_from_boot_info` from `BootInfo::initial_page_table_phys`
    // (whatever satp/CR3/TTBR held at HAL handoff — Bare mode on riscv64,
    // so `0`) — rebind it to the REAL root we just allocated, or
    // `syscall::do_map`'s hardware walk would target the wrong frame for
    // every `Map` into the Root Task's own space (see
    // `AddressSpace::set_root_phys`'s doc comment).
    if let Some(space) = state.addr_space_mut(state.root_addr_space) {
        space.set_root_phys(hal_core::PhysAddr::new(root_pt));
    }
    // A second, larger pool the runtime `Map` syscall path draws from
    // (`KernelState::install_map_pool`) — kept separate from the
    // boot-time `pool` above so a later `Map` can never trip over the
    // boot mapping's bookkeeping.
    let map_pool = state
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 8).ok());
    let map_pool = match map_pool {
        Some(p) => p.as_usize(),
        None => {
            klog!("could not allocate the runtime Map pool - halting\r\n");
            park();
        }
    };
    // SAFETY: `pool` / `map_pool` are fresh untyped RAM in the identity-
    // mapped low RAM; single-core; `map_range` requires them pre-zeroed.
    unsafe {
        core::ptr::write_bytes(pool as *mut u8, 0, 4096 * POOL_FRAMES);
        core::ptr::write_bytes(map_pool as *mut u8, 0, 4096 * 8);
    }

    let round4k = |n: usize| (n + 0xFFF) & !0xFFF;
    let user_sp = (user.stack_vma + user.stack_len) & !0xF;

    // ---- Space A (the Root Task): kernel identity U=0, user image U=1 ----
    hal.map_ram_identity(root_pt, bytes_gib, false);
    // R=1 W=2 X=4 U=8.
    let n1 = hal.map_range(
        root_pt,
        user.text_vma,
        user.text_lma,
        round4k(user.text_len),
        1 | 4 | 8,
        pool,
        POOL_FRAMES as usize,
    );
    let n2 = if n1 == u32::MAX {
        u32::MAX
    } else {
        hal.map_range(
            root_pt,
            user.stack_vma,
            user.stack_lma,
            round4k(user.stack_len),
            1 | 2 | 8,
            pool + (n1 as usize) * 4096,
            POOL_FRAMES as usize - n1 as usize,
        )
    };
    if n1 == u32::MAX || n2 == u32::MAX {
        klog!("failed to map the user image (map_range error) - halting\r\n");
        park();
    }
    let used_a = n1 + n2;

    // ---- Space B (the second process), if this architecture has one ----
    // Build a fully isolated Sv39 space with its own stack, sharing only
    // ONE physical frame with space A (mapped at a different VA in each),
    // then run BOTH via cooperative hand-off (02-Microkernel-Layer.md §8.4).
    if user.worker_entry_vma != 0
        && setup_two_process(hal, state, &user, root_pt, pool, used_a, user_sp)
    {
        hal.activate_address_space(root_pt);
        // `do_map`'s hardware walk needs this pool from here on.
        state.install_map_pool(map_pool, 8);
        // The Root Task's `Tcb::user_context` was filled by
        // `init_user_thread` in `setup_two_process` and it is the
        // scheduler's `running` thread. Resume it in U-mode.
        let ctx_a = state
            .user_context_bytes(state.root_thread)
            .expect("root TCB present");
        // SAFETY: a valid, resumable U-mode context; interrupts are
        // masked (never enabled in S-mode on this core). Never returns.
        unsafe { hal.resume_user(ctx_a) }
    }

    // ---- Single-process fallback (unchanged behaviour) ----
    hal.activate_address_space(root_pt);
    state.install_map_pool(map_pool, 8);
    klog!(
        "--- Sv39 paging active; dropping Root Task to U-mode (entry {:#x}, sp {:#x}, isolated on U=1 pages) ---\r\n",
        user.entry_vma,
        user_sp
    );
    hal.enter_user(user.entry_vma, user_sp)
}

/// Frames reserved for the boot-time `map_range` page-table pool (space A):
/// one L1 + one L0 for the user image, with headroom for the shared-frame
/// leaf and future growth.
const POOL_FRAMES: usize = 8;

/// Virtual addresses used by the two-process proof. `.user_text` is linked
/// at 0xC000_0000 and `.user_stack` just above it, so everything below
/// stays inside the same (already-a-page-table, not a superpage) Sv39 GiB
/// slot — `map_range` needs no superpage split for any of them.
const P2_STACK_B_VMA: usize = 0xC010_0000;
const P2_STACK_B_LEN: usize = 4096 * 4;
const P2_VA_A_CONST: usize = 0xC004_0000;
const P2_VA_B_CONST: usize = 0xC020_0000;

/// Builds address space B, maps the shared frame into both spaces, gives
/// the second process a real `kernel-core` TCB (its `user_context`
/// seeded, admitted to `kernel-sched`), and seeds the Root Task's TCB the
/// same way. Returns `false` (and logs) if untyped RAM, the page-table
/// pool, or a kernel table runs out — the caller then falls back to the
/// single-process path. On `true` the Root Task is the scheduler's
/// `running` thread and the caller may `resume_user` its `user_context`.
fn setup_two_process(
    hal: &HalInterface,
    state: &mut KernelState,
    user: &UserImage,
    root_pt: usize,
    pool_a: usize,
    used_a: u32,
    user_sp_a: usize,
) -> bool {
    let round4k = |n: usize| (n + 0xFFF) & !0xFFF;
    let carve = |st: &mut KernelState, bytes: u64| {
        st.untyped_mut(kernel_cap::UntypedId::new(0))
            .and_then(|u| u.alloc(4096, bytes).ok())
            .map(|p| p.as_usize())
    };

    let (shared, root_pt_b, pool_b, stack_b) = match (
        carve(state, 4096),
        // 3 pages, not 1 — see `enter`'s own `root_pt` carve for why.
        carve(state, 4096 * 3),
        carve(state, 4096 * 8),
        carve(state, P2_STACK_B_LEN as u64),
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => {
            klog!("two-process proof: out of untyped RAM - single-process path\r\n");
            return false;
        }
    };

    // SAFETY: all four regions are fresh untyped RAM, identity-addressable
    // (paging not yet active on space B); single-core. `map_range` needs
    // the pool pre-zeroed; the shared frame starts clean too.
    unsafe {
        core::ptr::write_bytes(pool_b as *mut u8, 0, 4096 * 8);
        core::ptr::write_bytes(shared as *mut u8, 0, 4096);
    }

    // Shared frame into space A (uses the remaining space-A pool).
    let sa = hal.map_range(
        root_pt,
        P2_VA_A_CONST,
        shared,
        4096,
        1 | 2 | 8,
        pool_a + used_a as usize * 4096,
        POOL_FRAMES as usize - used_a as usize,
    );

    // Space B: kernel identity U=0, then user text / its own stack / the
    // shared frame, all U=1.
    // SAFETY: single-core; only written once, by `enter`, before this runs.
    let bytes_gib = unsafe { core::ptr::addr_of!(G_BYTES_GIB).read() };
    hal.map_ram_identity(root_pt_b, bytes_gib, false);
    let mut ub = 0u32;
    let step = |vaddr, paddr, len, perm, ub: &mut u32| -> bool {
        let n = hal.map_range(
            root_pt_b,
            vaddr,
            paddr,
            len,
            perm,
            pool_b + *ub as usize * 4096,
            8 - *ub as usize,
        );
        if n == u32::MAX {
            false
        } else {
            *ub += n;
            true
        }
    };
    let ok = sa != u32::MAX
        && step(user.text_vma, user.text_lma, round4k(user.text_len), 1 | 4 | 8, &mut ub)
        && step(P2_STACK_B_VMA, stack_b, P2_STACK_B_LEN, 1 | 2 | 8, &mut ub)
        && step(P2_VA_B_CONST, shared, 4096, 1 | 2 | 8, &mut ub);
    if !ok {
        klog!("two-process proof: map_range error - single-process path\r\n");
        return false;
    }

    let stack_b_top = (P2_STACK_B_VMA + P2_STACK_B_LEN) & !0xF;

    // Process A = the Root Task (already admitted at boot; `init_user_thread`
    // just seeds its `user_context` and refreshes it `Ready`). Process B =
    // a fresh TCB bound to space B.
    let root = state.root_thread;
    state.init_user_thread(root, user.entry_vma, user_sp_a, root_pt, hal);

    let worker_as = match state.alloc_addr_space(root_pt_b as u64) {
        Some(a) => a,
        None => {
            klog!("two-process proof: no address-space slot - single-process path\r\n");
            return false;
        }
    };
    let worker_tid = match state.alloc_tcb(state.root_cap_space, worker_as) {
        Some(t) => t,
        None => {
            klog!("two-process proof: no TCB slot - single-process path\r\n");
            return false;
        }
    };
    state.init_user_thread(
        worker_tid,
        user.worker_entry_vma,
        stack_b_top,
        root_pt_b,
        hal,
    );

    // Process C is deliberately NOT spawned here. `kernel-sched` admits
    // every thread at the same priority with `vruntime = 0`
    // (`init_user_thread`), and `cooperative_yield`'s `pick_next` compares
    // vruntime BEFORE `ThreadId` — so a freshly-admitted, never-run C
    // would outrank the just-ran Root Task the moment B's own `P2_YIELD`
    // looks for who to switch to, stealing the hand-off `umode_worker`
    // expects to go back to process A. Spawning C only once the
    // cooperative phase is over and `p2_preempt_start` has moved to
    // TIMER-driven switching (where fairness among Ready threads is
    // exactly the point) avoids that: see `p2_preempt_start` below.
    //
    // Same reasoning is why `p2_preempt_start` does NOT keep root's own
    // (tid 0) TCB running the counting loop either: by the time the
    // cooperative phase ends, root has accumulated real, QEMU-timing-
    // dependent `vruntime` from its own ecall sequence — sometimes far
    // more than 40 short ticks can let B/C's vruntime catch up to, which
    // starves root for the WHOLE demo (observed: 0/40 ticks in some
    // runs). `kernel-sched`'s own invariant is that vruntime only ever
    // INCREASES (no reset primitive, by design), so the fix is not to
    // reuse root's loaded TCB at all: `p2_preempt_start` spawns a FRESH
    // thread (vruntime = 0, same footing as B/C) sharing root's EXISTING
    // address space + capability space to run the loop, and root's own
    // tid 0 TCB is retired (its demo narrative is complete). Stash what
    // both spawns need (this is bootstrap glue, not a real per-process
    // image table yet).
    // SAFETY: single-core boot; written once, before any syscall.
    unsafe {
        core::ptr::addr_of_mut!(G_TEXT_VMA).write(user.text_vma);
        core::ptr::addr_of_mut!(G_TEXT_LMA).write(user.text_lma);
        core::ptr::addr_of_mut!(G_TEXT_LEN).write(user.text_len);
        core::ptr::addr_of_mut!(G_SUBSYS_ENTRY).write(user.subsystem_entry_vma);
        core::ptr::addr_of_mut!(G_A_LOOP_ENTRY).write(user.a_loop_entry_vma);
        core::ptr::addr_of_mut!(G_A_STACK_TOP).write(user_sp_a);
    }

    // Make the Root Task the scheduler's running thread, so the first
    // `preempt_tick` (or cooperative `P2_YIELD`) has it as `outgoing`.
    let _ = state.sched.dispatch(root, hal.now_ns());

    // SAFETY: single-core boot; written once, before any syscall.
    unsafe {
        core::ptr::addr_of_mut!(P2_SHARED_PHYS).write(shared);
        core::ptr::addr_of_mut!(P2_VA_A).write(P2_VA_A_CONST);
        core::ptr::addr_of_mut!(P2_VA_B).write(P2_VA_B_CONST);
    }

    klog!(
        "--- Sv39 paging active; two isolated U-mode processes (tids {} / {}); shared frame {:#x} at VA {:#x} (A) / {:#x} (B) ---\r\n",
        root.as_u32(),
        worker_tid.as_u32(),
        shared,
        P2_VA_A_CONST,
        P2_VA_B_CONST
    );
    true
}

/// Generic process spawn (03-Kernel-Subsystems-Layer.md §0's "ordinary
/// user-space process" model, in miniature): builds a FRESH, fully
/// isolated Sv39 address space and a FRESH capability space (not shared
/// with the Root Task's, unlike A/B's MVP shortcut above — a real
/// layer-3 process gets its own of both) for a new U-mode thread, admits
/// it to `kernel-core`/`kernel-sched` via `init_user_thread`, and returns
/// its `ThreadId`, `CapSpaceId`, and the physical base of the stack frame
/// it carved (so the caller can address anything it placed there through
/// the kernel's own identity map, without needing that process's `satp`
/// active).
///
/// `text_*` describe the SAME `.user_text` output section every process
/// this binary spawns links into — including a real `subsystems/*`
/// crate's own compiled code (its entry point just needs `#[link_section
/// = ".user_text"]`, e.g. `device_manager::subsystem_entry::
/// subsystem_main`), since the section is one contiguous, page-rounded
/// range regardless of which crate contributed which bytes. There is
/// still no PER-PROCESS separate ELF / loader (IMPLEMENTATION-PLAN.md's
/// "subsystems as processes" follow-up) — every spawned process's code
/// lives in this ONE shared range; only `stack_vma`/`entry_vma` need be
/// distinct per call (the root page table, its `map_range` pool, and the
/// physical stack frames are fresh untyped RAM every time regardless).
/// `pub`: called both by this crate's own demo (`p2_preempt_start`, for
/// process C) and directly by the final binary (`kernel/src/main.rs`) to
/// launch a real subsystem process under `root-task`'s own boot policy.
/// Returns `None` (and logs) on any allocation failure — untyped RAM, an
/// object-table slot, or `map_range` are all bounded resources a real
/// capability-gated `Retype`/`Map` would also have to handle this way.
#[allow(clippy::too_many_arguments)]
pub fn spawn_process(
    hal: &HalInterface,
    state: &mut KernelState,
    text_vma: usize,
    text_lma: usize,
    text_len: usize,
    stack_vma: usize,
    stack_len: usize,
    entry_vma: usize,
) -> Option<(ThreadId, kernel_cap::CapSpaceId, usize)> {
    let round4k = |n: usize| (n + 0xFFF) & !0xFFF;
    let carve = |st: &mut KernelState, bytes: u64| {
        st.untyped_mut(kernel_cap::UntypedId::new(0))
            .and_then(|u| u.alloc(4096, bytes).ok())
            .map(|p| p.as_usize())
    };

    // 3 pages, not 1 — see `enter`'s own `root_pt` carve for why.
    let root_pt = carve(state, 4096 * 3)?;
    let pool = carve(state, 4096 * 8)?;
    let stack_phys = carve(state, round4k(stack_len) as u64)?;
    // SAFETY: fresh untyped RAM, identity-addressable (paging is not yet
    // active on this new space); single-core. `map_range` needs the pool
    // pre-zeroed.
    unsafe { core::ptr::write_bytes(pool as *mut u8, 0, 4096 * 8) };

    // SAFETY: single-core; only written once, by `enter`, before any
    // process (including this generic-spawn path) can run.
    let bytes_gib = unsafe { core::ptr::addr_of!(G_BYTES_GIB).read() };
    hal.map_ram_identity(root_pt, bytes_gib, false);
    let mut used = 0u32;
    let mut step = |vaddr: usize, paddr: usize, len: usize, perm: usize| -> bool {
        let n = hal.map_range(
            root_pt,
            vaddr,
            paddr,
            len,
            perm,
            pool + used as usize * 4096,
            8 - used as usize,
        );
        if n == u32::MAX {
            false
        } else {
            used += n;
            true
        }
    };
    if !step(text_vma, text_lma, round4k(text_len), 1 | 4 | 8) // R+X+U
        || !step(stack_vma, stack_phys, round4k(stack_len), 1 | 2 | 8) // R+W+U
    {
        klog!("spawn_process: map_range error\r\n");
        return None;
    }

    let addr_space = state.alloc_addr_space(root_pt as u64)?;
    let cap_space = state.alloc_cap_space()?;
    let tid = state.alloc_tcb(cap_space, addr_space)?;
    let stack_top = (stack_vma + stack_len) & !0xF;
    state.init_user_thread(tid, entry_vma, stack_top, root_pt, hal);
    Some((tid, cap_space, stack_phys))
}

/// The "subsystems as processes" packaging follow-up (IMPLEMENTATION-
/// PLAN.md — 03-Kernel-Subsystems-Layer.md's folder structure implies a
/// genuinely separate program per subsystem, not a function pointer
/// into the kernel's own image). `spawn_process` above loads a process
/// whose code is ALREADY part of this binary's own linked `.user_text`
/// (`entry_vma`/`text_lma` name addresses inside the CALLING kernel
/// image itself); this function instead takes a whole separately-built,
/// `include_bytes!`-embedded ELF (see `device-manager-bin`'s own doc
/// comment for how one gets built) and loads its `PT_LOAD` segments
/// into FRESH untyped memory, each with its own permissions taken from
/// the ELF's own `p_flags` (unlike `spawn_process`'s one blanket R+X+U
/// for the whole shared `.user_text` range).
///
/// `elf_bytes` is trusted, kernel-embedded input (built by this same
/// workspace, not adversarial), but every offset/size from it is still
/// bounds-checked before use — the same defensive posture as every
/// other place in this kernel that walks caller-provided-shaped data
/// (`kernel-core::fuzz`'s own adversarial-syscall harness set that
/// precedent).
///
/// Returns `None` (and logs) on a malformed ELF or any allocation
/// failure, exactly like `spawn_process`.
pub fn spawn_process_from_elf(
    hal: &HalInterface,
    state: &mut KernelState,
    elf_bytes: &[u8],
    expected_machine: u16,
    stack_vma: usize,
    stack_len: usize,
) -> Option<(ThreadId, kernel_cap::CapSpaceId, usize)> {
    let round4k = |n: usize| (n + 0xFFF) & !0xFFF;
    let carve = |st: &mut KernelState, bytes: u64| {
        st.untyped_mut(kernel_cap::UntypedId::new(0))
            .and_then(|u| u.alloc(4096, bytes).ok())
            .map(|p| p.as_usize())
    };

    let (entry, segments) =
        match elf_loader::parse_and_collect_load_segments(elf_bytes, expected_machine) {
            Ok(v) => v,
            Err(_) => {
                klog!("spawn_process_from_elf: malformed ELF\r\n");
                return None;
            }
        };

    // 3 pages, not 1 — see `enter`'s own `root_pt` carve for why.
    let root_pt = carve(state, 4096 * 3)?;
    let pool = carve(state, 4096 * 8)?;
    let stack_phys = carve(state, round4k(stack_len) as u64)?;
    // SAFETY: fresh untyped RAM, identity-addressable (paging is not yet
    // active on this new space); single-core. `map_range` needs the pool
    // pre-zeroed.
    unsafe { core::ptr::write_bytes(pool as *mut u8, 0, 4096 * 8) };

    // SAFETY: single-core; only written once, by `enter`, before any
    // process (including this generic-spawn path) can run.
    let bytes_gib = unsafe { core::ptr::addr_of!(G_BYTES_GIB).read() };
    hal.map_ram_identity(root_pt, bytes_gib, false);
    let mut used = 0u32;
    let mut step = |vaddr: usize, paddr: usize, len: usize, perm: usize| -> bool {
        let n = hal.map_range(
            root_pt,
            vaddr,
            paddr,
            len,
            perm,
            pool + used as usize * 4096,
            8 - used as usize,
        );
        if n == u32::MAX {
            false
        } else {
            used += n;
            true
        }
    };

    for seg in segments {
        let mem_size4k = round4k(seg.mem_size as usize);
        if mem_size4k == 0 {
            continue;
        }
        // Bounds-check the file-data range this segment claims BEFORE
        // any pointer arithmetic touches it (see this function's own
        // doc comment on why: `elf_bytes` is trusted-but-still-checked).
        let file_offset = seg.file_offset as usize;
        let file_size = seg.file_size as usize;
        let Some(file_end) = file_offset.checked_add(file_size) else {
            klog!("spawn_process_from_elf: segment file range overflows\r\n");
            return None;
        };
        if file_size > seg.mem_size as usize || file_end > elf_bytes.len() {
            klog!("spawn_process_from_elf: segment file range out of bounds\r\n");
            return None;
        }

        let seg_phys = carve(state, mem_size4k as u64)?;
        // SAFETY: `seg_phys` is fresh untyped RAM, identity-addressable,
        // `mem_size4k` bytes long. `elf_bytes[file_offset..file_end]` was
        // just bounds-checked above. Zeroing first then copying only
        // `file_size` bytes reproduces the ELF spec's standard
        // ".bss inside PT_LOAD" convention (mem_size > file_size is
        // zero-filled) — the same handling `elf-loader`'s own doc
        // comment describes for `uefi-bootloader`'s use of this shape.
        unsafe {
            core::ptr::write_bytes(seg_phys as *mut u8, 0, mem_size4k);
            core::ptr::copy_nonoverlapping(
                elf_bytes.as_ptr().add(file_offset),
                seg_phys as *mut u8,
                file_size,
            );
        }

        // Per-segment permissions from the ELF's own p_flags, translated
        // to this workspace's R(1)/W(2)/X(4)/U(8) `map_range` bit
        // encoding — tighter than `spawn_process`'s one blanket R+X+U
        // for the whole shared `.user_text` range (e.g. this process's
        // .rodata segment lands R-only, no X or W).
        let mut perm = 8usize; // U — every segment of a U-mode process image is user-accessible
        if seg.flags & elf_loader::PF_R != 0 {
            perm |= 1;
        }
        if seg.flags & elf_loader::PF_W != 0 {
            perm |= 2;
        }
        if seg.flags & elf_loader::PF_X != 0 {
            perm |= 4;
        }

        if !step(seg.vaddr as usize, seg_phys, mem_size4k, perm) {
            klog!("spawn_process_from_elf: map_range error (PT_LOAD segment)\r\n");
            return None;
        }
    }

    if !step(stack_vma, stack_phys, round4k(stack_len), 1 | 2 | 8) {
        // R+W+U
        klog!("spawn_process_from_elf: map_range error (stack)\r\n");
        return None;
    }

    let addr_space = state.alloc_addr_space(root_pt as u64)?;
    let cap_space = state.alloc_cap_space()?;
    let tid = state.alloc_tcb(cap_space, addr_space)?;
    let stack_top = (stack_vma + stack_len) & !0xF;
    state.init_user_thread(tid, entry as usize, stack_top, root_pt, hal);
    Some((tid, cap_space, stack_phys))
}

/// Called by the riscv64 syscall handler when a process makes a
/// `P2_YIELD` `ecall` (the cooperative §8.4 phase, before the timer is
/// armed). A voluntary yield is just a scheduler tick with no timer
/// involved: `KernelState::preempt_tick` charges the caller and picks the
/// other runnable thread. Returns `Some((save, into))` for
/// `TrapOutcome::SwitchTo`, or `None` (→ `Resume`) if there is no other
/// thread to run.
pub fn p2_yield() -> Option<(*mut u8, *const u8)> {
    // SAFETY: single-core; `G_HAL` set by `enter` before any syscall.
    let hal = unsafe { &*core::ptr::addr_of!(G_HAL).read() };
    let k = kstate();
    match k.cooperative_yield(hal.now_ns()) {
        PreemptStep::Switch { outgoing, incoming } => k.user_ctx_switch_ptrs(outgoing, incoming),
        PreemptStep::Continue | PreemptStep::Idle => None,
    }
}

/// `P2_REPORT` from process B: it read `value` through its own mapping of
/// the shared frame (which A wrote before the first hand-off).
pub fn p2_report_b(value: usize) {
    // SAFETY: single-core; `P2_*` set once by `setup_two_process`.
    let (phys, va_b) = unsafe {
        (
            core::ptr::addr_of!(P2_SHARED_PHYS).read(),
            core::ptr::addr_of!(P2_VA_B).read(),
        )
    };
    // SAFETY: `phys` is identity-mapped U=0 in the live space; single-core.
    let kernel_view = unsafe { core::ptr::read_volatile(phys as *const u32) as usize };
    // SAFETY: single-core; only written here, read by `p2_report_a`.
    unsafe { core::ptr::addr_of_mut!(P2_B_SAW).write(value) };
    klog!(
        "process B (space B, VA {:#x}): read {:#x} from the shared frame; kernel sees {:#x} at PA {:#x} ({})\r\n",
        va_b,
        value,
        kernel_view,
        phys,
        if value == P2_A_SENTINEL && kernel_view == P2_A_SENTINEL {
            "A's write crossed the isolation boundary"
        } else {
            "MISMATCH"
        }
    );
}

/// `P2_REPORT` from process A after B ran: it re-read `value` through its
/// own mapping and should now see B's write. Logs the final verdict.
pub fn p2_report_a(value: usize) {
    // SAFETY: single-core; `P2_*` set once by `setup_two_process`.
    let (phys, va_a, b_saw) = unsafe {
        (
            core::ptr::addr_of!(P2_SHARED_PHYS).read(),
            core::ptr::addr_of!(P2_VA_A).read(),
            core::ptr::addr_of!(P2_B_SAW).read(),
        )
    };
    // SAFETY: `phys` is identity-mapped U=0 in the live space; single-core.
    let kernel_view = unsafe { core::ptr::read_volatile(phys as *const u32) as usize };
    let pass = b_saw == P2_A_SENTINEL && value == P2_B_SENTINEL && kernel_view == P2_B_SENTINEL;
    klog!(
        "process A (space A, VA {:#x}): re-read {:#x}; kernel sees {:#x} at PA {:#x} -> {}\r\n",
        va_a,
        value,
        kernel_view,
        phys,
        if pass {
            "TWO-PROCESS ZERO-COPY: A->B->A round-trip through one shared frame, no copy, MMU-isolated spaces (02 8.4)"
        } else {
            "MISMATCH"
        }
    );
}

/// `P2_PREEMPT_START` from process A: the cooperative §8.4 round-trip is
/// done; arm the supervisor timer so from here the two processes are
/// switched by PREEMPTION (02-Microkernel-Layer.md §4), not an explicit
/// `P2_YIELD`. The worker's `Tcb::user_context` already holds it
/// suspended just after its own `P2_YIELD` (the head of its counting
/// loop) and it is `Ready` in `kernel-sched`, so the first tick's
/// `preempt_tick` switches straight into it.
/// Ends the cooperative phase and arms the preemptive scheduler. Returns
/// `Some((save, into))` for `TrapOutcome::SwitchTo` if a fresh thread took
/// over process A's counting loop (see the doc comment inline below for
/// why root's own TCB is retired rather than reused), or `None` (→
/// `Resume`, root's own context just continues) if that spawn failed —
/// the demo then falls back to whatever fairness root's pre-existing
/// vruntime gets it, unaffected otherwise.
pub fn p2_preempt_start() -> Option<(*mut u8, *const u8)> {
    // SAFETY: single-core; `G_HAL`/`G_STATE` were set by `enter` before any
    // syscall.
    let hal = unsafe { &*core::ptr::addr_of!(G_HAL).read() };
    let state = kstate();

    // Spawn process C NOW, not during the cooperative A<->B round-trip —
    // see `setup_two_process`'s doc comment on why an earlier spawn would
    // have hijacked B's `P2_YIELD` hand-off back to A (a fresh,
    // never-run thread's `vruntime = 0` outranks A's own nonzero vruntime
    // in `cooperative_yield`'s fairness comparison). Once we are about to
    // switch to TIMER-driven `preempt_tick`, that fairness is exactly the
    // point, so this is the right moment for C to join.
    // SAFETY: these were written once by `setup_two_process` before any
    // syscall could run.
    let (text_vma, text_lma, text_len, subsys_entry, a_loop_entry, a_stack_top) = unsafe {
        (
            core::ptr::addr_of!(G_TEXT_VMA).read(),
            core::ptr::addr_of!(G_TEXT_LMA).read(),
            core::ptr::addr_of!(G_TEXT_LEN).read(),
            core::ptr::addr_of!(G_SUBSYS_ENTRY).read(),
            core::ptr::addr_of!(G_A_LOOP_ENTRY).read(),
            core::ptr::addr_of!(G_A_STACK_TOP).read(),
        )
    };
    if subsys_entry != 0 {
        const PROC_C_STACK_VMA: usize = 0xC030_0000;
        const PROC_C_STACK_LEN: usize = 4096 * 4;
        match spawn_process(
            hal,
            state,
            text_vma,
            text_lma,
            text_len,
            PROC_C_STACK_VMA,
            PROC_C_STACK_LEN,
            subsys_entry,
        ) {
            Some((tid, _cap_space, stack_phys)) => {
                // SAFETY: single-core; only written here, read by `p2_tick`.
                unsafe { core::ptr::addr_of_mut!(P3_COUNTER_PHYS).write(stack_phys) };
                klog!(
                    "process A: process C spawned (tid {}) via the generic path, joining the preemption loop\r\n",
                    tid.as_u32()
                );
            }
            None => klog!("process A: process C spawn skipped (out of resources) - A/B unaffected\r\n"),
        }
    }

    // Retire root's own tid-0 TCB from the counting-loop role. It has
    // accumulated real, QEMU-timing-dependent `vruntime` from its own
    // ecall sequence during the cooperative phase — sometimes far more
    // than `P2_TICK_BUDGET` short ticks can let B/C's vruntime catch up
    // to, starving it for the WHOLE demo (`kernel-sched`'s own invariant
    // is that vruntime only ever increases — no reset primitive, by
    // design, so "give root a fresh start" has to mean a literally fresh
    // THREAD). A brand-new TCB sharing root's EXISTING address space and
    // capability space (multiple threads, one process — same model a
    // real OS uses) starts at `vruntime = 0`, the same footing as B/C,
    // and takes over the loop. Root's own TCB is marked `Exited` +
    // removed from the scheduler BEFORE this switch — same discipline as
    // `thread2_main`'s tail, and for the same reason: nothing ever
    // dispatches it again, so leaving it `Ready` would be a phantom
    // scheduler entity `pick_next` could later select into a thread that
    // can never make progress.
    if a_loop_entry == 0 {
        return None;
    }
    let root = state.root_thread;
    let fresh_tid = match state.alloc_tcb(state.root_cap_space, state.root_addr_space) {
        Some(t) => t,
        None => {
            klog!("process A: no TCB slot for the fresh loop thread - root's own TCB keeps running\r\n");
            return None;
        }
    };
    // `root_frame = 0`: keep whatever address space is already active
    // (root's own space A, unchanged — this fresh TCB shares it).
    state.init_user_thread(fresh_tid, a_loop_entry, a_stack_top, 0, hal);
    if let Some(t) = state.tcb_mut(root) {
        t.state = ThreadState::Exited;
    }
    state.sched.remove(root);
    // `state.sched.remove(root)` clears `running` (root was it), and this
    // switch to `fresh_tid` happens directly via `user_ctx_switch_ptrs`,
    // bypassing `preempt_tick`/`cooperative_yield` (whose own `Switch`
    // branches always call `dispatch` before returning). Without this,
    // the scheduler's bookkeeping would say NOBODY is running while
    // `fresh_tid` is physically executing — so the NEXT tick's
    // `account()` would charge whatever `pick_next` picks (having found
    // `running == None`) instead of `fresh_tid`, silently misattributing
    // real CPU time to a thread that never actually ran.
    let _ = state.sched.dispatch(fresh_tid, hal.now_ns());
    klog!(
        "process A: retiring tid {} (its own vruntime is too QEMU-timing-dependent to fairly compete for {} short ticks) - spawned fresh tid {} (vruntime 0) to run the counting loop\r\n",
        root.as_u32(),
        P2_TICK_BUDGET,
        fresh_tid.as_u32()
    );

    // SAFETY: single-core; only reset here, before the first tick.
    unsafe { core::ptr::addr_of_mut!(P2_TICKS).write(0) };
    let armed = hal.arm_timer(hal.now_ns() + P2_QUANTUM_NS);
    klog!(
        "process A: cooperative round-trip done - arming preemptive timer (quantum {} ns, armed: {}); NO more P2_YIELD from here\r\n",
        P2_QUANTUM_NS,
        armed
    );

    state.user_ctx_switch_ptrs(root, fresh_tid)
}

/// Preemptive-scheduler tick (registered as the arch `TickHandler`).
/// Round-robins between the two U-mode processes on every supervisor
/// timer interrupt, re-arming the next deadline. After `P2_TICK_BUDGET`
/// ticks it reads both processes' private counters out of the shared
/// frame, logs the verdict, disarms the timer and stops preempting
/// (`None`) — the running process then keeps its loop and QEMU stays up
/// for the smoke grep.
///
/// Returns `Some((save, into))` to switch (the trap vector snapshots the
/// preempted thread into `save` and resumes `into`), or `None` to let it
/// keep running.
pub fn p2_tick() -> Option<(*mut u8, *const u8)> {
    // SAFETY: single-core; `G_HAL` set by `enter`; `P2_TICKS` / `P2_*`
    // touched only from this path and the one-time setup.
    let hal = unsafe { &*core::ptr::addr_of!(G_HAL).read() };

    // Device-manager's own scheduling is governed ENTIRELY by the
    // deterministic crash/respawn hand-off (`p2_fault`'s hand-off to
    // `DM_TID` / `p2_dm_handoff_to_driver`), not this ordinary
    // round-robin timer — it is not a participant in the A/B/C fairness
    // demo this tick counts toward. Letting an ordinary tick preempt it
    // here would race with that protocol: if device-manager loses the
    // ordinary scheduler's fairness comparison at the WRONG moment
    // (between finishing a crash-notify resume and making its own next
    // respawn call), NOTHING would ever give it the CPU back — the
    // driver it would respawn is not even running yet to crash and
    // trigger the OTHER hand-off. A real bug hit via QEMU: the
    // crash/restart cycle would silently stop one step short of ever
    // reporting `Failed`, despite every crash having genuinely happened.
    // Simply never counting this tick, or switching away, while
    // device-manager holds the CPU closes it.
    // SAFETY: single-core.
    let dm_tid = unsafe { core::ptr::addr_of!(DM_TID).read() };
    if dm_tid.is_some() && dm_tid == kstate().sched.running() {
        hal.arm_timer(hal.now_ns() + P2_QUANTUM_NS);
        return None;
    }

    let ticks = unsafe { core::ptr::addr_of!(P2_TICKS).read() } + 1;
    unsafe { core::ptr::addr_of_mut!(P2_TICKS).write(ticks) };

    if ticks >= P2_TICK_BUDGET {
        hal.cancel_timer();
        let phys = unsafe { core::ptr::addr_of!(P2_SHARED_PHYS).read() };
        let c_phys = unsafe { core::ptr::addr_of!(P3_COUNTER_PHYS).read() };
        // SAFETY: both are identity-mapped U=0 in the live space (`phys`
        // from the §8.4 shared frame; `c_phys` from `spawn_process`'s
        // stack carve — `0` if process C was never spawned, in which case
        // this read is skipped below).
        let (a, b) = unsafe {
            (
                core::ptr::read_volatile((phys + P2_COUNTER_A_OFF) as *const u32),
                core::ptr::read_volatile((phys + P2_COUNTER_B_OFF) as *const u32),
            )
        };
        let c = if c_phys != 0 {
            // SAFETY: as above.
            Some(unsafe { core::ptr::read_volatile(c_phys as *const u32) })
        } else {
            None
        };
        let all_ran = a > 0 && b > 0 && c.unwrap_or(1) > 0;
        klog!(
            "preemption: {} timer ticks, NO P2_YIELD - process A's counter = {}, process B's counter = {}, process C's counter = {:?} -> {}\r\n",
            ticks,
            a,
            b,
            c,
            if all_ran {
                if c.is_some() {
                    "PREEMPTIVE THREE-PROCESS SCHEDULING (02 4): all three ran, timer-driven, C spawned via the generic path"
                } else {
                    "PREEMPTIVE TWO-PROCESS SCHEDULING (02 4): both ran, timer-driven"
                }
            } else {
                "MISMATCH"
            }
        );
        return None;
    }

    hal.arm_timer(hal.now_ns() + P2_QUANTUM_NS);
    let k = kstate();
    match k.preempt_tick(hal.now_ns()) {
        PreemptStep::Switch { outgoing, incoming } => k.user_ctx_switch_ptrs(outgoing, incoming),
        PreemptStep::Continue | PreemptStep::Idle => None,
    }
}

/// Per-process fault isolation (03-Kernel-Subsystems-Layer.md §2.1/§5.2):
/// registered as the arch `FaultHandler` for a synchronous exception
/// taken from U-mode that is not an `ecall`. `cause_code`/`sepc`/`stval`
/// are the raw architecture trap values, logged for diagnosis; WHICH
/// thread faulted is `kernel-sched`'s own `running()` bookkeeping — the
/// arch trap vector has no other way to know, since the exception could
/// be anything (illegal instruction, page fault, ...), not a syscall
/// naming its own caller.
///
/// Terminates that thread (`KernelState::terminate_thread`) and returns
/// the next runnable thread's context to resume, or `None` if nothing
/// else is runnable (the caller then has no thread left to `sret` into
/// — a real kernel would idle; logged as fatal here since every demo
/// process in this MVP either counts forever or has already finished).
pub fn p2_fault(cause_code: usize, sepc: usize, stval: usize) -> Option<*const u8> {
    // SAFETY: single-core; `G_HAL` set by `enter` before any syscall.
    let hal = unsafe { &*core::ptr::addr_of!(G_HAL).read() };
    let k = kstate();
    let Some(tid) = k.sched.running() else {
        klog!(
            "FAULT: no thread was running when exception (cause={:#x} sepc={:#x} stval={:#x}) landed - halting\r\n",
            cause_code, sepc, stval
        );
        return None;
    };
    klog!(
        "FAULT: thread {} took a fatal U-mode exception (cause={:#x} sepc={:#x} stval={:#x}) - terminating IT, rest of the system continues (03 5.2)\r\n",
        tid.as_u32(), cause_code, sepc, stval
    );

    // If the thread that just died is the one device-manager actually
    // supervises, hand off DIRECTLY to device-manager's own PERMANENT tid
    // (`KernelState::terminate_thread_and_handoff`) instead of the
    // generic `terminate_thread`/`pick_next` fairness path below — see
    // this module's own "Real IPC-driven driver supervision demo" doc
    // comment (above `WATCHED_DRIVER_TID`) for the two QEMU-found races
    // this unconditional hand-off exists to close. Fault isolation itself
    // (below, the non-watched-driver case) stays fully general — this
    // hand-off is an additional, demo-specific policy layered on top for
    // this ONE well-defined case (device-manager is DEFINITELY who
    // should run next).
    // SAFETY: single-core.
    if unsafe { core::ptr::addr_of!(WATCHED_DRIVER_TID).read() } == Some(tid) {
        // SAFETY: single-core; only written here, read by `p2_poll_crash`.
        unsafe { core::ptr::addr_of_mut!(PENDING_CRASH).write(Some((cause_code, sepc, stval))) };
        // SAFETY: single-core; only written once, by `p2_register_device_manager`.
        if let Some(dm_tid) = unsafe { core::ptr::addr_of!(DM_TID).read() } {
            klog!(
                "FAULT: hand-off to device-manager (tid {}) - direct, not generic fairness (03 5.2)\r\n",
                dm_tid.as_u32()
            );
            let now = hal.now_ns();
            k.wake_blocked(dm_tid, now);
            k.terminate_thread_and_handoff(tid, dm_tid, now);
            return k.user_context_bytes(dm_tid).map(|c| c.as_ptr());
        }
    }

    match k.terminate_thread(tid, hal.now_ns()) {
        kernel_core::TerminationOutcome::Switched { incoming } => {
            k.user_context_bytes(incoming).map(|c| c.as_ptr())
        }
        kernel_core::TerminationOutcome::Idle => {
            klog!(
                "FAULT: nothing else runnable after terminating thread {} - halting\r\n",
                tid.as_u32()
            );
            None
        }
    }
}

/// Records `tid` as the "faulty driver" instance `p2_fault` should treat
/// specially. Called once by `kernel/src/main.rs`'s `spawn_faulty_driver`
/// right after EVERY (re)spawn — a respawned driver gets a brand-new
/// `ThreadId`, so this must be re-armed each time, not just at boot.
pub fn p2_watch_driver(tid: ThreadId) {
    // SAFETY: single-core; only written here, read by `p2_fault`.
    unsafe { core::ptr::addr_of_mut!(WATCHED_DRIVER_TID).write(Some(tid)) };
}

/// Records `tid` as device-manager's own, PERMANENT `ThreadId` — called
/// once by `kernel/src/main.rs`'s `spawn_device_manager` right after it
/// succeeds. `p2_fault` targets this directly on a watched-driver crash
/// (see `DM_TID`'s own doc comment for why unconditionally, not via a
/// "currently blocked" registration).
pub fn p2_register_device_manager(tid: ThreadId) {
    // SAFETY: single-core; only written here, read by `p2_fault`.
    unsafe { core::ptr::addr_of_mut!(DM_TID).write(Some(tid)) };
}

/// Called once device-manager reports `Failed` (`sys::DM_REPORT` with
/// `a0 == 3`): it has given up and drops into its own "spin forever"
/// idle, so it must stop being exempt from ordinary preemption
/// (`p2_tick`'s `DM_TID` check) — it will never again call
/// `DM_WAIT_CRASH`/`DM_RESPAWN_DRIVER`, and staying exempt would let it
/// monopolize the CPU forever, starving A/B/C's own fairness demo. See
/// `p2_tick`'s doc comment for the exemption this undoes.
pub fn p2_dm_supervision_done() {
    // SAFETY: single-core; only written here and by `p2_register_device_manager`.
    unsafe { core::ptr::addr_of_mut!(DM_TID).write(None) };
}

/// `DM_WAIT_CRASH` from device-manager: block until the watched driver
/// process dies (real IPC-driven supervision — 03-Kernel-Subsystems-
/// Layer.md §5.2). If a crash is already pending — it happened before
/// device-manager got around to waiting, always possible since spawning
/// and scheduling order are not synchronized — returns `None` (→
/// `TrapOutcome::Resume`) immediately so device-manager can go straight to
/// `p2_poll_crash`; otherwise genuinely blocks (`KernelState::
/// block_thread`) and returns `Some((save, into))` for `TrapOutcome::
/// SwitchTo`. Blocking here is purely for `kernel-sched`'s own bookkeeping
/// (so device-manager does not appear to still be `Running` while it
/// waits) — `p2_fault` does not depend on this call having happened; it
/// always targets `DM_TID` directly regardless of device-manager's exact
/// state when the driver dies.
pub fn p2_dm_wait_crash() -> Option<(*mut u8, *const u8)> {
    // SAFETY: single-core; `G_HAL` set by `enter` before any syscall.
    let hal = unsafe { &*core::ptr::addr_of!(G_HAL).read() };
    let k = kstate();
    // SAFETY: single-core; only `p2_fault`/`p2_poll_crash` touch this too.
    if unsafe { core::ptr::addr_of!(PENDING_CRASH).read() }.is_some() {
        return None;
    }
    let Some(tid) = k.sched.running() else {
        return None;
    };
    match k.block_thread(tid, hal.now_ns()) {
        PreemptStep::Switch { outgoing, incoming } => k.user_ctx_switch_ptrs(outgoing, incoming),
        PreemptStep::Continue | PreemptStep::Idle => None,
    }
}

/// `DM_RESPAWN_DRIVER` from device-manager, called right after
/// `kernel/src/main.rs`'s `spawn_faulty_driver` succeeds: hands the CPU
/// DIRECTLY to the fresh driver thread (`KernelState::yield_to_thread`)
/// instead of just returning and trusting the ordinary fairness scheduler
/// (or an already-cancelled preemption timer) to ever pick it up — the
/// respawn-direction counterpart of the crash-notify hand-off above (see
/// `WATCHED_DRIVER_TID`'s doc comment for the starvation this whole
/// pattern exists to close). The fresh driver's only instruction faults
/// immediately, so control comes straight back via `p2_fault`'s own
/// hand-off to `DM_TID` — this call never really "returns" in the normal
/// sense, it just describes device-manager's OWN snapshot point.
pub fn p2_dm_handoff_to_driver(new_driver_tid: ThreadId) -> Option<(*mut u8, *const u8)> {
    // SAFETY: single-core; `G_HAL` set by `enter` before any syscall.
    let hal = unsafe { &*core::ptr::addr_of!(G_HAL).read() };
    let k = kstate();
    let caller = k.sched.running()?;
    match k.yield_to_thread(caller, new_driver_tid, hal.now_ns()) {
        PreemptStep::Switch { outgoing, incoming } => k.user_ctx_switch_ptrs(outgoing, incoming),
        PreemptStep::Continue | PreemptStep::Idle => None,
    }
}

/// `DM_POLL_CRASH` from device-manager, called right after waking from
/// `p2_dm_wait_crash` (or finding a crash already pending): consumes and
/// returns the pending crash's `cause_code` raw trap value, or `0` if
/// somehow nothing is pending (should not happen given `p2_dm_wait_crash`'s
/// contract, but this stays total rather than panicking).
pub fn p2_poll_crash() -> usize {
    // SAFETY: single-core; only this function clears `PENDING_CRASH`.
    let pending = unsafe { core::ptr::replace(core::ptr::addr_of_mut!(PENDING_CRASH), None) };
    pending.map(|(cause, _, _)| cause).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Real U-mode Call/Recv/Reply demo (02-Microkernel-Layer.md §5.1/§8.2 —
// IMPLEMENTATION-PLAN.md's own follow-up: everything ELSE in this file's
// U-mode demo machinery uses ad-hoc raw opcodes over `ecall`
// [`P2_YIELD`, `ALIVE`, `DM_REPORT`, ...], never `kernel_core::SyscallOp`'s
// REAL `Call`/`Recv`/`Reply` IPC surface through a genuine trap. This is
// the first — and, deliberately, only — demo to actually exercise that
// surface end to end, as the concrete thing the register-only IPC fast
// path (still pending — see `kernel_ipc::fastpath`'s own doc comment)
// needs to attach to and be verified against.
//
// `p2_ipc_call`/`p2_ipc_recv`/`p2_ipc_reply` stay entirely architecture-
// erased (no `cfg(target_arch)`, same as everything else in this crate):
// each returns a plain `IpcSwitch`/`Option<...>` describing what the
// ARCHITECTURE-SPECIFIC caller (`kernel/src/main.rs`'s `simurgh_syscall`)
// must do — including, when `poke` is `Some`, an (a0, a1) pair the
// caller must write into the target's SAVED context via its own
// `hal_<arch>::cpu::poke_saved_a0_a1`-style primitive BEFORE performing
// the actual switch. This function cannot do that poke itself: it would
// need to know the concrete `UserContext` layout, which is exactly the
// architecture knowledge this crate must not have.
// ---------------------------------------------------------------------------

/// What the architecture-specific caller must do to complete an
/// `IpcCall`/`IpcRecv`/`IpcReply` demo opcode that needs a real switch.
pub struct IpcSwitch {
    /// Where to write the outgoing (calling) thread's snapshot.
    pub save: *mut u8,
    /// The incoming thread's context to resume.
    pub into: *const u8,
    /// If `Some((a0, a1))`, the caller must poke `into`'s SAVED a0/a1
    /// registers with these values BEFORE performing the switch — `into`
    /// is being woken via a direct kernel-core delivery (`do_send`'s
    /// `Call` fast path, or `do_reply`), not resuming its own trap, so
    /// its saved context still holds whatever it originally trapped in
    /// WITH and needs the delivery's actual result written in instead.
    pub poke: Option<(usize, usize)>,
}

/// `IPC_CALL` demo opcode: `SyscallOp::Call` with a label-only
/// `SmallMessage` (no data words — this demo only needs to prove the
/// mechanism, not carry a real payload). Always either switches away
/// (a `Call` always blocks its caller pending the reply — see `do_send`'s
/// own doc comment) or fails outright; there is no "resume immediately"
/// case for `Call` the way there is for `Recv`.
pub fn p2_ipc_call(hal: &HalInterface, caller: ThreadId, endpoint_raw: u32, label: u64) -> Option<IpcSwitch> {
    let k = kstate();
    let msg = SmallMessage::new(label);
    match k.dispatch(caller, hal.now_ns(), SyscallOp::Call { endpoint: kernel_cap::CapId::new(endpoint_raw), msg }, hal) {
        Ok(SyscallReturn::Reschedule { next: Some(n) }) => {
            // `do_send`/`do_recv`/`do_reply` only ever call `note_ready`/
            // `note_blocked` on the entities they touch, never `dispatch`
            // — `Scheduler::dispatch` is the ONE call that both marks an
            // entity `Running` AND updates `self.running`, and skipping
            // it here would leave kernel-sched's own bookkeeping
            // pointing at `caller` even after the switch below actually
            // moves execution to `n` — corrupting a LATER `account()`/
            // `pick_next()`'s idea of who is really running. Matches
            // `p2_ipc_demo_start`'s own explicit `dispatch` call (itself
            // modeled on `p2_preempt_start`'s precedent) for the exact
            // same reason.
            let _ = k.sched.dispatch(n, hal.now_ns());
            let (save, into) = k.user_ctx_switch_ptrs(caller, n)?;
            // `n` is the receiver `do_send`'s fast path just delivered
            // to directly (see that function's own doc comment) exactly
            // when both fields below are present — the general
            // (non-fast-path) case picks some other, unrelated `Ready`
            // thread via `pick_next`, which never had these set, so
            // `poke` correctly comes back `None` for it.
            let poke = k
                .tcb_mut(n)
                .and_then(|t| Some((t.pending_from.take()?, t.pending_msg.take()?)))
                .map(|(from, m)| (from.as_u32() as usize, m.label as usize));
            Some(IpcSwitch { save, into, poke })
        }
        _ => None,
    }
}

/// `IPC_RECV` demo opcode: `SyscallOp::Recv`. Unlike `Call`, this CAN
/// resume immediately (a sender was already queued) — the caller must
/// then place `(from, label)` in its OWN `a0`/`a1` (`TrapOutcome::
/// Resume2`), not perform any switch at all.
pub enum IpcRecvOutcome {
    /// Resume the calling thread's own trap with `(from, label)`.
    Immediate { from: usize, label: usize },
    /// Block — perform this switch.
    Switch(IpcSwitch),
}

pub fn p2_ipc_recv(hal: &HalInterface, caller: ThreadId, endpoint_raw: u32) -> Option<IpcRecvOutcome> {
    let k = kstate();
    match k.dispatch(caller, hal.now_ns(), SyscallOp::Recv { endpoint: kernel_cap::CapId::new(endpoint_raw) }, hal) {
        Ok(SyscallReturn::Message { from, msg }) => {
            Some(IpcRecvOutcome::Immediate { from: from.as_u32() as usize, label: msg.label as usize })
        }
        Ok(SyscallReturn::Reschedule { next: Some(_) }) => {
            // **Real bug found via QEMU**: `do_recv`'s own `next` here
            // is `pick_next`'s GENERAL fairness answer — correct for
            // the general syscall surface, but wrong for THIS demo's
            // one-shot RPC shape, which for the whole rest of the boot
            // sequence up to this point had never once actually
            // consulted `pick_next` while process B (tid 3, `§8.4`'s own
            // worker) sat `Ready`-but-idle (finished its own role,
            // genuinely eligible, LOWER vruntime than root's — root has
            // been doing real ecall work this entire demo). The first
            // time anything DOES call `pick_next` here, it correctly-
            // by-its-own-rules preferred process B over `root` — NOT a
            // scheduler bug, but wrong for a deterministic 2-party
            // RPC's assumption "whoever blocked in `Recv` resumes
            // whoever `Call`s it next". Same fix `p2_fault`'s own
            // "unconditional hand-off to `DM_TID` — direct, not generic
            // fairness" already established for exactly this class of
            // problem: bypass `pick_next` and switch straight to the
            // ONE thread this scoped, one-shot demo ever expects to
            // interact with the server (`root`), rather than trusting
            // general fairness to guess correctly.
            // See `p2_ipc_call`'s own comment on why `dispatch` (not
            // just `user_ctx_switch_ptrs`) is needed here.
            let _ = k.sched.dispatch(k.root_thread, hal.now_ns());
            let (save, into) = k.user_ctx_switch_ptrs(caller, k.root_thread)?;
            Some(IpcRecvOutcome::Switch(IpcSwitch { save, into, poke: None }))
        }
        _ => None,
    }
}

/// `IPC_REPLY` demo opcode: `SyscallOp::Reply`. Like `Call`, always a
/// switch (`do_reply` never returns a `Resume`-worthy outcome to the
/// replying thread itself — see that function's own doc comment).
pub fn p2_ipc_reply(hal: &HalInterface, caller: ThreadId, to_raw: u32, label: u64) -> Option<IpcSwitch> {
    let k = kstate();
    let to = ThreadId::new(to_raw);
    match k.dispatch(caller, hal.now_ns(), SyscallOp::Reply { to, msg: SmallMessage::new(label) }, hal) {
        Ok(SyscallReturn::Reschedule { next: Some(n) }) => {
            // See `p2_ipc_call`'s own comment on why `dispatch` (not
            // just `user_ctx_switch_ptrs`) is needed here.
            let _ = k.sched.dispatch(n, hal.now_ns());
            let (save, into) = k.user_ctx_switch_ptrs(caller, n)?;
            // `do_reply` only ever sets `pending_msg` (never
            // `pending_from` — the woken caller already knows who it
            // `Call`ed, unlike a receiver waking to a fresh `Call`).
            let poke = k
                .tcb_mut(n)
                .and_then(|t| t.pending_msg.take())
                .map(|m| (m.label as usize, 0usize));
            Some(IpcSwitch { save, into, poke })
        }
        _ => None,
    }
}

/// `IPC_DEMO_START` demo opcode: creates the endpoint this whole demo
/// runs on and spawns the SERVER thread (`server_entry_vma`, sharing the
/// caller's OWN address + capability space — like `p2_preempt_start`'s
/// own fresh a_loop thread — so the same `CapId` resolves to the same
/// endpoint for both without needing a `CapGrant`), then switches
/// straight to it. The server's `IPC_RECV` runs a moment later, on its
/// OWN trap, and (per that opcode's own doc comment) switches back here
/// once it finds nothing queued — resuming the ORIGINAL `IPC_DEMO_START`
/// caller right after this same switch, per `TrapOutcome::SwitchTo`'s
/// own contract.
pub fn p2_ipc_demo_start(
    hal: &HalInterface,
    caller: ThreadId,
    server_entry_vma: usize,
) -> Option<(u32, *mut u8, *const u8)> {
    let k = kstate();
    let ep_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: kernel_cap::CapId::new(0),
            target_type: kernel_mm::KernelObjectType::Endpoint,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    let server = k.alloc_tcb(k.root_cap_space, k.root_addr_space)?;
    // `root_frame = 0`: share the caller's OWN (already-active) address
    // space — same convention `p2_preempt_start`'s own fresh thread uses.
    // Stack: reuse `G_A_STACK_TOP` (root's own U-mode stack top, already
    // `U=1 R+W` mapped in this shared address space) — same convention
    // `p2_preempt_start`'s own fresh a_loop thread uses, for the same
    // reason: this server's code is pure register ops around `ecall`,
    // never pushes a frame, so nothing about the stack's prior contents
    // matters, and it never runs concurrently with whatever else might
    // also be using that VA (single-core, cooperative hand-off only).
    // SAFETY: single-core; `G_A_STACK_TOP` is written once by `enter`,
    // before any syscall (including this one) can run.
    let server_stack_top = unsafe { core::ptr::addr_of!(G_A_STACK_TOP).read() };
    k.init_user_thread(server, server_entry_vma, server_stack_top, 0, hal);
    // **Real bug found via QEMU**: `caller` (the client, e.g. `root`)
    // stays `Running` in the scheduler's own bookkeeping — `dispatch()`
    // below only ever updates the INCOMING thread, never the outgoing
    // one (see its own doc comment: "commits `thread` as the running
    // thread"). Every OTHER direct hand-off in this crate either
    // retires the outgoing thread first (`p2_preempt_start`'s
    // `sched.remove(root)`) or goes through `yield_to`, which re-readies
    // the outgoing thread ITSELF ("if `from` is still `Running`, mark it
    // `Ready`" — see `run.rs`'s own `yield_to`). This function does
    // neither: it hands off directly WITHOUT retiring `caller` (unlike
    // `p2_preempt_start` — `caller` must still be schedulable, it will
    // resume once `Reply` wakes it later). Without this line, `caller`
    // stays (incorrectly) `Running` forever after this switch, so the
    // FIRST `pick_next` call afterward (the server's own `IPC_RECV`,
    // when it finds nothing queued and blocks) cannot find `caller` at
    // all — it silently picked a completely unrelated `Ready` thread
    // instead (process B, left `Ready` from the earlier §8.4 demo,
    // still waiting for `P2_PREEMPT_START` to arm the timer), switching
    // the CPU to code that never returns here — an unexplained, totally
    // silent hang with no crash or diagnostic at all.
    let _ = k.sched.note_ready(caller, hal.now_ns());
    // Bypass `pick_next` — we are about to switch straight to `server`
    // unconditionally, so tell the scheduler that directly (same
    // reasoning as `p2_preempt_start`'s own explicit `dispatch` call).
    let _ = k.sched.dispatch(server, hal.now_ns());
    let (save, into) = k.user_ctx_switch_ptrs(caller, server)?;
    Some((ep_cap.as_u32(), save, into))
}

/// Busy-park forever. The in-kernel demo threads have nothing to return
/// to once their part is done; a real service would loop on `Recv`.
fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// Accessor for the kernel state, valid after `enter` has been called.
///
/// # Safety contract
/// Single-core; `enter` sets the pointer once before anything else runs,
/// so the returned `&mut` is never aliased. The final binary's
/// `simurgh_syscall` uses this from the S-mode trap handler.
pub fn kstate() -> &'static mut KernelState {
    // SAFETY: see the contract above.
    unsafe { &mut *core::ptr::addr_of_mut!(G_STATE).read() }
}

/// Accessor for the HAL interface, valid after `enter` has been called.
pub fn khal() -> &'static HalInterface {
    // SAFETY: `G_HAL` is set by `enter` before any thread runs.
    unsafe { &*core::ptr::addr_of!(G_HAL).read() }
}


/// The in-kernel milestone demo (02-Microkernel-Layer.md §8.1 / §8.2 /
/// §8.5): retype an `Endpoint`, exercise capability revocation, retype
/// and start a second thread, and complete a synchronous IPC round-trip.
/// Runs at kernel privilege, reaching the kernel by calling `dispatch`
/// directly. Returns normally when done.
fn inkernel_demo(k: &mut KernelState, hal: &HalInterface) {
    let root = k.root_thread;
    klog!("root task: running (thread {})\r\n", root.as_u32());

    // 1. An endpoint for the round-trip.
    let ep_cap = match k.dispatch(
        root,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Endpoint,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        other => {
            klog!("root task: endpoint Retype failed: {:?}\r\n", other);
            park();
        }
    };
    klog!("root task: endpoint cap slot = {}\r\n", ep_cap.as_u32());

    // 1b. Capability revocation (02-Microkernel-Layer.md §8.5): derive a
    //     two-level subtree from `ep_cap`, then `CapRevoke` the middle
    //     node and confirm the whole subtree (but not `ep_cap`) is gone.
    {
        let cs = k.root_cap_space;
        let child_a = k
            .cap_space_mut(cs)
            .and_then(|t| t.derive_child(ep_cap, CapabilityRights::all(), 0).ok())
            .expect("derive child A");
        let child_b = k
            .cap_space_mut(cs)
            .and_then(|t| t.derive_child(child_a, CapabilityRights::RW, 0).ok())
            .expect("derive child B");
        let before = k
            .cap_space(cs)
            .map(|t| t.lookup(child_a).is_some() && t.lookup(child_b).is_some())
            .unwrap_or(false);
        let freed = match k.dispatch(root, hal.now_ns(), SyscallOp::CapRevoke { cap: child_a }, hal) {
            Ok(SyscallReturn::Revoked { freed }) => freed,
            other => {
                klog!("root task: CapRevoke unexpected: {:?}\r\n", other);
                0
            }
        };
        let after_gone = k
            .cap_space(cs)
            .map(|t| {
                t.lookup(child_a).is_none()
                    && t.lookup(child_b).is_none()
                    && t.lookup(ep_cap).is_some()
            })
            .unwrap_or(false);
        klog!(
            "root task: revocation - subtree present before: {}, freed {} slot(s), gone after (parent kept): {}\r\n",
            before,
            freed,
            after_gone
        );
    }

    // 2. A TCB for thread 2 (bound to the Root Task's own cap space by
    //    the MVP `Retype` - so thread 2 can use `ep_cap` directly).
    let t2_cap = match k.dispatch(
        root,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::ThreadControlBlock,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        other => {
            klog!("root task: TCB Retype failed: {:?}\r\n", other);
            park();
        }
    };
    let t2 = {
        let cs = k.root_cap_space;
        let id = k
            .cap_space(cs)
            .and_then(|t| t.lookup(t2_cap))
            .map(|c| c.object.id.as_u32())
            .expect("thread 2 TCB cap resolves");
        ThreadId::new(id)
    };
    klog!(
        "root task: thread 2 = tid {} (cap slot {})\r\n",
        t2.as_u32(),
        t2_cap.as_u32()
    );

    // 3. Publish what thread 2 needs, then start it.
    let t2_stack_top =
        (core::ptr::addr_of!(THREAD2_STACK) as usize + THREAD_STACK_SIZE) & !0xF;
    // SAFETY: single-core; written before `start_thread` makes thread 2
    // runnable, read only by `thread2_main`.
    unsafe {
        core::ptr::addr_of_mut!(G_T2).write(t2.as_u32());
        core::ptr::addr_of_mut!(G_EP).write(ep_cap.as_u32());
        core::ptr::addr_of_mut!(G_ROOT).write(root.as_u32());
    }
    k.start_thread(t2, thread2_main as usize, t2_stack_top, hal);
    klog!("root task: thread 2 started\r\n");

    // 4. Block in Recv, then hand the CPU to whoever the scheduler picked
    //    (thread 2).
    match k.dispatch(root, hal.now_ns(), SyscallOp::Recv { endpoint: ep_cap }, hal) {
        Ok(SyscallReturn::Reschedule { next: Some(n) }) => {
            klog!("root task: blocked on Recv - switching to thread {}\r\n", n.as_u32());
            k.yield_to(root, n, hal);
        }
        Ok(SyscallReturn::Message { from, msg }) => {
            klog!(
                "root task: Recv returned a message immediately from {} (label {:#x})\r\n",
                from.as_u32(),
                msg.label
            );
        }
        other => {
            klog!("root task: Recv unexpected: {:?}\r\n", other);
            park();
        }
    }

    // 5. Resumed after thread 2 sent + yielded back. Read the message the
    //    kernel parked in our TCB.
    match k.tcb_mut(root).and_then(|t| t.pending_msg.take()) {
        Some(m) => klog!(
            "root task: IPC OK - got label {:#x}, words {:?}\r\n",
            m.label,
            m.words()
        ),
        None => klog!("root task: resumed but no message was delivered\r\n"),
    }

    klog!("root task: 8.2 milestone - 2nd thread + synchronous IPC round-trip complete\r\n");

    // 5b. IPC round-trip micro-benchmark (02-Microkernel-Layer.md §8.3
    //     acceptance harness: "ipc_call fast-path < 500 ns on reference
    //     hardware"). A dedicated thread 3 acts as an RPC SERVER: loops
    //     Recv -> Reply, `IPC_BENCH_ITERATIONS` times (`bench_server_
    //     main`). The Root Task acts as the CLIENT: times each `Call`
    //     (-> `yield_to` the server, which `Reply`s -> `yield_to` back)
    //     round trip via `hal.now_ns()`.
    //
    //     Every one of these `Call`s hits `kernel-core::syscall::
    //     do_send`'s REAL L4-style fast path (`kernel_ipc::fastpath::
    //     fast_path_eligible` wired in for real, plus the `Reply`
    //     syscall completing the round trip — both this project's own
    //     prior session): the server is always already blocked in
    //     `Recv` by the time the client's next `Call` lands, so
    //     `pick_next`'s fairness scan is skipped both directions. This
    //     is the tuned-fast-path number §8.3 actually asks for — NOT
    //     the general-dispatch baseline earlier sessions measured
    //     (that baseline used plain `Send`/`Recv`, which never took
    //     this branch at all; still true today for `Send`, see
    //     `plain_send_does_not_take_the_call_fast_path`).
    //
    //     What is NOT yet real: the register-only PARTIAL context
    //     switch `kernel_ipc::fastpath`'s own doc comment describes —
    //     `yield_to` below still performs `hal_core::HalInterface::
    //     context_switch`'s FULL GPR save/restore every time, so
    //     QEMU/TCG wall-clock numbers stay far from the literal
    //     <500ns target for that reason alone — same honestly-
    //     documented emulation gap every other timing-sensitive
    //     benchmark in this project reports, not a flaw in the fast
    //     path itself.
    let t3_cap = match k.dispatch(
        root,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::ThreadControlBlock,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => Some(cap),
        other => {
            klog!("root task: bench TCB Retype failed: {:?} - skipping §8.3 benchmark\r\n", other);
            None
        }
    };
    if let Some(t3_cap) = t3_cap {
        let t3 = {
            let cs = k.root_cap_space;
            let id = k
                .cap_space(cs)
                .and_then(|t| t.lookup(t3_cap))
                .map(|c| c.object.id.as_u32())
                .expect("bench thread TCB cap resolves");
            ThreadId::new(id)
        };
        let t3_stack_top =
            (core::ptr::addr_of!(THREAD3_STACK) as usize + THREAD_STACK_SIZE) & !0xF;
        // SAFETY: single-core; written before `start_thread` makes thread 3
        // runnable, read only by `bench_thread_main`. G_EP/G_ROOT are
        // unchanged from thread 2's setup above (same endpoint, same root).
        unsafe { core::ptr::addr_of_mut!(G_T3).write(t3.as_u32()) };
        k.start_thread(t3, bench_server_main as usize, t3_stack_top, hal);

        // Kick the server once so it reaches its own first `Recv` and
        // blocks — otherwise the Root Task's first `Call` below would
        // find no receiver queued yet (`SenderQueued`, the general
        // path) instead of the fast path `fast_path_eligible` needs an
        // ALREADY-blocked receiver for.
        k.yield_to(root, t3, hal);

        let (mut min_ns, mut max_ns, mut sum_ns) = (u64::MAX, 0u64, 0u64);
        for i in 0..IPC_BENCH_ITERATIONS {
            let req = SmallMessage::from_words(0xCA11, &[i as u64])
                .unwrap_or_else(|_| SmallMessage::new(0xCA11));
            let t0 = hal.now_ns();
            match k.dispatch(root, hal.now_ns(), SyscallOp::Call { endpoint: ep_cap, msg: req }, hal) {
                Ok(SyscallReturn::Reschedule { next: Some(n) }) => k.yield_to(root, n, hal),
                other => {
                    klog!("root task: bench Call unexpected: {:?}\r\n", other);
                    break;
                }
            }
            let dt = hal.now_ns().saturating_sub(t0);
            min_ns = min_ns.min(dt);
            max_ns = max_ns.max(dt);
            sum_ns += dt;
            let _ = k.tcb_mut(root).and_then(|t| t.pending_msg.take());
        }
        let avg_ns = sum_ns / IPC_BENCH_ITERATIONS as u64;
        klog!(
            "root task: ipc round-trip benchmark (02 8.3, {} iters, REAL Call+Reply fast path - do_send/do_reply skip pick_next; register-only HAL primitive still pending) - min {} ns, avg {} ns, max {} ns\r\n",
            IPC_BENCH_ITERATIONS,
            min_ns,
            avg_ns,
            max_ns
        );
    }

    // 6. Shared-memory model (02-Microkernel-Layer.md §5.2 / §8.4):
    //    alias ONE physical frame at two virtual addresses in the Root
    //    Task's address space and confirm both translate to it. This is
    //    the software-model view; step 7 does the same thing in hardware.
    let frame_cap = match k.dispatch(
        root,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Untyped,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return,
    };
    let frame_phys = {
        let uid = kernel_cap::UntypedId::new(
            k.cap_space(k.root_cap_space)
                .and_then(|t| t.lookup(frame_cap))
                .map(|c| c.object.id.as_u32())
                .unwrap_or(0),
        );
        match k.untyped_mut(uid) {
            Some(u) => u.base(),
            None => return,
        }
    };
    let (va1, va2) = (VirtAddr::new(0x5000_0000), VirtAddr::new(0x6000_0000));
    let rw = MapPermissions::KERNEL_DATA;
    if let Some(space) = k.addr_space_mut(k.root_addr_space) {
        let _ = space.map(va1, frame_phys, kernel_mm::PAGE_SIZE, rw);
        let _ = space.map(va2, frame_phys, kernel_mm::PAGE_SIZE, rw);
        let p1 = space.translate(VirtAddr::new(va1.as_usize() + 0x80)).map(|(p, _)| p.as_usize());
        let p2 = space.translate(VirtAddr::new(va2.as_usize() + 0x80)).map(|(p, _)| p.as_usize());
        klog!(
            "root task: shared-memory model - va {:#x} -> {:?}, va {:#x} -> {:?} (one frame {:#x}, two mappings, aliased: {})\r\n",
            va1.as_usize(),
            p1,
            va2.as_usize(),
            p2,
            frame_phys.as_usize(),
            p1.is_some() && p1 == p2
        );
    }

    // 7. The same aliasing, MMU-enforced across TWO separate Sv39 address
    //    spaces (02-Microkernel-Layer.md §8.4). Build two independent root
    //    page tables, each with its own low-3 GiB kernel identity map (so
    //    S-mode keeps executing across the `satp` swaps) plus the shared
    //    frame at a DIFFERENT virtual address in each. Then: write through
    //    space A's VA, switch to space B, read it back through B's VA,
    //    write a new value, switch back to A, read that. If both crossings
    //    see the other space's write, the frame is genuinely shared with
    //    no copy. Runs here with paging still off (`satp == 0`), so
    //    `map_range`'s physical pointers are directly addressable; the
    //    final `activate_address_space(0)` returns to Bare mode before
    //    `enter` builds the real Root Task space.
    //
    //    This is the kernel-mechanism half of "two processes share memory
    //    zero-copy"; running two U-mode threads concurrently in spaces A
    //    and B additionally needs a context-switch primitive that can
    //    resume a user context (tracked in IMPLEMENTATION-PLAN.md).
    let two_space = (|| {
        let uid = || kernel_cap::UntypedId::new(0);
        // 3 pages each, not 1 — see `enter`'s own `root_pt` carve (this
        // function runs BEFORE `enter`'s own address-space setup, called
        // from inside `enter` itself, but the SAME "some architectures'
        // `root_frame` needs a companion page" reasoning applies here
        // identically). **Real bug found via QEMU**: with 1 page each,
        // x86_64's `map_ram_identity` (which always writes a PDPT at
        // `root_frame + 4096`) silently OVERWROTE `sp_b` while building
        // `sp_a`'s table, then overwrote `pool` while building `sp_b`'s —
        // a cascading corruption whose only symptom was the CPU quietly
        // executing garbage after `activate_address_space(sp_a)` (no
        // panic, no fault visible in serial output — just silence,
        // confirmed via `-d int`: no further kernel code ever ran).
        let sp_a = k.untyped_mut(uid())?.alloc(4096, 4096 * 3).ok()?.as_usize();
        let sp_b = k.untyped_mut(uid())?.alloc(4096, 4096 * 3).ok()?.as_usize();
        let pool = k.untyped_mut(uid())?.alloc(4096, 4096 * 4).ok()?.as_usize();
        Some((sp_a, sp_b, pool))
    })();
    let (sp_a, sp_b, pool) = match two_space {
        Some(v) => v,
        None => {
            klog!("root task: two-address-space proof skipped (no untyped left)\r\n");
            return;
        }
    };
    // SAFETY: `pool` is fresh untyped RAM, identity-addressable with
    // paging off; single-core; `map_range` requires it pre-zeroed.
    unsafe {
        core::ptr::write_bytes(pool as *mut u8, 0, 4096 * 4);
    }
    let phys = frame_phys.as_usize();
    let (va_a, va_b) = (0xE000_0000usize, 0xF000_0000usize);
    // SAFETY: single-core; only written once, by `enter`, before this runs.
    let bytes_gib = unsafe { core::ptr::addr_of!(G_BYTES_GIB).read() };
    hal.map_ram_identity(sp_a, bytes_gib, false);
    hal.map_ram_identity(sp_b, bytes_gib, false);
    let n_a = hal.map_range(sp_a, va_a, phys, 4096, 1 | 2, pool, 4);
    let n_b = if n_a == u32::MAX {
        u32::MAX
    } else {
        hal.map_range(sp_b, va_b, phys, 4096, 1 | 2, pool + (n_a as usize) * 4096, 4 - n_a as usize)
    };
    if n_a == u32::MAX || n_b == u32::MAX {
        klog!("root task: two-address-space proof skipped (map_range unsupported on this arch)\r\n");
        return;
    }
    // SAFETY: after each `activate_address_space`, `va_a` (in space A) /
    // `va_b` (in space B) map the shared frame `R+W`; the kernel's own
    // code/stack stay valid via each table's identity map. Single-core,
    // no other reference to the frame is live. `flush_tlb` after every
    // write makes the next crossing observe it.
    let (seen_in_b, seen_in_a) = unsafe {
        hal.activate_address_space(sp_a);
        core::ptr::write_volatile(va_a as *mut u32, 0xA1A1);
        hal.flush_tlb();

        hal.activate_address_space(sp_b);
        let b = core::ptr::read_volatile(va_b as *const u32);
        core::ptr::write_volatile(va_b as *mut u32, 0xB2B2);
        hal.flush_tlb();

        hal.activate_address_space(sp_a);
        let a = core::ptr::read_volatile(va_a as *const u32);

        hal.activate_address_space(0); // back to Bare mode for `enter`
        (b, a)
    };
    klog!(
        "root task: two Sv39 spaces - frame {:#x} at VA {:#x} (A) / {:#x} (B); A wrote 0xa1a1, B read {:#x}, B wrote 0xb2b2, A read {:#x} -> {}\r\n",
        phys,
        va_a,
        va_b,
        seen_in_b,
        seen_in_a,
        if seen_in_b == 0xA1A1 && seen_in_a == 0xB2B2 {
            "ZERO-COPY ACROSS ISOLATED SPACES"
        } else {
            "MISMATCH"
        }
    );
}

/// The second thread's entry point (runs on `THREAD2_STACK`). Sends one
/// message on the shared endpoint, then hands control back to the Root
/// Task.
extern "C" fn thread2_main() -> ! {
    let k = kstate();
    let hal = khal();
    // SAFETY: set by `root_task_main` before `start_thread`.
    let me = ThreadId::new(unsafe { core::ptr::addr_of!(G_T2).read() });
    let ep = CapId::new(unsafe { core::ptr::addr_of!(G_EP).read() });
    let root = ThreadId::new(unsafe { core::ptr::addr_of!(G_ROOT).read() });

    klog!("thread 2: running (tid {})\r\n", me.as_u32());

    let msg = SmallMessage::from_words(0xABCD, &[42, 7]).unwrap_or_else(|_| SmallMessage::new(0xABCD));
    match k.dispatch(me, hal.now_ns(), SyscallOp::Send { endpoint: ep, msg }, hal) {
        Ok(SyscallReturn::Delivered { woke }) => {
            klog!("thread 2: sent message; woke thread {}\r\n", woke.as_u32())
        }
        other => klog!("thread 2: Send unexpected: {:?}\r\n", other),
    }

    klog!("thread 2: done - handing control back to the Root Task\r\n");
    // Mark ourselves Exited and drop out of the scheduler BEFORE the final
    // yield_to. `yield_to` only re-admits an outgoing thread to `Ready` if
    // the scheduler still finds it `Running` — thread 2 never runs dispatch
    // again after this point (it just parks), so without this it would sit
    // forever as a phantom `Ready` entity that a later `pick_next` (e.g.
    // the §8.3 benchmark below) could select, switching into a thread that
    // can only spin — hanging the kernel.
    if let Some(t) = k.tcb_mut(me) {
        t.state = kernel_core::ThreadState::Exited;
    }
    k.sched.remove(me);
    k.yield_to(me, root, hal);
    park();
}

/// The `02-Microkernel-Layer.md §8.3` IPC round-trip benchmark's RPC
/// SERVER (runs on `THREAD3_STACK`): `Recv`s a request, `Reply`s to it,
/// `IPC_BENCH_ITERATIONS` times — the Root Task (the CLIENT) drives the
/// round trip with `Call`, timing each one.
///
/// Every `Recv`/`Reply` here is deliberately queued via `dispatch`
/// BEFORE the one real `yield_to` that actually switches away — never
/// "Reply, then immediately switch, then re-`Recv` after switching
/// back": `dispatch` on its own never performs a context switch (this
/// crate's own established contract), so calling `Reply` then `Recv`
/// back-to-back, and only THEN switching once, means this server is
/// ALREADY re-registered as the endpoint's blocked receiver by the time
/// control reaches the Root Task — exactly the precondition `kernel_
/// ipc::fastpath::fast_path_eligible` needs for the Root Task's NEXT
/// `Call` to hit the fast path too. Get this ordering wrong (switch
/// away first, `Recv` again after) and every `Call` after the first
/// would fall back to the general `SenderQueued` path instead.
///
/// The exit-the-scheduler step (same reasoning as `thread2_main`'s
/// tail) has to happen on the LAST iteration, right before that
/// iteration's own final switch (straight back to `from`, skipping the
/// "queue a `Recv` nobody will ever answer" step entirely) — once that
/// switch runs, this thread's saved context sits frozen there, and the
/// Root Task's own loop below never switches back in.
extern "C" fn bench_server_main() -> ! {
    let k = kstate();
    let hal = khal();
    // SAFETY: set by `inkernel_demo` before `start_thread`.
    let me = ThreadId::new(unsafe { core::ptr::addr_of!(G_T3).read() });
    let ep = CapId::new(unsafe { core::ptr::addr_of!(G_EP).read() });

    // Prime: block for the FIRST request. `inkernel_demo`'s own
    // `k.yield_to(root, t3, hal)` "kick" (right after `start_thread`)
    // is what runs this thread for the very first time, landing here.
    if let Ok(SyscallReturn::Reschedule { next: Some(n) }) =
        k.dispatch(me, hal.now_ns(), SyscallOp::Recv { endpoint: ep }, hal)
    {
        k.yield_to(me, n, hal);
    }
    // Resumed here (or fell straight through, if `Recv` somehow
    // delivered synchronously): the Root Task's first `Call` has
    // delivered its request directly into `pending_msg`/`pending_from`.

    for i in 0..IPC_BENCH_ITERATIONS {
        let from = k.tcb_mut(me).and_then(|t| t.pending_from.take());
        let _req = k.tcb_mut(me).and_then(|t| t.pending_msg.take());
        let Some(from) = from else {
            klog!("bench server: woke with no pending_from - stopping\r\n");
            break;
        };
        let reply = SmallMessage::from_words(0xF00D, &[i as u64])
            .unwrap_or_else(|_| SmallMessage::new(0xF00D));

        if let Err(e) = k.dispatch(me, hal.now_ns(), SyscallOp::Reply { to: from, msg: reply }, hal) {
            klog!("bench server: Reply failed: {:?}\r\n", e);
            break;
        }

        if i + 1 == IPC_BENCH_ITERATIONS {
            if let Some(t) = k.tcb_mut(me) {
                t.state = kernel_core::ThreadState::Exited;
            }
            k.sched.remove(me);
            k.yield_to(me, from, hal);
            break;
        }

        // Re-register as the blocked receiver for the NEXT request
        // BEFORE the real switch below — see this function's own doc
        // comment on why the ordering matters.
        match k.dispatch(me, hal.now_ns(), SyscallOp::Recv { endpoint: ep }, hal) {
            Ok(SyscallReturn::Reschedule { next: Some(n) }) => k.yield_to(me, n, hal),
            other => {
                klog!("bench server: Recv unexpected: {:?}\r\n", other);
                break;
            }
        }
        // Resumed here once the Root Task's NEXT `Call` delivers.
    }
    park();
}

#[cfg(test)]
mod tests {
    // The meaningful behaviour here (context switching into a real thread)
    // only runs on the bare-metal target and is exercised by booting
    // `kernel` under QEMU. The host build just needs to compile.
    #[test]
    fn compiles() {}
}
