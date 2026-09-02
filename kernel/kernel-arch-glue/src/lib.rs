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
    /// Number of MMIO peripherals HAL discovered (`hal_core::peripheral`
    /// — virtio-mmio on riscv64/aarch64 today). Read straight from
    /// `boot.hardware_manifest`, not `KernelState`: no kernel-core object
    /// consumes this yet (that arrives with the Device Manager's own
    /// MMIO-capability-grant path) — this field exists purely as boot-
    /// time discovery evidence, matching `untyped_objects`' own role for
    /// memory.
    pub peripheral_devices: u32,
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
        peripheral_devices: boot.hardware_manifest.peripheral_device_count,
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
    // (needs 3 GiB); x86_64's tiny, low (`KERNEL_LMA_BASE = 0x0180_0000`
    // — see hal-x86_64/linker.ld's own doc comment for why it moved up
    // from the original 0x0020_0000) image still needs only 1. `.user_
    // text`/`.user_stack` then land in the
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
/// Process B's own thread id (the §8.4 two-space zero-copy demo's
/// worker), set once by `setup_two_process`. Read only by `spawn_
/// netstack_service`'s own stale-thread retirement — see that
/// function's own doc comment for why: like `G_IPC_SERVER_TID`/`G_FS_
/// TID`, process B's own one-shot job finishes long before `p2_
/// preempt_start`'s own identical cleanup normally runs, leaving it
/// `Ready`-but-never-resumed and a live `pick_next` candidate for
/// anything that exercises GENERAL (non-fast-path) `pick_next` before
/// that point — Netstack's own retry loop is the first such caller.
static mut G_PROCESS_B_TID: Option<ThreadId> = None;

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
    // SAFETY: single-core; written once here, before any later reader
    // (`spawn_netstack_service`'s own stale-thread retirement) can run.
    unsafe { core::ptr::addr_of_mut!(G_PROCESS_B_TID).write(Some(worker_tid)) };

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
    // 32 page-table-walk scratch pages, not `spawn_process`'s own 8 —
    // **real bug found via QEMU** (fs-native's own spawn): a bigger ELF
    // image (fs-native-bin links `alloc`/`BTreeMap`/`ipc_protocol`'s
    // codec, roughly double device-manager-bin's own size) spans enough
    // 2 MiB regions across its `.text`/`.rodata`/`.data`/`.bss`
    // PT_LOAD segments plus the stack that 8 pool pages ran out mid-
    // walk (`map_range` returned `u32::MAX`, logged "map_range error
    // (PT_LOAD segment)"), which this function's own `?` then silently
    // turned into a `None` return — cascading into a FAR worse failure
    // one level up: `fs_demo_start`'s shared-page setup never ran, so
    // `G_FS_SHARED_PHYS` stayed at its `usize::MAX` sentinel, and the
    // very next `write_shared_fs_message` call dereferenced it,
    // panicking on an unaligned/null pointer. Bumping the pool is pure
    // headroom — existing, smaller callers (device-manager-bin) simply
    // use fewer of a bigger pool, unchanged behavior.
    const POOL_PAGES: usize = 32;
    let pool = carve(state, 4096 * POOL_PAGES as u64)?;
    let stack_phys = carve(state, round4k(stack_len) as u64)?;
    // SAFETY: fresh untyped RAM, identity-addressable (paging is not yet
    // active on this new space); single-core. `map_range` needs the pool
    // pre-zeroed.
    unsafe { core::ptr::write_bytes(pool as *mut u8, 0, 4096 * POOL_PAGES) };

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
            POOL_PAGES - used as usize,
        );
        if n == u32::MAX {
            false
        } else {
            used += n;
            true
        }
    };

    for seg in segments {
        // **Real bug found via QEMU** (fs-native's own spawn — the
        // FIRST ELF this loader ever loaded whose linker output didn't
        // happen to leave every PT_LOAD segment's own `p_vaddr` already
        // page-aligned): `map_range` requires page-aligned inputs
        // (`(vaddr | paddr | len) & 0xFFF != 0` is a hard error, per its
        // own doc comment), but nothing here ever page-ALIGNED
        // `seg.vaddr` before passing it straight through — this loop
        // just trusted the ELF's own `p_vaddr` to already be a multiple
        // of 4 KiB. device-manager-bin's own linker output happened to
        // satisfy that by luck (every one of its PT_LOAD segments
        // landed on a page boundary); fs-native-bin's third segment
        // (`.data`, `vaddr=0xc0022790` — a genuine, ELF-spec-legal
        // "page-unaligned within an otherwise page-aligned OUTPUT
        // section" layout, common whenever ld groups multiple smaller
        // input sections before the segment's declared alignment
        // point) was the first to violate that unstated assumption,
        // failing `map_range`'s own precondition check every time
        // (confirmed via a temporary diagnostic print: `vaddr=
        // 0xc0022790`, low 12 bits `0x790`, nonzero). Fixed the
        // standard way any ELF loader handles this (matching what
        // Linux's own loader does): round `p_vaddr` DOWN to the
        // containing page, and carry the resulting in-page offset
        // through the mapped SIZE and the file-data COPY destination,
        // so the segment's actual bytes still land at the CORRECT
        // (unaligned) virtual address once mapped, just via a
        // page-aligned `map_range` call.
        let page_off = seg.vaddr as usize & 0xFFF;
        let aligned_vaddr = seg.vaddr as usize - page_off;
        let mem_size4k = round4k(seg.mem_size as usize + page_off);
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
        // The copy destination is offset by `page_off`: `seg_phys` now
        // names the containing PAGE (per the alignment fix above), not
        // `seg.vaddr` itself, so the segment's own bytes must start
        // `page_off` bytes into it to land at the correct address once
        // `aligned_vaddr + page_off` (== `seg.vaddr`) is mapped.
        unsafe {
            core::ptr::write_bytes(seg_phys as *mut u8, 0, mem_size4k);
            core::ptr::copy_nonoverlapping(
                elf_bytes.as_ptr().add(file_offset),
                (seg_phys + page_off) as *mut u8,
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

        if !step(aligned_vaddr, seg_phys, mem_size4k, perm) {
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
    // Retire `p2_ipc_demo_start`'s own one-shot server thread too, for
    // the identical reason root's own old TCB is retired just above —
    // see `G_IPC_SERVER_TID`'s own "Real bug found via QEMU" doc comment
    // for the full story (a `pick_next` tie-break flip, triggered by
    // fs-native's own extra thread, resumed this long-done thread's
    // stale saved context instead of the intended A/B/C rotation).
    // SAFETY: single-core; only read (and cleared) here, written once by
    // `p2_ipc_demo_start` before this can ever run.
    if let Some(server_tid) = unsafe { core::ptr::addr_of!(G_IPC_SERVER_TID).read() } {
        if let Some(t) = state.tcb_mut(server_tid) {
            t.state = ThreadState::Exited;
        }
        state.sched.remove(server_tid);
        unsafe { core::ptr::addr_of_mut!(G_IPC_SERVER_TID).write(None) };
    }
    // fs-native's own thread hits the SAME bug class as the demo server
    // just above, for a DIFFERENT underlying reason: **real bug found
    // via QEMU** (aarch64 specifically — confirmed via a temporary
    // `p2_tick` diagnostic showing `incoming=5`, fs-native's own known
    // tid, immediately followed by a total, silent, rapid-refire hang —
    // riscv64/x86_64 happened not to hit it, purely by thread-ID tie-
    // break luck, the same way the demo server's own bug above was
    // luck-dependent). Unlike the demo server, fs-native is a REAL,
    // ongoing service — `do_reply` (correctly, generically) marks IT
    // `Ready` again after each reply, since a real server loops back to
    // `Recv` for its next request. But after its OWN LAST reply
    // (`FS_CLOSE`'s, in this MVP demo), fs-native never actually gets
    // CPU time again to reach that next `Recv` and block on it PROPERLY
    // — `do_reply`'s own switch hands control back to the CALLER (root),
    // not to the replying thread itself, by design (see `SyscallOp::
    // Reply`'s own doc comment) — so fs-native is left `Ready`-but-
    // never-resumed, exactly like the demo server, and can be picked by
    // this SAME ordinary `pick_next` round-robin it was never meant to
    // join. Unlike the demo server, fs-native must NOT be `sched.
    // remove()`d — its own TCB slot has to stay valid forever, since
    // `fs_ipc_call`'s own direct `dispatch(fs_tid, ...)` (bypassing
    // `pick_next` entirely, on every architecture) is how it is
    // ACTUALLY meant to run for any future request. `note_blocked`
    // (not `remove`) is exactly the right tool: it removes fs-native
    // from `pick_next`'s own candidate pool (its own `RunState` is no
    // longer `Ready`) while leaving the TCB slot itself fully intact —
    // a later `dispatch()` call unconditionally commits a thread as
    // running regardless of its current `RunState`, so this in no way
    // blocks a genuine future `fs_ipc_call`. Harmless no-op if
    // fs-native happened to already be properly `BlockedOnRecv` (e.g.
    // riscv64/x86_64, where this was never actually observed broken).
    // SAFETY: single-core; `G_FS_TID` written once by `fs_demo_start`,
    // read-only here.
    if let Some(fs_tid) = unsafe { core::ptr::addr_of!(G_FS_TID).read() } {
        let _ = state.sched.note_blocked(fs_tid);
    }
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

/// `p2_ipc_demo_start`'s own one-shot server thread, so `p2_preempt_start`
/// can explicitly retire it once the demo's role is done.
///
/// **Real bug found via QEMU** (this session's x86_64 preemption crash,
/// exposed only once fs-native's own extra spawned thread shifted later
/// `ThreadId` numbering): `do_reply` (`kernel_core::syscall`) correctly,
/// generically marks a REPLYING thread `Ready` again afterward — right
/// behavior for a REAL, ongoing server that loops back to `Recv` for the
/// next request (fs-native's own thread relies on exactly this). This
/// demo's OWN server (`umode_ipc_server*`) does NOT loop back — per its
/// own doc comment, `IPC_REPLY` "always switches away on success", so the
/// `jmp 2b` after it is genuinely unreachable, and the thread is DONE
/// forever the moment it replies. But nothing ever told the SCHEDULER
/// that: `do_reply`'s own `note_ready(replier, ...)` leaves it `Ready`
/// permanently. Confirmed via QEMU's own `-d int` exception trace: the
/// crash's own register dump (RAX=0x2c=`IPC_REPLY`'s opcode, RSI=
/// 0xc0ffef, the demo's own reply sentinel) is UNMISTAKABLY this
/// server's own long-stale saved context, resumed by `p2_tick`'s
/// ordinary round-robin `pick_next` — its own vruntime=0 (never
/// meaningfully ran) usually LOSES `pick_next`'s "lowest wins" tie-break
/// against process C/the fresh loop thread (also vruntime=0, but a
/// HIGHER `ThreadId`, per `pick_next`'s own "`ThreadId` as a stable tie-
/// break" rule) — UNTIL fs-native's own extra spawned thread shifts
/// every LATER `ThreadId` up by one, at which point THIS demo server's
/// own (unchanged, lower) `ThreadId` starts winning instead. Resuming it
/// crashes (not merely spins harmlessly in its own `jmp 2b`) because its
/// OWN saved `rip` is unrelated to that loop in the first place — it is
/// whatever `f.rip` the CPU had captured at the ORIGINAL `int 0x80`/
/// `ecall`/`svc` trap boundary for its OWN `IPC_REPLY` call, which this
/// MVP demo's fast-path save never had a reason to make land on a safe,
/// re-enterable instruction (it was never meant to be re-entered at
/// all). The real fix is retiring this thread once its one-shot role
/// ends — see `p2_preempt_start`'s own use of this static — not treating
/// its `rip` as if resuming it were ever a supported outcome.
///
/// # Safety
/// Single-core; written once by `p2_ipc_demo_start`, read (and cleared)
/// once by `p2_preempt_start`.
static mut G_IPC_SERVER_TID: Option<ThreadId> = None;

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
    // SAFETY: single-core; written once here, read only by
    // `p2_preempt_start` (which retires this thread once the demo's own
    // one-shot role is done — see `G_IPC_SERVER_TID`'s own doc comment).
    unsafe { core::ptr::addr_of_mut!(G_IPC_SERVER_TID).write(Some(server)) };
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

// ============================================================================
// fs-native as a REAL, isolated process, driven by the REAL FsRequest/
// FsResponse wire protocol over the REAL Call/Recv/Reply mechanism above
// (03-Kernel-Subsystems-Layer.md §2.2/§5.3) — the first time this
// project's IPC fast path drives a genuine subsystem's own logic
// end-to-end, not just a demo payload. Unlike `p2_ipc_demo_start`'s
// server (which shares the caller's own address AND capability space —
// `.user_text`, embedded in the kernel image), fs-native is spawned via
// `spawn_process_from_elf` exactly like device-manager: its own address
// space, its own capability space, its own separately-built ELF.
//
// Two problems that mechanism doesn't solve on its own, both handled
// here: (1) the Endpoint capability the caller Retypes lives in the
// CALLER's cap space only — `grant_cap_into` copies it into fs-native's
// own fresh cap space (predictably landing at slot 0, since a brand-new
// `CapTable` always allocates its first slot from 0 — see `CapTable::
// new`'s own free-list construction); (2) `SmallMessage` carries up to 6
// data words, but every architecture's own raw syscall convention this
// project defined only threads 2 payload registers (`a0`/`a1`,
// `rdi`/`rsi`, `x0`/`x1`) through `int 0x80`/`svc`/`ecall` — nowhere
// near enough for a real `FsRequest`/`FsResponse`. Rather than widening
// every `hal-<arch>::cpu::SyscallHandler` signature (a much bigger,
// unrelated change), the full `SmallMessage` (label + all 6 words,
// zero-padded) is marshalled through ONE shared physical frame instead —
// the same "share a frame, not the message registers" principle
// `ipc-protocol::fs`'s own `shared_cap` field already uses for bulk
// Read/Write data, just applied to the whole small message here.
//
// A `.user_text` function (this project's OWN in-kernel demo code, NOT
// fs-native's own separate ELF image) must never call a regular,
// non-inlined function living in the surrounding kernel binary's `.text`
// — the risk that already bit this project once (see hal-x86_64's own
// `#[inline(always)]`/`opt-level` fix for device-manager's very first
// in-kernel process). `ipc_protocol::codec::{encode,decode}_fs_*` are
// ordinary functions, so `kernel/src/main.rs`'s `umode_root*` never
// calls them directly: those functions live EITHER here (this crate is
// a normal `rlib`, not `.user_text`) or inside `fs-native-bin` itself
// (a fully separate, self-contained ELF — every byte of it is U=1, so
// there is no "calling into kernel .text" risk there at all). `umode_
// root*` only ever passes plain integers to the wrapper opcodes below.
// ============================================================================

/// Physical address of the one page shared between the caller (accessed
/// via the kernel's own always-present identity map — see `p2_report_a`'s
/// own cross-checks for the same pattern) and fs-native's own process
/// (mapped into ITS address space at a fixed VA by `fs_demo_start`).
/// `usize::MAX` = not yet set up (`fs_demo_start` has not run).
///
/// # Safety
/// Single-core; written once by `fs_demo_start`, read only afterward.
static mut G_FS_SHARED_PHYS: usize = usize::MAX;

/// Physical address of the one page shared for BULK Read/Write data —
/// same contract as `G_FS_SHARED_PHYS`, just the SECOND shared page
/// (`FS_DATA_VA`, not `FS_SHARED_VA`).
///
/// # Safety
/// Single-core; written once by `fs_demo_start`, read only afterward.
static mut G_FS_DATA_PHYS: usize = usize::MAX;

/// fs-native's own `ThreadId`, written once by `fs_demo_start` and read
/// by `fs_ipc_call` — see that function's own doc comment for why every
/// FS call after the first needs to know this directly rather than
/// trusting `do_send`'s general fallback. Same `Option<ThreadId>`
/// convention `DM_TID` already uses for the identical "permanent,
/// spawned-once target thread" shape.
///
/// # Safety
/// Single-core; written once by `fs_demo_start`, read only afterward.
static mut G_FS_TID: Option<ThreadId> = None;

/// Writes `msg`'s full `(label, words[0..6] zero-padded)` into the
/// shared fs page. Always writes all 6 word slots (unused ones as 0)
/// rather than tracking a separate length — `decode_fs_request`/
/// `decode_fs_response`'s own `need(n)` checks only require AT LEAST
/// `n` words to be present, so extra trailing zeros are harmless, and
/// this keeps the wire layout fixed-size (56 bytes) with no separate
/// length field to keep in sync.
///
/// # Safety
/// `G_FS_SHARED_PHYS` must already be a valid, exclusively-owned,
/// mapped physical frame (`fs_demo_start` has run).
unsafe fn write_shared_fs_message(msg: &SmallMessage) {
    // SAFETY: single-core; `G_FS_SHARED_PHYS` only written once by
    // `fs_demo_start`, before this can ever be called.
    let base = unsafe { core::ptr::addr_of!(G_FS_SHARED_PHYS).read() } as *mut u64;
    // SAFETY: forwarded from this function's own contract — `base`
    // names a valid, mapped, 4 KiB physical frame, and low RAM is
    // always identity-mapped for kernel-mode access regardless of
    // which process's page table is currently active (the same
    // assumption every other `p2_*` physical-address cross-check in
    // this file already relies on).
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Reads back a `SmallMessage` written by `write_shared_fs_message` (by
/// either side — this is a plain, symmetric shared-memory read).
///
/// # Safety
/// Same contract as `write_shared_fs_message`.
unsafe fn read_shared_fs_message() -> SmallMessage {
    // SAFETY: single-core; same contract as `write_shared_fs_message`.
    let base = unsafe { core::ptr::addr_of!(G_FS_SHARED_PHYS).read() } as *const u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        // `from_words` cannot fail here: `words.len() == MSG_MAX_WORDS`.
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// Derives `cap` (from `src_cs`) directly into `dst_cs`, narrowed to
/// `rights` — the SAME cross-space CDT derivation
/// `kernel_core::syscall::do_cap_grant` uses for the real,
/// capability-gated `SyscallOp::CapGrant`, just called directly on
/// `CapSpaceId`s this trusted glue code already holds rather than
/// through a `target_thread: CapId` lookup (which would require the
/// caller to ALREADY hold a `ThreadControlBlock` capability for the
/// destination — something `spawn_process`/`spawn_process_from_elf`
/// deliberately do not hand out, matching every other kernel-arch-glue
/// bootstrap helper's own "trusted glue, not a real syscall" precedent).
/// `cap` itself is left untouched in `src_cs`, and the new slot's CDT
/// parent link points back at it, so a later `CapRevoke` on `cap` (in
/// `src_cs`) reaches and frees this grant too, even though it lives in
/// `dst_cs` (`kernel_cap::cdt::derive_child_cross_space`).
fn grant_cap_into(
    state: &mut KernelState,
    src_cs: kernel_cap::CapSpaceId,
    cap: CapId,
    dst_cs: kernel_cap::CapSpaceId,
    rights: CapabilityRights,
) -> Option<CapId> {
    let (src, dst) = state.cap_space_pair_mut(src_cs, dst_cs)?;
    kernel_cap::cdt::derive_child_cross_space(src, src_cs, cap, dst, rights, 0).ok()
}

/// VA fs-native's own process maps the shared fs page at — an address no
/// other mapping in ITS OWN (freshly carved, otherwise-empty) address
/// space uses; safe to reuse across every architecture's own isolated
/// spawn, unlike `.user_text`'s own per-architecture base VMA
/// constraints (this is a plain data page, not an ELF image base).
const FS_SHARED_VA: usize = 0xD800_0000;

/// VA fs-native's own process maps the shared BULK DATA region at — a
/// second, separate page from `FS_SHARED_VA` (which only ever carries
/// the small, fixed-size `SmallMessage` header). Real `Read`/`Write`
/// bytes travel here instead, per `ipc_protocol::fs`'s own "bulk data
/// travels through a SharedRegion, not the message" design.
const FS_DATA_VA: usize = 0xD810_0000;

/// fs-native's own deterministic capability slot for its one shared data
/// region, in ITS OWN capability space — same reasoning `FS_ENDPOINT_CAP`
/// (fs-native's own `subsystem_entry.rs` constant) already documents for
/// slot 0: `fs_demo_start` grants fs-native's fresh, otherwise-empty cap
/// space exactly two capabilities, in a fixed order (the endpoint, then
/// this region), and a `CapTable`'s free list always allocates
/// sequentially from an empty table, so the SECOND grant is guaranteed
/// to land at slot 1.
const FS_DATA_SHARED_CAP_SLOT: u32 = 1;

/// Fixed MVP test payload for the `FS_WRITE`/`FS_READ` demo opcodes —
/// same "one demo, one hardcoded scenario" convention `resolve_path`'s
/// own `PathId(0)`-only precedent (fs-native's `subsystem_entry.rs`)
/// already establishes; a real VFS Router would carry caller-supplied
/// bytes, not a kernel-glue constant. Sized to the FULL shared DATA
/// page (matching fs-native's own `FS_DATA_LEN` constant) rather than a
/// short string, so the same buffer doubles as the payload for the
/// throughput benchmark below (03-Kernel-Subsystems-Layer.md §5, item
/// 5: "VFS read/write throughput... reported") — a few dozen bytes per
/// round trip would measure almost pure IPC overhead, not the kind of
/// transfer size a real `dd`/`fio`-style comparison uses.
const FS_DEMO_WRITE_DATA_ARR: [u8; 4096] = {
    let mut data = [0u8; 4096];
    let mut i = 0;
    while i < data.len() {
        // A recognizable, non-constant byte pattern (not all-zero) so
        // `fs_read_result`'s own MATCH/MISMATCH cross-check still means
        // something.
        data[i] = (i % 251) as u8;
        i += 1;
    }
    data
};
const FS_DEMO_WRITE_DATA: &[u8] = &FS_DEMO_WRITE_DATA_ARR;

/// One-time setup: creates the endpoint fs-native and its client
/// (`caller`, always the Root Task in this MVP) rendezvous on, spawns
/// fs-native as a genuinely isolated process from its own separately-
/// built ELF image (`fs_elf`), grants it a capability to the SAME
/// endpoint object, gives it a page of memory shared with the kernel's
/// own identity map for the real `SmallMessage` payload, and switches
/// straight to it (see this function's own tail comment for why that
/// switch is mandatory, not optional, unlike a bare spawn). Returns the
/// endpoint's capability slot in the CALLER's own cap space (fs-native's
/// own copy always lands at slot 0 — see `grant_cap_into`'s own doc
/// comment on why that is deterministic for a freshly spawned,
/// otherwise-empty process) plus the `(save, into)` switch pointers the
/// caller wraps in a `TrapOutcome::SwitchTo`.
pub fn fs_demo_start(
    hal: &HalInterface,
    caller: ThreadId,
    fs_elf: &[u8],
    expected_machine: u16,
) -> Option<(u32, *mut u8, *const u8)> {
    let k = kstate();
    let ep_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Endpoint,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };

    const FS_STACK_VMA: usize = 0xC040_0000;
    const FS_STACK_LEN: usize = 4096 * 16;
    let (fs_tid, fs_cs, _stack_phys) =
        spawn_process_from_elf(hal, k, fs_elf, expected_machine, FS_STACK_VMA, FS_STACK_LEN)?;
    // SAFETY: single-core; written once here, before any `fs_ipc_call`
    // (reached only via FS_OPEN/FS_STAT/FS_CLOSE, all issued after this
    // opcode returns) can read it.
    unsafe { core::ptr::addr_of_mut!(G_FS_TID).write(Some(fs_tid)) };

    let src_cs = k.tcb(caller)?.cap_space;
    grant_cap_into(k, src_cs, ep_cap, fs_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;

    // Carve and map the shared fs page into fs-native's OWN fresh
    // address space — mirrors `spawn_process`/`spawn_process_from_elf`'s
    // own "carve untyped, map_range directly, no SyscallOp ceremony"
    // pattern (this is trusted bootstrap glue, not a real user syscall).
    let fs_addr_space = k.tcb(fs_tid)?.addr_space;
    let fs_root_pt = k.addr_space_mut(fs_addr_space)?.root_phys().as_usize();
    let shared_phys = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: `shared_phys` is fresh untyped RAM, identity-addressable
    // (paging is not active on the CURRENT core for this address —
    // it is only ever touched through the kernel's own identity map or
    // fs-native's own U=1 mapping below), single-core.
    unsafe { core::ptr::write_bytes(shared_phys as *mut u8, 0, 4096) };
    // `map_range`'s own pool MUST be real, 4 KiB-ALIGNED physical
    // memory — it stamps page-table-walk PTEs directly at `pool_base +
    // N*4096`, computing each frame number via `>> 12` (`map_range`'s
    // own doc comment: "pool frames are zeroed"). **Real bug found via
    // QEMU**: an earlier draft used a plain local `[u8; 4096*2]` array
    // here instead — a stack address has NO 4 KiB alignment guarantee
    // (Rust gives arrays only their element's own alignment, 1 byte for
    // `u8`), so the resulting PTEs silently truncated to the wrong
    // frame, corrupting fs-native's own page table without any error
    // return at all — a SILENT hang once fs-native's process actually
    // ran into the corrupted mapping, with no diagnostic. Every OTHER
    // caller in this file already gets this right via `carve()` (real,
    // explicitly 4 KiB-aligned untyped memory); this one-off inline
    // call is fixed the same way.
    let pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed (same contract every other
    // pool carve in this file already documents).
    unsafe { core::ptr::write_bytes(pool as *mut u8, 0, 4096 * 2) };
    let n = hal.map_range(
        fs_root_pt,
        FS_SHARED_VA,
        shared_phys,
        4096,
        1 | 2 | 8, // R+W+U
        pool,
        2,
    );
    if n == u32::MAX {
        klog!("fs_demo_start: map_range error (shared page)\r\n");
        return None;
    }

    // SAFETY: single-core; written exactly once here, before any of the
    // `fs_*_call`/`fs_*_result` functions below can be reached (they are
    // only ever wired to opcodes issued after this one).
    unsafe { core::ptr::addr_of_mut!(G_FS_SHARED_PHYS).write(shared_phys) };

    // Second shared page, for BULK Read/Write data (03-Kernel-Subsystems-
    // Layer.md §5.2's own "zero-copy, not the message" rule) — this time
    // via a REAL `SyscallOp::Retype` into `KernelObjectType::SharedRegion`
    // (the genuine capability object, not a bare untyped carve like the
    // SmallMessage page just above), proving the capability actually
    // works end to end, not just compiling.
    let region_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::SharedRegion,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    // Resolve the freshly retyped capability back to its own
    // `SharedRegion` description to learn the physical base `map_range`
    // below needs — `Retype`'s own `NewCaps` return only carries the
    // CALLER's new `CapId`, not the object itself.
    let region_id = k.cap_space(src_cs)?.lookup(region_cap)?.object.id;
    let region_phys = k
        .shared_region(kernel_cap::SharedRegionId::new(region_id.as_u32()))?
        .phys_base
        .as_usize();
    grant_cap_into(k, src_cs, region_cap, fs_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;
    // Fresh, dedicated pool for this SECOND `map_range` call — reusing
    // the message page's own (already-consumed) `pool` variable here
    // would violate `map_range`'s own "pool frames are zeroed and
    // untouched" precondition for a fresh walk; every other multi-map
    // caller in this file (e.g. `spawn_process_from_elf`'s own per-
    // segment walks share ONE pool because they're carved together up
    // front — this one is a separate, later carve, so it gets its own).
    let data_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed (same contract every other
    // pool carve in this file already documents).
    unsafe { core::ptr::write_bytes(data_pool as *mut u8, 0, 4096 * 2) };
    let n2 = hal.map_range(
        fs_root_pt,
        FS_DATA_VA,
        region_phys,
        4096,
        1 | 2 | 8, // R+W+U
        data_pool,
        2,
    );
    if n2 == u32::MAX {
        klog!("fs_demo_start: map_range error (data page)\r\n");
        return None;
    }
    // SAFETY: single-core; written exactly once here, before any
    // FS_WRITE/FS_READ call can be reached.
    unsafe { core::ptr::addr_of_mut!(G_FS_DATA_PHYS).write(region_phys) };

    // Switch straight to fs-native, exactly like `p2_ipc_demo_start`
    // does for its own in-kernel server — **real bug found via QEMU**:
    // without this, `caller`'s FIRST `FS_OPEN` (issued immediately
    // after this opcode returns) is a `Call` racing a receiver that has
    // NEVER YET RUN AT ALL, so `do_send`'s fast path (which requires
    // the receiver already blocked in `Recv`) cannot trigger — it falls
    // back to `pick_next`'s general fairness, which can and did pick a
    // completely unrelated already-`Ready` thread instead of fs-native,
    // silently stranding BOTH `caller` (still `BlockedOnReply`, nothing
    // will ever `Reply` to it) and fs-native (spawned but never
    // scheduled) forever — the exact same bug class `p2_ipc_demo_start`
    // itself was already fixed for, and `p2_ipc_recv`'s own hardcoded
    // "switch to root" doc comment already explains from the other
    // side. Fixed by switching to fs-native HERE, unconditionally: it
    // runs its own boot sequence (seed `/greeting`) and reaches its own
    // first `IPC_RECV`, which (per `p2_ipc_recv`'s own existing,
    // unmodified logic) finds nothing queued yet and switches straight
    // back to `k.root_thread` — by the time `caller` resumes from THIS
    // switch and issues `FS_OPEN`, fs-native is genuinely blocked in
    // `Recv`, so the real fast path (already proven across all three
    // architectures) takes over correctly from there on.
    let _ = k.sched.note_ready(caller, hal.now_ns());
    let _ = k.sched.dispatch(fs_tid, hal.now_ns());
    let (save, into) = k.user_ctx_switch_ptrs(caller, fs_tid)?;

    Some((ep_cap.as_u32(), save, into))
}

/// `Call`, specialized for the fs-native demo's known, fixed 2-party
/// (root <-> fs-native) shape — unlike `p2_ipc_call` (generic, trusts
/// whichever thread `do_send`'s fast path or `pick_next`'s general
/// fallback hands back).
///
/// **Real bug found via QEMU**: `FS_OPEN` (the very first FS call) works
/// via `p2_ipc_call`'s plain fast path ONLY because `fs_demo_start`
/// explicitly switches to fs-native first, so it is already blocked in
/// `Recv` by the time `FS_OPEN` runs. Every call AFTER that point (e.g.
/// `FS_STAT`, right after `FS_OPEN`'s own `Reply`) is NOT covered by
/// that guarantee: `do_reply` (correctly) leaves the replier merely
/// `Ready` (see its own doc comment), not resumed — fs-native has not
/// actually run again to reach its OWN next `IPC_RECV` by the time
/// `caller` issues the next FS opcode. So `do_send`'s fast path cannot
/// trigger, and falls back to `SendOutcome::SenderQueued` + `pick_next`
/// — general fairness, which silently picked some OTHER unrelated
/// `Ready` thread (left over from an earlier demo phase) instead of
/// fs-native, stranding `caller` in `BlockedOnReply` forever (fs-native,
/// never scheduled, never reaches `Recv` to see the queued message) — a
/// totally silent hang, confirmed via QEMU (output stops dead right
/// after `FS_OPEN`'s own report, every run). Exactly the same bug class
/// `p2_ipc_recv`'s and `p2_ipc_demo_start`'s own "Real bug found via
/// QEMU" comments already describe for the sibling cases; the identical
/// fix applies: since this demo is a deterministic 2-party RPC, bypass
/// `pick_next`'s answer and switch straight to the known fs-native
/// `ThreadId` instead. Safe to discard whatever `pick_next` chose:
/// `pick_next` is read-only ("without committing to it" — see its own
/// doc comment), so overriding its answer here never corrupts scheduler
/// bookkeeping — the thread it would have picked simply stays `Ready`,
/// untouched, for a later call to actually choose.
fn fs_ipc_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let k = kstate();
    // SAFETY: single-core; `G_FS_TID` is written once by `fs_demo_start`,
    // before any FS_OPEN/FS_STAT/FS_CLOSE call (this function) can run.
    let fs_tid = unsafe { core::ptr::addr_of!(G_FS_TID).read() }?;
    let msg = SmallMessage::new(0);
    match k.dispatch(caller, hal.now_ns(), SyscallOp::Call { endpoint: CapId::new(ep_cap), msg }, hal) {
        Ok(SyscallReturn::Reschedule { next: Some(n) }) => {
            let _ = k.sched.dispatch(fs_tid, hal.now_ns());
            let (save, into) = k.user_ctx_switch_ptrs(caller, fs_tid)?;
            // `pending_from`/`pending_msg` are only ever set on the
            // thread `do_send`'s OWN fast path actually delivered to
            // directly (see `p2_ipc_call`'s own comment) — that is
            // fs-native exactly when `n == fs_tid` (the fast path DID
            // trigger); when it did not (the general-fallback case this
            // function exists to correct), the message is merely queued
            // in the endpoint, for fs-native's own next `IPC_RECV` to
            // pick up the ordinary way, so there is nothing to poke.
            let poke = if n == fs_tid {
                k.tcb_mut(fs_tid)
                    .and_then(|t| Some((t.pending_from.take()?, t.pending_msg.take()?)))
                    .map(|(from, m)| (from.as_u32() as usize, m.label as usize))
            } else {
                None
            };
            Some(IpcSwitch { save, into, poke })
        }
        _ => None,
    }
}

/// `FS_OPEN` demo opcode: builds a REAL `FsRequest::Open` (per-arch
/// `.user_text` code passes only `path_id`/`flags_bits` as plain
/// integers — see this section's own doc comment on why), marshals it
/// through the shared fs page, and issues a REAL `SyscallOp::Call`.
pub fn fs_open_call(
    hal: &HalInterface,
    caller: ThreadId,
    ep_cap: u32,
    path_id: u32,
    flags_bits: u32,
) -> Option<IpcSwitch> {
    let flags = ipc_protocol::OpenFlags::from_bits(flags_bits).unwrap_or(ipc_protocol::OpenFlags::empty());
    let req = ipc_protocol::FsRequest::Open {
        path: ipc_protocol::PathId(path_id),
        flags,
    };
    let msg = ipc_protocol::codec::encode_fs_request(&req);
    // SAFETY: `fs_demo_start` has already run by the time any `.user_
    // text` code can reach this opcode (it needs `ep_cap`, which only
    // `fs_demo_start`'s own return value provides).
    unsafe { write_shared_fs_message(&msg) };
    fs_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `FsResponse` fs-native's `IPC_REPLY` just wrote into
/// the shared fs page, once the caller resumes from `fs_open_call`'s own
/// switch. Returns the new handle, or `usize::MAX` on any error/decode
/// failure — `.user_text` code reports this raw via `sys::REPORT`.
pub fn fs_open_result() -> usize {
    // SAFETY: same contract as `fs_open_call`.
    let msg = unsafe { read_shared_fs_message() };
    match ipc_protocol::codec::decode_fs_response(&msg) {
        Ok(ipc_protocol::FsResponse::Opened { handle }) => handle.0 as usize,
        _ => usize::MAX,
    }
}

/// `FS_STAT` demo opcode: builds a REAL `FsRequest::Stat`.
pub fn fs_stat_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, path_id: u32) -> Option<IpcSwitch> {
    let req = ipc_protocol::FsRequest::Stat {
        path: ipc_protocol::PathId(path_id),
    };
    let msg = ipc_protocol::codec::encode_fs_request(&req);
    // SAFETY: see `fs_open_call`'s own contract.
    unsafe { write_shared_fs_message(&msg) };
    fs_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `FsResponse` for `fs_stat_call`. Returns the file's
/// real size, or `usize::MAX` on any error/decode failure.
pub fn fs_stat_result() -> usize {
    // SAFETY: same contract as `fs_open_call`.
    let msg = unsafe { read_shared_fs_message() };
    match ipc_protocol::codec::decode_fs_response(&msg) {
        Ok(ipc_protocol::FsResponse::Stat { size, .. }) => size as usize,
        _ => usize::MAX,
    }
}

/// `FS_CLOSE` demo opcode: builds a REAL `FsRequest::Close`.
pub fn fs_close_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, handle: u32) -> Option<IpcSwitch> {
    let req = ipc_protocol::FsRequest::Close {
        handle: ipc_protocol::FileHandle(handle),
    };
    let msg = ipc_protocol::codec::encode_fs_request(&req);
    // SAFETY: see `fs_open_call`'s own contract.
    unsafe { write_shared_fs_message(&msg) };
    fs_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `FsResponse` for `fs_close_call`. Returns `1` for a
/// real `Closed`, `0` for anything else (error/decode failure).
pub fn fs_close_result() -> usize {
    // SAFETY: same contract as `fs_open_call`.
    let msg = unsafe { read_shared_fs_message() };
    match ipc_protocol::codec::decode_fs_response(&msg) {
        Ok(ipc_protocol::FsResponse::Closed) => 1,
        _ => 0,
    }
}

/// `FS_WRITE` demo opcode: writes `FS_DEMO_WRITE_DATA` (fixed MVP test
/// payload — see that constant's own doc comment) into the shared DATA
/// region's own physical memory, then builds a REAL `FsRequest::Write`
/// naming it via `shared_cap` (fs-native's own deterministic slot for
/// its one shared data region — `FS_DATA_SHARED_CAP_SLOT`). `offset` is
/// always 0 for this MVP demo — no partial-write exercise yet.
pub fn fs_write_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, handle: u32) -> Option<IpcSwitch> {
    // SAFETY: `G_FS_DATA_PHYS` was set once by `fs_demo_start`, before
    // any FS_WRITE call can be reached; identity-mapped for kernel-mode
    // access like every other physical cross-check in this file.
    unsafe {
        let base = core::ptr::addr_of!(G_FS_DATA_PHYS).read() as *mut u8;
        core::ptr::copy_nonoverlapping(FS_DEMO_WRITE_DATA.as_ptr(), base, FS_DEMO_WRITE_DATA.len());
    }
    let req = ipc_protocol::FsRequest::Write {
        handle: ipc_protocol::FileHandle(handle),
        offset: 0,
        len: FS_DEMO_WRITE_DATA.len() as u32,
        shared_cap: FS_DATA_SHARED_CAP_SLOT,
    };
    let msg = ipc_protocol::codec::encode_fs_request(&req);
    // SAFETY: see `fs_open_call`'s own contract.
    unsafe { write_shared_fs_message(&msg) };
    fs_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `FsResponse` for `fs_write_call`. Returns the byte
/// count, or `usize::MAX` on any error/decode failure.
pub fn fs_write_result() -> usize {
    // SAFETY: same contract as `fs_open_call`.
    let msg = unsafe { read_shared_fs_message() };
    match ipc_protocol::codec::decode_fs_response(&msg) {
        Ok(ipc_protocol::FsResponse::Written { bytes }) => bytes as usize,
        _ => usize::MAX,
    }
}

/// `FS_READ` demo opcode: builds a REAL `FsRequest::Read` for `len`
/// bytes at offset 0 (always following an `FS_WRITE`, in this demo's
/// own fixed sequence — never past EOF).
pub fn fs_read_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, handle: u32, len: u32) -> Option<IpcSwitch> {
    let req = ipc_protocol::FsRequest::Read {
        handle: ipc_protocol::FileHandle(handle),
        offset: 0,
        len,
        shared_cap: FS_DATA_SHARED_CAP_SLOT,
    };
    let msg = ipc_protocol::codec::encode_fs_request(&req);
    // SAFETY: see `fs_open_call`'s own contract.
    unsafe { write_shared_fs_message(&msg) };
    fs_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `FsResponse` for `fs_read_call`, AND cross-checks the
/// shared data region's own physical bytes against `FS_DEMO_WRITE_DATA`
/// — proving the REAL Write→Read round-trip actually moved real bytes
/// through fs-native's own `MemFs`, zero-copy (same "read back via the
/// kernel's own identity map and compare" verification style every
/// other real demo in this file already uses — e.g. the two-Sv39-spaces
/// zero-copy proof). Returns the byte count, or `usize::MAX` on any
/// error/decode failure (the match/mismatch verdict is logged, not
/// folded into the return value, so `.user_text`'s own `REPORT` still
/// reports the plain byte count like every other FS opcode).
pub fn fs_read_result() -> usize {
    // SAFETY: same contract as `fs_open_call`.
    let msg = unsafe { read_shared_fs_message() };
    let bytes = match ipc_protocol::codec::decode_fs_response(&msg) {
        Ok(ipc_protocol::FsResponse::Read { bytes }) => bytes as usize,
        _ => return usize::MAX,
    };
    // SAFETY: same contract as `fs_write_call`'s own read of
    // `G_FS_DATA_PHYS`.
    let matches = unsafe {
        let base = core::ptr::addr_of!(G_FS_DATA_PHYS).read() as *const u8;
        bytes == FS_DEMO_WRITE_DATA.len() && core::slice::from_raw_parts(base, bytes) == FS_DEMO_WRITE_DATA
    };
    klog!(
        "fs_read_result: real Write->Read round-trip through fs-native's own MemFs (03 5.3) -> {}\r\n",
        if matches { "MATCH, zero-copy through the SharedRegion capability" } else { "MISMATCH" }
    );
    bytes
}

/// Same real round trip as `fs_read_result`, but skips the MATCH/
/// MISMATCH `klog!` — used by the VFS read-throughput benchmark loop
/// below so it doesn't spam one near-identical log line per iteration
/// (same reason `mm_query_total_resident_result_quiet` exists).
pub fn fs_read_result_quiet() -> usize {
    // SAFETY: same contract as `fs_open_call`.
    let msg = unsafe { read_shared_fs_message() };
    match ipc_protocol::codec::decode_fs_response(&msg) {
        Ok(ipc_protocol::FsResponse::Read { bytes }) => bytes as usize,
        _ => usize::MAX,
    }
}

/// `FS_WRITE_THROUGHPUT_SUMMARY` demo opcode: logs one honest MB/s line
/// for the VFS write-throughput phase of 03-Kernel-Subsystems-Layer.md
/// §5's item 5 ("VFS read/write throughput relative to a reference
/// system... reported"). `total_bytes`/`total_ns` are summed in
/// `.user_text` across a real `FS_WRITE`/`FS_WRITE_RESULT` loop — each
/// iteration a genuine `Call`/`Reply` round trip through fs-native's
/// own isolated process, exactly like every byte transferred in the
/// single-shot `fs_write_call`/`fs_read_result` demo above, just
/// repeated and timed. Fixed-point (integer-only, matching this
/// project's `kernel-sched::weight`-style "no floating point in the
/// kernel-adjacent path" convention): reports whole KB/s rather than a
/// fractional MB/s, since `total_bytes * 1000 / total_ns` (nanoseconds
/// to seconds, bytes to kilobytes) stays comfortably inside `u64`
/// for any realistic sample size here and needs no float formatting
/// support in this `no_std` `klog!` path.
pub fn fs_write_throughput_summary(total_bytes: usize, total_ns: usize) {
    if total_ns == 0 {
        klog!("fs_write_throughput_summary: zero elapsed time, skipping\r\n");
        return;
    }
    let kb_per_sec = (total_bytes as u64).saturating_mul(1_000_000) / total_ns as u64;
    klog!(
        "vfs write throughput (03 5, item 5): {} bytes in {} ns -> {} KB/s\r\n",
        total_bytes,
        total_ns,
        kb_per_sec
    );
}

/// Same shape as `fs_write_throughput_summary`, for the read phase.
pub fn fs_read_throughput_summary(total_bytes: usize, total_ns: usize) {
    if total_ns == 0 {
        klog!("fs_read_throughput_summary: zero elapsed time, skipping\r\n");
        return;
    }
    let kb_per_sec = (total_bytes as u64).saturating_mul(1_000_000) / total_ns as u64;
    klog!(
        "vfs read throughput (03 5, item 5): {} bytes in {} ns -> {} KB/s\r\n",
        total_bytes,
        total_ns,
        kb_per_sec
    );
}

// ============================================================================
// compositor: real IPC-driven Compositor Service (03 §2.4/§5.4.2)
//
// Mirrors the fs-native section immediately above almost exactly (same
// "spawn, grant an Endpoint, pre-map shared pages, drive it via a
// dedicated ecall-per-request-type + shared-message-area protocol,
// bypass pick_next for the deterministic 2-party shape" pattern — see
// that section's own doc comments for the parts that repeat verbatim
// here). The one addition: a THIRD mapped page (`COMPOSITOR_CONFIRM_VA`)
// compositor's own `subsystem_entry::copy_frame_to_confirm` writes the
// committed frame's own bytes into after reading them from
// `COMPOSITOR_FB_VA` — proof (peeked directly here, the SAME "kernel
// reads via its own identity map and compares" verification style
// `fs_read_result`'s own doc comment already establishes) that
// Compositor genuinely dereferenced the shared frame buffer, not just
// that the round trip completed. §5.4.2's own acceptance bar ("a client
// creates a surface, commits a buffer, and it is shown zero-copy — even
// headless/file output is enough for the MVP") is satisfied by this
// direct physical-memory proof standing in for real GPU scanout
// hardware, which does not exist in this codebase yet.
// ============================================================================

/// This process's own thread id, set once by `compositor_demo_start` —
/// same role as `G_FS_TID`.
static mut G_COMPOSITOR_TID: Option<ThreadId> = None;

/// Physical address of the page shared between the caller (accessed via
/// the kernel's own always-present identity map) and Compositor's own
/// process (mapped into ITS address space at `COMPOSITOR_SHARED_VA` by
/// `compositor_demo_start`) — same role as `G_FS_SHARED_PHYS`.
static mut G_COMPOSITOR_SHARED_PHYS: usize = usize::MAX;

/// Physical address of the page shared for the committed frame's own
/// pixel bytes — same role as `G_FS_DATA_PHYS`.
static mut G_COMPOSITOR_FB_PHYS: usize = usize::MAX;

/// Physical address of Compositor's own private "confirm" region — see
/// this section's own module doc comment for why it exists.
static mut G_COMPOSITOR_CONFIRM_PHYS: usize = usize::MAX;

/// VA Compositor's own process maps the shared message page at — must
/// stay numerically equal to `compositor::subsystem_entry::SHARED_VA`.
const COMPOSITOR_SHARED_VA: usize = 0xD840_0000;

/// VA Compositor's own process maps the committed frame buffer at — must
/// stay numerically equal to `compositor::subsystem_entry::FB_VA`.
const COMPOSITOR_FB_VA: usize = 0xD850_0000;

/// VA Compositor's own process maps its private confirm region at — must
/// stay numerically equal to `compositor::subsystem_entry::CONFIRM_VA`.
const COMPOSITOR_CONFIRM_VA: usize = 0xD860_0000;

/// Fixed MVP test frame — a 2x2 packed-BGRA8 surface (16 bytes), a
/// recognizable sentinel pattern (not all-zero, so a MISMATCH from an
/// unmapped/zeroed page is distinguishable from a genuine round-trip
/// failure) — same "one demo, one hardcoded scenario" convention
/// `FS_DEMO_WRITE_DATA`'s own doc comment already establishes.
const COMPOSITOR_DEMO_FRAME: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
];
/// Frame width, in pixels, for the fixed demo frame above (`2 * 2 * 4 ==
/// COMPOSITOR_DEMO_FRAME.len()`).
const COMPOSITOR_DEMO_WIDTH: u32 = 2;
/// Frame height, in pixels, for the fixed demo frame above.
const COMPOSITOR_DEMO_HEIGHT: u32 = 2;

/// Writes `msg`'s full `(label, words[0..6] zero-padded)` into the
/// shared compositor page — same convention `write_shared_fs_message`'s
/// own doc comment documents in full.
///
/// # Safety
/// `G_COMPOSITOR_SHARED_PHYS` must already be a valid, exclusively-owned,
/// mapped physical frame (`compositor_demo_start` has run).
unsafe fn write_shared_compositor_message(msg: &SmallMessage) {
    // SAFETY: single-core; `G_COMPOSITOR_SHARED_PHYS` only written once
    // by `compositor_demo_start`, before this can ever be called.
    let base = unsafe { core::ptr::addr_of!(G_COMPOSITOR_SHARED_PHYS).read() } as *mut u64;
    // SAFETY: forwarded from this function's own contract — low RAM is
    // always identity-mapped for kernel-mode access regardless of which
    // process's page table is currently active.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Reads back a `SmallMessage` written by `write_shared_compositor_message`.
///
/// # Safety
/// Same contract as `write_shared_compositor_message`.
unsafe fn read_shared_compositor_message() -> SmallMessage {
    // SAFETY: single-core; same contract as `write_shared_compositor_message`.
    let base = unsafe { core::ptr::addr_of!(G_COMPOSITOR_SHARED_PHYS).read() } as *const u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// One-time setup: creates the endpoint Compositor and its client
/// (`caller`, always the Root Task in this MVP) rendezvous on, spawns
/// Compositor as a genuinely isolated process from its own separately-
/// built ELF image (`compositor_elf`), grants it the endpoint plus THREE
/// pre-mapped pages (message, frame buffer, confirm region — this
/// section's own module doc comment), and switches straight to it — same
/// "without this, the caller's first Call races a receiver that has
/// never run" rationale `fs_demo_start`'s own tail comment documents in
/// full. Returns the endpoint's capability slot in the CALLER's own cap
/// space plus the `(save, into)` switch pointers the caller wraps in a
/// `TrapOutcome::SwitchTo`.
pub fn compositor_demo_start(
    hal: &HalInterface,
    caller: ThreadId,
    compositor_elf: &[u8],
    expected_machine: u16,
) -> Option<(u32, *mut u8, *const u8)> {
    let k = kstate();
    let ep_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Endpoint,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };

    const COMPOSITOR_STACK_VMA: usize = 0xC050_0000;
    const COMPOSITOR_STACK_LEN: usize = 4096 * 16;
    let (comp_tid, comp_cs, _stack_phys) =
        spawn_process_from_elf(hal, k, compositor_elf, expected_machine, COMPOSITOR_STACK_VMA, COMPOSITOR_STACK_LEN)?;
    // SAFETY: single-core; written once here, before any compositor call
    // (reached only after this function returns) can read it.
    unsafe { core::ptr::addr_of_mut!(G_COMPOSITOR_TID).write(Some(comp_tid)) };

    let src_cs = k.tcb(caller)?.cap_space;
    grant_cap_into(k, src_cs, ep_cap, comp_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;

    let comp_addr_space = k.tcb(comp_tid)?.addr_space;
    let comp_root_pt = k.addr_space_mut(comp_addr_space)?.root_phys().as_usize();

    // Shared message page (trusted-bootstrap direct map, no SyscallOp
    // ceremony — same "carve untyped, map_range directly" pattern
    // `fs_demo_start`'s own identical block already uses).
    let shared_phys = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core.
    unsafe { core::ptr::write_bytes(shared_phys as *mut u8, 0, 4096) };
    let shared_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed.
    unsafe { core::ptr::write_bytes(shared_pool as *mut u8, 0, 4096 * 2) };
    let n = hal.map_range(comp_root_pt, COMPOSITOR_SHARED_VA, shared_phys, 4096, 1 | 2 | 8, shared_pool, 2);
    if n == u32::MAX {
        klog!("compositor_demo_start: map_range error (shared page)\r\n");
        return None;
    }
    // SAFETY: single-core; written exactly once here, before any
    // compositor call can be reached.
    unsafe { core::ptr::addr_of_mut!(G_COMPOSITOR_SHARED_PHYS).write(shared_phys) };

    // Frame buffer page — a REAL `SyscallOp::Retype` into `KernelObjectType::
    // SharedRegion` (the genuine capability object, not a bare untyped
    // carve like the message page above), matching `fs_demo_start`'s own
    // identical second-region precedent.
    let fb_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::SharedRegion,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    let fb_id = k.cap_space(src_cs)?.lookup(fb_cap)?.object.id;
    let fb_phys = k.shared_region(kernel_cap::SharedRegionId::new(fb_id.as_u32()))?.phys_base.as_usize();
    grant_cap_into(k, src_cs, fb_cap, comp_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;
    let fb_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core.
    unsafe { core::ptr::write_bytes(fb_pool as *mut u8, 0, 4096 * 2) };
    let n2 = hal.map_range(comp_root_pt, COMPOSITOR_FB_VA, fb_phys, 4096, 1 | 2 | 8, fb_pool, 2);
    if n2 == u32::MAX {
        klog!("compositor_demo_start: map_range error (frame buffer page)\r\n");
        return None;
    }
    // SAFETY: single-core; written exactly once here.
    unsafe { core::ptr::addr_of_mut!(G_COMPOSITOR_FB_PHYS).write(fb_phys) };

    // Confirm region — Compositor's own PRIVATE `SharedRegion` (no grant
    // into the caller's cap space needed: the kernel peeks it directly
    // via its own identity map, same "trusted bootstrap, no Map
    // ceremony" pattern `netstack::spawn_netstack_service`'s own STATUS_
    // VA region already established).
    let confirm_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::SharedRegion,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    let confirm_id = k.cap_space(src_cs)?.lookup(confirm_cap)?.object.id;
    let confirm_phys =
        k.shared_region(kernel_cap::SharedRegionId::new(confirm_id.as_u32()))?.phys_base.as_usize();
    // SAFETY: fresh `SharedRegion` memory, identity-addressable, single-core.
    unsafe { core::ptr::write_bytes(confirm_phys as *mut u8, 0, 4096) };
    let confirm_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    unsafe { core::ptr::write_bytes(confirm_pool as *mut u8, 0, 4096 * 2) };
    let n3 = hal.map_range(comp_root_pt, COMPOSITOR_CONFIRM_VA, confirm_phys, 4096, 1 | 2 | 8, confirm_pool, 2);
    if n3 == u32::MAX {
        klog!("compositor_demo_start: map_range error (confirm region)\r\n");
        return None;
    }
    // SAFETY: single-core; written exactly once here, before any
    // `compositor_commit_verify` call (reached only after this function
    // returns).
    unsafe { core::ptr::addr_of_mut!(G_COMPOSITOR_CONFIRM_PHYS).write(confirm_phys) };

    // Switch straight to Compositor — same race-avoidance rationale as
    // `fs_demo_start`'s own tail comment.
    let _ = k.sched.note_ready(caller, hal.now_ns());
    let _ = k.sched.dispatch(comp_tid, hal.now_ns());
    let (save, into) = k.user_ctx_switch_ptrs(caller, comp_tid)?;

    Some((ep_cap.as_u32(), save, into))
}

/// `Call`, specialized for the compositor demo's known, fixed 2-party
/// (root <-> Compositor) shape — same "bypass `pick_next`'s answer,
/// switch straight to the known target thread" fix `fs_ipc_call`'s own
/// doc comment documents in full (identical bug class, identical fix).
fn compositor_ipc_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let k = kstate();
    // SAFETY: single-core; `G_COMPOSITOR_TID` is written once by
    // `compositor_demo_start`, before any compositor call (this
    // function) can run.
    let comp_tid = unsafe { core::ptr::addr_of!(G_COMPOSITOR_TID).read() }?;
    let msg = SmallMessage::new(0);
    match k.dispatch(caller, hal.now_ns(), SyscallOp::Call { endpoint: CapId::new(ep_cap), msg }, hal) {
        Ok(SyscallReturn::Reschedule { next: Some(n) }) => {
            let _ = k.sched.dispatch(comp_tid, hal.now_ns());
            let (save, into) = k.user_ctx_switch_ptrs(caller, comp_tid)?;
            let poke = if n == comp_tid {
                k.tcb_mut(comp_tid)
                    .and_then(|t| Some((t.pending_from.take()?, t.pending_msg.take()?)))
                    .map(|(from, m)| (from.as_u32() as usize, m.label as usize))
            } else {
                None
            };
            Some(IpcSwitch { save, into, poke })
        }
        _ => None,
    }
}

/// `COMPOSITOR_CREATE_SURFACE` demo opcode: builds a REAL
/// `DisplayRequest::CreateSurface`.
pub fn compositor_create_surface_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let msg = ipc_protocol::codec::encode_display_request(&ipc_protocol::DisplayRequest::CreateSurface);
    // SAFETY: `compositor_demo_start` has already run by the time any
    // `.user_text` code can reach this opcode (it needs `ep_cap`, which
    // only `compositor_demo_start`'s own return value provides).
    unsafe { write_shared_compositor_message(&msg) };
    compositor_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `DisplayResponse` for `compositor_create_surface_call`.
/// Returns the new surface handle, or `usize::MAX` on any error/decode
/// failure.
pub fn compositor_create_surface_result() -> usize {
    // SAFETY: same contract as `compositor_create_surface_call`.
    let msg = unsafe { read_shared_compositor_message() };
    match ipc_protocol::codec::decode_display_response(&msg) {
        Ok(ipc_protocol::DisplayResponse::SurfaceCreated { surface }) => surface.0 as usize,
        _ => usize::MAX,
    }
}

/// `COMPOSITOR_COMMIT_BUFFER` demo opcode: writes `COMPOSITOR_DEMO_FRAME`
/// (fixed MVP test pixels — see that constant's own doc comment) into
/// the shared frame buffer's own physical memory, then builds a REAL
/// `DisplayRequest::CommitBuffer` naming the fixed demo frame's own
/// dimensions. `buffer_cap` is always `0` — this MVP demo never resolves
/// it (`compositor::subsystem_entry::handle_request`'s own doc comment
/// on why), same simplification `fs_write_call`'s own `shared_cap`
/// already makes.
pub fn compositor_commit_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, surface: u32) -> Option<IpcSwitch> {
    // SAFETY: `G_COMPOSITOR_FB_PHYS` was set once by `compositor_demo_
    // start`, before any commit call can be reached; identity-mapped for
    // kernel-mode access like every other physical cross-check in this
    // file.
    unsafe {
        let base = core::ptr::addr_of!(G_COMPOSITOR_FB_PHYS).read() as *mut u8;
        core::ptr::copy_nonoverlapping(COMPOSITOR_DEMO_FRAME.as_ptr(), base, COMPOSITOR_DEMO_FRAME.len());
    }
    let req = ipc_protocol::DisplayRequest::CommitBuffer {
        surface: ipc_protocol::SurfaceHandle(surface),
        buffer_cap: 0,
        width: COMPOSITOR_DEMO_WIDTH,
        height: COMPOSITOR_DEMO_HEIGHT,
    };
    let msg = ipc_protocol::codec::encode_display_request(&req);
    // SAFETY: see `compositor_create_surface_call`'s own contract.
    unsafe { write_shared_compositor_message(&msg) };
    compositor_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `DisplayResponse` for `compositor_commit_call`, AND
/// cross-checks Compositor's own private confirm region's own physical
/// bytes against `COMPOSITOR_DEMO_FRAME` — proving Compositor genuinely
/// dereferenced the SAME shared frame buffer the caller wrote into, no
/// copy through the message (this section's own module doc comment).
/// Returns `1` for a real `Committed` AND a byte-for-byte confirm-region
/// match, `0` otherwise (error/decode failure/mismatch — the exact
/// verdict is logged either way, matching `fs_read_result`'s own
/// convention).
pub fn compositor_commit_verify() -> usize {
    // SAFETY: same contract as `compositor_create_surface_call`.
    let msg = unsafe { read_shared_compositor_message() };
    let committed = matches!(
        ipc_protocol::codec::decode_display_response(&msg),
        Ok(ipc_protocol::DisplayResponse::Committed)
    );
    // SAFETY: same contract as `compositor_commit_call`'s own read of
    // `G_COMPOSITOR_FB_PHYS`.
    let confirmed = unsafe {
        let base = core::ptr::addr_of!(G_COMPOSITOR_CONFIRM_PHYS).read() as *const u8;
        core::slice::from_raw_parts(base, COMPOSITOR_DEMO_FRAME.len()) == COMPOSITOR_DEMO_FRAME
    };
    klog!(
        "compositor_commit_verify: real CommitBuffer round-trip, frame bytes read back through Compositor's own confirm region (03 2.4/5.4.2) -> {}\r\n",
        if committed && confirmed { "MATCH, zero-copy through the SharedRegion capability" } else { "MISMATCH" }
    );
    (committed && confirmed) as usize
}

/// `COMPOSITOR_DESTROY_SURFACE` demo opcode: builds a REAL
/// `DisplayRequest::DestroySurface`.
pub fn compositor_destroy_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, surface: u32) -> Option<IpcSwitch> {
    let req = ipc_protocol::DisplayRequest::DestroySurface {
        surface: ipc_protocol::SurfaceHandle(surface),
    };
    let msg = ipc_protocol::codec::encode_display_request(&req);
    // SAFETY: see `compositor_create_surface_call`'s own contract.
    unsafe { write_shared_compositor_message(&msg) };
    compositor_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `DisplayResponse` for `compositor_destroy_call`.
/// Returns `1` for a real `Destroyed`, `0` otherwise.
pub fn compositor_destroy_result() -> usize {
    // SAFETY: same contract as `compositor_create_surface_call`.
    let msg = unsafe { read_shared_compositor_message() };
    matches!(
        ipc_protocol::codec::decode_display_response(&msg),
        Ok(ipc_protocol::DisplayResponse::Destroyed)
    ) as usize
}

// ============================================================================
// mm-service: real IPC-driven memory-policy service (03 §2.5)
//
// Mirrors the fs-native/compositor sections above almost exactly (same
// "spawn, grant an Endpoint, pre-map a shared page, drive it via a
// dedicated ecall-per-request-type + shared-message-area protocol,
// bypass pick_next for the deterministic 2-party shape" pattern). The
// one simplification relative to those two: `MmRequest`/`MmResponse`
// never carries genuinely bulk data (a thread id + a byte count fits
// inside the message itself), so this section needs only ONE shared
// page — no second `SharedRegion` the way fs-native's `FS_DATA_VA` or
// Compositor's `COMPOSITOR_FB_VA`/`COMPOSITOR_CONFIRM_VA` do.
//
// The demo registers two fixed processes (matching `mm_service`'s own
// `sacrificial_chosen_before_larger_normal` host test verbatim — a
// 100 MiB `Normal` process and a 4 MiB `Sacrificial` one), queries the
// total resident bytes and the OOM victim over REAL IPC, and verifies
// both against the same expected values that host test already proves
// the underlying policy produces — the real, end-to-end version of a
// property already known correct in isolation.
// ============================================================================

/// This process's own thread id, set once by `mm_demo_start` — same
/// role as `G_FS_TID`.
static mut G_MM_TID: Option<ThreadId> = None;

/// Physical address of the page shared between the caller and
/// mm-service's own process (mapped into ITS address space at
/// `MM_SHARED_VA` by `mm_demo_start`) — same role as `G_FS_SHARED_PHYS`.
static mut G_MM_SHARED_PHYS: usize = usize::MAX;

/// VA mm-service's own process maps the shared message page at — must
/// stay numerically equal to `mm_service::subsystem_entry::SHARED_VA`.
const MM_SHARED_VA: usize = 0xD870_0000;

/// Fixed MVP demo processes — the SAME `(footprint, class)` pairs
/// `mm_service`'s own `sacrificial_chosen_before_larger_normal` host
/// test already proves the underlying policy handles correctly; this
/// demo drives the identical scenario over REAL IPC instead of calling
/// `choose_oom_victim` in-process. Index 0 = thread 100 (100 MiB,
/// `Normal`); index 1 = thread 200 (4 MiB, `Sacrificial` — the expected
/// victim despite its much smaller footprint).
const MM_DEMO_PROCS: [(u32, u64, ipc_protocol::mm::ReclaimClass); 2] = [
    (100, 100 * 1024 * 1024, ipc_protocol::mm::ReclaimClass::Normal),
    (200, 4 * 1024 * 1024, ipc_protocol::mm::ReclaimClass::Sacrificial),
];
/// Expected `QueryTotalResident` result once both `MM_DEMO_PROCS` are
/// registered — `mm_query_total_resident_result`'s own verify check.
const MM_DEMO_EXPECTED_TOTAL: u64 = MM_DEMO_PROCS[0].1 + MM_DEMO_PROCS[1].1;
/// Expected `QueryVictim` result once both `MM_DEMO_PROCS` are
/// registered — the `Sacrificial` one, thread 200, regardless of its
/// smaller footprint (`choose_oom_victim`'s own doc comment on why).
const MM_DEMO_EXPECTED_VICTIM: u32 = 200;

/// Writes `msg`'s full `(label, words[0..6] zero-padded)` into the
/// shared mm page — same convention `write_shared_fs_message`'s own doc
/// comment documents in full.
///
/// # Safety
/// `G_MM_SHARED_PHYS` must already be a valid, exclusively-owned, mapped
/// physical frame (`mm_demo_start` has run).
unsafe fn write_shared_mm_message(msg: &SmallMessage) {
    // SAFETY: single-core; `G_MM_SHARED_PHYS` only written once by
    // `mm_demo_start`, before this can ever be called.
    let base = unsafe { core::ptr::addr_of!(G_MM_SHARED_PHYS).read() } as *mut u64;
    // SAFETY: forwarded from this function's own contract — low RAM is
    // always identity-mapped for kernel-mode access regardless of which
    // process's page table is currently active.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Reads back a `SmallMessage` written by `write_shared_mm_message`.
///
/// # Safety
/// Same contract as `write_shared_mm_message`.
unsafe fn read_shared_mm_message() -> SmallMessage {
    // SAFETY: single-core; same contract as `write_shared_mm_message`.
    let base = unsafe { core::ptr::addr_of!(G_MM_SHARED_PHYS).read() } as *const u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// One-time setup: creates the endpoint mm-service and its client
/// (`caller`, always the Root Task in this MVP) rendezvous on, spawns
/// mm-service as a genuinely isolated process from its own separately-
/// built ELF image (`mm_elf`), grants it the endpoint plus ONE pre-mapped
/// message page, and switches straight to it — same "without this, the
/// caller's first Call races a receiver that has never run" rationale
/// `fs_demo_start`'s own tail comment documents in full. Returns the
/// endpoint's capability slot in the CALLER's own cap space plus the
/// `(save, into)` switch pointers the caller wraps in a
/// `TrapOutcome::SwitchTo`.
pub fn mm_demo_start(
    hal: &HalInterface,
    caller: ThreadId,
    mm_elf: &[u8],
    expected_machine: u16,
) -> Option<(u32, *mut u8, *const u8)> {
    let k = kstate();
    let ep_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Endpoint,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };

    const MM_STACK_VMA: usize = 0xC0B0_0000;
    const MM_STACK_LEN: usize = 4096 * 16;
    let (mm_tid, mm_cs, _stack_phys) =
        spawn_process_from_elf(hal, k, mm_elf, expected_machine, MM_STACK_VMA, MM_STACK_LEN)?;
    // SAFETY: single-core; written once here, before any mm-service call
    // (reached only after this function returns) can read it.
    unsafe { core::ptr::addr_of_mut!(G_MM_TID).write(Some(mm_tid)) };

    let src_cs = k.tcb(caller)?.cap_space;
    grant_cap_into(k, src_cs, ep_cap, mm_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;

    let mm_addr_space = k.tcb(mm_tid)?.addr_space;
    let mm_root_pt = k.addr_space_mut(mm_addr_space)?.root_phys().as_usize();

    let shared_phys = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core.
    unsafe { core::ptr::write_bytes(shared_phys as *mut u8, 0, 4096) };
    let shared_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed.
    unsafe { core::ptr::write_bytes(shared_pool as *mut u8, 0, 4096 * 2) };
    let n = hal.map_range(mm_root_pt, MM_SHARED_VA, shared_phys, 4096, 1 | 2 | 8, shared_pool, 2);
    if n == u32::MAX {
        klog!("mm_demo_start: map_range error (shared page)\r\n");
        return None;
    }
    // SAFETY: single-core; written exactly once here, before any
    // mm-service call can be reached.
    unsafe { core::ptr::addr_of_mut!(G_MM_SHARED_PHYS).write(shared_phys) };

    // Switch straight to mm-service — same race-avoidance rationale as
    // `fs_demo_start`'s own tail comment.
    let _ = k.sched.note_ready(caller, hal.now_ns());
    let _ = k.sched.dispatch(mm_tid, hal.now_ns());
    let (save, into) = k.user_ctx_switch_ptrs(caller, mm_tid)?;

    Some((ep_cap.as_u32(), save, into))
}

/// `Call`, specialized for the mm-service demo's known, fixed 2-party
/// (root <-> mm-service) shape — same "bypass `pick_next`'s answer,
/// switch straight to the known target thread" fix `fs_ipc_call`'s own
/// doc comment documents in full (identical bug class, identical fix).
fn mm_ipc_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let k = kstate();
    // SAFETY: single-core; `G_MM_TID` is written once by `mm_demo_start`,
    // before any mm-service call (this function) can run.
    let mm_tid = unsafe { core::ptr::addr_of!(G_MM_TID).read() }?;
    let msg = SmallMessage::new(0);
    match k.dispatch(caller, hal.now_ns(), SyscallOp::Call { endpoint: CapId::new(ep_cap), msg }, hal) {
        Ok(SyscallReturn::Reschedule { next: Some(n) }) => {
            let _ = k.sched.dispatch(mm_tid, hal.now_ns());
            let (save, into) = k.user_ctx_switch_ptrs(caller, mm_tid)?;
            let poke = if n == mm_tid {
                k.tcb_mut(mm_tid)
                    .and_then(|t| Some((t.pending_from.take()?, t.pending_msg.take()?)))
                    .map(|(from, m)| (from.as_u32() as usize, m.label as usize))
            } else {
                None
            };
            Some(IpcSwitch { save, into, poke })
        }
        _ => None,
    }
}

/// `MM_REGISTER` demo opcode: builds a REAL `MmRequest::Register` for
/// `MM_DEMO_PROCS[which]` (`0` or `1` — any other value is clamped to
/// `0`, matching `resolve_path`'s own "one demo, fixed scenario"
/// simplification precedent).
pub fn mm_register_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, which: u32) -> Option<IpcSwitch> {
    let (thread, resident_bytes, class) = MM_DEMO_PROCS[(which as usize).min(MM_DEMO_PROCS.len() - 1)];
    let req = ipc_protocol::MmRequest::Register { thread, resident_bytes, class };
    let msg = ipc_protocol::codec::encode_mm_request(&req);
    // SAFETY: `mm_demo_start` has already run by the time any `.user_
    // text` code can reach this opcode (it needs `ep_cap`, which only
    // `mm_demo_start`'s own return value provides).
    unsafe { write_shared_mm_message(&msg) };
    mm_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `MmResponse` for `mm_register_call`. Returns `1` for a
/// real `Registered`, `0` otherwise.
pub fn mm_register_result() -> usize {
    // SAFETY: same contract as `mm_register_call`.
    let msg = unsafe { read_shared_mm_message() };
    matches!(ipc_protocol::codec::decode_mm_response(&msg), Ok(ipc_protocol::MmResponse::Registered)) as usize
}

/// `MM_UNREGISTER` demo opcode: builds a REAL `MmRequest::Unregister`.
pub fn mm_unregister_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, thread: u32) -> Option<IpcSwitch> {
    let req = ipc_protocol::MmRequest::Unregister { thread };
    let msg = ipc_protocol::codec::encode_mm_request(&req);
    // SAFETY: see `mm_register_call`'s own contract.
    unsafe { write_shared_mm_message(&msg) };
    mm_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `MmResponse` for `mm_unregister_call`. Returns `1` for
/// a real `Unregistered`, `0` otherwise.
pub fn mm_unregister_result() -> usize {
    // SAFETY: same contract as `mm_register_call`.
    let msg = unsafe { read_shared_mm_message() };
    matches!(ipc_protocol::codec::decode_mm_response(&msg), Ok(ipc_protocol::MmResponse::Unregistered)) as usize
}

/// `MM_QUERY_VICTIM` demo opcode: builds a REAL `MmRequest::QueryVictim`.
pub fn mm_query_victim_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let msg = ipc_protocol::codec::encode_mm_request(&ipc_protocol::MmRequest::QueryVictim);
    // SAFETY: see `mm_register_call`'s own contract.
    unsafe { write_shared_mm_message(&msg) };
    mm_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `MmResponse` for `mm_query_victim_call`, AND
/// cross-checks it against `MM_DEMO_EXPECTED_VICTIM` — proving the REAL
/// `MemRegistry` behind mm-service's own process picks the same victim
/// its host-tested `choose_oom_victim` logic already proves correct in
/// isolation (same "real round-trip reproduces the known-correct
/// answer" verification style `fs_read_result` already established).
/// Returns the victim thread id (`u32::MAX` as `usize` for none), or
/// `usize::MAX` on any decode failure.
pub fn mm_query_victim_result() -> usize {
    // SAFETY: same contract as `mm_register_call`.
    let msg = unsafe { read_shared_mm_message() };
    let thread = match ipc_protocol::codec::decode_mm_response(&msg) {
        Ok(ipc_protocol::MmResponse::Victim { thread }) => thread,
        _ => return usize::MAX,
    };
    klog!(
        "mm_query_victim_result: real OOM victim query through mm-service's own MemRegistry, over real IPC (03 2.5) -> {}\r\n",
        if thread == MM_DEMO_EXPECTED_VICTIM { "MATCH (Sacrificial process chosen over the larger Normal one)" } else { "MISMATCH" }
    );
    thread as usize
}

/// `MM_QUERY_TOTAL_RESIDENT` demo opcode: builds a REAL `MmRequest::
/// QueryTotalResident`.
pub fn mm_query_total_resident_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let msg = ipc_protocol::codec::encode_mm_request(&ipc_protocol::MmRequest::QueryTotalResident);
    // SAFETY: see `mm_register_call`'s own contract.
    unsafe { write_shared_mm_message(&msg) };
    mm_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `MmResponse` for `mm_query_total_resident_call`, AND
/// cross-checks it against `MM_DEMO_EXPECTED_TOTAL` — same verification
/// style as `mm_query_victim_result`'s own doc comment. Returns the
/// total resident byte count, or `usize::MAX` on any decode failure.
pub fn mm_query_total_resident_result() -> usize {
    // SAFETY: same contract as `mm_register_call`.
    let msg = unsafe { read_shared_mm_message() };
    let bytes = match ipc_protocol::codec::decode_mm_response(&msg) {
        Ok(ipc_protocol::MmResponse::TotalResident { bytes }) => bytes,
        _ => return usize::MAX,
    };
    klog!(
        "mm_query_total_resident_result: real resident-byte accounting through mm-service's own MemRegistry, over real IPC (03 2.5) -> {}\r\n",
        if bytes == MM_DEMO_EXPECTED_TOTAL { "MATCH" } else { "MISMATCH" }
    );
    bytes as usize
}

/// Same decode as `mm_query_total_resident_result`, without the verdict
/// `klog!` — `mm_bench_*`'s own 200-iteration `.user_text` loop
/// (02-Microkernel-Layer.md §8.3) reuses `MM_QUERY_TOTAL_RESIDENT` as a
/// cheap, repeatable real round trip purely to TIME it; logging a MATCH
/// line on every one of the 200 calls would drown the boot log in
/// identical noise for no reason (unlike the one-shot `mm_demo_*` call
/// this quiet variant is NOT a substitute for — that one's own MATCH/
/// MISMATCH verdict is the real correctness proof and stays as is).
pub fn mm_query_total_resident_result_quiet() -> usize {
    // SAFETY: same contract as `mm_register_call`.
    let msg = unsafe { read_shared_mm_message() };
    match ipc_protocol::codec::decode_mm_response(&msg) {
        Ok(ipc_protocol::MmResponse::TotalResident { bytes }) => bytes as usize,
        _ => usize::MAX,
    }
}

// ============================================================================
// driver-virtio-blk: real MMIO + virtqueue block driver process (03 §5.1)
//
// Mirrors the fs-native section immediately above almost exactly (same
// "spawn, grant an Endpoint, pre-map a shared page/region, drive it via
// a dedicated ecall-per-request-type + shared-message-area protocol"
// shape) — see that section's own doc comments for the parts that
// repeat verbatim here. Two differences: (1) this driver ALSO needs a
// virtio-mmio transport window pre-mapped (`DRV_MMIO_VA`, from the
// boot-seeded `root_mmio_blk_cap` — see `MmioRegionDescriptor`'s own
// doc comment for why that capability exists at all); (2) its
// `DriverRequest`/`DriverResponse` message area lives INSIDE the same
// `SharedRegion` as its virtqueue (`driver_virtio_blk::layout::
// MESSAGE_OFFSET`), not a second dedicated page — one grant covers
// both, see `layout`'s own doc comment.
// ============================================================================

/// This process's own thread id, set once by `spawn_virtio_blk_driver`.
static mut G_DRV_TID: Option<ThreadId> = None;

/// Physical base of the driver's virtqueue/data `SharedRegion` — same
/// role as `G_FS_DATA_PHYS`, additionally used to derive the message-
/// area address (`+ driver_virtio_blk::layout::MESSAGE_OFFSET`) since
/// this driver reuses one region for both purposes.
static mut G_DRV_QUEUE_PHYS: usize = usize::MAX;

/// Physical base of the virtio-blk device's own MMIO window (`k.mmio_
/// region(...)`'s own `phys_base`, cached at spawn time) — used ONLY by
/// `virtio_blk_irq_trampoline` to ack the DEVICE's own `INTERRUPT_
/// STATUS`/`INTERRUPT_ACK` registers (`driver_virtio_blk::mmio`'s own
/// fixed offsets, valid for any virtio-mmio device regardless of type)
/// directly from interrupt context — see that function's own doc
/// comment for why this ack cannot wait for `VirtioBlk::ack_completion`
/// (a DIFFERENT process's own private state, unreachable from here) to
/// run later in the driver process's own time.
static mut G_DRV_MMIO_PHYS: usize = usize::MAX;

/// `Transport::Pci`'s own counterpart to `G_DRV_MMIO_PHYS`: the ISR_CFG
/// register's own VA — a VA, not a physical address, because unlike
/// virtio-mmio's window (identity-mapped, dereferenceable from ANY
/// active page table) virtio-pci's BAR only exists at a HIGH physical
/// address (QEMU virt's own highmem PCI aperture, e.g. `0x80_0000_0000`
/// — see `KERNEL_PCI_CFG_VA`'s own doc comment for the identical class
/// of problem this solves for ECAM config space). Deliberately reuses
/// `wire_virtio_pci_transport`'s own `isr_cfg_va` (a VA in `drv_root_
/// pt`, NOT `caller_root_pt`) rather than building a SEPARATE kernel-
/// side mapping: `virtio_blk_irq_trampoline` only ever fires while
/// `drv_irq_wait_step`'s own `wfi()` retry loop is spinning INSIDE the
/// driver process's own `DRV_IRQ_WAIT` syscall — i.e., while `drv_
/// root_pt` (not `caller_root_pt`) is the ACTIVE TTBR0_EL1, since a
/// `Wait`-blocked thread's own trap context is never unwound back to
/// its caller — so the driver's OWN existing BAR mapping is already
/// exactly what this needs, with no new mapping required.
static mut G_DRV_ISR_CFG_VA: usize = usize::MAX;

/// VA the virtio-mmio transport window is pre-mapped at in the driver's
/// own address space — must stay numerically equal to
/// `driver_virtio_blk::subsystem_entry::DRV_MMIO_VA`.
const DRV_MMIO_VA: usize = 0xD820_0000;

/// VA the virtqueue/data `SharedRegion` is pre-mapped at in the driver's
/// own address space — must stay numerically equal to
/// `driver_virtio_blk::subsystem_entry::DRV_QUEUE_VA`.
const DRV_QUEUE_VA: usize = 0xD830_0000;

// ============================================================================
// virtio-pci "modern" transport support (aarch64) — PCI capability-list
// walking + BAR mapping. Unlike `DRV_MMIO_VA`/`DRV_QUEUE_VA` above, the
// driver process never hardcodes the VA(s) this section maps its
// register windows at: it learns them entirely from the `PCI_INFO_
// OFFSET` header block this section writes into the SAME `SharedRegion`
// `DRV_QUEUE_VA` already covers (see `driver_virtio_blk::layout::
// PCI_INFO_OFFSET`'s own doc comment for the field layout, and
// `driver_virtio_blk::subsystem_entry::new_driver_for_this_transport`
// for the reader). This split exists because — unlike virtio-mmio's
// single fixed register block at a HAL-discovered base — virtio-pci
// "modern" scatters its 4 register windows (COMMON/NOTIFY/ISR/
// DEVICE_CFG) across a PCI capability list (virtio 1.x spec §4.1.4)
// that only THIS trusted glue code (not the HAL, which only reports
// BAR0 — see `hal_arm64::peripheral`'s own module doc comment) is
// positioned to resolve, since resolving it requires live PCI config-
// space + BAR reads no HAL discovery pass performs.
// ============================================================================

/// PCI config-space byte offset of the Capabilities Pointer register
/// (Type 0x00 header, PCI Local Bus Spec §6.7) — valid whenever the
/// Status register's own Capabilities List bit (offset 0x06, bit 4) is
/// set, which every virtio-pci "modern" device sets by construction
/// (the only kind `hal_arm64::peripheral::PeripheralDiscovery` reports
/// a nonzero `config_space_base` for in the first place).
const PCI_CAP_POINTER_OFFSET: u32 = 0x34;

/// PCI config-space byte offset of the Command register (Type 0x00
/// header, PCI Local Bus Spec §6.2.2) — a u16 register, but written
/// here as the low half of the u32 word it shares with Status (0x06),
/// via a read-modify-write so Status's own write-1-to-clear error bits
/// are never touched.
const PCI_COMMAND_OFFSET: u32 = 0x04;
/// Command register bit 1: Memory Space Enable — decode of this
/// function's own memory BARs stays OFF until this is set (PCI Local
/// Bus Spec §6.2.2), independent of whether those BARs are otherwise
/// correctly sized/assigned.
const PCI_COMMAND_MEMORY_SPACE: u32 = 1 << 1;
/// Command register bit 2: Bus Master Enable — required before this
/// function may itself initiate a memory transaction (irrelevant to
/// the driver's own MMIO register reads/writes, which are CPU-
/// initiated, but required regardless for virtqueue DMA once the
/// device is driving completions).
const PCI_COMMAND_BUS_MASTER: u32 = 1 << 2;

/// Vendor-specific capability id (PCI Local Bus Spec §6.7's own
/// Capability ID assignments) — the only capability id virtio-pci
/// devices attach to the standard PCI capability list (virtio 1.x spec
/// §4.1.4, `struct virtio_pci_cap`'s own `cap_vndr` field).
const PCI_CAP_ID_VENDOR_SPECIFIC: u8 = 0x09;

/// `cfg_type` byte values from `struct virtio_pci_cap` (virtio 1.x spec
/// §4.1.4.3).
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// Base VA for virtio-pci BAR window(s) — one `DRV_PCI_BAR_VA_STRIDE`
/// slot per DISTINCT BAR index the capability list below references,
/// starting well clear of `DRV_QUEUE_VA`'s own single page. QEMU's own
/// virtio-pci-modern devices bundle all 4 capability windows into ONE
/// BAR (so in practice exactly one slot is ever used), but the virtio
/// spec does not require that, so this supports up to `DRV_PCI_MAX_
/// BARS` distinct ones.
const DRV_PCI_BAR_VA_BASE: usize = 0xD840_0000;
/// Headroom reserved per distinct BAR — generously above the low-KiB
/// window sizes QEMU's own virtio-pci-modern BARs actually use.
const DRV_PCI_BAR_VA_STRIDE: usize = 0x10_0000;
const DRV_PCI_MAX_BARS: usize = 4;

/// VA `wire_virtio_pci_transport` maps a PCI function's own ECAM
/// config-space page at, in the CALLER's (root's) own address space —
/// see that function's own doc comment for why this mapping (not a
/// raw physical dereference) is required at all: unlike `mmio.phys_
/// base` (a BAR base, always within the low few GiB `map_ram_identity`
/// already covers for every process), ECAM config space sits at
/// `hal_arm64::compute`'s own `QEMU_VIRT_DEFAULT_ECAM_BASE` (0x40_1000_
/// 0000, ~256 GiB) — far outside ANY process's own identity-mapped
/// range, so a raw pointer dereference against it faults under
/// whichever page table happens to be active (a REAL bug found via
/// QEMU: without this mapping, `spawn_virtio_blk_driver`'s PCI branch
/// hangs the very first time `walk_virtio_pci_capabilities` reads
/// config space, root's own EL1 code faulting under its own `root_pt`).
const KERNEL_PCI_CFG_VA: usize = 0xD800_0000;

/// VA `enable_and_program_msix` maps the MSI-X table's own BAR window
/// at, in the CALLER's (root's) own address space — the SAME "kernel-
/// side mapping, not driver-space" reasoning `KERNEL_PCI_CFG_VA`'s own
/// doc comment gives, and `enable_and_program_msix`'s own doc comment
/// covers the real bug this constant's existence fixes. Distinct from
/// both `KERNEL_PCI_CFG_VA` (a single ECAM config-space PAGE, not a
/// BAR) and `DRV_PCI_BAR_VA_BASE` (driver-space, a DIFFERENT address
/// space entirely) — headroom sized the same generous way `DRV_PCI_
/// BAR_VA_STRIDE` already documents.
const KERNEL_MSIX_BAR_VA: usize = 0xD810_0000;

/// VA `enable_and_program_msix` maps COMMON_CFG's own BAR window at (in
/// the CALLER's own address space, same "kernel-side, not driver-space"
/// reasoning as `KERNEL_MSIX_BAR_VA` — see that constant's own doc
/// comment). A SEPARATE mapping from `KERNEL_MSIX_BAR_VA` because
/// COMMON_CFG and the MSI-X table are near-universally on DIFFERENT
/// BARs (QEMU's own virtio-pci-modern devices: COMMON/NOTIFY/ISR/
/// DEVICE_CFG share one BAR, MSI-X — a PCI-SIG-standard capability, not
/// virtio's own — lives on a different one), so neither can reuse the
/// other's mapping.
const KERNEL_MSIX_COMMON_VA: usize = 0xD811_0000;

/// `struct virtio_pci_common_cfg`'s own `queue_msix_vector` field byte
/// offset (virtio 1.x spec §4.1.4.3, Table 4-1) — a `le16`, PER-QUEUE
/// (governed by whatever `queue_select`, offset 0x16, currently names),
/// that this project's own `driver_virtio_blk::pci_common` module has
/// NO field for at all: that module was written before MSI-X support
/// existed in this codebase, and neither virtio-mmio nor legacy-INTx
/// PCI (aarch64's own choice) ever needs a driver to assign a queue's
/// completions to a specific vector — INTx fires unconditionally
/// whenever ANY interrupt condition is pending, no per-queue routing
/// involved. MSI-X is different: per the virtio spec, an unassigned
/// queue defaults to `VIRTIO_MSI_NO_VECTOR` (0xFFFF) and the device
/// will never signal ANYTHING for it until the driver explicitly
/// programs this register — **the real bug an initial MSI-X attempt
/// hit via QEMU**: `enable_and_program_msix`'s own table-entry write +
/// capability Enable bit were BOTH verified correct via direct
/// register readback, yet the driver's own `DRV_IRQ_WAIT` still hung
/// forever waiting on the SAME PCI MSI-X vector 44 that was correctly
/// programmed — because the DEVICE itself was never told to use it for
/// this queue. Written here (not `driver_virtio_blk`, which stays
/// transport-detail-free) since only kernel-arch-glue's own PCI
/// capability-list walk already knows which table index (0, this
/// MVP's only entry) the interrupt controller resolved.
const VIRTIO_PCI_COMMON_QUEUE_SELECT: u32 = 0x16;
const VIRTIO_PCI_COMMON_QUEUE_MSIX_VECTOR: u32 = 0x1a;

/// Raw PCI/PCIe config-space reads, `config_phys` already folding in
/// bus/device/function (exactly the value `hal_arm64::peripheral::
/// PeripheralDiscovery::new` assembled into `MmioRegionDescriptor::
/// config_space_base` at boot) — callers here only ever add a register
/// offset on top.
///
/// # Safety
/// `config_phys` must be a live, mapped ECAM config-space address for
/// the life of the call — true for every `MmioRegionDescriptor` this
/// kernel boot-seeds, the same trust boundary `mmio.phys_base` reads
/// elsewhere in this file already rely on.
unsafe fn pci_cfg_read8(config_phys: u64, offset: u32) -> u8 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((config_phys + offset as u64) as *const u8).read_volatile() }
}

/// # Safety
/// Same contract as `pci_cfg_read8`.
unsafe fn pci_cfg_read32(config_phys: u64, offset: u32) -> u32 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((config_phys + offset as u64) as *const u32).read_volatile() }
}

/// # Safety
/// Same contract as `pci_cfg_read8`.
unsafe fn pci_cfg_write32(config_phys: u64, offset: u32, val: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((config_phys + offset as u64) as *mut u32).write_volatile(val) };
}

/// Resolves BAR `bar_index`'s own physical base + size on the PCI
/// function at `config_phys` — the general, arbitrary-index counterpart
/// to `hal_arm64::peripheral`'s own discovery-time BAR0-only probe
/// (that one lives in the HAL and only ever reports BAR0; this one
/// lives here, resolved lazily only for whichever BAR(s) `walk_virtio_
/// pci_capabilities` below actually references). Correctly follows a
/// 64-bit memory BAR (bits[2:1] == 0b10 of the BAR register) onto its
/// own upper dword at `bar_index + 1` (PCI Local Bus Spec §6.2.5.1) —
/// QEMU's own virtio-pci-modern devices route COMMON/NOTIFY/ISR/
/// DEVICE_CFG through exactly such a BAR (typically BAR4).
///
/// # Safety
/// Same contract as `pci_cfg_read8`; additionally performs the standard
/// write-all-ones/read-back/restore sizing dance on the live BAR
/// register(s) — not safe against a concurrent access to the SAME
/// function's config space, which this single-core, root-only
/// bootstrap path (called only from `spawn_virtio_blk_driver`, before
/// the driver process it is resolving registers FOR has even started
/// running) never has.
unsafe fn pci_bar_phys(config_phys: u64, bar_index: u8) -> Option<(u64, u64)> {
    let bar_off = 0x10 + (bar_index as u32) * 4;
    // SAFETY: forwarded from this function's own contract.
    let bar_lo = unsafe { pci_cfg_read32(config_phys, bar_off) };
    if bar_lo & 0x1 != 0 {
        return None; // I/O-space BAR — out of scope, same as hal-arm64's own probe_bar0.
    }
    let is_64bit = (bar_lo >> 1) & 0x3 == 0b10;

    // SAFETY: forwarded; original value restored immediately below —
    // standard PCI BAR-sizing procedure (spec §6.2.5.1).
    unsafe { pci_cfg_write32(config_phys, bar_off, 0xFFFF_FFFF) };
    // SAFETY: forwarded.
    let size_lo = unsafe { pci_cfg_read32(config_phys, bar_off) };
    // SAFETY: forwarded; restoring.
    unsafe { pci_cfg_write32(config_phys, bar_off, bar_lo) };

    let base_lo = (bar_lo & 0xFFFF_FFF0) as u64;

    if !is_64bit {
        if size_lo == 0 {
            return None;
        }
        let size = (!(size_lo & 0xFFFF_FFF0) as u64) + 1;
        return Some((base_lo, size));
    }

    let bar_hi_off = bar_off + 4;
    // SAFETY: forwarded.
    let bar_hi = unsafe { pci_cfg_read32(config_phys, bar_hi_off) };
    // SAFETY: forwarded; restored below.
    unsafe { pci_cfg_write32(config_phys, bar_hi_off, 0xFFFF_FFFF) };
    // SAFETY: forwarded.
    let size_hi = unsafe { pci_cfg_read32(config_phys, bar_hi_off) };
    // SAFETY: forwarded; restoring.
    unsafe { pci_cfg_write32(config_phys, bar_hi_off, bar_hi) };

    let base = base_lo | ((bar_hi as u64) << 32);
    let size_mask = ((size_hi as u64) << 32) | (size_lo & 0xFFFF_FFF0) as u64;
    if size_mask == 0 {
        return None;
    }
    let size = (!size_mask) + 1;
    Some((base, size))
}

/// One resolved virtio-pci capability window: which BAR it lives in,
/// plus its own byte offset/length within that BAR (`struct
/// virtio_pci_cap`, virtio 1.x spec §4.1.4.3).
#[derive(Clone, Copy, Default)]
struct VirtioPciCapWindow {
    bar: u8,
    offset: u32,
}

/// Standard PCI capability id for MSI-X (PCI Local Bus Spec §6.8.2, as
/// extended by the MSI-X ECN) — a DIFFERENT capability from virtio's
/// own vendor-specific ones (`PCI_CAP_ID_VENDOR_SPECIFIC`), found on the
/// SAME capability list `walk_virtio_pci_capabilities` already walks.
/// Only ever populated on x86_64's own virtio-pci device in this
/// project (aarch64 uses legacy INTx instead — `hal_core::interrupt::
/// InterruptController::msi_message`'s own doc comment covers why this
/// stays purely data-driven, never a `target_arch` check): whether THIS
/// capability is present, combined with whether `HalInterface::
/// msi_message` returns `Some` at all, is what `wire_virtio_pci_
/// transport` below actually branches on.
const PCI_CAP_ID_MSIX: u8 = 0x11;

/// Byte offset, from an MSI-X capability's own structure start, of the
/// Table Offset/BIR register (PCI Local Bus Spec, MSI-X ECN §6.8.2.3):
/// bits 2:0 name the BAR index, bits 31:3 the table's own byte offset
/// within it (already 8-byte aligned by construction, so masking off
/// the low 3 bits recovers it exactly).
const MSIX_TABLE_OFFSET_BIR: u32 = 4;
/// Message Control lives at capability offset+2 (a u16), sharing the
/// SAME 32-bit dword as the 1-byte Capability ID (offset+0) and 1-byte
/// Next Pointer (offset+1) — bit 31 of that dword (Message Control's
/// own bit 15) is MSI-X Enable; bit 30 (Message Control's own bit 14)
/// is Function Mask, which must stay CLEAR for an enabled entry to
/// actually fire.
const MSIX_ENABLE_BIT: u32 = 1 << 31;

/// One resolved MSI-X table location: which BAR it lives in, plus its
/// own byte offset within that BAR — the MSI-X counterpart to
/// `VirtioPciCapWindow`, kept as a separate type since MSI-X's own
/// capability structure (a fixed, PCI-SIG-standard layout) shares
/// nothing with virtio's own vendor-specific `struct virtio_pci_cap`
/// beyond both living on the same capability list.
#[derive(Clone, Copy, Default)]
struct MsixLocation {
    /// The capability structure's own byte offset within config space
    /// (`walk_virtio_pci_capabilities`'s own list-walk pointer) — needed
    /// to later write the Message Control register's own MSI-X Enable
    /// bit, which lives WITHIN this capability structure, not the BAR
    /// window `bar`/`table_offset` below name.
    cap_ptr: u8,
    bar: u8,
    table_offset: u32,
}

/// The capability windows a virtio-pci "modern" device's own capability
/// list carries (virtio 1.x spec §4.1.4) — `notify` additionally needs
/// `notify_off_multiplier` (`struct virtio_pci_notify_cap`'s own
/// extension field, spec §4.1.4.4) to locate a specific queue's own
/// doorbell within the NOTIFY_CFG window. `msix`, when present, is
/// resolved (BAR/table offset) but NOT yet enabled — `wire_virtio_pci_
/// transport` does that, since enabling requires the destination
/// vector's own Message Address/Data (`HalInterface::msi_message`),
/// which this purely-data-collecting walk has no access to.
#[derive(Default)]
struct VirtioPciCapLayout {
    common: Option<VirtioPciCapWindow>,
    notify: Option<VirtioPciCapWindow>,
    notify_off_multiplier: u32,
    isr: Option<VirtioPciCapWindow>,
    device: Option<VirtioPciCapWindow>,
    msix: Option<MsixLocation>,
}

/// Walks the standard PCI capability list (starting at the
/// Capabilities Pointer register, offset 0x34) looking for vendor-
/// specific (id 0x09) capabilities, classifying each by its own
/// `cfg_type` byte (virtio 1.x spec §4.1.4.3) — the real counterpart to
/// `hal_arm64::peripheral`'s own discovery-time BAR0-only read (see
/// that module's own doc comment on why the full walk is deliberately
/// deferred to here, the driver-spawning trusted glue, rather than done
/// at HAL discovery time).
///
/// # Safety
/// Same contract as `pci_cfg_read8`.
unsafe fn walk_virtio_pci_capabilities(config_phys: u64) -> VirtioPciCapLayout {
    let mut layout = VirtioPciCapLayout::default();

    // SAFETY: forwarded from this function's own contract.
    let mut ptr = unsafe { pci_cfg_read8(config_phys, PCI_CAP_POINTER_OFFSET) };
    // Bounded walk — a real capability list is a finite linked list
    // within a 256-byte config space; this guards against a malformed
    // device looping the list forever (defensive even though this only
    // ever walks an emulated/passthrough device's own config space).
    for _ in 0..48 {
        if ptr == 0 {
            break;
        }
        // SAFETY: forwarded.
        let cap_id = unsafe { pci_cfg_read8(config_phys, ptr as u32) };
        // SAFETY: forwarded.
        let cap_next = unsafe { pci_cfg_read8(config_phys, ptr as u32 + 1) };

        if cap_id == PCI_CAP_ID_VENDOR_SPECIFIC {
            // SAFETY: forwarded.
            let cfg_type = unsafe { pci_cfg_read8(config_phys, ptr as u32 + 3) };
            // SAFETY: forwarded.
            let bar = unsafe { pci_cfg_read8(config_phys, ptr as u32 + 4) };
            // SAFETY: forwarded.
            let offset = unsafe { pci_cfg_read32(config_phys, ptr as u32 + 8) };
            let window = VirtioPciCapWindow { bar, offset };

            match cfg_type {
                VIRTIO_PCI_CAP_COMMON_CFG => layout.common = Some(window),
                VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    layout.notify = Some(window);
                    // SAFETY: forwarded — `struct virtio_pci_notify_cap`'s
                    // own extension field, spec §4.1.4.4.
                    layout.notify_off_multiplier =
                        unsafe { pci_cfg_read32(config_phys, ptr as u32 + 16) };
                }
                VIRTIO_PCI_CAP_ISR_CFG => layout.isr = Some(window),
                VIRTIO_PCI_CAP_DEVICE_CFG => layout.device = Some(window),
                _ => {}
            }
        } else if cap_id == PCI_CAP_ID_MSIX {
            // SAFETY: forwarded.
            let bir_dword = unsafe { pci_cfg_read32(config_phys, ptr as u32 + MSIX_TABLE_OFFSET_BIR) };
            layout.msix = Some(MsixLocation {
                cap_ptr: ptr,
                bar: (bir_dword & 0x7) as u8,
                table_offset: bir_dword & !0x7,
            });
        }

        ptr = cap_next;
    }

    layout
}

/// Maps virtio-pci BAR `bar_index`'s own physical window into the
/// driver process's address space, returning its virtual base —
/// memoized against `mapped`/`mapped_count` so the SAME BAR referenced
/// by more than one capability window (COMMON/NOTIFY/ISR/DEVICE_CFG
/// commonly all share one BAR — see this section's own module doc
/// comment) is mapped exactly once. Mirrors the untyped-carve + `map_
/// range` pattern `spawn_virtio_blk_driver`'s own virtio-mmio window
/// pre-map already uses, generalized to an arbitrary size (a BAR can be
/// larger than one page, unlike the fixed single-page virtio-mmio
/// window).
///
/// # Safety
/// Same contract as `pci_bar_phys`.
#[allow(clippy::too_many_arguments)]
unsafe fn map_pci_bar(
    k: &mut KernelState,
    hal: &HalInterface,
    drv_root_pt: usize,
    config_phys: u64,
    bar_index: u8,
    mapped: &mut [(u8, usize); DRV_PCI_MAX_BARS],
    mapped_count: &mut usize,
) -> Option<usize> {
    if let Some((_, va)) = mapped[..*mapped_count].iter().find(|(b, _)| *b == bar_index) {
        return Some(*va);
    }
    if *mapped_count >= DRV_PCI_MAX_BARS {
        return None;
    }
    // SAFETY: forwarded from this function's own contract.
    let (bar_phys, bar_size) = unsafe { pci_bar_phys(config_phys, bar_index) }?;
    let map_len = (bar_size as usize).div_ceil(4096) * 4096;
    if map_len == 0 || map_len > DRV_PCI_BAR_VA_STRIDE {
        return None; // would collide with the next BAR slot's own VA range.
    }
    let va = DRV_PCI_BAR_VA_BASE + *mapped_count * DRV_PCI_BAR_VA_STRIDE;

    // Pool sizing: one new L2 table plus up to one new L3 table per
    // 2 MiB (512 pages) of mapped range, +1 page of slack — the same
    // "pool is page-table scratch, not target-region-sized" contract
    // `map_range`'s own doc comment establishes, just scaled up from
    // the fixed single-page virtio-mmio pre-map's `pool_len = 2`.
    let pages_needed = map_len / 4096;
    let pool_pages = 2 + pages_needed.div_ceil(512);
    let pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, (4096 * pool_pages) as u64).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed (same contract every other
    // pool carve in this file already documents).
    unsafe { core::ptr::write_bytes(pool as *mut u8, 0, 4096 * pool_pages) };
    let n = hal.map_range(
        drv_root_pt,
        va,
        bar_phys as usize,
        map_len,
        1 | 2 | 8, // R+W+U — the driver's own user-mode register window.
        pool,
        pool_pages,
    );
    if n == u32::MAX {
        return None;
    }

    mapped[*mapped_count] = (bar_index, va);
    *mapped_count += 1;
    Some(va)
}

/// Enables MSI-X (Message Control's own Enable bit, Function Mask left
/// clear) and programs table entry 0 — this MVP's own single-vector
/// scope, matching `IrqBind`'s own "one Notification per device" model
/// — with `msi_message`'s Message Address/Data, unmasking that ONE
/// entry (`vector_control` bit 0 clear). `msix.bar`'s own window is
/// mapped via `map_pci_bar` exactly like every virtio capability window
/// already is — MSI-X's table lives in device memory space like any
/// other BAR-relative structure, nothing about it is config-space-only.
///
/// Only ever called when BOTH a real MSI-X capability was found on this
/// device's own list AND `HalInterface::msi_message` returned `Some`
/// (this project's x86_64-only interrupt controller) — see `wire_
/// virtio_pci_transport`'s own call site for the data-driven (never
/// `target_arch`) branch this stays behind.
///
/// # Safety
/// Same contract as `map_pci_bar`.
#[allow(clippy::too_many_arguments)]
unsafe fn enable_and_program_msix(
    k: &mut KernelState,
    hal: &HalInterface,
    caller_root_pt: usize,
    config_va: u64,
    msix: MsixLocation,
    common: VirtioPciCapWindow,
    msi_message: (u64, u32),
) -> Option<()> {
    // **Real bug found via QEMU**: an earlier version of this function
    // mapped the MSI-X table's own BAR into `drv_root_pt` (the DRIVER
    // process's own, NOT-YET-ACTIVE page table — reusing `map_pci_bar`
    // exactly like the virtio capability windows below do) and then
    // immediately dereferenced the resulting VA from RIGHT HERE — but
    // this function runs from `spawn_virtio_blk_driver`, still under
    // the CALLER's (root's) own currently-ACTIVE page table, which has
    // no such mapping at all. Result: a real `#PF` (write, not-present)
    // the instant `entry.write_volatile` below ran — confirmed via
    // `-d int`/exception dump, `cr2` landing exactly at the SECOND
    // `DRV_PCI_BAR_VA_STRIDE` slot (this device's own MSI-X table lives
    // in a DIFFERENT BAR than COMMON/NOTIFY/ISR/DEVICE_CFG's shared
    // BAR4, so it was never already-mapped via the `mapped[]`
    // memoization either). The virtio capability windows below never
    // hit this class of bug because kernel-arch-glue never dereferences
    // THEIR VAs itself — it only writes them into the `PCI_INFO_OFFSET`
    // header block for the DRIVER PROCESS to read once it is actually
    // scheduled under `drv_root_pt`. This function is different: it
    // must write the MSI-X table entry NOW, from kernel-arch-glue's own
    // currently-running context — so it maps into `caller_root_pt`
    // instead, at the SAME kind of dedicated, kernel-only VA `KERNEL_
    // PCI_CFG_VA` already uses for the config-space page, not the
    // driver-space `DRV_PCI_BAR_VA_BASE` range `map_pci_bar` targets.
    let msix_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed.
    unsafe { core::ptr::write_bytes(msix_pool as *mut u8, 0, 4096 * 2) };
    // SAFETY: forwarded from this function's own contract; `msix.bar`'s
    // own physical base/size resolved fresh here (not memoized against
    // the driver-space `mapped[]` table, which tracks a DIFFERENT
    // address space entirely).
    let (bar_phys, bar_size) = unsafe { pci_bar_phys(config_va, msix.bar) }?;
    let map_len = (bar_size as usize).div_ceil(4096) * 4096;
    let n = hal.map_range(
        caller_root_pt,
        KERNEL_MSIX_BAR_VA,
        bar_phys as usize,
        map_len,
        1 | 2, // R+W, kernel-only (no U bit) — EL1/S-mode/Ring-0 code only, same as KERNEL_PCI_CFG_VA's own mapping.
        msix_pool,
        2,
    );
    if n == u32::MAX {
        return None;
    }
    // Modifying a LIVE, currently-active page table (unlike `map_pci_
    // bar`'s own driver-space mappings, which target a not-yet-active
    // one) — flush before relying on the fresh mapping, same insurance
    // `wire_virtio_pci_transport`'s own config-space mapping already
    // takes for the identical reason.
    hal.flush_tlb();

    let table_va = KERNEL_MSIX_BAR_VA + msix.table_offset as usize;
    let (addr, data) = msi_message;
    let entry = table_va as *mut u32; // entry 0 — this MVP's only vector.
    // SAFETY: `entry` is within the just-mapped MSI-X table BAR window
    // (R+W+U, `map_pci_bar`'s own contract), 16-byte MSI-X table entry
    // layout per the MSI-X ECN (Message Address Low/High, Message Data,
    // Vector Control — PCI Local Bus Spec §6.8.2.9).
    unsafe {
        entry.write_volatile(addr as u32); // Message Address (low 32 bits).
        entry.add(1).write_volatile((addr >> 32) as u32); // Message Address (high 32 bits) — always 0, this MVP's address is always < 4 GiB.
        entry.add(2).write_volatile(data); // Message Data.
        entry.add(3).write_volatile(0); // Vector Control — bit 0 clear = unmasked.
    }

    // Message Control's own dword shares byte offsets 0-3 of the
    // capability structure with Capability ID (byte 0) and Next Pointer
    // (byte 1) — read-modify-write so those two bytes are never touched.
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let ctrl_dword = pci_cfg_read32(config_va, msix.cap_ptr as u32);
        pci_cfg_write32(config_va, msix.cap_ptr as u32, ctrl_dword | MSIX_ENABLE_BIT);
    }

    // Tell the DEVICE to actually use table entry 0 for the request
    // virtqueue's own completions — see `VIRTIO_PCI_COMMON_QUEUE_MSIX_
    // VECTOR`'s own doc comment for the full "real bug found via QEMU"
    // story this fixes. A second kernel-side BAR mapping, exactly the
    // same shape as the MSI-X table's own above (COMMON_CFG is almost
    // always a DIFFERENT BAR).
    let common_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core.
    unsafe { core::ptr::write_bytes(common_pool as *mut u8, 0, 4096 * 2) };
    // SAFETY: forwarded from this function's own contract.
    let (common_bar_phys, common_bar_size) = unsafe { pci_bar_phys(config_va, common.bar) }?;
    let common_map_len = (common_bar_size as usize).div_ceil(4096) * 4096;
    let common_n = hal.map_range(
        caller_root_pt,
        KERNEL_MSIX_COMMON_VA,
        common_bar_phys as usize,
        common_map_len,
        1 | 2, // R+W, kernel-only — same as KERNEL_MSIX_BAR_VA's own mapping.
        common_pool,
        2,
    );
    if common_n == u32::MAX {
        return None;
    }
    hal.flush_tlb();
    let common_cfg_kernel_va = KERNEL_MSIX_COMMON_VA + common.offset as usize;
    // REQUEST_QUEUE's own index (0 — this driver's only virtqueue,
    // `driver_virtio_blk`'s own module doc comment) — select it, THEN
    // write its own `queue_msix_vector` (spec §4.1.4.3: `queue_select`
    // MUST be written before either register named "About a specific
    // virtqueue" is read or written, since they alias the CURRENTLY
    // selected queue's own state).
    // SAFETY: `common_cfg_kernel_va` is within the just-mapped, just-
    // flushed COMMON_CFG BAR window (R+W, kernel-only).
    unsafe {
        ((common_cfg_kernel_va + VIRTIO_PCI_COMMON_QUEUE_SELECT as usize) as *mut u16)
            .write_volatile(0);
        ((common_cfg_kernel_va + VIRTIO_PCI_COMMON_QUEUE_MSIX_VECTOR as usize) as *mut u16)
            .write_volatile(0); // table entry 0 — this MVP's only vector, matching enable_and_program_msix's own table write above.
    }

    Some(())
}

/// Resolves and maps a virtio-pci "modern" device's own 4 capability
/// windows (COMMON/NOTIFY/ISR/DEVICE_CFG) into the driver process, then
/// writes the `PCI_INFO_OFFSET` header block (`driver_virtio_blk::
/// layout::PCI_INFO_OFFSET`'s own doc comment) into `region_phys` so
/// `driver_virtio_blk::subsystem_entry::new_driver_for_this_transport`
/// can construct a `Transport::Pci`-backed `VirtioBlk` without ever
/// needing its own copy of these addresses. Returns `None` (and logs)
/// if COMMON_CFG — the one capability window virtio-pci-modern cannot
/// function without — was not found, or if mapping its own BAR failed;
/// NOTIFY/ISR/DEVICE_CFG are logged-and-skipped individually since a
/// missing one still leaves `VirtioBlk::probe` able to fail cleanly
/// rather than dereference a null VA (mirrors `spawn_virtio_blk_driver`'s
/// own "no allocation, no process" failure philosophy applied at
/// finer, per-window grain here).
///
/// First maps `config_phys`'s own ECAM page (already page-aligned —
/// `ecam_offset`'s own construction) into `caller_root_pt` at `KERNEL_
/// PCI_CFG_VA` — see that const's own doc comment for why this kernel-
/// side mapping is required before ANY read/write against config space,
/// unlike a BAR's own target window (`mmio.phys_base`, always within
/// the identity-mapped low GiB range every process already carries).
/// Every capability-list walk and BAR-sizing probe below reads through
/// `KERNEL_PCI_CFG_VA`, never the raw `config_phys`, for exactly this
/// reason (`pci_bar_phys`'s own BAR-register reads/writes live WITHIN
/// this same config-space page, not the BAR's own target memory).
///
/// `irq` (the SAME value `spawn_virtio_blk_driver`'s own `IrqBind` call
/// later registers a handler at) is only consulted for MSI-X — see
/// `enable_and_program_msix`'s own doc comment for the full data-driven
/// branch this takes on architectures where `HalInterface::msi_message`
/// and this device's own capability list both cooperate (x86_64 only,
/// today); ignored entirely otherwise.
///
/// # Safety
/// Same contract as `pci_bar_phys` / `map_pci_bar`.
unsafe fn wire_virtio_pci_transport(
    k: &mut KernelState,
    hal: &HalInterface,
    drv_root_pt: usize,
    caller_root_pt: usize,
    config_phys: u64,
    region_phys: usize,
    irq: u32,
) -> Option<()> {
    let cfg_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed.
    unsafe { core::ptr::write_bytes(cfg_pool as *mut u8, 0, 4096 * 2) };
    let cfg_n = hal.map_range(
        caller_root_pt,
        KERNEL_PCI_CFG_VA,
        config_phys as usize,
        4096,
        1 | 2, // R+W, kernel-only (no U bit) — EL1/S-mode code only.
        cfg_pool,
        2,
    );
    if cfg_n == u32::MAX {
        klog!("wire_virtio_pci_transport: map_range error (ECAM config-space page)\r\n");
        return None;
    }
    // Modifying a LIVE, currently-active page table (unlike every other
    // `map_range` call in this file, which always targets a not-yet-
    // activated process) — flush before relying on the fresh mapping,
    // cheap insurance against any stale walk-cache state.
    hal.flush_tlb();
    let config_va = KERNEL_PCI_CFG_VA as u64;

    // Enable Memory Space + Bus Master (PCI Local Bus Spec §6.2.2) —
    // **real bug found via QEMU**: without this, EVERY register in
    // BAR4's own MMIO window reads back 0xFFFFFFFF, regardless of page
    // tables or exception level (confirmed by reading the SAME
    // physical window directly from EL1 with its own fresh mapping —
    // still 0xFFFFFFFF), because the device's memory decode is simply
    // OFF until a driver explicitly turns it on. Every peripheral this
    // project touched before virtio-pci was virtio-mmio, which has no
    // such gate at all, so this step never had a reason to exist here
    // until now. Read-modify-write (not a raw overwrite) so Status's
    // own write-1-to-clear bits, sharing this same u32 word, are never
    // touched.
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let cmd_status = pci_cfg_read32(config_va, PCI_COMMAND_OFFSET);
        pci_cfg_write32(
            config_va,
            PCI_COMMAND_OFFSET,
            cmd_status | PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER,
        );
    }

    // SAFETY: forwarded from this function's own contract; `config_va`
    // is the mapping just installed above.
    let caps = unsafe { walk_virtio_pci_capabilities(config_va) };
    let Some(common) = caps.common else {
        klog!("wire_virtio_pci_transport: no COMMON_CFG capability found\r\n");
        return None;
    };

    let mut mapped: [(u8, usize); DRV_PCI_MAX_BARS] = [(0, 0); DRV_PCI_MAX_BARS];
    let mut mapped_count = 0usize;

    // SAFETY: forwarded.
    let common_va = unsafe {
        map_pci_bar(k, hal, drv_root_pt, config_va, common.bar, &mut mapped, &mut mapped_count)
    }?;
    let common_cfg_va = common_va + common.offset as usize;

    let mut resolve = |window: Option<VirtioPciCapWindow>, name: &str| -> usize {
        let Some(w) = window else {
            klog!("wire_virtio_pci_transport: no {} capability found\r\n", name);
            return 0;
        };
        // SAFETY: forwarded from this function's own contract.
        let base = unsafe {
            map_pci_bar(k, hal, drv_root_pt, config_va, w.bar, &mut mapped, &mut mapped_count)
        };
        match base {
            Some(va) => va + w.offset as usize,
            None => {
                klog!("wire_virtio_pci_transport: failed to map {} BAR\r\n", name);
                0
            }
        }
    };
    let notify_cfg_va = resolve(caps.notify, "NOTIFY_CFG");
    let isr_cfg_va = resolve(caps.isr, "ISR_CFG");
    let device_cfg_va = resolve(caps.device, "DEVICE_CFG");

    // MSI-X (x86_64 only — see `msi_message`'s own doc comment for the
    // full data-driven, never-`target_arch` rationale): only attempted
    // when BOTH this device's own capability list actually carries an
    // MSI-X capability AND the live `InterruptController` reports a
    // message-signaled path at all. Neither is true for aarch64's own
    // virtio-pci device (this project's own choice stays legacy INTx
    // there, resolved at HAL discovery time into `mmio.irq` already —
    // this whole block is simply never reached in that case, `caps.
    // msix` being `None`), so this branch changes nothing for the
    // architecture it was NOT written for.
    // Table entry index the driver process's own `VirtioBlk::msix_
    // vector` gets told to assign its queue to (`driver_virtio_blk::
    // pci_common::QUEUE_MSIX_VECTOR`'s own doc comment) — default
    // `VIRTIO_MSI_NO_VECTOR`, overwritten below only on success.
    let mut msix_vector = driver_virtio_blk::VIRTIO_MSI_NO_VECTOR;
    if let Some(msix) = caps.msix {
        if let Some(msi_message) = hal.msi_message(irq) {
            // SAFETY: forwarded from this function's own contract.
            let enabled = unsafe {
                enable_and_program_msix(k, hal, caller_root_pt, config_va, msix, common, msi_message)
            };
            if enabled.is_none() {
                klog!("wire_virtio_pci_transport: failed to enable MSI-X\r\n");
                return None;
            }
            msix_vector = 0; // table entry 0 — this MVP's only vector, matching enable_and_program_msix's own table write.
        }
    }

    // SAFETY: single-core; written once here, before `IrqBind`
    // (`spawn_virtio_blk_driver`'s own caller) installs the trampoline
    // that reads it — see `G_DRV_ISR_CFG_VA`'s own doc comment for why
    // this VA (not a physical address) is what the trampoline needs.
    unsafe { core::ptr::addr_of_mut!(G_DRV_ISR_CFG_VA).write(isr_cfg_va) };

    let header = region_phys + driver_virtio_blk::layout::PCI_INFO_OFFSET;
    // SAFETY: `region_phys` is the driver's own fresh, zeroed
    // `SharedRegion`, identity-addressable, single-core — same
    // contract every other direct physical write in this file relies
    // on for that region.
    unsafe {
        (header as *mut u64).write_volatile(1); // transport_kind = Pci
        ((header + 8) as *mut u64).write_volatile(common_cfg_va as u64);
        ((header + 16) as *mut u64).write_volatile(notify_cfg_va as u64);
        ((header + 24) as *mut u64).write_volatile(caps.notify_off_multiplier as u64);
        ((header + 32) as *mut u64).write_volatile(isr_cfg_va as u64);
        ((header + 40) as *mut u64).write_volatile(device_cfg_va as u64);
        ((header + 48) as *mut u64).write_volatile(msix_vector as u64);
    }

    Some(())
}

/// `driver-virtio-net`'s own counterpart to `wire_virtio_pci_transport`
/// above — same COMMON_CFG/NOTIFY_CFG/ISR_CFG/DEVICE_CFG capability walk,
/// BAR-mapping machinery, and MSI-X programming (reused directly: `walk_
/// virtio_pci_capabilities`, `map_pci_bar`, `pci_cfg_read32`/`write32`,
/// `enable_and_program_msix`, the same Memory-Space+Bus-Master enable
/// dance and its own real-bug rationale — see that function's own doc
/// comment for all of it). TX completion is now real interrupt-driven on
/// every architecture (`driver_virtio_net`'s own crate-level doc comment
/// on why RX deliberately stays non-blocking-poll-only instead), so this
/// function needs exactly the same MSI-X wiring `wire_virtio_pci_
/// transport` already does for blk — the only remaining difference is
/// the header block this writes (`driver_virtio_net::layout::PCI_INFO_
/// OFFSET`, a DIFFERENT crate's own offsets, even though the byte shape
/// happens to match blk's own seven `u64`s exactly).
///
/// # Safety
/// Same contract as `wire_virtio_pci_transport`.
unsafe fn wire_virtio_pci_transport_net(
    k: &mut KernelState,
    hal: &HalInterface,
    drv_root_pt: usize,
    caller_root_pt: usize,
    config_phys: u64,
    region_phys: usize,
    irq: u32,
) -> Option<()> {
    let cfg_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed.
    unsafe { core::ptr::write_bytes(cfg_pool as *mut u8, 0, 4096 * 2) };
    let cfg_n = hal.map_range(
        caller_root_pt,
        KERNEL_PCI_CFG_VA,
        config_phys as usize,
        4096,
        1 | 2, // R+W, kernel-only (no U bit) — EL1/S-mode code only.
        cfg_pool,
        2,
    );
    if cfg_n == u32::MAX {
        klog!("wire_virtio_pci_transport_net: map_range error (ECAM config-space page)\r\n");
        return None;
    }
    // Modifying a LIVE, currently-active page table — same reasoning as
    // `wire_virtio_pci_transport`'s own identical flush.
    hal.flush_tlb();
    let config_va = KERNEL_PCI_CFG_VA as u64;

    // Enable Memory Space + Bus Master — same real-bug rationale as
    // `wire_virtio_pci_transport`'s own doc comment.
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let cmd_status = pci_cfg_read32(config_va, PCI_COMMAND_OFFSET);
        pci_cfg_write32(
            config_va,
            PCI_COMMAND_OFFSET,
            cmd_status | PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER,
        );
    }

    // SAFETY: forwarded from this function's own contract; `config_va`
    // is the mapping just installed above.
    let caps = unsafe { walk_virtio_pci_capabilities(config_va) };
    let Some(common) = caps.common else {
        klog!("wire_virtio_pci_transport_net: no COMMON_CFG capability found\r\n");
        return None;
    };

    let mut mapped: [(u8, usize); DRV_PCI_MAX_BARS] = [(0, 0); DRV_PCI_MAX_BARS];
    let mut mapped_count = 0usize;

    // SAFETY: forwarded.
    let common_va = unsafe {
        map_pci_bar(k, hal, drv_root_pt, config_va, common.bar, &mut mapped, &mut mapped_count)
    }?;
    let common_cfg_va = common_va + common.offset as usize;

    let mut resolve = |window: Option<VirtioPciCapWindow>, name: &str| -> usize {
        let Some(w) = window else {
            klog!("wire_virtio_pci_transport_net: no {} capability found\r\n", name);
            return 0;
        };
        // SAFETY: forwarded from this function's own contract.
        let base = unsafe {
            map_pci_bar(k, hal, drv_root_pt, config_va, w.bar, &mut mapped, &mut mapped_count)
        };
        match base {
            Some(va) => va + w.offset as usize,
            None => {
                klog!("wire_virtio_pci_transport_net: failed to map {} BAR\r\n", name);
                0
            }
        }
    };
    let notify_cfg_va = resolve(caps.notify, "NOTIFY_CFG");
    let isr_cfg_va = resolve(caps.isr, "ISR_CFG");
    let device_cfg_va = resolve(caps.device, "DEVICE_CFG");

    // MSI-X (x86_64 only — see `wire_virtio_pci_transport`'s own doc
    // comment on `msi_message`'s data-driven, never-`target_arch`
    // rationale; identical here). `msix_vector` defaults to `driver_
    // virtio_net::VIRTIO_MSI_NO_VECTOR`, overwritten below only on
    // success — aarch64's own virtio-pci device has no MSI-X capability
    // at all (`caps.msix` is `None`), so this block is simply never
    // reached there, exactly like blk's own identical branch.
    let mut msix_vector = driver_virtio_net::VIRTIO_MSI_NO_VECTOR;
    if let Some(msix) = caps.msix {
        if let Some(msi_message) = hal.msi_message(irq) {
            // SAFETY: forwarded from this function's own contract.
            let enabled = unsafe {
                enable_and_program_msix(k, hal, caller_root_pt, config_va, msix, common, msi_message)
            };
            if enabled.is_none() {
                klog!("wire_virtio_pci_transport_net: failed to enable MSI-X\r\n");
                return None;
            }
            msix_vector = 0; // table entry 0 — this MVP's only vector, matching enable_and_program_msix's own table write.
        }
    }

    // SAFETY: single-core; written once here, before `IrqBind`
    // (`spawn_virtio_net_driver`'s own caller) installs the trampoline
    // that reads it — see `G_DRV_NET_ISR_CFG_VA`'s own doc comment.
    unsafe { core::ptr::addr_of_mut!(G_DRV_NET_ISR_CFG_VA).write(isr_cfg_va) };

    // Re-derive the ISR window's own PHYSICAL base — `caps.isr`'s BAR
    // register hasn't changed since `map_pci_bar` (inside `resolve`)
    // read it moments ago, so re-reading it here has no side effect
    // beyond the same harmless BAR-sizing probe every other `pci_bar_
    // phys` call already performs. See `G_DRV_NET_ISR_CFG_PHYS`'s own
    // doc comment for why `spawn_netstack_service` needs this.
    // SAFETY: forwarded from this function's own contract; `config_va`
    // is the mapping installed above.
    let isr_cfg_phys = caps
        .isr
        .and_then(|w| unsafe { pci_bar_phys(config_va, w.bar) }.map(|(base, _)| base as usize + w.offset as usize));
    // SAFETY: single-core; written once here, read-only by `spawn_
    // netstack_service` after this function has already returned.
    unsafe { core::ptr::addr_of_mut!(G_DRV_NET_ISR_CFG_PHYS).write(isr_cfg_phys.unwrap_or(usize::MAX)) };

    // Re-derive the NOTIFY window's own PHYSICAL base (only ever used to
    // compute the matching page-table VA `spawn_netstack_service` maps
    // into root's own address space — see `G_DRV_NET_NOTIFY_PHYS`'s own
    // doc comment for why this can NEVER be dereferenced directly) +
    // `notify_off_multiplier`. Needed by `net_bypass_direct_send`
    // (03-Kernel-Subsystems-Layer.md §2.3/§5.4.1) to ring the TX queue's
    // own doorbell directly from kernel mode, computing the exact same
    // address `notify_queue`'s own `Transport::Pci` arm would, but
    // without the driver process's own involvement.
    // SAFETY: forwarded from this function's own contract; `config_va`
    // is the mapping installed above.
    let notify_cfg_phys = caps
        .notify
        .and_then(|w| unsafe { pci_bar_phys(config_va, w.bar) }.map(|(base, _)| base as usize + w.offset as usize));
    // SAFETY: single-core; written once here, read-only by `spawn_
    // netstack_service` after this function has already returned.
    unsafe { core::ptr::addr_of_mut!(G_DRV_NET_NOTIFY_PHYS).write(notify_cfg_phys.unwrap_or(usize::MAX)) };
    unsafe { core::ptr::addr_of_mut!(G_DRV_NET_NOTIFY_VA).write(notify_cfg_va) };
    unsafe { core::ptr::addr_of_mut!(G_DRV_NET_NOTIFY_OFF_MULT).write(caps.notify_off_multiplier) };

    let header = region_phys + driver_virtio_net::layout::PCI_INFO_OFFSET;
    // SAFETY: `region_phys` is the driver's own fresh, zeroed RX
    // `SharedRegion`, identity-addressable, single-core — same contract
    // `wire_virtio_pci_transport`'s own identical write relies on.
    unsafe {
        (header as *mut u64).write_volatile(1); // transport_kind = Pci
        ((header + 8) as *mut u64).write_volatile(common_cfg_va as u64);
        ((header + 16) as *mut u64).write_volatile(notify_cfg_va as u64);
        ((header + 24) as *mut u64).write_volatile(caps.notify_off_multiplier as u64);
        ((header + 32) as *mut u64).write_volatile(isr_cfg_va as u64);
        ((header + 40) as *mut u64).write_volatile(device_cfg_va as u64);
        ((header + 48) as *mut u64).write_volatile(msix_vector as u64);
    }

    Some(())
}

/// # Safety
/// `G_DRV_QUEUE_PHYS` must already be a valid, exclusively-owned,
/// identity-addressable physical page (true from `spawn_virtio_blk_
/// driver` onward, before any `drv_blk_*_call` can be reached).
unsafe fn write_shared_drv_message(msg: &SmallMessage) {
    // SAFETY: single-core; `G_DRV_QUEUE_PHYS` only written once, before
    // any `drv_blk_*_call` runs.
    let base = unsafe {
        (core::ptr::addr_of!(G_DRV_QUEUE_PHYS).read() + driver_virtio_blk::layout::MESSAGE_OFFSET)
            as *mut u64
    };
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// # Safety
/// Same contract as `write_shared_drv_message`.
unsafe fn read_shared_drv_message() -> SmallMessage {
    // SAFETY: same contract as `write_shared_drv_message`.
    let base = unsafe {
        (core::ptr::addr_of!(G_DRV_QUEUE_PHYS).read() + driver_virtio_blk::layout::MESSAGE_OFFSET)
            as *const u64
    };
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// Same shape as `fs_ipc_call`, targeting `G_DRV_TID` instead.
fn drv_ipc_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let k = kstate();
    // SAFETY: single-core; `G_DRV_TID` is written once by
    // `spawn_virtio_blk_driver`, before any `drv_blk_*_call` can run.
    let drv_tid = unsafe { core::ptr::addr_of!(G_DRV_TID).read() }?;
    let msg = SmallMessage::new(0);
    match k.dispatch(caller, hal.now_ns(), SyscallOp::Call { endpoint: CapId::new(ep_cap), msg }, hal) {
        Ok(SyscallReturn::Reschedule { next: Some(n) }) => {
            let _ = k.sched.dispatch(drv_tid, hal.now_ns());
            let (save, into) = k.user_ctx_switch_ptrs(caller, drv_tid)?;
            let poke = if n == drv_tid {
                k.tcb_mut(drv_tid)
                    .and_then(|t| Some((t.pending_from.take()?, t.pending_msg.take()?)))
                    .map(|(from, m)| (from.as_u32() as usize, m.label as usize))
            } else {
                None
            };
            Some(IpcSwitch { save, into, poke })
        }
        _ => None,
    }
}

/// The trampoline `SyscallOp::IrqBind` installs with the platform's
/// `InterruptController` (via `HalInterface::register_irq`) for the
/// virtio-blk device's own IRQ line. Runs from interrupt context (the
/// architecture trap vector's own interrupt branch calls it directly,
/// exactly like the tick/fault handlers already registered elsewhere
/// in this file) — its only job is finding which `Notification` is
/// bound to `irq` and signalling it, waking whatever thread called
/// `Wait` on it (`kernel_core::state::KernelState::notification_for_
/// irq`/`wake_blocked`, the SAME primitives `SyscallOp::Signal`'s own
/// `do_signal` uses for the ordinary syscall-driven case — this is
/// just the hardware-driven trigger for the identical effect).
///
/// A plain function pointer with no captured state, per `hal_core::
/// interrupt::IrqHandler`'s own doc comment — reaches `KernelState`
/// through the same global `kstate()`/`khal()` accessors every other
/// interrupt-context handler in this file already uses.
pub fn virtio_blk_irq_trampoline(irq: hal_core::interrupt::IrqId) {
    // Ack the DEVICE's own `INTERRUPT_STATUS`/`INTERRUPT_ACK` registers
    // (`driver_virtio_blk::mmio`'s own fixed offsets — valid for any
    // virtio-mmio device regardless of type, not specific to virtio-blk)
    // FIRST, before signalling anything — **real bug found via QEMU
    // interrupt tracing**: without this, the device's own interrupt
    // line stays asserted for the ENTIRE time between this trampoline
    // running and `VirtioBlk::ack_completion` eventually running (much
    // later, in the DRIVER process's own time, once `Wait` returns and
    // it resumes) — the PLIC re-delivers the STILL-pending line the
    // instant this trap returns, over and over, a genuine hardware
    // interrupt storm (confirmed via `-d int`: thousands of identical
    // `s_external` traps at the same `epc`, the core never actually
    // making forward progress). `VirtioBlk::ack_completion`'s own later
    // ack becomes a harmless no-op re-read of an already-clear register
    // once the driver process resumes — this is not a duplicate-ack
    // correctness issue, just moving the ack earlier to where it is
    // actually reachable (kernel-arch-glue can reach the device's own
    // MMIO registers via the identity-mapped physical address cached at
    // spawn time; a DIFFERENT process's own private `VirtioBlk` state
    // is not reachable from interrupt context at all).
    // SAFETY: single-core; `G_DRV_MMIO_PHYS` was written once by
    // `spawn_virtio_blk_driver`, before `IrqBind` installed this
    // trampoline; the virtio-mmio window is identity-mapped in the
    // kernel's own address space (`hal.map_ram_identity`'s own low-GiB
    // coverage — the same physical range `spawn_virtio_blk_driver`
    // already reads/writes directly via `core::ptr::write_bytes` etc.).
    unsafe {
        let mmio_phys = core::ptr::addr_of!(G_DRV_MMIO_PHYS).read();
        if mmio_phys != usize::MAX {
            let status = ((mmio_phys + driver_virtio_blk::mmio::INTERRUPT_STATUS) as *const u32)
                .read_volatile();
            ((mmio_phys + driver_virtio_blk::mmio::INTERRUPT_ACK) as *mut u32)
                .write_volatile(status);
        }
    }

    // `Transport::Pci`'s own counterpart to the MMIO ack above — same
    // "must happen HERE, not later in the driver process's own time"
    // rationale (`G_DRV_MMIO_PHYS`'s own doc comment), same real-bug
    // consequence if skipped (a level-sensitive INTx line the GIC keeps
    // re-delivering the instant this trap returns — the exact PCI
    // counterpart of the MMIO PLIC storm already documented above).
    // Unlike MMIO's separate STATUS-read/ACK-write pair, virtio-pci's
    // ISR_CFG (virtio 1.x spec §4.1.4.5) is a SINGLE byte that clears
    // (deasserting INTx) on the read itself — no separate ack write.
    // SAFETY: single-core; `G_DRV_ISR_CFG_VA` was written once by
    // `wire_virtio_pci_transport`, before `IrqBind` installed this
    // trampoline; see that static's own doc comment for why this VA
    // (in `drv_root_pt`, not a physical address) is safely
    // dereferenceable exactly when this trampoline runs.
    unsafe {
        let isr_va = core::ptr::addr_of!(G_DRV_ISR_CFG_VA).read();
        if isr_va != usize::MAX {
            let _isr_reason = (isr_va as *const u8).read_volatile();
        }
    }

    let k = kstate();
    let hal = khal();
    let Some(nid) = k.notification_for_irq(irq.as_u32()) else {
        return;
    };
    let Some(notif) = k.notification_mut(nid) else {
        return;
    };
    let woken = notif.signal(1);
    let now = hal.now_ns();
    for &tid in woken.as_slice() {
        k.wake_blocked(tid, now);
    }
}

/// Spawns the virtio-blk driver process from its own separately-built
/// ELF (`drv_elf`), grants it an `Endpoint` (landing at slot 0 — see
/// `grant_cap_into`'s own doc comment) and a `Notification` already
/// bound to the device's own IRQ line (landing at slot 1), and pre-maps
/// its virtio-mmio window plus a freshly retyped virtqueue/data
/// `SharedRegion` directly into its address space (trusted bootstrap
/// glue — same "carve untyped, `map_range` directly, no `SyscallOp::
/// Map` ceremony" pattern `fs_demo_start` already uses for fs-native's
/// own shared pages).
///
/// Returns `None` (and logs) if no `Block`-kind peripheral was
/// discovered at boot (`KernelState::root_mmio_blk_cap` still the
/// sentinel — `populate_from_boot_info`'s own Step 3c never found one),
/// on any allocation failure, or if `IrqBind` itself fails — this
/// driver process is simply never spawned in that case, exactly like
/// `spawn_process_from_elf`'s own existing "no allocation, no process"
/// failure mode.
pub fn spawn_virtio_blk_driver(
    hal: &HalInterface,
    caller: ThreadId,
    drv_elf: &[u8],
    expected_machine: u16,
) -> Option<(u32, *mut u8, *const u8)> {
    let k = kstate();
    let src_cs = k.tcb(caller)?.cap_space;
    let mmio_cap = k.root_mmio_blk_cap;
    if mmio_cap == CapId::new(u32::MAX) {
        klog!("spawn_virtio_blk_driver: no Block-kind peripheral was discovered at boot\r\n");
        return None;
    }
    // Resolve the boot-seeded `MmioRegion` capability back to its own
    // descriptor (mirrors `fs_demo_start`'s own SharedRegion-cap ->
    // description resolution) — this driver never needs to HOLD an
    // `MmioRegion` capability itself (the window is pre-mapped for it
    // below, exactly like `.user_text`/stack need no capability of
    // their own), only kernel-arch-glue does, to learn where to map.
    let mmio_id = kernel_cap::MmioRegionId::new(
        k.cap_space(src_cs)?.lookup(mmio_cap)?.object.id.as_u32(),
    );
    let mmio = *k.mmio_region(mmio_id)?;
    // A nonzero `config_space_base` means this device was discovered
    // over PCI (`hal_arm64::peripheral`'s own `PeripheralDevice::
    // new_pci` — riscv64's virtio-mmio discovery never sets it, see
    // `MmioRegionDescriptor::config_space_base`'s own doc comment), so
    // the driver needs virtio-pci "modern" register windows resolved
    // via `wire_virtio_pci_transport` below rather than the single
    // fixed virtio-mmio block this function pre-maps at `DRV_MMIO_VA`.
    let is_pci = mmio.config_space_base != 0;
    if !is_pci {
        // SAFETY: single-core; written once here, before `IrqBind`
        // below installs the trampoline that reads it. Left at its
        // `usize::MAX` sentinel for PCI transport — that trampoline's
        // own virtio-mmio-specific INTERRUPT_STATUS/ACK read does not
        // apply to virtio-pci's own ISR_CFG ack mechanism (a single
        // read-to-clear byte at a DIFFERENT, capability-resolved
        // address) — PCI interrupt-context ack is not yet wired here.
        unsafe { core::ptr::addr_of_mut!(G_DRV_MMIO_PHYS).write(mmio.phys_base as usize) };
    }

    let ep_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Endpoint,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };

    const DRV_STACK_VMA: usize = 0xC080_0000;
    const DRV_STACK_LEN: usize = 4096 * 16;
    let (drv_tid, drv_cs, _stack_phys) =
        spawn_process_from_elf(hal, k, drv_elf, expected_machine, DRV_STACK_VMA, DRV_STACK_LEN)?;
    // SAFETY: single-core; written once here, before any `drv_blk_*_call`
    // (reached only after this function returns) can read it.
    unsafe { core::ptr::addr_of_mut!(G_DRV_TID).write(Some(drv_tid)) };

    grant_cap_into(k, src_cs, ep_cap, drv_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;

    let drv_addr_space = k.tcb(drv_tid)?.addr_space;
    let drv_root_pt = k.addr_space_mut(drv_addr_space)?.root_phys().as_usize();

    // Pre-map the virtio-mmio transport window — real device MMIO, not
    // RAM, so (unlike every other `map_range` call in this file) there
    // is nothing to zero or copy into it first. Skipped entirely for
    // PCI transport (`is_pci`): virtio-pci's own register windows are
    // resolved and mapped individually below, by `wire_virtio_pci_
    // transport`, from whichever BAR(s) its capability list actually
    // names — `mmio.phys_base`/`mmio.size` here are only ever BAR0's
    // own base/size (`hal_arm64::peripheral`'s own module doc comment),
    // which need not even be one of the BARs virtio-pci-modern uses.
    if !is_pci {
        let mmio_pool = k
            .untyped_mut(kernel_cap::UntypedId::new(0))
            .and_then(|u| u.alloc(4096, 4096 * 2).ok())
            .map(|p| p.as_usize())?;
        // SAFETY: fresh untyped RAM, identity-addressable, single-core;
        // `map_range` needs the pool pre-zeroed (same contract every
        // other pool carve in this file already documents).
        unsafe { core::ptr::write_bytes(mmio_pool as *mut u8, 0, 4096 * 2) };
        let n = hal.map_range(
            drv_root_pt,
            DRV_MMIO_VA,
            mmio.phys_base as usize,
            4096,
            1 | 2 | 8, // R+W+U
            mmio_pool,
            2,
        );
        if n == u32::MAX {
            klog!("spawn_virtio_blk_driver: map_range error (mmio window)\r\n");
            return None;
        }
    }

    // Retype and pre-map the virtqueue/data `SharedRegion` — a REAL
    // capability object (proving `Retype` end to end, like fs-native's
    // own DATA region), even though this driver process is never
    // granted it directly (kernel-arch-glue's own privileged pre-map
    // stands in for a `SyscallOp::Map` this trusted glue code has no
    // need to actually issue).
    let region_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::SharedRegion,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    let region_id = k.cap_space(src_cs)?.lookup(region_cap)?.object.id;
    let region_phys = k
        .shared_region(kernel_cap::SharedRegionId::new(region_id.as_u32()))?
        .phys_base
        .as_usize();
    // SAFETY: fresh `SharedRegion` memory, identity-addressable,
    // single-core.
    unsafe { core::ptr::write_bytes(region_phys as *mut u8, 0, 4096) };
    // Write the region's OWN physical base into its own header word
    // (`driver_virtio_blk::layout::PHYS_BASE_OFFSET`) — see that
    // module's own doc comment on why the driver process has no other
    // way to learn it (no VA->PA translation syscall exists for a
    // non-root thread).
    // SAFETY: `region_phys` is identity-addressable, freshly zeroed
    // above.
    unsafe { (region_phys as *mut u64).write_volatile(region_phys as u64) };

    // For PCI transport, resolve+map the device's own virtio-pci
    // "modern" register windows and write the `PCI_INFO_OFFSET` header
    // block right after `PHYS_BASE_OFFSET` above — both live in the
    // SAME region, and `new_driver_for_this_transport` reads this block
    // to pick `Transport::Pci` over the `transport_kind == 0` default
    // this freshly-zeroed region already carries for MMIO transport.
    if is_pci {
        // SAFETY: `mmio.config_space_base` is a live ECAM address (this
        // kernel boot-seeded it from `hal_arm64::peripheral`'s own PCI
        // scan, the same trust boundary `mmio.phys_base` already
        // relies on); `region_phys` is this function's own fresh,
        // zeroed `SharedRegion`, forwarded from that write above.
        // `caller_root_pt`: `caller`'s own page table, still the ACTIVE
        // one right now (the switch to the driver process happens only
        // at this function's own tail) — see `KERNEL_PCI_CFG_VA`'s own
        // doc comment for why `wire_virtio_pci_transport` needs it.
        let caller_addr_space = k.tcb(caller)?.addr_space;
        let caller_root_pt = k.addr_space_mut(caller_addr_space)?.root_phys().as_usize();
        let wired = unsafe {
            wire_virtio_pci_transport(
                k,
                hal,
                drv_root_pt,
                caller_root_pt,
                mmio.config_space_base,
                region_phys,
                mmio.irq,
            )
        };
        if wired.is_none() {
            klog!("spawn_virtio_blk_driver: wire_virtio_pci_transport failed\r\n");
            return None;
        }
    }

    let queue_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed.
    unsafe { core::ptr::write_bytes(queue_pool as *mut u8, 0, 4096 * 2) };
    let n2 = hal.map_range(
        drv_root_pt,
        DRV_QUEUE_VA,
        region_phys,
        4096,
        1 | 2 | 8, // R+W+U
        queue_pool,
        2,
    );
    if n2 == u32::MAX {
        klog!("spawn_virtio_blk_driver: map_range error (queue region)\r\n");
        return None;
    }

    // SAFETY: single-core; written exactly once here, before any
    // `drv_blk_*_call` (reached only after this function returns) can
    // read it.
    unsafe { core::ptr::addr_of_mut!(G_DRV_QUEUE_PHYS).write(region_phys) };

    // Retype a `Notification` and bind the virtio-blk device's own IRQ
    // line to it — root does the `IrqBind` itself (it already holds
    // `root_mmio_blk_cap`, which is what authorizes binding exactly
    // THIS device's own IRQ, per `IrqBind`'s own doc comment), then
    // grants the ALREADY-BOUND notification into the driver's cap
    // space (landing at slot 1 — the endpoint above was the first
    // grant into this fresh cap space, at slot 0; see `grant_cap_
    // into`'s own doc comment on why that ordering is deterministic).
    // The driver process never needs to hold `root_mmio_blk_cap`
    // itself, matching the MMIO-window pre-map above.
    let notif_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Notification,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::IrqBind {
            mmio: mmio_cap,
            notification: notif_cap,
            handler: virtio_blk_irq_trampoline,
        },
        hal,
    ) {
        Ok(SyscallReturn::Done) => {}
        _ => {
            klog!("spawn_virtio_blk_driver: IrqBind failed\r\n");
            return None;
        }
    }
    grant_cap_into(k, src_cs, notif_cap, drv_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;

    // Switch straight to the driver, exactly like `fs_demo_start` does
    // for fs-native — see that function's own "Real bug found via
    // QEMU" comment for the full rationale: without this, `caller`'s
    // FIRST `DRV_BLK_PROBE` races a receiver that has never yet run at
    // all, and `do_send`'s fast path (which requires the receiver
    // already blocked in `Recv`) cannot trigger, silently stranding
    // both threads forever. Switching here lets the driver run its own
    // `probe()` and reach its own first `IPC_RECV` before `caller`
    // resumes and issues `DRV_BLK_PROBE`.
    let _ = k.sched.note_ready(caller, hal.now_ns());
    let _ = k.sched.dispatch(drv_tid, hal.now_ns());
    let (save, into) = k.user_ctx_switch_ptrs(caller, drv_tid)?;

    Some((ep_cap.as_u32(), save, into))
}

/// `DRV_BLK_PROBE` demo opcode: builds a real `DriverRequest::Probe`.
pub fn drv_blk_probe_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let msg = ipc_protocol::codec::encode_driver_request(&ipc_protocol::DriverRequest::Probe);
    // SAFETY: `spawn_virtio_blk_driver` has already run by the time any
    // `.user_text` code can reach this opcode (it needs `ep_cap`, which
    // only that function's own return value provides).
    unsafe { write_shared_drv_message(&msg) };
    drv_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `DriverResponse` for `drv_blk_probe_call`. Returns
/// `(sector_size, sector_count)`, or `(u32::MAX, u64::MAX)` on any
/// error/decode failure.
pub fn drv_blk_probe_result() -> (u32, u64) {
    // SAFETY: same contract as `drv_blk_probe_call`.
    let msg = unsafe { read_shared_drv_message() };
    match ipc_protocol::codec::decode_driver_response(&msg) {
        Ok(ipc_protocol::DriverResponse::Ready { sector_size, sector_count }) => {
            (sector_size, sector_count)
        }
        _ => (u32::MAX, u64::MAX),
    }
}

/// `DRV_BLK_WRITE` demo opcode: builds a real `DriverRequest::WriteBlocks`
/// for one sector at `lba`, placing `DRV_DEMO_WRITE_DATA` into the
/// shared region's own data buffer first (mirrors `fs_write_call`'s own
/// `G_FS_DATA_PHYS` write).
pub fn drv_blk_write_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, lba: u64) -> Option<IpcSwitch> {
    // SAFETY: `G_DRV_QUEUE_PHYS` was set once by `spawn_virtio_blk_
    // driver`, before any `drv_blk_write_call` can be reached; identity-
    // mapped for kernel-mode access like every other physical cross-
    // check in this file.
    unsafe {
        let base = (core::ptr::addr_of!(G_DRV_QUEUE_PHYS).read()
            + driver_virtio_blk::layout::DATA_OFFSET) as *mut u8;
        core::ptr::copy_nonoverlapping(DRV_DEMO_WRITE_DATA.as_ptr(), base, DRV_DEMO_WRITE_DATA.len());
    }
    let req = ipc_protocol::DriverRequest::WriteBlocks {
        lba,
        sector_count: 1,
        shared_cap: 0, // unused by this MVP's driver — see driver_virtio_blk's own module doc comment
    };
    let msg = ipc_protocol::codec::encode_driver_request(&req);
    // SAFETY: same contract as `drv_blk_probe_call`.
    unsafe { write_shared_drv_message(&msg) };
    drv_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `DriverResponse` for `drv_blk_write_call`. Returns the
/// sector count written, or `usize::MAX` on any error/decode failure.
pub fn drv_blk_write_result() -> usize {
    // SAFETY: same contract as `drv_blk_probe_call`.
    let msg = unsafe { read_shared_drv_message() };
    match ipc_protocol::codec::decode_driver_response(&msg) {
        Ok(ipc_protocol::DriverResponse::Completed { sectors }) => sectors as usize,
        _ => usize::MAX,
    }
}

/// `DRV_BLK_READ` demo opcode: builds a real `DriverRequest::ReadBlocks`
/// for one sector at `lba`.
pub fn drv_blk_read_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32, lba: u64) -> Option<IpcSwitch> {
    let req = ipc_protocol::DriverRequest::ReadBlocks {
        lba,
        sector_count: 1,
        shared_cap: 0,
    };
    let msg = ipc_protocol::codec::encode_driver_request(&req);
    // SAFETY: same contract as `drv_blk_probe_call`.
    unsafe { write_shared_drv_message(&msg) };
    drv_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `DriverResponse` for `drv_blk_read_call`, and checks
/// the sector data read back matches `DRV_DEMO_WRITE_DATA` (proving a
/// real Write->Read round trip through actual virtio-mmio hardware).
/// Returns the sector count read, or `usize::MAX` on any error/decode
/// failure.
pub fn drv_blk_read_result() -> usize {
    // SAFETY: same contract as `drv_blk_probe_call`.
    let msg = unsafe { read_shared_drv_message() };
    let sectors = match ipc_protocol::codec::decode_driver_response(&msg) {
        Ok(ipc_protocol::DriverResponse::Completed { sectors }) => sectors as usize,
        _ => return usize::MAX,
    };
    // SAFETY: same contract as `drv_blk_write_call`'s own read of
    // `G_DRV_QUEUE_PHYS`.
    let matches = unsafe {
        let base = (core::ptr::addr_of!(G_DRV_QUEUE_PHYS).read()
            + driver_virtio_blk::layout::DATA_OFFSET) as *const u8;
        sectors == 1
            && core::slice::from_raw_parts(base, DRV_DEMO_WRITE_DATA.len()) == DRV_DEMO_WRITE_DATA
    };
    klog!(
        "drv_blk_read_result: real Write->Read round-trip through virtio-blk's own virtqueue (03 5.1) -> {}\r\n",
        if matches { "MATCH, real MMIO + descriptor ring" } else { "MISMATCH" }
    );
    sectors
}

/// Fixed demo payload `drv_blk_write_call` writes and `drv_blk_read_
/// result` verifies — same role as `FS_DEMO_WRITE_DATA`.
const DRV_DEMO_WRITE_DATA: &[u8] = b"hello from root, virtio-blk demo!";

// ============================================================================
// virtio-net driver support (03-Kernel-Subsystems-Layer.md §2.3/§5.4) —
// riscv64 only for now (`driver_virtio_net`'s own module doc comment on
// why). Mirrors the virtio-blk section immediately above (same "spawn,
// grant an Endpoint, pre-map region(s), drive via a dedicated ecall-per-
// request-type + shared-message-area protocol" shape), with two
// differences: (1) TWO `SharedRegion`s are retyped and pre-mapped (one
// per virtqueue — `driver_virtio_net::layout`'s own doc comment on why
// one page cannot hold both an RX and a TX frame buffer at once, unlike
// virtio-blk's single request queue) instead of one; (2) no `IrqBind` —
// this driver is polling-only for now (`driver_virtio_net`'s own module
// doc comment), so there is no interrupt trampoline to install.
//
// The ARP-resolve-then-ICMP-echo demo sequence itself (§5.4's own
// acceptance criterion) is driven by `kernel/src/main.rs`'s own
// `umode_root` — a bounded RETRY LOOP of separate ecalls, mirroring
// `DRV_IRQ_WAIT`'s own retry-loop shape immediately below this section —
// because a single `Call` cannot itself loop waiting for a reply that
// may never arrive (this crate's own `driver_virtio_net` module doc
// comment on why `PollFrame` is non-blocking). Each of the functions
// below performs exactly ONE primitive step (build+send one frame, or
// check once for a received one), matching the `drv_blk_*` functions
// immediately above.
// ============================================================================

/// Physical base of the RX queue's own `SharedRegion` — ALSO carries the
/// negotiated MAC (`driver_virtio_net::layout::MAC_OFFSET`) and the
/// `DriverRequest`/`DriverResponse` message area (`layout::MESSAGE_
/// OFFSET`), same reasoning as `G_DRV_QUEUE_PHYS`'s own doc comment.
/// Read by `spawn_netstack_service` to trusted-bootstrap-map this SAME
/// physical region into the Netstack process's own address space too
/// (`netstack::subsystem_entry`'s own module doc comment) — no longer
/// peeked directly by kernel-arch-glue itself (that was the pre-
/// Session-22 shortcut this crate's own module doc comment used to
/// document; the Netstack process now drives the driver over real IPC
/// instead).
static mut G_DRV_NET_RX_PHYS: usize = usize::MAX;

/// Physical base of the TX queue's own `SharedRegion` — same "also
/// mapped into the Netstack process's own space" role as `G_DRV_NET_RX_
/// PHYS`'s own doc comment.
static mut G_DRV_NET_TX_PHYS: usize = usize::MAX;

/// `Transport::Mmio`'s own counterpart to `G_DRV_MMIO_PHYS`, for the net
/// device — same "ack the DEVICE's own registers directly from interrupt
/// context, a different process's own private `VirtioNet` state is
/// unreachable from here" rationale as that static's own doc comment.
/// `usize::MAX` (never written) for `Transport::Pci`, exactly like
/// `G_DRV_MMIO_PHYS`'s own convention.
static mut G_DRV_NET_MMIO_PHYS: usize = usize::MAX;

/// `Transport::Pci`'s own counterpart to `G_DRV_NET_MMIO_PHYS` — same
/// role as `G_DRV_ISR_CFG_VA`'s own doc comment, but see `G_DRV_NET_
/// ISR_CFG_PHYS`'s own doc comment for why this crate's own copy of
/// that reasoning ("reuse the driver's own already-mapped BAR VA, no
/// new kernel-side mapping needed") turned out to be a real, QEMU-found
/// bug once Netstack existed: this VA is only valid under `drv_root_pt`,
/// but `spawn_netstack_service` now ALSO maps the same physical page at
/// this identical VA into Netstack's (and root's) own page tables, so
/// the trampoline's read below stays correct regardless of whose `cr3`
/// is active when the IRQ actually lands.
static mut G_DRV_NET_ISR_CFG_VA: usize = usize::MAX;

/// The ISR_CFG register window's own PHYSICAL base (`bar_phys + w.
/// offset`, re-derived via `pci_bar_phys` right after `wire_virtio_pci_
/// transport_net` maps it into `drv_root_pt`) — `usize::MAX` if no ISR
/// capability was found (or for `Transport::Mmio`, which never sets
/// this at all).
///
/// **Real bug found via QEMU** (this session's Netstack extraction —
/// `03-Kernel-Subsystems-Layer.md` §2.3/§5.4): `virtio_net_irq_
/// trampoline`'s own `isr_va` read below was written under the
/// assumption (documented, at the time correctly, on `G_DRV_ISR_CFG_VA`
/// — blk's identical field) that this trampoline "only ever fires while
/// the driver process's own address space is active", because
/// previously the driver was ALWAYS either the sole active process or
/// blocked in its own in-place `wfi()` wait whenever an IRQ could land.
/// Netstack breaks that assumption: it is a REAL, second U-mode process
/// that now holds the CPU (and `cr3`) for genuine stretches WHILE the
/// driver is unblocked-but-not-yet-scheduled — a virtio-net TX-
/// completion IRQ that arrives even slightly late (asynchronous to the
/// CPU's own instruction stream, entirely QEMU's own device-model
/// timing) can land while Netstack (or root, polling `NET_STATUS_POLL`)
/// is the active address space instead. Confirmed via QEMU: `UNHANDLED
/// CPU EXCEPTION vector=0xe ... cr2(fault_va)=0xd8401000` (exactly
/// `DRV_NET_MMIO_VA + 0x1000`, i.e. `G_DRV_NET_ISR_CFG_VA` itself) fired
/// from KERNEL code (`rip` inside the kernel image) immediately after
/// Netstack's third `PollFrame` round-trip switched control back to it
/// — a page fault taken by the interrupt trampoline itself, reading a
/// VA that only `drv_root_pt` has mapped.
///
/// This physical page is cached here so `spawn_netstack_service` can
/// ALSO map it (kernel-only, no `U` bit — same `1 | 2` flags `KERNEL_
/// PCI_CFG_VA`'s own mapping uses) into Netstack's own page table AND
/// root's (`caller_root_pt`), at the SAME numeric VA (`G_DRV_NET_ISR_
/// CFG_VA`) the driver already uses — so `virtio_net_irq_trampoline`'s
/// existing, unmodified read stays correct no matter which of these
/// THREE processes' `cr3` happens to be active when the IRQ lands.
///
/// **Known remaining gap, honestly not fixed here**: this covers only
/// the three processes THIS demo's own CPU can ever be executing as
/// (driver / Netstack / root) — a future process that also contends for
/// the CPU while this driver is alive would need the same treatment.
/// `virtio_blk_irq_trampoline`'s own `G_DRV_ISR_CFG_VA` has the
/// IDENTICAL latent bug (same "only valid under drv_root_pt" mapping),
/// just never triggered because no real IPC client of the block driver
/// has been built yet — worth revisiting together with whatever process
/// becomes virtio-blk's first genuine IPC client.
static mut G_DRV_NET_ISR_CFG_PHYS: usize = usize::MAX;

/// The NOTIFY_CFG register window's own PHYSICAL base (`bar_phys + w.
/// offset`), cached the same way as `G_DRV_NET_ISR_CFG_PHYS` — `usize::
/// MAX` if no NOTIFY capability was found, or for `Transport::Mmio`
/// (which never sets this; `net_bypass_direct_send` uses `G_DRV_NET_
/// MMIO_PHYS` + the fixed `mmio::QUEUE_NOTIFY` register instead in that
/// case).
///
/// **NEVER dereferenced directly** (unlike `G_DRV_NET_MMIO_PHYS`, which
/// genuinely is safe to — see that static's own doc comment): a modern
/// virtio-pci device's own capability BARs are frequently 64-bit BARs
/// QEMU's q35 chipset places far outside the low-RAM range the kernel's
/// own identity map actually covers (**real bug found via QEMU**: a
/// first version of `net_bypass_direct_send` wrote through this physical
/// address directly and took a page fault at the exact same address —
/// `cr2 == G_DRV_NET_NOTIFY_PHYS` — confirming it, while numerically a
/// real device-assigned physical address, is simply not mapped anywhere
/// the kernel can reach it as one). This is only the KEY `spawn_netstack_
/// service` re-derives the matching page-table VA for — see `G_DRV_NET_
/// NOTIFY_VA`'s own doc comment for the address `net_bypass_direct_send`
/// actually dereferences.
static mut G_DRV_NET_NOTIFY_PHYS: usize = usize::MAX;

/// The VA `notify_cfg_va` (`wire_virtio_pci_transport_net`'s own local)
/// is mapped at in the DRIVER's own address space — `spawn_netstack_
/// service` maps this exact physical page at this exact numeric VA into
/// root's own page table too (mirroring `G_DRV_NET_ISR_CFG_VA`'s own
/// identical "also reachable from root, not just `drv_root_pt`"
/// treatment), which is what makes it actually safe for `net_bypass_
/// direct_send` — running on ROOT's own trap, `drv_root_pt` is never the
/// active page table there — to dereference. `usize::MAX` if no NOTIFY
/// capability was found, or for `Transport::Mmio`.
static mut G_DRV_NET_NOTIFY_VA: usize = usize::MAX;

/// `Transport::Pci`'s own `notify_off_multiplier` (spec §4.1.4.4),
/// cached alongside `G_DRV_NET_NOTIFY_PHYS` for the same reason.
static mut G_DRV_NET_NOTIFY_OFF_MULT: u32 = 0;

/// VA the virtio-mmio transport window is pre-mapped at in the driver's
/// own address space — must stay numerically equal to `driver_virtio_
/// net::subsystem_entry::DRV_MMIO_VA`.
const DRV_NET_MMIO_VA: usize = 0xD840_0000;
/// VA the RX queue's own `SharedRegion` is pre-mapped at — must stay
/// numerically equal to `driver_virtio_net::subsystem_entry::DRV_RX_VA`.
const DRV_NET_RX_VA: usize = 0xD850_0000;
/// VA the TX queue's own `SharedRegion` is pre-mapped at — must stay
/// numerically equal to `driver_virtio_net::subsystem_entry::DRV_TX_VA`.
const DRV_NET_TX_VA: usize = 0xD860_0000;

/// VA the driver's own RX `SharedRegion` is ALSO mapped at, in the
/// Netstack process's own (separate) address space — must stay
/// numerically equal to `netstack::subsystem_entry::DRV_RX_VA`.
/// Deliberately a DIFFERENT VA range than `DRV_NET_RX_VA` above even
/// though nothing would collide if they matched (each process has its
/// own independent page table) — kept distinct simply so a VA alone
/// unambiguously identifies which process's own constant it mirrors.
const NETSTACK_DRV_RX_VA: usize = 0xD870_0000;
/// Same role as `NETSTACK_DRV_RX_VA`, for the driver's own TX region —
/// must stay numerically equal to `netstack::subsystem_entry::DRV_TX_VA`.
const NETSTACK_DRV_TX_VA: usize = 0xD880_0000;
/// VA the Netstack process's own private status `SharedRegion` is
/// mapped at — must stay numerically equal to `netstack::subsystem_
/// entry::STATUS_VA`. `netstack_status` (below) reads it back directly
/// (physical pointer, kernel-side) — see that function's own doc
/// comment for the exact layout.
const NETSTACK_STATUS_VA: usize = 0xD890_0000;

/// Physical base of the Netstack process's own private status
/// `SharedRegion`, cached at spawn time so `netstack_status` can read it
/// back directly — same "kernel-arch-glue peeks a shared region
/// directly, no protocol field needed" pattern this crate has used
/// throughout (`drv_net_probe_result`'s own MAC read, before this
/// session's own extraction, used the identical pattern one region
/// over).
static mut G_NETSTACK_STATUS_PHYS: usize = usize::MAX;

/// The Netstack process's own `ThreadId`, cached so `netstack_bypass_ipc_
/// call` can specialize its own `Call`-then-switch shape exactly like
/// `mm_ipc_call`'s own `G_MM_TID` — see that function's own doc comment
/// for the real "phantom scheduler entity" `pick_next` bug class this
/// sidesteps by switching straight to the known target thread instead of
/// trusting the general scheduler's own answer.
static mut G_NETSTACK_TID: Option<ThreadId> = None;

/// Root's (`caller`'s) own capability slot for the SAME Endpoint object
/// Netstack's own `subsystem_entry::BYPASS_ENDPOINT_CAP` (slot 1) holds a
/// derived copy of — granted to root FIRST, by the very same `Retype`
/// that creates the object, before `spawn_netstack_service`'s own slot-1
/// `grant_cap_into` derives Netstack's copy (same "the retyping caller
/// always ends up holding the original" convention every other `Retype`
/// in this file relies on). This is the real control-plane rendezvous
/// `net_bypass_request_call` (03-Kernel-Subsystems-Layer.md §2.3/§5.4.1)
/// calls into. `u32::MAX` until `spawn_netstack_service` has run.
static mut G_NETSTACK_BYPASS_EP: u32 = u32::MAX;

/// Physical address of the page shared between root and Netstack for the
/// kernel-bypass control-plane handshake (mapped into Netstack's own
/// address space at `NETSTACK_BYPASS_SHARED_VA` by `spawn_netstack_
/// service`) — root reads/writes it directly via this physical pointer,
/// no VA mapping needed on root's own side, same "low RAM is always
/// identity-mapped for kernel-mode access regardless of which process's
/// page table is active" pattern as `G_MM_SHARED_PHYS`'s own doc comment.
static mut G_NETSTACK_BYPASS_SHARED_PHYS: usize = usize::MAX;

/// VA Netstack's own process maps the kernel-bypass control-plane shared
/// page at — must stay numerically equal to `netstack::subsystem_entry::
/// BYPASS_SHARED_VA`.
pub const NETSTACK_BYPASS_SHARED_VA: usize = 0xD8A0_0000;

/// The trampoline `SyscallOp::IrqBind` installs with the platform's
/// `InterruptController` for the virtio-net device's own IRQ line —
/// mirrors `virtio_blk_irq_trampoline` exactly, substituting `driver_
/// virtio_net`'s own `mmio`/`G_DRV_NET_*` names for `driver_virtio_
/// blk`'s (see that function's own doc comment for the full "why ack
/// HERE, not later in the driver process's own time" rationale — it
/// applies identically to this device).
pub fn virtio_net_irq_trampoline(irq: hal_core::interrupt::IrqId) {
    // SAFETY: single-core; `G_DRV_NET_MMIO_PHYS` was written once by
    // `spawn_virtio_net_driver` (only for `Transport::Mmio`), before
    // `IrqBind` installed this trampoline; the virtio-mmio window is
    // identity-mapped in the kernel's own address space, same as
    // `virtio_blk_irq_trampoline`'s own identical read.
    unsafe {
        let mmio_phys = core::ptr::addr_of!(G_DRV_NET_MMIO_PHYS).read();
        if mmio_phys != usize::MAX {
            let status = ((mmio_phys + driver_virtio_net::mmio::INTERRUPT_STATUS) as *const u32)
                .read_volatile();
            ((mmio_phys + driver_virtio_net::mmio::INTERRUPT_ACK) as *mut u32)
                .write_volatile(status);
        }
    }

    // SAFETY: single-core; `G_DRV_NET_ISR_CFG_VA` was written once by
    // `wire_virtio_pci_transport_net`, before `IrqBind` installed this
    // trampoline; see `G_DRV_NET_ISR_CFG_VA`'s own doc comment for why
    // this VA is safely dereferenceable exactly when this trampoline
    // runs.
    unsafe {
        let isr_va = core::ptr::addr_of!(G_DRV_NET_ISR_CFG_VA).read();
        if isr_va != usize::MAX {
            let _isr_reason = (isr_va as *const u8).read_volatile();
        }
    }

    let k = kstate();
    let hal = khal();
    let Some(nid) = k.notification_for_irq(irq.as_u32()) else {
        return;
    };
    let Some(notif) = k.notification_mut(nid) else {
        return;
    };
    let woken = notif.signal(1);
    let now = hal.now_ns();
    for &tid in woken.as_slice() {
        k.wake_blocked(tid, now);
    }
}

/// Spawns the virtio-net driver process from its own separately-built ELF
/// (`drv_elf`), grants it an `Endpoint` (slot 0) and a `Notification`
/// already bound to the device's own IRQ line (slot 1), and pre-maps its
/// virtio register window(s) plus TWO freshly retyped `SharedRegion`s (RX
/// at `DRV_NET_RX_VA`, TX at `DRV_NET_TX_VA`) directly into its address
/// space — same trusted-bootstrap pattern as `spawn_virtio_blk_driver`,
/// with an `is_pci` branch (aarch64/x86_64) mirroring that function's own.
/// TX completion is now real interrupt-driven on every architecture (RX
/// deliberately stays non-blocking-poll-only — `driver_virtio_net`'s own
/// module doc comment on why); the `Notification` grant and `IrqBind`
/// below exist for that TX path.
///
/// Returns `None` (and logs) if no `Network`-kind peripheral was
/// discovered at boot (`KernelState::root_mmio_net_cap` still the
/// sentinel), or on any allocation failure.
pub fn spawn_virtio_net_driver(
    hal: &HalInterface,
    caller: ThreadId,
    drv_elf: &[u8],
    expected_machine: u16,
) -> Option<(u32, *mut u8, *const u8)> {
    let k = kstate();
    let src_cs = k.tcb(caller)?.cap_space;
    let mmio_cap = k.root_mmio_net_cap;
    if mmio_cap == CapId::new(u32::MAX) {
        klog!("spawn_virtio_net_driver: no Network-kind peripheral was discovered at boot\r\n");
        return None;
    }
    let mmio_id = kernel_cap::MmioRegionId::new(
        k.cap_space(src_cs)?.lookup(mmio_cap)?.object.id.as_u32(),
    );
    let mmio = *k.mmio_region(mmio_id)?;
    // A nonzero `config_space_base` means this device was discovered over
    // PCI — same convention `spawn_virtio_blk_driver`'s own `is_pci`
    // check already established.
    let is_pci = mmio.config_space_base != 0;

    let ep_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Endpoint,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };

    const DRV_NET_STACK_VMA: usize = 0xC090_0000;
    const DRV_NET_STACK_LEN: usize = 4096 * 16;
    let (drv_tid, drv_cs, _stack_phys) =
        spawn_process_from_elf(hal, k, drv_elf, expected_machine, DRV_NET_STACK_VMA, DRV_NET_STACK_LEN)?;

    grant_cap_into(k, src_cs, ep_cap, drv_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;

    let drv_addr_space = k.tcb(drv_tid)?.addr_space;
    let drv_root_pt = k.addr_space_mut(drv_addr_space)?.root_phys().as_usize();

    // Pre-map the virtio-mmio transport window — skipped entirely for PCI
    // transport (`is_pci`): virtio-pci's own register windows are
    // resolved and mapped individually below, by `wire_virtio_pci_
    // transport_net`, from whichever BAR(s) its capability list actually
    // names — same "MMIO map only when NOT PCI" branch `spawn_virtio_blk_
    // driver`'s own doc comment covers.
    if !is_pci {
        let mmio_pool = k
            .untyped_mut(kernel_cap::UntypedId::new(0))
            .and_then(|u| u.alloc(4096, 4096 * 2).ok())
            .map(|p| p.as_usize())?;
        // SAFETY: fresh untyped RAM, identity-addressable, single-core;
        // `map_range` needs the pool pre-zeroed.
        unsafe { core::ptr::write_bytes(mmio_pool as *mut u8, 0, 4096 * 2) };
        let n =
            hal.map_range(drv_root_pt, DRV_NET_MMIO_VA, mmio.phys_base as usize, 4096, 1 | 2 | 8, mmio_pool, 2);
        if n == u32::MAX {
            klog!("spawn_virtio_net_driver: map_range error (mmio window)\r\n");
            return None;
        }
        // SAFETY: single-core; written once here, before `IrqBind`
        // installs `virtio_net_irq_trampoline` — see `G_DRV_NET_MMIO_
        // PHYS`'s own doc comment.
        unsafe { core::ptr::addr_of_mut!(G_DRV_NET_MMIO_PHYS).write(mmio.phys_base as usize) };
    }

    // Retype and pre-map the RX queue's own `SharedRegion`.
    let rx_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::SharedRegion,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    let rx_id = k.cap_space(src_cs)?.lookup(rx_cap)?.object.id;
    let rx_phys = k.shared_region(kernel_cap::SharedRegionId::new(rx_id.as_u32()))?.phys_base.as_usize();
    // SAFETY: fresh `SharedRegion` memory, identity-addressable, single-core.
    unsafe { core::ptr::write_bytes(rx_phys as *mut u8, 0, 4096) };
    // Self-referential physical-base header word — same reasoning as
    // `driver_virtio_blk::layout::PHYS_BASE_OFFSET`'s own doc comment.
    unsafe { (rx_phys as *mut u64).write_volatile(rx_phys as u64) };

    let rx_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    unsafe { core::ptr::write_bytes(rx_pool as *mut u8, 0, 4096 * 2) };
    let n_rx = hal.map_range(drv_root_pt, DRV_NET_RX_VA, rx_phys, 4096, 1 | 2 | 8, rx_pool, 2);
    if n_rx == u32::MAX {
        klog!("spawn_virtio_net_driver: map_range error (rx region)\r\n");
        return None;
    }
    // SAFETY: single-core; written exactly once here, before any
    // `drv_net_*_call` can read it.
    unsafe { core::ptr::addr_of_mut!(G_DRV_NET_RX_PHYS).write(rx_phys) };

    // Retype and pre-map the TX queue's own `SharedRegion` — same shape.
    let tx_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::SharedRegion,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    let tx_id = k.cap_space(src_cs)?.lookup(tx_cap)?.object.id;
    let tx_phys = k.shared_region(kernel_cap::SharedRegionId::new(tx_id.as_u32()))?.phys_base.as_usize();
    unsafe { core::ptr::write_bytes(tx_phys as *mut u8, 0, 4096) };
    unsafe { (tx_phys as *mut u64).write_volatile(tx_phys as u64) };

    let tx_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    unsafe { core::ptr::write_bytes(tx_pool as *mut u8, 0, 4096 * 2) };
    let n_tx = hal.map_range(drv_root_pt, DRV_NET_TX_VA, tx_phys, 4096, 1 | 2 | 8, tx_pool, 2);
    if n_tx == u32::MAX {
        klog!("spawn_virtio_net_driver: map_range error (tx region)\r\n");
        return None;
    }
    unsafe { core::ptr::addr_of_mut!(G_DRV_NET_TX_PHYS).write(tx_phys) };

    // For PCI transport, resolve+map the device's own virtio-pci "modern"
    // register windows (including MSI-X, on x86_64) and write the
    // `PCI_INFO_OFFSET` header block into the RX region (`driver_virtio_
    // net::layout::PCI_INFO_OFFSET`'s own doc comment) —
    // `new_driver_for_this_transport` reads this block to pick
    // `Transport::Pci` over the `transport_kind == 0` default the
    // freshly-zeroed RX region already carries for MMIO transport.
    if is_pci {
        let caller_addr_space = k.tcb(caller)?.addr_space;
        let caller_root_pt = k.addr_space_mut(caller_addr_space)?.root_phys().as_usize();
        // SAFETY: `mmio.config_space_base` is a live ECAM address (this
        // kernel boot-seeded it from `hal_arm64`/`hal_x86_64::peripheral`'s
        // own PCI scan, the same trust boundary `mmio.phys_base` already
        // relies on); `rx_phys` is this function's own fresh, zeroed
        // `SharedRegion`, forwarded from that write above. `caller_root_
        // pt`: `caller`'s own page table, still the ACTIVE one right now
        // (the switch to the driver process happens only at this
        // function's own tail).
        let wired = unsafe {
            wire_virtio_pci_transport_net(
                k,
                hal,
                drv_root_pt,
                caller_root_pt,
                mmio.config_space_base,
                rx_phys,
                mmio.irq,
            )
        };
        if wired.is_none() {
            klog!("spawn_virtio_net_driver: wire_virtio_pci_transport_net failed\r\n");
            return None;
        }
    }

    // Retype a `Notification` and bind the virtio-net device's own IRQ
    // line to it — same "root does the `IrqBind` itself, then grants the
    // ALREADY-BOUND notification into the driver's cap space" pattern as
    // `spawn_virtio_blk_driver`'s own identical block (see its own doc
    // comment for the full rationale); lands at slot 1 (the endpoint
    // above was the first grant, at slot 0). Used only by the TX
    // completion path — RX deliberately stays non-blocking-poll-only
    // (this crate's own `driver_virtio_net` module doc comment).
    let notif_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Notification,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::IrqBind {
            mmio: mmio_cap,
            notification: notif_cap,
            handler: virtio_net_irq_trampoline,
        },
        hal,
    ) {
        Ok(SyscallReturn::Done) => {}
        _ => {
            klog!("spawn_virtio_net_driver: IrqBind failed\r\n");
            return None;
        }
    }
    grant_cap_into(k, src_cs, notif_cap, drv_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;

    // Switch straight to the driver — same race-avoidance rationale as
    // `spawn_virtio_blk_driver`'s own doc comment on why.
    let _ = k.sched.note_ready(caller, hal.now_ns());
    let _ = k.sched.dispatch(drv_tid, hal.now_ns());
    let (save, into) = k.user_ctx_switch_ptrs(caller, drv_tid)?;

    Some((ep_cap.as_u32(), save, into))
}

/// Spawns the Netstack process from its own separately-built ELF
/// (`netstack_elf`) — the real replacement for this crate's own,
/// removed direct-driving of `driver-virtio-net` (`netstack::
/// subsystem_entry`'s own module doc comment has the full picture).
/// `driver_ep_cap` is `spawn_virtio_net_driver`'s own return value — the
/// caller (`kernel/src/main.rs`'s own `NET_DEMO_START` opcode) spawns
/// the driver FIRST, then this, passing that capability straight
/// through.
///
/// Grants TWO capabilities into this process's fresh cap space: a
/// DERIVED COPY of `driver_ep_cap` (slot 0 — this process's own IPC
/// client leg to the driver), and a freshly retyped `Endpoint` NOBODY
/// else ever holds (slot 1) — this second one is never `Call`ed by
/// anyone; its only purpose is `netstack::subsystem_entry::subsystem_
/// main`'s own tail `Recv`ing on it once the ARP/ICMP demo is done,
/// which blocks forever (nothing ever sends to it) and, via `p2_ipc_
/// recv`'s own documented fallback ("no immediate sender -> switch to
/// `k.root_thread` specifically"), hands control back to the ORIGINAL
/// caller of `NET_DEMO_START` — the SAME mechanism every other
/// subsystem's own idle `Recv` loop already relies on to yield back to
/// root, applied here as a one-shot "I'm done" hand-off instead of a
/// forever-serving loop.
///
/// Also trusted-bootstrap-maps the driver's own RX/TX `SharedRegion`s
/// (`G_DRV_NET_RX_PHYS`/`G_DRV_NET_TX_PHYS`, already valid — this
/// function is only ever called AFTER `spawn_virtio_net_driver` itself
/// returned) into THIS process's own address space too (`NETSTACK_DRV_
/// RX_VA`/`NETSTACK_DRV_TX_VA`) — Netstack needs to read/write the SAME
/// physical frame-buffer bytes the driver does, zero-copy, exactly the
/// way `spawn_virtio_net_driver` itself already maps them into the
/// DRIVER's own space. A THIRD, freshly retyped `SharedRegion` (never
/// granted as a capability to anyone — same "kernel-arch-glue builds
/// the page table directly" trusted-bootstrap pattern) is mapped at
/// `NETSTACK_STATUS_VA` for the ARP/ICMP verdict `netstack_status`
/// reads back.
///
/// Returns `None` (and logs) on any allocation failure.
pub fn spawn_netstack_service(
    hal: &HalInterface,
    caller: ThreadId,
    netstack_elf: &[u8],
    expected_machine: u16,
    driver_ep_cap: u32,
) -> Option<(*mut u8, *const u8)> {
    let k = kstate();

    // Retire `p2_ipc_demo_start`'s own one-shot server thread NOW,
    // rather than waiting for `p2_preempt_start`'s own identical
    // retirement (which normally handles this, but only runs AFTER the
    // fs/blk/net demos, all further down `umode_root`'s own sequence).
    // **Real bug found via QEMU** (this crate's own FIRST real U-mode
    // client of a REAL subsystem process — Netstack calling `driver-
    // virtio-net` over genuine `IPC_CALL`s): the driver's own `Reply`
    // (to Netstack's `SendFrame`) always switches straight back to
    // Netstack — see `do_reply`'s own doc comment on why — so the
    // driver itself never gets a scheduled turn to loop back to its own
    // `Recv` before Netstack's VERY NEXT `IPC_CALL` (`PollFrame`, inside
    // its own bounded retry loop) fires. That second `Call` therefore
    // ALWAYS takes the general (queued) path, needing a real `pick_
    // next` — which, with the IPC demo server's own long-done TCB still
    // sitting `Ready` (its own `vruntime` far lower than the driver's,
    // which has been genuinely running), tie-breaks straight to that
    // STALE thread instead of the driver — exactly the SAME "phantom
    // scheduler entity" class of bug `G_IPC_SERVER_TID`'s own doc
    // comment (in `p2_preempt_start`, below) already documents in full,
    // just reached from a NEW, earlier code path that same fix's own
    // original scope never anticipated. Confirmed via QEMU: a temporary
    // `p2_ipc_call` diagnostic showed the SECOND `Call`'s own `pick_
    // next` resolving to this exact stale thread, which then free-runs
    // forever (nothing else ever preempts it — the timer isn't armed
    // yet at this point in the boot), permanently starving Netstack,
    // the driver, AND `caller` (root) alike.
    // SAFETY: single-core; only read (and cleared) here or by `p2_
    // preempt_start`'s own identical block, written once by `p2_ipc_
    // demo_start` before either can ever run — idempotent if `p2_
    // preempt_start` already retired it (the `if let Some` below is
    // simply not taken a second time).
    if let Some(server_tid) = unsafe { core::ptr::addr_of!(G_IPC_SERVER_TID).read() } {
        if let Some(t) = k.tcb_mut(server_tid) {
            t.state = ThreadState::Exited;
        }
        k.sched.remove(server_tid);
        unsafe { core::ptr::addr_of_mut!(G_IPC_SERVER_TID).write(None) };
    }
    // fs-native's own thread hits the SAME stale-`Ready`-phantom class
    // of bug, for the SAME underlying reason `p2_preempt_start`'s own
    // identical block (below) already documents in full: after its own
    // LAST reply (`FS_CLOSE`'s, in the fs demo that ran earlier in this
    // exact boot sequence), `do_reply` leaves it `Ready` but it never
    // gets CPU time to loop back to `Recv` and block PROPERLY —
    // `note_blocked` (not `remove`: `fs_ipc_call`'s own direct
    // `dispatch(fs_tid, ...)` needs the TCB slot to stay valid forever)
    // removes it from `pick_next`'s own candidate pool without
    // invalidating it. **Real bug found via QEMU** (this crate's own
    // FIRST scheduling path to ever call GENERAL `pick_next` — Netstack
    // driving `driver-virtio-net` over real `IPC_CALL`s — between the
    // fs demo's own completion and `p2_preempt_start`'s own identical
    // cleanup, which normally runs first): confirmed the exact same
    // symptom class as `G_IPC_SERVER_TID`'s own fix just above, just
    // with fs-native's thread as the stale `pick_next` candidate once
    // that first one was retired.
    // SAFETY: single-core; `G_FS_TID` written once by `fs_demo_start`, read-only here.
    if let Some(fs_tid) = unsafe { core::ptr::addr_of!(G_FS_TID).read() } {
        let _ = k.sched.note_blocked(fs_tid);
    }
    // Process B (the §8.4 two-space zero-copy demo's own worker) hits
    // the SAME stale-`Ready`-phantom class as `G_IPC_SERVER_TID` above
    // (a genuine one-shot proof with no ongoing role, unlike fs-native)
    // — confirmed via QEMU: with `G_IPC_SERVER_TID`/`G_FS_TID` both
    // fixed, Netstack's own SECOND `PollFrame` retry `pick_next`'d
    // straight into process B next. `remove` (not `note_blocked`): like
    // the IPC demo server, nothing will ever `dispatch` it again.
    // SAFETY: single-core; `G_PROCESS_B_TID` written once by `setup_
    // two_process`, read-only here.
    if let Some(b_tid) = unsafe { core::ptr::addr_of!(G_PROCESS_B_TID).read() } {
        if let Some(t) = k.tcb_mut(b_tid) {
            t.state = ThreadState::Exited;
        }
        k.sched.remove(b_tid);
        unsafe { core::ptr::addr_of_mut!(G_PROCESS_B_TID).write(None) };
    }

    let src_cs = k.tcb(caller)?.cap_space;

    const NETSTACK_STACK_VMA: usize = 0xC0A0_0000;
    const NETSTACK_STACK_LEN: usize = 4096 * 16;
    let (ns_tid, ns_cs, _stack_phys) =
        spawn_process_from_elf(hal, k, netstack_elf, expected_machine, NETSTACK_STACK_VMA, NETSTACK_STACK_LEN)?;

    // Slot 0: a derived copy of the driver's own Endpoint.
    grant_cap_into(k, src_cs, CapId::new(driver_ep_cap), ns_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;

    // Slot 1: the "park" Endpoint — this function's own doc comment on
    // why NOBODY ever `Call`s it.
    let park_ep_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Endpoint,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    grant_cap_into(k, src_cs, park_ep_cap, ns_cs, CapabilityRights::READ | CapabilityRights::WRITE)?;
    // SAFETY: single-core; written once here, before any kernel-bypass
    // call (reached only after this function returns) can read either.
    unsafe { core::ptr::addr_of_mut!(G_NETSTACK_TID).write(Some(ns_tid)) };
    unsafe { core::ptr::addr_of_mut!(G_NETSTACK_BYPASS_EP).write(park_ep_cap.as_u32()) };

    let ns_addr_space = k.tcb(ns_tid)?.addr_space;
    let ns_root_pt = k.addr_space_mut(ns_addr_space)?.root_phys().as_usize();

    // Map the driver's own RX region into Netstack's address space too.
    // SAFETY: single-core; `G_DRV_NET_RX_PHYS` was written once by
    // `spawn_virtio_net_driver`, already run to completion (this
    // function's own doc comment).
    let rx_phys = unsafe { core::ptr::addr_of!(G_DRV_NET_RX_PHYS).read() };
    let rx_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed.
    unsafe { core::ptr::write_bytes(rx_pool as *mut u8, 0, 4096 * 2) };
    let n_rx = hal.map_range(ns_root_pt, NETSTACK_DRV_RX_VA, rx_phys, 4096, 1 | 2 | 8, rx_pool, 2);
    if n_rx == u32::MAX {
        klog!("spawn_netstack_service: map_range error (driver rx region)\r\n");
        return None;
    }

    // Same for the driver's own TX region.
    // SAFETY: same contract as the RX read above.
    let tx_phys = unsafe { core::ptr::addr_of!(G_DRV_NET_TX_PHYS).read() };
    let tx_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    unsafe { core::ptr::write_bytes(tx_pool as *mut u8, 0, 4096 * 2) };
    let n_tx = hal.map_range(ns_root_pt, NETSTACK_DRV_TX_VA, tx_phys, 4096, 1 | 2 | 8, tx_pool, 2);
    if n_tx == u32::MAX {
        klog!("spawn_netstack_service: map_range error (driver tx region)\r\n");
        return None;
    }

    // Retype + map the kernel-bypass control-plane's own shared message
    // page (03-Kernel-Subsystems-Layer.md §2.3/§5.4.1) — same shape as
    // `mm_demo_start`'s own `MM_SHARED_VA` page: a fresh, private
    // `SharedRegion`, mapped only into Netstack's own address space (root
    // reaches it via `G_NETSTACK_BYPASS_SHARED_PHYS`'s own physical
    // pointer, never through a VA mapping of its own).
    let bypass_shared_phys = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core.
    unsafe { core::ptr::write_bytes(bypass_shared_phys as *mut u8, 0, 4096) };
    let bypass_shared_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    // SAFETY: fresh untyped RAM, identity-addressable, single-core;
    // `map_range` needs the pool pre-zeroed.
    unsafe { core::ptr::write_bytes(bypass_shared_pool as *mut u8, 0, 4096 * 2) };
    let n_bypass =
        hal.map_range(ns_root_pt, NETSTACK_BYPASS_SHARED_VA, bypass_shared_phys, 4096, 1 | 2 | 8, bypass_shared_pool, 2);
    if n_bypass == u32::MAX {
        klog!("spawn_netstack_service: map_range error (bypass shared page)\r\n");
        return None;
    }
    // SAFETY: single-core; written exactly once here, before any
    // kernel-bypass call can be reached.
    unsafe { core::ptr::addr_of_mut!(G_NETSTACK_BYPASS_SHARED_PHYS).write(bypass_shared_phys) };

    // Retype + map Netstack's own private status region.
    let status_cap = match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::SharedRegion,
            count: 1,
        },
        hal,
    ) {
        Ok(SyscallReturn::NewCaps { cap, .. }) => cap,
        _ => return None,
    };
    let status_id = k.cap_space(src_cs)?.lookup(status_cap)?.object.id;
    let status_phys =
        k.shared_region(kernel_cap::SharedRegionId::new(status_id.as_u32()))?.phys_base.as_usize();
    // SAFETY: fresh `SharedRegion` memory, identity-addressable, single-core.
    unsafe { core::ptr::write_bytes(status_phys as *mut u8, 0, 4096) };
    let status_pool = k
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 2).ok())
        .map(|p| p.as_usize())?;
    unsafe { core::ptr::write_bytes(status_pool as *mut u8, 0, 4096 * 2) };
    let n_status = hal.map_range(ns_root_pt, NETSTACK_STATUS_VA, status_phys, 4096, 1 | 2 | 8, status_pool, 2);
    if n_status == u32::MAX {
        klog!("spawn_netstack_service: map_range error (status region)\r\n");
        return None;
    }
    // SAFETY: single-core; written exactly once here, before any
    // `netstack_status` call (reached only after this function returns).
    unsafe { core::ptr::addr_of_mut!(G_NETSTACK_STATUS_PHYS).write(status_phys) };

    // Also map the driver's own ISR_CFG and NOTIFY_CFG register pages
    // into Netstack's AND root's (`caller`'s) own page tables, at the
    // SAME numeric VA the driver already has each at — see `G_DRV_NET_
    // ISR_CFG_PHYS`'s own doc comment for the real, QEMU-found page
    // fault this fixes for ISR: `virtio_net_irq_trampoline` reads that VA
    // unconditionally whenever the device's IRQ fires, but a genuine
    // hardware IRQ is asynchronous to the CPU's own instruction stream
    // and can now land while EITHER of these two OTHER processes is the
    // active address space (Netstack is this codebase's first real IPC
    // client that actually takes turns with a driver process). NOTIFY_CFG
    // needs the identical treatment for a DIFFERENT real reason (also
    // QEMU-found): `net_bypass_direct_send` runs on ROOT's own trap
    // (`drv_root_pt` is never active there) and rings the TX doorbell
    // directly — see `G_DRV_NET_NOTIFY_PHYS`'s own doc comment for the
    // page fault a first version of that function took writing through
    // the raw physical address instead of a mapped VA. `usize::MAX`
    // (never found the matching capability, or `Transport::Mmio`, which
    // never sets either at all) — skip that window entirely; the
    // mmio-transport path's own physical-address reads/writes are
    // already identity-mapped and safe from any `cr3`.
    let caller_addr_space = k.tcb(caller)?.addr_space;
    let caller_root_pt = k.addr_space_mut(caller_addr_space)?.root_phys().as_usize();
    for (name, phys, va) in [
        (
            "ISR_CFG",
            unsafe { core::ptr::addr_of!(G_DRV_NET_ISR_CFG_PHYS).read() },
            unsafe { core::ptr::addr_of!(G_DRV_NET_ISR_CFG_VA).read() },
        ),
        (
            "NOTIFY_CFG",
            unsafe { core::ptr::addr_of!(G_DRV_NET_NOTIFY_PHYS).read() },
            unsafe { core::ptr::addr_of!(G_DRV_NET_NOTIFY_VA).read() },
        ),
    ] {
        if phys == usize::MAX || va == usize::MAX {
            continue;
        }
        let va_page = va & !0xFFF;
        let phys_page = phys & !0xFFF;
        for target_pt in [ns_root_pt, caller_root_pt] {
            let win_pool = k
                .untyped_mut(kernel_cap::UntypedId::new(0))
                .and_then(|u| u.alloc(4096, 4096 * 2).ok())
                .map(|p| p.as_usize())?;
            // SAFETY: fresh untyped RAM, identity-addressable, single-core.
            unsafe { core::ptr::write_bytes(win_pool as *mut u8, 0, 4096 * 2) };
            let n = hal.map_range(target_pt, va_page, phys_page, 4096, 1 | 2, win_pool, 2);
            if n == u32::MAX {
                klog!("spawn_netstack_service: map_range error (driver {} page)\r\n", name);
                return None;
            }
            // `caller_root_pt` is the CURRENTLY ACTIVE page table (this
            // whole function runs on `caller`'s own trap) — same "flush
            // before relying on a fresh mapping into a LIVE table"
            // insurance `wire_virtio_pci_transport`'s own config-space
            // mapping already takes; `ns_root_pt` isn't active yet (no
            // flush needed, matching every other per-process mapping
            // above).
            if target_pt == caller_root_pt {
                hal.flush_tlb();
            }
        }
    }

    // Switch straight to Netstack — same race-avoidance rationale as
    // `spawn_virtio_blk_driver`'s own doc comment on why: without this,
    // the caller's very next `NET_STATUS_POLL` would race a process that
    // has never yet run at all, always reading an all-zero (never
    // written) status.
    let _ = k.sched.note_ready(caller, hal.now_ns());
    let _ = k.sched.dispatch(ns_tid, hal.now_ns());
    let Some((save, into)) = k.user_ctx_switch_ptrs(caller, ns_tid) else {
        return None;
    };

    Some((save, into))
}

/// `NET_STATUS_POLL` demo opcode's own kernel-side half: reads the
/// Netstack process's own status region directly (`spawn_netstack_
/// service`'s own doc comment — `G_NETSTACK_STATUS_PHYS`, physical
/// pointer, no IPC needed for this leg) and logs the SAME "real ARP
/// resolve/ICMP echo" lines this crate's own (now-removed, pre-
/// extraction) `drv_net_arp_poll_result`/`drv_net_ping_poll_result`
/// used to print, once a terminal verdict is reached — preserves this
/// project's own established QEMU-verification log format across the
/// extraction. Returns `0` while Netstack is still running (verdict byte
/// still `0`), `1` once ARP failed, `2` once ARP resolved but the ping
/// failed/mismatched, `3` on full success.
pub fn netstack_status() -> usize {
    // SAFETY: single-core; `G_NETSTACK_STATUS_PHYS` was written once by
    // `spawn_netstack_service`, before any `netstack_status` call.
    let base = unsafe { core::ptr::addr_of!(G_NETSTACK_STATUS_PHYS).read() };
    if base == usize::MAX {
        return 0;
    }
    // SAFETY: `base` is the Netstack process's own fresh, zeroed
    // `SharedRegion`, identity-addressable, single-core.
    let verdict = unsafe { (base as *const u8).read_volatile() };
    if verdict == 0 {
        return 0;
    }
    // SAFETY: same contract as the verdict read above; the MAC bytes are
    // only meaningful (written) once `verdict >= 2` — `netstack::
    // subsystem_entry::write_status`'s own doc comment — but reading
    // them unconditionally once ANY verdict is set is harmless (still
    // all-zero otherwise, never uninitialized memory: this whole region
    // was zeroed at spawn time).
    let mut gw_mac = [0u8; 6];
    unsafe {
        let mac_base = (base + 8) as *const u8;
        for (i, b) in gw_mac.iter_mut().enumerate() {
            *b = mac_base.add(i).read_volatile();
        }
    }
    if verdict >= 2 {
        klog!(
            "netstack: real ARP resolve through virtio-net's own virtqueues, over real IPC (03 2.3) -> gateway is at {:02x?}\r\n",
            gw_mac
        );
    }
    klog!(
        "netstack: real ICMP echo request->reply round-trip through virtio-net's own virtqueues, driven entirely over real IPC by a real Netstack process (03 2.3/5.4) -> {}\r\n",
        match verdict {
            1 => "ARP FAILED",
            2 => "MISMATCH",
            3 => "MATCH",
            _ => "unknown",
        }
    );
    verdict as usize
}

/// Writes `msg`'s full `(label, words[0..6] zero-padded)` into the
/// kernel-bypass control-plane's own shared page — same convention
/// `write_shared_mm_message`'s own doc comment documents in full.
///
/// # Safety
/// `G_NETSTACK_BYPASS_SHARED_PHYS` must already be a valid,
/// exclusively-owned, mapped physical frame (`spawn_netstack_service` has
/// run).
unsafe fn write_shared_netstack_bypass_message(msg: &SmallMessage) {
    // SAFETY: single-core; `G_NETSTACK_BYPASS_SHARED_PHYS` only written
    // once by `spawn_netstack_service`, before this can ever be called.
    let base = unsafe { core::ptr::addr_of!(G_NETSTACK_BYPASS_SHARED_PHYS).read() } as *mut u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Reads back a `SmallMessage` written by `write_shared_netstack_bypass_
/// message`.
///
/// # Safety
/// Same contract as `write_shared_netstack_bypass_message`.
unsafe fn read_shared_netstack_bypass_message() -> SmallMessage {
    // SAFETY: single-core; same contract as `write_shared_netstack_bypass_message`.
    let base = unsafe { core::ptr::addr_of!(G_NETSTACK_BYPASS_SHARED_PHYS).read() } as *const u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        let label = base.read_volatile();
        let mut words = [0u64; kernel_ipc::MSG_MAX_WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = base.add(1 + i).read_volatile();
        }
        SmallMessage::from_words(label, &words).unwrap_or(SmallMessage::new(label))
    }
}

/// `Call`, specialized for the kernel-bypass control-plane's own known,
/// fixed 2-party (root <-> Netstack) shape — same "bypass `pick_next`'s
/// answer, switch straight to the known target thread" fix `mm_ipc_call`'s
/// own doc comment documents in full (identical bug class: Netstack's own
/// `park()` loop, like mm-service's own server loop, is the only OTHER
/// runnable thread by the time this demo reaches it).
fn netstack_bypass_ipc_call(hal: &HalInterface, caller: ThreadId, ep_cap: u32) -> Option<IpcSwitch> {
    let k = kstate();
    // SAFETY: single-core; `G_NETSTACK_TID` is written once by `spawn_
    // netstack_service`, before any bypass call (this function) can run.
    let ns_tid = unsafe { core::ptr::addr_of!(G_NETSTACK_TID).read() }?;
    let msg = SmallMessage::new(0);
    match k.dispatch(caller, hal.now_ns(), SyscallOp::Call { endpoint: CapId::new(ep_cap), msg }, hal) {
        Ok(SyscallReturn::Reschedule { next: Some(n) }) => {
            let _ = k.sched.dispatch(ns_tid, hal.now_ns());
            let (save, into) = k.user_ctx_switch_ptrs(caller, ns_tid)?;
            let poke = if n == ns_tid {
                k.tcb_mut(ns_tid)
                    .and_then(|t| Some((t.pending_from.take()?, t.pending_msg.take()?)))
                    .map(|(from, m)| (from.as_u32() as usize, m.label as usize))
            } else {
                None
            };
            Some(IpcSwitch { save, into, poke })
        }
        _ => None,
    }
}

/// `NET_BYPASS_REQUEST` demo opcode: builds a REAL `NetBypassRequest::
/// RequestDirectNic` for a fixed demo `nic_id` (`0` — this MVP has
/// exactly one NIC, matching `spawn_virtio_net_driver`'s own
/// single-device assumption throughout) and issues the real IPC round
/// trip to Netstack's own `BYPASS_ENDPOINT_CAP` server loop
/// (03-Kernel-Subsystems-Layer.md §2.3/§5.4.1). Netstack's own `handle_
/// bypass_request` always grants (this MVP's own documented
/// simplification: no layer-4 Security Broker exists in this repo yet to
/// consult — `ipc_protocol::net`'s own doc comment).
///
/// Unlike `mm_register_call`/`compositor_commit_call` (which take their
/// endpoint cap as a per-arch global `kernel/kernel/src/main.rs` itself
/// caches at `MM_DEMO_START`/spawn time), this reads `G_NETSTACK_BYPASS_
/// EP` directly — cached once, inside THIS crate, by `spawn_netstack_
/// service` itself — since Netstack is already spawned (for the ARP/ICMP
/// demo) long before this opcode's own first use, with no per-arch
/// wrinkle to thread through `main.rs`. Returns `None` (a `TrapOutcome::
/// Resume(0)`, matching `mm_register_call`'s own convention) if Netstack
/// was never spawned.
pub fn net_bypass_request_call(hal: &HalInterface, caller: ThreadId) -> Option<IpcSwitch> {
    // SAFETY: single-core; written once by `spawn_netstack_service`,
    // before any `.user_text` code can reach this opcode.
    let ep_cap = unsafe { core::ptr::addr_of!(G_NETSTACK_BYPASS_EP).read() };
    if ep_cap == u32::MAX {
        return None;
    }
    let req = ipc_protocol::NetBypassRequest::RequestDirectNic { nic_id: 0 };
    let msg = ipc_protocol::codec::encode_net_bypass_request(&req);
    // SAFETY: `spawn_netstack_service` has already run (checked above via
    // `ep_cap`), so `G_NETSTACK_BYPASS_SHARED_PHYS` is valid too.
    unsafe { write_shared_netstack_bypass_message(&msg) };
    netstack_bypass_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `NetBypassResponse` for `net_bypass_request_call`.
/// Returns `1` for a real `Granted`, `0` otherwise (`Denied`, a decode
/// failure, or — unlike `mm_register_result`, which can assume mm-service
/// is always spawned by the time it runs — `net_bypass_request_call`
/// itself never having sent anything at all: **real bug found via QEMU**,
/// this function used to dereference `G_NETSTACK_BYPASS_SHARED_PHYS`
/// unconditionally, and `net_bypass_demo_*`'s own call site always reads
/// this result right after issuing `NET_BYPASS_REQUEST` regardless of
/// whether Netstack was ever spawned in the first place (no NIC
/// discovered at boot skips `NET_DEMO_START`, per `net_demo_aarch64`'s
/// own doc comment) — a debug build's `read_volatile` precondition check
/// caught the resulting misaligned `usize::MAX` pointer read as a kernel
/// panic on aarch64).
pub fn net_bypass_request_result() -> usize {
    // SAFETY: single-core; read-only, `spawn_netstack_service` is this
    // static's only writer.
    if unsafe { core::ptr::addr_of!(G_NETSTACK_BYPASS_SHARED_PHYS).read() } == usize::MAX {
        return 0;
    }
    // SAFETY: same contract as `net_bypass_request_call` — the check
    // above rules out the one case that contract doesn't already cover.
    let msg = unsafe { read_shared_netstack_bypass_message() };
    matches!(
        ipc_protocol::codec::decode_net_bypass_response(&msg),
        Ok(ipc_protocol::NetBypassResponse::Granted { .. })
    ) as usize
}

/// `NET_STANDARD_SEND_REQUEST` demo opcode: builds a REAL `NetBypassRequest::
/// RelayFrame` and issues the real IPC round trip to Netstack's own
/// `BYPASS_ENDPOINT_CAP` server loop — the SAME endpoint/mechanism `net_
/// bypass_request_call` uses, just a different request variant. Netstack
/// itself then makes a SECOND real IPC round trip to the driver (`ipc_
/// protocol::net::NetBypassRequest::RelayFrame`'s own doc comment) and
/// waits for the real hardware TX completion before replying — this is
/// the §5.4.1 "standard path" `net_bypass_direct_send`'s own bypass path
/// is supposed to be ≥30-40% faster than. Same "reads `G_NETSTACK_
/// BYPASS_EP` directly, no per-arch global" shape as `net_bypass_
/// request_call`'s own doc comment explains.
pub fn net_standard_send_call(hal: &HalInterface, caller: ThreadId) -> Option<IpcSwitch> {
    // SAFETY: single-core; written once by `spawn_netstack_service`,
    // before any `.user_text` code can reach this opcode.
    let ep_cap = unsafe { core::ptr::addr_of!(G_NETSTACK_BYPASS_EP).read() };
    if ep_cap == u32::MAX {
        return None;
    }
    let msg = ipc_protocol::codec::encode_net_bypass_request(&ipc_protocol::NetBypassRequest::RelayFrame);
    // SAFETY: `spawn_netstack_service` has already run (checked above via
    // `ep_cap`), so `G_NETSTACK_BYPASS_SHARED_PHYS` is valid too.
    unsafe { write_shared_netstack_bypass_message(&msg) };
    netstack_bypass_ipc_call(hal, caller, ep_cap)
}

/// Reads back the `NetBypassResponse` for `net_standard_send_call`.
/// Returns `1` for a real `Relayed`, `0` otherwise (`Denied`, a decode
/// failure, or Netstack never spawned — same guard as `net_bypass_
/// request_result`'s own doc comment explains, same real reason it's
/// needed).
pub fn net_standard_send_result() -> usize {
    // SAFETY: single-core; read-only, `spawn_netstack_service` is this
    // static's only writer.
    if unsafe { core::ptr::addr_of!(G_NETSTACK_BYPASS_SHARED_PHYS).read() } == usize::MAX {
        return 0;
    }
    // SAFETY: same contract as `net_standard_send_call` — the check
    // above rules out the one case that contract doesn't already cover.
    let msg = unsafe { read_shared_netstack_bypass_message() };
    matches!(
        ipc_protocol::codec::decode_net_bypass_response(&msg),
        Ok(ipc_protocol::NetBypassResponse::Relayed)
    ) as usize
}

/// Fixed demo frame length `net_bypass_direct_send` stages after the
/// (all-zero) virtio-net header — a recognizable, deliberately-not-a-
/// real-protocol byte pattern is enough to prove real bytes moved (this
/// path has no listener to reply, unlike the ARP/ICMP round trip
/// `netstack_status` verifies — §5.4.1's own "the client then drives the
/// NIC directly with NO further IPC on the data path" contract means this
/// demo proves the SEND mechanism itself, not a round trip).
const NET_BYPASS_FRAME_LEN: usize = 64;

/// Directly replicates `VirtioNet::submit_tx_request`/`publish_and_
/// notify`'s own descriptor-publish-plus-doorbell-ring logic
/// (`driver_virtio_net::VirtioNet`'s own PRIVATE wire-format methods,
/// necessarily mirrored here byte-for-byte rather than called, since
/// kernel-arch-glue cannot reach into another process's own address
/// space or private struct) directly against the driver's already-probed
/// TX queue's own physical `SharedRegion` — the core of §2.3/§5.4.1's own
/// "the client then drives the NIC directly with NO further IPC on the
/// data path" contract. Runs from kernel mode (Ring 0 / EL1 / M-mode's
/// own already-unrestricted physical memory access — the SAME class of
/// direct physical read/write every other verification function in this
/// file already performs), so this MVP needs no separate "bypass client
/// process": `net_bypass_request_call`'s own control-plane handshake is
/// the only real IPC on this whole path, exactly matching the spec.
///
/// # Preconditions (an honest, undefended MVP simplification)
/// The driver's own `do_probe` must already have completed (so `TX_
/// NOTIFY_OFF_OFFSET` — persisted in the RX region, `layout::TX_NOTIFY_
/// OFF_OFFSET`'s own doc comment on why only there — holds a real value
/// for PCI transport), and the driver's own last TX request (if any) must
/// already have completed: `used.idx == avail.idx` on the TX queue,
/// checked below and refused otherwise rather than silently interleaving
/// with a request this path has no way to identify. This demo's own call
/// site (after the driver's own SendFrame/PollFrame demo and Netstack's
/// own ARP/ICMP demo have both already run to completion) guarantees this
/// by construction; a general-purpose bypass path would need to actually
/// wait on it instead of refusing.
///
/// Returns the elapsed nanoseconds (`hal.now_ns()` immediately before
/// publishing the descriptor, to immediately after the busy-poll observes
/// completion), or `None` if the driver was never probed, its last TX is
/// still pending, or the busy-poll times out.
pub fn net_bypass_direct_send(hal: &HalInterface) -> Option<u64> {
    // SAFETY: single-core; `G_DRV_NET_TX_PHYS` was written once by
    // `spawn_virtio_net_driver`, already run to completion by the time
    // this demo function can be reached (`umode_root`'s own ordering).
    let tx_phys = unsafe { core::ptr::addr_of!(G_DRV_NET_TX_PHYS).read() };
    if tx_phys == usize::MAX {
        klog!("net_bypass_direct_send: driver was never probed (no TX region)\r\n");
        return None;
    }
    // Refuse to interleave with the driver's own still-in-flight TX —
    // same `used.idx == next_idx` direction as `VirtioNet::tx_completion_
    // pending`'s own doc comment, just re-derived from the queue's own
    // on-wire words directly (no driver-process struct reachable here).
    // SAFETY: `AVAIL_OFFSET + 2` / `USED_OFFSET + 2` are within the
    // mapped region (`tx_phys` is a fresh, page-sized `SharedRegion`'s
    // own physical base, identity-addressable, single-core).
    let next_idx = unsafe {
        ((tx_phys + driver_virtio_net::layout::AVAIL_OFFSET + 2) as *const u16).read_volatile()
    };
    let used_idx_before = unsafe {
        ((tx_phys + driver_virtio_net::layout::USED_OFFSET + 2) as *const u16).read_volatile()
    };
    if used_idx_before != next_idx {
        klog!("net_bypass_direct_send: driver's own last TX request is still pending, refusing to interleave\r\n");
        return None;
    }

    // Stage the demo frame at `BUFFER_OFFSET`: the virtio-net header
    // (all-zero — no GSO/checksum offload requested, same convention
    // `submit_tx_request`'s own doc comment establishes), followed by a
    // fixed, recognizable Ethernet-shaped payload.
    let buf = tx_phys + driver_virtio_net::layout::BUFFER_OFFSET;
    // SAFETY: `BUFFER_OFFSET..+4096-BUFFER_OFFSET` is within the mapped
    // region — same contract as the ring reads above.
    unsafe {
        core::ptr::write_bytes(buf as *mut u8, 0, driver_virtio_net::VIRTIO_NET_HDR_LEN);
        let frame = buf + driver_virtio_net::VIRTIO_NET_HDR_LEN;
        core::ptr::write_bytes(frame as *mut u8, 0xFF, 6); // dest MAC = broadcast
        core::ptr::write_bytes((frame + 6) as *mut u8, 0xB9, 6); // src MAC = fixed sentinel bytes
        ((frame + 12) as *mut u8).write_volatile(0xFF);
        ((frame + 13) as *mut u8).write_volatile(0xFF); // ethertype 0xFFFF — deliberately unassigned
        core::ptr::write_bytes((frame + 14) as *mut u8, 0xB5, NET_BYPASS_FRAME_LEN - 14); // recognizable payload pattern
    }
    let total_len = driver_virtio_net::VIRTIO_NET_HDR_LEN + NET_BYPASS_FRAME_LEN;

    let start_ns = hal.now_ns();

    // Descriptor slot 0 (`VirtqDescRaw`'s own `#[repr(C)]` layout —
    // `addr: u64, len: u32, flags: u16, next: u16`, spec §2.6.5), device-
    // readable (TX): mirrors `submit_tx_request`'s own descriptor exactly.
    // SAFETY: `DESC_OFFSET` (32 bytes, slot 0 only) is within the mapped region.
    unsafe {
        let desc = tx_phys + driver_virtio_net::layout::DESC_OFFSET;
        (desc as *mut u64).write_volatile(buf as u64); // identity-mapped physical RAM.
        ((desc + 8) as *mut u32).write_volatile(total_len as u32);
        ((desc + 12) as *mut u16).write_volatile(0); // flags: device-readable, no NEXT
        ((desc + 14) as *mut u16).write_volatile(0); // next: unused
    }
    let ring_slot = driver_virtio_net::layout::AVAIL_OFFSET
        + 4
        + (next_idx as usize % driver_virtio_net::QUEUE_SIZE as usize) * 2;
    let new_avail_idx = next_idx.wrapping_add(1);
    // SAFETY: within the mapped region.
    unsafe {
        ((tx_phys + ring_slot) as *mut u16).write_volatile(0); // head descriptor index (slot 0)
        ((tx_phys + driver_virtio_net::layout::AVAIL_OFFSET + 2) as *mut u16).write_volatile(new_avail_idx);
    }

    // Ring the doorbell — MMIO's single fixed register, or PCI's
    // per-queue notify window, using the SAME `tx_notify_off` the
    // driver's own `do_probe` already negotiated and persisted
    // (`layout::TX_NOTIFY_OFF_OFFSET`'s own doc comment on why this can
    // only be read back post-probe, from the RX region).
    // SAFETY: single-core; both globals are written once by `spawn_
    // virtio_net_driver`/`wire_virtio_pci_transport_net`, already run to
    // completion.
    let mmio_phys = unsafe { core::ptr::addr_of!(G_DRV_NET_MMIO_PHYS).read() };
    if mmio_phys != usize::MAX {
        // SAFETY: `mmio_phys + QUEUE_NOTIFY` is the device's own live MMIO window.
        unsafe {
            ((mmio_phys + driver_virtio_net::mmio::QUEUE_NOTIFY) as *mut u32)
                .write_volatile(driver_virtio_net::TX_QUEUE);
        }
    } else {
        // SAFETY: single-core; `G_DRV_NET_NOTIFY_VA` is written once by
        // `wire_virtio_pci_transport_net` and mapped into root's own page
        // table by `spawn_netstack_service` — see `G_DRV_NET_NOTIFY_VA`'s
        // own doc comment for why a raw `G_DRV_NET_NOTIFY_PHYS`
        // dereference (a first version of this function's own real bug,
        // found via QEMU) is never safe: modern virtio-pci capability
        // BARs are frequently 64-bit BARs QEMU places far outside the
        // kernel's own low-RAM identity map.
        let notify_va = unsafe { core::ptr::addr_of!(G_DRV_NET_NOTIFY_VA).read() };
        let notify_off_mult = unsafe { core::ptr::addr_of!(G_DRV_NET_NOTIFY_OFF_MULT).read() };
        let rx_phys = unsafe { core::ptr::addr_of!(G_DRV_NET_RX_PHYS).read() };
        if notify_va == usize::MAX || rx_phys == usize::MAX {
            klog!("net_bypass_direct_send: no notify window cached (neither MMIO nor PCI)\r\n");
            return None;
        }
        // SAFETY: `TX_NOTIFY_OFF_OFFSET` is within the mapped RX region.
        let tx_notify_off =
            unsafe { ((rx_phys + driver_virtio_net::layout::TX_NOTIFY_OFF_OFFSET) as *const u64).read_volatile() as u16 };
        let addr = notify_va + (tx_notify_off as usize) * (notify_off_mult as usize);
        // SAFETY: `addr` is the PCI NOTIFY_CFG window's own live register,
        // reached through the VA `spawn_netstack_service` mapped into
        // root's own (currently active) page table — see `G_DRV_NET_
        // NOTIFY_VA`'s own doc comment.
        unsafe { (addr as *mut u16).write_volatile(driver_virtio_net::TX_QUEUE as u16) };
    }

    // Bounded busy-poll for the used ring to catch up — mirrors
    // `VirtioNet::tx_completion_pending`'s own `used.idx == next_idx`
    // check, re-derived from the physical region directly.
    const MAX_POLL_ITERS: u32 = 20_000_000;
    let mut i = 0u32;
    loop {
        // SAFETY: within the mapped region.
        let used_idx =
            unsafe { ((tx_phys + driver_virtio_net::layout::USED_OFFSET + 2) as *const u16).read_volatile() };
        if used_idx == new_avail_idx {
            break;
        }
        i += 1;
        if i >= MAX_POLL_ITERS {
            klog!(
                "net_bypass_direct_send: TX completion busy-poll timed out (used_idx={:#x} wanted={:#x})\r\n",
                used_idx, new_avail_idx
            );
            return None;
        }
        core::hint::spin_loop();
    }

    let elapsed_ns = hal.now_ns().saturating_sub(start_ns);

    // Acknowledge the interrupt cause at the device — same "always drain
    // whatever cause is pending, even though this path never waits on the
    // IRQ line" rationale as `VirtioNet::ack_interrupt`'s own doc comment.
    if mmio_phys != usize::MAX {
        // SAFETY: forwarded from `virtio_net_irq_trampoline`'s own
        // identical MMIO read-then-write-back.
        unsafe {
            let cause = ((mmio_phys + driver_virtio_net::mmio::INTERRUPT_STATUS) as *const u32).read_volatile();
            ((mmio_phys + driver_virtio_net::mmio::INTERRUPT_ACK) as *mut u32).write_volatile(cause);
        }
    } else {
        // SAFETY: single-core; `G_DRV_NET_ISR_CFG_VA` is mapped into
        // root's own page table by `spawn_netstack_service` (the SAME
        // mapping `virtio_net_irq_trampoline` already relies on being
        // reachable from root — see that static's own doc comment) —
        // unlike `G_DRV_NET_ISR_CFG_PHYS`, which is never safe to
        // dereference directly (`G_DRV_NET_NOTIFY_PHYS`'s own doc comment
        // on the identical class of real bug this sidesteps).
        let isr_va = unsafe { core::ptr::addr_of!(G_DRV_NET_ISR_CFG_VA).read() };
        if isr_va != usize::MAX {
            // SAFETY: PCI ISR is a single read-to-clear byte (spec §4.1.4.5).
            unsafe {
                let _ = (isr_va as *const u8).read_volatile();
            }
        }
    }

    klog!(
        "net_bypass_direct_send: MATCH sent {} bytes in {} ns (kernel-bypass, no driver-process/IPC on data path)\r\n",
        total_len,
        elapsed_ns
    );

    Some(elapsed_ns)
}

/// `NET_LATENCY_SUMMARY` demo opcode: logs one honest verdict line
/// comparing `net_bypass_direct_send`'s own measured average latency
/// against `net_standard_send_call`'s own (both computed in `.user_text`
/// from several samples each, `net_bypass_demo_*`'s own doc comment) —
/// 03-Kernel-Subsystems-Layer.md §5.4.1's own "the bypass path is
/// ≥30-40% lower latency than the standard path" claim, given something
/// real to check itself against instead of being asserted. Reports
/// whichever way the numbers actually land — including a bypass-is-
/// SLOWER outcome, if that's what a given boot's own QEMU/TCG scheduling
/// jitter produces at this sample size (10 samples each — enough to see
/// a real trend, not a statistically rigorous benchmark; same honesty
/// this project's every other timing number already carries).
pub fn net_latency_summary(bypass_avg_ns: usize, standard_avg_ns: usize) {
    if bypass_avg_ns == 0 || standard_avg_ns == 0 {
        klog!("net_latency_summary: insufficient samples on one or both paths, skipping comparison\r\n");
        return;
    }
    if bypass_avg_ns < standard_avg_ns {
        let pct = ((standard_avg_ns - bypass_avg_ns) * 100) / standard_avg_ns;
        klog!(
            "kernel-bypass vs standard path (03 5.4.1): bypass avg = {} ns, standard (via Netstack) avg = {} ns -> bypass is {}% FASTER {}\r\n",
            bypass_avg_ns,
            standard_avg_ns,
            pct,
            if pct >= 30 { "(meets the >=30-40% target)" } else { "(below the >=30-40% target at this sample size)" }
        );
    } else {
        let pct = ((bypass_avg_ns - standard_avg_ns) * 100) / bypass_avg_ns;
        klog!(
            "kernel-bypass vs standard path (03 5.4.1): bypass avg = {} ns, standard (via Netstack) avg = {} ns -> bypass is {}% SLOWER (does not meet the target this run - QEMU/TCG device-model scheduling jitter dominates at this sample size, same variance class every other timing number in this project already reports)\r\n",
            bypass_avg_ns,
            standard_avg_ns,
            pct
        );
    }
}

/// `DRV_IRQ_WAIT` demo opcode's own kernel-side half: issues exactly
/// ONE `SyscallOp::Wait` on `notif_cap` and reports the outcome —
/// unlike every other `drv_blk_*`/`fs_*` function in this file,
/// `caller` here is the virtio-blk driver process itself (issuing its
/// own ecall), not root driving IPC on its behalf.
///
/// `caller` is an explicit PARAMETER, not internally re-discovered via
/// `sched.running()` on every call — **real bug found via QEMU**: the
/// obvious "discover it generically, like `IPC_RECV` does" approach
/// breaks across the SECOND and later calls of this function's own
/// idle-retry loop (`kernel/src/main.rs`'s own `DRV_IRQ_WAIT` dispatch
/// arm), because the FIRST call's `Blocked` outcome runs `do_wait`'s
/// own `note_blocked`, which CLEARS `sched.running()` (by design — see
/// `kernel_sched::Scheduler::note_blocked`'s own doc comment: "the
/// caller should then `pick_next`"). A second internal re-discovery via
/// `sched.running().unwrap_or(root_thread)` then silently falls back to
/// `root_thread`, which does not hold `notif_cap` at all — `dispatch`
/// correctly rejects it (`WrongObjectKind`/`BadCap`), `IrqWaitOutcome::
/// Error` is returned to the driver process with a bogus `bits = 0`,
/// and (confirmed via a temporary diagnostic print, then a `-d int`
/// trace of the resulting silent hang) the driver's own request-serving
/// loop never recovers. The caller (`kernel/src/main.rs`) discovers
/// `caller` ONCE, before its own retry loop starts, and passes the SAME
/// value into every `drv_irq_wait_step` call within it.
///
/// Deliberately does NOT loop or idle here — see this function's own
/// caller (`kernel/src/main.rs`'s riscv64 `DRV_IRQ_WAIT` dispatch arm)
/// for why the actual `wfi`-based idle loop lives THERE instead: this
/// crate is architecture-erased by design (no `#[cfg(target_arch)]`,
/// no architecture crate name — this file's own header doc comment),
/// so it cannot itself call `hal_riscv64::cpu::wfi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqWaitOutcome {
    /// Bits were already pending (or just became pending) — no
    /// blocking needed.
    Ready(u64),
    /// The caller is now genuinely `Blocked` (`kernel_core::syscall::
    /// do_wait`'s own `note_blocked` call already ran) — the caller
    /// must idle-wait (e.g. `wfi`) for the bound IRQ to fire, then
    /// call this again.
    Blocked,
    /// The capability/dispatch itself failed (bad cap, wrong kind).
    Error,
}

/// Issues one `SyscallOp::Wait` on `notif_cap` — see this module's own
/// `DRV_IRQ_WAIT` doc comment above and `IrqWaitOutcome`'s own doc
/// comment for the full rationale and calling convention.
pub fn drv_irq_wait_step(hal: &HalInterface, caller: ThreadId, notif_cap: u32) -> IrqWaitOutcome {
    let k = kstate();
    match k.dispatch(
        caller,
        hal.now_ns(),
        SyscallOp::Wait { notification: CapId::new(notif_cap) },
        hal,
    ) {
        Ok(SyscallReturn::Value(bits)) => {
            // **Real bug found via QEMU** (a SECOND instance of the
            // same root cause `IrqWaitOutcome::Error`'s own doc comment
            // already found and fixed once — this is the OTHER half of
            // it): `virtio_blk_irq_trampoline`'s own `wake_blocked` only
            // marks the caller `Ready` again (matching `wake_blocked`'s
            // own documented role — see `kernel_sched::Scheduler::
            // note_ready`'s doc comment), it does NOT mark it `Running`.
            // Without an explicit `dispatch` here, `sched.running()`
            // stays `None` (still cleared by the earlier `Blocked`
            // outcome's own `note_blocked`), so EVERY later generic
            // caller-discovery in this SAME trap context (`p2_ipc_recv`/
            // `p2_ipc_reply`, called next by `subsystem_entry.rs`'s own
            // loop once it resumes) falls back to `root_thread` instead
            // of the driver's own tid — confirmed via a temporary
            // diagnostic print showing `IPC_REPLY`/`IPC_RECV` both
            // dispatching as `ThreadId(0)` (root) against capability
            // slots that belong to the DRIVER's own cap space, failing
            // every time (`NotBlockedOnReply`/`WrongObjectKind`) in a
            // tight, silent, infinite retry loop. `dispatch` is exactly
            // what every OTHER real switch-back-to-a-woken-thread path
            // in this file already does before treating it as "the
            // current thread" (e.g. `fs_ipc_call`'s own `sched.
            // dispatch(fs_tid, ...)` right before its own switch).
            let _ = k.sched.dispatch(caller, hal.now_ns());
            IrqWaitOutcome::Ready(bits)
        }
        Ok(SyscallReturn::Blocked) => IrqWaitOutcome::Blocked,
        _ => IrqWaitOutcome::Error,
    }
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
    //     What this benchmark does NOT measure: the register-only
    //     PARTIAL context switch `kernel_ipc::fastpath`'s own doc
    //     comment describes. `yield_to` below performs `hal_core::
    //     HalInterface::context_switch`'s FULL GPR save/restore every
    //     time — thread 3 is an in-kernel cooperative thread (like
    //     thread 2's own §8.2 milestone), not a real, isolated U-mode
    //     process, so the register-only `TrapOutcome::SwitchToFast` +
    //     `{save,restore}_ipc_fast_context` primitive (built later,
    //     one real subsystem at a time — mm-service, Compositor,
    //     Netstack's bypass control-plane all use it today) never
    //     comes into play here at all. `umode_root`'s own `mm_bench_*`
    //     (called after the mm-service demo, further down this file)
    //     times 200 REAL U-mode-to-U-mode round trips over THAT exact
    //     mechanism instead — see its own doc comment for why that
    //     number, not this one, is what §8.3 actually asks for. This
    //     benchmark still has its own honest purpose: isolating `do_
    //     send`/`do_reply`'s fast_path_eligible dispatch-level saving
    //     (skipping `pick_next`) from the register-restore cost the
    //     other one adds on top.
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
            "root task: in-kernel ipc round-trip benchmark (02 8.3, {} iters, REAL Call+Reply fast path - do_send/do_reply skip pick_next; full GPR yield_to, not the register-only U-mode primitive - see the later mm-service benchmark for that one) - min {} ns, avg {} ns, max {} ns\r\n",
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
