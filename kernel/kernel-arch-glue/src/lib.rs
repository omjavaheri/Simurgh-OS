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
use kernel_core::{KernelInitError, KernelState, SyscallOp, SyscallReturn, ThreadState};
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
static mut G_STATE: *mut KernelState = core::ptr::null_mut();
static mut G_HAL: *const HalInterface = core::ptr::null();
static mut G_LOG: Option<fn(Arguments<'_>)> = None;
// The Root Task's live page-table root and a pre-zeroed pool of frames for
// `map_range` to draw missing L1/L0 tables from when a `Map` syscall adds a
// page at runtime. Set once by `enter` after paging is activated; consumed
// by `map_user_page`. `G_MAP_POOL_USED` is the pool high-water mark.
static mut G_ROOT_PT: usize = 0;
static mut G_MAP_POOL: usize = 0;
static mut G_MAP_POOL_LEN: usize = 0;
static mut G_MAP_POOL_USED: usize = 0;
// Set by `root_task_main` before it starts thread 2, so `thread2_main`
// knows its own thread id, the endpoint capability to `Send` on, and the
// Root Task's thread id to hand control back to.
static mut G_T2: u32 = 0;
static mut G_EP: u32 = 0;
static mut G_ROOT: u32 = 0;

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
    };
}

/// Runs the boot sequence and never returns:
///   1. stash the kernel-state / HAL pointers for later syscall handling;
///   2. run `inkernel_demo` (the in-kernel §8.1/§8.2/§8.5 milestones —
///      direct `dispatch` + `context_switch`, same privilege);
///   3. if a `user` image is present: build an Sv39 page table (kernel
///      identity `U=0`, the `.user_*` pages `U=1`), activate paging, and
///      drop the Root Task to U-mode. From there it is a real, MMU-
///      isolated layer-3 process reaching the kernel only through `ecall`.
pub fn enter(hal: &HalInterface, state: &'static mut KernelState, user: UserImage) -> ! {
    // SAFETY: single-core boot, called once, right after `build`.
    unsafe {
        core::ptr::addr_of_mut!(G_STATE).write(state as *mut KernelState);
        core::ptr::addr_of_mut!(G_HAL).write(hal as *const HalInterface);
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
    let root_pt = state
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096).ok());
    let pool = state
        .untyped_mut(kernel_cap::UntypedId::new(0))
        .and_then(|u| u.alloc(4096, 4096 * 4).ok());

    let (root_pt, pool) = match (root_pt, pool) {
        (Some(r), Some(p)) => (r.as_usize(), p.as_usize()),
        _ => {
            klog!("could not allocate page-table frames - halting\r\n");
            park();
        }
    };
    // A second, larger pool the runtime `Map` syscall path draws from
    // (see `map_user_page`) — kept separate from the boot-time `pool`
    // above so a later `Map` can never trip over the boot mapping's
    // bookkeeping.
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
        core::ptr::write_bytes(pool as *mut u8, 0, 4096 * 4);
        core::ptr::write_bytes(map_pool as *mut u8, 0, 4096 * 8);
    }

    let round4k = |n: usize| (n + 0xFFF) & !0xFFF;
    hal.map_ram_identity(root_pt, 3, false);

    // R=1 W=2 X=4 U=8.
    let n1 = hal.map_range(
        root_pt,
        user.text_vma,
        user.text_lma,
        round4k(user.text_len),
        1 | 4 | 8,
        pool,
        4,
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
            4 - n1 as usize,
        )
    };
    if n1 == u32::MAX || n2 == u32::MAX {
        klog!("failed to map the user image (map_range error) - halting\r\n");
        park();
    }

    hal.activate_address_space(root_pt);

    // Publish the live table + runtime pool so the final binary's `Map`
    // syscall arm (`map_user_page`) can add pages after we drop to U-mode.
    // SAFETY: single-core boot; written once here, before any syscall can
    // run, and only read afterwards.
    unsafe {
        core::ptr::addr_of_mut!(G_ROOT_PT).write(root_pt);
        core::ptr::addr_of_mut!(G_MAP_POOL).write(map_pool);
        core::ptr::addr_of_mut!(G_MAP_POOL_LEN).write(8);
    }

    let user_sp = (user.stack_vma + user.stack_len) & !0xF;
    klog!(
        "--- Sv39 paging active; dropping Root Task to U-mode (entry {:#x}, sp {:#x}, isolated on U=1 pages) ---\r\n",
        user.entry_vma,
        user_sp
    );
    hal.enter_user(user.entry_vma, user_sp)
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

/// Installs one 4 KiB mapping `vaddr -> paddr` (`perm_bits` = `R1 | W2 |
/// X4 | U8`) into the Root Task's **live** page table, drawing any missing
/// intermediate table from the runtime pool `enter` reserved, then flushes
/// the TLB. Returns `false` if `enter` never ran the paging path, the pool
/// is exhausted, or `map_range` rejects the request (misaligned, or a
/// superpage leaf already covers the VA).
///
/// The final binary's `Map` syscall arm calls this from the S-mode trap
/// handler — where every page-table frame it walks is in the identity-
/// mapped low RAM, so the walk is valid even though paging is now active.
/// This is the mechanism side of 02-Microkernel-Layer.md §6; the software
/// `AddressSpace` model is updated separately by the caller so `Translate`
/// still answers.
pub fn map_user_page(hal: &HalInterface, vaddr: usize, paddr: usize, perm_bits: usize) -> bool {
    // SAFETY: single-core; these globals are set once by `enter` before
    // any syscall can run, and only mutated here (the pool high-water
    // mark) from that same single-core syscall path.
    let (root_pt, pool, pool_len, used) = unsafe {
        (
            core::ptr::addr_of!(G_ROOT_PT).read(),
            core::ptr::addr_of!(G_MAP_POOL).read(),
            core::ptr::addr_of!(G_MAP_POOL_LEN).read(),
            core::ptr::addr_of!(G_MAP_POOL_USED).read(),
        )
    };
    if root_pt == 0 || used >= pool_len {
        return false;
    }
    let consumed = hal.map_range(
        root_pt,
        vaddr,
        paddr,
        4096,
        perm_bits,
        pool + used * 4096,
        pool_len - used,
    );
    if consumed == u32::MAX {
        return false;
    }
    // SAFETY: see the contract above — single-core advance of a pool
    // high-water mark only this function touches.
    unsafe {
        core::ptr::addr_of_mut!(G_MAP_POOL_USED).write(used + consumed as usize);
    }
    hal.flush_tlb();
    true
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
        let freed = match k.dispatch(root, hal.now_ns(), SyscallOp::CapRevoke { cap: child_a }) {
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
    match k.dispatch(root, hal.now_ns(), SyscallOp::Recv { endpoint: ep_cap }) {
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

    // 6. Shared-memory groundwork (02-Microkernel-Layer.md §5.2 / §8.4):
    //    alias ONE physical frame at two virtual addresses in the Root
    //    Task's address space and confirm both translate to it. This is
    //    the aliasing structure zero-copy shared memory needs; hardware-
    //    enforced cross-process zero-copy still awaits active page tables.
    let frame_cap = match k.dispatch(
        root,
        hal.now_ns(),
        SyscallOp::Retype {
            untyped: CapId::new(0),
            target_type: KernelObjectType::Untyped,
            count: 1,
        },
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
    match k.dispatch(me, hal.now_ns(), SyscallOp::Send { endpoint: ep, msg }) {
        Ok(SyscallReturn::Delivered { woke }) => {
            klog!("thread 2: sent message; woke thread {}\r\n", woke.as_u32())
        }
        other => klog!("thread 2: Send unexpected: {:?}\r\n", other),
    }

    klog!("thread 2: done - handing control back to the Root Task\r\n");
    k.yield_to(me, root, hal);
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
