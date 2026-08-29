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

/// Syscall selectors (a7 on RISC-V). Only the riscv64 build currently
/// runs a U-mode Root Task and wires the trap handler.
#[cfg(target_arch = "riscv64")]
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
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
unsafe fn raw_syscall(a7: usize, a0: usize, a1: usize) -> usize {
    let ret;
    // SAFETY: `ecall` from U-mode traps to our S-mode handler, which
    // saves and restores every register except a0 (the return value).
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

        // 7. Preemption phase (02-Microkernel-Layer.md §4). Ask the
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

/// Placeholder U-mode entry for the architectures whose real-kernel boot
/// is not yet wired (x86_64 / aarch64 still boot `kernel-stub`).
#[cfg(not(target_arch = "riscv64"))]
extern "C" fn umode_root() -> ! {
    loop {
        core::hint::spin_loop();
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
            return match kernel_arch_glue::p2_preempt_start() {
                Some((save, into)) => TrapOutcome::SwitchTo { save, into },
                None => TrapOutcome::Resume(0),
            };
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

// ----------------------------------------------------------------------------
// kernel_main — architecture-independent body
// ----------------------------------------------------------------------------

#[no_mangle]
pub extern "Rust" fn kernel_main(hal: hal_core::HalInterface, boot_info: BootInfo) -> ! {
    SerialWriter::init();
    let mut s = SerialWriter;

    let _ = writeln!(s, "|======================================================================|");
    let _ = writeln!(s, "|   Simurgh Operating System - Microkernel (Phase 2)  v0.1.0            |");
    let _ = writeln!(s, "|======================================================================|");

    match kernel_arch_glue::build(&hal, &boot_info, serial_log) {
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
            // invokes for an `ecall` from U-mode, and the tick handler it
            // invokes for a supervisor timer interrupt on a U-mode thread.
            #[cfg(target_arch = "riscv64")]
            hal_riscv64::cpu::set_syscall_handler(simurgh_syscall);
            #[cfg(target_arch = "riscv64")]
            hal_riscv64::cpu::set_tick_handler(simurgh_tick);
            // Never returns: runs the in-kernel demo, then (riscv64) maps
            // the user image U=1, activates Sv39 paging, and drops the
            // Root Task to U-mode isolated.
            #[cfg(target_arch = "riscv64")]
            {
                kernel_arch_glue::enter(&hal, state, user_image())
            }
            #[cfg(not(target_arch = "riscv64"))]
            {
                kernel_arch_glue::enter(&hal, state, kernel_arch_glue::UserImage::EMPTY)
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
