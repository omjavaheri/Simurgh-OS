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
    /// Map one page: `a0` = virtual address, `a1` = physical address, RW.
    /// Records the mapping in the Root Task's address space. Returns 0 on
    /// success, `usize::MAX` on error.
    ///
    /// MVP: operates on the Root Task's address space directly (not yet
    /// capability-gated per `02-Microkernel-Layer.md §6`), and the
    /// address space is still a software model — no Sv39 page-table
    /// entries are written and `satp` stays 0. This exercises the
    /// syscall -> `AddressSpace::map` path; real PTEs + a capability
    /// argument are the follow-up.
    pub const MAP_PAGE: usize = 2;
    /// Translate `a0` = virtual address through the Root Task's address
    /// space; returns the physical address, or `usize::MAX` if unmapped.
    pub const TRANSLATE: usize = 3;
    /// No arguments — the kernel logs a fixed "Root Task alive under
    /// paging" line. Used by the isolated U-mode entry, which carries no
    /// string literals of its own.
    pub const ALIVE: usize = 9;
    /// `a0` = a value the kernel should echo into the log (used to report
    /// a `TRANSLATE` result from code that cannot format it itself).
    pub const REPORT: usize = 10;
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
    // preserves every register except a0. All arguments here are plain
    // integers; nothing is dereferenced in U-mode.
    unsafe {
        raw_syscall(sys::ALIVE, 0, 0);
        let _cap = raw_syscall(sys::RETYPE_ENDPOINT, 0, 0);
        // Map a page in an empty part of our address space and read the
        // translation back, then have the kernel report it.
        raw_syscall(sys::MAP_PAGE, 0xD000_0000, 0x8800_0000);
        let pa = raw_syscall(sys::TRANSLATE, 0xD000_0040, 0);
        raw_syscall(sys::REPORT, pa, 0);
        // Spin forever without touching memory or any relocation.
        core::arch::asm!("1:", "j 1b", options(noreturn));
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
) -> usize {
    use kernel_core::{SyscallOp, SyscallReturn};
    use kernel_mm::KernelObjectType;

    let k = kernel_arch_glue::kstate();
    let hal = kernel_arch_glue::khal();
    let root = k.root_thread;

    match a7 {
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
            ) {
                Ok(SyscallReturn::NewCaps { cap, .. }) => cap.as_u32() as usize,
                _ => usize::MAX,
            }
        }
        sys::MAP_PAGE => {
            let space = match k.addr_space_mut(k.root_addr_space) {
                Some(s) => s,
                None => return usize::MAX,
            };
            match space.map(
                hal_core::VirtAddr::new(a0),
                hal_core::PhysAddr::new(a1),
                kernel_mm::PAGE_SIZE,
                hal_core::MapPermissions::KERNEL_DATA,
            ) {
                Ok(()) => 0,
                Err(_) => usize::MAX,
            }
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
                "root task (U-mode): ecall Map+Translate result = {:#x}\r\n",
                a0
            ));
            0
        }
        _ => usize::MAX,
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
            // invokes for an `ecall` from U-mode.
            #[cfg(target_arch = "riscv64")]
            hal_riscv64::cpu::set_syscall_handler(simurgh_syscall);
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
