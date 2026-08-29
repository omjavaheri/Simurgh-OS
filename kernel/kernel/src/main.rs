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
    //! RISC-V: SBI legacy console putchar (extension 0x01), always present
    //! on OpenSBI / QEMU virt.
    const SBI_EXT_LEGACY_CONSOLE_PUTCHAR: usize = 0x01;

    pub fn init() {}

    pub fn write_byte(byte: u8) {
        // SAFETY: SBI legacy console putchar is universally implemented and
        // well-defined for any byte value per the SBI spec.
        unsafe {
            core::arch::asm!(
                "ecall",
                in("a7") SBI_EXT_LEGACY_CONSOLE_PUTCHAR,
                in("a6") 0usize,
                in("a0") byte as usize,
                lateout("a0") _,
            );
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
            // Never returns: seeds the Root Task context and switches in.
            kernel_arch_glue::enter(&hal, state)
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
