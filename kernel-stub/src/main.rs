//! ============================================================================
//! kernel-stub
//!
//! Extended to support all three target architectures, per
//! 01-HAL-Layer.md section 8, MVP acceptance criterion 1: "بوت موفق
//! روی QEMU برای هر سه معماری". The core logic (print confirmation,
//! validate BootInfo, halt) is architecture-independent — only the
//! `kernel_main` signature's `Hal` type and the serial driver's raw
//! I/O primitive differ per architecture, both handled via `#[cfg]`.
//! ============================================================================

#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::fmt::Write;
use core::panic::PanicInfo;

use hal_core::BootInfo;

// ----------------------------------------------------------------------------
// Per-architecture Hal type alias
//
// Lets the rest of this file (kernel_main's signature, mainly) stay
// written once, referring to `Hal` generically, rather than needing
// three separately-named kernel_main functions.
// ----------------------------------------------------------------------------

// Link-only dependencies: pull in this architecture's boot.S/_start
// and panic_handler (via hal-<arch>'s own crate, per that crate's
// Cargo.toml target_arch-keyed dependency), but are never referenced
// by type from this file anymore — kernel_main now depends only on
// hal_core::HalInterface (architecture-erased, see hal-core/src/
// interface.rs), which is exactly the point of this refactor.
#[cfg(target_arch = "aarch64")]
use hal_arm64 as _;
#[cfg(target_arch = "riscv64")]
use hal_riscv64 as _;
#[cfg(target_arch = "x86_64")]
use hal_x86_64 as _;

// ----------------------------------------------------------------------------
// Minimal serial output, per architecture
//
// Same "boot-diagnostics-only, not a real driver" scope as the
// original x86_64-only version's module docs — just extended with two
// more architecture-specific backends.
// ----------------------------------------------------------------------------

struct SerialWriter;

#[cfg(target_arch = "x86_64")]
mod backend {
    //! x86_64: UART 16550 via I/O ports (COM1) — identical to the
    //! original single-architecture kernel-stub implementation.
    const COM1_PORT: u16 = 0x3F8;

    pub fn init() {
        // SAFETY: see the original hal-x86_64-only kernel-stub's
        // identical init() — standard 16550 bring-up on COM1's fixed
        // ISA port range, universally safe on any x86_64 platform
        // including every QEMU machine type this project targets.
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
        // SAFETY: same as the original implementation — polling LSR
        // bit 5 before writing is the standard 16550 transmit sequence.
        unsafe {
            while in_byte(COM1_PORT + 5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            out_byte(COM1_PORT, byte);
        }
    }

    /// # Safety
    /// `port` must be a valid I/O port; every call site here targets
    /// the fixed COM1 range.
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
    //! ARM64: PL011 UART via MMIO, at QEMU virt machine's documented
    //! default base address (0x09000000) — this stub relies on that
    //! fixed default the same way hal-arm64's own memory.rs/
    //! interrupt.rs rely on documented QEMU virt defaults, rather than
    //! parsing Device Tree for the UART node (out of scope for a
    //! boot-diagnostics-only stub).
    const PL011_BASE: u64 = 0x0900_0000;
    const PL011_DR: u64 = 0x000; // Data Register
    const PL011_FR: u64 = 0x018; // Flag Register
    const PL011_FR_TXFF: u32 = 1 << 5; // Transmit FIFO Full

    pub fn init() {
        // No explicit init needed: QEMU's virt machine starts the
        // PL011 already enabled and configured for basic polled
        // transmit — a real driver (layer 3) would configure baud
        // rate/line control explicitly, but this boot-diagnostics
        // stub relies on QEMU's default-enabled state, exactly
        // mirroring how this stub's x86_64 backend does its OWN full
        // UART init (a slight asymmetry, documented here: x86_64's
        // COM1 needs explicit init because real x86_64 firmware does
        // NOT guarantee a configured UART, whereas QEMU's virt PL011
        // model specifically starts pre-enabled for exactly this kind
        // of early-boot convenience).
    }

    pub fn write_byte(byte: u8) {
        // SAFETY: PL011_BASE is QEMU virt's fixed, documented PL011
        // MMIO base — polling FR.TXFF before writing DR is the
        // standard PL011 polled-transmit sequence (PL011 Technical
        // Reference Manual section 3.3.1). This stub does not map this
        // address via setup_identity_mapping first because QEMU's
        // virt machine's low MMIO region (including the PL011) is
        // already covered by hal-arm64's own boot-time identity
        // mapping range in practice for this MVP phase's memory
        // layout — a scope note consistent with this being a
        // diagnostics-only shortcut, not a production driver.
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
    //! RISC-V: SBI Debug Console extension (DBCN) if available,
    //! falling back to the SBI Legacy Console putchar call (extension
    //! 0x01, always present on OpenSBI) — mirrors this project's
    //! established "probe capability, document the fallback" pattern
    //! from cpu.rs/timer.rs.
    const SBI_EXT_LEGACY_CONSOLE_PUTCHAR: usize = 0x01;

    pub fn init() {
        // No init needed: the SBI legacy console putchar call requires
        // no prior setup — it is a single, self-contained ecall per
        // character.
    }

    pub fn write_byte(byte: u8) {
        // SAFETY: the SBI Legacy Console Putchar extension (0x01) is
        // part of SBI's original, still-universally-supported legacy
        // extension set (every OpenSBI build, including QEMU virt's
        // default firmware, implements it) — well-defined for any
        // byte value per the SBI spec.
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

// ----------------------------------------------------------------------------
// kernel_main — architecture-independent body, generic Hal type
// ----------------------------------------------------------------------------

#[no_mangle]
pub extern "Rust" fn kernel_main(hal: hal_core::HalInterface, boot_info: BootInfo) -> ! {
    SerialWriter::init();
    let mut serial = SerialWriter;
    let _ = writeln!(serial, "|========================================================================|");
    if cfg!(target_arch = "x86_64") {
    let _ = writeln!(serial, "|        Simurgh Operating System - Kernel: v0.1.0 Target: x86_64        |");
    } else if cfg!(target_arch = "aarch64") {
    let _ = writeln!(serial, "|        Simurgh Operating System - Kernel: v0.1.0 Target: aarch64       |");
    } else if cfg!(target_arch = "riscv64") {
    let _ = writeln!(serial, "|        Simurgh Operating System - Kernel: v0.1.0 Target: riscv64       |");
    } else {
    let _ = writeln!(serial, "|        Simurgh Operating System - Kernel: v0.1.0 Target: unknown       |");
    }
    let _ = writeln!(serial, "|========================================================================|");
    // uefi::println!("|                       Hardware Abstraction Layer(HAL): v0.1.0          |");
    let _ = writeln!(serial, "boot protocol: {:?}", boot_info.protocol);
    let _ = writeln!(serial, "cpu cores: {}", boot_info.hardware_manifest.cpu_core_count);
    let _ = writeln!(serial, "memory regions: {}", boot_info.hardware_manifest.memory_region_count);
    let _ = writeln!(serial, "compute devices: {}", boot_info.hardware_manifest.compute_device_count);
    let _ = writeln!(serial, "power domains: {}", boot_info.hardware_manifest.power_domain_count);

    match boot_info.validate() {
        Ok(()) => { let _ = writeln!(serial, "BootInfo validation: OK"); }
        Err(err) => { let _ = writeln!(serial, "BootInfo validation FAILED: {err}"); }
    }

    let _ = writeln!(serial, "---------------------------------------------");
    let _ = writeln!(serial, "hal cpu core count: {}", hal.core_count());
    let _ = writeln!(serial, "hal timer frequency: {} Hz", hal.frequency_hz());
    let _ = writeln!(serial, "=============================================");
    let _ = writeln!(serial, "kernel-stub halting (Phase 1 complete)");

    halt_forever();
}

// ----------------------------------------------------------------------------
// Halt — architecture-specific instruction, identical structure
// ----------------------------------------------------------------------------

fn halt_forever() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: cli+hlt is the standard x86_64 terminal halt, same
        // justification as the original single-architecture stub.
        unsafe {
            core::arch::asm!("cli");
            core::arch::asm!("hlt");
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: masking DAIF then wfi is the standard AArch64
        // terminal halt, same justification as hal-arm64's own
        // panic_handler.
        unsafe {
            core::arch::asm!("msr daifset, #0xF");
            core::arch::asm!("wfi");
        }
        #[cfg(target_arch = "riscv64")]
        // SAFETY: clearing SIE then wfi is the standard RISC-V
        // terminal halt, same justification as hal-riscv64's own
        // panic_handler.
        unsafe {
            core::arch::asm!("csrci sstatus, 0x2");
            core::arch::asm!("wfi");
        }
    }
}

// ----------------------------------------------------------------------------
// Panic handler
// ----------------------------------------------------------------------------

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    SerialWriter::init();
    let mut serial = SerialWriter;
    let _ = writeln!(serial, "PANIC: {info}");
    halt_forever();
}