//! ============================================================================
//! driver-virtio-net-bin
//!
//! Purpose: this crate's REAL, separately-built process image — the
//! "subsystems as processes" packaging, mirroring `driver-virtio-blk-bin`
//! exactly (see its own doc comment for the full rationale).
//! `kernel-arch-glue::spawn_virtio_net_driver` loads this ELF into a
//! fresh, isolated process via `spawn_process_from_elf`.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.3/§5.4
//! (virtio-net over MMIO on QEMU is the MVP acceptance device for the
//! Netstack ICMP echo demo).
//!
//! Position in the system: the ONLY thing this file does is provide the
//! ELF entry point (`_start`) and this binary's own `#[panic_handler]`.
//! All real logic stays in `driver_virtio_net::subsystem_entry::
//! subsystem_main`. No `alloc`/heap — this driver's virtqueues and frame
//! buffers are fixed-size, same reasoning as `driver-virtio-blk-bin`'s
//! own allocator-free choice.
//!
//! Safety/invariants: no stack/`.bss` setup of its own — see
//! `device-manager-bin`'s own doc comment for why `_start` is reached
//! with both already valid.
//! ============================================================================
#![no_std]
#![no_main]

/// Entry point named to match this crate's own minimal linker script
/// (`ENTRY(_start)`, `subsystem-bin-riscv64.ld`).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    driver_virtio_net::subsystem_entry::subsystem_main()
}

/// This binary's own, mandatory panic handler — see `device-manager-
/// bin`'s own doc comment on why a separately-linked `[[bin]]` needs one
/// where the library crate's own modules did not.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
