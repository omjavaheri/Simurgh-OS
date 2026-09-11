//! ============================================================================
//! driver-i8042-bin
//!
//! Purpose: this crate's REAL, separately-built process image — the
//! "subsystems as processes" packaging, mirroring `driver-virtio-blk-
//! bin` exactly (see that file's own doc comment for the full
//! rationale). `kernel_arch_glue::spawn_i8042_driver` loads this ELF
//! into a fresh, isolated process via `spawn_process_from_elf`.
//!
//! Position in the system: the ONLY thing this file does is provide the
//! ELF entry point (`_start`) and this binary's own `#[panic_handler]`.
//! All real logic stays in `driver_i8042::subsystem_entry::
//! subsystem_main`. No `alloc`/heap — this driver's own state (a single
//! `u64` read counter, on the stack) needs no dynamic allocation, same
//! reasoning as `driver-virtio-blk-bin`'s own allocator-free choice.
//! ============================================================================
#![no_std]
#![no_main]

/// Entry point named to match this crate's own minimal linker script
/// (`ENTRY(_start)`, `subsystem-bin-x86_64.ld`).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    driver_i8042::subsystem_entry::subsystem_main()
}

/// This binary's own, mandatory panic handler — see `driver-virtio-blk-
/// bin`'s own doc comment on why a separately-linked `[[bin]]` needs one
/// where the library crate's own modules did not.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
