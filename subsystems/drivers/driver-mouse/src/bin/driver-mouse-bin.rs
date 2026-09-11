//! ============================================================================
//! driver-mouse-bin
//!
//! Purpose: this crate's REAL, separately-built process image — mirrors
//! `driver-i8042-bin` exactly. `kernel_arch_glue::spawn_mouse_driver`
//! loads this ELF into a fresh, isolated process.
//! ============================================================================
#![no_std]
#![no_main]

/// Entry point named to match this crate's own minimal linker script.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    driver_mouse::subsystem_entry::subsystem_main()
}

/// This binary's own, mandatory panic handler.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
