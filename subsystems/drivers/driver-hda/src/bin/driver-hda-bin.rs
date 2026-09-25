//! driver-hda-bin: process image entry point (`_start`) and panic handler; all
//! logic lives in `driver_hda::subsystem_entry::subsystem_main`. No heap.
#![no_std]
#![no_main]

/// Entry point named to match this crate's own minimal linker script
/// (`ENTRY(_start)`, `subsystem-bin-x86_64.ld`).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    driver_hda::subsystem_entry::subsystem_main()
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
