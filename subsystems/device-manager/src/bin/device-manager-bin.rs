//! ============================================================================
//! device-manager-bin
//!
//! Purpose: this crate's REAL, separately-built process image — the
//! "subsystems as processes" packaging follow-up (IMPLEMENTATION-PLAN.md).
//! Before this, `subsystem_entry::subsystem_main` was compiled INTO the
//! `kernel` binary itself (a dependency, placed via `#[link_section =
//! ".user_text"]` alongside every other demo process) — spawnable, but
//! not genuinely a separate program. This `[[bin]]` builds device-manager
//! as its OWN standalone, statically-linked ELF executable for the exact
//! same `targets/<arch>-hal.json` custom targets the kernel itself uses,
//! which `kernel-arch-glue::spawn_process_from_elf` parses (via the
//! shared `elf-loader` crate) and loads into a fresh process at spawn
//! time — `include_bytes!`-embedded in the kernel image, never linked
//! into it.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1/§4 (this
//! is exactly the "هرکدام یک پروسه‌ی ایزوله است" packaging folder
//! structure implies — a real, separate program, not a function pointer
//! into the kernel's own image).
//!
//! Position in the system: the ONLY thing this file does is provide the
//! ELF entry point (`_start`) and this binary's own `#[panic_handler]`
//! (mandatory — unlike `subsystem_entry.rs`'s `subsystem_main`, which is
//! a library function with no binary-crate obligations of its own, THIS
//! crate is now a genuinely separate, final `no_std`/`no_main` binary,
//! so it needs the one-`#[panic_handler]`-per-binary machinery every
//! other final binary crate in this workspace already has — see
//! `kernel/kernel/src/main.rs`'s own doc comment on why). All real
//! logic stays in `device_manager::subsystem_entry::subsystem_main`
//! (arch-generic — no `#[cfg(target_arch)]` needed here either, since
//! that function's own per-arch `raw_syscall` is already the ONE narrow,
//! documented exception to "no cfg(target_arch) in kernel/subsystems").
//!
//! Safety/invariants: no stack/`.bss` setup of its own — unlike a real
//! boot entry point (which must zero `.bss` and set up its own stack
//! before any Rust code can safely run), `_start` here is reached with
//! BOTH already valid: `kernel-arch-glue::spawn_process_from_elf`'s
//! loader zero-fills each `PT_LOAD` segment's `mem_size - file_size`
//! tail (standard ELF `.bss`-inside-`PT_LOAD` handling — see
//! `elf-loader`'s own doc comment), and the kernel allocates and maps
//! this process's stack separately, seeding the initial `UserContext`'s
//! stack pointer before ever resuming it — this function is the FIRST
//! Rust code that runs in this process, already on a valid stack.
//! ============================================================================
#![no_std]
#![no_main]

/// Entry point named to match this crate's own minimal linker script
/// (`ENTRY(_start)`, `subsystem-bin-linker.ld`) — the same convention
/// every `hal-<arch>` crate's own boot assembly jumps into, reused here
/// even though this process needs none of that assembly's own
/// bss-zeroing/stack-setup work (see this file's own doc comment).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    device_manager::subsystem_entry::subsystem_main()
}

/// This binary's own, mandatory panic handler (see this file's doc
/// comment on why a separately-linked `[[bin]]` needs one where the
/// library crate `subsystem_entry` module did not). Halts via the same
/// side-effect-free spin this workspace's other minimal handlers use
/// where no architecture-specific `hlt`/`wfi` is available without a
/// `hal-<arch>` dependency this crate deliberately does not take.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
