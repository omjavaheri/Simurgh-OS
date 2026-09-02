//! ============================================================================
//! netstack-bin
//!
//! Purpose: this crate's REAL, separately-built process image — the
//! "subsystems as processes" packaging, mirroring `fs-native-bin`/
//! `driver-virtio-net-bin` exactly (see either's own doc comment for the
//! full rationale). `kernel_arch_glue::spawn_netstack_service` loads this
//! ELF into a fresh, isolated process via `spawn_process_from_elf`.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.3/§5.4 — a
//! real, isolated Netstack process that talks to `driver-virtio-net`
//! over genuine IPC (`sys::IPC_CALL`), not driven directly by
//! `kernel-arch-glue` the way the driver's own demo previously was.
//!
//! Position in the system: the ONLY thing this file does is provide the
//! ELF entry point (`_start`), this binary's own `#[panic_handler]`, and
//! a global allocator (`netstack::{build_arp_request, parse_arp_reply,
//! build_echo_request, parse_echo_reply}` all return `alloc::vec::Vec`).
//! All real logic stays in `netstack::subsystem_entry::subsystem_main`.
//!
//! Safety/invariants: no stack/`.bss` setup of its own — see
//! `device-manager-bin`'s own doc comment for why `_start` is reached
//! with both already valid.
//! ============================================================================
#![no_std]
#![no_main]

// ----------------------------------------------------------------------------
// A minimal global allocator — same bump-allocator shape `fs-native-bin`
// already uses for the identical reason (`netstack`'s own ARP/ICMP
// builders return `alloc::vec::Vec`).
// ----------------------------------------------------------------------------

const HEAP_BYTES: usize = 32 * 1024;

/// Backing storage for the bump allocator below. `.bss`, zeroed by the
/// loader — never read before being written by an allocation.
static mut HEAP: [u8; HEAP_BYTES] = [0; HEAP_BYTES];

struct BumpAllocator {
    offset: core::sync::atomic::AtomicUsize,
}

// SAFETY: `alloc`'s only memory access is through `HEAP.as_mut_ptr()` at
// an offset this same call reserved via the atomic bump (never handed
// out to two callers — single-threaded, and the compare-exchange below
// is the sole writer of `offset`); `dealloc` touches nothing.
unsafe impl core::alloc::GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        use core::sync::atomic::Ordering;
        let (align, size) = (layout.align(), layout.size());
        loop {
            let cur = self.offset.load(Ordering::Relaxed);
            let aligned = (cur + align - 1) & !(align - 1);
            let Some(new_offset) = aligned.checked_add(size) else {
                return core::ptr::null_mut();
            };
            if new_offset > HEAP_BYTES {
                return core::ptr::null_mut();
            }
            if self
                .offset
                .compare_exchange(cur, new_offset, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                // SAFETY: `aligned + size <= HEAP_BYTES`, just checked;
                // `aligned` is a multiple of `align` by construction.
                return unsafe { core::ptr::addr_of_mut!(HEAP).cast::<u8>().add(aligned) };
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        // No reclaim — see this section's own doc comment.
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator {
    offset: core::sync::atomic::AtomicUsize::new(0),
};

/// Entry point named to match this crate's own minimal linker script
/// (`ENTRY(_start)`, `subsystem-bin-<arch>.ld`).
#[no_mangle]
pub extern "C" fn _start() -> ! {
    netstack::subsystem_entry::subsystem_main()
}

/// This binary's own, mandatory panic handler — see `device-manager-
/// bin`'s own doc comment on why a separately-linked `[[bin]]` needs
/// one where the library crate's own modules did not.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
