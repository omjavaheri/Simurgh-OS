//! ============================================================================
//! subsystem_entry.rs — driver-mouse (x86_64-only)
//!
//! Purpose: the mouse driver's real process entry point. Waits (real,
//! interrupt-driven — `DRV_IRQ_WAIT`, same primitive `driver-i8042`
//! already uses) for `kernel_arch_glue::mouse_irq_trampoline`'s own ring
//! to have new bytes, groups them into real 3-byte PS/2 packets
//! (`mouse_packet::PacketAssembler`), and pushes each decoded event to
//! the Compositor service over a dedicated `Endpoint` — signal-then-
//! call, the exact same real pattern `driver-i8042`'s own
//! `subsystem_entry` already established.
//!
//! Position in the system: `kernel_arch_glue::spawn_mouse_driver` spawns
//! this process via `spawn_process_from_elf`. Granted THREE capabilities
//! (deterministic slots, mirroring `driver-i8042`'s own convention):
//! `DRV_ENDPOINT_CAP` (slot 0, the service `Endpoint` to Compositor),
//! `DRV_NOTIF_CAP` (slot 1, IRQ-bound), `DRV_SIGNAL_NOTIF_CAP` (slot 2,
//! shared with Compositor). Two VAs pre-mapped: `DRV_QUEUE_VA` (the raw
//! packet-byte ring `SharedRegion`) and `DRV_MSG_VA` (the service
//! `Endpoint`'s own shared message page).
//! ============================================================================

use crate::mouse_packet::PacketAssembler;
use crate::wire::encode_mouse_event;
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_CALL`.
const IPC_CALL: usize = 42;
/// Must stay numerically equal to `kernel/src/main.rs`'s
/// `sys::DRV_IRQ_WAIT`.
const DRV_IRQ_WAIT: usize = 63;
/// Must stay numerically equal to `kernel/src/main.rs`'s
/// `sys::NOTIF_SIGNAL`.
const NOTIF_SIGNAL: usize = 110;

const DRV_ENDPOINT_CAP: usize = 0;
const DRV_NOTIF_CAP: usize = 1;
const DRV_SIGNAL_NOTIF_CAP: usize = 2;
const SIGNAL_BIT: u64 = 1;

/// VA the raw packet-byte ring `SharedRegion` is mapped at — must stay
/// numerically equal to `kernel_arch_glue::DRV_MOUSE_QUEUE_VA`. Same
/// layout as `driver_i8042`'s own ring: one `u64` "write count" header
/// (offset 0) followed by `RING_CAPACITY` raw bytes (offset 8).
const DRV_QUEUE_VA: usize = 0xD860_0000;
/// VA the service `Endpoint`'s own shared message page is mapped at —
/// must stay numerically equal to `kernel_arch_glue::DRV_MOUSE_MSG_VA`.
const DRV_MSG_VA: usize = 0xD870_0000;

/// Must match `kernel_arch_glue::MOUSE_RING_CAPACITY` exactly.
const RING_CAPACITY: u64 = 32;

/// # Safety
/// Same contract as `driver_i8042::subsystem_entry::raw_syscall`.
#[inline(never)]
unsafe fn raw_syscall(a7: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") a7 => ret,
            in("rdi") a0,
            in("rsi") a1,
            options(nostack),
        );
    }
    ret
}

// Same stack-slot-reuse miscompilation every other subsystem's own
// `zero!()` macro documents in full.
macro_rules! zero {
    () => {{
        let mut v: usize = 0;
        // SAFETY: a no-op asm block (`v` is read back unchanged) — its
        // only purpose is defeating the stack-slot-reuse miscompilation
        // above. Forwarded from the enclosing `unsafe` block at every
        // call site.
        core::arch::asm!("/* {0} */", inout(reg) v, options(nomem, nostack, preserves_flags));
        v
    }};
}

/// # Safety
/// `DRV_QUEUE_VA` is mapped `U=1 R+W` in this process's own address
/// space by `kernel_arch_glue::spawn_mouse_driver`, before this process
/// is ever scheduled.
unsafe fn read_write_count() -> u64 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { (DRV_QUEUE_VA as *const u64).read_volatile() }
}

/// # Safety
/// Same contract as [`read_write_count`].
unsafe fn read_ring_byte(i: u64) -> u8 {
    let offset = 8 + (i % RING_CAPACITY) as usize;
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((DRV_QUEUE_VA + offset) as *const u8).read_volatile() }
}

/// # Safety
/// `DRV_MSG_VA` is mapped `U=1 R+W` in this process's own address space
/// by `kernel_arch_glue::spawn_mouse_driver`.
unsafe fn write_shared_message(msg: &SmallMessage) {
    let base = DRV_MSG_VA as *mut u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        base.write_volatile(msg.label);
        let words = msg.words();
        for i in 0..kernel_ipc::MSG_MAX_WORDS {
            base.add(1 + i).write_volatile(words.get(i).copied().unwrap_or(0));
        }
    }
}

/// Real interrupt-driven wait for new packet bytes — same shape as
/// `driver_i8042::subsystem_entry::wait_for_irq`.
#[inline(never)]
unsafe fn wait_for_irq() {
    // SAFETY: `raw_syscall`'s own contract.
    unsafe { raw_syscall(DRV_IRQ_WAIT, DRV_NOTIF_CAP, zero!()) };
}

/// Sends one decoded [`crate::mouse_packet::MouseEvent`] to Compositor —
/// same signal-then-call shape as `driver_i8042::subsystem_entry::
/// call_compositor`.
///
/// # Safety
/// `raw_syscall`'s own contract; `write_shared_message`'s own contract.
unsafe fn call_compositor(event: crate::mouse_packet::MouseEvent) {
    let msg = encode_mouse_event(event);
    // SAFETY: forwarded from this function's own contract.
    unsafe { write_shared_message(&msg) };
    // SAFETY: `raw_syscall`'s own contract.
    unsafe { raw_syscall(NOTIF_SIGNAL, DRV_SIGNAL_NOTIF_CAP, SIGNAL_BIT as usize) };
    // SAFETY: `raw_syscall`'s own contract. Blocks until Compositor's
    // own `Reply` wakes this thread.
    unsafe { raw_syscall(IPC_CALL, DRV_ENDPOINT_CAP, zero!()) };
}

/// The mouse driver's process entry point. Real, interrupt-driven,
/// forever: wait for new packet bytes, drain every byte the ring's own
/// write-count header reports (bounded to `RING_CAPACITY`, oldest
/// dropped if this process fell behind — same drop-oldest policy
/// `driver-i8042` already established), feed each through a real
/// [`PacketAssembler`], and `call_compositor` for every byte triple that
/// completes a real packet.
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut read_count: u64 = 0;
    let mut assembler = PacketAssembler::new();
    loop {
        // SAFETY: `wait_for_irq`'s own contract.
        unsafe { wait_for_irq() };
        // SAFETY: `read_write_count`'s own contract.
        let write_count = unsafe { read_write_count() };
        if write_count.wrapping_sub(read_count) > RING_CAPACITY {
            read_count = write_count - RING_CAPACITY;
        }
        while read_count < write_count {
            // SAFETY: `read_ring_byte`'s own contract.
            let byte = unsafe { read_ring_byte(read_count) };
            read_count += 1;
            if let Some(event) = assembler.push(byte) {
                // SAFETY: `call_compositor`'s own contract.
                unsafe { call_compositor(event) };
            }
        }
    }
}
