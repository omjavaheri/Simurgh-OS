//! ============================================================================
//! subsystem_entry.rs — driver-mouse (x86_64-only)
//!
//! Purpose: the mouse driver's real process entry point. Waits (real,
//! interrupt-driven — `DRV_IRQ_WAIT`, same primitive `driver-i8042`
//! already uses) for `kernel_arch_glue::mouse_irq_trampoline`'s own ring
//! to have new bytes, groups them into real 3-byte PS/2 packets
//! (`mouse_packet::PacketAssembler`), merges each drained run into as few
//! events as possible (`coalesce::Coalescer` — every button edge kept),
//! and pushes them to the Compositor service over a dedicated
//! `Endpoint` — signal-then-
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
// Bit 2: driver-i8042 owns bit 1 and both may signal ONE shared Notification
// (kernel_arch_glue::G_INPUT_SIGNAL_CAP), which Compositor tells apart by bit.
const SIGNAL_BIT: u64 = 2;

/// VA the raw packet-byte ring `SharedRegion` is mapped at — must stay
/// numerically equal to `kernel_arch_glue::DRV_MOUSE_QUEUE_VA`. Same
/// layout as `driver_i8042`'s own ring: one `u64` "write count" header
/// (offset 0) followed by `RING_CAPACITY` raw bytes (offset 8).
const DRV_QUEUE_VA: usize = 0xD860_0000;
/// VA the service `Endpoint`'s own shared message page is mapped at —
/// must stay numerically equal to `kernel_arch_glue::DRV_MOUSE_MSG_VA`.
const DRV_MSG_VA: usize = 0xD870_0000;

/// Must match `kernel_arch_glue::MOUSE_RING_CAPACITY` exactly. 2048
/// bytes (~680 packets), not the original 32 (~10): bytes keep arriving
/// while this process waits in a `Call` for the Compositor, which can
/// take a whole ui-core frame, and at 32 the kernel could overwrite
/// unread bytes — lost motion plus a packet stream misaligned until the
/// next sync byte. The page has room for it, so there is no reason to
/// run that risk. Must stay below `RING_READ_COUNT_OFF - 8` (the page's
/// tail holds the measurement words).
const RING_CAPACITY: u64 = 2048;

/// Byte offset in the ring page where THIS process publishes how many
/// bytes it has consumed so far (a `u64`). Must match `kernel_arch_glue::
/// MOUSE_RING_READ_COUNT_OFF`. The kernel's trampoline compares it with
/// its own write count to tell "this byte lands in an empty ring" — the
/// moment the next wake-latency measurement starts (see
/// [`RING_PENDING_SINCE_OFF`]).
const RING_READ_COUNT_OFF: usize = 4080;
/// Byte offset in the ring page where `kernel_arch_glue::
/// mouse_irq_trampoline` stamps `now_ns` whenever it writes a byte into
/// an EMPTY ring (per [`RING_READ_COUNT_OFF`]) — the IRQ time of the
/// oldest byte this process has not read yet. Must match `kernel_arch_
/// glue::MOUSE_RING_PENDING_SINCE_OFF`. Measurement only
/// (`crate::latency_stats`); nothing functional depends on it.
const RING_PENDING_SINCE_OFF: usize = 4088;

/// VA of this process's own debug-print page — the fixed VA
/// `sys::SERIAL_PRINT` reads from in the CALLING process's address space
/// (`kernel/src/main.rs`'s `SHELL_OUT_VA`, mapped for this process by
/// `kernel_arch_glue::spawn_mouse_driver`). Used only for the
/// `crate::latency_stats` report line.
const PRINT_VA: usize = 0xD900_0000;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::NOW_NS`.
const NOW_NS: usize = 86;
/// Must stay numerically equal to `kernel/src/main.rs`'s
/// `sys::SERIAL_PRINT`.
const SERIAL_PRINT: usize = 118;

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

/// Publishes how many ring bytes this process has consumed (see
/// [`RING_READ_COUNT_OFF`]).
///
/// # Safety
/// Same contract as [`read_write_count`].
unsafe fn publish_read_count(read_count: u64) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((DRV_QUEUE_VA + RING_READ_COUNT_OFF) as *mut u64).write_volatile(read_count) };
}

/// The IRQ time of the oldest unread byte (see
/// [`RING_PENDING_SINCE_OFF`]); `0` if the kernel never stamped one.
///
/// # Safety
/// Same contract as [`read_write_count`].
unsafe fn read_pending_since() -> u64 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((DRV_QUEUE_VA + RING_PENDING_SINCE_OFF) as *const u64).read_volatile() }
}

/// # Safety
/// `raw_syscall`'s own contract.
unsafe fn now_ns() -> u64 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { raw_syscall(NOW_NS, zero!(), zero!()) as u64 }
}

/// Prints the `crate::latency_stats` report line and resets the totals.
///
/// # Safety
/// `PRINT_VA` is mapped `U=1 R+W` by `kernel_arch_glue::
/// spawn_mouse_driver`; `raw_syscall`'s own contract.
unsafe fn print_report(stats: &mut crate::latency_stats::LatencyStats) {
    // SAFETY: forwarded from this function's own contract.
    let now = unsafe { now_ns() };
    let mut line = [0u8; 256];
    let n = stats.format_report(now, &mut line);
    for (i, &b) in line[..n].iter().enumerate() {
        // SAFETY: forwarded from this function's own contract (one page,
        // `n <= 256`).
        unsafe { ((PRINT_VA + i) as *mut u8).write_volatile(b) };
    }
    // SAFETY: `raw_syscall`'s own contract.
    unsafe { raw_syscall(SERIAL_PRINT, n, zero!()) };
    *stats = crate::latency_stats::LatencyStats::new();
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

/// [`call_compositor`] plus the measurement bookkeeping: counts the
/// message and, once a MIDDLE-button press edge has been handed over,
/// prints the `crate::latency_stats` report (see that module for why the
/// middle button is the marker).
///
/// # Safety
/// [`call_compositor`]'s and [`print_report`]'s own contracts.
unsafe fn send_event(
    event: crate::mouse_packet::MouseEvent,
    stats: &mut crate::latency_stats::LatencyStats,
    last_middle: &mut bool,
) {
    stats.messages += 1;
    stats.net_dx += event.dx as i64;
    stats.net_dy += event.dy as i64;
    // SAFETY: forwarded from this function's own contract.
    unsafe { call_compositor(event) };
    if event.middle && !*last_middle {
        // SAFETY: forwarded from this function's own contract.
        unsafe { print_report(stats) };
    }
    *last_middle = event.middle;
}

/// The mouse driver's process entry point. Real, interrupt-driven,
/// forever: wait for new packet bytes, then drain the ring until it is
/// really empty — re-reading the kernel's write count after every pass,
/// because more bytes keep arriving while this process is blocked in a
/// `Call` — feeding each byte through a [`PacketAssembler`] and each
/// packet through a [`Coalescer`](crate::coalesce::Coalescer). Button
/// changes go out the moment they are seen; all remaining motion goes
/// out as ONE summed event when the ring is empty.
///
/// Why batch (measured, see `crate::coalesce`'s module doc comment and
/// the README entry of 2026-09-24): the Compositor takes one driver
/// message per display request it serves, so one message per 3-byte
/// packet let motion pile up behind that gate and the cursor trailed the
/// hand by more and more. The message format is unchanged — the
/// Compositor cannot tell a summed event from a single big packet.
///
/// Ring overflow (this process fell more than `RING_CAPACITY` bytes
/// behind) still drops the oldest bytes, as `driver-i8042` does; the
/// assembler's sync-bit check then resynchronizes.
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut read_count: u64 = 0;
    let mut assembler = PacketAssembler::new();
    let mut coalescer = crate::coalesce::Coalescer::new();
    let mut stats = crate::latency_stats::LatencyStats::new();
    let mut last_middle = false;
    loop {
        // SAFETY: `wait_for_irq`'s own contract.
        unsafe { wait_for_irq() };
        loop {
            // SAFETY: `read_write_count`'s own contract.
            let write_count = unsafe { read_write_count() };
            if write_count == read_count {
                break;
            }
            // SAFETY: `read_pending_since`/`now_ns`'s own contracts.
            stats.note_wake(unsafe { read_pending_since() }, unsafe { now_ns() });
            if write_count.wrapping_sub(read_count) > RING_CAPACITY {
                stats.dropped_bytes += write_count - RING_CAPACITY - read_count;
                read_count = write_count - RING_CAPACITY;
                // Bytes were lost: whatever partial packet the assembler
                // holds no longer continues with the next byte read.
                // See `PacketAssembler::reset`.
                assembler.reset();
            }
            while read_count < write_count {
                // SAFETY: `read_ring_byte`'s own contract.
                let byte = unsafe { read_ring_byte(read_count) };
                read_count += 1;
                // Published per byte, not once per drain: a byte that
                // arrives while this loop is blocked in a `Call` (a button
                // edge goes out mid-drain) must see an up-to-date count, or
                // the kernel would not restamp `RING_PENDING_SINCE_OFF` for
                // it and its measured wait would wrongly include time from
                // before it existed.
                // SAFETY: `publish_read_count`'s own contract.
                unsafe { publish_read_count(read_count) };
                stats.bytes += 1;
                if let Some(packet) = assembler.push(byte) {
                    stats.packets += 1;
                    coalescer.push(packet, |event| {
                        // SAFETY: `send_event`'s own contract.
                        unsafe { send_event(event, &mut stats, &mut last_middle) }
                    });
                }
            }
        }
        if let Some(event) = coalescer.take() {
            // SAFETY: `send_event`'s own contract.
            unsafe { send_event(event, &mut stats, &mut last_middle) };
        }
    }
}
