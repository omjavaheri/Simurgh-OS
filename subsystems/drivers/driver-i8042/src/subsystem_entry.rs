//! ============================================================================
//! subsystem_entry.rs — driver-i8042 (x86_64-only)
//!
//! Purpose: the i8042 keyboard driver's real process entry point. Waits
//! (real, interrupt-driven — `DRV_IRQ_WAIT`, same primitive `driver-
//! virtio-blk`/`driver-virtio-net` already use for their own IRQ
//! completion waits) for `kernel_arch_glue::i8042_irq_trampoline`'s own
//! ring to have new bytes, decodes each into a `scancode::KeyEvent`, and
//! pushes it to the Compositor service over a dedicated `Endpoint`
//! (`kernel_arch_glue::wire_service_endpoint`'s own edge) — signal-then-
//! call, the same real, working pattern this project's account-manager
//! hub work already established (`Simurgh-OS`'s own session record).
//!
//! Position in the system: `kernel_arch_glue::spawn_i8042_driver` spawns
//! this process via `spawn_process_from_elf`. It is granted THREE
//! capabilities (deterministic slots, same "fixed compile-time constant"
//! convention every other driver's own `subsystem_entry.rs` uses):
//! `DRV_ENDPOINT_CAP` (slot 0, the service `Endpoint` to Compositor),
//! `DRV_NOTIF_CAP` (slot 1, IRQ-bound — the SAME `Notification` `IrqBind`
//! bound to IRQ1 in Stage A, now actually granted into this process),
//! `DRV_SIGNAL_NOTIF_CAP` (slot 2, shared with Compositor — signal-
//! before-call). Two VAs are pre-mapped: `DRV_QUEUE_VA` (the raw-
//! scancode ring `SharedRegion` — kernel-written, this process reads it
//! directly) and `DRV_MSG_VA` (the service `Endpoint`'s own shared
//! message page — this process writes it before each `Call`).
//!
//! Note on this file's ONE architecture-conditional-shaped piece:
//! `raw_syscall` issues the raw syscall INSTRUCTION itself (`int 0x80`)
//! — unlike every OTHER subsystem's own identically-named function, this
//! one is NOT `#[cfg(target_arch = ...)]`-gated across three
//! architectures, because this crate is x86_64-only by design (no i8042
//! on aarch64/riscv64 — this crate's own `Cargo.toml`/`build.rs` already
//! reflect that; see `driver_i8042`'s own crate doc comment).
//! ============================================================================

use crate::scancode;
use crate::wire::encode_key_event;
use kernel_ipc::SmallMessage;

/// Must stay numerically equal to `kernel/src/main.rs`'s `sys::IPC_CALL`.
const IPC_CALL: usize = 42;
/// Must stay numerically equal to `kernel/src/main.rs`'s
/// `sys::DRV_IRQ_WAIT` — real, interrupt-driven wait for new scancode
/// bytes (see this file's own module doc comment).
const DRV_IRQ_WAIT: usize = 63;
/// Must stay numerically equal to `kernel/src/main.rs`'s
/// `sys::NOTIF_SIGNAL`.
const NOTIF_SIGNAL: usize = 110;

/// This process's own capability slot for the service `Endpoint` to
/// Compositor — `kernel_arch_glue::spawn_i8042_driver`'s own FIRST grant
/// into this process's fresh cap space (`wire_service_endpoint`'s own
/// client-side grant).
const DRV_ENDPOINT_CAP: usize = 0;
/// This process's own capability slot for the IRQ-bound `Notification`
/// — the SECOND grant (Stage A's own `IrqBind`-bound object, now
/// actually handed to this process instead of staying only in root).
const DRV_NOTIF_CAP: usize = 1;
/// This process's own capability slot for the `Notification` shared
/// with Compositor (signal-before-call) — the THIRD grant
/// (`kernel_arch_glue::wire_notification`, fanned into {Compositor,
/// this process}).
const DRV_SIGNAL_NOTIF_CAP: usize = 2;
/// The bit this process sets on `DRV_SIGNAL_NOTIF_CAP` — the only
/// signal source on this particular `Notification` today, so any
/// nonzero bit works; `1` matches this project's own established
/// convention for a Notification's first (and so far only) client.
const SIGNAL_BIT: u64 = 1;

/// VA the raw-scancode ring `SharedRegion` is mapped at in THIS
/// process's own address space — must stay numerically equal to
/// `kernel_arch_glue::DRV_I8042_QUEUE_VA`. Layout: one `u64` "write
/// count" header (offset 0) followed by `RING_CAPACITY` raw scancode
/// bytes (offset 8) — `kernel_arch_glue::i8042_irq_trampoline`'s own
/// doc comment has the producer side; this file is the sole consumer.
const DRV_QUEUE_VA: usize = 0xD820_0000;
/// VA the service `Endpoint`'s own shared message page is mapped at —
/// must stay numerically equal to `kernel_arch_glue::DRV_I8042_MSG_VA`.
const DRV_MSG_VA: usize = 0xD830_0000;

/// Must match `kernel_arch_glue::I8042_RING_CAPACITY` exactly — this is
/// a plain numeric-agreement constant (same convention as every VA
/// above), not a shared type, since the ring lives in raw physical
/// memory two independently-built binaries each address by fixed offset.
const RING_CAPACITY: u64 = 32;

/// # Safety
/// `int 0x80` from Ring 3 traps to `hal_x86_64::cpu`'s dedicated DPL-3
/// gate, which preserves every register except `rax`/`rsi`. `#[inline(never)]`
/// — same real, QEMU-found LLVM-codegen bug every other subsystem's own
/// `raw_syscall` doc comment documents in full (stack-slot reuse across
/// repeated calls with literal args).
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
// `zero!()` macro documents in full — kept here for the identical
// defense-in-depth reason, at every `raw_syscall` call site.
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

/// Reads the ring's own "write count" header word — see `DRV_QUEUE_VA`'s
/// own doc comment for the layout.
///
/// # Safety
/// `DRV_QUEUE_VA` is mapped `U=1 R+W` in this process's own address
/// space by `kernel_arch_glue::spawn_i8042_driver`, before this process
/// is ever scheduled.
unsafe fn read_write_count() -> u64 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { (DRV_QUEUE_VA as *const u64).read_volatile() }
}

/// Reads one raw scancode byte from the ring at logical index `i`
/// (`i % RING_CAPACITY` is the real slot — the caller is responsible for
/// only calling this for an `i` the write-count header already covers).
///
/// # Safety
/// Same contract as [`read_write_count`].
unsafe fn read_ring_byte(i: u64) -> u8 {
    let offset = 8 + (i % RING_CAPACITY) as usize;
    // SAFETY: forwarded from this function's own contract; `offset` is
    // always within the ring's own fixed byte range.
    unsafe { ((DRV_QUEUE_VA + offset) as *const u8).read_volatile() }
}

/// Writes `msg` into the service `Endpoint`'s own shared message page —
/// same fixed layout (label word, then up to `MSG_MAX_WORDS` data words)
/// every other subsystem's own `write_shared_message` uses.
///
/// # Safety
/// `DRV_MSG_VA` is mapped `U=1 R+W` in this process's own address space
/// by `kernel_arch_glue::spawn_i8042_driver` (via `wire_service_
/// endpoint`'s own client-side mapping), before this process is ever
/// scheduled.
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

/// Real interrupt-driven wait for new scancode bytes — issues `DRV_IRQ_
/// WAIT` (`SyscallOp::Wait` on `DRV_NOTIF_CAP`, the same `Notification`
/// `IrqBind` bound to IRQ1 in Stage A). The kernel side genuinely idles
/// the core until the interrupt fires (or returns immediately if bits
/// are already pending — `kernel_core::syscall`'s own `do_wait` doc
/// comment) — no polling loop needed here.
///
/// `#[inline(never)]` — same rationale as `raw_syscall`'s own doc
/// comment.
#[inline(never)]
unsafe fn wait_for_irq() {
    // SAFETY: `raw_syscall`'s own contract.
    unsafe { raw_syscall(DRV_IRQ_WAIT, DRV_NOTIF_CAP, zero!()) };
}

/// Sends one decoded [`scancode::KeyEvent`] to Compositor: writes it
/// into the shared message page, signals the shared Notification (so
/// Compositor's own `Poll`-at-loop-top can learn a message is waiting
/// without blocking its main `Recv`), then issues a real, blocking
/// `Call` on the service `Endpoint` — this thread resumes once
/// Compositor's own `Reply` wakes it (`IPC_CALL`'s own doc comment,
/// shared across every subsystem in this codebase).
///
/// # Safety
/// `raw_syscall`'s own contract; `write_shared_message`'s own contract.
unsafe fn call_compositor(event: scancode::KeyEvent) {
    let msg = encode_key_event(event);
    // SAFETY: forwarded from this function's own contract.
    unsafe { write_shared_message(&msg) };
    // SAFETY: `raw_syscall`'s own contract.
    unsafe { raw_syscall(NOTIF_SIGNAL, DRV_SIGNAL_NOTIF_CAP, SIGNAL_BIT as usize) };
    // SAFETY: `raw_syscall`'s own contract. Blocks until Compositor's
    // own `Reply` wakes this thread — see this function's own doc
    // comment.
    unsafe { raw_syscall(IPC_CALL, DRV_ENDPOINT_CAP, zero!()) };
}

/// The i8042 driver's process entry point. Real, interrupt-driven,
/// forever: wait for new scancode bytes, drain every byte the ring's
/// own write-count header reports (bounded to `RING_CAPACITY`, oldest
/// dropped if this process fell behind — matches `kernel_arch_glue::
/// i8042_irq_trampoline`'s own producer-side drop-oldest policy exactly,
/// since both sides read the SAME monotonic counters), decode each, and
/// `call_compositor` for every byte that decodes to a real key event
/// (an 0xE0 extended-key prefix decodes to `None` and is skipped — see
/// `scancode`'s own doc comment).
#[no_mangle]
pub extern "C" fn subsystem_main() -> ! {
    let mut read_count: u64 = 0;
    loop {
        // SAFETY: `wait_for_irq`'s own contract.
        unsafe { wait_for_irq() };
        // SAFETY: `read_write_count`'s own contract.
        let write_count = unsafe { read_write_count() };
        if write_count.wrapping_sub(read_count) > RING_CAPACITY {
            read_count = write_count - RING_CAPACITY;
        }
        while read_count < write_count {
            // SAFETY: `read_ring_byte`'s own contract; `read_count` is
            // always within the range the write-count header covers.
            let byte = unsafe { read_ring_byte(read_count) };
            read_count += 1;
            if let Some(event) = scancode::decode(byte) {
                // SAFETY: `call_compositor`'s own contract.
                unsafe { call_compositor(event) };
            }
        }
    }
}
