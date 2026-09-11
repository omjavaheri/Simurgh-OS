//! ============================================================================
//! driver-i8042
//!
//! Purpose: the real i8042 PS/2 keyboard driver — Stage B of this
//! project's real-input-handling plan (Stage A, `hal_x86_64::pic` +
//! `kernel_arch_glue::i8042_irq_trampoline`, built the IRQ1 routing
//! foundation and verified it on real QEMU hardware; see that stage's
//! own doc comments for the full record). This crate decodes the raw
//! scancode bytes Stage A's trampoline queues into structured key
//! events and pushes them to the Compositor service — the driver-as-
//! isolated-process half of the pipeline, mirroring `driver-virtio-blk`/
//! `driver-virtio-net`'s own "subsystems as processes" packaging.
//!
//! Architecture reference: no `MD/REPO-Simurgh-OS/` charter exists for
//! this crate — same "Omid's own direction, no charter yet" standing
//! every other addition in this project's real-input-handling plan has.
//!
//! Position in the system: a layer-3 driver process, x86_64-only (no
//! i8042 on aarch64/riscv64). `kernel_arch_glue::spawn_i8042_driver`
//! spawns it and wires it as a genuine new IPC client of the Compositor
//! service — see `subsystem_entry`'s own doc comment for the full
//! capability/VA layout.
//! ============================================================================
#![no_std]

pub mod scancode;
pub mod subsystem_entry;
pub mod wire;
