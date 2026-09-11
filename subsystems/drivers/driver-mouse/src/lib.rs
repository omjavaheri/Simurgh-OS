//! ============================================================================
//! driver-mouse
//!
//! Purpose: the real PS/2 mouse driver — Stage 1b of the mouse-input
//! plan (Stage 1a, `hal_x86_64::pic`'s own mouse additions +
//! `kernel_arch_glue::mouse_irq_trampoline`, built the IRQ12 routing
//! foundation; see that stage's own doc comments, including the real
//! finding that a checkpoint with no consuming process can never
//! observe this pipeline fire — this crate IS that consuming process).
//! Decodes raw PS/2 mouse packet bytes into structured motion/button
//! events and pushes them to the Compositor service — mirrors `driver-
//! i8042`'s own "subsystems as processes" packaging exactly.
//!
//! Architecture reference: no `MD/REPO-Simurgh-OS/` charter exists for
//! this crate — same standing `driver-i8042` already has.
//!
//! Position in the system: a layer-3 driver process, x86_64-only.
//! `kernel_arch_glue::spawn_mouse_driver` spawns it and wires it as a
//! new IPC client of Compositor — see `subsystem_entry`'s own doc
//! comment for the full capability/VA layout.
//! ============================================================================
#![no_std]

pub mod mouse_packet;
pub mod subsystem_entry;
pub mod wire;
