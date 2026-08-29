//! ============================================================================
//! kernel-sched
//!
//! Purpose: the Simurgh microkernel's scheduler. Two modes, selected
//! per-thread (02-Microkernel-Layer.md §4.4): `Interactive` (priority +
//! aging, short quantum — general/gaming) and `Throughput` (the custom
//! NUMA/IPC-chain-aware algorithm of §4.1/§4.3 — AI batch / professional).
//! The distinguishing idea is that the throughput scheduling unit is the
//! **IPC chain group** (app → VFS → driver share one `vruntime` account),
//! which neither CFS nor EEVDF models natively (§4.1).
//!
//! Architecture reference: 02-Microkernel-Layer.md §4 (Scheduler), §4.1
//! (custom-algorithm rationale), §4.3 (the `effective_weight` /
//! `vruntime_next` formula and its starting constants), §4.4 (per-thread
//! mode, NUMA awareness, mandatory priority inheritance), §1.1
//! (verification-readiness — hence integer-only, side-effect-scoped code).
//!
//! Position in the system: linked into the one privileged kernel binary
//! with `hal/*` (REPO-Simurgh-OS.md §6). `kernel-core` owns a `Scheduler`
//! inside `KernelState`, feeds it timer ticks and IPC block/unblock
//! events, and asks `pick_next` which thread to `context_switch` to. The
//! numeric constants are the doc's stated starting points and are meant to
//! be benchmark-tuned in the MVP performance phase, not treated as final
//! (§4.3, §9).
//!
//! Safety/invariants:
//!   - `vruntime` values are monotonically non-decreasing per thread /
//!     per chain group;
//!   - all arithmetic is integer fixed-point (`weight` module) — no `f32`/
//!     `f64` anywhere;
//!   - the entity table and chain-group table are fixed-capacity; adding
//!     past capacity is an explicit error.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod mode;
pub mod weight;
pub mod chain_group;
pub mod sched;

pub use chain_group::{ChainGroup, ChainGroupError};
pub use mode::SchedulerMode;
pub use sched::{RunState, SchedEntity, Scheduler, SchedError};
pub use weight::{
    base_priority_weight_fp, effective_weight_fp, vruntime_next, AGING_CAP_MS, AGING_FACTOR_FP,
    MAX_PRIORITY, NUMA_LOCALITY_BONUS_FP, WEIGHT_ONE,
};
