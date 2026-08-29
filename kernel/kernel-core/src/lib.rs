//! ============================================================================
//! kernel-core
//!
//! Purpose: the microkernel's syscall dispatcher and kernel object model.
//! It owns one `KernelState` — the fixed-capacity tables of every kernel
//! object (capability spaces, untyped memory, address spaces, endpoints,
//! notifications, thread control blocks) plus the scheduler — and exposes
//! exactly one entry point, `KernelState::dispatch`, an explicit `match`
//! over the small `SyscallOp` set (02-Microkernel-Layer.md §6).
//!
//! Architecture reference: 02-Microkernel-Layer.md §6 (`SyscallOp`, "sطح
//! syscall باید بسیار کوچک بماند"), §1.1 (dispatcher is an explicit state
//! machine; every arm has a bounded, traceable effect and no hidden global
//! mutation), §3 (`Retype`, object model), §8.1/§8.2 (boot: build the
//! first `UntypedMemory` objects and the Root Task from the HAL
//! `BootInfo`).
//!
//! Position in the system: linked into the one privileged kernel binary
//! with `hal/*` and the other `kernel/*` crates (REPO-Simurgh-OS.md §6).
//! `kernel-arch-glue` calls `KernelState::from_boot_info` at boot and then
//! drives `dispatch` on every trap from user space (layer 3+). Nothing in
//! this crate is `#[cfg(target_arch)]`.
//!
//! Safety/invariants:
//!   - every object id handed to user space is really an occupied slot in
//!     the matching table;
//!   - `dispatch` never allocates and never blocks the kernel — a syscall
//!     that must wait returns a "caller should block" outcome the caller
//!     (arch-glue trap handler) acts on;
//!   - the total object budget is bounded by `config`'s capacity
//!     constants, which are compile-time.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod config;
pub mod tcb;
pub mod state;
pub mod syscall;
pub mod run;
pub mod preempt;

pub use config::CONTEXT_BYTES;
pub use preempt::PreemptStep;
pub use run::ScheduleOutcome;
pub use state::{KernelInitError, KernelState};
pub use syscall::{SyscallError, SyscallOp, SyscallReturn};
pub use tcb::{ThreadState, Tcb};

/// The concrete `CpuContext` width this kernel is built with. All three
/// architecture crates fix their own `*_CONTEXT_BYTES` to 160
/// (`hal-x86_64::X86_64_CONTEXT_BYTES`, etc.); `kernel-core` uses that one
/// value so `KernelState` is not itself generic over `N` — the arch-erased
/// `HalInterface` boundary means the kernel never needs to vary it.
pub type CpuContext = hal_core::cpu::CpuContext<CONTEXT_BYTES>;
