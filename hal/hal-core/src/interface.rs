//! ============================================================================
//! interface.rs
//!
//! An architecture-erased interface from HAL (layer 1) to whatever
//! sits above it — currently `kernel-stub`, later the real
//! microkernel. This is the point where per-architecture types
//! (`X86_64Hal`, `Arm64Hal`, `Riscv64Hal`) stop existing for upper
//! layers, per 01-HAL-Layer.md section 4: "هیچ #[cfg(target_arch)] در
//! لایه ۲ به بالا نباید دیده شود".
//!
//! `kernel_main`'s signature is fixed via `extern "Rust" { fn
//! kernel_main(...); }` and a plain declaration cannot be generic — so
//! it cannot take a concrete Hal type without leaking arch-specific
//! naming into upper layers. `HalInterface` is a small hand-rolled
//! vtable (opaque state pointers + `unsafe fn` pointers) built ONCE,
//! generically, inside each hal-<arch> crate (where the concrete type
//! is still known) via `build_interface`. Its own type never varies.
//!
//! Grow this only when kernel_main (or its future microkernel
//! replacement) genuinely needs one more capability — never
//! speculatively.
//! ============================================================================

use crate::cpu::CpuAbstraction;
use crate::timer::TimerAbstraction;

unsafe fn trampoline_core_count<const N: usize, C: CpuAbstraction<N>>(state: *const ()) -> usize {
    // SAFETY: `state` was produced by `build_interface` from a `&C`
    // and remains valid per that function's safety contract.
    let cpu = unsafe { &*(state as *const C) };
    cpu.core_count()
}

unsafe fn trampoline_current_core_id<const N: usize, C: CpuAbstraction<N>>(state: *const ()) -> usize {
    // SAFETY: same contract as `trampoline_core_count`.
    let cpu = unsafe { &*(state as *const C) };
    cpu.current_core_id()
}

unsafe fn trampoline_feature_flags_bits<const N: usize, C: CpuAbstraction<N>>(state: *const ()) -> u64 {
    // SAFETY: same contract as `trampoline_core_count`.
    let cpu = unsafe { &*(state as *const C) };
    cpu.feature_flags().bits()
}

unsafe fn trampoline_now_ns<T: TimerAbstraction>(state: *const ()) -> u64 {
    // SAFETY: same contract, timer side.
    let timer = unsafe { &*(state as *const T) };
    timer.now_ns()
}

unsafe fn trampoline_frequency_hz<T: TimerAbstraction>(state: *const ()) -> u64 {
    // SAFETY: same contract as `trampoline_now_ns`.
    let timer = unsafe { &*(state as *const T) };
    timer.frequency_hz()
}

/// Architecture-erased handle to a subset of hal-core's capabilities.
/// `#[repr(C)]` for a stable layout across the `extern "Rust"`
/// declaration/definition boundary, matching this project's other
/// cross-crate boundary types (e.g. `HardwareManifestRaw`).
#[repr(C)]
pub struct HalInterface {
    cpu_state: *const (),
    timer_state: *const (),
    cpu_core_count: unsafe fn(*const ()) -> usize,
    cpu_current_core_id: unsafe fn(*const ()) -> usize,
    cpu_feature_flags_bits: unsafe fn(*const ()) -> u64,
    timer_now_ns: unsafe fn(*const ()) -> u64,
    timer_frequency_hz: unsafe fn(*const ()) -> u64,
}

impl HalInterface {
    pub fn core_count(&self) -> usize {
        // SAFETY: `cpu_state`/`cpu_core_count` were produced together
        // by `build_interface`.
        unsafe { (self.cpu_core_count)(self.cpu_state) }
    }

    pub fn current_core_id(&self) -> usize {
        // SAFETY: same contract as `core_count`.
        unsafe { (self.cpu_current_core_id)(self.cpu_state) }
    }

    /// Raw `CpuFeatureFlags` bits (kept as `u64` so this struct stays
    /// small and does not need to import bitflags-generated types).
    pub fn cpu_feature_flags_bits(&self) -> u64 {
        // SAFETY: same contract as `core_count`.
        unsafe { (self.cpu_feature_flags_bits)(self.cpu_state) }
    }

    pub fn now_ns(&self) -> u64 {
        // SAFETY: `timer_state`/`timer_now_ns` were produced together
        // by `build_interface`.
        unsafe { (self.timer_now_ns)(self.timer_state) }
    }

    pub fn frequency_hz(&self) -> u64 {
        // SAFETY: same contract as `now_ns`.
        unsafe { (self.timer_frequency_hz)(self.timer_state) }
    }
}

/// Builds a `HalInterface` from a concrete CPU/timer implementation.
/// Called once per architecture inside each `hal_<arch>_rust_entry`,
/// where the concrete types are still known — the only generic call
/// site in the whole codebase; its output type never varies.
///
/// # Safety
/// The caller must ensure `cpu`/`timer` remain valid (not moved, not
/// dropped) for as long as the returned `HalInterface` might be used.
/// In this project's call sites, both are locals inside a `-> !`
/// entry function whose only continuation is passing this same
/// `HalInterface` into an equally diverging `kernel_main` — that stack
/// frame is never popped, so this holds for the remainder of
/// execution.
pub fn build_interface<const N: usize, C, T>(cpu: &C, timer: &T) -> HalInterface
where
    C: CpuAbstraction<N>,
    T: TimerAbstraction,
{
    HalInterface {
        cpu_state: cpu as *const C as *const (),
        timer_state: timer as *const T as *const (),
        cpu_core_count: trampoline_core_count::<N, C>,
        cpu_current_core_id: trampoline_current_core_id::<N, C>,
        cpu_feature_flags_bits: trampoline_feature_flags_bits::<N, C>,
        timer_now_ns: trampoline_now_ns::<T>,
        timer_frequency_hz: trampoline_frequency_hz::<T>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::{CpuContext, CpuFeatureFlags, PrivilegeLevel};
    use crate::error::HalError;
    use crate::timer::{TimerCallback, TimerMode};

    const TEST_CTX_BYTES: usize = 16;

    struct MockCpu;
    impl CpuAbstraction<TEST_CTX_BYTES> for MockCpu {
        fn core_count(&self) -> usize { 4 }
        fn current_core_id(&self) -> usize { 2 }
        fn feature_flags(&self) -> CpuFeatureFlags { CpuFeatureFlags::SIMD_128 }
        unsafe fn context_switch(&self, _from: &mut CpuContext<TEST_CTX_BYTES>, _to: &CpuContext<TEST_CTX_BYTES>) {}
        fn set_privilege_level(&self, _level: PrivilegeLevel) -> Result<(), HalError> { Ok(()) }
        fn bootstrap_current_core(&self) -> Result<(), HalError> { Ok(()) }
    }

    struct MockTimer;
    impl TimerAbstraction for MockTimer {
        fn now_ns(&self) -> u64 { 123_456 }
        fn set_oneshot(&self, _deadline_ns: u64, _mode: TimerMode) -> Result<(), HalError> { Ok(()) }
        fn cancel_oneshot(&self) {}
        fn set_tickless(&self, _enabled: bool) -> Result<(), HalError> { Ok(()) }
        fn set_timer_callback(&self, _callback: TimerCallback) {}
        fn supports_tickless(&self) -> bool { true }
        fn frequency_hz(&self) -> u64 { 1_000_000_000 }
    }

    #[test]
    fn interface_forwards_cpu_calls() {
        let (cpu, timer) = (MockCpu, MockTimer);
        let iface = build_interface(&cpu, &timer);
        assert_eq!(iface.core_count(), 4);
        assert_eq!(iface.current_core_id(), 2);
        assert_eq!(iface.cpu_feature_flags_bits(), CpuFeatureFlags::SIMD_128.bits());
    }

    #[test]
    fn interface_forwards_timer_calls() {
        let (cpu, timer) = (MockCpu, MockTimer);
        let iface = build_interface(&cpu, &timer);
        assert_eq!(iface.now_ns(), 123_456);
        assert_eq!(iface.frequency_hz(), 1_000_000_000);
    }
}