//! ============================================================================
//! interface.rs
//!
//! An architecture-erased interface from HAL (layer 1) to whatever
//! sits above it — currently `kernel-stub` / `kernel`, later the real
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
//!
//! ## Growth history
//!
//!   - v1 (kernel-stub, 01-HAL-Layer.md §8): `core_count`,
//!     `current_core_id`, `cpu_feature_flags_bits`, `now_ns`,
//!     `frequency_hz` — enough to print a boot report.
//!   - v2 (microkernel, 02-Microkernel-Layer.md §8.2): `context_switch`
//!     added. The microkernel's scheduler must be able to switch between
//!     the register contexts of two threads (`§4`, `§8.2` — "یک ترد دوم
//!     می‌سازد و با آن IPC synchronous برقرار می‌کند"). This is the
//!     first genuine "one more capability" the layer above needs.
//!     Preemption primitives (`set_oneshot` timer arming, `register_irq`)
//!     are NOT added yet — cooperative `Yield` + IPC block/unblock is
//!     enough for the §8.2 milestone; they are the next growth when the
//!     preemptive scheduler lands.
//! ============================================================================

use crate::cpu::CpuAbstraction;
use crate::timer::TimerAbstraction;

/// The single saved-register-context width the architecture-erased
/// interface works in, in bytes. Every architecture crate implements
/// `CpuAbstraction<HAL_CONTEXT_BYTES>` (each also re-exports its own
/// `*_CONTEXT_BYTES` alias set to this same value — 160). Fixing it here
/// lets `HalInterface::context_switch` take a plain byte buffer instead
/// of being generic over a const the erased boundary must not vary.
pub const HAL_CONTEXT_BYTES: usize = 160;

unsafe fn trampoline_core_count<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(state: *const ()) -> usize {
    // SAFETY: `state` was produced by `build_interface` from a `&C`
    // and remains valid per that function's safety contract.
    let cpu = unsafe { &*(state as *const C) };
    cpu.core_count()
}

unsafe fn trampoline_current_core_id<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(
    state: *const (),
) -> usize {
    // SAFETY: same contract as `trampoline_core_count`.
    let cpu = unsafe { &*(state as *const C) };
    cpu.current_core_id()
}

unsafe fn trampoline_feature_flags_bits<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(
    state: *const (),
) -> u64 {
    // SAFETY: same contract as `trampoline_core_count`.
    let cpu = unsafe { &*(state as *const C) };
    cpu.feature_flags().bits()
}

unsafe fn trampoline_context_switch<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(
    state: *const (),
    from: *mut u8,
    to: *const u8,
) {
    // SAFETY: `state` is a valid `&C` (build_interface contract). `from`
    // and `to` each point at `HAL_CONTEXT_BYTES` valid, initialized
    // bytes owned by the caller (the microkernel's TCB storage), and
    // `CpuContext<HAL_CONTEXT_BYTES>` is `#[repr(C)]` wrapping exactly a
    // `[u8; HAL_CONTEXT_BYTES]` — so a byte buffer of that length IS a
    // valid `CpuContext`. Non-aliasing of `from`/`to` and
    // interrupts-disabled are the microkernel's responsibility, exactly
    // as `CpuAbstraction::context_switch`'s own safety contract states.
    let cpu = unsafe { &*(state as *const C) };
    let from_ctx = unsafe { &mut *(from as *mut crate::cpu::CpuContext<HAL_CONTEXT_BYTES>) };
    let to_ctx = unsafe { &*(to as *const crate::cpu::CpuContext<HAL_CONTEXT_BYTES>) };
    // SAFETY: forwards to the architecture implementation; every
    // precondition is inherited from this function's own contract above.
    unsafe { cpu.context_switch(from_ctx, to_ctx) }
}

unsafe fn trampoline_init_context<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(
    state: *const (),
    context: *mut u8,
    entry: usize,
    stack_top: usize,
) {
    // SAFETY: `state` is a valid `&C` (build_interface contract);
    // `context` points at `HAL_CONTEXT_BYTES` writable bytes owned by the
    // caller, and a byte buffer of that length IS a valid
    // `CpuContext<HAL_CONTEXT_BYTES>` (`#[repr(C)]` over `[u8; N]`).
    let cpu = unsafe { &*(state as *const C) };
    let ctx = unsafe { &mut *(context as *mut crate::cpu::CpuContext<HAL_CONTEXT_BYTES>) };
    cpu.init_context(ctx, entry, stack_top);
}

unsafe fn trampoline_enter_user<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(
    state: *const (),
    entry: usize,
    stack_top: usize,
) -> ! {
    // SAFETY: `state` is a valid `&C` (build_interface contract).
    let cpu = unsafe { &*(state as *const C) };
    cpu.enter_user(entry, stack_top)
}

unsafe fn trampoline_map_ram_identity<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(
    state: *const (),
    root_frame: usize,
    bytes_gib: usize,
    user_accessible: bool,
) {
    // SAFETY: `state` is a valid `&C` (build_interface contract).
    let cpu = unsafe { &*(state as *const C) };
    cpu.map_ram_identity(root_frame, bytes_gib, user_accessible)
}

unsafe fn trampoline_activate_address_space<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(
    state: *const (),
    root_frame: usize,
) {
    // SAFETY: `state` is a valid `&C` (build_interface contract).
    let cpu = unsafe { &*(state as *const C) };
    cpu.activate_address_space(root_frame)
}

#[allow(clippy::too_many_arguments)]
unsafe fn trampoline_map_range<C: CpuAbstraction<HAL_CONTEXT_BYTES>>(
    state: *const (),
    root_frame: usize,
    vaddr: usize,
    paddr: usize,
    len: usize,
    perm_bits: usize,
    pool_base: usize,
    pool_len: usize,
) -> u32 {
    // SAFETY: `state` is a valid `&C` (build_interface contract).
    let cpu = unsafe { &*(state as *const C) };
    cpu.map_range(root_frame, vaddr, paddr, len, perm_bits, pool_base, pool_len)
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
    cpu_context_switch: unsafe fn(*const (), *mut u8, *const u8),
    cpu_init_context: unsafe fn(*const (), *mut u8, usize, usize),
    cpu_map_ram_identity: unsafe fn(*const (), usize, usize, bool),
    cpu_activate_address_space: unsafe fn(*const (), usize),
    cpu_map_range: unsafe fn(*const (), usize, usize, usize, usize, usize, usize, usize) -> u32,
    cpu_enter_user: unsafe fn(*const (), usize, usize) -> !,
    timer_now_ns: unsafe fn(*const ()) -> u64,
    timer_frequency_hz: unsafe fn(*const ()) -> u64,
}

impl HalInterface {
    /// Number of logical CPU cores.
    pub fn core_count(&self) -> usize {
        // SAFETY: `cpu_state`/`cpu_core_count` were produced together
        // by `build_interface`.
        unsafe { (self.cpu_core_count)(self.cpu_state) }
    }

    /// The core id the calling code is running on.
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

    /// Performs a hardware context switch: saves the currently running
    /// register context into `from`, restores `to`, and resumes at
    /// `to`'s saved instruction pointer. Both buffers are exactly
    /// `HAL_CONTEXT_BYTES` long and hold a context previously written by
    /// this function or freshly initialised by architecture "new thread"
    /// setup.
    ///
    /// # Safety
    /// The microkernel scheduler must guarantee, exactly as
    /// `CpuAbstraction::context_switch` requires:
    ///   - interrupts are disabled on the current core;
    ///   - `from` and `to` do not alias;
    ///   - `to` holds a valid, resumable context for THIS architecture.
    pub unsafe fn context_switch(
        &self,
        from: &mut [u8; HAL_CONTEXT_BYTES],
        to: &[u8; HAL_CONTEXT_BYTES],
    ) {
        // SAFETY: `cpu_state`/`cpu_context_switch` were produced together
        // by `build_interface`; the buffer-length and non-aliasing /
        // interrupts-off obligations are forwarded to the caller by this
        // method's own `# Safety` section.
        unsafe { (self.cpu_context_switch)(self.cpu_state, from.as_mut_ptr(), to.as_ptr()) }
    }

    /// Initializes a fresh saved-context buffer so the first
    /// `context_switch` into it starts executing `entry` (a `-> !`
    /// function) with `stack_top` as the stack pointer, in the current
    /// address space / privilege level. See
    /// `CpuAbstraction::init_context`.
    pub fn init_context(
        &self,
        context: &mut [u8; HAL_CONTEXT_BYTES],
        entry: usize,
        stack_top: usize,
    ) {
        // SAFETY: `cpu_state`/`cpu_init_context` were produced together
        // by `build_interface`; `context` is `HAL_CONTEXT_BYTES` long.
        unsafe { (self.cpu_init_context)(self.cpu_state, context.as_mut_ptr(), entry, stack_top) }
    }

    /// Writes a flat identity map of the low `bytes_gib` GiB of physical
    /// memory into the page-table root frame at `root_frame`. See
    /// `CpuAbstraction::map_ram_identity`.
    pub fn map_ram_identity(&self, root_frame: usize, bytes_gib: usize, user_accessible: bool) {
        // SAFETY: produced together by `build_interface`.
        unsafe {
            (self.cpu_map_ram_identity)(self.cpu_state, root_frame, bytes_gib, user_accessible)
        }
    }

    /// Activates the address space rooted at `root_frame` on this core
    /// (loads `satp`/`CR3`/`TTBR0`). See
    /// `CpuAbstraction::activate_address_space`.
    pub fn activate_address_space(&self, root_frame: usize) {
        // SAFETY: produced together by `build_interface`; the caller
        // vouches for `root_frame` mapping current execution.
        unsafe { (self.cpu_activate_address_space)(self.cpu_state, root_frame) }
    }

    /// Maps `[vaddr, vaddr+len)` -> `[paddr, ...)` at base-page
    /// granularity in the table at `root_frame`, drawing missing table
    /// levels from the pre-zeroed frame pool. `perm_bits`: `R=1 | W=2 |
    /// X=4 | U=8`. Returns pool frames consumed, or `u32::MAX` on error.
    /// See `CpuAbstraction::map_range`.
    #[allow(clippy::too_many_arguments)]
    pub fn map_range(
        &self,
        root_frame: usize,
        vaddr: usize,
        paddr: usize,
        len: usize,
        perm_bits: usize,
        pool_base: usize,
        pool_len: usize,
    ) -> u32 {
        // SAFETY: produced together by `build_interface`; the caller
        // vouches for the frames and alignment.
        unsafe {
            (self.cpu_map_range)(
                self.cpu_state,
                root_frame,
                vaddr,
                paddr,
                len,
                perm_bits,
                pool_base,
                pool_len,
            )
        }
    }

    /// One-way drop of the current core to user privilege, starting at
    /// `entry` (a `-> !` function) on `stack_top`. Never returns. See
    /// `CpuAbstraction::enter_user`.
    pub fn enter_user(&self, entry: usize, stack_top: usize) -> ! {
        // SAFETY: `cpu_state`/`cpu_enter_user` were produced together by
        // `build_interface`; `entry`/`stack_top` are the caller's to
        // vouch for.
        unsafe { (self.cpu_enter_user)(self.cpu_state, entry, stack_top) }
    }

    /// Current monotonic time in nanoseconds.
    pub fn now_ns(&self) -> u64 {
        // SAFETY: `timer_state`/`timer_now_ns` were produced together
        // by `build_interface`.
        unsafe { (self.timer_now_ns)(self.timer_state) }
    }

    /// Hardware timer tick frequency in Hz.
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
/// The CPU implementation must use `HAL_CONTEXT_BYTES` as its context
/// width (every architecture crate already does — see each one's
/// `*_CONTEXT_BYTES` alias, all set to 160).
///
/// # Safety
/// The caller must ensure `cpu`/`timer` remain valid (not moved, not
/// dropped) for as long as the returned `HalInterface` might be used.
/// In this project's call sites, both are locals inside a `-> !`
/// entry function whose only continuation is passing this same
/// `HalInterface` into an equally diverging `kernel_main` — that stack
/// frame is never popped, so this holds for the remainder of
/// execution.
pub fn build_interface<C, T>(cpu: &C, timer: &T) -> HalInterface
where
    C: CpuAbstraction<HAL_CONTEXT_BYTES>,
    T: TimerAbstraction,
{
    HalInterface {
        cpu_state: cpu as *const C as *const (),
        timer_state: timer as *const T as *const (),
        cpu_core_count: trampoline_core_count::<C>,
        cpu_current_core_id: trampoline_current_core_id::<C>,
        cpu_feature_flags_bits: trampoline_feature_flags_bits::<C>,
        cpu_context_switch: trampoline_context_switch::<C>,
        cpu_init_context: trampoline_init_context::<C>,
        cpu_map_ram_identity: trampoline_map_ram_identity::<C>,
        cpu_activate_address_space: trampoline_activate_address_space::<C>,
        cpu_map_range: trampoline_map_range::<C>,
        cpu_enter_user: trampoline_enter_user::<C>,
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
    use core::cell::Cell;

    struct MockCpu {
        switches: Cell<u32>,
    }
    impl CpuAbstraction<HAL_CONTEXT_BYTES> for MockCpu {
        fn core_count(&self) -> usize {
            4
        }
        fn current_core_id(&self) -> usize {
            2
        }
        fn feature_flags(&self) -> CpuFeatureFlags {
            CpuFeatureFlags::SIMD_128
        }
        unsafe fn context_switch(
            &self,
            from: &mut CpuContext<HAL_CONTEXT_BYTES>,
            to: &CpuContext<HAL_CONTEXT_BYTES>,
        ) {
            // Mock: record the call and copy bytes, as the hal-core
            // mock implementations do.
            self.switches.set(self.switches.get() + 1);
            *from.as_bytes_mut() = *to.as_bytes();
        }
        fn set_privilege_level(&self, _level: PrivilegeLevel) -> Result<(), HalError> {
            Ok(())
        }
        fn bootstrap_current_core(&self) -> Result<(), HalError> {
            Ok(())
        }
    }

    struct MockTimer;
    impl TimerAbstraction for MockTimer {
        fn now_ns(&self) -> u64 {
            123_456
        }
        fn set_oneshot(&self, _deadline_ns: u64, _mode: TimerMode) -> Result<(), HalError> {
            Ok(())
        }
        fn cancel_oneshot(&self) {}
        fn set_tickless(&self, _enabled: bool) -> Result<(), HalError> {
            Ok(())
        }
        fn set_timer_callback(&self, _callback: TimerCallback) {}
        fn supports_tickless(&self) -> bool {
            true
        }
        fn frequency_hz(&self) -> u64 {
            1_000_000_000
        }
    }

    #[test]
    fn interface_forwards_cpu_calls() {
        let (cpu, timer) = (MockCpu { switches: Cell::new(0) }, MockTimer);
        let iface = build_interface(&cpu, &timer);
        assert_eq!(iface.core_count(), 4);
        assert_eq!(iface.current_core_id(), 2);
        assert_eq!(iface.cpu_feature_flags_bits(), CpuFeatureFlags::SIMD_128.bits());
    }

    #[test]
    fn interface_forwards_timer_calls() {
        let (cpu, timer) = (MockCpu { switches: Cell::new(0) }, MockTimer);
        let iface = build_interface(&cpu, &timer);
        assert_eq!(iface.now_ns(), 123_456);
        assert_eq!(iface.frequency_hz(), 1_000_000_000);
    }

    #[test]
    fn interface_forwards_context_switch() {
        let cpu = MockCpu { switches: Cell::new(0) };
        let timer = MockTimer;
        let iface = build_interface(&cpu, &timer);
        let mut from = [0u8; HAL_CONTEXT_BYTES];
        let mut to = [0u8; HAL_CONTEXT_BYTES];
        to[0] = 0xAB;
        // SAFETY: single-threaded test, buffers do not alias, `to` is a
        // valid (zeroed) mock context.
        unsafe { iface.context_switch(&mut from, &to) };
        assert_eq!(from[0], 0xAB);
        assert_eq!(cpu.switches.get(), 1);
    }
}
