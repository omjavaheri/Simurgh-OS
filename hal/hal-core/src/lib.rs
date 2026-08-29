//! ============================================================================
//! hal-core
//!
//! Architecture-independent HAL trait contracts, per 01-HAL-Layer.md,
//! section 1:
//!
//!   HAL
//!    ├── hal-core      -> always active, safe, auto-detect, no config needed
//!    └── hal-direct    -> optional, capability-gated
//!
//! This crate is the "always active" half of layer 1. It defines ONLY
//! trait/type contracts — no architecture-specific code lives here.
//! Each architecture crate (`hal-x86_64`, `hal-arm64`, `hal-riscv64`)
//! depends on hal-core and implements every trait declared below.
//!
//! Per section 4's closing rule:
//!   "کد بالادست (میکروکرنل) فقط با traitها کار می‌کند و هیچ
//!    #[cfg(target_arch)] در لایه ۲ به بالا نباید دیده شود"
//! — this crate's entire purpose is to make that possible: it is the
//! single point where "what a CPU/memory/timer/interrupt/compute/power
//! abstraction must be able to do" is defined, independent of which of
//! the three target architectures actually implements it.
//!
//! ## `#![no_std]` and the absence of `alloc`
//!
//! Per hal-manifest's section-9-derived design (see hal-manifest/src/
//! lib.rs and raw.rs), hal-core never enables hal-manifest's `alloc`
//! feature. This crate runs during the earliest part of boot — before
//! the Root Task exists and before any heap allocator has been set up
//! — so every trait here is deliberately shaped to avoid `Vec`,
//! `Box`, `String`, or any other heap-backed type. Where dynamic-
//! feeling behavior is needed (e.g. iterating discovered devices), the
//! traits return borrowed slices/fixed-size arrays owned by the
//! architecture implementation itself, never allocate.
//!
//! ## Relationship to the microkernel (layer 2)
//!
//! Per 01-HAL-Layer.md section 0, hal-core and the microkernel are
//! compiled into the SAME final Privileged binary and communicate via
//! direct Rust function/trait calls — never IPC, never a syscall.
//! `kernel-arch-glue` (02-Microkernel-Layer.md, section 7) is the crate
//! on the microkernel side that is generic over these traits, exactly
//! mirroring how this crate is generic over which `hal-<arch>` crate
//! provides the concrete implementation.
//!
//! ## What is NOT in this crate
//!
//!   - `hal-direct` (section 5): capability-gated direct hardware
//!     access for professional users/driver authors. Deliberately kept
//!     in its own crate so it can be excluded from a minimal/locked-
//!     down build entirely — see 01-HAL-Layer.md section 1: "باید از
//!     هم جدا (در کد و در باینری نهایی) باشند".
//!   - Any concrete architecture implementation (CPUID parsing, GIC
//!     register layout, SBI calls, etc.) — those live in hal-x86_64,
//!     hal-arm64, hal-riscv64 respectively.
//!   - `HardwareManifestRaw` and its raw field types themselves — those
//!     are defined once in `hal-manifest` and re-exported/used by the
//!     relevant hal-core modules (memory.rs, compute.rs, power.rs), so
//!     there is exactly one authoritative definition of "what a memory
//!     region / compute device / power domain looks like" shared by
//!     the boot-time raw format and every hal-core trait that discovers
//!     or queries them.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
// hal-core itself contains very little `unsafe` (mostly in cpu.rs's
// context_switch contract and the const-generic CpuContext byte
// access) — but per 01-HAL-Layer.md section 7's project-wide rule
// ("ممنوعیت unsafe غیرمستند: هر بلوک unsafe باید کامنت توضیح‌دهنده‌ی
// «چرا ایمن است» داشته باشد") and 02-Microkernel-Layer.md section 1.1's
// verification-readiness goals, we hold this crate to the stricter
// warning set below even though it is layer 1, not layer 2 — since it
// links into the same Privileged binary.
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

// ----------------------------------------------------------------------------
// Module declarations
//
// One module per HAL responsibility area from 01-HAL-Layer.md section 3
// (3.1 CPU, 3.2 Memory, 3.3 Timer, 3.4 Interrupt Controller, 3.5 Boot,
// 3.6 Compute Discovery, 3.7 Power & Thermal), plus `error` for the
// shared HalError type every trait method returns.
// ----------------------------------------------------------------------------

/// Shared error type for every hal-core trait. See `error::HalError`.
pub mod error;

/// CPU Abstraction (section 3.1): per-core bootstrap, privilege levels,
/// context switch, feature flag detection.
pub mod cpu;

/// Memory Bootstrap (section 3.2): firmware memory map, minimal
/// identity/kernel mapping, IOMMU presence.
pub mod memory;

/// Timer & Clock (section 3.3): monotonic time, oneshot deadlines,
/// interactive vs tickless mode.
pub mod timer;

/// Interrupt Controller Abstraction (section 3.4): IRQ registration,
/// masking, inter-processor interrupts.
pub mod interrupt;

/// Heterogeneous Compute Discovery (section 3.6): GPU/NPU/TPU/FPGA as
/// first-class entities.
pub mod compute;

/// Power & Thermal Query Interface (section 3.7): per-domain DVFS and
/// temperature.
pub mod power;

/// Boot Abstraction (section 3.5): the standard `BootInfo` structure
/// handed from HAL to the microkernel.
pub mod boot;

pub mod interface;

// ----------------------------------------------------------------------------
// Convenience re-exports at the crate root
//
// Lets consumers (hal-x86_64, hal-arm64, hal-riscv64, and eventually
// kernel-arch-glue on the microkernel side) write
// `use hal_core::{CpuAbstraction, MemoryBootstrap, ...}` instead of
// reaching into each submodule individually, while still keeping the
// module boundaries above for documentation/organization clarity.
// ----------------------------------------------------------------------------

pub use error::HalError;

pub use cpu::{CpuAbstraction, CpuContext, CpuFeatureFlags, PrivilegeLevel};

pub use memory::{MapPermissions, MemoryBootstrap, MemoryRegion, MemoryRegionKind, PhysAddr, VirtAddr};

pub use timer::{TimerAbstraction, TimerCallback, TimerMode};

pub use interrupt::{InterruptController, IrqHandler, IrqId};

pub use compute::{ComputeDevice, ComputeDeviceDiscovery, ComputeKind, VendorId};

pub use power::{DomainsAboveThresholdIter, DvfsRequest, DvfsState, MilliCelsius, PowerDomain, PowerThermal};

pub use boot::{BootInfo, BootProtocol};

pub use interface::{build_interface, HalInterface, HAL_CONTEXT_BYTES};

// ----------------------------------------------------------------------------
// Aggregate trait
//
// Not required by section 4's pre-draft, but useful: the microkernel's
// `kernel-arch-glue` (02-Microkernel-Layer.md, section 7) typically
// wants "the one HAL implementation for this architecture" as a single
// generic parameter, rather than threading seven separate trait bounds
// through every function signature. Each hal-<arch> crate provides one
// top-level type implementing all seven traits plus this marker trait,
// e.g. `hal_x86_64::X86_64Hal`.
//
// This trait carries no methods of its own — it exists purely to let
// upper-layer code write one bound (`H: PlatformHal<...>`) instead of
// seven, while every method call still goes through the specific trait
// that actually declares it.
// ----------------------------------------------------------------------------

/// Marker trait aggregating every hal-core capability trait into one
/// bound, for convenience on the microkernel side
/// (`kernel-arch-glue`, 02-Microkernel-Layer.md section 7).
///
/// `ARCH_CONTEXT_BYTES` mirrors the const generic thread through
/// `CpuAbstraction`/`CpuContext` (see cpu.rs) — each architecture's top-
/// level HAL type fixes this to its own register file size.
pub trait PlatformHal<const ARCH_CONTEXT_BYTES: usize>:
    CpuAbstraction<ARCH_CONTEXT_BYTES>
    + MemoryBootstrap
    + TimerAbstraction
    + InterruptController
    + ComputeDeviceDiscovery
    + PowerThermal
{
}

// Blanket impl: any type implementing all six capability traits
// automatically satisfies `PlatformHal` — architecture crates never
// need to write `impl PlatformHal for X86_64Hal {}` by hand.
impl<const N: usize, T> PlatformHal<N> for T where
    T: CpuAbstraction<N> + MemoryBootstrap + TimerAbstraction + InterruptController + ComputeDeviceDiscovery + PowerThermal
{
}

#[cfg(test)]
mod integration_tests {
    //! Crate-level integration test verifying the module re-exports
    //! above actually resolve and that a single mock type can satisfy
    //! `PlatformHal` end-to-end — a lightweight substitute for a full
    //! architecture implementation, useful as a smoke test that the
    //! trait surface is internally consistent before any real
    //! hal-x86_64/arm64/riscv64 code exists yet.
    use super::*;
    use core::cell::{Cell, RefCell};

    const TEST_CTX_BYTES: usize = 16;

    struct MockPlatform {
        core_count: usize,
        memory_regions: [MemoryRegion; 1],
        power_domains: [PowerDomain; 0],
        compute_devices: [ComputeDevice; 0],
        armed_deadline: Cell<Option<u64>>,
        irq_handlers: RefCell<[Option<IrqHandler>; 4]>,
    }

    impl CpuAbstraction<TEST_CTX_BYTES> for MockPlatform {
        fn core_count(&self) -> usize {
            self.core_count
        }
        fn current_core_id(&self) -> usize {
            0
        }
        fn feature_flags(&self) -> CpuFeatureFlags {
            CpuFeatureFlags::empty()
        }
        unsafe fn context_switch(&self, from: &mut CpuContext<TEST_CTX_BYTES>, to: &CpuContext<TEST_CTX_BYTES>) {
            *from.as_bytes_mut() = *to.as_bytes();
        }
        fn set_privilege_level(&self, _level: PrivilegeLevel) -> Result<(), HalError> {
            Ok(())
        }
        fn bootstrap_current_core(&self) -> Result<(), HalError> {
            Ok(())
        }
    }

    impl MemoryBootstrap for MockPlatform {
        fn physical_memory_map(&self) -> &[MemoryRegion] {
            &self.memory_regions
        }
        fn iommu_present(&self) -> bool {
            false
        }
        unsafe fn setup_identity_mapping(&self, region: MemoryRegion, _perms: MapPermissions) -> Result<VirtAddr, HalError> {
            Ok(VirtAddr::new(region.base_addr as usize))
        }
        fn base_page_size_bytes(&self) -> usize {
            4096
        }
    }

    impl TimerAbstraction for MockPlatform {
        fn now_ns(&self) -> u64 {
            0
        }
        fn set_oneshot(&self, deadline_ns: u64, _mode: TimerMode) -> Result<(), HalError> {
            self.armed_deadline.set(Some(deadline_ns));
            Ok(())
        }
        fn cancel_oneshot(&self) {
            self.armed_deadline.set(None);
        }
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

    impl InterruptController for MockPlatform {
        fn register_irq(&self, irq: IrqId, handler: IrqHandler) -> Result<(), HalError> {
            let idx = irq.as_u32() as usize;
            if idx >= 4 {
                return Err(HalError::InvalidIrqId);
            }
            self.irq_handlers.borrow_mut()[idx] = Some(handler);
            Ok(())
        }
        fn unregister_irq(&self, irq: IrqId) {
            let idx = irq.as_u32() as usize;
            if idx < 4 {
                self.irq_handlers.borrow_mut()[idx] = None;
            }
        }
        fn mask_irq(&self, _irq: IrqId) -> Result<(), HalError> {
            Ok(())
        }
        fn unmask_irq(&self, _irq: IrqId) -> Result<(), HalError> {
            Ok(())
        }
        fn send_ipi(&self, _target_core: usize, _vector: u8) -> Result<(), HalError> {
            Ok(())
        }
        fn irq_line_count(&self) -> u32 {
            4
        }
        fn ipi_target_core_count(&self) -> u32 {
            self.core_count as u32
        }
        fn end_of_interrupt(&self, _irq: IrqId) {}
    }

    impl ComputeDeviceDiscovery for MockPlatform {
        fn enumerate_compute_devices(&self) -> &[ComputeDevice] {
            &self.compute_devices
        }
        fn rescan(&self, _kind_filter: Option<ComputeKind>) -> Result<(), HalError> {
            Ok(())
        }
        fn device_by_index(&self, _device_index: u32) -> Option<&ComputeDevice> {
            None
        }
    }

    impl PowerThermal for MockPlatform {
        fn enumerate_power_domains(&self) -> &[PowerDomain] {
            &self.power_domains
        }
        fn read_dvfs_state(&self, _domain_id: u32) -> Result<DvfsState, HalError> {
            Err(HalError::InvalidPowerDomain)
        }
        fn request_dvfs(&self, _domain_id: u32, _request: DvfsRequest) -> Result<(), HalError> {
            Err(HalError::InvalidPowerDomain)
        }
        fn read_temperature(&self, _domain_id: u32) -> Result<MilliCelsius, HalError> {
            Err(HalError::InvalidPowerDomain)
        }
        fn domains_above_threshold(&self, threshold: MilliCelsius) -> DomainsAboveThresholdIter<'_, Self>
        where
            Self: Sized,
        {
            DomainsAboveThresholdIter::new(self, threshold)
        }
    }

    fn mock_platform() -> MockPlatform {
        MockPlatform {
            core_count: 4,
            memory_regions: [hal_manifest::raw::MemoryRegionRaw::ZERO],
            power_domains: [],
            compute_devices: [],
            armed_deadline: Cell::new(None),
            irq_handlers: RefCell::new([None; 4]),
        }
    }

    /// Compile-time-and-runtime check: a single mock type satisfying
    /// all six capability traits automatically satisfies `PlatformHal`
    /// via the blanket impl above — this is the exact shape
    /// `kernel-arch-glue` will rely on for each real architecture.
    fn assert_is_platform_hal<H: PlatformHal<TEST_CTX_BYTES>>(_h: &H) {}

    #[test]
    fn mock_platform_satisfies_platform_hal_bound() {
        let platform = mock_platform();
        assert_is_platform_hal(&platform);
        assert_eq!(platform.core_count(), 4);
        assert_eq!(platform.irq_line_count(), 4);
        assert!(platform.physical_memory_map().len() == 1);
    }
}