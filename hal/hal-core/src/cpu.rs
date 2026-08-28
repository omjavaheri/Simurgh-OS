//! ============================================================================
//! cpu.rs
//!
//! CPU Abstraction, per 01-HAL-Layer.md section 3.1 and the trait
//! pre-draft in section 4:
//!
//!   pub trait CpuAbstraction {
//!       fn core_count(&self) -> usize;
//!       fn current_core_id(&self) -> usize;
//!       fn feature_flags(&self) -> CpuFeatureFlags;
//!       unsafe fn context_switch(&self, from: &mut CpuContext, to: &CpuContext);
//!       fn set_privilege_level(&self, level: PrivilegeLevel);
//!   }
//!
//! Responsibilities per section 3.1:
//!   - per-core bootstrap
//!   - privilege level management (Ring 0/3 x86_64, EL0-EL3 ARM64,
//!     M/S/U-mode RISC-V)
//!   - Interrupt/Exception Vector Table setup, uniform across all three
//!     architectures
//!   - hardware-level context switch (register save/restore) — kept as
//!     the thinnest possible layer; REAL scheduling is the
//!     microkernel's job (layer 2), not HAL's
//!   - CPU feature flag detection/reporting as an architecture-
//!     independent standard bitfield
//! ============================================================================

use crate::error::HalError;
use bitflags::bitflags;

// ============================================================================
// Privilege level (section 3.1)
// ============================================================================

/// Architecture-independent privilege level, unifying:
///   - x86_64: Ring 0 (Kernel) / Ring 3 (User)
///   - ARM64:  EL1 (Kernel) / EL0 (User) / EL2 (Monitor, hypervisor)
///   - RISC-V: M-mode / S-mode (Kernel) / U-mode (User) / M-mode (Monitor)
///
/// Per section 0: HAL and the microkernel are both Privileged and link
/// into the same final kernel binary, so this type is what the
/// microkernel uses to ask HAL to drop privilege for a newly created
/// user-space process (layer 3+), without ever needing architecture-
/// specific knowledge of what "Ring 3" vs "EL0" vs "U-mode" means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    /// Highest privilege the kernel itself runs at (Ring 0 / EL1 /
    /// S-mode after the initial M-mode boot handoff on RISC-V).
    Kernel,
    /// Unprivileged level for layer 3-5 processes (Ring 3 / EL0 /
    /// U-mode).
    User,
    /// Hypervisor/monitor level. Only meaningful on ARM64 (EL2) and, in
    /// a boot-stage sense, RISC-V M-mode. Requesting this on x86_64
    /// (which has no equivalent ring for this purpose in our model)
    /// yields `HalError::UnsupportedPrivilegeLevel` from
    /// `set_privilege_level`.
    Monitor,
}

// ============================================================================
// CPU feature flags (section 3.1: "بیت‌فیلد استاندارد مستقل از معماری")
// ============================================================================

bitflags! {
    /// A single, architecture-independent bitfield reporting which CPU
    /// features are present, regardless of what the underlying hardware
    /// calls them (AVX512 on x86_64, SVE on ARM64, the Vector extension
    /// on RISC-V, etc. — per section 3.1's explicit examples).
    ///
    /// Each hal-<arch> crate maps its own architecture's native feature
    /// detection (CPUID on x86_64, ID_AA64*_EL1 registers on ARM64,
    /// misa/vendor-specific CSRs on RISC-V) onto this shared set. Bits
    /// that have no equivalent on a given architecture are simply never
    /// set by that architecture's implementation.
    ///
    /// This is intentionally a flat, coarse-grained set covering
    /// features relevant to upper layers' decisions (e.g. Profile
    /// Policy in layer 4 deciding scheduler defaults, or the AI runtime
    /// deciding whether to use vectorized kernels) — not an exhaustive
    /// mirror of every possible CPUID/ID register bit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CpuFeatureFlags: u64 {
        /// 128-bit SIMD (SSE2 baseline on x86_64, NEON baseline on
        /// ARM64, the "V" vector extension baseline on RISC-V).
        const SIMD_128          = 1 << 0;
        /// 256-bit SIMD (AVX/AVX2 on x86_64; no direct ARM64/RISC-V
        /// equivalent at this width, so those architectures never set
        /// this bit).
        const SIMD_256          = 1 << 1;
        /// 512-bit SIMD (AVX512 on x86_64; ARM64 SVE/SVE2 sets this bit
        /// when the implementation's vector length reaches 512 bits).
        const SIMD_512          = 1 << 2;
        /// Scalable vector extension present (ARM64 SVE/SVE2, RISC-V
        /// "V" vector extension) — distinct from the fixed-width SIMD
        /// bits above because scalable vector length is a different
        /// programming model upper layers may want to detect
        /// separately.
        const SCALABLE_VECTOR   = 1 << 3;
        /// Hardware AES acceleration instructions.
        const CRYPTO_AES        = 1 << 4;
        /// Hardware SHA acceleration instructions.
        const CRYPTO_SHA        = 1 << 5;
        /// Atomic compare-and-swap width beyond the base ISA guarantee
        /// (e.g. CMPXCHG16B on x86_64, LSE atomics on ARM64, the "A"
        /// extension already implies this on RISC-V and is reported via
        /// this bit for uniformity).
        const WIDE_ATOMICS      = 1 << 6;
        /// Hardware virtualization extensions present (VMX/SVM on
        /// x86_64, EL2 on ARM64, the "H" hypervisor extension on
        /// RISC-V). Relevant to layer 5's Linux Compat Runtime (VMM).
        const VIRTUALIZATION    = 1 << 7;
        /// Hardware supports an IOMMU/SMMU/IOPMP for this core's
        /// address space (mirrors `MemoryBootstrap::iommu_present`, but
        /// exposed here too since it is sometimes discovered as a CPU
        /// feature bit rather than a separate bus scan, depending on
        /// architecture).
        const IOMMU_CAPABLE     = 1 << 8;
        /// Hardware performance counters accessible (feeds
        /// `HalDirectAccess::read_performance_counter` in hal-direct,
        /// section 5).
        const PERF_COUNTERS     = 1 << 9;
    }
}

// ============================================================================
// CPU context (section 3.1: "Context switch سطح سخت‌افزاری")
// ============================================================================

/// Saved hardware register state for one execution context.
///
/// Deliberately opaque at the hal-core level: each architecture defines
/// its own concrete layout (general-purpose registers, stack/program
/// counter, and — per architecture — FPU/SIMD state) inside
/// `hal-<arch>::cpu::CpuContext` and is responsible for filling this
/// wrapper. hal-core only needs a `#[repr(C)]`, fixed-size, `Copy`
/// container it can pass by reference into `context_switch`, since (per
/// 01-HAL-Layer.md, section 9's boot-time philosophy) nothing at this
/// layer may allocate.
///
/// The generic `ARCH_CONTEXT_BYTES` const is a compile-time capacity,
/// not a runtime-chosen size: each hal-<arch> crate picks the value
/// matching its own register file (see the architecture crate's
/// `cpu.rs` for the concrete number) and re-exports a type alias, e.g.
/// `pub type CpuContext = hal_core::cpu::CpuContext<CONTEXT_BYTES_X86_64>;`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuContext<const ARCH_CONTEXT_BYTES: usize> {
    /// Raw architecture-specific register bytes. Never interpreted by
    /// hal-core itself — only by the architecture crate's own
    /// `context_switch` implementation, which knows the exact register
    /// layout it wrote here.
    bytes: [u8; ARCH_CONTEXT_BYTES],
}

impl<const ARCH_CONTEXT_BYTES: usize> CpuContext<ARCH_CONTEXT_BYTES> {
    /// A zeroed context, used as the initial state before the first
    /// `context_switch` into a newly created thread (constructed by the
    /// microkernel's scheduler, layer 2, via architecture-specific
    /// helpers that write the entry point / initial stack pointer into
    /// the appropriate byte offsets).
    pub const fn zeroed() -> Self {
        Self {
            bytes: [0; ARCH_CONTEXT_BYTES],
        }
    }

    /// Raw byte access for architecture code to read/write concrete
    /// register fields at known offsets. Not exposed as `pub` outside
    /// this crate's architecture implementations by convention — upper
    /// layers (layer 2+) must never poke at these bytes directly, only
    /// architecture crates that know the exact layout they defined.
    pub fn as_bytes_mut(&mut self) -> &mut [u8; ARCH_CONTEXT_BYTES] {
        &mut self.bytes
    }

    pub fn as_bytes(&self) -> &[u8; ARCH_CONTEXT_BYTES] {
        &self.bytes
    }
}

// ============================================================================
// CpuAbstraction trait (section 4 pre-draft, verbatim contract)
// ============================================================================

/// Per-architecture CPU abstraction. Implemented once per architecture
/// crate (`hal-x86_64::cpu::Cpu`, `hal-arm64::cpu::Cpu`,
/// `hal-riscv64::cpu::Cpu`). The microkernel (layer 2) depends only on
/// this trait — never on a concrete architecture type — per section 0's
/// requirement that layer 2+ code contain no `#[cfg(target_arch)]`.
///
/// `ARCH_CONTEXT_BYTES` is threaded through as the same const generic
/// used by `CpuContext` above, so a given architecture's
/// `CpuAbstraction` implementation and its `CpuContext` type always
/// agree on context size at compile time.
pub trait CpuAbstraction<const ARCH_CONTEXT_BYTES: usize> {
    /// Total number of logical CPU cores detected on this machine.
    fn core_count(&self) -> usize;

    /// The core id the calling code is currently executing on. Used by
    /// upper layers (e.g. the layer 2 scheduler, or NUMA-aware code) to
    /// make per-core decisions without needing architecture-specific
    /// register reads.
    fn current_core_id(&self) -> usize;

    /// Which CPU features were detected on this machine, as the
    /// architecture-independent bitfield defined above.
    fn feature_flags(&self) -> CpuFeatureFlags;

    /// Performs a raw hardware context switch: saves the currently
    /// running context into `from`, then restores `to` and resumes
    /// execution there.
    ///
    /// # Safety
    /// The caller (the layer 2 scheduler) must guarantee:
    ///   - `from` and `to` are both fully valid, non-aliasing
    ///     `CpuContext` values for this exact architecture.
    ///   - This is called with interrupts disabled on the current core
    ///     (an interrupt firing mid-switch, before `to`'s context is
    ///     fully live, would corrupt execution state).
    ///   - `to` was either previously saved by a prior call to this
    ///     same function, or was freshly initialized by
    ///     architecture-specific "new thread" setup code that wrote a
    ///     valid entry point and stack pointer into it.
    ///
    /// This function does NOT perform any scheduling decision (which
    /// thread runs next) — that policy lives entirely in the
    /// microkernel's scheduler (02-Microkernel-Layer.md, section 4).
    /// hal-core's `context_switch` is purely the hardware mechanism:
    /// "this function must be the thinnest possible layer" per section
    /// 3.1.
    unsafe fn context_switch(
        &self,
        from: &mut CpuContext<ARCH_CONTEXT_BYTES>,
        to: &CpuContext<ARCH_CONTEXT_BYTES>,
    );

    /// Requests a privilege level transition for the CURRENT core.
    ///
    /// Returns `Err(HalError::UnsupportedPrivilegeLevel)` if the
    /// requested level has no meaning on this architecture (e.g.
    /// `PrivilegeLevel::Monitor` requested on a CPU without
    /// virtualization extensions present, per
    /// `CpuFeatureFlags::VIRTUALIZATION`).
    fn set_privilege_level(&self, level: PrivilegeLevel) -> Result<(), HalError>;

    /// Performs the one-time, per-core bootstrap sequence (section
    /// 3.1: "راه‌اندازی اولیه‌ی هسته (per-core bootstrap)"): setting up
    /// this core's Interrupt/Exception Vector Table in the uniform
    /// layout shared across all three architectures, and any other
    /// per-core initialization that must happen exactly once before
    /// this core can safely take interrupts or run scheduled threads.
    ///
    /// Called once per core, during boot, by the architecture-specific
    /// entry point (`boot.S` → early Rust init) before handoff to the
    /// microkernel's Root Task (section 8, MVP acceptance criterion 3).
    fn bootstrap_current_core(&self) -> Result<(), HalError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Mock hardware implementation, per section 8.4: "تست واحد برای هر
    // trait روی معماری میزبان (mock hardware)". This runs on the host
    // target (default-members), not on any real no_std architecture.
    // ------------------------------------------------------------------

    const MOCK_CONTEXT_BYTES: usize = 32;

    struct MockCpu {
        core_count: usize,
    }

    impl CpuAbstraction<MOCK_CONTEXT_BYTES> for MockCpu {
        fn core_count(&self) -> usize {
            self.core_count
        }

        fn current_core_id(&self) -> usize {
            0
        }

        fn feature_flags(&self) -> CpuFeatureFlags {
            CpuFeatureFlags::SIMD_128 | CpuFeatureFlags::WIDE_ATOMICS
        }

        unsafe fn context_switch(
            &self,
            from: &mut CpuContext<MOCK_CONTEXT_BYTES>,
            to: &CpuContext<MOCK_CONTEXT_BYTES>,
        ) {
            // Mock behavior: just copy bytes, simulating "save old,
            // load new" without any real register manipulation.
            *from.as_bytes_mut() = *to.as_bytes();
        }

        fn set_privilege_level(&self, level: PrivilegeLevel) -> Result<(), HalError> {
            match level {
                PrivilegeLevel::Monitor => Err(HalError::UnsupportedPrivilegeLevel),
                _ => Ok(()),
            }
        }

        fn bootstrap_current_core(&self) -> Result<(), HalError> {
            Ok(())
        }
    }

    #[test]
    fn feature_flags_bitfield_combines_correctly() {
        let cpu = MockCpu { core_count: 4 };
        let flags = cpu.feature_flags();
        assert!(flags.contains(CpuFeatureFlags::SIMD_128));
        assert!(flags.contains(CpuFeatureFlags::WIDE_ATOMICS));
        assert!(!flags.contains(CpuFeatureFlags::SCALABLE_VECTOR));
    }

    #[test]
    fn monitor_privilege_unsupported_on_mock() {
        let cpu = MockCpu { core_count: 4 };
        assert_eq!(
            cpu.set_privilege_level(PrivilegeLevel::Monitor),
            Err(HalError::UnsupportedPrivilegeLevel)
        );
        assert!(cpu.set_privilege_level(PrivilegeLevel::User).is_ok());
    }

    #[test]
    fn context_switch_copies_state() {
        let cpu = MockCpu { core_count: 1 };
        let mut from = CpuContext::<MOCK_CONTEXT_BYTES>::zeroed();
        let mut to = CpuContext::<MOCK_CONTEXT_BYTES>::zeroed();
        to.as_bytes_mut()[0] = 0xAB;

        unsafe {
            cpu.context_switch(&mut from, &to);
        }

        assert_eq!(from.as_bytes()[0], 0xAB);
    }

    #[test]
    fn core_count_reflects_mock_topology() {
        let cpu = MockCpu { core_count: 16 };
        assert_eq!(cpu.core_count(), 16);
    }
}