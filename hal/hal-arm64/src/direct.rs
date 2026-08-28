//! ============================================================================
//! direct.rs — ARM64
//!
//! Implements `hal_direct::HalDirectAccess` for ARM64. Structurally
//! identical to hal-x86_64/src/direct.rs (hal-direct's API is fully
//! architecture-independent, per hal-direct/src/lib.rs's module docs)
//! — the only real difference is the underlying instruction used to
//! read a performance counter (PMEVCNTR<n>_EL0 via MRS, instead of
//! x86_64's RDPMC) and that pin_thread_to_core/set_numa_policy remain
//! pure verification gates for the same architecture-independent
//! reason documented in hal-x86_64/src/direct.rs.
//! ============================================================================

use hal_core::error::HalError;
use hal_core::memory::{MapPermissions, PhysAddr, VirtAddr};
use hal_direct::{CapabilityScope, CapabilityToken, HalDirectAccess, NumaPolicy, PerfCounterId, TokenVerifier};

use crate::memory::Memory;
use crate::timer::Timer;

pub struct DirectAccess<'a, V: TokenVerifier> {
    verifier: V,
    memory: &'a Memory,
    timer: &'a Timer,
}

impl<'a, V: TokenVerifier> DirectAccess<'a, V> {
    pub fn new(verifier: V, memory: &'a Memory, timer: &'a Timer) -> Self {
        Self { verifier, memory, timer }
    }

    fn now_ns(&self) -> u64 {
        use hal_core::timer::TimerAbstraction;
        self.timer.now_ns()
    }
}

impl<'a, V: TokenVerifier> HalDirectAccess for DirectAccess<'a, V> {
    fn map_mmio_region(&self, token: CapabilityToken, phys: PhysAddr, size: usize) -> Result<VirtAddr, HalError> {
        hal_direct::verify_token(
            &self.verifier,
            &token,
            CapabilityScope::MmioRegion { phys_base: phys.as_usize() as u64, size: size as u64 },
            self.now_ns(),
        )?;

        use hal_core::memory::MemoryBootstrap;
        // `::new` rather than struct-literal + `..ZERO`: `MemoryRegionRaw`'s
        // `_reserved` padding is private to hal-manifest, so functional
        // record update across that crate boundary is E0451 (same pattern
        // as hal-<arch>/memory.rs).
        let region = hal_manifest::raw::MemoryRegionRaw::new(
            phys.as_usize() as u64,
            size as u64,
            hal_manifest::raw::MemoryRegionKindRaw::Mmio,
            self.memory.iommu_present(),
        );

        // SAFETY: same justification as hal-x86_64/src/direct.rs's
        // identical call — verified token stands in for
        // setup_identity_mapping's "caller guarantees valid physical
        // memory" precondition.
        unsafe { self.memory.setup_identity_mapping(region, MapPermissions::DEVICE_MMIO) }
    }

    fn read_performance_counter(&self, token: CapabilityToken, counter: PerfCounterId) -> Result<u64, HalError> {
        hal_direct::verify_token(
            &self.verifier,
            &token,
            CapabilityScope::PerformanceCounter { counter_id: counter.0 },
            self.now_ns(),
        )?;

        // ARM64 performance counters are read via PMEVCNTR<n>_EL0,
        // where <n> is selected by first writing PMSELR_EL0 (unlike
        // x86_64's RDPMC, which takes the counter index directly as an
        // operand) — a two-step select-then-read sequence per the ARM
        // Architecture Reference Manual's PMU chapter.
        #[allow(unused_variables)]
        let value: u64;
        // SAFETY: `counter.0` was just verified above to be exactly
        // the counter this token authorizes; selecting and reading an
        // out-of-range PMU counter index is well-defined to either
        // read a reserved/zero value or trap via an access-control
        // mechanism the Security Broker (layer 4) is responsible for
        // not granting tokens beyond what this CPU actually
        // implements — mirrors hal-x86_64/direct.rs's identical
        // "policy vs mechanism" reasoning for RDPMC.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!("msr PMSELR_EL0, {}", in(reg) counter.0 as u64);
            core::arch::asm!("isb");
            core::arch::asm!("mrs {}, PMXEVCNTR_EL0", out(reg) value);
        }
        // Host (`cargo test`) build: PMU register access is bare-metal
        // only; the token-verification gate above is what unit tests
        // exercise.
        #[cfg(not(target_os = "none"))]
        {
            value = 0;
        }
        Ok(value)
    }

    fn pin_thread_to_core(&self, token: CapabilityToken, core_id: usize) -> Result<(), HalError> {
        hal_direct::verify_token(
            &self.verifier,
            &token,
            CapabilityScope::ThreadAffinity { core_id: core_id as u32 },
            self.now_ns(),
        )?;
        // Same reasoning as hal-x86_64/direct.rs: actual pinning is a
        // scheduler (layer 2) responsibility; this is the verified
        // gate only.
        Ok(())
    }

    fn set_numa_policy(&self, token: CapabilityToken, policy: NumaPolicy) -> Result<(), HalError> {
        hal_direct::verify_token(&self.verifier, &token, CapabilityScope::NumaPolicy, self.now_ns())?;
        let _ = policy;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVerifier;
    impl TokenVerifier for MockVerifier {
        fn verify_signature(&self, token: &CapabilityToken) -> Result<(), HalError> {
            if token.signature_bytes().first() == Some(&0xAA) { Ok(()) } else { Err(HalError::InvalidCapabilityToken) }
        }
    }

    struct FixedNowVerifierOnly { verifier: MockVerifier, now_ns: u64 }
    impl FixedNowVerifierOnly {
        fn pin_thread_to_core(&self, token: CapabilityToken, core_id: usize) -> Result<(), HalError> {
            hal_direct::verify_token(&self.verifier, &token, CapabilityScope::ThreadAffinity { core_id: core_id as u32 }, self.now_ns)?;
            Ok(())
        }
    }

    fn valid_signature() -> &'static [u8] { &[0xAA] }

    #[test]
    fn pin_thread_succeeds_with_matching_scope() {
        let h = FixedNowVerifierOnly { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(1, CapabilityScope::ThreadAffinity { core_id: 3 }, 2000).with_signature(valid_signature());
        assert!(h.pin_thread_to_core(token, 3).is_ok());
    }

    #[test]
    fn pin_thread_rejects_mismatched_core() {
        let h = FixedNowVerifierOnly { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(1, CapabilityScope::ThreadAffinity { core_id: 3 }, 2000).with_signature(valid_signature());
        assert_eq!(h.pin_thread_to_core(token, 5), Err(HalError::InvalidCapabilityToken));
    }
}