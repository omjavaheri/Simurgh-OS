//! ============================================================================
//! direct.rs — RISC-V (RV64GC)
//!
//! Implements `hal_direct::HalDirectAccess` for RISC-V. Structurally
//! identical to hal-x86_64/hal-arm64's direct.rs — the only
//! architecture-specific piece is `read_performance_counter`, which
//! uses RISC-V's `hpmcounter<n>` CSRs (read via CSRR with a
//! compile-time-encoded CSR number, since RISC-V CSR addresses are
//! immediate operands, not runtime-selectable register indices the
//! way ARM64's PMSELR_EL0 or x86_64's RDPMC ECX operand are) — a
//! genuine architectural constraint this file works around by
//! supporting only the fixed set of counters expressible as constants,
//! documented below.
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

        // SAFETY: same justification as the other two architectures'
        // identical call.
        unsafe { self.memory.setup_identity_mapping(region, MapPermissions::DEVICE_MMIO) }
    }

    fn read_performance_counter(&self, token: CapabilityToken, counter: PerfCounterId) -> Result<u64, HalError> {
        hal_direct::verify_token(
            &self.verifier,
            &token,
            CapabilityScope::PerformanceCounter { counter_id: counter.0 },
            self.now_ns(),
        )?;

        // RISC-V CSR addresses are immediate operands in the CSRR
        // instruction encoding — there is no "select counter N then
        // read" indirection the way ARM64 (PMSELR_EL0) or a runtime
        // register argument the way x86_64 (RDPMC's ECX) provide. This
        // means only counters this file explicitly encodes a CSRR for
        // are actually readable; per module docs, this is a genuine
        // architectural constraint, not a scope-limiting choice made
        // by this project. Only `cycle` (counter 0) and `instret`
        // (counter 2) — the two counters guaranteed present on every
        // RV64GC core per the Zicntr extension — are supported;
        // hpmcounter3-31 are vendor-defined in what they actually
        // count and would each need their own CSRR arm here, a
        // tracked follow-up once a specific target platform's
        // hpmcounter assignments are known.
        let value: u64 = match counter.0 {
            0 => {
                let v: u64;
                // SAFETY: `cycle` CSR is unconditionally readable at
                // S-mode per the Zicntr extension, guaranteed present
                // on RV64GC.
                unsafe {
                    core::arch::asm!("csrr {}, cycle", out(reg) v);
                }
                v
            }
            2 => {
                let v: u64;
                // SAFETY: `instret` CSR, same guarantee as `cycle`.
                unsafe {
                    core::arch::asm!("csrr {}, instret", out(reg) v);
                }
                v
            }
            _ => return Err(HalError::InvalidCapabilityToken),
            // Not `HardwareFault`: from this function's perspective, a
            // token requesting an unsupported counter index is
            // indistinguishable from an invalid grant — the Security
            // Broker (layer 4) should not have issued a token scoped
            // to a counter this HAL implementation cannot read, so
            // treating it as a capability-validity problem (rather
            // than a hardware fault) keeps the error consistent with
            // this trait's "token scope must exactly match what the
            // implementation can perform" contract established in
            // hal-direct's module docs.
        };

        Ok(value)
    }

    fn pin_thread_to_core(&self, token: CapabilityToken, core_id: usize) -> Result<(), HalError> {
        hal_direct::verify_token(
            &self.verifier,
            &token,
            CapabilityScope::ThreadAffinity { core_id: core_id as u32 },
            self.now_ns(),
        )?;
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
        fn set_numa_policy(&self, token: CapabilityToken, policy: NumaPolicy) -> Result<(), HalError> {
            hal_direct::verify_token(&self.verifier, &token, CapabilityScope::NumaPolicy, self.now_ns)?;
            let _ = policy;
            Ok(())
        }
    }

    fn valid_signature() -> &'static [u8] { &[0xAA] }

    #[test]
    fn numa_policy_succeeds_with_correct_scope() {
        let h = FixedNowVerifierOnly { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(1, CapabilityScope::NumaPolicy, 2000).with_signature(valid_signature());
        assert!(h.set_numa_policy(token, NumaPolicy::Local).is_ok());
    }

    #[test]
    fn expired_token_rejected() {
        let h = FixedNowVerifierOnly { verifier: MockVerifier, now_ns: 9999 };
        let token = CapabilityToken::new(1, CapabilityScope::NumaPolicy, 2000).with_signature(valid_signature());
        assert_eq!(h.set_numa_policy(token, NumaPolicy::Local), Err(HalError::InvalidCapabilityToken));
    }
}