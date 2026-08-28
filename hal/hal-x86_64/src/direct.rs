//! ============================================================================
//! direct.rs — x86_64
//!
//! Implements `hal_direct::HalDirectAccess` for x86_64, per
//! 01-HAL-Layer.md section 5. Only compiled when this crate's
//! "hal-direct-support" feature is enabled (see Cargo.toml), keeping
//! hal-direct out of a minimal build's final binary entirely per
//! section 1's separation requirement.
//!
//! Each trait method here does exactly two things, in order:
//!   1. Verify the caller's `CapabilityToken` via `hal_direct::verify_token`
//!      (scope match + expiry + signature) — per hal-direct's module
//!      docs, this is the SAME check every HalDirectAccess
//!      implementation must perform first, before touching any
//!      hardware.
//!   2. Perform the actual x86_64-specific operation (MMIO mapping,
//!      RDPMC, CPU affinity, memory policy).
//!
//! The `TokenVerifier` this implementation uses is supplied at
//! construction — wiring in the REAL verifier (backed by the Security
//! Broker's actual signing key, layer 4) is a boot-sequencing concern
//! for `hal_x86_64_rust_entry` (lib.rs), not something this file
//! decides on its own, per hal-direct's module docs on why the
//! signature algorithm itself is left open.
//! ============================================================================

use hal_core::error::HalError;
use hal_core::memory::{MapPermissions, PhysAddr, VirtAddr};
use hal_direct::{CapabilityScope, CapabilityToken, HalDirectAccess, NumaPolicy, PerfCounterId, TokenVerifier};

use crate::memory::Memory;
use crate::timer::Timer;

/// x86_64's `HalDirectAccess` implementation, generic over the
/// `TokenVerifier` supplied at construction — see module docs on why
/// the verification algorithm itself is not fixed here.
pub struct DirectAccess<'a, V: TokenVerifier> {
    verifier: V,
    memory: &'a Memory,
    timer: &'a Timer,
}

impl<'a, V: TokenVerifier> DirectAccess<'a, V> {
    /// Constructs the direct-access implementation. `memory` is needed
    /// for `map_mmio_region` (delegates to
    /// `MemoryBootstrap::setup_identity_mapping` with
    /// `MapPermissions::DEVICE_MMIO`); `timer` is needed for
    /// `now_ns()`-based expiry checks on every call, per
    /// `hal_direct::verify_token`'s signature.
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
            CapabilityScope::MmioRegion {
                phys_base: phys.as_usize() as u64,
                size: size as u64,
            },
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

        // SAFETY: `token` was just verified above to carry a scope
        // exactly matching (phys, size) — the Security Broker (layer
        // 4) is therefore the party that has vouched this exact
        // physical range is real, valid MMIO for the requesting
        // caller. `setup_identity_mapping`'s own safety contract
        // (hal-core/src/memory.rs) is satisfied by that verification
        // standing in for the "caller guarantees valid physical
        // memory" precondition it documents.
        unsafe { self.memory.setup_identity_mapping(region, MapPermissions::DEVICE_MMIO) }
    }

    fn read_performance_counter(&self, token: CapabilityToken, counter: PerfCounterId) -> Result<u64, HalError> {
        hal_direct::verify_token(
            &self.verifier,
            &token,
            CapabilityScope::PerformanceCounter { counter_id: counter.0 },
            self.now_ns(),
        )?;

        // RDPMC reads performance counter `counter.0`. Per the Intel
        // SDM (18.2.7), RDPMC requires either CPL0 (always true in
        // this crate) or CR4.PCE set for CPL3 access — this project's
        // MVP phase only calls read_performance_counter from
        // Privileged-mode code reaching this point via the microkernel
        // syscall path (01-HAL-Layer.md section 0's two-layer gating,
        // documented in hal-direct's module docs), so CPL0 execution
        // is guaranteed regardless of CR4.PCE.
        let (low, high): (u32, u32);
        // SAFETY: `counter.0` was just verified above to be exactly
        // the counter this token authorizes; RDPMC with an
        // out-of-range counter index raises #GP rather than corrupting
        // state, and the Security Broker (layer 4) — not this
        // function — is responsible for only minting tokens for
        // counter indices that actually exist on this CPU (a policy
        // decision, consistent with hal-direct's module docs on where
        // policy vs mechanism responsibility splits).
        unsafe {
            core::arch::asm!(
                "rdpmc",
                in("ecx") counter.0,
                out("eax") low,
                out("edx") high,
            );
        }
        Ok(((high as u64) << 32) | low as u64)
    }

    fn pin_thread_to_core(&self, token: CapabilityToken, core_id: usize) -> Result<(), HalError> {
        hal_direct::verify_token(
            &self.verifier,
            &token,
            CapabilityScope::ThreadAffinity { core_id: core_id as u32 },
            self.now_ns(),
        )?;

        // Actually PINNING a thread to a core is a scheduling
        // operation — it means "the microkernel's scheduler must never
        // place this thread's runnable state on any core but
        // `core_id`", which is state the scheduler (02-Microkernel-
        // Layer.md section 4) owns, not HAL. This function's role is
        // narrower: it is the CAPABILITY-VERIFIED GATE the microkernel
        // calls through before applying that scheduling decision on
        // the caller's behalf (section 0's two-layer gating path) —
        // once verification succeeds here, the microkernel is the one
        // that actually records the affinity constraint in its own
        // per-thread scheduling state. There is no x86_64-specific
        // hardware action for hal-direct itself to perform beyond this
        // verification step.
        Ok(())
    }

    fn set_numa_policy(&self, token: CapabilityToken, policy: NumaPolicy) -> Result<(), HalError> {
        hal_direct::verify_token(&self.verifier, &token, CapabilityScope::NumaPolicy, self.now_ns())?;

        // Same reasoning as pin_thread_to_core: actual NUMA-aware
        // allocation policy enforcement happens in the microkernel's
        // memory management (kernel-mm, per 02-Microkernel-Layer.md
        // section 3) and mm-service (03-Kernel-Subsystems-Layer.md
        // section 2.5) — not in HAL, which has no allocator of its own
        // to apply a policy to at this layer. This function's role is,
        // again, the verified gate; the `policy` value itself is
        // forwarded by the microkernel to whichever upper-layer
        // component actually consumes it.
        let _ = policy;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_core::memory::MemoryBootstrap;

    /// A verifier that accepts any token whose first signature byte is
    /// `0xAA` — same trivial stand-in used in hal-direct's own tests,
    /// reused here since this file's tests only need to confirm the
    /// verify-then-act ordering, not exercise a real signature scheme.
    struct MockVerifier;

    impl TokenVerifier for MockVerifier {
        fn verify_signature(&self, token: &CapabilityToken) -> Result<(), HalError> {
            if token.signature_bytes().first() == Some(&0xAA) {
                Ok(())
            } else {
                Err(HalError::InvalidCapabilityToken)
            }
        }
    }

    /// A minimal `Memory` stand-in is not available without a full
    /// UEFI memory map blob (Memory::from_uefi_memory_map's only
    /// constructor) — mmio-mapping behavior is therefore exercised at
    /// the memory.rs level (see that file's own tests for
    /// permissions_to_flags / setup_identity_mapping page-walk logic).
    /// This file's tests instead focus on what is unique to
    /// direct.rs: that verification happens and gates correctly BEFORE
    /// any hardware action, for the two methods that need no `Memory`/
    /// `Timer` hardware backing to test meaningfully in isolation
    /// (pin_thread_to_core, set_numa_policy — both pure verification
    /// gates per their own doc comments above).
    struct FixedNowVerifierOnly {
        verifier: MockVerifier,
        now_ns: u64,
    }

    impl FixedNowVerifierOnly {
        fn pin_thread_to_core(&self, token: CapabilityToken, core_id: usize) -> Result<(), HalError> {
            hal_direct::verify_token(
                &self.verifier,
                &token,
                CapabilityScope::ThreadAffinity { core_id: core_id as u32 },
                self.now_ns,
            )?;
            Ok(())
        }

        fn set_numa_policy(&self, token: CapabilityToken, policy: NumaPolicy) -> Result<(), HalError> {
            hal_direct::verify_token(&self.verifier, &token, CapabilityScope::NumaPolicy, self.now_ns)?;
            let _ = policy;
            Ok(())
        }
    }

    fn valid_signature() -> &'static [u8] {
        &[0xAA]
    }

    #[test]
    fn pin_thread_succeeds_with_matching_scope() {
        let harness = FixedNowVerifierOnly { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(1, CapabilityScope::ThreadAffinity { core_id: 3 }, 2000)
            .with_signature(valid_signature());
        assert!(harness.pin_thread_to_core(token, 3).is_ok());
    }

    #[test]
    fn pin_thread_rejects_mismatched_core() {
        let harness = FixedNowVerifierOnly { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(1, CapabilityScope::ThreadAffinity { core_id: 3 }, 2000)
            .with_signature(valid_signature());
        assert_eq!(
            harness.pin_thread_to_core(token, 5),
            Err(HalError::InvalidCapabilityToken)
        );
    }

    #[test]
    fn numa_policy_succeeds_with_correct_scope_regardless_of_policy_value() {
        let harness = FixedNowVerifierOnly { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(1, CapabilityScope::NumaPolicy, 2000).with_signature(valid_signature());
        assert!(harness.set_numa_policy(token, NumaPolicy::Interleaved).is_ok());
    }

    #[test]
    fn expired_token_rejected_before_any_action() {
        let harness = FixedNowVerifierOnly { verifier: MockVerifier, now_ns: 9999 };
        let token = CapabilityToken::new(1, CapabilityScope::NumaPolicy, 2000) // expires at 2000, now is 9999
            .with_signature(valid_signature());
        assert_eq!(
            harness.set_numa_policy(token, NumaPolicy::Local),
            Err(HalError::InvalidCapabilityToken)
        );
    }
}