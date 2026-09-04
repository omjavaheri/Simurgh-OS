//! ============================================================================
//! hal-direct
//!
//! Capability-gated direct hardware access, per 01-HAL-Layer.md section 5.
//!
//! This is the "hal-direct" half described in section 1:
//!
//!   HAL
//!    ├── hal-core      -> always active, safe, auto-detect, no config needed
//!    └── hal-direct    -> optional, capability-gated, for professional
//!                          users and driver authors
//!
//! Per section 5's pre-draft trait:
//!
//!   pub trait HalDirectAccess {
//!       fn map_mmio_region(&self, token: CapabilityToken, phys: PhysAddr, size: usize)
//!           -> Result<VirtAddr, HalError>;
//!       fn read_performance_counter(&self, token: CapabilityToken, counter: PerfCounterId) -> u64;
//!       fn pin_thread_to_core(&self, token: CapabilityToken, core_id: usize);
//!       fn set_numa_policy(&self, token: CapabilityToken, policy: NumaPolicy);
//!   }
//!
//! and the governing rule:
//!   "هیچ تابعی در hal-direct بدون CapabilityToken معتبر اجرا نمی‌شود؛
//!    صدور این token مسئولیت Security/Permission Broker در لایه ۴ است،
//!    نه HAL. HAL فقط توکن را verify می‌کند (امضا/scope چک می‌شود؛
//!    الگوریتم تایید در پیوست امنیتی لایه ۲ مشخص می‌شود)."
//!
//! ## Two layers of gating (per section 0's access path)
//!
//! Per 01-HAL-Layer.md section 0, `hal-direct` can be reached from two
//! places:
//!   1. Directly, by code linked into the same Privileged binary as the
//!      microkernel (layer 2 itself, e.g. its own performance-tuning
//!      diagnostics).
//!   2. From layer 5 (a professional application), via the path:
//!      app -> syscall to microkernel -> microkernel validates its OWN
//!      Capability (the kernel-cap type, 02-Microkernel-Layer.md
//!      section 2) -> microkernel calls the hal-direct function on the
//!      app's behalf.
//!
//! This means `CapabilityToken` here is DELIBERATELY NOT the same type
//! as the microkernel's `Capability` (kernel-cap, layer 2) — that type
//! belongs to layer 2 and hal-core/hal-direct must not depend on it
//! (dependency direction is strictly bottom-up, section 0). Instead,
//! `CapabilityToken` is a HAL-local, signed credential that the
//! Security Broker (layer 4) mints specifically for hal-direct
//! operations, passed down through the microkernel alongside its own
//! Capability check. This gives defense-in-depth: even a caller that
//! somehow reached this trait without a valid layer-2 Capability still
//! cannot perform an operation without a HAL-verifiable token scoped to
//! exactly that operation.
//!
//! The actual signature/verification ALGORITHM is explicitly left
//! open by section 5 ("الگوریتم تایید در پیوست امنیتی لایه ۲ مشخص
//! می‌شود") — this crate defines the token's SHAPE and the scope-
//! matching logic that is architecture-independent, while the
//! signature check itself is delegated to a `TokenVerifier`
//! implementation supplied by whoever wires up the Security Broker's
//! actual crypto (layer 4), so hal-direct never hardcodes an algorithm
//! that might need to change without a breaking API change here.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

use hal_core::{HalError, PhysAddr, VirtAddr};

/// Concrete Ed25519 `TokenVerifier` (Issue #29's resolved algorithm
/// decision). Feature-gated so a build that never needs a real
/// (non-mock) verifier never pulls in the crypto dependency — see
/// this crate's `Cargo.toml` and `ed25519.rs`'s own module docs.
#[cfg(feature = "ed25519")]
pub mod ed25519;

// ============================================================================
// CapabilityToken (section 5)
// ============================================================================

/// Maximum length of the opaque signature blob embedded in a token.
/// 64 bytes comfortably covers common signature schemes (e.g. Ed25519
/// at 64 bytes, or an HMAC-SHA512 tag) without committing this crate to
/// one specific algorithm — see the module-level doc comment on why the
/// algorithm itself is left to the Security Broker's `TokenVerifier`.
pub const MAX_SIGNATURE_BYTES: usize = 64;

/// What kind of hal-direct operation a `CapabilityToken` authorizes.
///
/// Kept as a flat enum with an associated resource identifier per
/// variant (rather than one generic "scope string") so that scope
/// matching in `CapabilityToken::covers` is a simple, fast, allocation-
/// free comparison — appropriate for this being a hot-path check on
/// every hal-direct call.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityScope {
    /// Authorizes `map_mmio_region` for a specific physical base
    /// address and size. Both are part of the scope (not just "any
    /// MMIO"), so a token minted for one device's registers cannot be
    /// reused to map a different device's MMIO range.
    MmioRegion { phys_base: u64, size: u64 },
    /// Authorizes `read_performance_counter` for one specific counter
    /// id.
    PerformanceCounter { counter_id: u32 },
    /// Authorizes `pin_thread_to_core` for one specific core id. (A
    /// token scoped to core 2 cannot be used to pin to core 5.)
    ThreadAffinity { core_id: u32 },
    /// Authorizes `set_numa_policy` generally (NUMA policy is a
    /// per-thread scheduling hint, not tied to one specific hardware
    /// resource the way the other three scopes are).
    NumaPolicy,
}

/// A capability-gated credential for one `hal-direct` operation,
/// minted by the Security/Permission Broker (04-System-Services-
/// Policy-Layer.md, section 5) and passed down to HAL for verification
/// per 01-HAL-Layer.md section 5.
///
/// `#[repr(C)]` and `Copy`, consistent with the rest of the boot-
/// adjacent HAL crates: tokens are small, fixed-size values that may be
/// checked on a hot path (e.g. a driver reading a performance counter
/// frequently) and must never require heap allocation to construct,
/// copy, or verify.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CapabilityToken {
    /// Identifies which process/thread this token was issued to. HAL
    /// itself does not enforce that the CALLER matches this field
    /// (HAL has no notion of "process" — that's a layer 2/3 concept);
    /// the microkernel is responsible for ensuring it only ever
    /// presents a token to hal-direct on behalf of the subject it was
    /// actually issued to.
    pub subject_id: u64,

    /// What this token authorizes.
    pub scope: CapabilityScope,

    /// Monotonic HAL time (per `TimerAbstraction::now_ns`) after which
    /// this token is no longer valid. Section 5 does not mandate
    /// expiry, but per this project's Capability model
    /// (02-Microkernel-Layer.md section 2: "Revocation باید ممکن
    /// باشد"), every credential in this system should be revocable or
    /// time-bounded — a permanently-valid hal-direct token would be a
    /// standing exception to that principle. `None` is intentionally
    /// disallowed (see `CapabilityToken::new`) to keep that guarantee
    /// non-optional at the type level for tokens constructed through
    /// the normal path.
    pub expires_at_ns: u64,

    /// Opaque signature bytes proving this token was actually issued
    /// by the Security Broker and has not been tampered with (e.g. a
    /// scope field flipped from `ThreadAffinity { core_id: 2 }` to
    /// `{ core_id: 0 }` by a malicious caller). Verified by a
    /// `TokenVerifier` implementation, not by this crate directly —
    /// see module-level docs.
    pub signature: [u8; MAX_SIGNATURE_BYTES],
    pub signature_len: u8,
    _reserved: [u8; 7],
}

impl CapabilityToken {
    /// Constructs a token. In practice this is called only by code that
    /// has access to the Security Broker's signing key (layer 4) — this
    /// constructor itself performs NO signing; it just assembles the
    /// plaintext fields. Signing happens separately (outside this
    /// crate's concern) before the signature bytes are placed into the
    /// resulting value via `with_signature`.
    pub const fn new(subject_id: u64, scope: CapabilityScope, expires_at_ns: u64) -> Self {
        Self {
            subject_id,
            scope,
            expires_at_ns,
            signature: [0; MAX_SIGNATURE_BYTES],
            signature_len: 0,
            _reserved: [0; 7],
        }
    }

    /// Returns a copy of this token with its signature bytes set.
    /// Panics (in debug) if `signature` is longer than
    /// `MAX_SIGNATURE_BYTES` — this is a programmer error at the
    /// Security Broker call site, not a runtime/hardware condition, so
    /// a hard failure here is appropriate rather than a `Result`.
    pub fn with_signature(mut self, signature: &[u8]) -> Self {
        assert!(
            signature.len() <= MAX_SIGNATURE_BYTES,
            "signature exceeds MAX_SIGNATURE_BYTES"
        );
        self.signature[..signature.len()].copy_from_slice(signature);
        self.signature_len = signature.len() as u8;
        self
    }

    /// The signature bytes actually in use (ignoring unused trailing
    /// capacity in the fixed `signature` array).
    pub fn signature_bytes(&self) -> &[u8] {
        &self.signature[..self.signature_len as usize]
    }

    /// Returns `true` if this token's scope exactly covers the
    /// requested `scope`. This is a pure, local, allocation-free
    /// comparison — it does NOT check the signature (see
    /// `TokenVerifier` for that) or expiry (see `is_expired`); callers
    /// must check all three before trusting a token.
    pub fn covers(&self, requested: CapabilityScope) -> bool {
        self.scope == requested
    }

    /// Returns `true` if `now_ns` (from `TimerAbstraction::now_ns`) is
    /// at or past this token's expiry.
    pub fn is_expired(&self, now_ns: u64) -> bool {
        now_ns >= self.expires_at_ns
    }
}

// ============================================================================
// Token verification
// ============================================================================

/// Verifies the cryptographic authenticity of a `CapabilityToken`'s
/// signature.
///
/// Deliberately a separate trait from `HalDirectAccess`: per the
/// module-level docs, section 5 leaves the actual signing/verification
/// ALGORITHM to be specified in the layer 2 security appendix. Each
/// architecture's `HalDirectAccess` implementation is generic over (or
/// holds a reference to) a `TokenVerifier`, so swapping the algorithm
/// later (e.g. from HMAC to Ed25519) never requires touching
/// `HalDirectAccess`'s own trait surface or any of its call sites.
pub trait TokenVerifier {
    /// Returns `Ok(())` if `token.signature_bytes()` is a valid
    /// signature over the token's other fields (`subject_id`, `scope`,
    /// `expires_at_ns`) under the Security Broker's current signing
    /// key. Returns `Err(HalError::InvalidCapabilityToken)` otherwise.
    fn verify_signature(&self, token: &CapabilityToken) -> Result<(), HalError>;
}

/// Combines scope, expiry, and signature checks into the one
/// verification step every `HalDirectAccess` method must perform before
/// doing anything else. Architecture implementations call this at the
/// top of every trait method rather than re-implementing the same three
/// checks independently each time.
pub fn verify_token<V: TokenVerifier>(
    verifier: &V,
    token: &CapabilityToken,
    required_scope: CapabilityScope,
    now_ns: u64,
) -> Result<(), HalError> {
    if !token.covers(required_scope) {
        return Err(HalError::InvalidCapabilityToken);
    }
    if token.is_expired(now_ns) {
        return Err(HalError::InvalidCapabilityToken);
    }
    verifier.verify_signature(token)
}

// ============================================================================
// Supporting types for HalDirectAccess operations
// ============================================================================

/// Identifies a hardware performance monitoring counter (PMC on
/// x86_64, PMU event counter on ARM64, the "hpmcounter" set on
/// RISC-V), unified behind one id space the same way `IrqId` (hal-core
/// interrupt.rs) unifies interrupt lines.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerfCounterId(pub u32);

/// NUMA memory placement policy for a thread, requested via
/// `set_numa_policy`. Mirrors the kind of policy Linux's `numactl`/
/// `set_mempolicy` exposes, since this is a familiar vocabulary for
/// professional users and driver authors (the audience section 5
/// targets) and for software ported through the layer 5 POSIX
/// Compatibility path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumaPolicy {
    /// Allocate from whichever NUMA node the requesting thread is
    /// currently running on.
    Local,
    /// Round-robin allocation across all NUMA nodes.
    Interleaved,
    /// Prefer a specific node, but fall back to others if it is out of
    /// memory rather than failing the allocation.
    Preferred(u8),
    /// Require a specific node; an allocation that cannot be satisfied
    /// there fails rather than falling back.
    Strict(u8),
}

// ============================================================================
// HalDirectAccess trait (section 5 pre-draft, extended with Result
// return types — the pre-draft signatures for read_performance_counter,
// pin_thread_to_core, and set_numa_policy did not return Result at
// all, which would force a panic-or-ignore choice on every failed
// verification; unacceptable in Privileged-mode code, same rationale
// applied throughout hal-core's traits)
// ============================================================================

/// Per-architecture direct hardware access, gated by `CapabilityToken`
/// on every call. Implemented once per architecture crate
/// (`hal-x86_64::direct::DirectAccess`, `hal-arm64::direct::DirectAccess`,
/// `hal-riscv64::direct::DirectAccess`), typically composed with a
/// concrete `TokenVerifier` supplied at construction time (wiring that
/// concrete verifier in is a layer 4 Security Broker integration
/// concern, not something hal-direct's trait definition needs to know
/// about).
pub trait HalDirectAccess {
    /// Maps physical MMIO region `[phys, phys + size)` into the calling
    /// context's address space and returns the resulting virtual
    /// address.
    ///
    /// `token` must carry
    /// `CapabilityScope::MmioRegion { phys_base: phys.as_usize() as u64, size: size as u64 }`
    /// exactly — a token scoped to a different base address or a
    /// smaller/larger size is rejected with
    /// `HalError::InvalidCapabilityToken`, even if it is otherwise
    /// validly signed and unexpired. This exact-match requirement (no
    /// partial overlap allowed) is deliberate: it means the Security
    /// Broker, not HAL, is the sole place that decides how finely
    /// scoped an MMIO grant is.
    fn map_mmio_region(&self, token: CapabilityToken, phys: PhysAddr, size: usize) -> Result<VirtAddr, HalError>;

    /// Reads the current value of hardware performance counter
    /// `counter`.
    ///
    /// `token` must carry
    /// `CapabilityScope::PerformanceCounter { counter_id: counter.0 }`.
    fn read_performance_counter(&self, token: CapabilityToken, counter: PerfCounterId) -> Result<u64, HalError>;

    /// Pins the calling thread to `core_id` for the remainder of its
    /// execution (or until a subsequent call changes/clears the
    /// pinning — clearing is a layer 2 scheduler policy operation, not
    /// something hal-direct itself exposes, since "pinned vs not" is
    /// scheduling state the microkernel owns).
    ///
    /// `token` must carry
    /// `CapabilityScope::ThreadAffinity { core_id: core_id as u32 }`.
    fn pin_thread_to_core(&self, token: CapabilityToken, core_id: usize) -> Result<(), HalError>;

    /// Requests a NUMA memory placement policy for the calling thread's
    /// future allocations.
    ///
    /// `token` must carry `CapabilityScope::NumaPolicy`.
    fn set_numa_policy(&self, token: CapabilityToken, policy: NumaPolicy) -> Result<(), HalError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Mock verifier + mock hardware implementation, per section 8.4's
    // "mock hardware" testing philosophy, applied here to hal-direct.
    // ------------------------------------------------------------------

    /// A verifier that accepts any token whose first signature byte is
    /// `0xAA` — a deliberately trivial stand-in for the real
    /// algorithm, which section 5 explicitly defers to the layer 2
    /// security appendix.
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

    struct MockDirectAccess {
        verifier: MockVerifier,
        now_ns: u64,
    }

    impl HalDirectAccess for MockDirectAccess {
        fn map_mmio_region(&self, token: CapabilityToken, phys: PhysAddr, size: usize) -> Result<VirtAddr, HalError> {
            verify_token(
                &self.verifier,
                &token,
                CapabilityScope::MmioRegion {
                    phys_base: phys.as_usize() as u64,
                    size: size as u64,
                },
                self.now_ns,
            )?;
            Ok(VirtAddr::new(phys.as_usize()))
        }

        fn read_performance_counter(&self, token: CapabilityToken, counter: PerfCounterId) -> Result<u64, HalError> {
            verify_token(
                &self.verifier,
                &token,
                CapabilityScope::PerformanceCounter { counter_id: counter.0 },
                self.now_ns,
            )?;
            Ok(42) // mock counter value
        }

        fn pin_thread_to_core(&self, token: CapabilityToken, core_id: usize) -> Result<(), HalError> {
            verify_token(
                &self.verifier,
                &token,
                CapabilityScope::ThreadAffinity { core_id: core_id as u32 },
                self.now_ns,
            )?;
            Ok(())
        }

        fn set_numa_policy(&self, token: CapabilityToken, policy: NumaPolicy) -> Result<(), HalError> {
            let _ = policy;
            verify_token(&self.verifier, &token, CapabilityScope::NumaPolicy, self.now_ns)?;
            Ok(())
        }
    }

    fn valid_signature() -> &'static [u8] {
        &[0xAA, 0x01, 0x02]
    }

    #[test]
    fn mmio_map_succeeds_with_matching_scope_and_valid_signature() {
        let hal = MockDirectAccess { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(
            7,
            CapabilityScope::MmioRegion { phys_base: 0xFEE0_0000, size: 0x1000 },
            2000,
        )
        .with_signature(valid_signature());

        let result = hal.map_mmio_region(token, PhysAddr::new(0xFEE0_0000), 0x1000);
        assert!(result.is_ok());
    }

    #[test]
    fn mmio_map_rejects_mismatched_scope() {
        let hal = MockDirectAccess { verifier: MockVerifier, now_ns: 1000 };
        // Token scoped to a DIFFERENT physical base than requested.
        let token = CapabilityToken::new(
            7,
            CapabilityScope::MmioRegion { phys_base: 0x1000_0000, size: 0x1000 },
            2000,
        )
        .with_signature(valid_signature());

        let result = hal.map_mmio_region(token, PhysAddr::new(0xFEE0_0000), 0x1000);
        assert_eq!(result, Err(HalError::InvalidCapabilityToken));
    }

    #[test]
    fn expired_token_is_rejected() {
        let hal = MockDirectAccess { verifier: MockVerifier, now_ns: 5000 };
        let token = CapabilityToken::new(
            7,
            CapabilityScope::PerformanceCounter { counter_id: 3 },
            2000, // already expired relative to now_ns = 5000
        )
        .with_signature(valid_signature());

        let result = hal.read_performance_counter(token, PerfCounterId(3));
        assert_eq!(result, Err(HalError::InvalidCapabilityToken));
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let hal = MockDirectAccess { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(7, CapabilityScope::ThreadAffinity { core_id: 2 }, 2000)
            .with_signature(&[0xBB, 0x00]); // wrong first byte

        let result = hal.pin_thread_to_core(token, 2);
        assert_eq!(result, Err(HalError::InvalidCapabilityToken));
    }

    #[test]
    fn numa_policy_scope_ignores_policy_value() {
        let hal = MockDirectAccess { verifier: MockVerifier, now_ns: 1000 };
        let token = CapabilityToken::new(7, CapabilityScope::NumaPolicy, 2000).with_signature(valid_signature());

        // Same token scope authorizes any NumaPolicy value — scope is
        // "may set NUMA policy at all", not tied to which policy.
        assert!(hal.set_numa_policy(token, NumaPolicy::Local).is_ok());
        assert!(hal.set_numa_policy(token, NumaPolicy::Strict(1)).is_ok());
    }

    #[test]
    fn token_covers_checks_exact_scope_equality() {
        let token = CapabilityToken::new(1, CapabilityScope::ThreadAffinity { core_id: 5 }, 1000);
        assert!(token.covers(CapabilityScope::ThreadAffinity { core_id: 5 }));
        assert!(!token.covers(CapabilityScope::ThreadAffinity { core_id: 6 }));
    }
}