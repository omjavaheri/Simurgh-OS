//! ============================================================================
//! ed25519.rs
//!
//! Purpose: a concrete `TokenVerifier` for `CapabilityToken`, backed by
//! Ed25519 (Issue #29's resolved design decision — the algorithm
//! `hal-direct`'s module docs left explicitly open).
//!
//! Architecture reference: 01-HAL-Layer.md section 5 ("HAL فقط توکن را
//! verify می‌کند"). This crate never signs anything — the Security
//! Broker (layer 4) holds the ONLY private key and mints tokens
//! outside this crate's concern; this module only ever constructs a
//! `VerifyingKey` (public) and checks a signature against it.
//!
//! Position in the system: an optional (`ed25519` feature) addition to
//! `hal-direct`, consumed by a `hal-<arch>`'s `direct.rs` at
//! construction time via `TokenVerifier`, exactly like the mock
//! verifier already used in tests — see `super::verify_token` and
//! `hal_x86_64::direct::DirectAccess::new`.
//!
//! Safety/invariants: no `unsafe` in this file. Choosing Ed25519
//! (asymmetric) over an HMAC-style shared secret means a hal-<arch>
//! image only ever needs to embed a PUBLIC key — a leaked/dumped
//! kernel binary reveals nothing usable to forge a token, unlike a
//! symmetric secret that would have to be duplicated identically
//! across all three architecture crates.
//!
//! NOTE — deliberately out of scope here: HOW the public key actually
//! reaches a `hal-<arch>` crate at boot (embedded constant? passed via
//! `BootInfo`? provisioned by the bootloader?) is a separate, still-
//! open design question (see Issue #29's own body) — this module only
//! provides the verifier GIVEN a public key, not the provisioning
//! story. Do not wire this into any `hal_<arch>_rust_entry` boot path
//! until that follow-up decision is made.
//! ============================================================================

use ed25519_dalek::{Signature, VerifyingKey};

use crate::{CapabilityScope, CapabilityToken, TokenVerifier};
use hal_core::HalError;

/// Fixed-size, unambiguous byte encoding of the fields a `CapabilityToken`'s
/// signature actually covers (`subject_id`, `scope`, `expires_at_ns`).
///
/// Built field-by-field with explicit `to_le_bytes()` writes rather than
/// reinterpreting the `CapabilityToken`/`CapabilityScope` structs' own
/// memory as bytes: `CapabilityScope` is `#[repr(u8)]` (fixes the
/// discriminant's size) but that alone does NOT guarantee a stable,
/// padding-free byte layout for its data-carrying variants across
/// compiler versions — reading such padding would be unspecified at
/// best. A hand-written encoder has no padding to worry about and is
/// exactly the sort of authenticated-message construction a signature
/// scheme's soundness actually depends on getting right.
///
/// Layout (all integers little-endian, total 41 bytes):
///   `DOMAIN_TAG` (16) ++ `subject_id` (8) ++ scope-tag (1) ++
///   scope-payload (16, zero-padded for variants narrower than the
///   widest one) ++ `expires_at_ns` (8)
const ENCODED_LEN: usize = 16 + 8 + 1 + 16 + 8;

/// Domain-separation prefix: ties a signature to "this is a Simurgh
/// hal-direct CapabilityToken" specifically, so the Security Broker's
/// Ed25519 signing key can never be confused with — or a signature
/// replayed from — some unrelated protocol that happens to reuse the
/// same key material. Standard defense-in-depth practice for signed
/// tokens, cheap to add, no downside.
const DOMAIN_TAG: &[u8; 16] = b"SimurghHalDirect";
const _: () = assert!(DOMAIN_TAG.len() == 16);

fn encode_signed_fields(token: &CapabilityToken) -> [u8; ENCODED_LEN] {
    let mut out = [0u8; ENCODED_LEN];
    let mut pos = 0;

    out[pos..pos + 16].copy_from_slice(DOMAIN_TAG);
    pos += 16;

    out[pos..pos + 8].copy_from_slice(&token.subject_id.to_le_bytes());
    pos += 8;

    match token.scope {
        CapabilityScope::MmioRegion { phys_base, size } => {
            out[pos] = 0;
            pos += 1;
            out[pos..pos + 8].copy_from_slice(&phys_base.to_le_bytes());
            out[pos + 8..pos + 16].copy_from_slice(&size.to_le_bytes());
            pos += 16;
        }
        CapabilityScope::PerformanceCounter { counter_id } => {
            out[pos] = 1;
            pos += 1;
            out[pos..pos + 4].copy_from_slice(&counter_id.to_le_bytes());
            // Remaining 12 bytes of the 16-byte payload slot stay zero.
            pos += 16;
        }
        CapabilityScope::ThreadAffinity { core_id } => {
            out[pos] = 2;
            pos += 1;
            out[pos..pos + 4].copy_from_slice(&core_id.to_le_bytes());
            pos += 16;
        }
        CapabilityScope::NumaPolicy => {
            out[pos] = 3;
            pos += 1 + 16;
        }
    }

    out[pos..pos + 8].copy_from_slice(&token.expires_at_ns.to_le_bytes());
    pos += 8;

    debug_assert_eq!(pos, ENCODED_LEN);
    out
}

/// A `TokenVerifier` backed by one Ed25519 public key.
///
/// Holds only the PUBLIC key — see module docs. `Copy`/heap-free like
/// every other type in this crate's hot verification path.
#[derive(Clone, Copy)]
pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    /// Constructs a verifier from a raw 32-byte Ed25519 public key
    /// (the Security Broker's signing key, layer 4). Returns
    /// `Err(HalError::InvalidCapabilityToken)` if `bytes` is not a
    /// valid compressed Edwards point — this is a boot-time
    /// configuration error (a corrupt/wrong key was provisioned), not
    /// a per-token failure, but reuses the same error type per
    /// hal-core's own "no HAL-specific error proliferation" convention
    /// (see `hal_core::error`).
    pub fn from_public_key_bytes(bytes: &[u8; 32]) -> Result<Self, HalError> {
        VerifyingKey::from_bytes(bytes)
            .map(|key| Self { key })
            .map_err(|_| HalError::InvalidCapabilityToken)
    }
}

impl TokenVerifier for Ed25519Verifier {
    fn verify_signature(&self, token: &CapabilityToken) -> Result<(), HalError> {
        // A short/wrong-length signature is a malformed token, not a
        // cryptographic question — reject before touching the verify
        // path at all (also avoids a slice-length mismatch below).
        if token.signature_len as usize != Signature::BYTE_SIZE {
            return Err(HalError::InvalidCapabilityToken);
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(token.signature_bytes());
        let signature = Signature::from_bytes(&sig_bytes);

        let message = encode_signed_fields(token);
        self.key
            .verify_strict(&message, &signature)
            .map_err(|_| HalError::InvalidCapabilityToken)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Deterministic test-only key material — NOT a real Security
    /// Broker key. `SigningKey::from_bytes` (not `generate`) so these
    /// tests need no RNG dependency.
    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn sign(signing_key: &SigningKey, token: &CapabilityToken) -> CapabilityToken {
        let message = encode_signed_fields(token);
        let signature = signing_key.sign(&message);
        token.with_signature(&signature.to_bytes())
    }

    #[test]
    fn valid_signature_over_matching_fields_verifies() {
        let signing_key = test_signing_key();
        let verifier = Ed25519Verifier::from_public_key_bytes(signing_key.verifying_key().as_bytes()).unwrap();

        let token = CapabilityToken::new(42, CapabilityScope::NumaPolicy, 5000);
        let signed = sign(&signing_key, &token);

        assert!(verifier.verify_signature(&signed).is_ok());
    }

    #[test]
    fn tampered_scope_after_signing_is_rejected() {
        let signing_key = test_signing_key();
        let verifier = Ed25519Verifier::from_public_key_bytes(signing_key.verifying_key().as_bytes()).unwrap();

        let token = CapabilityToken::new(42, CapabilityScope::ThreadAffinity { core_id: 2 }, 5000);
        let signed = sign(&signing_key, &token);

        // Flip the scope AFTER signing, keeping the original signature
        // bytes — the classic "scope field flipped" attack the crate's
        // own module docs call out.
        let tampered = CapabilityToken {
            scope: CapabilityScope::ThreadAffinity { core_id: 99 },
            ..signed
        };

        assert_eq!(
            verifier.verify_signature(&tampered),
            Err(HalError::InvalidCapabilityToken)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signing_key = test_signing_key();
        let other_signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let wrong_verifier =
            Ed25519Verifier::from_public_key_bytes(other_signing_key.verifying_key().as_bytes()).unwrap();

        let token = CapabilityToken::new(1, CapabilityScope::NumaPolicy, 5000);
        let signed = sign(&signing_key, &token);

        assert_eq!(
            wrong_verifier.verify_signature(&signed),
            Err(HalError::InvalidCapabilityToken)
        );
    }

    #[test]
    fn wrong_signature_length_is_rejected_without_panicking() {
        let signing_key = test_signing_key();
        let verifier = Ed25519Verifier::from_public_key_bytes(signing_key.verifying_key().as_bytes()).unwrap();

        let token = CapabilityToken::new(1, CapabilityScope::NumaPolicy, 5000).with_signature(&[0xAA; 3]);

        assert_eq!(
            verifier.verify_signature(&token),
            Err(HalError::InvalidCapabilityToken)
        );
    }

    #[test]
    fn different_scopes_produce_different_signed_messages() {
        // Guards the hand-written encoder itself: two tokens differing
        // ONLY in scope variant/payload must not collide onto the same
        // signed byte string (which would let a token minted for one
        // scope verify successfully against another).
        let a = CapabilityToken::new(1, CapabilityScope::PerformanceCounter { counter_id: 5 }, 100);
        let b = CapabilityToken::new(1, CapabilityScope::ThreadAffinity { core_id: 5 }, 100);
        let c = CapabilityToken::new(1, CapabilityScope::MmioRegion { phys_base: 0, size: 5 }, 100);

        assert_ne!(encode_signed_fields(&a), encode_signed_fields(&b));
        assert_ne!(encode_signed_fields(&a), encode_signed_fields(&c));
        assert_ne!(encode_signed_fields(&b), encode_signed_fields(&c));
    }
}
