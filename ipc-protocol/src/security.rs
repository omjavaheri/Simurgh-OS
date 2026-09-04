//! ============================================================================
//! security.rs
//!
//! Purpose: the wire protocol between the Security/Permission Broker
//! (layer 4, `simurgh-security-broker`) and this repo's layer-3
//! CapGrant/CapRevoke intermediary process (Issue #28). This is the
//! Security Broker's ONLY path to a real, layer-2 `Capability` — it
//! never holds kernel capabilities itself, never calls a kernel syscall
//! directly, and this protocol is the entire boundary.
//!
//! Architecture reference: 04-System-Services-Policy-Layer.md §0 and
//! 02-Microkernel-Layer.md §6 (the intermediary-process requirement);
//! 02-Microkernel-Layer.md §2.1 (Issue #30's decision on how a
//! destination is named across this boundary — see `target_service`'s
//! own doc comment below); 03-Kernel-Subsystems-Layer.md §3 (this
//! crate's own wire-protocol conventions, matched here).
//!
//! Position in the system: encoded into `kernel_ipc::SmallMessage`.
//! `CapGrant`/`CapRevoke` here deliberately mirror
//! `kernel_core::syscall::SyscallOp::CapGrant`/`CapRevoke` field-for-field
//! (the kernel-side mechanism is already proven — 03-Kernel-Subsystems-
//! Layer.md's own framing of Issue #28 is that this is purely the
//! layer-3/4 BOUNDARY design, not a new kernel mechanism), except for how
//! the destination and source capability are NAMED — see each field's own
//! doc comment.
//!
//! Safety/invariants: plain integer fields; `Copy`. This protocol never
//! carries a raw kernel `CapId`/`GlobalCapId` value to a layer-4 caller —
//! `CapId`s are only ever meaningful within one specific capability
//! space, and Security Broker (layer 4) holds none of its own; see
//! `target_service`.
//! ============================================================================

/// A request from the Security Broker to this repo's CapGrant/CapRevoke
/// intermediary process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityRequest {
    /// Copies `cap` (narrowed to `rights`) into the capability space of
    /// the destination named by `target_service`. Mirrors the kernel's
    /// own `SyscallOp::CapGrant` exactly, except for how the destination
    /// is identified — see `target_service`'s own doc comment. Reply:
    /// `Granted` or `Error`.
    CapGrant {
        /// An opaque, layer-4-defined service-instance identifier (e.g.
        /// "the currently-running instance of driver X"), NOT a raw
        /// kernel `CapId`. Issue #30's resolved decision
        /// (02-Microkernel-Layer.md §2.1): the kernel has no
        /// `ProcessId`/`UserId` concept and never will, so a `UserId` →
        /// destination-thread mapping cannot be expressed as a kernel
        /// primitive on this wire. The intermediary process — the only
        /// party that actually holds destination-TCB `CapId`s, granted
        /// to it by Root Task at boot — resolves this identifier to a
        /// real destination `CapId` using its own internal, boot-time
        /// mapping. What values are valid and what they mean is defined
        /// entirely by layer 4 (Security Broker / account-manager), not
        /// by this protocol or this repo.
        target_service: u32,
        /// The capability to copy: a slot in the INTERMEDIARY's own
        /// capability space, not the Security Broker's (it holds none).
        /// How the Security Broker learns which `cap` value corresponds
        /// to which real resource is layer-4 policy, out of this
        /// repo's scope (REPO-Simurgh-OS.md §3).
        cap: u32,
        /// `CapabilityRights` bitflags requested for the copy (must be a
        /// subset of `cap`'s own rights — enforced by the real kernel
        /// `CapGrant` syscall the intermediary issues on this request's
        /// behalf; a mismatch surfaces back as `Error`).
        rights: u32,
    },
    /// Revokes `cap` and every capability derived from it. Mirrors
    /// `SyscallOp::CapRevoke` exactly. Reply: `Revoked` or `Error`.
    CapRevoke {
        /// The capability (subtree root) to revoke, in the
        /// intermediary's own capability space — see `CapGrant::cap`.
        cap: u32,
    },
}

/// A reply from the intermediary process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityResponse {
    /// `CapGrant` placed a copy at `dst`, in the destination named by
    /// the request's `target_service`.
    Granted {
        /// The new slot in the destination's own capability space.
        dst: u32,
    },
    /// `CapRevoke` completed; `freed` slots (across every capability
    /// space the kernel's `CapRevoke` reached) were invalidated.
    Revoked {
        /// Slots freed.
        freed: u32,
    },
    /// The request could not be completed — same "an honest error
    /// variant, not a repurposed success shape" convention `FsResponse::
    /// Error`/`MmResponse::Error` already establish in this crate.
    Error {
        /// Machine-readable error code.
        code: SecurityErrorCode,
    },
}

/// Intermediary-process error codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityErrorCode {
    /// The request could not be decoded, or named an unsupported
    /// operation.
    Unsupported = 1,
    /// `target_service` did not resolve to a known destination in the
    /// intermediary's own boot-time mapping.
    UnknownService = 2,
    /// The underlying kernel `CapGrant`/`CapRevoke` syscall itself
    /// failed (rights escalation, empty slot, badge conflict — see
    /// `kernel_cap::cdt::CapTableError` for the real kernel-side
    /// reasons this can happen). The intermediary does not distinguish
    /// which kernel-side reason on this wire; the Security Broker's own
    /// audit log (out of this repo's scope) is the place a human
    /// diagnoses a specific rejection.
    KernelRejected = 3,
}
