//! ============================================================================
//! security-broker-intermediary
//!
//! Purpose: Simurgh's CapGrant/CapRevoke intermediary (Issue #28) — the
//! ONLY process the Security Broker (layer 4, `simurgh-security-broker`)
//! is ever allowed to route a real capability mint/revoke through
//! (04-System-Services-Policy-Layer.md §0, 02-Microkernel-Layer.md §6:
//! "never a backdoor"). This crate's pure logic is the boot-time
//! `target_service -> capability slot` table (`Intermediary`) — the real
//! IPC server loop and the real `CAP_GRANT`/`CAP_REVOKE` syscalls
//! themselves live in `subsystem_entry`, which this table backs.
//!
//! Architecture reference: `ipc-protocol/src/security.rs` (the
//! `SecurityRequest`/`SecurityResponse` wire protocol this crate serves);
//! `root_task::Service::SecurityBrokerIntermediary`'s own doc comment
//! (this process "needs a destination-TCB CapId for every other service
//! it might need to grant capabilities into").
//!
//! Position in the system: an isolated layer-3 process, granted its own
//! Endpoint plus a fixed, small set of destination-TCB capabilities by
//! Root Task at spawn time (`kernel_arch_glue::
//! security_broker_intermediary_demo_start`) — this crate never mints its
//! OWN capabilities; it only ever copies ones it was already granted,
//! into a destination named by `SecurityRequest::CapGrant::target_service`
//! (resolved through `Intermediary`, never a raw kernel `CapId` accepted
//! directly from the wire — Issue #30's resolved decision).
//!
//! Safety/invariants: `target_service` values and their meaning are
//! entirely layer-4-defined (`SecurityRequest::CapGrant::target_service`'s
//! own doc comment) — this crate just holds whatever boot-time mapping
//! `subsystem_entry::subsystem_main` populates it with.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::collections::BTreeMap;

/// The intermediary's own process entry point (see that module's own doc
/// comment) — mirrors `compositor::subsystem_entry`'s own unconditional
/// module declaration (per-architecture gating lives inside the file, not
/// at this level).
pub mod subsystem_entry;

/// Why [`Intermediary::resolve_target`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntermediaryError {
    /// `target_service` did not resolve to a known destination in this
    /// process's own boot-time mapping. Mirrors
    /// `ipc_protocol::security::SecurityErrorCode::UnknownService`.
    UnknownService,
}

/// The intermediary's own boot-time `target_service -> capability slot`
/// table — the ENTIRE resolution `SecurityRequest::CapGrant::
/// target_service`'s own doc comment describes: "The intermediary
/// process ... resolves this identifier to a real destination `CapId`
/// using its own internal, boot-time mapping."
///
/// A `target_service` value is opaque and layer-4-defined; the capability
/// slot it maps to is a `ThreadControlBlock` capability in THIS process's
/// own capability space (minted there by Root Task via `kernel_arch_glue
/// ::mint_tcb_cap_into`, at spawn time — this struct never mints
/// anything itself, only remembers where each already-granted capability
/// landed).
#[derive(Debug, Default)]
pub struct Intermediary {
    targets: BTreeMap<u32, u32>,
}

impl Intermediary {
    /// An intermediary with no registered targets yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `target_service` resolves to `cap_slot` (a capability
    /// slot in THIS process's own capability space, granted by Root Task
    /// at spawn time). Overwrites any previous mapping for the same
    /// `target_service`.
    pub fn register_target(&mut self, target_service: u32, cap_slot: u32) {
        self.targets.insert(target_service, cap_slot);
    }

    /// Resolves `target_service` to the capability slot a `CAP_GRANT`/
    /// `CAP_REVOKE` syscall should use as its `target_thread` argument.
    ///
    /// Postconditions: `Ok(slot)` iff `target_service` was previously
    /// registered; `Err(IntermediaryError::UnknownService)` otherwise —
    /// mirrors `SecurityResponse::Error { code: SecurityErrorCode::
    /// UnknownService }`.
    pub fn resolve_target(&self, target_service: u32) -> Result<u32, IntermediaryError> {
        self.targets.get(&target_service).copied().ok_or(IntermediaryError::UnknownService)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolving_an_unregistered_service_is_unknown() {
        let intermediary = Intermediary::new();
        assert_eq!(intermediary.resolve_target(0), Err(IntermediaryError::UnknownService));
    }

    #[test]
    fn resolving_a_registered_service_returns_its_slot() {
        let mut intermediary = Intermediary::new();
        intermediary.register_target(0, 1);
        assert_eq!(intermediary.resolve_target(0), Ok(1));
    }

    #[test]
    fn re_registering_a_service_overwrites_its_previous_slot() {
        let mut intermediary = Intermediary::new();
        intermediary.register_target(0, 1);
        intermediary.register_target(0, 5);
        assert_eq!(intermediary.resolve_target(0), Ok(5));
    }

    #[test]
    fn multiple_services_resolve_independently() {
        let mut intermediary = Intermediary::new();
        intermediary.register_target(0, 1);
        intermediary.register_target(1, 2);
        assert_eq!(intermediary.resolve_target(0), Ok(1));
        assert_eq!(intermediary.resolve_target(1), Ok(2));
    }
}
