//! ============================================================================
//! mm.rs
//!
//! Purpose: the wire-level control protocol for mm-service, the
//! high-level memory POLICY service (03-Kernel-Subsystems-Layer.md
//! §2.5) — distinct from the microkernel's raw `UntypedMemory`
//! mechanism (02 §3). Other services register their own memory
//! accounting with it; it answers OOM victim-selection queries.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.5 (this
//! service's three responsibilities — OOM policy is the one this MVP
//! wire protocol covers; swap and CXL unified-memory coordination are
//! `// TODO(omid)` in `mm_service`'s own doc comment, needing block-
//! device/compute-device capabilities this protocol does not carry).
//!
//! Position in the system: encoded into `kernel_ipc::SmallMessage`.
//! `ReclaimClass` here is this protocol's OWN wire-level copy of
//! `mm_service::ReclaimClass` (same three variants) — kept separate
//! rather than shared, matching this crate's own established
//! "`ipc-protocol` never depends on a subsystem crate" dependency
//! direction (subsystems depend on `ipc-protocol`, never the reverse);
//! `mm::subsystem_entry` converts between the two.
//!
//! Safety/invariants: plain integer fields; `Copy`.
//! ============================================================================

/// How aggressively a process should be reclaimed from — the wire-level
/// twin of `mm_service::ReclaimClass` (see that type's own doc comment
/// for what each variant means to OOM victim selection).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimClass {
    /// Spare unless nothing else remains.
    Protected = 0,
    /// Ordinary candidate, ranked by footprint.
    Normal = 1,
    /// Preferred victim.
    Sacrificial = 2,
}

/// A request to mm-service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmRequest {
    /// Registers or updates a process's own memory accounting. Reply:
    /// `Registered`.
    Register {
        /// The process's thread id (its handle for reclaim requests).
        thread: u32,
        /// Resident bytes it is currently charged for.
        resident_bytes: u64,
        /// How reclaimable it is.
        class: ReclaimClass,
    },
    /// Drops a process's own accounting (it exited). Reply:
    /// `Unregistered`.
    Unregister {
        /// The process's thread id.
        thread: u32,
    },
    /// Asks for the current OOM victim under the registered set. Reply:
    /// `Victim`.
    QueryVictim,
    /// Asks for the running total of resident memory across the
    /// registered set. Reply: `TotalResident`.
    QueryTotalResident,
}

/// A reply from mm-service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmResponse {
    /// `Register` completed.
    Registered,
    /// `Unregister` completed.
    Unregistered,
    /// `QueryVictim` result. `thread == u32::MAX` means no process is
    /// currently registered (the wire-level "no victim" sentinel — same
    /// convention this crate's own `FsResponse`/`DriverResponse` already
    /// use throughout instead of an `Option`).
    Victim {
        /// The chosen victim's thread id, or `u32::MAX` for none.
        thread: u32,
    },
    /// `QueryTotalResident` result.
    TotalResident {
        /// Total resident bytes across the registered set.
        bytes: u64,
    },
    /// The request could not be decoded/handled (e.g. an unsupported
    /// opcode from a version-skewed peer) — same "an honest error
    /// variant, not a repurposed success shape" convention `FsResponse::
    /// Error`/`DisplayResponse::Error` already establish.
    Error {
        /// Machine-readable error code.
        code: MmErrorCode,
    },
}

/// mm-service error codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmErrorCode {
    /// The request could not be decoded, or named an unsupported
    /// operation.
    Unsupported = 1,
}
