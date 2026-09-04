//! ============================================================================
//! ipc-protocol
//!
//! Purpose: the typed message contract every layer-3 subsystem speaks to
//! every other (and to layer-4 clients) — VFS requests, driver requests,
//! the compositor's display protocol, the kernel-bypass networking
//! interface. One shared definition so versioning never drifts between
//! services (03-Kernel-Subsystems-Layer.md §3).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §3 (shared IDL,
//! avoid serialization cost, typed Rust output used from `kernel-ipc`),
//! §2.1 (`DriverRequest`/`DriverResponse`), §2.2 (`FsRequest`/`FsResponse`),
//! §2.3 (`KernelBypassNetworking`), §2.4 (`DisplayProtocol`).
//! REPO-Simurgh-OS.md §4: this crate is the project's most
//! semver-sensitive surface — other repos depend on it.
//!
//! Position in the system: `no_std`, links into every layer-3 service
//! binary and (via the codec) rides inside `kernel_ipc::SmallMessage`
//! payloads across the syscall IPC boundary.
//!
//! Safety/invariants: message types are `#[repr(C)]` / plain enums with no
//! pointers; the codec is total (`decode` always returns a `Result`, never
//! panics) and versioned (`PROTOCOL_VERSION`).
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod fs;
pub mod driver;
pub mod display;
pub mod net;
pub mod mm;
pub mod security;
pub mod codec;

pub use codec::{decode_fs_request, encode_fs_request, DecodeError};
pub use display::{DisplayErrorCode, DisplayRequest, DisplayResponse, SurfaceHandle};
pub use driver::{DriverRequest, DriverResponse};
pub use fs::{FileHandle, FsRequest, FsResponse, OpenFlags, PathId};
pub use mm::{MmErrorCode, MmRequest, MmResponse, ReclaimClass};
pub use net::{DirectNicHandle, NetBypassRequest, NetBypassResponse};
pub use security::{SecurityErrorCode, SecurityRequest, SecurityResponse};

/// Protocol version. Bump on any incompatible change to a message type or
/// the codec. A peer that decodes a message tagged with an unrecognised
/// version returns `DecodeError::VersionMismatch` rather than
/// misinterpreting bytes (03-Kernel-Subsystems-Layer.md §3 — "برای
/// جلوگیری از سردرگمی نسخه‌بندی").
pub const PROTOCOL_VERSION: u16 = 1;

/// Top-level namespaces, encoded in the high byte of a `SmallMessage`
/// label so a receiver can route a message to the right handler before
/// decoding the rest.
///
/// Possible values:
/// - `Fs`: a `FsRequest` / `FsResponse` (VFS service, §2.2).
/// - `Driver`: a `DriverRequest` / `DriverResponse` (a driver process,
///   §2.1).
/// - `Display`: a `DisplayRequest` (compositor service, §2.4).
/// - `NetBypass`: a `NetBypassRequest` (kernel-bypass networking, §2.3).
/// - `Mm`: an `MmRequest` (memory policy service, §2.5).
/// - `Security`: a `SecurityRequest` (the Security Broker's CapGrant/
///   CapRevoke intermediary process, Issue #28 — 02-Microkernel-Layer.md
///   §6).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    /// Filesystem / VFS.
    Fs = 1,
    /// Device driver.
    Driver = 2,
    /// Display / compositor.
    Display = 3,
    /// Kernel-bypass networking.
    NetBypass = 4,
    /// Memory policy service.
    Mm = 5,
    /// Security Broker's CapGrant/CapRevoke intermediary.
    Security = 6,
}

impl Namespace {
    /// The namespace encoded in a message `label`'s high byte, if valid.
    pub fn from_label(label: u64) -> Option<Self> {
        match (label >> 56) as u8 {
            1 => Some(Self::Fs),
            2 => Some(Self::Driver),
            3 => Some(Self::Display),
            4 => Some(Self::NetBypass),
            5 => Some(Self::Mm),
            6 => Some(Self::Security),
            _ => None,
        }
    }

    /// Builds a full `label` from this namespace, a per-namespace opcode,
    /// and the protocol version.
    pub const fn label(self, opcode: u8) -> u64 {
        ((self as u64) << 56) | ((PROTOCOL_VERSION as u64) << 8) | (opcode as u64)
    }
}

/// Extracts `(version, opcode)` from a message label.
pub const fn label_parts(label: u64) -> (u16, u8) {
    (((label >> 8) & 0xFFFF) as u16, (label & 0xFF) as u8)
}
