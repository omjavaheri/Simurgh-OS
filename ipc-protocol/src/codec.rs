//! ============================================================================
//! codec.rs
//!
//! Purpose: pack/unpack message types to/from `kernel_ipc::SmallMessage`
//! words. Hand-written for the MVP (IMPLEMENTATION-PLAN.md D7) — no `serde`,
//! no proc-macro IDL. The encoding is: the `SmallMessage` label carries
//! `(namespace, version, opcode)` (see `crate::Namespace`), and the data
//! words carry the variant's fields in declaration order.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §3 (typed,
//! low-overhead, versioned).
//!
//! Position in the system: called on both ends of every layer-3 IPC. This
//! module implements the `FsRequest` codec in full as the reference; the
//! other namespaces follow the identical pattern and are a mechanical
//! follow-up (their opcodes/labels are already defined).
//!
//! Safety/invariants: `decode_*` is total — it returns `DecodeError` for a
//! bad version, an unknown opcode, or a truncated payload, and never
//! panics.
//! ============================================================================

use crate::fs::{FileHandle, FsRequest, OpenFlags, PathId};
use crate::{label_parts, Namespace, PROTOCOL_VERSION};
use kernel_ipc::SmallMessage;

/// Why decoding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The label's namespace byte did not match the expected namespace.
    WrongNamespace,
    /// The label's protocol version is not `PROTOCOL_VERSION`.
    VersionMismatch,
    /// The opcode is not a known variant of this namespace.
    UnknownOpcode,
    /// The message had fewer data words than the variant needs.
    Truncated,
    /// A field held a value outside its valid range (e.g. undefined
    /// flag bits).
    BadField,
}

// FsRequest opcodes (low byte of the label).
const OP_OPEN: u8 = 1;
const OP_READ: u8 = 2;
const OP_WRITE: u8 = 3;
const OP_STAT: u8 = 4;
const OP_CLOSE: u8 = 5;

/// Encodes a `FsRequest` into a `SmallMessage`.
///
/// Word layout by variant:
/// - `Open`:  `[path, flags]`
/// - `Read`:  `[handle, offset, len, shared_cap]`
/// - `Write`: `[handle, offset, len, shared_cap]`
/// - `Stat`:  `[path]`
/// - `Close`: `[handle]`
pub fn encode_fs_request(req: &FsRequest) -> SmallMessage {
    let (op, words): (u8, [u64; 4]) = match *req {
        FsRequest::Open { path, flags } => {
            (OP_OPEN, [path.0 as u64, flags.bits() as u64, 0, 0])
        }
        FsRequest::Read {
            handle,
            offset,
            len,
            shared_cap,
        } => (
            OP_READ,
            [handle.0 as u64, offset, len as u64, shared_cap as u64],
        ),
        FsRequest::Write {
            handle,
            offset,
            len,
            shared_cap,
        } => (
            OP_WRITE,
            [handle.0 as u64, offset, len as u64, shared_cap as u64],
        ),
        FsRequest::Stat { path } => (OP_STAT, [path.0 as u64, 0, 0, 0]),
        FsRequest::Close { handle } => (OP_CLOSE, [handle.0 as u64, 0, 0, 0]),
    };
    let n = match op {
        OP_OPEN => 2,
        OP_READ | OP_WRITE => 4,
        _ => 1,
    };
    // `from_words` cannot fail here: n <= 4 <= MSG_MAX_WORDS.
    SmallMessage::from_words(Namespace::Fs.label(op), &words[..n])
        .unwrap_or_else(|_| SmallMessage::new(Namespace::Fs.label(op)))
}

/// Decodes a `FsRequest` from a `SmallMessage`.
pub fn decode_fs_request(msg: &SmallMessage) -> Result<FsRequest, DecodeError> {
    match Namespace::from_label(msg.label) {
        Some(Namespace::Fs) => {}
        _ => return Err(DecodeError::WrongNamespace),
    }
    let (version, op) = label_parts(msg.label);
    if version != PROTOCOL_VERSION {
        return Err(DecodeError::VersionMismatch);
    }
    let w = msg.words();
    let need = |n: usize| -> Result<(), DecodeError> {
        if w.len() < n {
            Err(DecodeError::Truncated)
        } else {
            Ok(())
        }
    };
    match op {
        OP_OPEN => {
            need(2)?;
            let flags = OpenFlags::from_bits(w[1] as u32).ok_or(DecodeError::BadField)?;
            Ok(FsRequest::Open {
                path: PathId(w[0] as u32),
                flags,
            })
        }
        OP_READ => {
            need(4)?;
            Ok(FsRequest::Read {
                handle: FileHandle(w[0] as u32),
                offset: w[1],
                len: w[2] as u32,
                shared_cap: w[3] as u32,
            })
        }
        OP_WRITE => {
            need(4)?;
            Ok(FsRequest::Write {
                handle: FileHandle(w[0] as u32),
                offset: w[1],
                len: w[2] as u32,
                shared_cap: w[3] as u32,
            })
        }
        OP_STAT => {
            need(1)?;
            Ok(FsRequest::Stat {
                path: PathId(w[0] as u32),
            })
        }
        OP_CLOSE => {
            need(1)?;
            Ok(FsRequest::Close {
                handle: FileHandle(w[0] as u32),
            })
        }
        _ => Err(DecodeError::UnknownOpcode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(req: FsRequest) {
        let msg = encode_fs_request(&req);
        assert_eq!(decode_fs_request(&msg), Ok(req));
    }

    #[test]
    fn all_variants_roundtrip() {
        roundtrip(FsRequest::Open {
            path: PathId(7),
            flags: OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE,
        });
        roundtrip(FsRequest::Read {
            handle: FileHandle(3),
            offset: 4096,
            len: 512,
            shared_cap: 9,
        });
        roundtrip(FsRequest::Write {
            handle: FileHandle(3),
            offset: 0,
            len: 128,
            shared_cap: 10,
        });
        roundtrip(FsRequest::Stat { path: PathId(1) });
        roundtrip(FsRequest::Close {
            handle: FileHandle(3),
        });
    }

    #[test]
    fn wrong_namespace_is_rejected() {
        let msg = SmallMessage::new(Namespace::Driver.label(1));
        assert_eq!(
            decode_fs_request(&msg),
            Err(DecodeError::WrongNamespace)
        );
    }

    #[test]
    fn version_mismatch_is_rejected() {
        // Hand-build a label with namespace Fs but version 0.
        let bad_label = ((Namespace::Fs as u64) << 56) | (0u64 << 8) | OP_STAT as u64;
        let msg = SmallMessage::from_words(bad_label, &[1]).unwrap();
        assert_eq!(
            decode_fs_request(&msg),
            Err(DecodeError::VersionMismatch)
        );
    }

    #[test]
    fn truncated_payload_is_rejected() {
        let mut msg = SmallMessage::new(Namespace::Fs.label(OP_READ));
        msg.push(1).unwrap(); // only 1 word, Read needs 4
        assert_eq!(decode_fs_request(&msg), Err(DecodeError::Truncated));
    }
}
