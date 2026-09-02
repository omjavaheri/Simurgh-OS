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
//! module implements the `FsRequest`/`FsResponse` codec in full as the
//! reference (`FsResponse` used for real by the fs-native process —
//! 03-Kernel-Subsystems-Layer.md §2.2, §5.3), and the `DriverRequest`/
//! `DriverResponse` codec (used by the real Device Manager ↔ driver
//! process IPC — §2.1, §5.2) the identical way; the remaining namespaces
//! follow the same pattern and are a mechanical follow-up (their
//! opcodes/labels are already defined).
//!
//! Safety/invariants: `decode_*` is total — it returns `DecodeError` for a
//! bad version, an unknown opcode, or a truncated payload, and never
//! panics.
//! ============================================================================

use crate::display::{DisplayErrorCode, DisplayRequest, DisplayResponse, SurfaceHandle};
use crate::driver::{DriverErrorCode, DriverRequest, DriverResponse};
use crate::fs::{FileHandle, FsErrorCode, FsRequest, FsResponse, OpenFlags, PathId};
use crate::mm::{MmErrorCode, MmRequest, MmResponse, ReclaimClass};
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

// FsResponse opcodes — a separate small sequence from the FsRequest
// opcodes above; the two are never decoded by the same function (each
// side of the IPC knows which direction a given message is), so the
// numbers may overlap in principle, but are kept sequential-and-distinct
// here for readability when reading a raw trace — same convention
// `OP_DRR_*` below uses relative to `OP_DR_*`.
const OP_FR_OPENED: u8 = 1;
const OP_FR_READ: u8 = 2;
const OP_FR_WRITTEN: u8 = 3;
const OP_FR_STAT: u8 = 4;
const OP_FR_CLOSED: u8 = 5;
const OP_FR_ERROR: u8 = 6;

/// Encodes a `FsResponse` into a `SmallMessage`.
///
/// Word layout by variant:
/// - `Opened`: `[handle]`
/// - `Read`: `[bytes]`
/// - `Written`: `[bytes]`
/// - `Stat`: `[size, is_dir]`
/// - `Closed`: `[]`
/// - `Error`: `[code]`
pub fn encode_fs_response(resp: &FsResponse) -> SmallMessage {
    let (op, words): (u8, [u64; 2]) = match *resp {
        FsResponse::Opened { handle } => (OP_FR_OPENED, [handle.0 as u64, 0]),
        FsResponse::Read { bytes } => (OP_FR_READ, [bytes as u64, 0]),
        FsResponse::Written { bytes } => (OP_FR_WRITTEN, [bytes as u64, 0]),
        FsResponse::Stat { size, is_dir } => (OP_FR_STAT, [size, is_dir as u64]),
        FsResponse::Closed => (OP_FR_CLOSED, [0, 0]),
        FsResponse::Error { code } => (OP_FR_ERROR, [code as u64, 0]),
    };
    let n = if op == OP_FR_STAT {
        2
    } else if op == OP_FR_CLOSED {
        0
    } else {
        1
    };
    // `from_words` cannot fail here: n <= 2 <= MSG_MAX_WORDS.
    SmallMessage::from_words(Namespace::Fs.label(op), &words[..n])
        .unwrap_or_else(|_| SmallMessage::new(Namespace::Fs.label(op)))
}

/// Decodes a `FsResponse` from a `SmallMessage`.
pub fn decode_fs_response(msg: &SmallMessage) -> Result<FsResponse, DecodeError> {
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
        OP_FR_OPENED => {
            need(1)?;
            Ok(FsResponse::Opened {
                handle: FileHandle(w[0] as u32),
            })
        }
        OP_FR_READ => {
            need(1)?;
            Ok(FsResponse::Read { bytes: w[0] as u32 })
        }
        OP_FR_WRITTEN => {
            need(1)?;
            Ok(FsResponse::Written { bytes: w[0] as u32 })
        }
        OP_FR_STAT => {
            need(2)?;
            Ok(FsResponse::Stat {
                size: w[0],
                is_dir: w[1] != 0,
            })
        }
        OP_FR_CLOSED => Ok(FsResponse::Closed),
        OP_FR_ERROR => {
            need(1)?;
            let code = match w[0] {
                1 => FsErrorCode::NotFound,
                2 => FsErrorCode::Denied,
                3 => FsErrorCode::BadHandle,
                4 => FsErrorCode::BadPath,
                5 => FsErrorCode::Unsupported,
                6 => FsErrorCode::BadSharedRegion,
                7 => FsErrorCode::Io,
                _ => return Err(DecodeError::BadField),
            };
            Ok(FsResponse::Error { code })
        }
        _ => Err(DecodeError::UnknownOpcode),
    }
}

// DriverRequest opcodes (low byte of the label).
const OP_DR_PROBE: u8 = 1;
const OP_DR_IRQ: u8 = 2;
const OP_DR_READ_BLOCKS: u8 = 3;
const OP_DR_WRITE_BLOCKS: u8 = 4;
const OP_DR_QUIESCE: u8 = 5;
const OP_DR_SEND_FRAME: u8 = 6;
const OP_DR_POLL_FRAME: u8 = 7;

/// Encodes a `DriverRequest` into a `SmallMessage`.
///
/// Word layout by variant:
/// - `Probe`, `Quiesce`, `PollFrame`: `[]`
/// - `Irq`: `[line]`
/// - `ReadBlocks` / `WriteBlocks`: `[lba, sector_count, shared_cap]`
/// - `SendFrame`: `[len]`
pub fn encode_driver_request(req: &DriverRequest) -> SmallMessage {
    let (op, words): (u8, [u64; 3]) = match *req {
        DriverRequest::Probe => (OP_DR_PROBE, [0, 0, 0]),
        DriverRequest::Irq { line } => (OP_DR_IRQ, [line as u64, 0, 0]),
        DriverRequest::ReadBlocks {
            lba,
            sector_count,
            shared_cap,
        } => (
            OP_DR_READ_BLOCKS,
            [lba, sector_count as u64, shared_cap as u64],
        ),
        DriverRequest::WriteBlocks {
            lba,
            sector_count,
            shared_cap,
        } => (
            OP_DR_WRITE_BLOCKS,
            [lba, sector_count as u64, shared_cap as u64],
        ),
        DriverRequest::Quiesce => (OP_DR_QUIESCE, [0, 0, 0]),
        DriverRequest::SendFrame { len } => (OP_DR_SEND_FRAME, [len as u64, 0, 0]),
        DriverRequest::PollFrame => (OP_DR_POLL_FRAME, [0, 0, 0]),
    };
    let n = match op {
        OP_DR_IRQ | OP_DR_SEND_FRAME => 1,
        OP_DR_READ_BLOCKS | OP_DR_WRITE_BLOCKS => 3,
        _ => 0,
    };
    // `from_words` cannot fail here: n <= 3 <= MSG_MAX_WORDS.
    SmallMessage::from_words(Namespace::Driver.label(op), &words[..n])
        .unwrap_or_else(|_| SmallMessage::new(Namespace::Driver.label(op)))
}

/// Decodes a `DriverRequest` from a `SmallMessage`.
pub fn decode_driver_request(msg: &SmallMessage) -> Result<DriverRequest, DecodeError> {
    match Namespace::from_label(msg.label) {
        Some(Namespace::Driver) => {}
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
        OP_DR_PROBE => Ok(DriverRequest::Probe),
        OP_DR_IRQ => {
            need(1)?;
            Ok(DriverRequest::Irq { line: w[0] as u32 })
        }
        OP_DR_READ_BLOCKS => {
            need(3)?;
            Ok(DriverRequest::ReadBlocks {
                lba: w[0],
                sector_count: w[1] as u32,
                shared_cap: w[2] as u32,
            })
        }
        OP_DR_WRITE_BLOCKS => {
            need(3)?;
            Ok(DriverRequest::WriteBlocks {
                lba: w[0],
                sector_count: w[1] as u32,
                shared_cap: w[2] as u32,
            })
        }
        OP_DR_QUIESCE => Ok(DriverRequest::Quiesce),
        OP_DR_SEND_FRAME => {
            need(1)?;
            Ok(DriverRequest::SendFrame { len: w[0] as u32 })
        }
        OP_DR_POLL_FRAME => Ok(DriverRequest::PollFrame),
        _ => Err(DecodeError::UnknownOpcode),
    }
}

// DriverResponse opcodes — a separate small sequence from the request
// opcodes above; the two are never decoded by the same function (each
// side of the IPC knows which direction a given message is), so the
// numbers may overlap in principle, but are kept sequential-and-distinct
// here for readability when reading a raw trace.
const OP_DRR_READY: u8 = 1;
const OP_DRR_COMPLETED: u8 = 2;
const OP_DRR_FAILED: u8 = 3;
const OP_DRR_FRAME_SENT: u8 = 4;
const OP_DRR_FRAME_RECEIVED: u8 = 5;

/// Encodes a `DriverResponse` into a `SmallMessage`.
///
/// Word layout by variant:
/// - `Ready`: `[sector_size, sector_count]`
/// - `Completed`: `[sectors]`
/// - `Failed`: `[code]`
/// - `FrameSent`: `[]`
/// - `FrameReceived`: `[len]`
pub fn encode_driver_response(resp: &DriverResponse) -> SmallMessage {
    let (op, words): (u8, [u64; 2]) = match *resp {
        DriverResponse::Ready {
            sector_size,
            sector_count,
        } => (OP_DRR_READY, [sector_size as u64, sector_count]),
        DriverResponse::Completed { sectors } => (OP_DRR_COMPLETED, [sectors as u64, 0]),
        DriverResponse::Failed { code } => (OP_DRR_FAILED, [code as u64, 0]),
        DriverResponse::FrameSent => (OP_DRR_FRAME_SENT, [0, 0]),
        DriverResponse::FrameReceived { len } => (OP_DRR_FRAME_RECEIVED, [len as u64, 0]),
    };
    let n = if op == OP_DRR_READY { 2 } else if op == OP_DRR_FRAME_SENT { 0 } else { 1 };
    // `from_words` cannot fail here: n <= 2 <= MSG_MAX_WORDS.
    SmallMessage::from_words(Namespace::Driver.label(op), &words[..n])
        .unwrap_or_else(|_| SmallMessage::new(Namespace::Driver.label(op)))
}

/// Decodes a `DriverResponse` from a `SmallMessage`.
pub fn decode_driver_response(msg: &SmallMessage) -> Result<DriverResponse, DecodeError> {
    match Namespace::from_label(msg.label) {
        Some(Namespace::Driver) => {}
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
        OP_DRR_READY => {
            need(2)?;
            Ok(DriverResponse::Ready {
                sector_size: w[0] as u32,
                sector_count: w[1],
            })
        }
        OP_DRR_COMPLETED => {
            need(1)?;
            Ok(DriverResponse::Completed {
                sectors: w[0] as u32,
            })
        }
        OP_DRR_FAILED => {
            need(1)?;
            let code = match w[0] {
                1 => DriverErrorCode::ProbeFailed,
                2 => DriverErrorCode::OutOfRange,
                3 => DriverErrorCode::BadSharedRegion,
                4 => DriverErrorCode::DeviceIo,
                5 => DriverErrorCode::Unsupported,
                6 => DriverErrorCode::NoData,
                _ => return Err(DecodeError::BadField),
            };
            Ok(DriverResponse::Failed { code })
        }
        OP_DRR_FRAME_SENT => Ok(DriverResponse::FrameSent),
        OP_DRR_FRAME_RECEIVED => {
            need(1)?;
            Ok(DriverResponse::FrameReceived { len: w[0] as u32 })
        }
        _ => Err(DecodeError::UnknownOpcode),
    }
}

// DisplayRequest opcodes (low byte of the label).
const OP_DP_CREATE_SURFACE: u8 = 1;
const OP_DP_COMMIT_BUFFER: u8 = 2;
const OP_DP_DESTROY_SURFACE: u8 = 3;
const OP_DP_SUBSCRIBE_INPUT: u8 = 4;
const OP_DP_QUERY_OUTPUTS: u8 = 5;

/// Encodes a `DisplayRequest` into a `SmallMessage`.
///
/// Word layout by variant:
/// - `CreateSurface`, `SubscribeInput`, `QueryOutputs`: `[]`
/// - `CommitBuffer`: `[surface, buffer_cap, width, height]`
/// - `DestroySurface`: `[surface]`
pub fn encode_display_request(req: &DisplayRequest) -> SmallMessage {
    let (op, words): (u8, [u64; 4]) = match *req {
        DisplayRequest::CreateSurface => (OP_DP_CREATE_SURFACE, [0, 0, 0, 0]),
        DisplayRequest::CommitBuffer {
            surface,
            buffer_cap,
            width,
            height,
        } => (
            OP_DP_COMMIT_BUFFER,
            [surface.0 as u64, buffer_cap as u64, width as u64, height as u64],
        ),
        DisplayRequest::DestroySurface { surface } => (OP_DP_DESTROY_SURFACE, [surface.0 as u64, 0, 0, 0]),
        DisplayRequest::SubscribeInput => (OP_DP_SUBSCRIBE_INPUT, [0, 0, 0, 0]),
        DisplayRequest::QueryOutputs => (OP_DP_QUERY_OUTPUTS, [0, 0, 0, 0]),
    };
    let n = match op {
        OP_DP_COMMIT_BUFFER => 4,
        OP_DP_DESTROY_SURFACE => 1,
        _ => 0,
    };
    // `from_words` cannot fail here: n <= 4 <= MSG_MAX_WORDS.
    SmallMessage::from_words(Namespace::Display.label(op), &words[..n])
        .unwrap_or_else(|_| SmallMessage::new(Namespace::Display.label(op)))
}

/// Decodes a `DisplayRequest` from a `SmallMessage`.
pub fn decode_display_request(msg: &SmallMessage) -> Result<DisplayRequest, DecodeError> {
    match Namespace::from_label(msg.label) {
        Some(Namespace::Display) => {}
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
        OP_DP_CREATE_SURFACE => Ok(DisplayRequest::CreateSurface),
        OP_DP_COMMIT_BUFFER => {
            need(4)?;
            Ok(DisplayRequest::CommitBuffer {
                surface: SurfaceHandle(w[0] as u32),
                buffer_cap: w[1] as u32,
                width: w[2] as u32,
                height: w[3] as u32,
            })
        }
        OP_DP_DESTROY_SURFACE => {
            need(1)?;
            Ok(DisplayRequest::DestroySurface {
                surface: SurfaceHandle(w[0] as u32),
            })
        }
        OP_DP_SUBSCRIBE_INPUT => Ok(DisplayRequest::SubscribeInput),
        OP_DP_QUERY_OUTPUTS => Ok(DisplayRequest::QueryOutputs),
        _ => Err(DecodeError::UnknownOpcode),
    }
}

// DisplayResponse opcodes — a separate small sequence from the request
// opcodes above, same "kept sequential-and-distinct for readability"
// convention every other namespace here already follows.
const OP_DPR_SURFACE_CREATED: u8 = 1;
const OP_DPR_COMMITTED: u8 = 2;
const OP_DPR_DESTROYED: u8 = 3;
const OP_DPR_INPUT_SUBSCRIBED: u8 = 4;
const OP_DPR_OUTPUT_TOPOLOGY: u8 = 5;
const OP_DPR_ERROR: u8 = 6;

/// Encodes a `DisplayResponse` into a `SmallMessage`.
///
/// Word layout by variant:
/// - `SurfaceCreated`: `[surface]`
/// - `Committed`, `Destroyed`, `InputSubscribed`: `[]`
/// - `OutputTopology`: `[output_count, primary_width, primary_height, primary_refresh_mhz]`
/// - `Error`: `[code]`
pub fn encode_display_response(resp: &DisplayResponse) -> SmallMessage {
    let (op, words): (u8, [u64; 4]) = match *resp {
        DisplayResponse::SurfaceCreated { surface } => (OP_DPR_SURFACE_CREATED, [surface.0 as u64, 0, 0, 0]),
        DisplayResponse::Committed => (OP_DPR_COMMITTED, [0, 0, 0, 0]),
        DisplayResponse::Destroyed => (OP_DPR_DESTROYED, [0, 0, 0, 0]),
        DisplayResponse::InputSubscribed => (OP_DPR_INPUT_SUBSCRIBED, [0, 0, 0, 0]),
        DisplayResponse::OutputTopology {
            output_count,
            primary_width,
            primary_height,
            primary_refresh_mhz,
        } => (
            OP_DPR_OUTPUT_TOPOLOGY,
            [
                output_count as u64,
                primary_width as u64,
                primary_height as u64,
                primary_refresh_mhz as u64,
            ],
        ),
        DisplayResponse::Error { code } => (OP_DPR_ERROR, [code as u64, 0, 0, 0]),
    };
    let n = match op {
        OP_DPR_OUTPUT_TOPOLOGY => 4,
        OP_DPR_SURFACE_CREATED | OP_DPR_ERROR => 1,
        _ => 0,
    };
    // `from_words` cannot fail here: n <= 4 <= MSG_MAX_WORDS.
    SmallMessage::from_words(Namespace::Display.label(op), &words[..n])
        .unwrap_or_else(|_| SmallMessage::new(Namespace::Display.label(op)))
}

/// Decodes a `DisplayResponse` from a `SmallMessage`.
pub fn decode_display_response(msg: &SmallMessage) -> Result<DisplayResponse, DecodeError> {
    match Namespace::from_label(msg.label) {
        Some(Namespace::Display) => {}
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
        OP_DPR_SURFACE_CREATED => {
            need(1)?;
            Ok(DisplayResponse::SurfaceCreated {
                surface: SurfaceHandle(w[0] as u32),
            })
        }
        OP_DPR_COMMITTED => Ok(DisplayResponse::Committed),
        OP_DPR_DESTROYED => Ok(DisplayResponse::Destroyed),
        OP_DPR_INPUT_SUBSCRIBED => Ok(DisplayResponse::InputSubscribed),
        OP_DPR_OUTPUT_TOPOLOGY => {
            need(4)?;
            Ok(DisplayResponse::OutputTopology {
                output_count: w[0] as u32,
                primary_width: w[1] as u32,
                primary_height: w[2] as u32,
                primary_refresh_mhz: w[3] as u32,
            })
        }
        OP_DPR_ERROR => {
            need(1)?;
            let code = match w[0] {
                1 => DisplayErrorCode::BadSurface,
                2 => DisplayErrorCode::BadBuffer,
                3 => DisplayErrorCode::Unsupported,
                _ => return Err(DecodeError::BadField),
            };
            Ok(DisplayResponse::Error { code })
        }
        _ => Err(DecodeError::UnknownOpcode),
    }
}

// MmRequest opcodes (low byte of the label).
const OP_MM_REGISTER: u8 = 1;
const OP_MM_UNREGISTER: u8 = 2;
const OP_MM_QUERY_VICTIM: u8 = 3;
const OP_MM_QUERY_TOTAL_RESIDENT: u8 = 4;

/// Encodes an `MmRequest` into a `SmallMessage`.
///
/// Word layout by variant:
/// - `Register`: `[thread, resident_bytes, class]`
/// - `Unregister`: `[thread]`
/// - `QueryVictim`, `QueryTotalResident`: `[]`
pub fn encode_mm_request(req: &MmRequest) -> SmallMessage {
    let (op, words): (u8, [u64; 3]) = match *req {
        MmRequest::Register {
            thread,
            resident_bytes,
            class,
        } => (OP_MM_REGISTER, [thread as u64, resident_bytes, class as u64]),
        MmRequest::Unregister { thread } => (OP_MM_UNREGISTER, [thread as u64, 0, 0]),
        MmRequest::QueryVictim => (OP_MM_QUERY_VICTIM, [0, 0, 0]),
        MmRequest::QueryTotalResident => (OP_MM_QUERY_TOTAL_RESIDENT, [0, 0, 0]),
    };
    let n = match op {
        OP_MM_REGISTER => 3,
        OP_MM_UNREGISTER => 1,
        _ => 0,
    };
    // `from_words` cannot fail here: n <= 3 <= MSG_MAX_WORDS.
    SmallMessage::from_words(Namespace::Mm.label(op), &words[..n])
        .unwrap_or_else(|_| SmallMessage::new(Namespace::Mm.label(op)))
}

/// Decodes an `MmRequest` from a `SmallMessage`.
pub fn decode_mm_request(msg: &SmallMessage) -> Result<MmRequest, DecodeError> {
    match Namespace::from_label(msg.label) {
        Some(Namespace::Mm) => {}
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
        OP_MM_REGISTER => {
            need(3)?;
            let class = match w[2] {
                0 => ReclaimClass::Protected,
                1 => ReclaimClass::Normal,
                2 => ReclaimClass::Sacrificial,
                _ => return Err(DecodeError::BadField),
            };
            Ok(MmRequest::Register {
                thread: w[0] as u32,
                resident_bytes: w[1],
                class,
            })
        }
        OP_MM_UNREGISTER => {
            need(1)?;
            Ok(MmRequest::Unregister { thread: w[0] as u32 })
        }
        OP_MM_QUERY_VICTIM => Ok(MmRequest::QueryVictim),
        OP_MM_QUERY_TOTAL_RESIDENT => Ok(MmRequest::QueryTotalResident),
        _ => Err(DecodeError::UnknownOpcode),
    }
}

// MmResponse opcodes — a separate small sequence from the request
// opcodes above, same "kept sequential-and-distinct for readability"
// convention every other namespace here already follows.
const OP_MMR_REGISTERED: u8 = 1;
const OP_MMR_UNREGISTERED: u8 = 2;
const OP_MMR_VICTIM: u8 = 3;
const OP_MMR_TOTAL_RESIDENT: u8 = 4;
const OP_MMR_ERROR: u8 = 5;

/// Encodes an `MmResponse` into a `SmallMessage`.
///
/// Word layout by variant:
/// - `Registered`, `Unregistered`: `[]`
/// - `Victim`: `[thread]`
/// - `TotalResident`: `[bytes]`
/// - `Error`: `[code]`
pub fn encode_mm_response(resp: &MmResponse) -> SmallMessage {
    let (op, words): (u8, [u64; 1]) = match *resp {
        MmResponse::Registered => (OP_MMR_REGISTERED, [0]),
        MmResponse::Unregistered => (OP_MMR_UNREGISTERED, [0]),
        MmResponse::Victim { thread } => (OP_MMR_VICTIM, [thread as u64]),
        MmResponse::TotalResident { bytes } => (OP_MMR_TOTAL_RESIDENT, [bytes]),
        MmResponse::Error { code } => (OP_MMR_ERROR, [code as u64]),
    };
    let n = match op {
        OP_MMR_REGISTERED | OP_MMR_UNREGISTERED => 0,
        _ => 1,
    };
    // `from_words` cannot fail here: n <= 1 <= MSG_MAX_WORDS.
    SmallMessage::from_words(Namespace::Mm.label(op), &words[..n])
        .unwrap_or_else(|_| SmallMessage::new(Namespace::Mm.label(op)))
}

/// Decodes an `MmResponse` from a `SmallMessage`.
pub fn decode_mm_response(msg: &SmallMessage) -> Result<MmResponse, DecodeError> {
    match Namespace::from_label(msg.label) {
        Some(Namespace::Mm) => {}
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
        OP_MMR_REGISTERED => Ok(MmResponse::Registered),
        OP_MMR_UNREGISTERED => Ok(MmResponse::Unregistered),
        OP_MMR_VICTIM => {
            need(1)?;
            Ok(MmResponse::Victim { thread: w[0] as u32 })
        }
        OP_MMR_TOTAL_RESIDENT => {
            need(1)?;
            Ok(MmResponse::TotalResident { bytes: w[0] })
        }
        OP_MMR_ERROR => {
            need(1)?;
            let code = match w[0] {
                1 => MmErrorCode::Unsupported,
                _ => return Err(DecodeError::BadField),
            };
            Ok(MmResponse::Error { code })
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

    fn fs_response_roundtrip(resp: FsResponse) {
        let msg = encode_fs_response(&resp);
        assert_eq!(decode_fs_response(&msg), Ok(resp));
    }

    #[test]
    fn all_fs_response_variants_roundtrip() {
        fs_response_roundtrip(FsResponse::Opened {
            handle: FileHandle(3),
        });
        fs_response_roundtrip(FsResponse::Read { bytes: 512 });
        fs_response_roundtrip(FsResponse::Written { bytes: 128 });
        fs_response_roundtrip(FsResponse::Stat {
            size: 4096,
            is_dir: false,
        });
        fs_response_roundtrip(FsResponse::Stat {
            size: 0,
            is_dir: true,
        });
        fs_response_roundtrip(FsResponse::Closed);
        fs_response_roundtrip(FsResponse::Error {
            code: FsErrorCode::NotFound,
        });
    }

    #[test]
    fn fs_response_wrong_namespace_is_rejected() {
        let msg = SmallMessage::new(Namespace::Driver.label(OP_FR_OPENED));
        assert_eq!(
            decode_fs_response(&msg),
            Err(DecodeError::WrongNamespace)
        );
    }

    #[test]
    fn fs_response_bad_field_is_rejected() {
        let msg = SmallMessage::from_words(Namespace::Fs.label(OP_FR_ERROR), &[99]).unwrap();
        assert_eq!(decode_fs_response(&msg), Err(DecodeError::BadField));
    }

    fn driver_request_roundtrip(req: DriverRequest) {
        let msg = encode_driver_request(&req);
        assert_eq!(decode_driver_request(&msg), Ok(req));
    }

    #[test]
    fn all_driver_request_variants_roundtrip() {
        driver_request_roundtrip(DriverRequest::Probe);
        driver_request_roundtrip(DriverRequest::Irq { line: 5 });
        driver_request_roundtrip(DriverRequest::ReadBlocks {
            lba: 4096,
            sector_count: 8,
            shared_cap: 3,
        });
        driver_request_roundtrip(DriverRequest::WriteBlocks {
            lba: 0,
            sector_count: 1,
            shared_cap: 9,
        });
        driver_request_roundtrip(DriverRequest::Quiesce);
        driver_request_roundtrip(DriverRequest::SendFrame { len: 60 });
        driver_request_roundtrip(DriverRequest::PollFrame);
    }

    fn driver_response_roundtrip(resp: DriverResponse) {
        let msg = encode_driver_response(&resp);
        assert_eq!(decode_driver_response(&msg), Ok(resp));
    }

    #[test]
    fn all_driver_response_variants_roundtrip() {
        driver_response_roundtrip(DriverResponse::Ready {
            sector_size: 512,
            sector_count: 2048,
        });
        driver_response_roundtrip(DriverResponse::Completed { sectors: 8 });
        driver_response_roundtrip(DriverResponse::Failed {
            code: DriverErrorCode::DeviceIo,
        });
        driver_response_roundtrip(DriverResponse::Failed {
            code: DriverErrorCode::NoData,
        });
        driver_response_roundtrip(DriverResponse::FrameSent);
        driver_response_roundtrip(DriverResponse::FrameReceived { len: 60 });
    }

    #[test]
    fn driver_request_wrong_namespace_is_rejected() {
        let msg = SmallMessage::new(Namespace::Fs.label(OP_DR_PROBE));
        assert_eq!(
            decode_driver_request(&msg),
            Err(DecodeError::WrongNamespace)
        );
    }

    #[test]
    fn driver_response_bad_field_is_rejected() {
        let msg = SmallMessage::from_words(Namespace::Driver.label(OP_DRR_FAILED), &[99]).unwrap();
        assert_eq!(decode_driver_response(&msg), Err(DecodeError::BadField));
    }

    fn display_request_roundtrip(req: DisplayRequest) {
        let msg = encode_display_request(&req);
        assert_eq!(decode_display_request(&msg), Ok(req));
    }

    #[test]
    fn all_display_request_variants_roundtrip() {
        display_request_roundtrip(DisplayRequest::CreateSurface);
        display_request_roundtrip(DisplayRequest::CommitBuffer {
            surface: SurfaceHandle(2),
            buffer_cap: 5,
            width: 1920,
            height: 1080,
        });
        display_request_roundtrip(DisplayRequest::DestroySurface {
            surface: SurfaceHandle(2),
        });
        display_request_roundtrip(DisplayRequest::SubscribeInput);
        display_request_roundtrip(DisplayRequest::QueryOutputs);
    }

    fn display_response_roundtrip(resp: DisplayResponse) {
        let msg = encode_display_response(&resp);
        assert_eq!(decode_display_response(&msg), Ok(resp));
    }

    #[test]
    fn all_display_response_variants_roundtrip() {
        display_response_roundtrip(DisplayResponse::SurfaceCreated {
            surface: SurfaceHandle(2),
        });
        display_response_roundtrip(DisplayResponse::Committed);
        display_response_roundtrip(DisplayResponse::Destroyed);
        display_response_roundtrip(DisplayResponse::InputSubscribed);
        display_response_roundtrip(DisplayResponse::OutputTopology {
            output_count: 1,
            primary_width: 1920,
            primary_height: 1080,
            primary_refresh_mhz: 60000,
        });
        display_response_roundtrip(DisplayResponse::Error {
            code: DisplayErrorCode::BadBuffer,
        });
    }

    #[test]
    fn display_request_wrong_namespace_is_rejected() {
        let msg = SmallMessage::new(Namespace::Fs.label(OP_DP_CREATE_SURFACE));
        assert_eq!(
            decode_display_request(&msg),
            Err(DecodeError::WrongNamespace)
        );
    }

    #[test]
    fn display_response_bad_field_is_rejected() {
        let msg = SmallMessage::from_words(Namespace::Display.label(OP_DPR_ERROR), &[99]).unwrap();
        assert_eq!(decode_display_response(&msg), Err(DecodeError::BadField));
    }

    #[test]
    fn display_request_truncated_payload_is_rejected() {
        let msg = SmallMessage::new(Namespace::Display.label(OP_DP_COMMIT_BUFFER));
        assert_eq!(
            decode_display_request(&msg),
            Err(DecodeError::Truncated)
        );
    }

    fn mm_request_roundtrip(req: MmRequest) {
        let msg = encode_mm_request(&req);
        assert_eq!(decode_mm_request(&msg), Ok(req));
    }

    #[test]
    fn all_mm_request_variants_roundtrip() {
        mm_request_roundtrip(MmRequest::Register {
            thread: 3,
            resident_bytes: 4096,
            class: ReclaimClass::Sacrificial,
        });
        mm_request_roundtrip(MmRequest::Unregister { thread: 3 });
        mm_request_roundtrip(MmRequest::QueryVictim);
        mm_request_roundtrip(MmRequest::QueryTotalResident);
    }

    fn mm_response_roundtrip(resp: MmResponse) {
        let msg = encode_mm_response(&resp);
        assert_eq!(decode_mm_response(&msg), Ok(resp));
    }

    #[test]
    fn all_mm_response_variants_roundtrip() {
        mm_response_roundtrip(MmResponse::Registered);
        mm_response_roundtrip(MmResponse::Unregistered);
        mm_response_roundtrip(MmResponse::Victim { thread: 7 });
        mm_response_roundtrip(MmResponse::Victim { thread: u32::MAX });
        mm_response_roundtrip(MmResponse::TotalResident { bytes: 123456 });
        mm_response_roundtrip(MmResponse::Error {
            code: MmErrorCode::Unsupported,
        });
    }

    #[test]
    fn mm_request_wrong_namespace_is_rejected() {
        let msg = SmallMessage::new(Namespace::Fs.label(OP_MM_QUERY_VICTIM));
        assert_eq!(decode_mm_request(&msg), Err(DecodeError::WrongNamespace));
    }

    #[test]
    fn mm_request_bad_field_is_rejected() {
        let msg = SmallMessage::from_words(Namespace::Mm.label(OP_MM_REGISTER), &[1, 2, 99]).unwrap();
        assert_eq!(decode_mm_request(&msg), Err(DecodeError::BadField));
    }

    #[test]
    fn mm_response_truncated_payload_is_rejected() {
        let msg = SmallMessage::new(Namespace::Mm.label(OP_MMR_VICTIM));
        assert_eq!(decode_mm_response(&msg), Err(DecodeError::Truncated));
    }
}
