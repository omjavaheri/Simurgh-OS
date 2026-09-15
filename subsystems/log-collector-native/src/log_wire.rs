//! # log_wire
//!
//! Purpose: the exact byte-level encoding this process's real `Recv`
//! loop speaks — confirmed against `simurgh-diagnostics::diagnostics-
//! manager::wire`'s own, already-complete CLIENT-side mirror (a separate,
//! out-of-tree repo) for the `NextEvent` half of this edge: namespace
//! `202`, protocol version `1`, request opcode `1`, response opcodes `1`
//! (event pending) / `2` (none pending), a `SmallMessage` header (offset
//! `0..56` in the shared page) plus a fixed-layout bulk region starting
//! at [`BULK_OFFSET`] (`64`) for the actual `RawCrashEvent` bytes — that
//! repo's own module doc comment already named this exact layout as
//! "this crate's own first, unilateral proposal ... written so the
//! eventual real Log Collector server-side module has something
//! concrete to confirm or correct against." This module CONFIRMS it,
//! unchanged, for `NextEvent`.
//!
//! `ReportEvent` (opcode `2`, reply opcode `3` = ack) is NEW — the
//! out-of-tree client mirror had no reason to define a server-only
//! opcode before a real server existed to receive it. It reuses the
//! exact same bulk-region layout/offset as `NextEvent`'s own reply, just
//! read instead of written by this server.
//!
//! **This server never parses a single `RawCrashEvent` field.** Unlike
//! `ipc_protocol::fs`/`ipc_protocol::mm` (typed Rust enums this crate's
//! sibling subsystems decode into their own domain structs), this
//! service's whole job is "hold onto events and hand them back in
//! order" — it never inspects `component_id`/`severity`/etc. at all, so
//! there is nothing to gain from parsing them, and real cost (this
//! bulk-region byte layout is `simurgh-diagnostics`'s own free-standing
//! `// TODO(spec)` judgment call, not a stable architecture-doc type —
//! see that repo's `wire.rs` module doc comment) in coupling this
//! server's own correctness to it. [`EventBlob`] is a fixed-size, opaque
//! byte array; [`decode_request`] only ever needs the `SmallMessage`
//! header (its label alone carries the opcode — neither real request
//! variant carries any other payload word).
//!
//! Position in the system: this crate is the SERVER for this edge —
//! opposite role from `simurgh-diagnostics::wire`, which is the CLIENT
//! (that module's own doc comment).
//!
//! Safety/invariants: no `unsafe`; plain integer/byte-slice operations.

use kernel_ipc::SmallMessage;

const NAMESPACE_LOG_COLLECTOR: u8 = 202;
const PROTOCOL_VERSION: u16 = 1;

const OP_LC_NEXT_EVENT: u8 = 1;
/// New — see this module's own doc comment.
const OP_LC_REPORT_EVENT: u8 = 2;

const OP_LCR_EVENT: u8 = 1;
const OP_LCR_NONE: u8 = 2;
/// New — see this module's own doc comment.
const OP_LCR_ACK: u8 = 3;

/// Confirmed mirror of `simurgh-diagnostics::diagnostics-manager::wire::
/// LC_BULK_OFFSET`.
pub const BULK_OFFSET: usize = 64;
/// Confirmed mirror of `simurgh-diagnostics::diagnostics-manager::wire::
/// LC_BULK_TOTAL_SIZE`.
pub const BULK_TOTAL_SIZE: usize = 320;

/// One opaque, fixed-size event record — this module's own doc comment
/// explains why this server never decodes it into named fields.
pub type EventBlob = [u8; BULK_TOTAL_SIZE];

fn label(opcode: u8) -> u64 {
    ((NAMESPACE_LOG_COLLECTOR as u64) << 56) | ((PROTOCOL_VERSION as u64) << 8) | (opcode as u64)
}

fn label_parts(l: u64) -> (u8, u16, u8) {
    (((l >> 56) & 0xFF) as u8, ((l >> 8) & 0xFFFF) as u16, (l & 0xFF) as u8)
}

/// A decoded request — this server's own two real opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LcRequest {
    NextEvent,
    ReportEvent,
}

/// Decodes one incoming request's `SmallMessage` header. `None` for a
/// message this server does not recognize (wrong namespace, wrong
/// version, or an opcode neither real request uses) — the caller
/// (`subsystem_entry::handle_request`) treats this the same as any other
/// malformed input: reply `NoEvent`/ignore, never panic (this project's
/// "tolerant of a bad peer" convention every other real IPC server here
/// already follows).
pub fn decode_request(msg: &SmallMessage) -> Option<LcRequest> {
    let (ns, version, op) = label_parts(msg.label);
    if ns != NAMESPACE_LOG_COLLECTOR || version != PROTOCOL_VERSION {
        return None;
    }
    match op {
        OP_LC_NEXT_EVENT => Some(LcRequest::NextEvent),
        OP_LC_REPORT_EVENT => Some(LcRequest::ReportEvent),
        _ => None,
    }
}

/// Encodes `NextEvent`'s "one was pending" reply — the bulk region
/// itself is written separately (the caller already has the raw
/// [`EventBlob`] bytes to copy; this function only ever builds the
/// small header).
pub fn encode_event_response() -> SmallMessage {
    SmallMessage::new(label(OP_LCR_EVENT))
}

/// Encodes `NextEvent`'s "nothing pending" reply.
pub fn encode_none_response() -> SmallMessage {
    SmallMessage::new(label(OP_LCR_NONE))
}

/// Encodes `ReportEvent`'s ack reply.
pub fn encode_ack_response() -> SmallMessage {
    SmallMessage::new(label(OP_LCR_ACK))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_event_request_decodes() {
        let msg = SmallMessage::new(label(OP_LC_NEXT_EVENT));
        assert_eq!(decode_request(&msg), Some(LcRequest::NextEvent));
    }

    #[test]
    fn report_event_request_decodes() {
        let msg = SmallMessage::new(label(OP_LC_REPORT_EVENT));
        assert_eq!(decode_request(&msg), Some(LcRequest::ReportEvent));
    }

    #[test]
    fn wrong_namespace_is_rejected() {
        let msg = SmallMessage::new(0);
        assert_eq!(decode_request(&msg), None);
    }

    #[test]
    fn unknown_opcode_is_rejected() {
        let msg = SmallMessage::new(label(99));
        assert_eq!(decode_request(&msg), None);
    }

    #[test]
    fn event_response_carries_the_confirmed_opcode() {
        let (ns, version, op) = label_parts(encode_event_response().label);
        assert_eq!((ns, version, op), (NAMESPACE_LOG_COLLECTOR, PROTOCOL_VERSION, OP_LCR_EVENT));
    }

    #[test]
    fn none_response_carries_the_confirmed_opcode() {
        let (_, _, op) = label_parts(encode_none_response().label);
        assert_eq!(op, OP_LCR_NONE);
    }

    #[test]
    fn ack_response_carries_its_own_new_opcode() {
        let (_, _, op) = label_parts(encode_ack_response().label);
        assert_eq!(op, OP_LCR_ACK);
    }
}
