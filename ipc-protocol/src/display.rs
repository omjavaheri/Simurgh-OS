//! ============================================================================
//! display.rs
//!
//! Purpose: the compositor's native display protocol at the wire level
//! (03-Kernel-Subsystems-Layer.md §2.4). Deliberately NOT Wayland-derived
//! — the whole point is to carry the capability model up to the UI (§2.4:
//! "پروتکل کاملاً بومی و جدید (نه سازگار با Wayland)").
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.4
//! (`DisplayProtocol` trait: `create_surface`, `commit_buffer`,
//! `destroy_surface`, `input_event_stream`, `output_topology`), §5.4.2
//! (MVP: a client creates a surface, commits a buffer, it is shown
//! zero-copy).
//!
//! Position in the system: encoded into `kernel_ipc::SmallMessage`. The
//! committed frame buffer itself is a `SharedRegion` capability
//! (`buffer_cap`) from GPU memory — never copied through the message
//! (§2.4, §5.2).
//!
//! Safety/invariants: plain integer fields; `Copy`.
//! ============================================================================

/// An opaque per-client surface id, returned by `CreateSurface`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SurfaceHandle(pub u32);

/// A request to the compositor service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayRequest {
    /// Create a new surface for this client. Reply: `SurfaceCreated`.
    CreateSurface,
    /// Present the frame in `buffer_cap` on `surface`. The buffer is a
    /// `SharedRegion` capability (zero-copy, §5.2). `width`/`height` are
    /// in pixels; the pixel format is fixed for the MVP (packed BGRA8).
    /// Reply: `Committed`.
    CommitBuffer {
        /// The target surface.
        surface: SurfaceHandle,
        /// Client capability slot naming the frame `SharedRegion`.
        buffer_cap: u32,
        /// Frame width in pixels.
        width: u32,
        /// Frame height in pixels.
        height: u32,
    },
    /// Destroy `surface` and release its resources. Reply: `Destroyed`.
    DestroySurface {
        /// The surface to destroy.
        surface: SurfaceHandle,
    },
    /// Subscribe this client's connection to the input-event stream
    /// (events then arrive asynchronously via a `Notification`, §2.4).
    /// Reply: `InputSubscribed`.
    SubscribeInput,
    /// Query the output topology (monitor count / resolution / refresh).
    /// Reply: `OutputTopology`.
    QueryOutputs,
    /// Real-input-handling plan (Stage C): a non-blocking check for one
    /// pending real keyboard event — driven by the SAME real i8042
    /// pipeline `SubscribeInput`'s own doc comment above describes as
    /// not-yet-built, but landing this way instead: `driver-i8042`
    /// (`subsystems/drivers/driver-i8042`) pushes real, decoded key
    /// events to Compositor's own internal queue over a dedicated
    /// internal edge (not this wire protocol — that edge is this
    /// driver's own small, locally-scoped shape), and THIS request is
    /// how a real display client (`ui-core`) drains that queue, one
    /// event per call, matching `driver-virtio-net`'s own "unsolicited
    /// external data exposed as a non-blocking poll, not a push"
    /// precedent in this same codebase. Reply: `InputEvent` if one was
    /// pending, `NoInputPending` otherwise (a normal reply, not an
    /// error — matching `SyscallOp::Poll`'s own "0 bits is not a
    /// failure" semantics).
    PollInputEvent,
    /// The mouse-shaped counterpart of `PollInputEvent` — a non-blocking
    /// check for one pending real mouse motion/button event, draining
    /// the same real `driver-mouse` pipeline (`Simurgh-OS`'s own
    /// `subsystems/drivers/driver-mouse`) Compositor's own internal
    /// queue already receives, matching `PollInputEvent`'s own "poll,
    /// not push" shape exactly — a separate request rather than folding
    /// mouse events into `PollInputEvent` itself, since a client needs
    /// to be able to drain keyboard and mouse independently (they queue
    /// at different, unrelated rates). Reply: `MouseEvent` if one was
    /// pending, `NoMouseEventPending` otherwise (a normal reply, not an
    /// error, same reasoning as `PollInputEvent`'s own doc comment).
    PollMouseEvent,
}

/// A reply from the compositor service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayResponse {
    /// `CreateSurface` result.
    SurfaceCreated {
        /// The new surface handle.
        surface: SurfaceHandle,
    },
    /// `CommitBuffer` accepted; the frame will be shown on the next
    /// compositor pass.
    Committed,
    /// `DestroySurface` completed.
    Destroyed,
    /// `SubscribeInput` completed.
    InputSubscribed,
    /// `QueryOutputs` result (single-output MVP: just the primary).
    OutputTopology {
        /// Number of connected outputs.
        output_count: u32,
        /// Primary output width in pixels.
        primary_width: u32,
        /// Primary output height in pixels.
        primary_height: u32,
        /// Primary output refresh rate in milli-Hz (e.g. 60000 = 60 Hz).
        primary_refresh_mhz: u32,
    },
    /// The request failed.
    Error {
        /// Machine-readable error code.
        code: DisplayErrorCode,
    },
    /// `PollInputEvent` found one real, pending key event. `keycode` is
    /// a raw Scan Code Set 1 make code (bit 7 cleared) — see
    /// `driver_i8042::scancode`'s own doc comment (`Simurgh-OS`'s own
    /// `subsystems/drivers/driver-i8042` crate) for the full decode
    /// scope (make/break only, no extended keys, no mouse).
    InputEvent {
        /// Raw Scan Code Set 1 keycode (bit 7 already cleared).
        keycode: u8,
        /// `true` for a key-down (make), `false` for key-up (break).
        pressed: bool,
    },
    /// `PollInputEvent` found nothing pending — a normal reply, not an
    /// error (see `DisplayRequest::PollInputEvent`'s own doc comment).
    NoInputPending,
    /// `PollMouseEvent` found one real, pending mouse packet. `dx`/`dy`
    /// keep PS/2's own raw sign convention (positive `dy` = real upward
    /// motion, unflipped — see `driver_mouse::mouse_packet`'s own doc
    /// comment, `Simurgh-OS`'s own `subsystems/drivers/driver-mouse`
    /// crate); flipping to screen-down-positive, if wanted, is a client
    /// concern.
    MouseEvent {
        /// Raw X delta (PS/2 sign convention).
        dx: i16,
        /// Raw Y delta (PS/2 sign convention: positive = up).
        dy: i16,
        /// Left button held.
        left: bool,
        /// Right button held.
        right: bool,
        /// Middle button held.
        middle: bool,
    },
    /// `PollMouseEvent` found nothing pending — a normal reply, not an
    /// error (see `DisplayRequest::PollMouseEvent`'s own doc comment).
    NoMouseEventPending,
}

/// Compositor error codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayErrorCode {
    /// The surface handle is unknown on this connection.
    BadSurface = 1,
    /// The buffer capability was missing, or its size does not match
    /// `width * height * 4`.
    BadBuffer = 2,
    /// The requested operation is not supported (e.g. in a headless
    /// profile the compositor is not loaded).
    Unsupported = 3,
}
