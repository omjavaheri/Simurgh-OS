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
