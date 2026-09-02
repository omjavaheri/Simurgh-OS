//! ============================================================================
//! compositor
//!
//! Purpose: Simurgh's Compositor Service — the shared UI infrastructure
//! layer every Window Manager/DE (layer 5) sits on top of, never the
//! WM/DE itself (03-Kernel-Subsystems-Layer.md §2.4: "یک سرویس Compositor
//! در همین لایه، در برابر Window Managerها/DEها که در لایه ۵ اپلیکیشن
//! هستند"). This MVP form tracks surfaces and accepts committed frames —
//! enough to satisfy §5.4.2 (a client creates a surface, commits a
//! buffer, it is shown zero-copy; headless/file output is explicitly
//! allowed for the MVP) while a real GPU-backed output path is not yet
//! built.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.4 (the
//! `DisplayProtocol` trait this crate's own `ipc_protocol::display`
//! module mirrors at the wire level), §5.4.2 (MVP acceptance).
//!
//! Position in the system: an isolated layer-3 process. Receives real
//! `ipc_protocol::display::DisplayRequest`s and replies
//! `DisplayResponse`. A committed frame's own pixel bytes travel through
//! a `SharedRegion`, never the message (§2.4, §5.2's zero-copy design) —
//! the in-memory store here just tracks WHICH surface is live, the
//! actual buffer bytes are read directly by the request-handling glue in
//! `subsystem_entry`.
//!
//! Safety/invariants: surface handles are dense small integers into a
//! slot table; a destroyed surface never resolves again.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::collections::BTreeMap;

/// Compositor's real process entry point (03-Kernel-Subsystems-Layer.md
/// §2.4/§5.4.2) — see that module's own doc comment. Mirrors `fs_native::
/// subsystem_entry`'s own unconditional module declaration (per-
/// architecture gating lives inside the file, not at this level).
pub mod subsystem_entry;

/// Errors from the surface table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositorError {
    /// The surface handle is unknown (never created, or already
    /// destroyed).
    BadSurface,
}

/// A live surface's own tracked state — just its committed frame
/// dimensions for this MVP (no real damage-tracking/output-scanout
/// state yet).
#[derive(Debug, Clone, Copy, Default)]
pub struct SurfaceState {
    /// Width of the last committed frame, in pixels (`0` before the
    /// first `commit_buffer`).
    pub width: u32,
    /// Height of the last committed frame, in pixels.
    pub height: u32,
    /// How many frames this surface has had committed to it — a cheap
    /// "did commit_buffer ever actually run" proof for tests, distinct
    /// from `width`/`height` staying nonzero (a 0x0 commit is legal per
    /// this MVP's own validation and would otherwise look identical to
    /// "never committed").
    pub commit_count: u32,
}

/// The compositor's own surface table — the pure, host-testable logic
/// behind `subsystem_entry`'s real IPC server loop.
#[derive(Debug, Default)]
pub struct Compositor {
    surfaces: BTreeMap<u32, SurfaceState>,
    next_surface_id: u32,
}

impl Compositor {
    /// A compositor with no surfaces yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new, empty surface and returns its handle.
    pub fn create_surface(&mut self) -> u32 {
        let id = self.next_surface_id;
        self.next_surface_id += 1;
        self.surfaces.insert(id, SurfaceState::default());
        id
    }

    /// Records a committed frame's own dimensions against `surface`.
    /// This MVP has no real damage/scanout tracking — the actual pixel
    /// bytes are read directly out of the shared frame buffer by
    /// `subsystem_entry`'s own request handler, not copied through here.
    pub fn commit_buffer(&mut self, surface: u32, width: u32, height: u32) -> Result<(), CompositorError> {
        let s = self.surfaces.get_mut(&surface).ok_or(CompositorError::BadSurface)?;
        s.width = width;
        s.height = height;
        s.commit_count += 1;
        Ok(())
    }

    /// Destroys `surface`. A destroyed handle never resolves again.
    pub fn destroy_surface(&mut self, surface: u32) -> Result<(), CompositorError> {
        self.surfaces.remove(&surface).map(|_| ()).ok_or(CompositorError::BadSurface)
    }

    /// The tracked state of `surface`, if it still exists — test/
    /// diagnostic access, not an IPC entry point.
    pub fn surface(&self, surface: u32) -> Option<&SurfaceState> {
        self.surfaces.get(&surface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_commit_then_destroy_roundtrips() {
        let mut c = Compositor::new();
        let s = c.create_surface();
        assert_eq!(c.surface(s).unwrap().commit_count, 0);
        c.commit_buffer(s, 2, 2).unwrap();
        assert_eq!(c.surface(s).unwrap().width, 2);
        assert_eq!(c.surface(s).unwrap().height, 2);
        assert_eq!(c.surface(s).unwrap().commit_count, 1);
        c.destroy_surface(s).unwrap();
        assert!(c.surface(s).is_none());
    }

    #[test]
    fn commit_on_unknown_surface_is_bad_surface() {
        let mut c = Compositor::new();
        assert_eq!(c.commit_buffer(99, 1, 1), Err(CompositorError::BadSurface));
    }

    #[test]
    fn destroy_on_unknown_surface_is_bad_surface() {
        let mut c = Compositor::new();
        assert_eq!(c.destroy_surface(99), Err(CompositorError::BadSurface));
    }

    #[test]
    fn destroyed_surface_stops_resolving() {
        let mut c = Compositor::new();
        let s = c.create_surface();
        c.destroy_surface(s).unwrap();
        assert_eq!(c.commit_buffer(s, 1, 1), Err(CompositorError::BadSurface));
    }

    #[test]
    fn surface_ids_are_distinct() {
        let mut c = Compositor::new();
        let a = c.create_surface();
        let b = c.create_surface();
        assert_ne!(a, b);
    }

    #[test]
    fn repeated_commit_increments_count() {
        let mut c = Compositor::new();
        let s = c.create_surface();
        c.commit_buffer(s, 4, 4).unwrap();
        c.commit_buffer(s, 8, 8).unwrap();
        assert_eq!(c.surface(s).unwrap().commit_count, 2);
        assert_eq!(c.surface(s).unwrap().width, 8);
    }
}
