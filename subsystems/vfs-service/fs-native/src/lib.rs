//! ============================================================================
//! fs-native
//!
//! Purpose: Simurgh's own filesystem service. The long-term design is a
//! copy-on-write, checksummed, Rust-native filesystem
//! (03-Kernel-Subsystems-Layer.md §2.2). This MVP form is a small
//! in-memory filesystem — enough to satisfy §5.3 (a mounted filesystem
//! doing basic read/write over IPC) while the on-disk format is being
//! specified (IMPLEMENTATION-PLAN.md Q3).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.2 (native FS
//! as a separate service), §5.3 (MVP acceptance).
//!
//! Position in the system: an isolated layer-3 process behind the VFS
//! Router. Receives forwarded `ipc_protocol::fs::FsRequest`s and replies
//! `FsResponse`. Bulk bytes travel through a `SharedRegion`, not the
//! message — but the in-memory store here works on plain slices; the
//! shared-region copy-in/out is done by the request-handling glue.
//!
//! Safety/invariants: handles are dense small integers into a slot table;
//! a closed handle never resolves; reads past EOF return a short count,
//! not an error.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// fs-native's real process entry point (03-Kernel-Subsystems-Layer.md
/// §2.2/§5.3) — see that module's own doc comment. Mirrors `device-
/// manager::subsystem_entry`'s own unconditional module declaration
/// (per-architecture gating lives inside the file, not at this level).
pub mod subsystem_entry;

/// Errors from the in-memory store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// No file at that path.
    NotFound,
    /// The handle is closed / never existed.
    BadHandle,
    /// A write would exceed the per-file size cap.
    TooLarge,
    /// Opened without the right the operation needs.
    Denied,
}

/// Per-file size cap for the MVP in-memory store (1 MiB).
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

/// An open-file handle.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle(pub u32);

#[derive(Debug, Clone, Copy)]
struct OpenFile {
    /// Index into `files` (by insertion id, stable).
    file_id: u32,
    can_write: bool,
}

/// The in-memory filesystem.
#[derive(Debug, Default)]
pub struct MemFs {
    /// path -> file id.
    index: BTreeMap<String, u32>,
    /// file id -> contents.
    files: BTreeMap<u32, Vec<u8>>,
    /// open handle -> open state.
    open: BTreeMap<u32, OpenFile>,
    next_file_id: u32,
    next_handle: u32,
}

impl MemFs {
    /// An empty filesystem.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates (or truncates) a file at `path` and returns nothing — a
    /// helper for tests / boot seeding, not an IPC entry point.
    pub fn create(&mut self, path: &str) -> u32 {
        if let Some(&id) = self.index.get(path) {
            self.files.insert(id, Vec::new());
            return id;
        }
        let id = self.next_file_id;
        self.next_file_id += 1;
        self.index.insert(String::from(path), id);
        self.files.insert(id, Vec::new());
        id
    }

    /// Opens `path`. `write` requests write access; `create` makes the
    /// file if absent.
    pub fn open(&mut self, path: &str, write: bool, create: bool) -> Result<Handle, FsError> {
        let file_id = match self.index.get(path).copied() {
            Some(id) => id,
            None if create => self.create(path),
            None => return Err(FsError::NotFound),
        };
        let h = self.next_handle;
        self.next_handle += 1;
        self.open.insert(
            h,
            OpenFile {
                file_id,
                can_write: write,
            },
        );
        Ok(Handle(h))
    }

    /// Reads up to `buf.len()` bytes from `handle` at `offset` into `buf`,
    /// returning the number of bytes read (0 at/after EOF).
    pub fn read(&self, handle: Handle, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let of = self.open.get(&handle.0).ok_or(FsError::BadHandle)?;
        let data = self.files.get(&of.file_id).ok_or(FsError::BadHandle)?;
        let start = (offset as usize).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }

    /// Writes `src` to `handle` at `offset`, extending the file if
    /// needed. Returns bytes written.
    pub fn write(&mut self, handle: Handle, offset: u64, src: &[u8]) -> Result<usize, FsError> {
        let of = *self.open.get(&handle.0).ok_or(FsError::BadHandle)?;
        if !of.can_write {
            return Err(FsError::Denied);
        }
        let data = self.files.get_mut(&of.file_id).ok_or(FsError::BadHandle)?;
        let end = offset as usize + src.len();
        if end > MAX_FILE_BYTES {
            return Err(FsError::TooLarge);
        }
        if data.len() < end {
            data.resize(end, 0);
        }
        data[offset as usize..end].copy_from_slice(src);
        Ok(src.len())
    }

    /// Size of the file behind `handle`.
    pub fn size(&self, handle: Handle) -> Result<u64, FsError> {
        let of = self.open.get(&handle.0).ok_or(FsError::BadHandle)?;
        Ok(self.files.get(&of.file_id).map(|d| d.len() as u64).unwrap_or(0))
    }

    /// Closes `handle`.
    pub fn close(&mut self, handle: Handle) -> Result<(), FsError> {
        self.open.remove(&handle.0).map(|_| ()).ok_or(FsError::BadHandle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_roundtrips() {
        let mut fs = MemFs::new();
        let h = fs.open("/greeting", true, true).unwrap();
        assert_eq!(fs.write(h, 0, b"hello from kernel").unwrap(), 17);
        assert_eq!(fs.size(h).unwrap(), 17);

        let mut buf = [0u8; 32];
        let n = fs.read(h, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello from kernel");
    }

    #[test]
    fn read_past_eof_is_short_not_error() {
        let mut fs = MemFs::new();
        let h = fs.open("/f", true, true).unwrap();
        fs.write(h, 0, b"abc").unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(fs.read(h, 2, &mut buf).unwrap(), 1);
        assert_eq!(fs.read(h, 99, &mut buf).unwrap(), 0);
    }

    #[test]
    fn write_without_write_access_denied() {
        let mut fs = MemFs::new();
        fs.create("/ro");
        let h = fs.open("/ro", false, false).unwrap();
        assert_eq!(fs.write(h, 0, b"x"), Err(FsError::Denied));
    }

    #[test]
    fn missing_file_without_create() {
        let mut fs = MemFs::new();
        assert_eq!(fs.open("/nope", false, false), Err(FsError::NotFound));
    }

    #[test]
    fn closed_handle_stops_resolving() {
        let mut fs = MemFs::new();
        let h = fs.open("/f", true, true).unwrap();
        fs.close(h).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(fs.read(h, 0, &mut buf), Err(FsError::BadHandle));
    }
}
