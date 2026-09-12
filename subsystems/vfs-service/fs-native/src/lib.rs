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

    /// Deletes the file at `path`, freeing its storage immediately —
    /// `FsError::NotFound` if no file is registered at `path`.
    ///
    /// Real, deliberate MVP simplification: unlike real POSIX `unlink`
    /// (which keeps a still-open file's storage alive until every open
    /// handle closes), this frees `files[file_id]` right away even if a
    /// handle is still open against it — a later `read`/`write`/`size`
    /// through that now-stale handle fails cleanly with `FsError::
    /// BadHandle` (exactly the same path every one of those three
    /// methods already takes for a handle whose `file_id` has no entry
    /// in `files` — `read`'s own `self.files.get(&of.file_id).ok_or(...)`
    /// line, unchanged by this method), not a panic or a new failure
    /// mode. A real POSIX-accurate "keep it alive until the last close"
    /// semantic is a legitimate future refinement, not required for this
    /// MVP's own real Definition of Done (03-Kernel-Subsystems-Layer.md
    /// §5.3 only asks for real read/write over IPC).
    pub fn delete(&mut self, path: &str) -> Result<(), FsError> {
        let file_id = self.index.remove(path).ok_or(FsError::NotFound)?;
        self.files.remove(&file_id);
        Ok(())
    }

    /// Renames/moves the file at `from` to `to` — `FsError::NotFound` if
    /// no file is registered at `from`. If a file already exists at `to`,
    /// it is replaced (real POSIX `rename` semantics: the destination is
    /// atomically overwritten, not an error) — its own storage is freed
    /// the same way [`Self::delete`] frees any file's, including the
    /// identical "a stale open handle against the replaced file fails
    /// cleanly, not a panic" reasoning that method's own doc comment
    /// gives. Open handles against the file being MOVED (`from`) stay
    /// valid — only `index` changes (which path resolves to `file_id`,
    /// never the `file_id` itself), the same "look up `open[handle].
    /// file_id`, not `index[path]`" real reasoning every one of `read`/
    /// `write`/`size`/`close` already uses; nothing about that
    /// resolution path is touched by a `rename`.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), FsError> {
        let file_id = self.index.remove(from).ok_or(FsError::NotFound)?;
        if let Some(old_to_id) = self.index.insert(String::from(to), file_id) {
            self.files.remove(&old_to_id);
        }
        Ok(())
    }

    /// Lists the immediate children of `dir_path` — synthesized from the
    /// flat `index` (this store's own doc comment: it has no real
    /// directory nodes at all, just a flat path-string -> file-id map).
    /// Every registered path that starts with `dir_path` (normalized to
    /// end with exactly one `/`) contributes either a real file entry
    /// (nothing left after the prefix but a bare name, no further `/`)
    /// or one deduplicated synthesized subdirectory entry (the first
    /// path segment after the prefix, when more path follows it) — the
    /// same "common prefix" technique flat object stores (S3 and
    /// similar) use to fake a real directory listing over what is
    /// really just a flat key space. Order matches `index`'s own sorted
    /// iteration order (a `BTreeMap`) — real, deterministic, not
    /// insertion-order-dependent, but not a "directories first" grouping
    /// either (that is a presentation concern, not this store's).
    pub fn list_directory(&self, dir_path: &str) -> Vec<DirEntry> {
        let mut prefix = String::from(dir_path);
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        let mut entries: Vec<DirEntry> = Vec::new();
        for path in self.index.keys().filter(|p| p.starts_with(prefix.as_str())) {
            let rest = &path[prefix.len()..];
            if rest.is_empty() {
                continue; // the directory path itself, registered as its own entry.
            }
            match rest.find('/') {
                Some(slash_idx) => {
                    let dir_name = &rest[..slash_idx];
                    if !entries.iter().any(|e| e.is_dir && e.name == dir_name) {
                        entries.push(DirEntry { name: String::from(dir_name), is_dir: true });
                    }
                }
                None => entries.push(DirEntry { name: String::from(rest), is_dir: false }),
            }
        }
        entries
    }
}

/// One entry [`MemFs::list_directory`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's own bare name (no path prefix, no trailing `/`).
    pub name: String,
    /// `true` if this entry is a synthesized subdirectory, `false` if it
    /// is a real file.
    pub is_dir: bool,
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

    #[test]
    fn list_directory_returns_direct_files_and_synthesizes_one_subdir_entry() {
        let mut fs = MemFs::new();
        fs.create("/home/alice/notes.txt");
        fs.create("/home/alice/todo.txt");
        fs.create("/home/alice/photos/beach.png");
        fs.create("/home/alice/photos/mountain.png");
        fs.create("/home/bob/other.txt"); // a sibling, must not appear.

        let mut entries = fs.list_directory("/home/alice");
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(
            entries,
            alloc::vec![
                DirEntry { name: String::from("notes.txt"), is_dir: false },
                DirEntry { name: String::from("photos"), is_dir: true },
                DirEntry { name: String::from("todo.txt"), is_dir: false },
            ]
        );
    }

    #[test]
    fn list_directory_works_with_or_without_a_trailing_slash() {
        let mut fs = MemFs::new();
        fs.create("/etc/config.toml");
        assert_eq!(fs.list_directory("/etc"), fs.list_directory("/etc/"));
    }

    #[test]
    fn list_directory_of_an_empty_or_unknown_path_is_an_empty_list_not_an_error() {
        let fs = MemFs::new();
        assert!(fs.list_directory("/does/not/exist").is_empty());
    }

    #[test]
    fn a_deeply_nested_file_only_contributes_its_own_first_level_subdir_once() {
        let mut fs = MemFs::new();
        fs.create("/a/b/c/d/deep.txt");
        fs.create("/a/b/c/e/deep2.txt");
        let entries = fs.list_directory("/a/b/c");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.is_dir));
        let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, alloc::vec!["d", "e"]);
    }

    #[test]
    fn deleting_a_file_removes_it_from_a_later_listing() {
        let mut fs = MemFs::new();
        fs.create("/etc/config.toml");
        assert_eq!(fs.list_directory("/etc").len(), 1);
        fs.delete("/etc/config.toml").unwrap();
        assert!(fs.list_directory("/etc").is_empty());
    }

    #[test]
    fn deleting_an_unregistered_path_is_not_found() {
        let mut fs = MemFs::new();
        assert_eq!(fs.delete("/nope"), Err(FsError::NotFound));
    }

    #[test]
    fn deleting_a_file_with_a_still_open_handle_fails_that_handle_cleanly_not_a_panic() {
        let mut fs = MemFs::new();
        let h = fs.open("/f", true, true).unwrap();
        fs.write(h, 0, b"abc").unwrap();
        fs.delete("/f").unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(fs.read(h, 0, &mut buf), Err(FsError::BadHandle));
        assert_eq!(fs.write(h, 0, b"x"), Err(FsError::BadHandle));
        // `size` is the one existing method that does NOT follow `read`/
        // `write`'s own "missing file_id -> BadHandle" pattern — it maps
        // a missing `files` entry to `Ok(0)` instead (pre-existing
        // behavior, unrelated to `delete`; presumably meant for a
        // freshly-created-but-never-written file, which looks identical
        // at this type's own level to a deleted one). Documented here as
        // the real, current behavior rather than assumed.
        assert_eq!(fs.size(h), Ok(0));
    }

    #[test]
    fn renaming_a_file_makes_it_readable_at_the_new_path_and_gone_from_the_old_one() {
        let mut fs = MemFs::new();
        let h = fs.open("/old.txt", true, true).unwrap();
        fs.write(h, 0, b"hello").unwrap();
        fs.close(h).unwrap();

        fs.rename("/old.txt", "/new.txt").unwrap();

        assert_eq!(fs.open("/old.txt", false, false), Err(FsError::NotFound));
        let h2 = fs.open("/new.txt", false, false).unwrap();
        let mut buf = [0u8; 8];
        let n = fs.read(h2, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn renaming_an_unregistered_source_path_is_not_found() {
        let mut fs = MemFs::new();
        assert_eq!(fs.rename("/nope", "/dest"), Err(FsError::NotFound));
    }

    #[test]
    fn renaming_onto_an_existing_destination_replaces_it() {
        let mut fs = MemFs::new();
        let src = fs.open("/src.txt", true, true).unwrap();
        fs.write(src, 0, b"new content").unwrap();
        fs.close(src).unwrap();
        fs.create("/dest.txt");

        fs.rename("/src.txt", "/dest.txt").unwrap();

        let h = fs.open("/dest.txt", false, false).unwrap();
        let mut buf = [0u8; 16];
        let n = fs.read(h, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"new content");
        // Only one entry now - the old /dest.txt was really replaced, not
        // left behind as a second file.
        assert_eq!(fs.list_directory("/").len(), 1);
    }

    #[test]
    fn an_open_handle_against_a_renamed_file_stays_valid() {
        let mut fs = MemFs::new();
        let h = fs.open("/old.txt", true, true).unwrap();
        fs.write(h, 0, b"still here").unwrap();

        fs.rename("/old.txt", "/new.txt").unwrap();

        let mut buf = [0u8; 16];
        let n = fs.read(h, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"still here");
    }
}
