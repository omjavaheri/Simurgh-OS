//! ============================================================================
//! vfs-router
//!
//! Purpose: the VFS front door. Clients (and the layer-4 POSIX shim) send
//! `FsRequest`s to the router; it resolves the request's path against a
//! mount table and forwards it to the filesystem service that owns the
//! longest matching mount prefix (03-Kernel-Subsystems-Layer.md §2.2 — "هر
//! فایل‌سیستم یک سرویس جدا است که پشت یک VFS Router قرار می‌گیرد").
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.2 (VFS as
//! separate services behind a router), §5.3 (MVP: mount a simple filesystem
//! and do read/write over IPC).
//!
//! Position in the system: an isolated layer-3 process. Speaks
//! `ipc_protocol::fs` messages to clients and to backend filesystem
//! services.
//!
//! MVP scope: the mount table + longest-prefix resolution are implemented
//! and tested. Path strings are represented as byte slices the router owns
//! (registered by clients via a `PathId`); the forwarding IPC itself is
//! wired with the syscall shim.
//!
//! Safety/invariants: `resolve` is total; a path that matches no mount
//! returns `None` rather than a wrong backend.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Identifies a backend filesystem service (its endpoint, from the
/// router's point of view). A small integer here; the router maps it to a
/// real endpoint capability separately.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendId(pub u32);

/// One mount: a path prefix and the backend that serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mount {
    prefix: String,
    backend: BackendId,
}

/// The VFS mount table.
#[derive(Debug, Default)]
pub struct MountTable {
    mounts: Vec<Mount>,
}

/// Errors from mount-table operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountError {
    /// A mount already exists at exactly this prefix.
    AlreadyMounted,
    /// The prefix was empty or did not start with `/`.
    BadPrefix,
}

impl MountTable {
    /// A table with no mounts.
    pub const fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    /// Mounts `backend` at `prefix` (an absolute path like `/` or
    /// `/data`). Later `resolve` calls route any path under `prefix` to
    /// `backend`, unless a longer prefix also matches.
    pub fn mount(&mut self, prefix: &str, backend: BackendId) -> Result<(), MountError> {
        if prefix.is_empty() || !prefix.starts_with('/') {
            return Err(MountError::BadPrefix);
        }
        let norm = normalize(prefix);
        if self.mounts.iter().any(|m| m.prefix == norm) {
            return Err(MountError::AlreadyMounted);
        }
        self.mounts.push(Mount {
            prefix: norm,
            backend,
        });
        Ok(())
    }

    /// Removes the mount at exactly `prefix`. Returns whether one was
    /// removed.
    pub fn unmount(&mut self, prefix: &str) -> bool {
        let norm = normalize(prefix);
        let before = self.mounts.len();
        self.mounts.retain(|m| m.prefix != norm);
        self.mounts.len() != before
    }

    /// Resolves `path` to the backend that should serve it: the mount
    /// whose prefix is the longest one that `path` lies under. Returns
    /// `None` if nothing matches (not even `/`).
    pub fn resolve(&self, path: &str) -> Option<BackendId> {
        let norm = normalize(path);
        let mut best: Option<(&Mount, usize)> = None;
        for m in &self.mounts {
            if path_under(&norm, &m.prefix) {
                let len = m.prefix.len();
                if best.map(|(_, l)| len > l).unwrap_or(true) {
                    best = Some((m, len));
                }
            }
        }
        best.map(|(m, _)| m.backend)
    }

    /// Number of mounts.
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// True if nothing is mounted.
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

/// Collapses trailing slashes (except for the root itself) so `/data` and
/// `/data/` compare equal.
fn normalize(p: &str) -> String {
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() {
        String::from("/")
    } else {
        String::from(trimmed)
    }
}

/// True if `path` is `prefix` itself or a descendant of it.
fn path_under(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    if path == prefix {
        return true;
    }
    path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_wins() {
        let mut t = MountTable::new();
        t.mount("/", BackendId(1)).unwrap();
        t.mount("/data", BackendId(2)).unwrap();
        t.mount("/data/logs", BackendId(3)).unwrap();

        assert_eq!(t.resolve("/etc/hosts"), Some(BackendId(1)));
        assert_eq!(t.resolve("/data/file"), Some(BackendId(2)));
        assert_eq!(t.resolve("/data/logs/today"), Some(BackendId(3)));
        assert_eq!(t.resolve("/data"), Some(BackendId(2)));
    }

    #[test]
    fn no_root_mount_means_unmatched_paths_are_none() {
        let mut t = MountTable::new();
        t.mount("/data", BackendId(2)).unwrap();
        assert_eq!(t.resolve("/etc"), None);
        assert_eq!(t.resolve("/data/x"), Some(BackendId(2)));
    }

    #[test]
    fn duplicate_and_bad_prefixes_are_rejected() {
        let mut t = MountTable::new();
        t.mount("/data", BackendId(1)).unwrap();
        assert_eq!(t.mount("/data/", BackendId(9)), Err(MountError::AlreadyMounted));
        assert_eq!(t.mount("data", BackendId(9)), Err(MountError::BadPrefix));
        assert_eq!(t.mount("", BackendId(9)), Err(MountError::BadPrefix));
    }

    #[test]
    fn unmount_removes_route() {
        let mut t = MountTable::new();
        t.mount("/data", BackendId(2)).unwrap();
        assert!(t.unmount("/data"));
        assert_eq!(t.resolve("/data/x"), None);
        assert!(!t.unmount("/data"));
    }
}
