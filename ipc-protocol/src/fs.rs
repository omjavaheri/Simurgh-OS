//! ============================================================================
//! fs.rs
//!
//! Purpose: the VFS request/response message set
//! (03-Kernel-Subsystems-Layer.md §2.2). An application (or the layer-4
//! POSIX compat shim) sends a `FsRequest` to the VFS Router over IPC; the
//! router forwards it to the filesystem service that owns the mount, which
//! replies with a `FsResponse`.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.2 (`FsRequest`
//! enum), §5.3 (MVP: mount + basic read/write over IPC).
//!
//! Position in the system: encoded into `kernel_ipc::SmallMessage` by
//! `codec.rs`. Bulk data (the bytes of a `Read`/`Write`) never travels in
//! the message — it goes through a `SharedRegion` capability referenced by
//! `shared_cap`, per §2.2's page-cache-as-shared-memory design and §5.2's
//! zero-copy rule.
//!
//! Safety/invariants: all fields are plain integers. Paths are not inlined
//! (a `SmallMessage` is only 6 words) — a `PathId` refers to a path string
//! the client has already registered with the router via a separate
//! `RegisterPath` call. (MVP simplification; a real IDL would carry
//! variable-length data through a side buffer.)
//! ============================================================================

use bitflags::bitflags;

/// An opaque handle to an open file, returned by `Open` and passed to
/// `Read`/`Write`/`Close`. Scoped to the connection it was issued on.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileHandle(pub u32);

/// An opaque id for a path string previously registered with the VFS
/// Router (see the module note on why paths are not inlined).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId(pub u32);

bitflags! {
    /// Flags for `FsRequest::Open`.
    ///
    /// Possible bits and their effect:
    /// - `READ`: open for reading.
    /// - `WRITE`: open for writing.
    /// - `CREATE`: create the file if it does not exist.
    /// - `TRUNCATE`: truncate to zero length on open (requires `WRITE`).
    /// - `APPEND`: writes are positioned at end-of-file.
    /// - `DIRECTORY`: the target must be a directory; fail otherwise.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        /// Open for reading.
        const READ      = 1 << 0;
        /// Open for writing.
        const WRITE     = 1 << 1;
        /// Create if absent.
        const CREATE    = 1 << 2;
        /// Truncate on open.
        const TRUNCATE  = 1 << 3;
        /// Append-only writes.
        const APPEND    = 1 << 4;
        /// Must be a directory.
        const DIRECTORY = 1 << 5;
    }
}

/// A request to the VFS layer (03-Kernel-Subsystems-Layer.md §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsRequest {
    /// Open the file named by `path` with `flags`. Reply: `Opened` or
    /// `Error`.
    Open {
        /// Registered path id.
        path: PathId,
        /// Open flags.
        flags: OpenFlags,
    },
    /// Read up to `len` bytes from `handle` at `offset`. The bytes are
    /// written into the caller-provided shared region `shared_cap`; the
    /// reply `Read` carries only the byte count. Reply: `Read` or `Error`.
    Read {
        /// Open file handle.
        handle: FileHandle,
        /// Byte offset.
        offset: u64,
        /// Maximum bytes to read.
        len: u32,
        /// Client capability slot naming a `SharedRegion` to receive the
        /// data (zero-copy — §5.2).
        shared_cap: u32,
    },
    /// Write bytes from the shared region `shared_cap` to `handle` at
    /// `offset`. Reply: `Written` or `Error`.
    Write {
        /// Open file handle.
        handle: FileHandle,
        /// Byte offset.
        offset: u64,
        /// Number of bytes in the shared region to write.
        len: u32,
        /// Client capability slot naming the source `SharedRegion`.
        shared_cap: u32,
    },
    /// Fetch metadata for the file named by `path`. Reply: `Stat` or
    /// `Error`.
    Stat {
        /// Registered path id.
        path: PathId,
    },
    /// Close `handle`. Reply: `Closed`.
    Close {
        /// Open file handle.
        handle: FileHandle,
    },
}

/// A reply from the VFS layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsResponse {
    /// `Open` succeeded.
    Opened {
        /// The new handle.
        handle: FileHandle,
    },
    /// `Read` completed; `bytes` were placed in the shared region.
    Read {
        /// Bytes actually read (may be `< len` at EOF).
        bytes: u32,
    },
    /// `Write` completed.
    Written {
        /// Bytes actually written.
        bytes: u32,
    },
    /// `Stat` result.
    Stat {
        /// File size in bytes.
        size: u64,
        /// True if the target is a directory.
        is_dir: bool,
    },
    /// `Close` completed.
    Closed,
    /// The request failed. `code` is a `FsErrorCode`.
    Error {
        /// Machine-readable error code.
        code: FsErrorCode,
    },
}

/// VFS error codes (a compact, `Copy` set — no `errno` sprawl).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsErrorCode {
    /// No such file or directory.
    NotFound = 1,
    /// Permission denied by the filesystem service.
    Denied = 2,
    /// The handle is not open / not valid on this connection.
    BadHandle = 3,
    /// The path id was never registered with the router.
    BadPath = 4,
    /// The operation is not supported by this filesystem.
    Unsupported = 5,
    /// The shared region capability was missing or too small.
    BadSharedRegion = 6,
    /// Underlying storage / device error.
    Io = 7,
}
