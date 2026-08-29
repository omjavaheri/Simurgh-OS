//! ============================================================================
//! driver.rs
//!
//! Purpose: the message set between the Device Manager (and clients) and a
//! driver process (03-Kernel-Subsystems-Layer.md §2.1). Mirrors the
//! `DeviceDriver` trait's `probe` / `handle_irq` / `handle_request` shape
//! at the wire level.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1
//! (`DeviceDriver` trait, driver process isolation, restart policy), §5.1
//! (MVP: a simple block driver, virtio-blk on QEMU), §5.2 (injected panic
//! → Device Manager restart).
//!
//! Position in the system: encoded into `kernel_ipc::SmallMessage` by
//! `codec.rs`. A block driver's bulk data (sectors) rides a `SharedRegion`
//! referenced by `shared_cap`, never the message body.
//!
//! Safety/invariants: plain integer fields; the enum is `Copy`.
//! ============================================================================

/// A request to a driver process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverRequest {
    /// Ask the driver to bind to its device. The Device Manager sends
    /// this once, right after spawning the driver, having already granted
    /// it an MMIO capability and an IRQ capability scoped to that one
    /// device (§2.1). Reply: `Ready` or `Failed`.
    Probe,
    /// A hardware interrupt on `line` was delivered to this driver (via
    /// the notification the kernel signals from the HAL `IrqHandler`
    /// trampoline — §2.1). No reply expected.
    Irq {
        /// The interrupt line that fired (as the driver knows it).
        line: u32,
    },
    /// A block-device read: transfer `sector_count` sectors starting at
    /// `lba` into the shared region `shared_cap`. Reply: `Completed` or
    /// `Failed`.
    ReadBlocks {
        /// Starting logical block address.
        lba: u64,
        /// Number of sectors.
        sector_count: u32,
        /// Client capability slot naming the destination `SharedRegion`.
        shared_cap: u32,
    },
    /// A block-device write: transfer `sector_count` sectors from
    /// `shared_cap` to the device starting at `lba`. Reply: `Completed`
    /// or `Failed`.
    WriteBlocks {
        /// Starting logical block address.
        lba: u64,
        /// Number of sectors.
        sector_count: u32,
        /// Client capability slot naming the source `SharedRegion`.
        shared_cap: u32,
    },
    /// Ask the driver to quiesce (flush, mask its IRQ) ahead of a planned
    /// restart or shutdown. Reply: `Ready`.
    Quiesce,
}

/// A reply from a driver process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverResponse {
    /// `Probe` / `Quiesce` succeeded; the driver is bound and idle.
    Ready {
        /// Device sector size in bytes (block drivers), else 0.
        sector_size: u32,
        /// Device capacity in sectors (block drivers), else 0.
        sector_count: u64,
    },
    /// A `ReadBlocks` / `WriteBlocks` finished.
    Completed {
        /// Sectors actually transferred.
        sectors: u32,
    },
    /// The request could not be completed. `code` is a `DriverErrorCode`.
    Failed {
        /// Machine-readable error code.
        code: DriverErrorCode,
    },
}

/// Driver error codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverErrorCode {
    /// The device did not respond / failed self-test during `Probe`.
    ProbeFailed = 1,
    /// LBA out of range for the device.
    OutOfRange = 2,
    /// The shared region capability was missing or too small.
    BadSharedRegion = 3,
    /// The device reported an I/O error.
    DeviceIo = 4,
    /// The request kind is not supported by this driver.
    Unsupported = 5,
}
