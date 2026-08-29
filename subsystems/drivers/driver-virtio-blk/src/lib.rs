//! ============================================================================
//! driver-virtio-blk
//!
//! Purpose: the MVP block driver — virtio-blk over MMIO on QEMU
//! (03-Kernel-Subsystems-Layer.md §5.1). Runs as its own isolated process,
//! implements `driver_framework::DeviceDriver`, and serves
//! `DriverRequest::{ReadBlocks,WriteBlocks}` by driving a virtio virtqueue.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (driver
//! process model), §5.1 (virtio-blk on QEMU is the named acceptance
//! device), §5.2 (an injected panic must trigger a Device Manager
//! restart — so this driver deliberately does not swallow its own faults).
//!
//! Position in the system: layer-3 process. It is granted a capability to
//! the virtio-blk MMIO window and its IRQ line by the Device Manager, maps
//! the MMIO window, and sets up its virtqueue in a `SharedRegion` it
//! retyped from granted untyped memory.
//!
//! MVP scope: the register map, feature bits, and request-header layout
//! are defined here; the actual virtqueue descriptor ring manipulation and
//! MMIO pokes are marked `// TODO(omid)` — they need the mapped MMIO base
//! and a DMA-capable shared region, both of which arrive with the
//! capability-grant path.
//!
//! Safety/invariants: all MMIO access will go through `read_volatile` /
//! `write_volatile` on the mapped base with `// SAFETY:` notes; none is
//! performed yet.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use driver_framework::{DeviceDriver, DeviceInfo, DriverError};
use ipc_protocol::driver::DriverErrorCode;
use ipc_protocol::{DriverRequest, DriverResponse};

/// virtio-mmio register offsets (from the virtio 1.x spec, §4.2.2). Only
/// the ones this driver needs.
pub mod mmio {
    /// `0x74726976` ("virt" LE) if a virtio-mmio device is present.
    pub const MAGIC_VALUE: usize = 0x000;
    /// Device version (2 for virtio 1.x).
    pub const VERSION: usize = 0x004;
    /// Device type (2 = block device).
    pub const DEVICE_ID: usize = 0x008;
    /// Driver status register.
    pub const STATUS: usize = 0x070;
    /// Selected queue index.
    pub const QUEUE_SEL: usize = 0x030;
    /// Max size of the selected queue (0 = unavailable).
    pub const QUEUE_NUM_MAX: usize = 0x034;
    /// Size to use for the selected queue.
    pub const QUEUE_NUM: usize = 0x038;
    /// Notify the device that the selected queue has new buffers.
    pub const QUEUE_NOTIFY: usize = 0x050;
    /// Interrupt status (bit 0: used-ring update).
    pub const INTERRUPT_STATUS: usize = 0x060;
    /// Acknowledge handled interrupts.
    pub const INTERRUPT_ACK: usize = 0x064;
    /// Device-specific config space (block capacity lives here).
    pub const CONFIG: usize = 0x100;
}

/// virtio-blk request type (first 4 bytes of the request header).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkReqType {
    /// Read sectors from the device.
    In = 0,
    /// Write sectors to the device.
    Out = 1,
    /// Flush the device write cache.
    Flush = 4,
}

/// The virtio-blk 16-byte request header that precedes the data buffer in
/// a virtqueue descriptor chain (virtio spec §5.2.6).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlkReqHeader {
    /// `BlkReqType`.
    pub req_type: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
    /// Starting sector (512-byte units regardless of logical block size).
    pub sector: u64,
}

/// The virtio-blk driver state.
pub struct VirtioBlk {
    /// Mapped MMIO base of the virtio-mmio transport (0 until `probe`
    /// maps it).
    mmio_base: usize,
    /// Device capacity in 512-byte sectors, read from config space in
    /// `probe`.
    capacity_sectors: u64,
    /// Whether `probe` has completed.
    ready: bool,
}

impl VirtioBlk {
    /// Creates the driver bound to a virtio-mmio window that will be
    /// mapped at `mmio_base` (pass 0 in tests / before the grant).
    pub const fn new(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            capacity_sectors: 0,
            ready: false,
        }
    }

    /// Sector size this driver reports (virtio-blk is always 512-byte
    /// sectors at the transport level).
    pub const SECTOR_SIZE: u32 = 512;
}

impl DeviceDriver for VirtioBlk {
    fn probe(&mut self) -> Result<DeviceInfo, DriverError> {
        // TODO(omid): with `mmio_base` mapped, verify MAGIC_VALUE /
        // VERSION / DEVICE_ID, run the ACKNOWLEDGE→DRIVER→FEATURES_OK→
        // DRIVER_OK status handshake, set up the request virtqueue in a
        // DMA-capable SharedRegion, and read `capacity` from CONFIG.
        if self.mmio_base == 0 {
            return Err(DriverError::ProbeFailed);
        }
        self.ready = true;
        Ok(DeviceInfo {
            sector_size: Self::SECTOR_SIZE,
            sector_count: self.capacity_sectors,
        })
    }

    fn handle_irq(&mut self, _line: u32) {
        // TODO(omid): read INTERRUPT_STATUS, walk the used ring to
        // complete in-flight requests, write INTERRUPT_ACK.
    }

    fn handle_request(&mut self, req: DriverRequest) -> DriverResponse {
        if !self.ready {
            return DriverResponse::Failed {
                code: DriverErrorCode::ProbeFailed,
            };
        }
        match req {
            DriverRequest::Probe => DriverResponse::Ready {
                sector_size: Self::SECTOR_SIZE,
                sector_count: self.capacity_sectors,
            },
            DriverRequest::ReadBlocks {
                lba, sector_count, ..
            }
            | DriverRequest::WriteBlocks {
                lba, sector_count, ..
            } => {
                if self.capacity_sectors != 0 && lba + sector_count as u64 > self.capacity_sectors {
                    return DriverResponse::Failed {
                        code: DriverErrorCode::OutOfRange,
                    };
                }
                // TODO(omid): build the descriptor chain (header + data +
                // status), publish it, ring QUEUE_NOTIFY, and complete
                // asynchronously in `handle_irq`. For now report the
                // request as accepted with zero sectors moved.
                DriverResponse::Completed { sectors: 0 }
            }
            DriverRequest::Irq { line } => {
                self.handle_irq(line);
                DriverResponse::Completed { sectors: 0 }
            }
            DriverRequest::Quiesce => DriverResponse::Ready {
                sector_size: Self::SECTOR_SIZE,
                sector_count: self.capacity_sectors,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_without_mmio_fails() {
        let mut d = VirtioBlk::new(0);
        assert_eq!(d.probe(), Err(DriverError::ProbeFailed));
    }

    #[test]
    fn requests_before_ready_are_rejected() {
        let mut d = VirtioBlk::new(0x1000_0000);
        let r = d.handle_request(DriverRequest::ReadBlocks {
            lba: 0,
            sector_count: 1,
            shared_cap: 1,
        });
        assert!(matches!(
            r,
            DriverResponse::Failed {
                code: DriverErrorCode::ProbeFailed
            }
        ));
    }

    #[test]
    fn probe_then_out_of_range_read_is_rejected() {
        let mut d = VirtioBlk::new(0x1000_0000);
        d.capacity_sectors = 100;
        d.probe().unwrap();
        let r = d.handle_request(DriverRequest::ReadBlocks {
            lba: 90,
            sector_count: 20,
            shared_cap: 1,
        });
        assert!(matches!(
            r,
            DriverResponse::Failed {
                code: DriverErrorCode::OutOfRange
            }
        ));
    }
}
