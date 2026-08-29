//! ============================================================================
//! driver-framework
//!
//! Purpose: the contract every Simurgh driver implements and the tiny
//! runtime that drives it. A driver is a normal isolated layer-3 process
//! (03-Kernel-Subsystems-Layer.md §2.1) that has been granted a capability
//! to exactly one device's MMIO region and one IRQ. This crate defines the
//! `DeviceDriver` trait (mirroring §2.1's `probe` / `handle_irq` /
//! `handle_request`) and a `serve` loop that decodes `ipc-protocol`
//! messages into trait calls.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (`DeviceDriver`
//! trait, driver process model), §5.1 (virtio-blk MVP).
//!
//! Position in the system: linked into each concrete driver crate
//! (`driver-virtio-blk`, …). The runtime's I/O (receiving a message,
//! sending a reply, waiting on the IRQ notification) is done through the
//! syscall surface; here it is abstracted behind the `DriverChannel` trait
//! so drivers and their tests do not depend on a live kernel.
//!
//! Safety/invariants: `serve` never blocks the process on anything except
//! the channel; a panic in a trait method propagates to the process
//! boundary, where the Device Manager observes the crash and restarts it
//! (§2.1) — the framework does not catch it.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use ipc_protocol::{DriverRequest, DriverResponse};

/// Errors a driver method can return to the framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    /// The device failed to initialise during `probe`.
    ProbeFailed,
    /// A request referenced an out-of-range address / block.
    OutOfRange,
    /// The device signalled a hardware error.
    DeviceIo,
    /// The request is not supported by this driver.
    Unsupported,
}

/// What a driver reports about its device after a successful `probe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Sector size in bytes for a block device (0 for non-block).
    pub sector_size: u32,
    /// Capacity in sectors for a block device (0 for non-block).
    pub sector_count: u64,
}

/// The contract every Simurgh driver implements
/// (03-Kernel-Subsystems-Layer.md §2.1). Sync rather than the doc's
/// `async_trait` sketch: the MVP runtime is a single-threaded message loop
/// and an `async` executor is a later addition that does not change this
/// surface.
pub trait DeviceDriver {
    /// Bind to the device: map its MMIO region (the driver already holds
    /// the capability), run any reset / feature-negotiation, and return
    /// its `DeviceInfo`. Called once, right after the process starts.
    fn probe(&mut self) -> Result<DeviceInfo, DriverError>;

    /// A hardware interrupt on `line` fired. The driver acknowledges it
    /// at the device and advances whatever in-flight work it completed.
    fn handle_irq(&mut self, line: u32);

    /// Handle one client request, returning the reply to send back.
    fn handle_request(&mut self, req: DriverRequest) -> DriverResponse;

    /// Flush and mask the device ahead of a planned restart / shutdown.
    fn quiesce(&mut self) {}
}

/// The process's link to the outside world (kernel IPC), abstracted so
/// drivers and tests do not need a live kernel. A real driver process is
/// handed a concrete implementation backed by syscalls.
pub trait DriverChannel {
    /// Block until the next event: a client `DriverRequest`, or an IRQ on
    /// the given line. `None` means the channel closed (the Device
    /// Manager is tearing this driver down).
    fn next_event(&mut self) -> Option<DriverEvent>;

    /// Send `resp` back to the client of the most recent request.
    fn reply(&mut self, resp: DriverResponse);
}

/// One event delivered by a `DriverChannel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverEvent {
    /// A client request to handle.
    Request(DriverRequest),
    /// The device's IRQ line fired.
    Irq {
        /// The line number.
        line: u32,
    },
}

/// Runs a driver's message loop until the channel closes. This is a driver
/// process's `main`, minus the process/runtime bootstrap.
///
/// Flow: `probe` first (a failure here is fatal — return so the process
/// exits and the Device Manager restarts it), then loop dispatching
/// `Request` → `handle_request` (+ `reply`) and `Irq` → `handle_irq`.
pub fn serve<D: DeviceDriver, C: DriverChannel>(driver: &mut D, chan: &mut C) -> Result<(), DriverError> {
    let _info = driver.probe()?;
    while let Some(ev) = chan.next_event() {
        match ev {
            DriverEvent::Request(req) => {
                let resp = driver.handle_request(req);
                chan.reply(resp);
            }
            DriverEvent::Irq { line } => driver.handle_irq(line),
        }
    }
    driver.quiesce();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc_protocol::driver::DriverErrorCode;

    struct FakeBlock {
        probed: bool,
        irqs: u32,
    }
    impl DeviceDriver for FakeBlock {
        fn probe(&mut self) -> Result<DeviceInfo, DriverError> {
            self.probed = true;
            Ok(DeviceInfo {
                sector_size: 512,
                sector_count: 2048,
            })
        }
        fn handle_irq(&mut self, _line: u32) {
            self.irqs += 1;
        }
        fn handle_request(&mut self, req: DriverRequest) -> DriverResponse {
            match req {
                DriverRequest::ReadBlocks { sector_count, .. } => {
                    DriverResponse::Completed { sectors: sector_count }
                }
                _ => DriverResponse::Failed {
                    code: DriverErrorCode::Unsupported,
                },
            }
        }
    }

    /// A channel that replays a fixed script of events and records replies
    /// into a small array — no `alloc`.
    struct ScriptChannel {
        events: [Option<DriverEvent>; 4],
        idx: usize,
        replies: [Option<DriverResponse>; 4],
        replies_len: usize,
    }
    impl DriverChannel for ScriptChannel {
        fn next_event(&mut self) -> Option<DriverEvent> {
            let e = self.events.get(self.idx).copied().flatten();
            self.idx += 1;
            e
        }
        fn reply(&mut self, resp: DriverResponse) {
            self.replies[self.replies_len] = Some(resp);
            self.replies_len += 1;
        }
    }

    #[test]
    fn serve_probes_then_dispatches() {
        let mut d = FakeBlock {
            probed: false,
            irqs: 0,
        };
        let mut c = ScriptChannel {
            events: [
                Some(DriverEvent::Irq { line: 3 }),
                Some(DriverEvent::Request(DriverRequest::ReadBlocks {
                    lba: 0,
                    sector_count: 8,
                    shared_cap: 1,
                })),
                None,
                None,
            ],
            idx: 0,
            replies: [None; 4],
            replies_len: 0,
        };
        serve(&mut d, &mut c).unwrap();
        assert!(d.probed);
        assert_eq!(d.irqs, 1);
        assert_eq!(
            c.replies[0],
            Some(DriverResponse::Completed { sectors: 8 })
        );
    }
}
