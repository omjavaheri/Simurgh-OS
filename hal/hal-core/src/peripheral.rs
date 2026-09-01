//! ============================================================================
//! peripheral.rs
//!
//! Peripheral (MMIO transport) Device Discovery.
//!
//! Purpose: for ordinary hardware peripherals (block/network/GPU/console
//! devices, discovered today via virtio-mmio on QEMU's `virt` machines) —
//! deliberately NOT part of `compute.rs`'s `ComputeDeviceDiscovery`, which
//! 01-HAL-Layer.md section 3.6 frames explicitly as "GPU/NPU/TPU/FPGA as
//! first-class entities... distinct from ordinary peripherals". This
//! module is that "ordinary peripheral" surface, mirroring `compute.rs`'s
//! own shape (a discovery trait over a fixed-size, boot-time raw type)
//! for the same reasons and under the same no-heap constraint.
//!
//! Not a numbered HAL-Layer.md section — section 11's own "nothing open
//! in this layer currently; record new decisions as they arise" note
//! covers exactly this: this surface exists to unblock
//! 03-Kernel-Subsystems-Layer.md section 5.1's MVP acceptance driver
//! (virtio-blk on QEMU), the first real consumer.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md section 2.1
//! (Device Manager grants a driver process exactly the MMIO region + IRQ
//! for its one device — this trait is how that information reaches the
//! Root Task in the first place) and section 5.1 (virtio-blk MVP).
//!
//! Position in the system: implemented once per architecture crate
//! (`hal-riscv64::peripheral::PeripheralDiscovery`,
//! `hal-arm64::peripheral::PeripheralDiscovery`; x86_64's own PCI-based
//! discovery is a deferred follow-up — see that crate's own
//! implementation for the current stand-in). Discovery mechanism differs
//! per architecture (Device Tree `compatible = "virtio,mmio"` matching on
//! riscv64/aarch64 `virt` machines; PCI config space enumeration on
//! x86_64) — this trait hides all of that behind one uniform query
//! surface, same "no `#[cfg(target_arch)]` above the HAL" rule
//! `ComputeDeviceDiscovery` already follows.
//!
//! Safety/invariants: same as `ComputeDeviceDiscovery` — discovery always
//! runs fully regardless of install profile (section 2's Discovery+Policy
//! split); an empty result is valid, not an error.
//! ============================================================================

// Re-export the raw peripheral device types directly from hal-manifest —
// same reasoning as `compute.rs`'s own re-export of `ComputeDeviceRaw`:
// at the point discovery runs (before any heap exists), the raw,
// `#[repr(C)]`, no-heap representation IS the correct representation.
pub use hal_manifest::raw::{PeripheralDeviceRaw as PeripheralDevice, PeripheralKindRaw as PeripheralKind};

// ============================================================================
// PeripheralDeviceDiscovery trait
// ============================================================================

/// Per-architecture MMIO peripheral discovery. See this module's own doc
/// comment for why this is separate from `ComputeDeviceDiscovery`.
pub trait PeripheralDeviceDiscovery {
    /// Returns every MMIO peripheral discovered on this machine.
    ///
    /// The returned slice borrows directly from the architecture
    /// implementation's own fixed-capacity storage (ultimately backed by
    /// `hal_manifest::raw::HardwareManifestRaw`), never from `alloc` —
    /// same no-heap contract `ComputeDeviceDiscovery::
    /// enumerate_compute_devices` documents.
    ///
    /// An empty slice is a valid, non-error result (e.g. x86_64's own
    /// deferred PCI-based discovery, until that follow-up lands) — see
    /// `HalError::PeripheralDiscoveryFailed` for the distinct case of
    /// discovery itself failing.
    fn enumerate_peripheral_devices(&self) -> &[PeripheralDevice];

    /// Looks up a single device by its stable `device_index` — same
    /// contract as `ComputeDeviceDiscovery::device_by_index`.
    fn device_by_index(&self, device_index: u32) -> Option<&PeripheralDevice>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use hal_manifest::raw::MAX_PERIPHERAL_DEVICES;

    // Mock hardware implementation, mirroring `compute.rs`'s own
    // `MockComputeDiscovery` — see that type's own doc comment for the
    // fixed-array-not-Vec rationale and the single-threaded-only SAFETY
    // contract of the raw-pointer borrow trick below.
    struct MockPeripheralDiscovery {
        devices: RefCell<([PeripheralDevice; 4], usize)>,
    }

    impl MockPeripheralDiscovery {
        fn new() -> Self {
            let mut devices = [PeripheralDevice::ZERO; 4];
            devices[0] = PeripheralDevice::new(PeripheralKind::Block, 0x1000_1000, 0x1000, 1);
            let mut net = PeripheralDevice::new(PeripheralKind::Network, 0x1000_2000, 0x1000, 2);
            net.device_index = 1;
            devices[1] = net;
            Self {
                devices: RefCell::new((devices, 2)),
            }
        }
    }

    impl PeripheralDeviceDiscovery for MockPeripheralDiscovery {
        fn enumerate_peripheral_devices(&self) -> &[PeripheralDevice] {
            let borrow = self.devices.borrow();
            let (arr, count) = &*borrow;
            let ptr = arr.as_ptr();
            let len = *count;
            // SAFETY: `arr` is stored inline in `self` (via `RefCell`)
            // and outlives this borrow's use in every test below, which
            // never mutates `devices` while holding the returned slice
            // (single-threaded test only).
            unsafe { core::slice::from_raw_parts(ptr, len) }
        }

        fn device_by_index(&self, device_index: u32) -> Option<&PeripheralDevice> {
            self.enumerate_peripheral_devices()
                .iter()
                .find(|d| d.device_index == device_index)
        }
    }

    #[test]
    fn enumerate_returns_discovered_devices() {
        let discovery = MockPeripheralDiscovery::new();
        let devices = discovery.enumerate_peripheral_devices();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].kind, PeripheralKind::Block);
        assert_eq!(devices[0].mmio_base, 0x1000_1000);
        assert_eq!(devices[1].kind, PeripheralKind::Network);
    }

    #[test]
    fn empty_discovery_is_not_an_error() {
        let discovery = MockPeripheralDiscovery {
            devices: RefCell::new(([PeripheralDevice::ZERO; 4], 0)),
        };
        assert!(discovery.enumerate_peripheral_devices().is_empty());
    }

    #[test]
    fn device_by_index_finds_correct_device() {
        let discovery = MockPeripheralDiscovery::new();
        let dev = discovery.device_by_index(1).unwrap();
        assert_eq!(dev.kind, PeripheralKind::Network);
    }

    #[test]
    fn device_by_index_returns_none_when_absent() {
        let discovery = MockPeripheralDiscovery::new();
        assert!(discovery.device_by_index(99).is_none());
    }

    #[test]
    fn manifest_capacity_matches_max_peripheral_devices_constant() {
        // Sanity check that this trait's mental model of capacity stays
        // aligned with hal-manifest's actual constant, matching
        // compute.rs's own identical check.
        assert_eq!(MAX_PERIPHERAL_DEVICES, 32);
    }
}
