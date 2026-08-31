//! ============================================================================
//! peripheral.rs — ARM64
//!
//! Implements `hal_core::peripheral::PeripheralDeviceDiscovery` for
//! ARM64 — see `hal_core::peripheral`'s own module doc comment for why
//! this is separate from `compute.rs`'s `ComputeDeviceDiscovery`
//! (GPU/NPU/TPU/FPGA-only, 01-HAL-Layer.md section 3.6).
//!
//! Design difference from hal-riscv64's own `peripheral.rs`: this crate
//! boots via ACPI (01-HAL-Layer.md section 10's own "ACPI first, Device
//! Tree only as a fallback this project has not implemented" decision —
//! `memory.rs`'s own module docs), not SBI+Device Tree, so it has no
//! `virtio,mmio`-compatible Device Tree nodes to walk in the first
//! place. QEMU's aarch64 `virt` machine's own PCIe root complex (already
//! how `compute.rs` discovers GPU/NPU/TPU-class devices here) is this
//! architecture's own natural analog: `virtio-blk-pci` (not `virtio-
//! blk-device`/MMIO) is the standard way to attach virtio-blk on a
//! PCI-based aarch64 QEMU boot, and this file reuses `compute.rs`'s own
//! ECAM scan primitives rather than duplicating them.
//!
//! Classification uses the SAME "PCI class code first, vendor ID as a
//! confirming signal" approach `compute.rs`'s own `classify_pci_device`
//! already establishes (class code 0x01 = Mass Storage, 0x02 = Network,
//! 0x03 = Display — PCI Code and ID Assignment Specification, not
//! virtio-specific), scoped to devices carrying virtio's own PCI-SIG
//! vendor id (`0x1AF4`, "Red Hat, Inc." / Virtio). MVP scope: reports
//! BAR0's own base+size as `mmio_base`/`mmio_size` (mirroring
//! `compute.rs`'s own `probe_bar_size(..., 0)` choice for compute
//! devices) — a real driver still needs virtio-pci's own PCI capability
//! list (virtio 1.x spec §4.1.4) to locate COMMON_CFG/NOTIFY/ISR/
//! DEVICE_CFG within whichever BAR each capability names, which may not
//! be BAR0 and is NOT resolved here; that parsing is the driver's own
//! job once it maps the capability grant, same division of labor
//! `compute.rs` already draws between "HAL discovers, driver configures".
//! ============================================================================

use hal_manifest::raw::{PeripheralDeviceRaw as PeripheralDevice, PeripheralKindRaw as PeripheralKind};

use crate::compute::{ecam_offset, ecam_read_u32, read_pci_header, PciDeviceHeader};

/// Capacity for this walker's own scratch storage — matches
/// `hal_manifest::raw::MAX_PERIPHERAL_DEVICES`, same reasoning as
/// hal-riscv64's own identical constant.
const MAX_SCAN: usize = hal_manifest::raw::MAX_PERIPHERAL_DEVICES;

/// virtio's own PCI-SIG vendor id ("Red Hat, Inc."), per the virtio 1.x
/// spec's own PCI Vendor/Device ID appendix.
const VIRTIO_PCI_VENDOR_ID: u16 = 0x1AF4;

const PCI_CLASS_MASS_STORAGE: u8 = 0x01;
const PCI_CLASS_NETWORK: u8 = 0x02;
const PCI_CLASS_DISPLAY: u8 = 0x03;

/// Maps a PCI class code (for a device already confirmed to carry
/// virtio's own vendor id) to this project's own `PeripheralKind`.
fn classify_virtio_pci_device(header: &PciDeviceHeader) -> PeripheralKind {
    match header.class_code {
        PCI_CLASS_MASS_STORAGE => PeripheralKind::Block,
        PCI_CLASS_NETWORK => PeripheralKind::Network,
        PCI_CLASS_DISPLAY => PeripheralKind::Gpu,
        _ => PeripheralKind::Unknown,
    }
}

/// BAR0 sizing — identical logic to `compute.rs`'s own `probe_bar_size`,
/// duplicated here (rather than made `pub(crate)` and reused) because
/// this file only ever needs BAR0 and the general N-index version pulls
/// in the full write-all-ones-and-restore dance for a parameter this
/// caller never varies — kept small and self-contained instead.
///
/// # Safety
/// Same contract as `ecam_read_u32`.
unsafe fn probe_bar0(ecam_base: u64, bus: u8, device: u8, function: u8) -> Option<(u64, u64)> {
    // SAFETY: forwarded from this function's own contract.
    let bar0 = unsafe { ecam_read_u32(ecam_base, bus, device, function, 0x10) };
    if bar0 & 0x1 != 0 {
        return None; // I/O-space BAR — same documented non-scope as
                      // compute.rs's own probe_bar_size.
    }
    let base = (bar0 & 0xFFFF_FFF0) as u64;

    let addr = ecam_base + ecam_offset(bus, device, function) + 0x10;
    let ptr = addr as *mut u32;
    // SAFETY: forwarded from this function's own contract; original
    // value always restored below (standard PCI BAR-sizing procedure,
    // spec section 6.2.5.1).
    unsafe { ptr.write_volatile(0xFFFF_FFFF) };
    // SAFETY: forwarded from this function's own contract.
    let size_mask = unsafe { ptr.read_volatile() };
    // SAFETY: forwarded from this function's own contract; restoring.
    unsafe { ptr.write_volatile(bar0) };

    if size_mask == 0 {
        return None;
    }
    let size = (!(size_mask & 0xFFFF_FFF0) as u64) + 1;
    Some((base, size))
}

// ============================================================================
// PeripheralDiscovery — PeripheralDeviceDiscovery implementation
// ============================================================================

pub struct PeripheralDiscovery {
    devices: [PeripheralDevice; MAX_SCAN],
    device_count: usize,
}

impl PeripheralDiscovery {
    /// Performs a full PCI bus scan over ECAM looking for virtio's own
    /// vendor id, mirroring `ComputeDiscovery::new`'s own scan loop
    /// shape exactly (same bus/device/function space, same `ecam_base`
    /// — see this file's own module docs for why `ecam_base` is a
    /// parameter here too). Per section 2's Discovery + Policy model,
    /// this always runs in full at construction.
    pub fn new(ecam_base: u64) -> Self {
        let mut devices = [PeripheralDevice::ZERO; MAX_SCAN];
        let mut device_count = 0usize;

        'bus_scan: for bus in 0..=255u8 {
            for device in 0..32u8 {
                // SAFETY: `ecam_base` is trusted per the same ordering
                // contract `ComputeDiscovery::new` already documents —
                // `hal_arm64_rust_entry` maps it before either scan runs.
                let header0 = unsafe { read_pci_header(ecam_base, bus, device, 0) };
                let Some(header0) = header0 else {
                    continue;
                };

                let function_count = if header0.header_type & 0x80 != 0 { 8 } else { 1 };

                for function in 0..function_count {
                    // SAFETY: same ordering contract as above.
                    let header = unsafe { read_pci_header(ecam_base, bus, device, function) };
                    let Some(header) = header else {
                        continue;
                    };

                    if header.vendor_id != VIRTIO_PCI_VENDOR_ID {
                        continue;
                    }

                    if device_count >= MAX_SCAN {
                        break 'bus_scan;
                    }

                    // SAFETY: same ordering contract as above.
                    let bar0 = unsafe { probe_bar0(ecam_base, bus, device, function) };
                    let (mmio_base, mmio_size) = bar0.unwrap_or((0, 0));

                    let kind = classify_virtio_pci_device(&header);
                    devices[device_count] = PeripheralDevice::new(kind, mmio_base, mmio_size, 0);
                    device_count += 1;
                }
            }
        }

        for (i, d) in devices.iter_mut().enumerate().take(device_count) {
            d.device_index = i as u32;
        }

        Self { devices, device_count }
    }
}

impl hal_core::peripheral::PeripheralDeviceDiscovery for PeripheralDiscovery {
    fn enumerate_peripheral_devices(&self) -> &[PeripheralDevice] {
        &self.devices[..self.device_count]
    }

    fn device_by_index(&self, device_index: u32) -> Option<&PeripheralDevice> {
        self.enumerate_peripheral_devices()
            .iter()
            .find(|d| d.device_index == device_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_virtio_pci_matches_pci_class_codes() {
        let mk = |class_code: u8| PciDeviceHeader {
            vendor_id: VIRTIO_PCI_VENDOR_ID,
            device_id: 0,
            class_code,
            subclass: 0,
            header_type: 0,
        };
        assert_eq!(classify_virtio_pci_device(&mk(PCI_CLASS_MASS_STORAGE)), PeripheralKind::Block);
        assert_eq!(classify_virtio_pci_device(&mk(PCI_CLASS_NETWORK)), PeripheralKind::Network);
        assert_eq!(classify_virtio_pci_device(&mk(PCI_CLASS_DISPLAY)), PeripheralKind::Gpu);
        assert_eq!(classify_virtio_pci_device(&mk(0xFF)), PeripheralKind::Unknown);
    }

    #[test]
    fn virtio_pci_vendor_id_matches_spec() {
        assert_eq!(VIRTIO_PCI_VENDOR_ID, 0x1AF4);
    }
}
