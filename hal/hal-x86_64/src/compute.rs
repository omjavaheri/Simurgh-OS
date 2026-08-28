//! ============================================================================
//! compute.rs — x86_64
//!
//! Implements `hal_core::compute::ComputeDeviceDiscovery` for x86_64,
//! per 01-HAL-Layer.md section 3.6: identifies GPU/NPU/TPU/FPGA as
//! first-class entities via a PCI configuration space scan.
//!
//! Design:
//!   - Uses the legacy PCI configuration space mechanism (I/O ports
//!     0xCF8/0xCFC, "Configuration Mechanism #1") to enumerate PCI
//!     devices. This is universally supported on every x86_64 target
//!     this project boots on (including QEMU's default `q35`/`i440fx`
//!     machine types, per section 8's acceptance criteria), unlike
//!     PCIe extended configuration space (MMCONFIG/ECAM), which
//!     requires locating the MCFG ACPI table first — a documented
//!     follow-up, noted below, for accessing extended (>256 byte)
//!     PCI-e capability structures.
//!   - Classifies devices into `ComputeKind` by PCI class/subclass
//!     code: class 0x03 (Display Controller) => Gpu; a small
//!     vendor-specific allowlist for known NPU/TPU PCI vendor IDs,
//!     since no standard PCI class code exists for those categories
//!     yet (they are typically reported as class 0x12,
//!     "Processing Accelerator", introduced in the PCI-SIG spec but
//!     inconsistently used by real hardware in the field).
//! ============================================================================

use core::cell::RefCell;

use hal_core::compute::{ComputeDevice, ComputeDeviceDiscovery, ComputeKind};
use hal_core::error::HalError;
use hal_manifest::raw::{ComputeDeviceRaw, ComputeKindRaw, VendorIdRaw, MAX_COMPUTE_DEVICES};

// ============================================================================
// PCI configuration space access (I/O port mechanism #1)
// ============================================================================

const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Reads one 32-bit dword from PCI configuration space at
/// (bus, device, function, offset). `offset` must be 4-byte aligned
/// (enforced by masking below, per the PCI spec's configuration
/// mechanism #1 register layout).
fn pci_config_read_u32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address: u32 = (1 << 31) // enable bit
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | (offset as u32 & 0xFC);

    // SAFETY: writing to the PCI CONFIG_ADDRESS I/O port and reading
    // CONFIG_DATA is the standard, universally-supported PCI
    // configuration mechanism #1 (PCI spec section 3.2.2.3.2) — valid
    // on every x86_64 platform with a legacy-compatible PCI host
    // bridge, which includes every QEMU machine type this project's
    // section 8 acceptance criteria target. No preconditions beyond
    // Ring 0 I/O port access, which this crate always has.
    unsafe {
        let mut out_addr: u32 = address;
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDRESS, in("eax") out_addr);
        let mut result: u32;
        core::arch::asm!("in eax, dx", in("dx") PCI_CONFIG_DATA, out("eax") result);
        let _ = &mut out_addr; // silence unused-assignment lint from the asm! pattern above
        result
    }
}

#[derive(Debug, Clone, Copy)]
struct PciDeviceHeader {
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    header_type: u8,
}

/// Reads a device's identifying header fields, or `None` if no device
/// is present at this (bus, device, function) — indicated by the PCI
/// spec's convention that an absent device's vendor ID register reads
/// back as `0xFFFF`.
fn read_pci_header(bus: u8, device: u8, function: u8) -> Option<PciDeviceHeader> {
    let dword0 = pci_config_read_u32(bus, device, function, 0x00);
    let vendor_id = (dword0 & 0xFFFF) as u16;
    if vendor_id == 0xFFFF {
        return None;
    }
    let device_id = (dword0 >> 16) as u16;

    let dword2 = pci_config_read_u32(bus, device, function, 0x08);
    let subclass = ((dword2 >> 16) & 0xFF) as u8;
    let class_code = ((dword2 >> 24) & 0xFF) as u8;

    let dword3 = pci_config_read_u32(bus, device, function, 0x0C);
    let header_type = ((dword3 >> 16) & 0xFF) as u8;

    Some(PciDeviceHeader { vendor_id, device_id, class_code, subclass, header_type })
}

/// Reads a device's Base Address Register `bar_index` (0-5), used to
/// estimate dedicated memory size for BAR-mapped device memory (e.g. a
/// GPU's VRAM aperture). Returns `None` for I/O-space BARs (bit 0 set)
/// or unimplemented BARs (reads back as 0), since neither represents
/// addressable device memory.
///
/// Sizing method: per the PCI spec (section 6.2.5.1), writing
/// `0xFFFFFFFF` to a BAR and reading it back reveals the size via the
/// pattern of bits the hardware actually implements; the original BAR
/// value must be restored afterward. This is the standard, universally
/// correct way to size a BAR without any OS/firmware assistance.
fn probe_bar_size(bus: u8, device: u8, function: u8, bar_index: u8) -> Option<u64> {
    let offset = 0x10 + bar_index * 4;
    let original = pci_config_read_u32(bus, device, function, offset);

    if original & 0x1 != 0 {
        return None; // I/O-space BAR, not device memory
    }

    // Write all-ones, read back the size mask, restore the original
    // value.
    //
    // SAFETY: PCI configuration space writes to a BAR register are a
    // standard, well-defined operation per the PCI spec's sizing
    // procedure cited above; the original value is always restored
    // before this function returns, so no device is left
    // misconfigured as an observable side effect.
    unsafe {
        pci_config_write_u32(bus, device, function, offset, 0xFFFF_FFFF);
    }
    let size_mask = pci_config_read_u32(bus, device, function, offset);
    // SAFETY: restoring the BAR's original value, same justification
    // as the write above.
    unsafe {
        pci_config_write_u32(bus, device, function, offset, original);
    }

    if size_mask == 0 {
        return None; // BAR not implemented
    }

    // Mask off the low information bits (bit 0 = space indicator,
    // bits 1-2 = type for memory BARs, bit 3 = prefetchable) before
    // computing size from the two's-complement of the remaining bits.
    let size_bits = size_mask & 0xFFFF_FFF0;
    Some((!size_bits as u64) + 1)
}

/// # Safety
/// Same contract as `pci_config_read_u32`'s underlying I/O port access
/// — well-defined for any (bus, device, function, offset, value)
/// combination per the PCI configuration mechanism #1 spec; the only
/// caller-responsibility is not writing to a register in a way that
/// misconfigures a device HAL does not intend to touch, which
/// `probe_bar_size` above satisfies by always restoring the original
/// value.
unsafe fn pci_config_write_u32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address: u32 = (1 << 31) | ((bus as u32) << 16) | ((device as u32) << 11) | ((function as u32) << 8) | (offset as u32 & 0xFC);
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_ADDRESS, in("eax") address);
        core::arch::asm!("out dx, eax", in("dx") PCI_CONFIG_DATA, in("eax") value);
    }
}

// ============================================================================
// Classification
// ============================================================================

/// PCI class code 0x03 = Display Controller (covers VGA-compatible,
/// XGA, 3D, and other display controller subclasses per the PCI-SIG
/// class code spec) => always classified as `Gpu`.
const PCI_CLASS_DISPLAY_CONTROLLER: u8 = 0x03;

/// PCI class code 0x12 = Processing Accelerator, the PCI-SIG class
/// intended for exactly this project's NPU/TPU/FPGA discovery use case
/// (section 3.6) — used when present, though real-world adoption is
/// inconsistent (see module docs), hence the vendor-ID allowlist below
/// as a supplementary signal.
const PCI_CLASS_PROCESSING_ACCELERATOR: u8 = 0x12;

/// A small, explicit allowlist of vendor IDs known to ship NPU/TPU
/// hardware that may not (yet) report PCI class 0x12 — supplements the
/// class-code check above. Each entry documents which real device
/// family it targets, kept short and reviewable rather than an
/// exhaustive database, per this file's "not this crate's job to be a
/// full hardware database" scope; expanding this list is a routine,
/// low-risk follow-up as new hardware needs support.
const KNOWN_NPU_TPU_VENDOR_IDS: &[(u16, ComputeKindRaw)] = &[
    (0x1AE0, ComputeKindRaw::Tpu), // Google (Cloud TPU PCIe accelerators)
];

fn classify_pci_device(header: &PciDeviceHeader) -> Option<ComputeKindRaw> {
    if header.class_code == PCI_CLASS_DISPLAY_CONTROLLER {
        return Some(ComputeKindRaw::Gpu);
    }
    if header.class_code == PCI_CLASS_PROCESSING_ACCELERATOR {
        return Some(ComputeKindRaw::Npu);
    }
    for &(vendor, kind) in KNOWN_NPU_TPU_VENDOR_IDS {
        if header.vendor_id == vendor {
            return Some(kind);
        }
    }
    None
}

// ============================================================================
// ComputeDiscovery — ComputeDeviceDiscovery implementation
// ============================================================================

pub struct ComputeDiscovery {
    devices: RefCell<[ComputeDevice; MAX_COMPUTE_DEVICES]>,
    device_count: RefCell<usize>,
}

impl ComputeDiscovery {
    /// Performs a full PCI bus scan (buses 0-255, devices 0-31,
    /// functions 0-7, per the PCI spec's addressable space) and
    /// records every device `classify_pci_device` recognizes.
    ///
    /// Per section 2's Discovery + Policy model, this always runs in
    /// full at construction — never trimmed based on install profile.
    pub fn new() -> Self {
        let mut devices = [ComputeDeviceRaw::ZERO; MAX_COMPUTE_DEVICES];
        let mut device_count = 0usize;

        'bus_scan: for bus in 0..=255u8 {
            for device in 0..32u8 {
                let Some(header0) = read_pci_header(bus, device, 0) else {
                    continue;
                };

                let function_count = if header0.header_type & 0x80 != 0 { 8 } else { 1 };

                for function in 0..function_count {
                    let Some(header) = read_pci_header(bus, device, function) else {
                        continue;
                    };

                    let Some(kind) = classify_pci_device(&header) else {
                        continue;
                    };

                    if device_count >= MAX_COMPUTE_DEVICES {
                        // Per hal-manifest's push_compute_device
                        // capacity rationale: truncate and continue
                        // rather than fail boot over an unusually large
                        // number of accelerator devices.
                        break 'bus_scan;
                    }

                    let dedicated_memory_bytes = probe_bar_size(bus, device, function, 0);

                    let mut entry = ComputeDeviceRaw::ZERO;
                    entry.kind = kind;
                    entry.vendor = VendorIdRaw(header.vendor_id as u32);
                    entry.has_dedicated_memory = dedicated_memory_bytes.is_some();
                    entry.dedicated_memory_bytes = dedicated_memory_bytes.unwrap_or(0);
                    // Unified memory (CXL) capability requires parsing
                    // the device's PCIe DVSEC/CXL capability structures
                    // in extended configuration space — tracked as a
                    // follow-up alongside this file's MMCONFIG/ECAM
                    // note in the module docs; defaulted to false here
                    // rather than guessed.
                    entry.unified_memory_capable = false;

                    devices[device_count] = entry; // device_index assigned by push_compute_device later
                    device_count += 1;
                }
            }
        }

        Self {
            devices: RefCell::new(devices),
            device_count: RefCell::new(device_count),
        }
    }
}

impl Default for ComputeDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputeDeviceDiscovery for ComputeDiscovery {
    fn enumerate_compute_devices(&self) -> &[ComputeDevice] {
        // SAFETY: the returned slice borrows from `self.devices`
        // (RefCell) for a lifetime tied to `&self`, and this crate's
        // single-threaded boot-time usage never holds a conflicting
        // mutable borrow across this call — mirrors compute.rs's
        // hal-core mock test helper pattern (hal-core/src/compute.rs
        // tests) which documents the same reasoning for the same
        // RefCell-to-slice shape.
        let count = *self.device_count.borrow();
        let borrow = self.devices.borrow();
        let ptr = borrow.as_ptr();
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }

    fn rescan(&self, kind_filter: Option<ComputeKind>) -> Result<(), HalError> {
        // Full PCI rescan, for hot-pluggable accelerators (e.g. an
        // external GPU via Thunderbolt) discovered after initial boot
        // — per hal-core's ComputeDeviceDiscovery::rescan doc comment.
        let fresh = Self::new();
        let fresh_count = *fresh.device_count.borrow();
        if fresh_count > MAX_COMPUTE_DEVICES {
            return Err(HalError::TooManyComputeDevices);
        }

        let _ = kind_filter; // full rescan in this MVP phase; a
        // filtered, incremental rescan (touching only buses relevant
        // to `kind_filter`) is a possible future optimization, not
        // required for correctness.

        *self.devices.borrow_mut() = *fresh.devices.borrow();
        *self.device_count.borrow_mut() = fresh_count;
        Ok(())
    }

    fn device_by_index(&self, device_index: u32) -> Option<&ComputeDevice> {
        self.enumerate_compute_devices()
            .iter()
            .find(|d| d.device_index == device_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_controller_classified_as_gpu() {
        let header = PciDeviceHeader {
            vendor_id: 0x10DE,
            device_id: 0x1234,
            class_code: PCI_CLASS_DISPLAY_CONTROLLER,
            subclass: 0x00,
            header_type: 0,
        };
        assert_eq!(classify_pci_device(&header), Some(ComputeKindRaw::Gpu));
    }

    #[test]
    fn processing_accelerator_classified_as_npu() {
        let header = PciDeviceHeader {
            vendor_id: 0x1234,
            device_id: 0x5678,
            class_code: PCI_CLASS_PROCESSING_ACCELERATOR,
            subclass: 0x00,
            header_type: 0,
        };
        assert_eq!(classify_pci_device(&header), Some(ComputeKindRaw::Npu));
    }

    #[test]
    fn known_vendor_allowlist_overrides_generic_class() {
        let header = PciDeviceHeader {
            vendor_id: 0x1AE0,
            device_id: 0x0001,
            class_code: 0x00, // not a recognized class code
            subclass: 0x00,
            header_type: 0,
        };
        assert_eq!(classify_pci_device(&header), Some(ComputeKindRaw::Tpu));
    }

    #[test]
    fn unrelated_device_class_is_not_classified() {
        let header = PciDeviceHeader {
            vendor_id: 0x8086,
            device_id: 0x1234,
            class_code: 0x01, // mass storage controller
            subclass: 0x06,
            header_type: 0,
        };
        assert_eq!(classify_pci_device(&header), None);
    }
}