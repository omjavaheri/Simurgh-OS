//! ============================================================================
//! peripheral.rs — RISC-V (RV64GC)
//!
//! Implements `hal_core::peripheral::PeripheralDeviceDiscovery` for
//! RISC-V, by walking the SAME Device Tree Blob `memory.rs`'s own FDT
//! walker parses (see that file's own module docs for the FDT-only, no
//! ACPI/UEFI, rationale), looking for `compatible = "virtio,mmio"` nodes
//! — QEMU's `virt` machine exposes every virtio device (block, net, ...)
//! through this SAME MMIO transport, one node per slot (confirmed via a
//! device-tree dump of this project's own pinned QEMU version: 8 slots,
//! `0x1000_1000`-`0x1000_8000`, 4 KiB apart, `interrupts` = the PLIC
//! source number directly, one cell).
//!
//! See `hal_core::peripheral`'s own module doc comment for why this is a
//! separate discovery surface from `compute.rs`'s `ComputeDeviceDiscovery`
//! (GPU/NPU/TPU/FPGA-only, per 01-HAL-Layer.md section 3.6).
//!
//! A `virtio,mmio` node only proves a TRANSPORT slot exists — WHICH
//! virtio device (if any) is actually plugged into it is a runtime
//! property (the `DEVICE_ID` register, virtio-mmio spec §4.2.2), not a
//! Device Tree property, so this file also does one raw, volatile,
//! pre-paging MMIO read per discovered slot to classify it — the exact
//! same "raw physical `read_volatile` at this exact boot stage" pattern
//! `compute.rs`'s own `ecam_read_u32` already establishes for PCI ECAM.
//! An unpopulated slot (QEMU always exposes all of them, empty or not)
//! reads `MAGIC_VALUE` as anything other than `"virt"` and is skipped.
//! ============================================================================

use hal_manifest::raw::{PeripheralDeviceRaw as PeripheralDevice, PeripheralKindRaw as PeripheralKind};

use crate::memory::{FdtHeader, FdtWalker, FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_NOP, FDT_PROP};

/// Capacity for this walker's own scratch storage during discovery —
/// matches `hal_manifest::raw::MAX_PERIPHERAL_DEVICES` (the manifest's
/// own cap), not this platform's actual slot count (8 on riscv64
/// `virt`), so a future QEMU machine revision with more slots is not
/// silently truncated below the manifest's own documented capacity.
const MAX_SCAN: usize = hal_manifest::raw::MAX_PERIPHERAL_DEVICES;

/// virtio-mmio register offsets this file reads directly (virtio 1.x
/// spec §4.2.2) — a small, local subset of `driver_virtio_blk::mmio`'s
/// own table (that crate is a `subsystems/*` layer-3 dependency this
/// `hal-*` crate must never depend on, per the strict bottom-up
/// dependency direction — 01-HAL-Layer.md section 0).
mod mmio {
    pub const MAGIC_VALUE: u64 = 0x000;
    pub const DEVICE_ID: u64 = 0x008;
}

/// `"virt"` read little-endian as a u32 — virtio-mmio spec §4.2.2's
/// fixed magic value confirming a slot is a real virtio-mmio transport
/// (populated or not; an EMPTY slot on QEMU's `virt` machine still
/// reads this magic, per the spec's own "MagicValue... always present"
/// wording — `DEVICE_ID` is what actually distinguishes populated from
/// empty).
const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

/// Maps a virtio-mmio `DEVICE_ID` register value (virtio 1.x spec §5,
/// "Device Types") to this project's own `PeripheralKind`. `0` is the
/// spec's own "no device present" value for an empty slot.
fn classify_device_id(device_id: u32) -> Option<PeripheralKind> {
    match device_id {
        0 => None,
        1 => Some(PeripheralKind::Network),
        2 => Some(PeripheralKind::Block),
        3 => Some(PeripheralKind::Console),
        16 => Some(PeripheralKind::Gpu),
        _ => Some(PeripheralKind::Unknown),
    }
}

/// Reads one virtio-mmio slot's `MAGIC_VALUE`/`DEVICE_ID` registers and
/// classifies it. Returns `None` for an unpopulated slot (bad magic, or
/// `DEVICE_ID == 0`).
///
/// # Safety
/// `mmio_base` must be a valid, readable virtio-mmio transport window's
/// physical base address — true for every `reg` this file's own DTB
/// walk reports, per the SAME "physical addressing works pre-paging at
/// this boot stage" contract `compute.rs`'s `ecam_read_u32` already
/// relies on.
unsafe fn probe_virtio_slot(mmio_base: u64) -> Option<PeripheralKind> {
    // SAFETY: forwarded from this function's own contract.
    let magic = unsafe { ((mmio_base + mmio::MAGIC_VALUE) as *const u32).read_volatile() };
    if magic != VIRTIO_MMIO_MAGIC {
        return None;
    }
    // SAFETY: forwarded from this function's own contract.
    let device_id = unsafe { ((mmio_base + mmio::DEVICE_ID) as *const u32).read_volatile() };
    classify_device_id(device_id)
}

/// Walks the FDT structure block looking for every node whose name
/// starts with `virtio_mmio@`, reading its `reg` (address-cells=2,
/// size-cells=2, per the root node's own cells — confirmed via this
/// project's own device-tree dump) and `interrupts` (one cell: the PLIC
/// source number directly) properties, then classifying each via
/// `probe_virtio_slot`. Mirrors `memory.rs`'s own `walk_device_tree`
/// shape (single current-node tracking, no full tree) but scoped to
/// this one node kind, since it can find MANY matches (unlike that
/// function's "exactly one memory/plic node" scope).
///
/// # Safety
/// `dtb_phys` must be a valid FDT blob physical address — same contract
/// as `memory.rs`'s `walk_device_tree`.
unsafe fn discover_virtio_mmio_devices(dtb_phys: *const u8) -> ([PeripheralDevice; MAX_SCAN], usize) {
    let mut devices = [PeripheralDevice::ZERO; MAX_SCAN];
    let mut count = 0usize;

    // SAFETY: forwarded from this function's own contract.
    let Some(header) = (unsafe { FdtHeader::read(dtb_phys) }) else {
        return (devices, count);
    };
    // SAFETY: forwarded from this function's own contract; header just
    // validated above.
    let mut walker = unsafe { FdtWalker::new(dtb_phys, &header) };

    let mut in_virtio_node = false;
    let mut node_depth: i32 = -1;
    let mut depth: i32 = 0;
    let mut cur_base: Option<u64> = None;
    let mut cur_size: Option<u64> = None;
    let mut cur_irq: Option<u32> = None;

    loop {
        if walker.offset >= walker.struct_end || count >= MAX_SCAN {
            break;
        }

        // SAFETY: bounds-checked by the loop condition above.
        let token = unsafe { walker.read_u32_at(walker.offset) };
        walker.offset += 4;

        match token {
            FDT_BEGIN_NODE => {
                // SAFETY: node name is a NUL-terminated string
                // immediately following the token, within blob bounds.
                let name = unsafe { walker.read_cstr_at(walker.offset) };
                walker.offset += name.len() as u32 + 1;
                walker.align_offset();
                depth += 1;

                if !in_virtio_node && name.starts_with(b"virtio_mmio@") {
                    in_virtio_node = true;
                    node_depth = depth;
                    cur_base = None;
                    cur_size = None;
                    cur_irq = None;
                }
            }

            FDT_END_NODE => {
                if in_virtio_node && depth == node_depth {
                    if let (Some(base), Some(size)) = (cur_base, cur_size) {
                        // SAFETY: `base` came directly from this node's
                        // own `reg` property — a physical MMIO window
                        // address per this function's own contract.
                        if let Some(kind) = unsafe { probe_virtio_slot(base) } {
                            devices[count] = PeripheralDevice::new(kind, base, size, cur_irq.unwrap_or(0));
                            count += 1;
                        }
                    }
                    in_virtio_node = false;
                    node_depth = -1;
                }
                depth -= 1;
            }

            FDT_PROP => {
                // SAFETY: property header (len, nameoff) is 8 bytes
                // immediately following the token, within blob bounds.
                let len = unsafe { walker.read_u32_at(walker.offset) };
                let nameoff = unsafe { walker.read_u32_at(walker.offset + 4) };
                let value_offset = walker.offset + 8;
                walker.offset = value_offset + len;
                walker.align_offset();

                if in_virtio_node {
                    // SAFETY: nameoff points within the strings block
                    // per dtspec's own guarantee.
                    let prop_name = unsafe { walker.read_cstr_at(walker.strings_start + nameoff) };
                    if prop_name == b"reg" && len >= 16 {
                        // SAFETY: value_offset..value_offset+16 is
                        // within blob bounds per `len >= 16`.
                        let base_hi = unsafe { walker.read_u32_at(value_offset) } as u64;
                        let base_lo = unsafe { walker.read_u32_at(value_offset + 4) } as u64;
                        let size_hi = unsafe { walker.read_u32_at(value_offset + 8) } as u64;
                        let size_lo = unsafe { walker.read_u32_at(value_offset + 12) } as u64;
                        cur_base = Some((base_hi << 32) | base_lo);
                        cur_size = Some((size_hi << 32) | size_lo);
                    } else if prop_name == b"interrupts" && len >= 4 {
                        // SAFETY: value_offset..value_offset+4 is within
                        // blob bounds per `len >= 4`.
                        cur_irq = Some(unsafe { walker.read_u32_at(value_offset) });
                    }
                }
            }

            FDT_NOP => {}
            FDT_END => break,
            _ => break, // malformed/unknown token — same defensive stop
                        // `memory.rs`'s own walker documents.
        }
    }

    (devices, count)
}

// ============================================================================
// PeripheralDiscovery — PeripheralDeviceDiscovery implementation
// ============================================================================

pub struct PeripheralDiscovery {
    devices: [PeripheralDevice; MAX_SCAN],
    device_count: usize,
}

impl PeripheralDiscovery {
    /// Walks the FDT once for every virtio-mmio slot. Per section 2's
    /// Discovery + Policy model, this always runs in full at
    /// construction — never trimmed based on install profile.
    ///
    /// # Safety
    /// `dtb_phys` must be a valid FDT blob physical address — same
    /// contract as `memory::Memory::from_device_tree`, this crate's
    /// other DTB-consuming constructor.
    pub unsafe fn new(dtb_phys: *const u8) -> Self {
        // SAFETY: forwarded from this function's own contract.
        let (devices, device_count) = unsafe { discover_virtio_mmio_devices(dtb_phys) };
        let mut devices = devices;
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
    fn classify_device_id_matches_virtio_spec() {
        assert_eq!(classify_device_id(0), None);
        assert_eq!(classify_device_id(1), Some(PeripheralKind::Network));
        assert_eq!(classify_device_id(2), Some(PeripheralKind::Block));
        assert_eq!(classify_device_id(3), Some(PeripheralKind::Console));
        assert_eq!(classify_device_id(16), Some(PeripheralKind::Gpu));
        assert_eq!(classify_device_id(999), Some(PeripheralKind::Unknown));
    }

    #[test]
    fn virtio_mmio_magic_matches_spec_ascii() {
        assert_eq!(&VIRTIO_MMIO_MAGIC.to_le_bytes(), b"virt");
    }
}
