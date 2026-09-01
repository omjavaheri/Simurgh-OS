//! ============================================================================
//! driver-virtio-net
//!
//! Purpose: the MVP network driver — virtio-net (03-Kernel-Subsystems-
//! Layer.md §2.3/§5.4) over EITHER of two transports (`Transport`'s own
//! doc comment): virtio-mmio (riscv64, Device Tree discovery) or
//! virtio-pci "modern" (aarch64/x86_64, PCI/ECAM discovery) — mirrors
//! `driver_virtio_blk::Transport`'s own shape exactly, one session later.
//!
//! TX completion is now genuinely interrupt-driven (PLIC/MSI-X/legacy
//! INTx, matching `driver_virtio_blk`'s own IRQ-line wiring exactly —
//! `kernel_arch_glue::wire_virtio_pci_transport_net` programs MSI-X on
//! x86_64 the same way `wire_virtio_pci_transport` does for blk): a
//! transmit queue completion is a LOCAL virtqueue event the device
//! always eventually produces on its own, regardless of network
//! conditions, so a bounded real `Wait` (this crate's own module doc
//! comment continues below) is exactly as safe as `driver_virtio_blk`'s
//! own interrupt-driven I/O.
//!
//! RX (`PollFrame`) DELIBERATELY stays a single non-blocking used-ring
//! check, NOT converted to a blocking `Wait` — this is a considered
//! choice, not unfinished work: a network reply may never arrive at all
//! (unlike a local block read/write or a local TX completion, both of
//! which the device always eventually produces on its own), and this
//! kernel has no `Wait`-with-timeout primitive — a `SyscallOp::Wait` on
//! a `Notification` that never gets signalled again blocks the calling
//! thread PERMANENTLY, with no way to un-block it. Making `PollFrame`
//! itself block on the IRQ notification would trade the current design's
//! bounded-by-retry-COUNT worst case (the outer caller's own finite
//! `Call` retry loop, `kernel_arch_glue`'s own net demo) for a genuinely
//! unbounded one (a single lost reply wedges this driver process
//! forever, unrecoverable). The caller retrying non-blocking `PollFrame`
//! `Call`s is therefore the correct design for "might never arrive"
//! traffic, not a limitation — see `poll_rx`'s own doc comment.
//!
//! Runs as its own isolated process, implements `driver_framework::
//! DeviceDriver`, and serves `DriverRequest::{SendFrame,PollFrame}` by
//! driving TWO virtio virtqueues (receiveq1/transmitq1, spec §5.1.2).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (driver
//! process model, shared with every other driver crate), §2.3 (Netstack
//! talks to the network device through the Device Manager + a capability
//! scoped to it), §5.4 (Netstack ICMP echo over virtio-net is the MVP
//! acceptance demo).
//!
//! Position in the system: layer-3 process, spawned by `kernel_arch_glue::
//! spawn_virtio_net_driver`. Its virtio register window(s) (discovered by
//! the HAL peripheral scan, `hal_core::peripheral`, and — for `Transport::
//! Pci` only — resolved from a real PCI capability-list walk `kernel_
//! arch_glue` performs at spawn time, never this crate) are pre-mapped
//! directly into its address space at spawn time, exactly like `driver_
//! virtio_blk`'s own trusted-bootstrap pattern. TWO virtqueue/buffer
//! `SharedRegion`s (one per queue — see `layout`'s own doc comment for
//! why this driver needs two separate regions where `driver_virtio_blk`
//! gets by with one) are pre-mapped the same way.
//!
//! MVP scope: `do_probe` runs the virtio 1.x device-init handshake for
//! BOTH queues and negotiates ONLY `VIRTIO_F_VERSION_1` (mandatory) plus
//! `VIRTIO_NET_F_MAC` (if the device offers it, to read a real MAC from
//! config space rather than a hardcoded fallback — QEMU's own virtio-net
//! backend always offers it). No offload features (checksum/TSO/GSO/
//! MRG_RXBUF) are negotiated, matching the fixed 12-byte `virtio_net_hdr_
//! v1` this driver always writes/expects. Completion is a bounded busy-
//! poll on each queue's own used ring — `submit_tx` blocks (bounded) for
//! its own completion; `poll_rx` is explicitly non-blocking (a single
//! check), because unlike a block read a network reply may never arrive
//! at all, so the caller (this driver's own `subsystem_entry.rs`, driven
//! in turn by `kernel_arch_glue`'s own demo sequencing) is the one that
//! retries across separate `Call`s.
//!
//! Safety/invariants: every MMIO/PCI/virtqueue-memory access goes through
//! `read_volatile`/`write_volatile` with a `// SAFETY:` note tying it to
//! the caller's "already mapped" contract (`self.ready`), mirroring
//! `driver_virtio_blk` exactly.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod subsystem_entry;

use driver_framework::{DeviceDriver, DeviceInfo, DriverError};
use ipc_protocol::driver::DriverErrorCode;
use ipc_protocol::{DriverRequest, DriverResponse};

/// virtio-mmio register offsets (virtio 1.x spec §4.2.2, "modern"/
/// version-2 transport) — numerically identical to `driver_virtio_blk::
/// mmio`'s own module (the register FILE is the same for every virtio-
/// mmio device; only `DEVICE_ID`'s own VALUE and the device-specific
/// `CONFIG` layout differ). Redefined here rather than shared, matching
/// this project's established one-crate-owns-its-own-register-map layout
/// (no `virtio-common` crate exists).
pub mod mmio {
    /// `0x74726976` ("virt" LE) if a virtio-mmio device is present.
    pub const MAGIC_VALUE: usize = 0x000;
    /// Device version (2 for virtio 1.x / "modern").
    pub const VERSION: usize = 0x004;
    /// Device type (1 = network device, spec §5).
    pub const DEVICE_ID: usize = 0x008;
    /// Device feature bits, 32 at a time — which 32 selected by
    /// `DEVICE_FEATURES_SEL`.
    pub const DEVICE_FEATURES: usize = 0x010;
    /// Selects which 32-bit word of `DEVICE_FEATURES` is visible.
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    /// Driver feature bits accepted, 32 at a time.
    pub const DRIVER_FEATURES: usize = 0x020;
    /// Selects which 32-bit word `DRIVER_FEATURES` writes.
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    /// Driver status register.
    pub const STATUS: usize = 0x070;
    /// Selected queue index.
    pub const QUEUE_SEL: usize = 0x030;
    /// Max size of the selected queue (0 = unavailable).
    pub const QUEUE_NUM_MAX: usize = 0x034;
    /// Size to use for the selected queue.
    pub const QUEUE_NUM: usize = 0x038;
    /// Queue ready flag.
    pub const QUEUE_READY: usize = 0x044;
    /// Notify the device that the selected queue has new buffers.
    pub const QUEUE_NOTIFY: usize = 0x050;
    /// Interrupt status (bit 0: used-ring update).
    pub const INTERRUPT_STATUS: usize = 0x060;
    /// Acknowledge handled interrupts.
    pub const INTERRUPT_ACK: usize = 0x064;
    /// Descriptor table physical address, low/high 32 bits.
    pub const QUEUE_DESC_LOW: usize = 0x080;
    /// High 32 bits of the descriptor table physical address.
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    /// Driver (avail) ring physical address, low 32 bits.
    pub const QUEUE_DRIVER_LOW: usize = 0x090;
    /// High 32 bits of the avail ring physical address.
    pub const QUEUE_DRIVER_HIGH: usize = 0x094;
    /// Device (used) ring physical address, low 32 bits.
    pub const QUEUE_DEVICE_LOW: usize = 0x0a0;
    /// High 32 bits of the used ring physical address.
    pub const QUEUE_DEVICE_HIGH: usize = 0x0a4;
    /// Device-specific config space (`virtio_net_config`: `mac[6]` first,
    /// spec §5.1.4).
    pub const CONFIG: usize = 0x100;
}

/// `STATUS` register bits (virtio 1.x spec §2.1) — identical semantics to
/// `driver_virtio_blk::status`, redefined for the same "each crate owns
/// its own register map" reason as `mmio` above.
pub mod status {
    /// Guest OS has found the device and recognized it as valid.
    pub const ACKNOWLEDGE: u32 = 1;
    /// Guest OS knows how to drive the device.
    pub const DRIVER: u32 = 2;
    /// Something went wrong; the driver has given up.
    pub const FAILED: u32 = 128;
    /// The driver has acknowledged the negotiated feature set.
    pub const FEATURES_OK: u32 = 8;
    /// The driver is set up and ready to drive the device.
    pub const DRIVER_OK: u32 = 4;
}

/// virtio-pci "modern" transport (spec §4.1.4) register layouts — offsets
/// WITHIN whichever BAR+offset window the device's own PCI capability
/// list (spec §4.1.4, cap_id 0x09) resolved for each `cfg_type`.
/// Numerically identical to `driver_virtio_blk::pci_common`'s own module
/// (the virtio-pci register FILE is the same regardless of device type —
/// only `DEVICE_CFG`'s own contents differ) — redefined here rather than
/// shared, matching this project's established one-crate-owns-its-own-
/// register-map layout.
pub mod pci_common {
    /// le32 — selects which 32-bit word `DEVICE_FEATURE` reads.
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    /// le32.
    pub const DEVICE_FEATURE: usize = 0x04;
    /// le32 — selects which 32-bit word `DRIVER_FEATURE` writes.
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    /// le32.
    pub const DRIVER_FEATURE: usize = 0x0c;
    /// u8 — same semantics as virtio-mmio's `STATUS`, different width.
    pub const DEVICE_STATUS: usize = 0x14;
    /// le16 — selects which queue the fields below name.
    pub const QUEUE_SELECT: usize = 0x16;
    /// le16, read-write: read for `QUEUE_NUM_MAX`, written for
    /// `QUEUE_NUM` — the same register serves both roles in the PCI
    /// layout (unlike MMIO's two separate registers).
    pub const QUEUE_SIZE: usize = 0x18;
    /// le16 — write 1 once this queue's addresses below are set, the
    /// PCI equivalent of MMIO's `QUEUE_READY`.
    pub const QUEUE_ENABLE: usize = 0x1c;
    /// le16 — this queue's own offset (in `notify_off_multiplier`
    /// units) into the NOTIFY_CFG BAR window; read once per queue during
    /// `probe` and cached (`rx_notify_off`/`tx_notify_off`).
    pub const QUEUE_NOTIFY_OFF: usize = 0x1e;
    /// le64.
    pub const QUEUE_DESC: usize = 0x20;
    /// le64.
    pub const QUEUE_DRIVER: usize = 0x28;
    /// le64.
    pub const QUEUE_DEVICE: usize = 0x30;
    /// le16, PER-QUEUE (governed by whatever `QUEUE_SELECT` currently
    /// names) — assigns the currently-selected queue's own completions
    /// to an MSI-X table entry. Numerically identical to `driver_virtio_
    /// blk::pci_common::QUEUE_MSIX_VECTOR` — see that constant's own doc
    /// comment for the real bug (device RESET during `do_probe` clears
    /// any earlier assignment) this driver's own `write_queue_msix_
    /// vector` call, from inside `do_probe`'s per-queue setup loop,
    /// exists to avoid.
    pub const QUEUE_MSIX_VECTOR: usize = 0x1a;
}

/// `VIRTIO_MSI_NO_VECTOR` (virtio 1.x spec §4.1.4.3) — the reset default
/// / "no vector assigned" sentinel `write_queue_msix_vector` writes for
/// `Transport::Mmio` (harmless there — see that method's own doc
/// comment) and whatever `new`'s own default leaves `msix_vector` at
/// before `kernel_arch_glue`'s own PCI wiring ever overwrites it via
/// `new_pci`. Numerically identical to `driver_virtio_blk::
/// VIRTIO_MSI_NO_VECTOR`.
pub const VIRTIO_MSI_NO_VECTOR: u16 = 0xFFFF;

/// `VIRTIO_F_VERSION_1` (feature bit 32, word index 1) — mandatory for the
/// modern transport this driver speaks, same as `driver_virtio_blk`'s own.
pub const VIRTIO_F_VERSION_1: u32 = 1 << (32 - 32);
/// `VIRTIO_NET_F_MAC` (feature bit 5, word index 0, spec §5.1.3) —
/// negotiated ONLY if the device actually offers it (QEMU's own virtio-net
/// backend always does); when present, `do_probe` reads a real MAC from
/// `virtio_net_config::mac` instead of using `FALLBACK_MAC`.
pub const VIRTIO_NET_F_MAC: u32 = 1 << 5;

/// A locally-administered, clearly-synthetic MAC (`02:...` — the
/// "locally administered, unicast" bit pattern, RFC-reserved for exactly
/// this "no real vendor OUI" use) used ONLY if a device somehow does not
/// offer `VIRTIO_NET_F_MAC` — QEMU's own backend always does, so this path
/// is defensive, not exercised in this project's own QEMU testing.
pub const FALLBACK_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// Fixed virtqueue size this driver sets up for EACH of its two queues —
/// same power-of-2 requirement `driver_virtio_blk::QUEUE_SIZE`'s own doc
/// comment documents in full (QEMU's own virtio-mmio ring-index
/// wraparound is `idx & (QUEUE_SIZE - 1)`, only correct for a power of 2).
/// `2` is the smallest legal power of 2; this driver only ever keeps ONE
/// descriptor chain in flight per queue (MVP scope, mirroring
/// `driver_virtio_blk`'s own one-request-in-flight philosophy), so one
/// slot goes unused per queue — costs nothing.
pub const QUEUE_SIZE: u16 = 2;

/// receiveq1 (spec §5.1.2) — the only RX queue when `VIRTIO_NET_F_MQ`
/// (multiqueue) is not negotiated, which this driver never does.
pub const RX_QUEUE: u32 = 0;
/// transmitq1 (spec §5.1.2) — the only TX queue, same condition.
pub const TX_QUEUE: u32 = 1;

/// The 12-byte `struct virtio_net_hdr_v1` (spec §5.1.6.1) this driver
/// always prepends to a TX frame and always expects prepended to an RX
/// frame. **Real bug found via QEMU packet capture**: this was FIRST
/// written as 10 bytes — the LEGACY `struct virtio_net_hdr` size, correct
/// only when `VIRTIO_F_VERSION_1` has NOT been negotiated. Spec §5.1.6.1
/// is explicit that once `VIRTIO_F_VERSION_1` IS negotiated (which this
/// driver's own `do_probe` always does — it is the mandatory bit for the
/// modern transport this driver speaks at all, `VIRTIO_F_VERSION_1`'s own
/// doc comment), the driver MUST use `struct virtio_net_hdr_v1` instead
/// — 12 bytes, with a trailing `num_buffers` field the wire format always
/// carries even when `VIRTIO_NET_F_MRG_RXBUF` itself is not negotiated
/// (unlike the legacy struct, which omits that field entirely). Getting
/// this wrong by exactly 2 bytes was caught by attaching a QEMU
/// `-object filter-dump` packet capture to the `-netdev user` backend:
/// the ONE captured outbound frame was missing its first 2 bytes (a
/// broadcast destination MAC that should read `ff ff ff ff ff ff` instead
/// began right at its 5th byte) — proof the device was consuming 2 MORE
/// header bytes than this driver intended.
///
/// Always zero-filled on TX (no GSO/checksum offload requested —
/// `gso_type = VIRTIO_NET_HDR_GSO_NONE = 0` is the all-zero value; the
/// trailing `num_buffers = 0` is likewise harmless — device-only
/// semantics on this leg, spec §5.1.6.2.1).
pub const VIRTIO_NET_HDR_LEN: usize = 12;

/// Largest Ethernet frame (header included) this driver's fixed buffers
/// accept — comfortably covers this project's own MVP traffic (a 42-byte
/// ARP frame, a ~74-98-byte ICMP echo) with generous headroom for
/// whatever else QEMU's slirp network might hand the guest (e.g. an
/// unsolicited broadcast) without truncation.
pub const FRAME_MAX: usize = 700;

// `VIRTQ_DESC_F_NEXT` (bit 0) is unused: every descriptor chain this
// driver builds is exactly ONE descriptor (the `virtio_net_hdr` and frame
// share one contiguous buffer — this crate's own module doc comment), so
// no descriptor ever needs to chain to a `next`.
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// The virtqueue split-ring layout this driver builds inside EACH of its
/// two granted `SharedRegion`s (one for the RX queue, one for the TX
/// queue — unlike `driver_virtio_blk`, which fits its single request
/// queue's descriptor/avail/used tables plus a fixed one-sector data
/// buffer inside ONE page, a `virtio_net_hdr`-prefixed frame buffer on
/// BOTH the RX and TX sides means two independent buffers are needed at
/// once — kernel-arch-glue's own trusted pre-map, mirroring the "map the
/// mmio window AND the queue region separately" pattern it already uses
/// for `driver_virtio_blk`, just with one more region).
///
/// Byte layout (all offsets from the region's own base — identical
/// layout reused for both the RX and TX regions):
///   `0..8`    `queue_phys_base` (u64 LE) — the region's own physical
///             base address, written by `kernel_arch_glue` before this
///             process's first instruction runs (same reasoning as
///             `driver_virtio_blk::layout::PHYS_BASE_OFFSET`'s own doc
///             comment).
///   `8..14`   `MAC_OFFSET`: the negotiated device MAC, written by THIS
///             driver's own `do_probe` (RX region only — see that
///             constant's own doc comment).
///   `16..48`  descriptor table (`QUEUE_SIZE` * 16 bytes = 32 bytes).
///   `48..56`  avail (driver) ring (`4 + QUEUE_SIZE * 2` = 8 bytes).
///   `64..84`  used (device) ring (`4 + QUEUE_SIZE * 8` = 20 bytes).
///   `96..96+48` `PCI_INFO_OFFSET`: RX region only, `Transport::Pci`'s own
///             resolved register-window VAs — see that constant's own
///             doc comment.
///   `256..256+712` the `virtio_net_hdr` (12 bytes) + frame buffer
///             (`FRAME_MAX` = 700 bytes) — descriptor slot 0 always
///             points here (single buffer in flight per queue, MVP
///             scope).
///   `1024..1080` the `DriverRequest`/`DriverResponse` `SmallMessage`
///             marshaling area (RX region ONLY — `subsystem_entry.rs`'s
///             own `read_shared_message`/`write_shared_message` target
///             the RX region exclusively, reusing it rather than
///             requesting a third capability grant, exactly like
///             `driver_virtio_blk`'s own single-region reuse).
pub mod layout {
    /// The region's own physical base address, as a little-endian `u64`.
    pub const PHYS_BASE_OFFSET: usize = 0;
    /// RX region only: the negotiated device MAC (6 bytes), written by
    /// `do_probe`. `kernel_arch_glue`'s own demo reads it directly from
    /// physical memory once its `DRV_NET_PROBE` IPC call returns `Ready`
    /// (proving `do_probe` has already run) — the same "kernel-arch-glue
    /// peeks the driver's own shared region directly, no protocol field
    /// needed" pattern `driver_virtio_blk`'s own demo write path already
    /// uses in the other direction (`drv_blk_write_call`'s `DATA_OFFSET`
    /// write).
    pub const MAC_OFFSET: usize = 8;
    /// The descriptor table (`QUEUE_SIZE` * 16 bytes).
    pub const DESC_OFFSET: usize = 16;
    /// The avail (driver) ring.
    pub const AVAIL_OFFSET: usize = 48;
    /// The used (device) ring.
    pub const USED_OFFSET: usize = 64;
    /// RX region only: the register-window info block `kernel_arch_glue`'s
    /// own PCI capability-list walk resolves at spawn time and writes here
    /// for `Transport::Pci` — this driver process has no other way to
    /// learn it (no PCI-config-space access of its own, and no VA->PA-or-
    /// back translation syscall exists for a non-root thread; same
    /// reasoning as `driver_virtio_blk::layout::PCI_INFO_OFFSET`'s own doc
    /// comment). Comfortably clear of the used ring above (`64..84`) and
    /// the MAC/message regions. Same seven `u64`s as `driver_virtio_blk::
    /// layout::PCI_INFO_OFFSET`, now that TX completion is real
    /// interrupt-driven (this crate's own module doc comment):
    ///   `+0`  `transport_kind` (`0` = `Transport::Mmio`, meaningless —
    ///         the driver uses `DRV_NET_MMIO_VA` directly in that case;
    ///         `1` = `Transport::Pci`, the fields below are real).
    ///   `+8`  `common_cfg_va`
    ///   `+16` `notify_cfg_va`
    ///   `+24` `notify_off_multiplier` (widened to `u64` for uniform
    ///         field width; the real value always fits `u32`)
    ///   `+32` `isr_cfg_va`
    ///   `+40` `device_cfg_va`
    ///   `+48` `msix_vector` (widened to `u64`; the real value always
    ///         fits `u16` — `VIRTIO_MSI_NO_VECTOR` if MSI-X was not
    ///         enabled, e.g. aarch64's own legacy-INTx choice)
    pub const PCI_INFO_OFFSET: usize = 96;
    /// The `virtio_net_hdr` + frame buffer (descriptor slot 0, both
    /// queues).
    pub const BUFFER_OFFSET: usize = 256;
    /// Small-message (`DriverRequest`/`DriverResponse`) marshaling area —
    /// RX region only, see this module's own doc comment.
    pub const MESSAGE_OFFSET: usize = 1024;
}

/// Reads a `u16` from `region_base + offset` (ordinary RAM — the granted
/// `SharedRegion` — so a plain volatile access is enough).
///
/// # Safety
/// `region_base + offset + 2` must be within the mapped `SharedRegion`.
unsafe fn q_read_u16(region_base: usize, offset: usize) -> u16 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((region_base + offset) as *const u16).read_volatile() }
}

/// # Safety
/// `region_base + offset + 2` must be within the mapped `SharedRegion`.
unsafe fn q_write_u16(region_base: usize, offset: usize, value: u16) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((region_base + offset) as *mut u16).write_volatile(value) };
}

/// `#[repr(C)]` mirror of the virtio spec §2.6.5 `struct virtq_desc` —
/// private wire-layout type, redefined per-crate like `driver_virtio_blk`'s
/// own (never shared/exposed).
#[repr(C)]
struct VirtqDescRaw {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Sentinel a bounded busy-poll returns when the used ring never advances
/// — mirrors `driver_virtio_blk::STATUS_TIMEOUT`'s own role.
const MAX_SPINS: u32 = 20_000_000;

/// The transport this driver instance speaks — see each variant's own
/// doc comment. `VirtioNet`'s own probe/submit/poll logic is transport-
/// generic; only the low-level register accessors below branch on this.
/// Mirrors `driver_virtio_blk::Transport` exactly, one session later.
pub enum Transport {
    /// virtio-mmio (riscv64, discovered via Device Tree) — one flat,
    /// always-32-bit register window at `base`.
    Mmio {
        /// Mapped virtual base of the virtio-mmio transport window.
        base: usize,
    },
    /// virtio-pci "modern" (aarch64/x86_64, discovered via PCI/ECAM) —
    /// FOUR independently-located sub-regions, resolved once by `kernel_
    /// arch_glue`'s own PCI capability-list walk at spawn time and pre-
    /// mapped the same trusted way the MMIO window is (this driver
    /// process never parses PCI capabilities itself).
    Pci {
        /// Mapped virtual base of the COMMON_CFG sub-region
        /// (`pci_common`'s own offsets, cfg_type 1).
        common: usize,
        /// Mapped virtual base of the NOTIFY_CFG sub-region (cfg_type
        /// 2) — a specific queue's own doorbell lives at `notify +
        /// queue_notify_off * notify_off_multiplier`, a le16 write.
        notify: usize,
        /// `notify_off_multiplier` from the device's own `virtio_pci_
        /// notify_cap` (the NOTIFY_CFG capability's own trailing field
        /// beyond the base `virtio_pci_cap` struct).
        notify_off_multiplier: u32,
        /// Mapped virtual base of the ISR_CFG sub-region (cfg_type 3) —
        /// a single u8, read-to-clear (spec §4.1.4.5).
        isr: usize,
        /// Mapped virtual base of the DEVICE_CFG sub-region (cfg_type
        /// 4) — device-specific config space (the MAC), the PCI
        /// equivalent of MMIO's `CONFIG` region.
        device_cfg: usize,
    },
}

/// The virtio-net driver state.
pub struct VirtioNet {
    /// The transport this instance speaks.
    transport: Transport,
    /// Mapped virtual base of the RX queue's own `SharedRegion` (also
    /// carries the negotiated MAC, the `Transport::Pci` info block, and
    /// the message-marshaling area — see `layout`'s own doc comment).
    rx_base: usize,
    /// Mapped virtual base of the TX queue's own `SharedRegion`.
    tx_base: usize,
    /// Whether `probe` has completed.
    ready: bool,
    /// The RX avail/used idx value after the last buffer this driver
    /// posted — same single-descriptor-in-flight semantics as
    /// `driver_virtio_blk::VirtioBlk::next_idx`'s own doc comment,
    /// applied per-queue here.
    rx_next_idx: u16,
    /// Same role as `rx_next_idx`, for the TX queue.
    tx_next_idx: u16,
    /// The negotiated device MAC (all-zero until `do_probe` runs).
    mac: [u8; 6],
    /// `Transport::Pci` only: the RX queue's own `queue_notify_off`
    /// (`pci_common::QUEUE_NOTIFY_OFF`'s own doc comment), read once
    /// during `probe` and cached. Always `0` (harmless — never read) for
    /// `Transport::Mmio`.
    rx_notify_off: u16,
    /// Same role as `rx_notify_off`, for the TX queue — a SEPARATE field
    /// because, unlike `driver_virtio_blk` (one queue only), this driver
    /// has two queues, each with its own independent notify offset.
    tx_notify_off: u16,
    /// `Transport::Pci` only: the MSI-X table entry BOTH queues' own
    /// completions are assigned to (`write_queue_msix_vector`'s own doc
    /// comment) — `VIRTIO_MSI_NO_VECTOR` for `Transport::Mmio` or
    /// whenever `kernel_arch_glue`'s own PCI wiring did not enable MSI-X
    /// (aarch64's own legacy-INTx choice; `wire_virtio_pci_transport_
    /// net`'s own doc comment).
    msix_vector: u16,
}

impl VirtioNet {
    /// Creates the driver bound to a virtio-mmio window mapped at
    /// `mmio_base`, an RX queue region mapped at `rx_base`, and a TX queue
    /// region mapped at `tx_base` (pass 0/0/0 in tests, before any grant
    /// exists).
    pub const fn new(mmio_base: usize, rx_base: usize, tx_base: usize) -> Self {
        Self {
            transport: Transport::Mmio { base: mmio_base },
            rx_base,
            tx_base,
            ready: false,
            rx_next_idx: 0,
            tx_next_idx: 0,
            mac: [0; 6],
            rx_notify_off: 0,
            tx_notify_off: 0,
            msix_vector: VIRTIO_MSI_NO_VECTOR,
        }
    }

    /// Creates the driver bound to a virtio-pci "modern" transport
    /// (`Transport::Pci`'s own doc comment covers each sub-region's role)
    /// and RX/TX queue regions. `msix_vector`: the MSI-X table entry
    /// `kernel_arch_glue`'s own PCI wiring already programmed for BOTH
    /// queues (`VIRTIO_MSI_NO_VECTOR` if MSI-X was not enabled for this
    /// device, e.g. aarch64's own legacy-INTx choice).
    #[allow(clippy::too_many_arguments)]
    pub const fn new_pci(
        common: usize,
        notify: usize,
        notify_off_multiplier: u32,
        isr: usize,
        device_cfg: usize,
        rx_base: usize,
        tx_base: usize,
        msix_vector: u16,
    ) -> Self {
        Self {
            transport: Transport::Pci { common, notify, notify_off_multiplier, isr, device_cfg },
            rx_base,
            tx_base,
            ready: false,
            rx_next_idx: 0,
            tx_next_idx: 0,
            mac: [0; 6],
            rx_notify_off: 0,
            tx_notify_off: 0,
            msix_vector,
        }
    }

    /// Whether every constructor argument is a real (non-zero) mapped
    /// base — `probe`'s own "nothing granted yet" early-return check,
    /// mirroring `driver_virtio_blk::VirtioBlk::transport_is_bound`.
    fn regions_bound(&self) -> bool {
        let transport_bound = match self.transport {
            Transport::Mmio { base } => base != 0,
            Transport::Pci { common, .. } => common != 0,
        };
        transport_bound && self.rx_base != 0 && self.tx_base != 0
    }

    /// The negotiated device MAC (all-zero before `probe` succeeds).
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    // ---- transport-generic register accessors ---------------------
    //
    // Each one branches on `self.transport` and uses whichever width
    // (`u32` for MMIO's uniformly-32-bit registers; the PCI spec's own
    // mixed u8/u16/u32/u64 widths for `Transport::Pci`) that transport's
    // own register actually is — mirrors `driver_virtio_blk`'s own
    // accessor set exactly.

    /// # Safety
    /// The transport's own base(s) must be real, mapped windows.
    unsafe fn read_device_feature(&self, word: u32) -> u32 {
        match self.transport {
            Transport::Mmio { base } => unsafe {
                ((base + mmio::DEVICE_FEATURES_SEL) as *mut u32).write_volatile(word);
                ((base + mmio::DEVICE_FEATURES) as *const u32).read_volatile()
            },
            Transport::Pci { common, .. } => unsafe {
                ((common + pci_common::DEVICE_FEATURE_SELECT) as *mut u32).write_volatile(word);
                ((common + pci_common::DEVICE_FEATURE) as *const u32).read_volatile()
            },
        }
    }

    /// # Safety
    /// Same contract as `read_device_feature`.
    unsafe fn write_driver_feature(&self, word: u32, value: u32) {
        match self.transport {
            Transport::Mmio { base } => unsafe {
                ((base + mmio::DRIVER_FEATURES_SEL) as *mut u32).write_volatile(word);
                ((base + mmio::DRIVER_FEATURES) as *mut u32).write_volatile(value);
            },
            Transport::Pci { common, .. } => unsafe {
                ((common + pci_common::DRIVER_FEATURE_SELECT) as *mut u32).write_volatile(word);
                ((common + pci_common::DRIVER_FEATURE) as *mut u32).write_volatile(value);
            },
        }
    }

    /// # Safety
    /// Same contract as `read_device_feature`.
    unsafe fn read_status(&self) -> u32 {
        match self.transport {
            Transport::Mmio { base } => unsafe { ((base + mmio::STATUS) as *const u32).read_volatile() },
            Transport::Pci { common, .. } => unsafe {
                ((common + pci_common::DEVICE_STATUS) as *const u8).read_volatile() as u32
            },
        }
    }

    /// # Safety
    /// Same contract as `read_device_feature`.
    unsafe fn write_status(&self, value: u32) {
        match self.transport {
            Transport::Mmio { base } => unsafe { ((base + mmio::STATUS) as *mut u32).write_volatile(value) },
            Transport::Pci { common, .. } => unsafe {
                ((common + pci_common::DEVICE_STATUS) as *mut u8).write_volatile(value as u8)
            },
        }
    }

    /// # Safety
    /// Same contract as `read_device_feature`.
    unsafe fn select_queue(&self, idx: u32) {
        match self.transport {
            Transport::Mmio { base } => unsafe { ((base + mmio::QUEUE_SEL) as *mut u32).write_volatile(idx) },
            Transport::Pci { common, .. } => unsafe {
                ((common + pci_common::QUEUE_SELECT) as *mut u16).write_volatile(idx as u16)
            },
        }
    }

    /// # Safety
    /// Same contract as `read_device_feature`; a queue must already be
    /// selected via `select_queue`.
    unsafe fn read_queue_size_max(&self) -> u32 {
        match self.transport {
            Transport::Mmio { base } => unsafe { ((base + mmio::QUEUE_NUM_MAX) as *const u32).read_volatile() },
            Transport::Pci { common, .. } => unsafe {
                ((common + pci_common::QUEUE_SIZE) as *const u16).read_volatile() as u32
            },
        }
    }

    /// # Safety
    /// Same contract as `read_queue_size_max`.
    unsafe fn write_queue_size(&self, size: u32) {
        match self.transport {
            Transport::Mmio { base } => unsafe { ((base + mmio::QUEUE_NUM) as *mut u32).write_volatile(size) },
            Transport::Pci { common, .. } => unsafe {
                ((common + pci_common::QUEUE_SIZE) as *mut u16).write_volatile(size as u16)
            },
        }
    }

    /// # Safety
    /// Same contract as `read_queue_size_max`.
    unsafe fn write_queue_addrs(&self, desc: u64, avail: u64, used: u64) {
        match self.transport {
            Transport::Mmio { base } => unsafe {
                ((base + mmio::QUEUE_DESC_LOW) as *mut u32).write_volatile(desc as u32);
                ((base + mmio::QUEUE_DESC_HIGH) as *mut u32).write_volatile((desc >> 32) as u32);
                ((base + mmio::QUEUE_DRIVER_LOW) as *mut u32).write_volatile(avail as u32);
                ((base + mmio::QUEUE_DRIVER_HIGH) as *mut u32).write_volatile((avail >> 32) as u32);
                ((base + mmio::QUEUE_DEVICE_LOW) as *mut u32).write_volatile(used as u32);
                ((base + mmio::QUEUE_DEVICE_HIGH) as *mut u32).write_volatile((used >> 32) as u32);
            },
            Transport::Pci { common, .. } => unsafe {
                ((common + pci_common::QUEUE_DESC) as *mut u64).write_volatile(desc);
                ((common + pci_common::QUEUE_DRIVER) as *mut u64).write_volatile(avail);
                ((common + pci_common::QUEUE_DEVICE) as *mut u64).write_volatile(used);
            },
        }
    }

    /// Marks the currently-selected queue live — MMIO's `QUEUE_READY` /
    /// PCI's `QUEUE_ENABLE`, the same semantic bit. For `Transport::Pci`
    /// ALSO reads `queue_notify_off` and returns it (the caller stores it
    /// into whichever of `rx_notify_off`/`tx_notify_off` matches the
    /// queue just enabled — this driver has TWO independently-selected
    /// queues, unlike `driver_virtio_blk`'s single one, so the caller
    /// must route the returned value itself). `0` (harmless) for
    /// `Transport::Mmio`.
    ///
    /// # Safety
    /// Same contract as `read_queue_size_max`.
    unsafe fn enable_queue(&self) -> u16 {
        match self.transport {
            Transport::Mmio { base } => unsafe {
                ((base + mmio::QUEUE_READY) as *mut u32).write_volatile(1);
                0
            },
            Transport::Pci { common, .. } => unsafe {
                let notify_off = ((common + pci_common::QUEUE_NOTIFY_OFF) as *const u16).read_volatile();
                ((common + pci_common::QUEUE_ENABLE) as *mut u16).write_volatile(1);
                notify_off
            },
        }
    }

    /// Assigns the CURRENTLY selected queue's own completions to
    /// `self.msix_vector`. Called unconditionally from `do_probe`, for
    /// BOTH queues and regardless of whether a real vector is in use —
    /// same real-bug rationale as `driver_virtio_blk::VirtioBlk::write_
    /// queue_msix_vector`'s own doc comment (`do_probe`'s own `write_
    /// status(0)` device RESET clears any earlier per-queue assignment
    /// `kernel_arch_glue`'s own PCI wiring made before this process's
    /// first instruction ever ran). `Transport::Mmio` has no such
    /// register, so this is a harmless no-op there.
    ///
    /// # Safety
    /// Same contract as `read_device_feature`.
    unsafe fn write_queue_msix_vector(&self) {
        if let Transport::Pci { common, .. } = self.transport {
            // SAFETY: forwarded from this method's own contract.
            unsafe {
                ((common + pci_common::QUEUE_MSIX_VECTOR) as *mut u16).write_volatile(self.msix_vector)
            };
        }
    }

    /// Rings the doorbell for `queue_idx`, whose own `notify_off` the
    /// caller passes (from `rx_notify_off`/`tx_notify_off` — see
    /// `enable_queue`'s own doc comment for why this driver, unlike
    /// `driver_virtio_blk`, cannot cache a single notify offset).
    ///
    /// # Safety
    /// Same contract as `read_device_feature`; `enable_queue` must
    /// already have run for this queue.
    unsafe fn notify_queue(&self, queue_idx: u32, notify_off: u16) {
        match self.transport {
            Transport::Mmio { base } => unsafe {
                ((base + mmio::QUEUE_NOTIFY) as *mut u32).write_volatile(queue_idx)
            },
            Transport::Pci { notify, notify_off_multiplier, .. } => unsafe {
                let addr = notify + (notify_off as usize) * (notify_off_multiplier as usize);
                (addr as *mut u16).write_volatile(queue_idx as u16);
            },
        }
    }

    /// Reads and acknowledges the device's own pending interrupt cause —
    /// MMIO's own explicit read-`INTERRUPT_STATUS`-then-write-
    /// `INTERRUPT_ACK`-the-same-value pair, or PCI's single read-to-clear
    /// `ISR_CFG` byte (spec §4.1.4.5) — both fully consumed here, so the
    /// caller never needs to know which. Called unconditionally after
    /// every completion (this driver never actually WAITS on the
    /// resulting interrupt line — it always polls the used ring directly,
    /// this crate's own module doc comment — but draining whatever cause
    /// is pending still avoids a later poll observing a stale one).
    ///
    /// # Safety
    /// Same contract as `read_device_feature`.
    unsafe fn ack_interrupt(&self) {
        match self.transport {
            Transport::Mmio { base } => unsafe {
                let cause = ((base + mmio::INTERRUPT_STATUS) as *const u32).read_volatile();
                ((base + mmio::INTERRUPT_ACK) as *mut u32).write_volatile(cause);
            },
            Transport::Pci { isr, .. } => unsafe {
                let _ = (isr as *const u8).read_volatile();
            },
        }
    }

    /// Reads one byte of the device-specific config space (the MAC,
    /// spec §5.1.4) at `offset`.
    ///
    /// # Safety
    /// Same contract as `read_device_feature`.
    unsafe fn read_config_byte(&self, offset: usize) -> u8 {
        match self.transport {
            Transport::Mmio { base } => unsafe { ((base + mmio::CONFIG + offset) as *const u8).read_volatile() },
            Transport::Pci { device_cfg, .. } => unsafe {
                ((device_cfg + offset) as *const u8).read_volatile()
            },
        }
    }

    /// The physical address of `region_base + offset`, derived from the
    /// header word `kernel_arch_glue` wrote at `layout::PHYS_BASE_OFFSET`
    /// — same reasoning as `driver_virtio_blk::VirtioBlk::queue_phys`'s
    /// own doc comment.
    ///
    /// # Safety
    /// `region_base` must be mapped and its header word populated.
    unsafe fn region_phys(region_base: usize, offset: usize) -> u64 {
        // SAFETY: forwarded from this function's own contract.
        let base = unsafe { ((region_base + layout::PHYS_BASE_OFFSET) as *const u64).read_volatile() };
        base + offset as u64
    }

    /// Publishes descriptor slot 0 of `region_base`'s own queue into the
    /// avail ring and rings the doorbell for `queue_idx` (using
    /// `notify_off` — `enable_queue`'s own doc comment on why this is a
    /// per-call parameter, not a single cached field). `desc` is the
    /// caller-built descriptor (already pointing at `BUFFER_OFFSET`, with
    /// the right `len`/`flags` for the direction — device-writable for
    /// RX, device-readable for TX). `next_idx` is threaded through
    /// (rather than a `&mut self` field access) so `post_rx_buffer` can
    /// call this for `rx_base` and `submit_tx` for `tx_base` without
    /// aliasing `self` twice.
    ///
    /// # Safety
    /// `region_base` must be mapped; `queue_idx` must already be
    /// `select_queue`d and set up (`do_probe`'s own contract).
    #[allow(clippy::too_many_arguments)]
    unsafe fn publish_and_notify(
        &self,
        region_base: usize,
        queue_idx: u32,
        notify_off: u16,
        next_idx: &mut u16,
        desc: VirtqDescRaw,
    ) {
        // SAFETY: `DESC_OFFSET` (32 bytes, slot 0 only ever used) is
        // within the mapped region — forwarded from this method's own
        // contract.
        unsafe { ((region_base + layout::DESC_OFFSET) as *mut VirtqDescRaw).write_volatile(desc) };
        // SAFETY: `q_write_u16`'s own contract — every offset here is
        // within the mapped region.
        unsafe {
            let ring_slot = layout::AVAIL_OFFSET + 4 + (*next_idx as usize % QUEUE_SIZE as usize) * 2;
            q_write_u16(region_base, ring_slot, 0); // head descriptor index (always slot 0)
            *next_idx = next_idx.wrapping_add(1);
            q_write_u16(region_base, layout::AVAIL_OFFSET + 2, *next_idx); // avail.idx
        }
        // SAFETY: `notify_queue`'s own contract (forwarded).
        unsafe { self.notify_queue(queue_idx, notify_off) };
    }

    /// Posts (or re-posts) the ONE RX buffer this driver keeps in flight
    /// — a device-writable descriptor covering `virtio_net_hdr` + up to
    /// `FRAME_MAX` bytes.
    ///
    /// # Safety
    /// `self.rx_base` must be mapped.
    unsafe fn post_rx_buffer(&mut self) {
        // SAFETY: forwarded from this method's own contract.
        let buf_phys = unsafe { Self::region_phys(self.rx_base, layout::BUFFER_OFFSET) };
        let desc = VirtqDescRaw {
            addr: buf_phys,
            len: (VIRTIO_NET_HDR_LEN + FRAME_MAX) as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        // SAFETY: `self.rx_base` is mapped (forwarded); RX_QUEUE was
        // already selected/enabled by `do_probe`.
        let rx_base = self.rx_base;
        let mut next_idx = self.rx_next_idx;
        unsafe { self.publish_and_notify(rx_base, RX_QUEUE, self.rx_notify_off, &mut next_idx, desc) };
        self.rx_next_idx = next_idx;
    }

    /// Runs the virtio 1.x device-init handshake (spec §3.1) for BOTH
    /// queues. Real MMIO/PCI/virtqueue reads/writes throughout, via the
    /// transport-generic accessors above. For `Transport::Mmio` only,
    /// ALSO verifies `MAGIC_VALUE`/`DEVICE_ID`/`VERSION` first — a PCI
    /// device has no equivalent registers at all (PCI discovery already
    /// confirmed vendor/class during the bus scan).
    fn do_probe(&mut self) -> Result<(), DriverError> {
        if let Transport::Mmio { base } = self.transport {
            // SAFETY: `base` is trusted per this method's own contract
            // (verified non-zero by the caller, `probe`).
            let magic = unsafe { ((base + mmio::MAGIC_VALUE) as *const u32).read_volatile() };
            // SAFETY: same contract.
            let device_id = unsafe { ((base + mmio::DEVICE_ID) as *const u32).read_volatile() };
            // SAFETY: same contract.
            let version = unsafe { ((base + mmio::VERSION) as *const u32).read_volatile() };
            const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
            const VIRTIO_NETWORK_DEVICE: u32 = 1;
            const VIRTIO_MMIO_VERSION_MODERN: u32 = 2;
            if magic != VIRTIO_MMIO_MAGIC || device_id != VIRTIO_NETWORK_DEVICE {
                return Err(DriverError::ProbeFailed);
            }
            // Same "modern-only, reject anything else" reasoning as
            // `driver_virtio_blk::VirtioBlk::do_probe`'s own check.
            if version != VIRTIO_MMIO_VERSION_MODERN {
                return Err(DriverError::ProbeFailed);
            }
        }

        // SAFETY: every accessor call below shares its own contract —
        // the transport's own base(s) are trusted per this method's own
        // contract (verified by the caller, `probe`).
        unsafe {
            self.write_status(0);
            self.write_status(status::ACKNOWLEDGE);
            self.write_status(status::ACKNOWLEDGE | status::DRIVER);

            // Feature negotiation (spec §3.1 steps 3-6): VIRTIO_F_VERSION_1
            // is mandatory; VIRTIO_NET_F_MAC is accepted IF offered (see
            // this constant's own doc comment) so a real MAC can be read
            // from config space below.
            let dev_features_lo = self.read_device_feature(0);
            let dev_features_hi = self.read_device_feature(1);
            let mac_offered = dev_features_lo & VIRTIO_NET_F_MAC != 0;

            self.write_driver_feature(0, if mac_offered { VIRTIO_NET_F_MAC } else { 0 });
            self.write_driver_feature(1, dev_features_hi & VIRTIO_F_VERSION_1);

            self.write_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);
            let after_features = self.read_status();
            if after_features & status::FEATURES_OK == 0 {
                self.write_status(status::FAILED);
                return Err(DriverError::ProbeFailed);
            }

            // Queue setup (spec §3.1 step 7, §4.2.3.2) — RX then TX.
            for (queue_idx, region_base) in [(RX_QUEUE, self.rx_base), (TX_QUEUE, self.tx_base)] {
                self.select_queue(queue_idx);
                self.write_queue_msix_vector();
                let max = self.read_queue_size_max();
                if max == 0 || (max as u16) < QUEUE_SIZE {
                    self.write_status(status::FAILED);
                    return Err(DriverError::ProbeFailed);
                }
                self.write_queue_size(QUEUE_SIZE as u32);
                let desc_phys = Self::region_phys(region_base, layout::DESC_OFFSET);
                let avail_phys = Self::region_phys(region_base, layout::AVAIL_OFFSET);
                let used_phys = Self::region_phys(region_base, layout::USED_OFFSET);
                self.write_queue_addrs(desc_phys, avail_phys, used_phys);
                let notify_off = self.enable_queue();
                if queue_idx == RX_QUEUE {
                    self.rx_notify_off = notify_off;
                } else {
                    self.tx_notify_off = notify_off;
                }
            }

            self.write_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK);

            // Device-specific config space: `mac` is the struct's first
            // field (spec §5.1.4) — only meaningful if `mac_offered`;
            // otherwise keep `FALLBACK_MAC` (this constant's own doc
            // comment on why that path is defensive-only).
            self.mac = if mac_offered {
                let mut m = [0u8; 6];
                for (i, byte) in m.iter_mut().enumerate() {
                    *byte = self.read_config_byte(i);
                }
                m
            } else {
                FALLBACK_MAC
            };
            // Mirror the MAC into the RX region's own header block — see
            // `layout::MAC_OFFSET`'s own doc comment for why kernel-
            // arch-glue reads it from there rather than a protocol field.
            let mac_ptr = (self.rx_base + layout::MAC_OFFSET) as *mut u8;
            for (i, byte) in self.mac.iter().enumerate() {
                mac_ptr.add(i).write_volatile(*byte);
            }
        }

        // SAFETY: `self.rx_base` is mapped (this method's own contract,
        // verified by the caller `probe`); RX_QUEUE was just enabled
        // above.
        unsafe { self.post_rx_buffer() };

        Ok(())
    }

    /// Publishes ONE frame's descriptor chain on the TX queue and rings
    /// the doorbell — does NOT wait for completion. `len` is the frame's
    /// own byte length; the frame's bytes themselves must ALREADY be
    /// written at `tx_base + layout::BUFFER_OFFSET + VIRTIO_NET_HDR_LEN`
    /// by the caller BEFORE this call — this method only zero-fills the
    /// `virtio_net_hdr` ahead of them and builds the descriptor, exactly
    /// mirroring `driver_virtio_blk::VirtioBlk::submit_request`'s own
    /// "caller already placed the data, this method only writes the
    /// header" convention (avoids a same-address `copy_nonoverlapping`,
    /// which `subsystem_entry.rs`'s own zero-copy staging would otherwise
    /// trigger).
    ///
    /// `pub`: `subsystem_entry.rs` calls this directly for the real
    /// interrupt-driven TX path — only it can issue the actual `Wait`
    /// ecall in between submission and completion (this crate's own
    /// module doc comment on why TX, unlike RX, is safe to make
    /// interrupt-driven).
    ///
    /// # Safety
    /// `self.ready` must be true (`probe` already mapped every region and
    /// set up both queues), and the frame bytes must already be staged as
    /// described above.
    pub unsafe fn submit_tx_request(&mut self, len: usize) {
        // SAFETY: `layout::BUFFER_OFFSET..+VIRTIO_NET_HDR_LEN` is within
        // the mapped TX region (forwarded from this method's own
        // contract) — the header is always all-zero (no GSO/checksum
        // offload requested, this crate's own module doc comment).
        unsafe {
            core::ptr::write_bytes((self.tx_base + layout::BUFFER_OFFSET) as *mut u8, 0, VIRTIO_NET_HDR_LEN);
        }
        // SAFETY: `Self::region_phys`'s own contract (forwarded).
        let buf_phys = unsafe { Self::region_phys(self.tx_base, layout::BUFFER_OFFSET) };
        let desc = VirtqDescRaw {
            addr: buf_phys,
            len: (VIRTIO_NET_HDR_LEN + len) as u32,
            flags: 0, // device-readable (TX), single descriptor, no NEXT
            next: 0,
        };
        let tx_base = self.tx_base;
        let mut next_idx = self.tx_next_idx;
        // SAFETY: `publish_and_notify`'s own contract — `tx_base` is
        // mapped, TX_QUEUE was set up by `do_probe`.
        unsafe { self.publish_and_notify(tx_base, TX_QUEUE, self.tx_notify_off, &mut next_idx, desc) };
        self.tx_next_idx = next_idx;
    }

    /// Whether the LAST `submit_tx_request`'s own chain has landed in the
    /// TX used ring yet — same "`used.idx == next_idx` means done"
    /// direction as `driver_virtio_blk::VirtioBlk::completion_pending`.
    ///
    /// `pub`: `subsystem_entry.rs`'s own real interrupt-driven TX path
    /// checks this itself after each `Wait`, rather than trusting a
    /// single `Wait` return as proof of completion — same "the shared
    /// vector can carry other event sources too" rationale as `driver_
    /// virtio_blk::VirtioBlk::completion_pending`'s own doc comment.
    ///
    /// # Safety
    /// Same contract as `submit_tx_request`.
    pub unsafe fn tx_completion_pending(&self) -> bool {
        // SAFETY: `q_read_u16`'s own contract.
        let used_idx = unsafe { q_read_u16(self.tx_base, layout::USED_OFFSET + 2) };
        used_idx == self.tx_next_idx
    }

    /// Acknowledges the interrupt at the device — the tail end of TX
    /// completion handling, called once `tx_completion_pending` is true.
    ///
    /// `pub`: same reasoning as `submit_tx_request`'s own doc comment.
    ///
    /// # Safety
    /// Same contract as `submit_tx_request`.
    pub unsafe fn ack_tx_completion(&mut self) {
        // SAFETY: `ack_interrupt`'s own contract (forwarded).
        unsafe { self.ack_interrupt() };
    }

    /// Submits ONE frame on the TX queue and busy-polls (bounded) for its
    /// own completion via `submit_tx_request`/`tx_completion_pending`/
    /// `ack_tx_completion` above — mirrors `driver_virtio_blk::VirtioBlk::
    /// wait_for_completion`'s own bounded-spin shape exactly, and kept
    /// for the same reason that method is kept: a documented, still-
    /// correct, host-testable alternative to the real interrupt-driven
    /// path `subsystem_entry.rs` now uses in production. Returns `true`
    /// once the device's used ring shows this chain consumed, `false` on
    /// timeout (the caller should treat this as `DriverErrorCode::
    /// DeviceIo`, same as `driver_virtio_blk`'s own `STATUS_TIMEOUT`
    /// handling).
    ///
    /// # Safety
    /// Same contract as `submit_tx_request`.
    pub unsafe fn submit_tx(&mut self, len: usize) -> bool {
        // SAFETY: forwarded from this method's own contract.
        unsafe { self.submit_tx_request(len) };

        let mut completed = false;
        for _ in 0..MAX_SPINS {
            // SAFETY: forwarded from this method's own contract.
            if unsafe { self.tx_completion_pending() } {
                completed = true;
                break;
            }
            core::hint::spin_loop();
        }
        // SAFETY: forwarded from this method's own contract — drain
        // whatever interrupt cause is pending so a later `submit_tx`/
        // `poll_rx` is not stuck behind a stale one.
        unsafe { self.ack_tx_completion() };
        completed
    }

    /// Checks the RX queue ONCE for a newly-received frame — never
    /// blocks (this module's own doc comment on why). Returns the frame's
    /// own length (`virtio_net_hdr` NOT included) if one arrived — the
    /// caller reads the bytes directly from `rx_base + layout::
    /// BUFFER_OFFSET + VIRTIO_NET_HDR_LEN` (same "read it from the fixed
    /// offset directly" convention `driver_virtio_blk`'s own demo path
    /// uses) — or `None` if nothing had arrived yet. Re-posts the RX
    /// buffer before returning `Some`, so the queue is always ready for
    /// the next frame.
    ///
    /// # Safety
    /// `self.ready` must be true.
    pub unsafe fn poll_rx(&mut self) -> Option<u32> {
        // SAFETY: `q_read_u16`'s own contract.
        let used_idx = unsafe { q_read_u16(self.rx_base, layout::USED_OFFSET + 2) };
        // A completion is ready once `used.idx` CATCHES UP to `rx_next_
        // idx` (the avail.idx value `post_rx_buffer` last published) —
        // same "used_idx == next_idx means done" direction `driver_
        // virtio_blk::VirtioBlk::completion_pending`/`wait_for_
        // completion` both use.
        if used_idx != self.rx_next_idx {
            return None;
        }
        // SAFETY: the used ring entry at slot `(rx_next_idx - 1) %
        // QUEUE_SIZE` is within the mapped RX region — `driver_virtio_
        // blk`'s own used-ring-entry layout (`id: u32, len: u32`, spec
        // §2.6.8) applies identically here; `len` is this entry's
        // second `u32`, so `+4`.
        let slot = ((self.rx_next_idx.wrapping_sub(1)) as usize % QUEUE_SIZE as usize) as usize;
        let entry_off = layout::USED_OFFSET + 4 + slot * 8 + 4;
        let total_len = unsafe { ((self.rx_base + entry_off) as *const u32).read_volatile() };
        // SAFETY: `ack_interrupt`'s own contract (forwarded).
        unsafe { self.ack_interrupt() };
        // SAFETY: `post_rx_buffer`'s own contract (`self.rx_base` mapped).
        unsafe { self.post_rx_buffer() };
        Some(total_len.saturating_sub(VIRTIO_NET_HDR_LEN as u32))
    }

    /// Whether `probe` has completed successfully.
    pub fn is_ready(&self) -> bool {
        self.ready
    }
}

impl DeviceDriver for VirtioNet {
    fn probe(&mut self) -> Result<DeviceInfo, DriverError> {
        if !self.regions_bound() {
            return Err(DriverError::ProbeFailed);
        }
        self.do_probe()?;
        self.ready = true;
        // Non-block-device driver: both fields are the documented
        // "0 for non-block" sentinel (`driver_framework::DeviceInfo`'s
        // own doc comment).
        Ok(DeviceInfo {
            sector_size: 0,
            sector_count: 0,
        })
    }

    fn handle_irq(&mut self, _line: u32) {
        // Same "no separate async-notify path in this MVP" reasoning as
        // `driver_virtio_blk::VirtioBlk::handle_irq`'s own no-op.
    }

    fn handle_request(&mut self, req: DriverRequest) -> DriverResponse {
        if !self.ready {
            return DriverResponse::Failed {
                code: DriverErrorCode::ProbeFailed,
            };
        }
        match req {
            DriverRequest::Probe => DriverResponse::Ready {
                sector_size: 0,
                sector_count: 0,
            },
            DriverRequest::Irq { line } => {
                self.handle_irq(line);
                DriverResponse::Ready {
                    sector_size: 0,
                    sector_count: 0,
                }
            }
            DriverRequest::Quiesce => DriverResponse::Ready {
                sector_size: 0,
                sector_count: 0,
            },
            DriverRequest::ReadBlocks { .. } | DriverRequest::WriteBlocks { .. } => {
                DriverResponse::Failed {
                    code: DriverErrorCode::Unsupported,
                }
            }
            // `SendFrame`/`PollFrame` are driven by `subsystem_entry.rs`
            // directly (it alone knows the real frame length/bytes
            // already staged in the shared region) — see that module's
            // own doc comment, mirroring `driver_virtio_blk::
            // subsystem_entry`'s own split for `ReadBlocks`/`WriteBlocks`.
            DriverRequest::SendFrame { .. } | DriverRequest::PollFrame => DriverResponse::Failed {
                code: DriverErrorCode::Unsupported,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_without_regions_fails() {
        // All three regions absent (0/0/0): `probe`'s own early-return
        // check catches this BEFORE `do_probe` ever touches real memory
        // — the only `probe` path a host test can safely exercise, same
        // reasoning as `driver_virtio_blk`'s own `probe_without_mmio_
        // fails` test.
        let mut d = VirtioNet::new(0, 0, 0);
        assert_eq!(d.probe(), Err(DriverError::ProbeFailed));
    }

    #[test]
    fn regions_bound_requires_all_three() {
        assert!(!VirtioNet::new(0, 0x1000, 0x2000).regions_bound());
        assert!(!VirtioNet::new(0x1000, 0, 0x2000).regions_bound());
        assert!(!VirtioNet::new(0x1000, 0x2000, 0).regions_bound());
        assert!(VirtioNet::new(0x1000, 0x2000, 0x3000).regions_bound());
    }

    #[test]
    fn probe_without_pci_common_cfg_fails() {
        // Same reasoning as `probe_without_regions_fails`, `Transport::
        // Pci` side: `common == 0` is `transport_bound`'s own "not
        // granted yet" sentinel for this transport too.
        let mut d = VirtioNet::new_pci(0, 0, 0, 0, 0, 0, 0, VIRTIO_MSI_NO_VECTOR);
        assert_eq!(d.probe(), Err(DriverError::ProbeFailed));
    }

    #[test]
    fn pci_transport_is_bound_once_common_cfg_is_real() {
        // Constructing with a non-zero `common` base alone (no real
        // hardware touched) is enough for `probe`'s own early-return
        // check to pass through to the real-hardware path, mirroring
        // `driver_virtio_blk`'s own identical test.
        let d = VirtioNet::new_pci(
            0x4000_0000,
            0x4000_1000,
            4,
            0x4000_2000,
            0x4000_3000,
            0x5000_0000,
            0x6000_0000,
            0,
        );
        assert!(d.regions_bound());
    }

    #[test]
    fn mac_is_zero_before_probe() {
        let d = VirtioNet::new(0x1000, 0x2000, 0x3000);
        assert_eq!(d.mac(), [0u8; 6]);
    }

    #[test]
    fn requests_before_ready_are_rejected() {
        let mut d = VirtioNet::new(0x1000, 0x2000, 0x3000);
        let r = d.handle_request(DriverRequest::Probe);
        assert!(matches!(
            r,
            DriverResponse::Failed {
                code: DriverErrorCode::ProbeFailed
            }
        ));
    }

    #[test]
    fn send_frame_and_poll_frame_are_rejected_by_handle_request() {
        // `handle_request`'s own arms for these two ALWAYS answer
        // `Unsupported` (`subsystem_entry.rs` drives the real hardware
        // path directly, per this module's own doc comment) — exercised
        // with `ready` set directly (same-module private-field access) so
        // this test does not need a real `probe()` against fake hardware.
        let mut d = VirtioNet::new(0x1000, 0x2000, 0x3000);
        d.ready = true;
        let r = d.handle_request(DriverRequest::SendFrame { len: 42 });
        assert!(matches!(
            r,
            DriverResponse::Failed {
                code: DriverErrorCode::Unsupported
            }
        ));
        let r2 = d.handle_request(DriverRequest::PollFrame);
        assert!(matches!(
            r2,
            DriverResponse::Failed {
                code: DriverErrorCode::Unsupported
            }
        ));
    }
}
