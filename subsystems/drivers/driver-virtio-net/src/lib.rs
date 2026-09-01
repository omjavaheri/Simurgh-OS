//! ============================================================================
//! driver-virtio-net
//!
//! Purpose: the MVP network driver — virtio-net (03-Kernel-Subsystems-
//! Layer.md §2.3/§5.4) over virtio-mmio, riscv64 ONLY for now (Device Tree
//! discovery via `hal_riscv64::peripheral`, which already classifies a
//! `DEVICE_ID == 1` virtio-mmio slot as `PeripheralKind::Network` — no HAL
//! change was needed to unblock this crate). aarch64 (virtio-pci) and
//! x86_64 (virtio-pci + MSI-X) fan-out is a follow-up, mirroring
//! `driver-virtio-blk`'s own multi-session history (that driver, too,
//! started MMIO/riscv64-only before later sessions added PCI transports).
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
//! spawn_virtio_net_driver`. Its virtio-mmio register window (discovered
//! by the HAL peripheral scan, `hal_core::peripheral`) and TWO virtqueue/
//! buffer `SharedRegion`s (one per queue — see `layout`'s own doc comment
//! for why this driver needs two separate regions where `driver_virtio_
//! blk` gets by with one) are pre-mapped directly into its address space
//! at spawn time, exactly like `driver-virtio-blk`'s own trusted-bootstrap
//! pattern.
//!
//! MVP scope: `do_probe` runs the virtio 1.x device-init handshake for
//! BOTH queues and negotiates ONLY `VIRTIO_F_VERSION_1` (mandatory) plus
//! `VIRTIO_NET_F_MAC` (if the device offers it, to read a real MAC from
//! config space rather than a hardcoded fallback — QEMU's own virtio-net
//! backend always offers it). No offload features (checksum/TSO/GSO/
//! MRG_RXBUF) are negotiated, matching the fixed 10-byte `virtio_net_hdr`
//! this driver always writes/expects. Completion is a bounded busy-poll on
//! each queue's own used ring (no interrupt-driven path yet — a
//! deliberately smaller first step than `driver-virtio-blk`'s own history,
//! which added interrupts in a LATER session too) — `submit_tx` blocks
//! (bounded) for its own completion; `poll_rx` is explicitly non-blocking
//! (a single check), because unlike a block read a network reply may
//! never arrive at all, so the caller (this driver's own `subsystem_
//! entry.rs`, driven in turn by `kernel_arch_glue`'s own demo sequencing)
//! is the one that retries across separate `Call`s.
//!
//! Safety/invariants: every MMIO/virtqueue-memory access goes through
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
/// header bytes than this driver intended, silently eating the front of
/// every real Ethernet frame this driver ever sent (and, symmetrically,
/// misreading the true length of anything it ever received) — not a
/// virtqueue/completion bug at all, despite `poll_rx`'s own inverted-
/// comparison bug (fixed separately, see that function's own doc
/// comment) looking like the obvious suspect at first.
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
///   `256..256+710` the `virtio_net_hdr` (10 bytes) + frame buffer
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

/// The virtio-net driver state. MMIO transport only for now (see this
/// crate's own module doc comment) — no `Transport` enum yet, unlike
/// `driver_virtio_blk` (which grew one only once a second, PCI-based
/// architecture actually needed it; this crate will grow the same shape
/// when its own PCI fan-out session arrives).
pub struct VirtioNet {
    /// Mapped virtual base of the virtio-mmio transport window (0 = not
    /// granted yet).
    mmio_base: usize,
    /// Mapped virtual base of the RX queue's own `SharedRegion` (also
    /// carries the negotiated MAC and the message-marshaling area — see
    /// `layout`'s own doc comment).
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
}

impl VirtioNet {
    /// Creates the driver bound to a virtio-mmio window mapped at
    /// `mmio_base`, an RX queue region mapped at `rx_base`, and a TX queue
    /// region mapped at `tx_base` (pass 0/0/0 in tests, before any grant
    /// exists).
    pub const fn new(mmio_base: usize, rx_base: usize, tx_base: usize) -> Self {
        Self {
            mmio_base,
            rx_base,
            tx_base,
            ready: false,
            rx_next_idx: 0,
            tx_next_idx: 0,
            mac: [0; 6],
        }
    }

    /// Whether every constructor argument is a real (non-zero) mapped
    /// base — `probe`'s own "nothing granted yet" early-return check,
    /// mirroring `driver_virtio_blk::VirtioBlk::transport_is_bound`.
    fn regions_bound(&self) -> bool {
        self.mmio_base != 0 && self.rx_base != 0 && self.tx_base != 0
    }

    /// The negotiated device MAC (all-zero before `probe` succeeds).
    pub fn mac(&self) -> [u8; 6] {
        self.mac
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
    /// avail ring and rings the doorbell for `queue_idx`. `desc` is the
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
    unsafe fn publish_and_notify(&self, region_base: usize, queue_idx: u32, next_idx: &mut u16, desc: VirtqDescRaw) {
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
        // SAFETY: same contract as this method's own.
        unsafe {
            ((self.mmio_base + mmio::QUEUE_NOTIFY) as *mut u32).write_volatile(queue_idx);
        }
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
        unsafe { self.publish_and_notify(rx_base, RX_QUEUE, &mut next_idx, desc) };
        self.rx_next_idx = next_idx;
    }

    /// Runs the virtio 1.x device-init handshake (spec §3.1) for BOTH
    /// queues. Real MMIO/virtqueue reads/writes throughout — see each
    /// helper's own `# Safety`.
    fn do_probe(&mut self) -> Result<(), DriverError> {
        let base = self.mmio_base;
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
        // `driver_virtio_blk::VirtioBlk::do_probe`'s own check — this
        // driver's whole register map is the version-2 transport's own
        // layout.
        if version != VIRTIO_MMIO_VERSION_MODERN {
            return Err(DriverError::ProbeFailed);
        }

        // SAFETY: every accessor call below is a plain volatile MMIO
        // access to `base` (trusted per this method's own contract,
        // verified by the caller `probe`) or to `self.rx_base`/`self.
        // tx_base` (same contract).
        unsafe {
            ((base + mmio::STATUS) as *mut u32).write_volatile(0);
            ((base + mmio::STATUS) as *mut u32).write_volatile(status::ACKNOWLEDGE);
            ((base + mmio::STATUS) as *mut u32).write_volatile(status::ACKNOWLEDGE | status::DRIVER);

            // Feature negotiation (spec §3.1 steps 3-6): VIRTIO_F_VERSION_1
            // is mandatory; VIRTIO_NET_F_MAC is accepted IF offered (see
            // this constant's own doc comment) so a real MAC can be read
            // from config space below.
            ((base + mmio::DEVICE_FEATURES_SEL) as *mut u32).write_volatile(0);
            let dev_features_lo = ((base + mmio::DEVICE_FEATURES) as *const u32).read_volatile();
            ((base + mmio::DEVICE_FEATURES_SEL) as *mut u32).write_volatile(1);
            let dev_features_hi = ((base + mmio::DEVICE_FEATURES) as *const u32).read_volatile();
            let mac_offered = dev_features_lo & VIRTIO_NET_F_MAC != 0;

            ((base + mmio::DRIVER_FEATURES_SEL) as *mut u32).write_volatile(0);
            ((base + mmio::DRIVER_FEATURES) as *mut u32)
                .write_volatile(if mac_offered { VIRTIO_NET_F_MAC } else { 0 });
            ((base + mmio::DRIVER_FEATURES_SEL) as *mut u32).write_volatile(1);
            ((base + mmio::DRIVER_FEATURES) as *mut u32)
                .write_volatile(dev_features_hi & VIRTIO_F_VERSION_1);

            ((base + mmio::STATUS) as *mut u32)
                .write_volatile(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);
            let after_features = ((base + mmio::STATUS) as *const u32).read_volatile();
            if after_features & status::FEATURES_OK == 0 {
                ((base + mmio::STATUS) as *mut u32).write_volatile(status::FAILED);
                return Err(DriverError::ProbeFailed);
            }

            // Queue setup (spec §3.1 step 7, §4.2.3.2) — RX then TX.
            for (queue_idx, region_base) in [(RX_QUEUE, self.rx_base), (TX_QUEUE, self.tx_base)] {
                ((base + mmio::QUEUE_SEL) as *mut u32).write_volatile(queue_idx);
                let max = ((base + mmio::QUEUE_NUM_MAX) as *const u32).read_volatile();
                if max == 0 || (max as u16) < QUEUE_SIZE {
                    ((base + mmio::STATUS) as *mut u32).write_volatile(status::FAILED);
                    return Err(DriverError::ProbeFailed);
                }
                ((base + mmio::QUEUE_NUM) as *mut u32).write_volatile(QUEUE_SIZE as u32);
                let desc_phys = Self::region_phys(region_base, layout::DESC_OFFSET);
                let avail_phys = Self::region_phys(region_base, layout::AVAIL_OFFSET);
                let used_phys = Self::region_phys(region_base, layout::USED_OFFSET);
                ((base + mmio::QUEUE_DESC_LOW) as *mut u32).write_volatile(desc_phys as u32);
                ((base + mmio::QUEUE_DESC_HIGH) as *mut u32).write_volatile((desc_phys >> 32) as u32);
                ((base + mmio::QUEUE_DRIVER_LOW) as *mut u32).write_volatile(avail_phys as u32);
                ((base + mmio::QUEUE_DRIVER_HIGH) as *mut u32).write_volatile((avail_phys >> 32) as u32);
                ((base + mmio::QUEUE_DEVICE_LOW) as *mut u32).write_volatile(used_phys as u32);
                ((base + mmio::QUEUE_DEVICE_HIGH) as *mut u32).write_volatile((used_phys >> 32) as u32);
                ((base + mmio::QUEUE_READY) as *mut u32).write_volatile(1);
            }

            ((base + mmio::STATUS) as *mut u32).write_volatile(
                status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
            );

            // Device-specific config space: `mac` is the struct's first
            // field (spec §5.1.4) — only meaningful if `mac_offered`;
            // otherwise keep `FALLBACK_MAC` (this constant's own doc
            // comment on why that path is defensive-only).
            self.mac = if mac_offered {
                let mut m = [0u8; 6];
                for (i, byte) in m.iter_mut().enumerate() {
                    *byte = ((base + mmio::CONFIG + i) as *const u8).read_volatile();
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

    /// Submits ONE frame on the TX queue and busy-polls (bounded) for its
    /// own completion — mirrors `driver_virtio_blk::VirtioBlk::wait_for_
    /// completion`'s own bounded-spin shape exactly. `len` is the frame's
    /// own byte length; the frame's bytes themselves must ALREADY be
    /// written at `tx_base + layout::BUFFER_OFFSET + VIRTIO_NET_HDR_LEN`
    /// by the caller BEFORE this call — this method only zero-fills the
    /// `virtio_net_hdr` ahead of them and builds the descriptor, exactly
    /// mirroring `driver_virtio_blk::VirtioBlk::submit_request`'s own
    /// "caller already placed the data, this method only writes the
    /// header" convention (avoids a same-address `copy_nonoverlapping`,
    /// which `subsystem_entry.rs`'s own zero-copy staging would otherwise
    /// trigger). Returns `true` once the device's used ring shows this
    /// chain consumed, `false` on timeout (the caller should treat this
    /// as `DriverErrorCode::DeviceIo`, same as `driver_virtio_blk`'s own
    /// `STATUS_TIMEOUT` handling).
    ///
    /// # Safety
    /// `self.ready` must be true (`probe` already mapped every region and
    /// set up both queues), and the frame bytes must already be staged as
    /// described above.
    pub unsafe fn submit_tx(&mut self, len: usize) -> bool {
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
        unsafe { self.publish_and_notify(tx_base, TX_QUEUE, &mut next_idx, desc) };
        self.tx_next_idx = next_idx;

        let mut completed = false;
        for _ in 0..MAX_SPINS {
            // SAFETY: `q_read_u16`'s own contract.
            let used_idx = unsafe { q_read_u16(self.tx_base, layout::USED_OFFSET + 2) };
            if used_idx == self.tx_next_idx {
                completed = true;
                break;
            }
            core::hint::spin_loop();
        }
        // SAFETY: `self.mmio_base` is mapped (forwarded from this
        // method's own contract) — drain whatever interrupt cause is
        // pending so a later `submit_tx`/`poll_rx` is not stuck behind a
        // stale one, mirroring `driver_virtio_blk::VirtioBlk::ack_
        // interrupt`'s own role.
        unsafe {
            let cause = ((self.mmio_base + mmio::INTERRUPT_STATUS) as *const u32).read_volatile();
            ((self.mmio_base + mmio::INTERRUPT_ACK) as *mut u32).write_volatile(cause);
        }
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
        // completion` both use; this function's own FIRST version had it
        // backwards (`== ` guarded the EARLY RETURN instead of the
        // proceed-to-read path) — **real bug found via QEMU**: with the
        // comparison inverted, `used_idx (0, genuinely nothing completed
        // yet) != rx_next_idx (1, just published)` was already true on
        // the very FIRST poll, so the "nothing new" branch never
        // triggered and every single call fell through to read a used-
        // ring slot the device had never actually written, reporting a
        // phantom `FrameReceived { len: 0 }` forever regardless of real
        // device state (confirmed via a temporary diagnostic log: every
        // one of 5000+ poll attempts logged `len=0` starting immediately
        // after the ARP request was sent, far too fast for even a
        // genuine SLIRP reply, and never varying).
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
        // SAFETY: `self.rx_base` is mapped (this method's own contract).
        unsafe {
            let cause = ((self.mmio_base + mmio::INTERRUPT_STATUS) as *const u32).read_volatile();
            ((self.mmio_base + mmio::INTERRUPT_ACK) as *mut u32).write_volatile(cause);
        }
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
