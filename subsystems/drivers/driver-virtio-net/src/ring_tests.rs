//! Host tests of the multi-buffer queue logic against a FAKE device: the
//! "hardware" is plain memory (an mmio window and two queue regions) and the
//! tests play the device's role by writing used-ring entries themselves.

extern crate std;
use super::*;
use std::vec;
use std::vec::Vec;

struct Fake {
    mmio: Vec<u64>,
    rx: Vec<u64>,
    tx: Vec<u64>,
}

impl Fake {
    fn new() -> Self {
        let mut f = Fake { mmio: vec![0; 0x200 / 8], rx: vec![0; REGION_LEN / 8], tx: vec![0; REGION_LEN / 8] };
        let m = f.mmio.as_mut_ptr() as *mut u8;
        // SAFETY: all writes are inside the freshly allocated vectors.
        unsafe {
            (m.add(mmio::MAGIC_VALUE) as *mut u32).write(0x7472_6976);
            (m.add(mmio::VERSION) as *mut u32).write(2);
            (m.add(mmio::DEVICE_ID) as *mut u32).write(1);
            // Same word for both feature selects: MAC | STATUS | VERSION_1.
            (m.add(mmio::DEVICE_FEATURES) as *mut u32).write(VIRTIO_NET_F_MAC | VIRTIO_NET_F_STATUS | 1);
            (m.add(mmio::QUEUE_NUM_MAX) as *mut u32).write(256);
            for i in 0..6 {
                m.add(mmio::CONFIG + i).write(0x52 + i as u8);
            }
            (m.add(mmio::CONFIG + CONFIG_STATUS_OFFSET) as *mut u16).write(1);
        }
        let (rx, tx) = (f.rx.as_ptr() as u64, f.tx.as_ptr() as u64);
        f.rx[0] = rx;
        f.tx[0] = tx;
        f
    }

    fn driver(&mut self) -> VirtioNet {
        VirtioNet::new(self.mmio.as_mut_ptr() as usize, self.rx.as_mut_ptr() as usize, self.tx.as_mut_ptr() as usize)
    }

    fn rx_base(&self) -> usize {
        self.rx.as_ptr() as usize
    }

    fn tx_base(&self) -> usize {
        self.tx.as_ptr() as usize
    }

    /// The device completes a buffer: used entry `n` plus a used.idx bump.
    fn dev_complete(base: usize, n: u16, id: u16, len: u32) {
        // SAFETY: `base` is a live fake region.
        unsafe {
            let off = layout::USED_OFFSET + 4 + (n as usize % QUEUE_SIZE as usize) * 8;
            ((base + off) as *mut u32).write(id as u32);
            ((base + off + 4) as *mut u32).write(len);
            q_write_u16(base, layout::USED_OFFSET + 2, n.wrapping_add(1));
        }
    }

    fn avail_idx(base: usize) -> u16 {
        // SAFETY: live fake region.
        unsafe { q_read_u16(base, layout::AVAIL_OFFSET + 2) }
    }

    fn avail_entry(base: usize, i: u16) -> u16 {
        // SAFETY: live fake region.
        unsafe { q_read_u16(base, layout::AVAIL_OFFSET + 4 + (i as usize % QUEUE_SIZE as usize) * 2) }
    }
}

#[test]
fn layout_fits_regions() {
    assert!(QUEUE_SIZE.is_power_of_two());
    assert!(BUFFER_STRIDE >= VIRTIO_NET_HDR_LEN + FRAME_MAX);
    assert!(layout::DESC_OFFSET + QUEUE_SIZE as usize * 16 <= layout::AVAIL_OFFSET);
    assert!(layout::AVAIL_OFFSET + 6 + QUEUE_SIZE as usize * 2 <= layout::USED_OFFSET);
    assert!(layout::USED_OFFSET + 6 + QUEUE_SIZE as usize * 8 <= layout::MESSAGE_OFFSET);
    assert!(layout::MESSAGE_OFFSET + 64 <= layout::BUFFER_OFFSET);
    assert_eq!(layout::buffer_offset(QUEUE_SIZE as usize), REGION_LEN);
    // Fields the kernel and the PCI wiring write must not overlap the rings.
    assert!(layout::SLOT_OFFSET + 2 <= layout::PCI_INFO_OFFSET);
    assert!(layout::PCI_INFO_OFFSET + 56 <= layout::TX_NOTIFY_OFF_OFFSET);
    assert!(layout::TX_NOTIFY_OFF_OFFSET + 8 <= layout::DESC_OFFSET);
}

#[test]
fn probe_posts_every_rx_buffer() {
    let mut f = Fake::new();
    let mut d = f.driver();
    assert!(d.probe().is_ok());
    assert_eq!(d.mac(), [0x52, 0x53, 0x54, 0x55, 0x56, 0x57]);
    let rx = f.rx_base();
    assert_eq!(Fake::avail_idx(rx), QUEUE_SIZE);
    for i in 0..QUEUE_SIZE {
        assert_eq!(Fake::avail_entry(rx, i), i);
        // SAFETY: live fake region.
        let desc = unsafe { ((rx + layout::DESC_OFFSET + i as usize * 16) as *const VirtqDescRaw).read() };
        assert_eq!(desc.addr, rx as u64 + layout::buffer_offset(i as usize) as u64);
        assert_eq!(desc.len as usize, VIRTIO_NET_HDR_LEN + FRAME_MAX);
        assert_eq!(desc.flags, VIRTQ_DESC_F_WRITE);
    }
    // The TX queue starts empty.
    assert_eq!(Fake::avail_idx(f.tx_base()), 0);
}

#[test]
fn poll_rx_hands_out_frames_and_reposts_the_previous_one() {
    let mut f = Fake::new();
    let mut d = f.driver();
    d.probe().unwrap();
    let rx = f.rx_base();
    // SAFETY (whole test): the driver is ready and the regions are live.
    assert_eq!(unsafe { d.poll_rx() }, None);
    Fake::dev_complete(rx, 0, 5, (VIRTIO_NET_HDR_LEN + 60) as u32);
    Fake::dev_complete(rx, 1, 6, (VIRTIO_NET_HDR_LEN + 1514) as u32);
    assert_eq!(unsafe { d.poll_rx() }, Some((5, 60)));
    // Buffer 5 is held by the caller: not re-posted yet.
    assert_eq!(Fake::avail_idx(rx), QUEUE_SIZE);
    // The next poll re-posts 5 first, then returns frame 6.
    assert_eq!(unsafe { d.poll_rx() }, Some((6, 1514)));
    assert_eq!(Fake::avail_idx(rx), QUEUE_SIZE + 1);
    assert_eq!(Fake::avail_entry(rx, QUEUE_SIZE), 5);
    assert_eq!(unsafe { d.poll_rx() }, None);
    assert_eq!(Fake::avail_idx(rx), QUEUE_SIZE + 2);
    assert_eq!(Fake::avail_entry(rx, QUEUE_SIZE + 1), 6);
}

#[test]
fn poll_rx_clamps_oversized_and_rejects_bad_ids() {
    let mut f = Fake::new();
    let mut d = f.driver();
    d.probe().unwrap();
    let rx = f.rx_base();
    Fake::dev_complete(rx, 0, 1, 100_000);
    assert_eq!(unsafe { d.poll_rx() }, Some((1, FRAME_MAX as u32)));
    Fake::dev_complete(rx, 1, 999, 64);
    assert_eq!(unsafe { d.poll_rx() }, None); // bad id skipped, never indexed
    // A runt: the device reports fewer bytes than the header.
    Fake::dev_complete(rx, 2, 2, 4);
    assert_eq!(unsafe { d.poll_rx() }, Some((2, 0)));
}

#[test]
fn rx_indices_wrap_around_u16() {
    let mut f = Fake::new();
    let mut d = f.driver();
    d.probe().unwrap();
    let rx = f.rx_base();
    // Drive 70_000 frames through the ring so both u16 indices wrap.
    for n in 0..70_000u32 {
        Fake::dev_complete(rx, n as u16, (n % QUEUE_SIZE as u32) as u16, (VIRTIO_NET_HDR_LEN + 60) as u32);
        let (slot, len) = unsafe { d.poll_rx() }.expect("frame");
        assert_eq!(slot as u32, n % QUEUE_SIZE as u32);
        assert_eq!(len, 60);
    }
}

#[test]
fn tx_slots_track_busy_and_reap() {
    let mut f = Fake::new();
    let mut d = f.driver();
    d.probe().unwrap();
    let tx = f.tx_base();
    // SAFETY (whole test): the driver is ready and the regions are live.
    assert!(unsafe { d.submit_tx_slot(0, 60) });
    assert!(unsafe { d.submit_tx_slot(1, 1514) });
    assert_eq!(d.tx_in_flight(), 2);
    assert_eq!(Fake::avail_idx(tx), 2);
    assert_eq!(Fake::avail_entry(tx, 0), 0);
    assert_eq!(Fake::avail_entry(tx, 1), 1);
    // A busy slot, an out-of-range slot and an oversized frame are refused.
    assert!(!unsafe { d.submit_tx_slot(0, 60) });
    assert!(!unsafe { d.submit_tx_slot(QUEUE_SIZE, 60) });
    assert!(!unsafe { d.submit_tx_slot(2, FRAME_MAX + 1) });
    // The descriptor length includes the virtio header.
    let desc1 = unsafe { ((tx + layout::DESC_OFFSET + 16) as *const VirtqDescRaw).read() };
    assert_eq!(desc1.len as usize, VIRTIO_NET_HDR_LEN + 1514);
    assert_eq!(desc1.flags, 0);
    // Nothing is reaped until the device reports.
    assert_eq!(unsafe { d.reap_tx() }, 0);
    Fake::dev_complete(tx, 0, 1, 0);
    assert_eq!(unsafe { d.reap_tx() }, 1);
    assert!(d.tx_slot_free(1));
    assert!(!d.tx_slot_free(0));
    assert!(unsafe { d.submit_tx_slot(1, 60) });
}

#[test]
fn tx_can_fill_every_slot() {
    let mut f = Fake::new();
    let mut d = f.driver();
    d.probe().unwrap();
    for s in 0..QUEUE_SIZE {
        assert!(unsafe { d.submit_tx_slot(s, 64) }, "slot {s}");
    }
    assert_eq!(d.tx_in_flight(), QUEUE_SIZE as u32);
    assert!(!unsafe { d.submit_tx_slot(0, 64) });
    for s in 0..QUEUE_SIZE {
        Fake::dev_complete(f.tx_base(), s, s, 0);
    }
    assert_eq!(unsafe { d.reap_tx() }, QUEUE_SIZE as u32);
    assert_eq!(d.tx_in_flight(), 0);
}

#[test]
fn external_avail_writer_does_not_desync_the_driver() {
    // The kernel-bypass demo writes descriptor 0 and the avail ring directly
    // and waits for the device; the driver must keep working afterwards
    // because it re-reads avail.idx from the ring instead of caching it.
    let mut f = Fake::new();
    let mut d = f.driver();
    d.probe().unwrap();
    let tx = f.tx_base();
    // SAFETY: live fake region.
    unsafe {
        q_write_u16(tx, layout::AVAIL_OFFSET + 4, 0);
        q_write_u16(tx, layout::AVAIL_OFFSET + 2, 1);
    }
    Fake::dev_complete(tx, 0, 0, 0);
    assert!(unsafe { d.submit_tx_slot(3, 100) });
    assert_eq!(Fake::avail_idx(tx), 2);
    assert_eq!(Fake::avail_entry(tx, 1), 3);
    // The bypass frame's used entry (id 0, never marked busy) reaps harmlessly.
    assert_eq!(unsafe { d.reap_tx() }, 1);
    assert_eq!(d.tx_in_flight(), 1);
}

#[test]
fn link_state_is_published_at_probe() {
    let mut f = Fake::new();
    let mut d = f.driver();
    d.probe().unwrap();
    let rx = f.rx_base();
    // SAFETY: live fake region.
    unsafe {
        assert_eq!(((rx + layout::LINK_VALID_OFFSET) as *const u8).read(), 1);
        assert_eq!(((rx + layout::LINK_UP_OFFSET) as *const u8).read(), 1);
        assert!(d.link_up());
    }
}
