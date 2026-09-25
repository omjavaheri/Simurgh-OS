//! ============================================================================
//! scanout.rs — the Compositor's real display output path
//!
//! Purpose: take a committed BGRA8 frame and put it on the actual
//! screen. Until this existed, `CommitBuffer` ended in RAM
//! (03-Kernel-Subsystems-Layer.md §5.4.2 explicitly allowed that for the
//! MVP: "even headless/file output is enough") — this module is the
//! step past it, writing committed pixels into the linear framebuffer
//! UEFI's Graphics Output Protocol programmed before ExitBootServices.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.4
//! (Compositor Service), §5.4.2 (MVP acceptance); 01-HAL-Layer.md §3.6
//! (`hal_manifest::raw::FramebufferInfoRaw`, where this geometry
//! originates).
//!
//! Position in the system: the Compositor process is the ONLY process in
//! the system that holds a mapping of the framebuffer's physical pages —
//! `kernel_arch_glue::compositor_demo_start` derives exactly one grant
//! of `KernelState::root_mmio_framebuffer_cap` and maps it at
//! `SCANOUT_VA`, alongside a small info page at `SCANOUT_INFO_VA`
//! carrying the geometry. Every other process reaches the screen by
//! committing a buffer to this one, which is the point: "the Compositor
//! owns the display" is enforced by the capability system, not by
//! convention.
//!
//! Safety/invariants: everything that can be decided without touching
//! the mapping (does a framebuffer exist, where does a frame land, which
//! rows/columns survive clipping, how does one pixel convert) is pure,
//! `#[cfg(test)]`-covered logic in this file. The unsafe surface is
//! deliberately two functions — `Scanout::from_info_page` and the two
//! writers — each of which can only ever touch `[base, base + mapped_
//! bytes)`, a range the kernel both chose and mapped.
//! ============================================================================

/// Magic word introducing the scanout info page — ASCII `"SIMGSC"` plus
/// a 16-bit layout version. Must stay numerically equal to
/// `kernel_arch_glue::SCANOUT_INFO_MAGIC`.
///
/// Same reasoning as the bootloader's own handoff magic: the kernel
/// zero-fills this page before writing it, so a Compositor built against
/// a layout the running kernel does not produce reads `0` here and
/// cleanly concludes "no framebuffer was granted" instead of blitting
/// through a misread base address. There is no version negotiation —
/// a mismatch means headless, which is always a safe outcome.
pub const SCANOUT_INFO_MAGIC: u64 = 0x5349_4D47_5343_0001;

/// Byte offset, in the info page, of the fields the COMPOSITOR writes
/// back (blit count and last blitted size). The kernel reads them from
/// its own identity map to report the real, observed state of the
/// output in the boot log — the same "kernel peeks a shared region
/// directly, no protocol field needed" proof pattern the confirm region
/// already uses for `CommitBuffer`.
pub const SCANOUT_STATUS_OFFSET: usize = 32;

/// Byte offset, in the info page, of the Compositor's acknowledgement —
/// an echo of [`SCANOUT_INFO_MAGIC`] written the moment it has decoded
/// the page and taken ownership of the output.
///
/// It exists because "the Compositor reached its display" and "the
/// Compositor has drawn a client's frame" are different facts, and a
/// blit count of zero cannot distinguish them from "the process never
/// ran at all" — which, given this project's known scheduling-capacity
/// characteristic, is a real possibility the boot log must not blur.
pub const SCANOUT_ACK_OFFSET: usize = 48;

/// Pixel byte order of the firmware-programmed framebuffer. Mirrors
/// `hal_manifest::raw::PixelFormatRaw`'s two writable variants; the raw
/// `Unknown` has no counterpart here because this type only ever exists
/// for a framebuffer that can actually be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelOrder {
    /// `[B, G, R, X]` — byte-identical to the packed BGRA8 every
    /// committed frame in this system already uses, so a row is a plain
    /// copy.
    Bgrx8,
    /// `[R, G, B, X]` — every pixel needs its red and blue bytes
    /// swapped on the way out.
    Rgbx8,
}

/// The geometry of the granted scanout, as the kernel wrote it into the
/// info page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanoutInfo {
    /// Visible width, in pixels.
    pub width: u32,
    /// Visible height, in pixels.
    pub height: u32,
    /// Distance between consecutive rows, in PIXELS — frequently larger
    /// than `width` (firmware pads rows for alignment). Every row
    /// offset in this module goes through this, never through `width`.
    pub stride_pixels: u32,
    /// Pixel byte order — see [`PixelOrder`].
    pub order: PixelOrder,
    /// How many bytes of framebuffer the kernel actually mapped. Every
    /// write is bounded by this and never by the geometry alone, so a
    /// disagreement between the two can only ever under-draw, never
    /// write past the mapping.
    pub mapped_bytes: u64,
}

impl ScanoutInfo {
    /// Decodes the first 32 bytes of the info page.
    ///
    /// Returns `None` — meaning "run headless, exactly as before this
    /// path existed" — for a missing/mismatched magic, an unknown pixel
    /// order, or any geometry that does not describe a writable
    /// rectangle. Nothing here is a hard error: a Compositor with no
    /// output is precisely what every boot of this system did until
    /// now, and is the correct behaviour on riscv64 and on any machine
    /// whose firmware offered no usable mode.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let u32_at = |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let magic = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        if magic != SCANOUT_INFO_MAGIC {
            return None;
        }
        let width = u32_at(8);
        let height = u32_at(12);
        let stride_pixels = u32_at(16);
        let order = match u32_at(20) {
            1 => PixelOrder::Bgrx8,
            2 => PixelOrder::Rgbx8,
            _ => return None,
        };
        let mapped_bytes = u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);

        if width == 0 || height == 0 || stride_pixels < width {
            return None;
        }
        // The mapping must cover every row this geometry claims;
        // otherwise the two disagree and the geometry is the wrong one
        // to trust.
        if mapped_bytes < stride_pixels as u64 * height as u64 * 4 {
            return None;
        }
        Some(Self { width, height, stride_pixels, order, mapped_bytes })
    }

    /// Byte offset of pixel `(x, y)` within the mapping.
    pub fn pixel_offset(&self, x: u32, y: u32) -> usize {
        (y as usize * self.stride_pixels as usize + x as usize) * 4
    }
}

/// Where a committed frame lands on the output, and how much of it
/// survives.
///
/// The policy this encodes — chosen once, here, so it is one documented
/// decision rather than an accident of arithmetic:
///
///   - A frame SMALLER than the output is CENTERED. The alternative
///     (top-left) is simpler but makes an 800x600 desktop on a 1024x768
///     firmware mode look like a mistake rather than a window.
///   - A frame LARGER than the output is CLIPPED from its top-left
///     corner, never scaled. This Compositor has no scaler (and a
///     software one would be both slow and a quality decision that
///     belongs to whoever renders the frame), and drawing nothing at
///     all would hide a real, diagnosable mismatch behind a black
///     screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlitPlan {
    /// Destination column of the frame's left edge.
    pub dst_x: u32,
    /// Destination row of the frame's top edge.
    pub dst_y: u32,
    /// How many columns of the source actually get drawn.
    pub copy_width: u32,
    /// How many rows of the source actually get drawn.
    pub copy_height: u32,
}

impl BlitPlan {
    /// Computes where a `src_width` x `src_height` frame lands on a
    /// `dst_width` x `dst_height` output. See the type's own doc
    /// comment for the centering/clipping policy.
    pub fn compute(dst_width: u32, dst_height: u32, src_width: u32, src_height: u32) -> Self {
        let copy_width = src_width.min(dst_width);
        let copy_height = src_height.min(dst_height);
        Self {
            dst_x: (dst_width - copy_width) / 2,
            dst_y: (dst_height - copy_height) / 2,
            copy_width,
            copy_height,
        }
    }

    /// Whether this plan draws nothing at all (an empty committed
    /// frame) — checked by callers so a 0x0 commit, which is legal per
    /// `Compositor::commit_buffer`, is a no-op rather than a
    /// zero-length copy against a computed pointer.
    pub fn is_empty(&self) -> bool {
        self.copy_width == 0 || self.copy_height == 0
    }
}

/// Converts one packed-BGRA8 source pixel (as a little-endian `u32`,
/// which is how every frame in this system is stored) to the output's
/// own byte order.
///
/// For `Bgrx8` this is the identity — the source format IS the output
/// format, which is why the common path can copy whole rows instead of
/// going through here.
pub fn convert_pixel(pixel: u32, order: PixelOrder) -> u32 {
    match order {
        PixelOrder::Bgrx8 => pixel,
        // Source bytes are [B, G, R, X] = 0xXXRRGGBB as a LE u32;
        // swapping the low and third bytes yields [R, G, B, X].
        PixelOrder::Rgbx8 => (pixel & 0xFF00_FF00) | ((pixel & 0x00FF_0000) >> 16) | ((pixel & 0x0000_00FF) << 16),
    }
}

/// Packs a BGRA8 pixel from its components — used for the one colour
/// this module paints on its own (see `Scanout::fill`).
pub const fn bgra8(r: u8, g: u8, b: u8) -> u32 {
    ((0xFFu32) << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

/// `Simurgh-UI-Template01::ui_core::framebuffer::Color::DESKTOP_BACKGROUND`
/// (RGB 0x2C1A3D), hand-mirrored — the same "small constant duplicated
/// with a sync comment rather than a cross-repo dependency" convention
/// `subsystem_entry`'s own `KeyEvent`/`MOUSE_EVENT_LABEL` already follow.
///
/// Why this Compositor paints anything at all on its own: acquiring the
/// scanout means taking ownership of every pixel on screen, and what is
/// on those pixels at that moment is whatever the UEFI firmware console
/// last drew — stale boot text that would otherwise sit there for the
/// rest of the boot, under any frame later committed. Clearing on
/// acquire is what a real compositor does, and using the desktop's own
/// background colour means the first real `ui-core` frame is a
/// continuation of what is already on screen rather than a flash.
pub const DESKTOP_BACKGROUND: u32 = bgra8(0x2C, 0x1A, 0x3D);

/// A mapped, writable scanout buffer.
///
/// Holds the geometry plus the base address of the mapping. Every write
/// through it is bounded by `info.mapped_bytes`, which the kernel both
/// chose and mapped.
#[derive(Debug, Clone, Copy)]
pub struct Scanout {
    base: usize,
    info: ScanoutInfo,
}

impl Scanout {
    /// Reads the info page at `info_page_va` and, if it describes a
    /// real granted framebuffer, returns a `Scanout` over
    /// `framebuffer_va`.
    ///
    /// # Safety
    /// `info_page_va` must point at the 4 KiB page
    /// `kernel_arch_glue::compositor_demo_start` maps at
    /// `SCANOUT_INFO_VA` in this process's address space, and
    /// `framebuffer_va` at the framebuffer mapping it creates alongside
    /// it. Both are established before this process is ever scheduled,
    /// so any code path in `subsystem_main` may rely on them.
    pub unsafe fn from_info_page(info_page_va: usize, framebuffer_va: usize) -> Option<Self> {
        let mut bytes = [0u8; 32];
        // SAFETY: the info page is mapped `U=1 R+W` for this process by
        // the kernel before it is first scheduled, per this function's
        // own contract; 32 bytes is well inside its single page.
        unsafe {
            core::ptr::copy_nonoverlapping(info_page_va as *const u8, bytes.as_mut_ptr(), 32);
        }
        let info = ScanoutInfo::from_bytes(&bytes)?;
        Some(Self { base: framebuffer_va, info })
    }

    /// This scanout's geometry.
    pub fn info(&self) -> ScanoutInfo {
        self.info
    }

    /// Fills the entire visible area with one packed-BGRA8 colour.
    ///
    /// Row by row over `width` (not `stride_pixels`): the padding
    /// columns past the visible width are never displayed, and writing
    /// them would be pointless traffic to video memory.
    pub fn fill(&self, color: u32) {
        let converted = convert_pixel(color, self.info.order);
        for y in 0..self.info.height {
            let row = self.base + self.info.pixel_offset(0, y);
            for x in 0..self.info.width {
                let px = (row + x as usize * 4) as *mut u32;
                // SAFETY: `(x, y)` is inside the visible rectangle, and
                // `ScanoutInfo::from_bytes` already rejected any
                // geometry whose last row falls outside `mapped_bytes`
                // — so this address is inside the kernel-established
                // mapping. Volatile because this is video memory: the
                // effect of the write is the display itself, and
                // nothing in this process ever reads it back.
                unsafe { core::ptr::write_volatile(px, converted) };
            }
        }
    }

    /// Blits a committed, packed-BGRA8 frame of `src_width` x
    /// `src_height` pixels, laid out with no padding, from `src_va`.
    ///
    /// Returns the plan actually used, so the caller can record what
    /// really made it to the screen rather than what was requested.
    ///
    /// # Safety
    /// `src_va` must be readable for at least `src_width * src_height *
    /// 4` bytes — in practice it is `FB_VA`, the shared region the
    /// kernel maps for committed frames, and the caller has already
    /// bounded the length against `FRAME_MAX`.
    pub unsafe fn blit(&self, src_va: usize, src_width: u32, src_height: u32) -> BlitPlan {
        let plan = BlitPlan::compute(self.info.width, self.info.height, src_width, src_height);
        if plan.is_empty() {
            return plan;
        }
        for row in 0..plan.copy_height {
            let src_row = src_va + (row as usize * src_width as usize) * 4;
            let dst_row = self.base + self.info.pixel_offset(plan.dst_x, plan.dst_y + row);
            match self.info.order {
                // The source format IS the output format: one memcpy
                // per row, which is the whole reason a compositor can
                // afford to run at full resolution here.
                PixelOrder::Bgrx8 => {
                    // SAFETY: the destination row is inside the visible
                    // rectangle (hence inside the mapping, per
                    // `from_bytes`'s own check), and the source is
                    // valid for this many bytes per this function's own
                    // contract. The two mappings are distinct physical
                    // memory — a shared RAM region versus device
                    // framebuffer pages — so they cannot overlap.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            src_row as *const u8,
                            dst_row as *mut u8,
                            plan.copy_width as usize * 4,
                        );
                    }
                }
                PixelOrder::Rgbx8 => {
                    for x in 0..plan.copy_width {
                        // SAFETY: same bounds argument as the memcpy
                        // arm above, one pixel at a time because each
                        // needs its channels reordered.
                        unsafe {
                            let pixel = core::ptr::read_unaligned((src_row + x as usize * 4) as *const u32);
                            core::ptr::write_volatile(
                                (dst_row + x as usize * 4) as *mut u32,
                                convert_pixel(pixel, PixelOrder::Rgbx8),
                            );
                        }
                    }
                }
            }
        }
        plan
    }

    /// Presents a committed frame by writing ONLY what changed since the
    /// last one, and returns the plan used plus the number of bytes
    /// actually written to the framebuffer.
    ///
    /// Why: ui-core commits a whole 800x600 frame for every input event,
    /// yet a mouse move changes a few hundred pixels of it. Writing the
    /// other ~1.9 MB again every time is the dominant per-commit cost —
    /// video memory is the slow side (under QEMU every framebuffer page
    /// written is also marked dirty and re-scanned for the display), so
    /// this compares against a SHADOW copy of what was last presented,
    /// kept in ordinary RAM, and touches the framebuffer only for the
    /// spans that differ. An identical frame writes nothing at all.
    ///
    /// The shadow is laid out exactly like the source (packed, row
    /// stride `src_width * 4`); only the region inside the returned plan
    /// is meaningful. `shadow_valid` says whether it currently mirrors
    /// the screen for a frame of this same size — when it does not (the
    /// first frame, or a size change), every visible row is written and
    /// the shadow refilled.
    ///
    /// # Safety
    /// `src_va` must be readable, and `shadow_va` readable and writable,
    /// for `src_width * src_height * 4` bytes each, and the two must not
    /// overlap each other or the framebuffer.
    pub unsafe fn present_diff(
        &self,
        src_va: usize,
        shadow_va: usize,
        src_width: u32,
        src_height: u32,
        shadow_valid: bool,
    ) -> (BlitPlan, u64) {
        let plan = BlitPlan::compute(self.info.width, self.info.height, src_width, src_height);
        if plan.is_empty() {
            return (plan, 0);
        }
        let width = plan.copy_width as usize;
        let src_stride = src_width as usize * 4;
        let order = self.info.order;
        let mut written: u64 = 0;
        for row in 0..plan.copy_height as usize {
            let src_row = (src_va + row * src_stride) as *const u8;
            let shadow_row = (shadow_va + row * src_stride) as *mut u8;
            let dst_row = (self.base + self.info.pixel_offset(plan.dst_x, plan.dst_y + row as u32)) as *mut u8;
            if shadow_valid {
                // SAFETY: both rows are `width * 4 <= src_stride` bytes
                // inside their regions per this function's contract;
                // every emitted span lies inside `[0, width)`, so the
                // destination stays inside the visible rectangle and
                // therefore inside the mapping (`from_bytes`'s check).
                unsafe {
                    diff_row(src_row, shadow_row, width, |start, len| {
                        write_span(dst_row.add(start * 4), src_row.add(start * 4), len, order);
                        written += len as u64 * 4;
                    });
                }
            } else {
                // SAFETY: same bounds argument as above, for the whole
                // visible row.
                unsafe {
                    core::ptr::copy_nonoverlapping(src_row, shadow_row, width * 4);
                    write_span(dst_row, src_row, width, order);
                }
                written += width as u64 * 4;
            }
        }
        (plan, written)
    }
}

/// Compares one row of `width_px` pixels of a new frame against the
/// shadow of what is on screen, 8 bytes (two pixels) at a time, updates
/// the shadow to the new contents, and calls `emit(start_px, len_px)`
/// once per maximal run of changed pixels, in left-to-right order.
///
/// Two-pixel granularity is a deliberate trade: comparing whole words
/// halves the loop count and a span can be at most one pixel wider than
/// the true change, which costs 4 bytes of extra framebuffer write. An
/// odd trailing pixel is compared on its own. Raw pointers, not slices,
/// because this is the hot loop of every commit and must carry no bounds
/// checks.
///
/// # Safety
/// `new` must be readable and `shadow` readable and writable for
/// `width_px * 4` bytes; they must not overlap. Neither needs any
/// alignment beyond what `read_unaligned`/`write_unaligned` accept.
pub unsafe fn diff_row(new: *const u8, shadow: *mut u8, width_px: usize, mut emit: impl FnMut(usize, usize)) {
    let mut run_start: Option<usize> = None;
    let mut px = 0;
    while px + 2 <= width_px {
        // SAFETY: `px + 2 <= width_px`, so these 8 bytes are in range
        // for both rows per this function's contract.
        let (a, b) = unsafe {
            (
                core::ptr::read_unaligned(new.add(px * 4) as *const u64),
                core::ptr::read_unaligned(shadow.add(px * 4) as *const u64),
            )
        };
        if a != b {
            // SAFETY: same range as the read just above.
            unsafe { core::ptr::write_unaligned(shadow.add(px * 4) as *mut u64, a) };
            if run_start.is_none() {
                run_start = Some(px);
            }
        } else if let Some(start) = run_start.take() {
            emit(start, px - start);
        }
        px += 2;
    }
    if px < width_px {
        // SAFETY: the one remaining pixel, `px == width_px - 1`.
        let (a, b) = unsafe {
            (
                core::ptr::read_unaligned(new.add(px * 4) as *const u32),
                core::ptr::read_unaligned(shadow.add(px * 4) as *const u32),
            )
        };
        if a != b {
            // SAFETY: same pixel as the read just above.
            unsafe { core::ptr::write_unaligned(shadow.add(px * 4) as *mut u32, a) };
            if run_start.is_none() {
                run_start = Some(px);
            }
        } else if let Some(start) = run_start.take() {
            emit(start, px - start);
        }
    }
    if let Some(start) = run_start {
        emit(start, width_px - start);
    }
}

/// Writes `len_px` packed-BGRA8 source pixels to the framebuffer at
/// `dst`, converting to the output's byte order.
///
/// Volatile, word-wide stores: volatile because the effect of the write
/// IS the display (and so LLVM cannot turn the loop back into a call to
/// an unoptimized `memcpy` from the build-std `compiler_builtins`); an
/// 8-byte-aligned middle section so the framebuffer sees aligned 64-bit
/// stores, never a misaligned access to device memory — one leading
/// 4-byte store fixes up an odd start, one trailing store an odd length.
///
/// # Safety
/// `dst` must be writable and `src` readable for `len_px * 4` bytes, and
/// `dst` 4-byte aligned (every pixel address in a 32-bpp framebuffer is).
pub unsafe fn write_span(dst: *mut u8, src: *const u8, len_px: usize, order: PixelOrder) {
    // SAFETY (whole body): every access below is at a pixel index in
    // `[0, len_px)`, in range per this function's own contract.
    unsafe {
        match order {
            PixelOrder::Bgrx8 => {
                let mut i = 0;
                if len_px > 0 && (dst as usize) % 8 != 0 {
                    core::ptr::write_volatile(dst as *mut u32, core::ptr::read_unaligned(src as *const u32));
                    i = 1;
                }
                while i + 2 <= len_px {
                    let v = core::ptr::read_unaligned(src.add(i * 4) as *const u64);
                    core::ptr::write_volatile(dst.add(i * 4) as *mut u64, v);
                    i += 2;
                }
                if i < len_px {
                    let v = core::ptr::read_unaligned(src.add(i * 4) as *const u32);
                    core::ptr::write_volatile(dst.add(i * 4) as *mut u32, v);
                }
            }
            PixelOrder::Rgbx8 => {
                for i in 0..len_px {
                    let v = core::ptr::read_unaligned(src.add(i * 4) as *const u32);
                    core::ptr::write_volatile(dst.add(i * 4) as *mut u32, convert_pixel(v, PixelOrder::Rgbx8));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn info_bytes(magic: u64, width: u32, height: u32, stride: u32, order: u32, mapped: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&magic.to_le_bytes());
        b[8..12].copy_from_slice(&width.to_le_bytes());
        b[12..16].copy_from_slice(&height.to_le_bytes());
        b[16..20].copy_from_slice(&stride.to_le_bytes());
        b[20..24].copy_from_slice(&order.to_le_bytes());
        b[24..32].copy_from_slice(&mapped.to_le_bytes());
        b
    }

    #[test]
    fn a_real_info_page_decodes() {
        let info = ScanoutInfo::from_bytes(&info_bytes(SCANOUT_INFO_MAGIC, 800, 600, 1024, 1, 1024 * 600 * 4))
            .expect("a well-formed info page must decode");
        assert_eq!(info.width, 800);
        assert_eq!(info.stride_pixels, 1024);
        assert_eq!(info.order, PixelOrder::Bgrx8);
        // Row offsets follow the stride, not the visible width — the
        // exact assumption that shears an image when it is wrong.
        assert_eq!(info.pixel_offset(0, 1), 1024 * 4);
        assert_eq!(info.pixel_offset(2, 1), 1024 * 4 + 8);
    }

    /// Every "no output" case must decode to `None`, because that is
    /// the path that preserves the pre-scanout behaviour exactly.
    #[test]
    fn an_absent_or_incoherent_info_page_means_headless() {
        // Zero-filled page: no framebuffer was granted at all.
        assert!(ScanoutInfo::from_bytes(&[0u8; 32]).is_none());
        // A layout version this build does not know.
        assert!(ScanoutInfo::from_bytes(&info_bytes(SCANOUT_INFO_MAGIC + 1, 800, 600, 800, 1, 800 * 600 * 4)).is_none());
        // An unwritable pixel order.
        assert!(ScanoutInfo::from_bytes(&info_bytes(SCANOUT_INFO_MAGIC, 800, 600, 800, 9, 800 * 600 * 4)).is_none());
        // Stride narrower than the visible width.
        assert!(ScanoutInfo::from_bytes(&info_bytes(SCANOUT_INFO_MAGIC, 800, 600, 640, 1, 800 * 600 * 4)).is_none());
        // A mapping too short for the last row.
        assert!(ScanoutInfo::from_bytes(&info_bytes(SCANOUT_INFO_MAGIC, 800, 600, 800, 1, 4096)).is_none());
        // An empty rectangle.
        assert!(ScanoutInfo::from_bytes(&info_bytes(SCANOUT_INFO_MAGIC, 800, 0, 800, 1, 4096)).is_none());
    }

    #[test]
    fn a_smaller_frame_is_centered() {
        let plan = BlitPlan::compute(800, 600, 640, 480);
        assert_eq!(plan, BlitPlan { dst_x: 80, dst_y: 60, copy_width: 640, copy_height: 480 });
    }

    #[test]
    fn an_exactly_sized_frame_lands_at_the_origin() {
        let plan = BlitPlan::compute(800, 600, 800, 600);
        assert_eq!(plan, BlitPlan { dst_x: 0, dst_y: 0, copy_width: 800, copy_height: 600 });
    }

    /// The documented policy: clip from the top-left, never scale,
    /// never refuse to draw.
    #[test]
    fn a_larger_frame_is_clipped_not_scaled() {
        let plan = BlitPlan::compute(800, 600, 1920, 1080);
        assert_eq!(plan, BlitPlan { dst_x: 0, dst_y: 0, copy_width: 800, copy_height: 600 });
    }

    /// The Root Task's own 2x2 bootstrap test frame — the smallest real
    /// commit this system makes, and the one a QEMU screendump is
    /// checked against pixel by pixel.
    #[test]
    fn the_two_by_two_bootstrap_frame_lands_dead_center() {
        let plan = BlitPlan::compute(800, 600, 2, 2);
        assert_eq!(plan, BlitPlan { dst_x: 399, dst_y: 299, copy_width: 2, copy_height: 2 });
    }

    #[test]
    fn an_empty_commit_draws_nothing() {
        assert!(BlitPlan::compute(800, 600, 0, 0).is_empty());
        assert!(BlitPlan::compute(800, 600, 16, 0).is_empty());
        assert!(!BlitPlan::compute(800, 600, 1, 1).is_empty());
    }

    #[test]
    fn bgrx_output_needs_no_conversion_and_rgbx_swaps_red_and_blue() {
        // Source pixel: B=0x11, G=0x22, R=0x33, X=0xFF.
        let src = 0xFF33_2211u32;
        assert_eq!(convert_pixel(src, PixelOrder::Bgrx8), src);
        // Output [R, G, B, X] = 0xFF112233 as a LE u32.
        assert_eq!(convert_pixel(src, PixelOrder::Rgbx8), 0xFF11_2233);
        // The conversion is its own inverse, so a round trip is lossless.
        assert_eq!(convert_pixel(convert_pixel(src, PixelOrder::Rgbx8), PixelOrder::Rgbx8), src);
    }

    #[test]
    fn the_desktop_background_constant_matches_ui_cores_own_colour() {
        // ui-core's Color::DESKTOP_BACKGROUND is RGB(0x2C, 0x1A, 0x3D);
        // packed BGRA8 puts B in the low byte and opaque alpha on top.
        assert_eq!(DESKTOP_BACKGROUND, 0xFF2C_1A3D);
    }

    /// Runs `diff_row` over two pixel rows and returns the spans it
    /// emitted, leaving `shadow` updated.
    fn spans(new: &[u32], shadow: &mut [u32]) -> Vec<(usize, usize)> {
        assert_eq!(new.len(), shadow.len());
        let mut out = Vec::new();
        // SAFETY: both slices are `len * 4` bytes and distinct.
        unsafe {
            diff_row(new.as_ptr() as *const u8, shadow.as_mut_ptr() as *mut u8, new.len(), |s, l| out.push((s, l)));
        }
        out
    }

    #[test]
    fn an_identical_row_emits_nothing() {
        let row = [7u32; 800];
        let mut shadow = row;
        assert!(spans(&row, &mut shadow).is_empty());
    }

    #[test]
    fn one_changed_pixel_emits_one_small_span_and_updates_the_shadow() {
        let mut new = [7u32; 800];
        let mut shadow = new;
        new[401] = 9;
        let s = spans(&new, &mut shadow);
        // Two-pixel granularity: the span is the word holding pixel 401.
        assert_eq!(s, vec![(400, 2)]);
        assert_eq!(shadow, new);
        // Presenting the same frame again is now a no-op.
        assert!(spans(&new, &mut shadow).is_empty());
    }

    #[test]
    fn separate_changes_become_separate_spans_in_order() {
        let mut new = [0u32; 20];
        let mut shadow = new;
        new[0] = 1;
        new[1] = 1;
        new[2] = 1;
        new[10] = 1;
        assert_eq!(spans(&new, &mut shadow), vec![(0, 4), (10, 2)]);
    }

    #[test]
    fn an_odd_width_row_compares_its_last_pixel_alone() {
        let mut new = [0u32; 7];
        let mut shadow = new;
        new[6] = 5;
        assert_eq!(spans(&new, &mut shadow), vec![(6, 1)]);
        // A run reaching the odd tail is one span, not two.
        new[5] = 5;
        new[6] = 6;
        assert_eq!(spans(&new, &mut shadow), vec![(4, 3)]);
        assert_eq!(shadow, new);
    }

    /// A fake framebuffer in host memory, so `present_diff` can be run
    /// end to end: `stride` > `width` exercises the padding columns.
    fn fake_scanout(fb: &mut Vec<u32>, width: u32, height: u32, stride: u32) -> Scanout {
        fb.clear();
        fb.resize((stride * height) as usize, 0);
        Scanout {
            base: fb.as_mut_ptr() as usize,
            info: ScanoutInfo {
                width,
                height,
                stride_pixels: stride,
                order: PixelOrder::Bgrx8,
                mapped_bytes: stride as u64 * height as u64 * 4,
            },
        }
    }

    fn present(s: &Scanout, frame: &[u32], shadow: &mut [u32], w: u32, h: u32, valid: bool) -> (BlitPlan, u64) {
        // SAFETY: `frame`/`shadow` are `w * h` pixels; the fake
        // framebuffer covers the scanout's whole geometry.
        unsafe { s.present_diff(frame.as_ptr() as usize, shadow.as_mut_ptr() as usize, w, h, valid) }
    }

    #[test]
    fn the_shadowed_present_writes_everything_once_then_only_changes() {
        let mut fb = Vec::new();
        let s = fake_scanout(&mut fb, 8, 6, 10);
        let mut frame = vec![3u32; 8 * 6];
        let mut shadow = vec![0u32; 8 * 6];
        let (plan, bytes) = present(&s, &frame, &mut shadow, 8, 6, false);
        assert_eq!(plan, BlitPlan { dst_x: 0, dst_y: 0, copy_width: 8, copy_height: 6 });
        assert_eq!(bytes, 8 * 6 * 4);
        // Identical frame: zero framebuffer writes.
        assert_eq!(present(&s, &frame, &mut shadow, 8, 6, true).1, 0);
        // One changed pixel: one 2-pixel span, and it really lands.
        frame[2 * 8 + 5] = 42;
        assert_eq!(present(&s, &frame, &mut shadow, 8, 6, true).1, 8);
        assert_eq!(fb[2 * 10 + 5], 42);
        // Padding columns past the visible width are never written.
        assert!(fb.iter().enumerate().all(|(i, &p)| (i % 10) < 8 || p == 0));
    }

    #[test]
    fn the_shadowed_present_keeps_the_centering_and_clipping_policy() {
        let mut fb = Vec::new();
        // Centered: a 2x2 frame on 8x6 lands at (3, 2).
        let s = fake_scanout(&mut fb, 8, 6, 8);
        let frame = [1u32, 2, 3, 4];
        let mut shadow = [0u32; 4];
        let (plan, bytes) = present(&s, &frame, &mut shadow, 2, 2, false);
        assert_eq!(plan, BlitPlan::compute(8, 6, 2, 2));
        assert_eq!(bytes, 16);
        assert_eq!((fb[2 * 8 + 3], fb[2 * 8 + 4], fb[3 * 8 + 3], fb[3 * 8 + 4]), (1, 2, 3, 4));
        // Clipped: a 12x8 frame on 8x6 draws its top-left 8x6 only.
        let s = fake_scanout(&mut fb, 8, 6, 8);
        let frame: Vec<u32> = (0..12 * 8).collect();
        let mut shadow = vec![0u32; 12 * 8];
        let (plan, bytes) = present(&s, &frame, &mut shadow, 12, 8, false);
        assert_eq!(plan, BlitPlan::compute(8, 6, 12, 8));
        assert_eq!(bytes, 8 * 6 * 4);
        assert_eq!(fb[5 * 8 + 7], 5 * 12 + 7);
        // A change outside the visible part writes nothing.
        let mut frame2 = frame.clone();
        frame2[7 * 12 + 11] = 999;
        assert_eq!(present(&s, &frame2, &mut shadow, 12, 8, true).1, 0);
    }

    #[test]
    fn write_span_aligns_to_eight_bytes_and_handles_both_orders() {
        let src = [0x0011_2233u32, 0x0044_5566, 0x0077_8899];
        let mut dst = [0u32; 4];
        // Start at an odd pixel so the leading 4-byte fix-up runs.
        // SAFETY: 3 pixels from index 1 stay inside the 4-pixel buffer.
        unsafe { write_span(dst.as_mut_ptr().add(1) as *mut u8, src.as_ptr() as *const u8, 3, PixelOrder::Bgrx8) };
        assert_eq!(dst, [0, 0x0011_2233, 0x0044_5566, 0x0077_8899]);
        let mut dst = [0u32; 1];
        // SAFETY: one pixel into a one-pixel buffer.
        unsafe { write_span(dst.as_mut_ptr() as *mut u8, src.as_ptr() as *const u8, 1, PixelOrder::Rgbx8) };
        assert_eq!(dst[0], convert_pixel(src[0], PixelOrder::Rgbx8));
    }
}
