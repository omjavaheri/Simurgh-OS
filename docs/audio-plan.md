# Audio plan (Intel HD Audio first, x86_64)

Owner priority: an audio driver, then a volume control in the tray.

## Decision

Intel High Definition Audio (HDA), not virtio-sound.

- It is the audio standard of essentially every real x86 PC (and QEMU emulates
  it as `-device intel-hda -device hda-duplex`), so the work carries over to
  real hardware. virtio-sound is simpler but exists almost only in VMs.
- Cost: CORB/RIRB command rings, codec discovery, a widget graph walk, a stream
  descriptor with a buffer descriptor list (BDL) and DMA. All of it is
  register/verb protocol, so it is host-testable as pure code.
- Reference: Intel High Definition Audio Specification rev 1.0a (section
  numbers below refer to it). PCI class 0x04 subclass 0x03.

## Shape (same as driver-nvme / driver-virtio-net)

`subsystems/drivers/driver-hda`: `no_std` library (register map, verb encoding,
BDL, stream format, codec widget walk over a `send verb -> response` closure,
tone generator, status page and mailbox layout, volume math) with host tests,
plus `subsystem_entry` and the `driver-hda-bin` process image. x86_64 only for
the process; the library also builds on the host and the other targets.

Kernel glue: a new `PeripheralKind::Audio` (discovered by class code, BAR0
mapped, like NVMe), `spawn_hda_driver` (BAR0 window, a command page holding
CORB/RIRB/BDL, a contiguous PCM ring, a sleep Notification), and one shared
"audio page" mapped read-write into the driver and into ui-core only.

## Client interface: one shared page (no IPC yet)

The 4 KiB audio page has a driver-written, seqlocked STATUS record (device
present, codec name, playing, volume 0-100, muted, ...) and a client-written
MAILBOX (sequence number + command + arguments; the driver polls it every
few ms and acknowledges by echoing the sequence). Commands: set volume, set
mute, play tone (frequency, milliseconds), play PCM (bytes already in the
ring), stop. Layout is documented in `driver-hda/src/page.rs`.

Playback is one-shot: fill the ring, program the cyclic buffer length to the
clip length, run the stream, stop when the link position reaches the end.
Polling only (no MSI-X): the driver sleeps on a timed notification between
polls, like Netstack.

## Phases

1. This plan.
2. `driver-hda` library + host tests (verbs, registers, BDL, widget walk against
   a fake codec, tone, page layout).
3. Kernel glue + process image; boot self-check (demo image plays 440 Hz for
   1 s; desktop image is silent unless asked). Evidence: QEMU
   `-audiodev wav` output analysed by `scripts/check-wav-tone.ps1`.
4. ui-core: tray icon reflects present / muted / level; flyout with a slider,
   +/-, mute and a Test button; Devices window already lists the controller.
5. Later: interrupts (MSI), capture (mic), HDMI/DP audio codecs, jack sensing,
   volume knob widgets, per-application streams and mixing, capability-gated
   access instead of the kernel mapping the page into ui-core only.

## TODO(spec)

1. Who may change the volume or play sound (capability) - today the audio page
   is simply mapped into ui-core. Same open question as machine-id TODO-5 and
   the network status page.
2. Multi-client model: mixing, per-client streams, and how a client obtains the
   PCM ring (today only the driver itself, and ui-core through PLAY_TONE).
3. Route/policy: which output pin wins when several are present (speaker vs
   headphone vs HDMI); v1 picks the first pin with an output-capable default
   configuration that reaches a DAC.
4. Uncached mapping of the BAR0 window on real hardware (the mapping flags used
   by every driver here have no cache attribute); DMA coherence is fine on x86.
5. Real-hardware quirks: codec-specific widget setup (EAPD, GPIO amp enables,
   vendor verbs, power-state sequencing) is not covered.

## Status (2026-09-26): phases 1-4 done on x86_64

Built: `driver-hda` (25 host tests), `PeripheralKind::Audio` discovery by PCI
class, `spawn_hda_driver` (enables PCI memory space + bus master itself, maps
BAR0, audio page, command area, 200 KiB PCM ring), `HDA_LOG` syscall, ui-core
`audioinfo` + tray volume icon/flyout (slider, +/-, Mute, Test sound). Run with
`simurgh-run.ps1 -Audio` (host sound) or `-AudioWav C:\Temp\x.wav` (record).
The demo image plays the 440 Hz self-check tone; the desktop image is silent.

Evidence (QEMU `-device intel-hda -device hda-duplex`, `-audiodev wav`,
`scripts/check-wav-tone.ps1`):

- Demo image: serial `hda: codec 0 vendor/device 1af40022: DAC nid 2, pin nid 3`,
  `playing 440 Hz tone, 1000 ms`, `playback finished`; wav = 48 kHz stereo,
  0.96 s non-silent, dominant frequency 440 Hz, peak 12337 (16384 x 75 %).
- Desktop image driven over the QEMU monitor: flyout `Volume: 85%` after two
  `+` clicks (driver log `volume set to 80% / 85%`), `Test sound` plays 0.6 s
  (wav peak 13943 = 16384 x 85 %, 440 Hz), `Mute` shows `Volume: muted` and the
  tray icon gets a red cross; screenshots in `run-audio-ui/`.

Findings worth keeping: QEMU's intel-hda stops fetching CORB commands after
RINTCNT responses unless RIRBCTL bit 0 is set and RIRBSTS is acknowledged after
each response; the emulated audio clock can run slower than the guest clock, so
playback end is detected by link position, with a generous time limit.

Gaps: no capture (microphone), no HDMI/DP codecs, no interrupts (polling), no
jack sensing or codec-specific quirks, BAR0 mapped without a cache attribute,
single stream, no mixing, only ui-core can drive the driver, aarch64/riscv64
compile only, the Devices window still lists the controller from the PCI scan
(no codec name), and a virtio-sound driver was not written.
