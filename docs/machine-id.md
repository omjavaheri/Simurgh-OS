# Machine ID — design note

Status: PARTIALLY IMPLEMENTED (v1, 2026-09-25): board-level ids only, recompute-only
stability, raw id visible to ui-core. See section 13 for exactly what exists and the
read ABI. Sections 1-12 are the full design; parts not listed in section 13 are still
design only. Open questions remain as `TODO(spec)` items in section 12 and must be
answered by Omid before the parts that depend on them are built.

Architecture reference: 01-HAL-Layer.md (discovery is always complete),
03-Kernel-Subsystems-Layer.md (device-manager, drivers), 04 (policy layer).
Related but independent: the per-user `company_guid` issued by the company
(see `simurgh-account-manager/README.md`, "Identity model").

## 1. Goal

Give every physical computer one stable, worldwide-unique 128-bit identifier
("machine id"), GUID-shaped, that:

- is derived purely from hardware identifiers, so wiping the disk and
  reinstalling Simurgh on the same hardware regenerates the same value;
- has negligible collision probability across machines;
- is independent of the user GUID (a user has one company GUID on many
  machines; a machine has one machine id for many users);
- is never exposed raw to arbitrary software (section 10).

Non-goals: it is not a secret, not an authenticator, and not proof of
identity (identifiers can be spoofed on VMs and by hardware modification).
Anything needing authentication must combine it with enrollment (see TODO-5 in section 12).

## 2. Survey: what the code exposes today (before v1; SMBIOS row is now implemented, see 13)

Surveyed in branch `fix/33-fix`. "HardwareManifestRaw" is the fixed-size
discovery result the HAL hands to the kernel inside `BootInfo`.

What exists:

| Identifier | x86_64 | aarch64 | riscv64 | Notes |
|---|---|---|---|---|
| CPU feature flags | yes (CPUID leaf 1/7) | yes (ID_AA64*) | yes (misa-style flags) | Feature bits only, not an identity. |
| CPU vendor/brand/family/model/stepping | not exposed (only feature bits are read from CPUID) | not exposed (MIDR_EL1 is not read; only MPIDR Aff0 as core id) | not exposed (mvendorid/marchid/mimpid not read; hart id is only a boot parameter) | Trivial to add but low entropy anyway. |
| Per-CPU serial number | none exists in hardware on modern parts | none | none | Do not plan on it. |
| PCI scan | yes, but each scan is purpose-built (compute-device scan, virtio peripheral scan, NVMe discovery); vendor/device/class only | same (`compute.rs`, `peripheral.rs`) | same pattern | No general "list all PCI devices with bus/dev/fn + subsystem ids" record. |
| Peripheral records | `PeripheralDeviceRaw`: kind (Unknown/Block/Network/Gpu/Console), MMIO base/size, irq, device index | same | same | No serial, MAC or model string field. |
| NIC MAC | only inside `driver-virtio-net` (layer 3, read from virtio config space, `mac()`); mirrored into the driver's RX shared region at `MAC_OFFSET`; falls back to a synthetic locally-administered `02:00:00:00:00:01` | same driver | same driver | Real NICs (e1000/r8169/etc.) have no driver at all. Nothing publishes MACs to a central place. |
| Disk serial | none. `driver-nvme` and `driver-virtio-blk` never issue Identify Controller (NVMe SN/MN/FR) or virtio-blk ID (`VIRTIO_BLK_T_GET_ID`). | same | same | NVMe driver only does Identify Namespace. |
| ACPI | RSDP located via UEFI config table (`ACPI2_GUID`) in `uefi-bootloader`, forwarded as a physical address; HAL walks XSDT for MADT / DMAR presence | XSDT walk for MADT (GICD) and IORT/SMMU presence | not used (Device Tree) | Only the tables needed for interrupt/IOMMU discovery are parsed. |
| SMBIOS / DMI (system UUID, board serial, product, manufacturer) | not read. The bootloader does not look up the SMBIOS/SMBIOS3 UEFI config table GUIDs and `BootInfo` has no field for it. | same gap | not applicable (no SMBIOS on most RISC-V boards; UEFI+SMBIOS exists on some servers) | Biggest gap, and the most valuable source on x86_64/aarch64 servers and laptops. |
| Device Tree root `serial-number`, `compatible`, `model` | n/a | possible on non-UEFI boards, not read | DT is walked (memory, cpus, PLIC etc.) but root `serial-number`/`model` not captured | Best riscv64/embedded-arm64 source. |
| TPM serial / EK | no TPM support at all (no TPM 2.0 driver, no ACPI TPM2 table read, no TCG event log) | none | none | Also absent: any measured-boot code. |
| UEFI handoff record | memory map, RSDP, framebuffer only | same | n/a (SBI + DTB) | Adding SMBIOS pointer here is the cheap fix. |
| Hash primitives | `sha2` is only referenced from hal-direct's Cargo comment about the dependency policy; no SHA-256/HMAC is available to layer 3 today | | | Needs a decision, see TODO-8. |

Summary: today the system knows the machine's structure (cores, memory,
interrupt controller, compute and peripheral classes) but essentially no
identity data. The only real identifier read anywhere is the virtio NIC MAC
(in a driver, and QEMU virtio MACs are synthetic on VMs).

## 3. What must be added (missing inputs)

Layer 1 (HAL discovery; pure read-only parsing, consistent with "discovery is
always complete"):

1. SMBIOS/SMBIOS3 entry-point location: `uefi-bootloader` looks up the
   SMBIOS3 and SMBIOS UEFI configuration table GUIDs (same mechanism as
   `locate_acpi_rsdp`) and appends the physical address to the handoff block;
   HAL parses Type 1 (System Information: manufacturer, product, serial,
   UUID), Type 2 (Baseboard: serial, asset tag), Type 3 (Chassis serial).
2. Device Tree root properties (`serial-number`, `model`, `compatible`) on
   riscv64 and on DT-booted arm64.
3. CPU identification words: x86 CPUID vendor + family/model/stepping +
   brand string; aarch64 MIDR_EL1 + REVIDR_EL1; riscv64 mvendorid/marchid/
   mimpid (via SBI `sbi_get_mvendorid` etc. since S-mode cannot read the CSRs).
   These are class identifiers, not unique; used as low-weight salt only.
4. ACPI `TPM2` table presence and, later, TPM EK / serial (requires a TPM
   driver, out of scope for the first version).

Layer 3 (user-space drivers, reported over IPC to a central service):

5. Every network driver exports its permanent (burned-in) MAC, not just the
   negotiated one. The virtio-net driver must distinguish "device offered
   VIRTIO_NET_F_MAC" from the synthetic fallback and mark the latter unusable.
6. `driver-nvme`: Identify Controller (serial number, model, firmware);
   `driver-virtio-blk`: `GET_ID`. Disk serials must be reported as
   identifiers only; reading them needs no data access.
7. PCI subsystem vendor/device ids for onboard NICs (used for MAC ordering, see 5.2).

## 4. Identifier set and weights

Identifiers are grouped into classes. Each is either STRONG (individually
sufficient to make the machine effectively unique if not a placeholder) or
WEAK (only salt; never enough on its own).

| Id | Field | Class | Weight | Comment |
|---|---|---|---|---|
| S1 | SMBIOS Type 1 system UUID | strong | 3 | Best single source on x86/arm64 PCs and servers. Many cheap boards ship duplicates or junk; canonicalisation catches those. |
| S2 | SMBIOS Type 2 baseboard serial | strong | 2 | Often placeholder on OEM desktops. |
| S3 | SMBIOS Type 1 system serial (+ Type 3 chassis serial as fallback) | strong | 2 | |
| S4 | Primary onboard NIC permanent MAC (lowest valid globally-administered MAC among physical, PCI-attached, non-removable NICs) | strong | 2 | USB dongles and virtual NICs are excluded. |
| S5 | Boot/system disk serial (NVMe SN, or SATA/virtio ID once supported) | strong | 1 | Lowest weight because disks are the most commonly replaced part. |
| S6 | TPM 2.0 Endorsement Key public-key hash or TPM manufacturer+serial | strong | 3 | Only when present; needs a TPM driver (future). |
| S7 | Device Tree root `serial-number` (riscv64/arm64 boards) | strong | 3 | Board-level unique on well-behaved vendors. |
| W1 | CPU vendor + family/model/stepping (or MIDR / mvendorid+marchid+mimpid) | weak | 0 | Salt/tie-break only. |
| W2 | Board manufacturer + product name | weak | 0 | Salt only. |
| W3 | Total RAM size, core count | weak | 0 | Must NOT be included in the hash (they change on upgrade); used only for VM/clone heuristics. Listed to state the exclusion. |

TODO(spec) TODO-2 covers whether the weights above are the right ones; they
are a proposal, not a decision.

## 5. Canonicalisation

Every raw identifier is turned into a canonical byte string before use, or
REJECTED (treated as absent). Rules:

5.1 Text identifiers (serials, UUID strings, product names)
- Decode as ASCII/UTF-8; trim leading/trailing whitespace and NULs.
- Lowercase (ASCII), remove internal whitespace, hyphens, colons and braces.
- Reject if empty, if shorter than 4 characters after cleaning, or if all
  characters are the same (`0000...`, `ffff...`, `1111...`, `xxxx...`).
- Reject (case-insensitive, after cleaning) placeholder strings from a
  denylist, initial contents:
  `tobefilledbyoem`, `tobefilledbyo.e.m.`, `defaultstring`, `default`,
  `notspecified`, `notapplicable`, `n/a`, `na`, `none`, `null`,
  `unknown`, `systemserialnumber`, `systemproductname`,
  `systemmanufacturer`, `baseboardserialnumber`, `chassisserialnumber`,
  `oem`, `ok`, `123456789`, `0123456789`, `serialnumber`, `notavailable`,
  `invalid`, `empty`, `filledbyoem`, `tobefilledbyo.e.m`.
  The list is versioned with the label (v1); adding entries later changes ids
  for machines that previously accepted the value, so it may only grow
  through a new label version (TODO-9).
- SMBIOS UUID: 16 raw bytes. Reject all-zero and all-0xFF. Also reject known
  duplicated vendor UUIDs from a small denylist of bytes maintained in the
  same versioned list. Apply the SMBIOS 2.6 byte-order fix (first three fields
  little-endian) before hashing so firmware that reports the same UUID in
  either endianness yields one value. Since 2.6-mixed firmware exists, hash
  the bytes in the SMBIOS-specified RFC 4122 order.

5.2 MAC addresses
- 6 raw bytes, hashed as lowercase hex without separators.
- Reject all-zero, all-FF, and multicast (bit 0 of first byte set).
- Reject locally-administered addresses (bit 1 of first byte set): these are
  randomised, VM-generated or software-assigned (`02:...` fallback, most
  virtio/QEMU/Hyper-V/containers) and are not stable identifiers.
- Reject well-known virtual OUIs even if the U/L bit is clear: VMware
  `00:05:69`, `00:0c:29`, `00:1c:14`, `00:50:56`; Microsoft Hyper-V
  `00:15:5d`; QEMU/KVM `52:54:00` (already locally administered);
  Xen `00:16:3e`; Parallels `00:1c:42`; VirtualBox `08:00:27`.
- Only use NICs that are PCI-attached physical functions and not removable
  (excludes USB NICs, bridges, VLANs, tunnels).
- If several NICs remain, use the numerically smallest valid MAC (stable
  regardless of probe order). See TODO-4 on whether more than one should be
  used.

5.3 Disk serial
- NVMe: 20-byte `SN` field trimmed of trailing spaces, then text rules; prefix
  the model string (`MN`) inside the same field so identical serials from
  different vendors do not collide.
- Only the boot/system disk is considered. Removable and virtual disks
  (virtio-blk serial set by the hypervisor config) are marked "virtual" and
  rejected for the strong set.

5.4 CPU / TPM / DT
- Numeric ids are hashed as fixed-width big-endian integers.
- TPM: hash of the EK public key (not any owner-settable data).
- DT `serial-number`: text rules of 5.1.

## 6. Hash construction

Input encoding is unambiguous: every field is emitted as
`tag (1 byte) || length (u16 big-endian) || bytes`, fields sorted by tag,
absent (rejected) identifiers omitted entirely.

```
label   = "simurgh-machine-id-v1"          // ASCII, no terminator
digest  = SHA-256(
            u16be(len(label)) || label ||
            for each accepted identifier, in ascending tag order:
                u8(tag) || u16be(len(value)) || value )
id_bytes = digest[0..16]
id_bytes[6] = (id_bytes[6] & 0x0F) | 0x50   // version 5 style: name-based, SHA
id_bytes[8] = (id_bytes[8] & 0x3F) | 0x80   // RFC 4122 variant 10xx
```

Tags: S1=0x01 ... S7=0x07 as in section 4; weak ids use 0x80+ and are
included only where TODO-3 decides they are salt.

Notes:
- RFC 4122 layout is used only so the value round-trips through any GUID
  tooling; the value is not an RFC 4122 v5 UUID (different hash and no
  namespace UUID). Version nibble 5 is chosen as the closest match
  ("name-based, hashed"). TODO-7 asks whether to use a custom marker.
- 128 bits truncated from SHA-256 leaves about 122 random bits after the
  fixed version/variant bits, birthday collision for 10^10 machines is about
  10^-17. This holds only when inputs are unique; the real collision risk is
  duplicated firmware data, which canonicalisation and the strong-id
  requirement address.
- The label is versioned. A future v2 (new denylist, new fields) changes all
  ids; migration is section 7.4.

## 7. Stability rules

The id must survive: OS reinstall, disk swap, NIC swap, RAM upgrade, GPU
change. It should not survive: motherboard swap (that is a different
machine, matching what SMBIOS/TPM/NIC binding means).

7.1 What is hashed: ALL currently-valid strong identifiers. So, a naive
recomputation changes the id when any one changes. To avoid that, the
service keeps a persisted record (storage: section 10, code location: section 11) of the identifier set used to
compute the id, and on each boot:

7.2 Match rule (K of N):
- Let N = number of strong identifiers valid now AND recorded; let M = how
  many of them are byte-identical to the recorded ones.
- If M >= K, the stored machine id is kept unchanged and the record is
  updated with the new identifier values (so slow drift, one part at a time,
  does not reach K failures).
- Otherwise the machine is considered new hardware and a new id is derived.
- Proposed K: max(1, ceil(N/2)) weighted, i.e. accept when the matched
  weight is at least half of the recorded weight, and always require at least
  one match among {S1, S6, S7, S2} (board-level ids), so replacing disk +
  NIC never counts as "same machine" by weight alone. K is an open question
  (TODO-1).

7.3 Reinstall on the same hardware: the persisted record is gone (disk
wiped), so the id is recomputed from scratch from the current identifiers.
Result equals the original only if the same set of strong identifiers is
valid and unchanged. Therefore the first-boot derivation must be
DETERMINISTIC in the identifier set, which is why the hash is over the whole
set and not over a chosen subset. Consequence: if the user swapped the disk
(S5) between install 1 and install 2, the reinstalled id differs from the
original unless the derivation uses only identifiers likely to be stable.
This tension is real: see TODO-3 (should the derivation hash the whole strong
set, or only the board-level subset {S1,S2,S3,S6,S7,S4}, with S5 disks only
used for the match rule and weak-id case?). Recommendation: hash the
board-level subset; use S4/S5 as match evidence only and as fallback input
when no board-level id exists.

7.4 Version migration: if the label changes to v2, the service computes both
and keeps the v1 value as the id when the persisted record says v1, unless
Omid decides otherwise (TODO-9).

## 8. Weak-id flag

If the set of accepted STRONG identifiers is empty, the derivation still
produces a value (from weak ids plus, as a last resort, the persisted
random seed) but sets `weak = true`. Possible flag meanings and behaviour:

- `weak = false`: at least one strong identifier accepted.
- `weak = true`: no strong identifier; the id is NOT guaranteed unique and
  NOT guaranteed to survive reinstall. Consumers (enrollment, licensing)
  must treat it as advisory only and may refuse to bind to it.
- In a weak case the machine id is generated from 128 random bits from the
  hardware RNG at first boot and persisted; reinstalling then produces a
  different id (documented, expected). TODO-6 covers whether a weak id may
  be used at all.

## 9. VM and clone caveats

- Cloned VM images and disk images copied to other hardware carry the same
  persisted record; identifiers differ, so on a hypervisor that regenerates
  SMBIOS UUID/MAC per VM the K-of-N rule triggers a new id, which is right.
- Hypervisors that pin the same SMBIOS UUID for cloned VMs, or "golden
  images" with sysprep-less clones, produce duplicate ids. The detection
  signals available: hypervisor CPUID bit / `hypervisor` DMI product string
  (QEMU, KVM, VMware, VirtualBox, Xen, Hyper-V), virtio/locally-administered
  MACs, missing physical TPM. The service records `virtual = true` when any
  fires.
- Virtual machines are allowed to have ids (developers use them), but the
  `virtual` flag is exposed with the id so policy can decline VM ids for
  enrollment.
- Moving a VM to a new host with the same virtual hardware keeps its id
  (intended); cloning a VM without regenerating the SMBIOS UUID does not.
  The service cannot detect this by itself, enrollment (server-side
  duplicate detection) has to. See TODO-5.
- Containers and the Linux compat layer never see hardware ids at all.

## 10. Privacy: raw id is never handed out

- The raw machine id is held by exactly one component. Everything else gets
  a per-service derived id:
  `derived = HMAC-SHA-256(key = machine_id (16 bytes), msg = "simurgh-derived-v1" || 0x00 || service_name)[0..16]`,
  with the same RFC 4122-shaped bit fixing as section 6. Two services see
  unrelated ids for the same machine; leaking one does not reveal the raw id
  or another service's id.
- `service_name` is a stable reverse-DNS-like string owned by the service
  (e.g. `com.simurgh.updates`). The service's identity is established by the
  kernel-attested capability the caller presents, never by a name in the
  request body (otherwise any process could ask for any service's id).
- Access API (capability-gated, mirrors hal-direct: HAL and kernel only
  VERIFY tokens, layer 4 issues them):
  - `MachineIdRaw` capability: read the raw id and the identifier record.
    Held by at most the enrollment/security-broker path (TODO-5).
  - `MachineIdDerive(service_name)` capability: derive-only. Bound to one
    service name at issue time.
  - `MachineIdInfo` capability (optional): read only the `weak` and `virtual`
    flags and the algorithm version.
- Raw hardware identifiers (serials, MACs, SMBIOS UUID) are handled the same
  way: they leave the HAL only toward the machine-id service, are never
  logged, and never written to the manifest dump on serial (the serial
  log currently prints structural manifest data and must not gain these).
- Storage of the persisted record: it contains identifiers, so it must
  be protected (TODO-10: encrypt, and which key).

## 11. Where the code lives

Follows the repo rule: nothing in the kernel unless mechanically required;
discovery in the HAL; policy above.

1. Layer 1 (`hal-manifest`, `hal-core`, `hal-<arch>`): raw discovery only.
   - New fixed-size record `MachineIdentityRaw` (`#[repr(C)]`, no heap) in
     `hal-manifest`, carried in `HardwareManifestRaw` (bumps the BootInfo
     layout version): SMBIOS strings/UUID (x86_64, aarch64/UEFI), DT
     `serial-number`/`model` (riscv64/aarch64-DT), CPU id words, TPM2-table
     presence flag. All fields carry an explicit "present" bit so absence
     is representable; raw bytes only, no canonicalisation here.
   - A `hal-core` trait, e.g. `IdentityDiscovery`, implemented by all three
     arch crates. No `#[cfg(target_arch)]` above the HAL; the identical
     record shape on all three keeps that rule.
2. `uefi-bootloader`: also passes SMBIOS/SMBIOS3 table addresses in the
   handoff block (same pattern as the RSDP).
3. Layer 3 drivers: extend `driver-virtio-net`, `driver-nvme`,
   `driver-virtio-blk` (and future real NIC drivers) to report permanent
   MAC / disk serial to the machine-id service via IPC. `device-manager`
   is the natural aggregator of driver-reported ids. (TODO-11: device-manager
   vs a dedicated service.)
4. The machine-id service (layer 3, user space, `subsystems/machine-id`,
   proposed): receives the HAL identity record plus driver reports, does
   canonicalisation (section 5), hashing (6), K-of-N logic (7), persistence
   (via vfs-service), and serves the derived-id API (10). The pure
   canonicalise/hash/HMAC logic goes in its own `no_std` library crate so it
   is unit-testable on the host for all three targets with fixed vectors.
   Rationale for user space: parsing, policy, and storage do not need
   privilege; keeping them out of the HAL keeps the HAL "discover only".
5. Layer 4 (not this repo): enrollment binds machine id to the company
   account; the security broker issues the `MachineId*` capabilities.

All three architectures are first-class: the discovery record and the
service logic are identical; only the discovery source differs (SMBIOS/ACPI
via UEFI, or Device Tree via SBI). riscv64 without UEFI/SMBIOS must reach
a strong id via DT `serial-number` or via NIC/disk; otherwise it is weak.

## 12. Open questions (not decided)

`TODO(spec)` items. Each blocks the part of the implementation named.

- TODO(spec) TODO-1 (blocks 7.2): K in the K-of-N stability rule; is
  "at least half of recorded weight and one board-level id" right, or a fixed
  K such as 2?
- TODO(spec) TODO-2 (blocks section 4): final identifier weights, and
  whether disk serial should count at all.
- TODO(spec) TODO-3 (blocks 6/7.3): is the hash over ALL strong ids or only
  the board-level subset? (Recommendation in 7.3; not decided.) Also whether
  weak ids (CPU model, board name) are ever included as salt. v1 (owner, 2026-09-25):
  board-level subset only; W2 manufacturer/product salt only in the weak case (section 13).
- TODO(spec) TODO-4 (blocks 5.2): use only the smallest valid NIC MAC, or
  all onboard MACs? Behaviour on multi-NIC servers where one NIC is removed.
- TODO(spec) TODO-5 (blocks 10, 9): who may hold `MachineIdRaw`. Only
  enrollment? Also how the company backend detects duplicate ids from
  cloned VMs, and whether enrollment (company GUID <-> machine id) is
  one-to-one, one-to-many, and what happens on hardware replacement
  (re-enroll, or "transfer" flow). Layer 4 decision, recorded here.
- TODO(spec) TODO-6 (blocks 8): may a weak machine id be persisted and used
  at all, or must such machines refuse enrollment?
- TODO(spec) TODO-7 (blocks 6): RFC 4122 v5 version nibble vs a custom marker
  so software can distinguish machine ids from other GUIDs; and whether the
  wire/textual form is canonical lowercase `8-4-4-4-12` like `company_guid`
  (proposed: yes).
- TODO(spec) TODO-8 (blocks 10/11): which SHA-256/HMAC implementation layer 3
  uses (hal-direct's dependency policy mentions `sha2`; layer-3 dependency
  policy for crypto crates unspecified).
- TODO(spec) TODO-9 (blocks 5.1/7.4): governance of the placeholder
  denylist and label versioning; migration policy when v2 appears.
- TODO(spec) TODO-10 (blocks 10): persistence location, integrity and
  confidentiality of the persisted identifier record (which key, TPM
  sealing), and whether the record is per-machine or per-install.
- TODO(spec) TODO-11 (blocks 11): dedicated `machine-id` service vs a part
  of `device-manager`; which boot-order position (`Service::BOOT_ORDER`).
- TODO(spec) TODO-12 (blocks 3): TPM: is a TPM 2.0 driver/EK read in scope
  for the first version, or v1 ships without S6?
- TODO(spec) TODO-13 (blocks 5.1): SMBIOS byte-order handling for firmware
  older than 2.6, exact treatment (hash as reported vs normalised).
- TODO(spec) TODO-14 (blocks 9): should a VM's machine id be permitted for
  company enrollment at all, or is it flagged and gated by policy?
- TODO(spec) TODO-15 (blocks 10): should the derived per-service id also
  include the user or install, or strictly per (machine, service)?

## 13. Implementation status (v1, 2026-09-25)

Owner decisions of 2026-09-25 that scope this first implementation:

- (a) The id is built from BOARD-LEVEL identifiers only: S1 SMBIOS system UUID,
  S2 baseboard serial, S3 system serial (Type 3 chassis serial as its
  fallback). This settles the recommendation in 7.3 / TODO-3 for v1: disk (S5),
  NIC MAC (S4) and TPM (S6) are NOT hashed. No central source of a physical NIC
  MAC or disk serial exists yet (section 2), so they were left out rather than
  obtained expensively. Weak ids (W2 manufacturer/product) are hashed ONLY when
  no strong id was accepted, so a weak id at least differs between models.
- (b) Stability is the deterministic recompute only: same hardware gives the
  same id on every boot and after a reinstall. The persisted identifier record,
  the K-of-N match rule (7.2) and the random-seed weak case (8) are NOT
  implemented; they remain TODO-1, TODO-6 and TODO-10 above.
- (c) The raw id is a GUID-shaped 128-bit value that the logged-in user may SEE
  in the desktop USERS window. That is the only consumer for now. The per-service
  HMAC derivation of section 10 is out of scope and unimplemented.

What exists:

| Piece | Where |
|---|---|
| Raw record `MachineIdentityRaw` (344 bytes, all-`u8`, alignment 1), carried in `HardwareManifestRaw::machine_identity` | `hal/hal-manifest/src/identity.rs` |
| SMBIOS 2.x / 3.x entry point + Type 1/2/3 parser, canonicalisation, placeholder/junk rejection, SHA-256 construction of section 6, weak/virtual flags, own streaming SHA-256; host tests with fixed vectors | `machine-id-core/` |
| Bootloader: reads SMBIOS from the UEFI configuration table (SMBIOS3 preferred) BEFORE ExitBootServices and appends the record to the handoff block after the framebuffer record (`SIMSMB` magic) | `uefi-bootloader/src/main.rs` |
| HAL decode (x86_64 and aarch64 share the UEFI handoff; riscv64 has no identity source and reports "none") | `hal-x86_64/src/memory.rs`, `hal-arm64/src/memory.rs` |
| Derivation at boot, serial log line `machine id: <guid> (weak=.., virtual=.., ...)` | `kernel-core` (`KernelState::machine_id`), `kernel-arch-glue::build` |
| Exposure to ui-core | `kernel-arch-glue::map_machine_id_info`, mapped by `spawn_ui_core_x86` |

Handoff byte contract (after the memory-map descriptors): `u64 RSDP`, then the
48-byte framebuffer record, then `u64 0x5349_4D53_4D42_0001` ("SIMSMB", version
1) followed by the 344-byte `MachineIdentityRaw` (header 8 bytes: present bits,
source, SMBIOS major, minor, 4 reserved; UUID 16 bytes as stored; then five
64-byte text fields manufacturer, product, system serial, board serial, chassis
serial, each `len` byte + 63 bytes). A missing or different magic reads as "no
identity" (weak id).

### 13.1 Exposure ABI (how a client reads the id)

No new syscall (the syscall surface is deliberately tiny and fuzzed). The
kernel derives the id once and maps ONE read-only 4 KiB page into ui-core's
address space (x86_64), at virtual address `0xD8B0_0000` (`UI_CORE_MACHINE_ID_VA`
in `kernel/kernel/src/main.rs`; the mapping is `R | U`, not writable, not
executable). All values little-endian, every other byte zero:

| Offset | Size | Field |
|---|---|---|
| 0 | u64 | magic `0x5349_4D4D_4944_0001` (ASCII "SIMMID" + layout version 1); the client MUST check it before trusting the page |
| 8 | 16 bytes | machine id in RFC 4122 byte order (identical to the text form's order) |
| 24 | u32 | flags: bit 0 = `weak` (no strong board-level id; advisory only), bit 1 = `virtual` (firmware strings name a hypervisor) |
| 28 | u32 | algorithm version (1 = label `simurgh-machine-id-v1`) |
| 32 | 36 bytes | canonical lowercase `8-4-4-4-12` text form, ASCII, no terminator |

A follow-up ui-core client only has to read that page (a `const` pointer at the
fixed VA) and print the text at offset 32 in the USERS window; show a "weak" or
"virtual" note from the flags. A page whose magic does not match means the
kernel did not map it (out of resources): show "unavailable".

TODO(spec) TODO-5 (access control): the "who may see the raw id" decision is
today made by kernel code that maps the page only into ui-core, not by a
capability. The `MachineIdRaw` / `MachineIdInfo` capabilities of section 10 (issued by
layer 4) are not built; when they exist this page should be granted through them.

### 13.2 Known limits of v1

- Only SMBIOS-sourced identity. riscv64: device-tree root `serial-number` is not
  captured (the DT walker does not expose root properties cheaply), so riscv64
  always yields a weak id. aarch64 uses the same UEFI/SMBIOS path as x86_64 and
  compiles, but was not booted in QEMU for this.
- SMBIOS UUID byte order: 2.6+ tables use the mixed-endian rule (first three
  fields swapped), older tables are used as reported. Exact handling of < 2.6
  firmware is still TODO-13.
- The virtual flag is derived from firmware strings only (QEMU, KVM, VMware,
  VirtualBox, Xen, Hyper-V, ...); the CPUID hypervisor bit and virtual-OUI MACs
  (section 9) are not folded in yet.
- The placeholder list and the small duplicated-UUID list are the v1 lists of
  section 5.1; growing them requires a new label (TODO-9).
- Plain QEMU without `-smbios type=1,uuid=...` reports an all-zero UUID and empty
  serials, so its id is WEAK (and differs only by machine model); give QEMU a UUID to
  get a strong id.
- The serial log prints the derived id and its flags, never the raw UUID or serials
  (section 10). The id itself is meant to be visible to the logged-in user.
