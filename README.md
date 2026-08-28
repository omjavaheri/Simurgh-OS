# Simurgh-OS-Layer01-HAL
Hardware Abstraction Layer for Simurgh OS – a no_std, architecture-agnostic HAL implementing CPU, memory, interrupt, timer, and heterogeneous compute discovery for x86_64, ARM64, and RISC-V. a unified Hardware Manifest for professional users.

## Hardware Abstraction Layer (HAL) Base structure
[English HAL Base structure](https://github.com/omjavaheri/Simurgh-OS-Doc/blob/main/en_US/HAL-STRUCTURE-GUIDE.md)

[Persian/فارسی HAL Base structure](https://github.com/omjavaheri/Simurgh-OS-Doc/blob/main/fa_IR/HAL-STRUCTURE-GUIDE.md)

[Chinese/简体中文 HAL Base structure](https://github.com/omjavaheri/Simurgh-OS-Doc/blob/main/zh_CN/HAL-STRUCTURE-GUIDE.md)

[Arabic/العربية HAL Base structure](https://github.com/omjavaheri/Simurgh-OS-Doc/blob/main/ar_AE/HAL-STRUCTURE-GUIDE.md)


## Overview

`os-hal` is the lowest-level hardware abstraction layer of the operating system.

It runs in kernel space and has no dependency on an existing operating system. The implementation is primarily written in Rust with `no_std`, with minimal architecture-specific assembly required during the earliest bootstrap stage.

The initial target architectures are:

* x86_64
* ARM64 / AArch64
* RISC-V / RV64GC

HAL is the only layer allowed to communicate directly with hardware registers, MMIO regions, CPU-specific instructions, interrupt controllers, timers, and other privileged hardware interfaces.

## Architecture

```text
HAL
├── hal-core
│   └── Common safe hardware abstractions
│
├── hal-direct
│   └── Capability-gated advanced hardware access
│
├── hal-x86_64
│   └── x86_64 implementation
│
├── hal-arm64
│   └── ARM64 implementation
│
├── hal-riscv64
│   └── RISC-V implementation
│
└── hal-manifest
    └── Hardware Manifest representation
```

## Responsibilities

HAL provides abstractions for:

* CPU initialization
* CPU feature discovery
* Privilege levels
* Hardware context switching
* Memory discovery and bootstrap
* MMU/IOMMU initialization
* Timers and clocks
* Interrupt controllers
* Boot information
* GPU/NPU/TPU/FPGA discovery
* Power and thermal information
* Hardware capability discovery

## Discovery Model

Hardware discovery is always complete.

Installation profiles do not determine which hardware HAL discovers.

For example, an NPU must still be discovered and represented in the Hardware Manifest even when the installed system profile does not enable the corresponding service.

Policy decisions are handled by higher layers.

## Hardware Manifest

HAL produces a `HardwareManifest` describing the detected hardware.

The initial boot-time representation uses a fixed-size binary structure:

```rust
#[repr(C)]
pub struct HardwareManifestRaw {
    pub cpu_core_count: u32,
    pub cpu_feature_flags: u64,
    pub memory_region_count: u32,
    pub memory_regions: [MemoryRegionRaw; MAX_MEMORY_REGIONS],
    pub compute_device_count: u32,
    pub compute_devices: [ComputeDeviceRaw; MAX_COMPUTE_DEVICES],
    pub interrupt_controller: InterruptControllerInfoRaw,
    pub timer: TimerInfoRaw,
    pub power_domain_count: u32,
    pub power_domains: [PowerDomainRaw; MAX_POWER_DOMAINS],
}
```

The fixed representation is used during the earliest boot stage where no real allocator is available.

After the Root Task has initialized the heap, higher layers may convert this representation into a dynamic structure.

## Supported Architectures

### x86_64

Initial support includes:

* UEFI
* e820 memory information
* APIC / x2APIC
* TSC / HPET

### ARM64

Both ACPI and Device Tree are supported.

When a valid ACPI RSDP is available, ACPI has priority. Otherwise Device Tree is used.

### RISC-V

Initial support includes:

* SBI
* Device Tree
* PLIC / CLIC
* `mtime` / `mtimecmp`

## HAL Direct

`hal-direct` provides advanced hardware operations for trusted users and drivers.

All operations require a valid `CapabilityToken`.

Examples include:

* MMIO mapping
* Performance counters
* CPU pinning
* NUMA policy configuration

HAL does not issue capabilities. Capability issuance belongs to the Security / Permission Broker in the higher system layers.

HAL only validates the supplied capability.

## Safety Requirements

All crates use `#![no_std]`.

Architecture-specific code must remain isolated inside the architecture crates.

No architecture-specific conditional compilation should leak into higher layers.

Every `unsafe` block must document why the operation is safe.

## Build Targets

Expected targets include:

```text
x86_64-unknown-none
aarch64-unknown-none
riscv64gc-unknown-none-elf
```

The earliest bootstrap code may contain minimal assembly in:

```text
boot.S
```

The remaining implementation should be Rust.

## MVP Definition of Done

The MVP is considered complete when:

1. HAL successfully boots on QEMU for all three architectures.
2. A valid Hardware Manifest is generated.
3. The system reports CPU cores, at least one memory region, and an active timer.
4. Control is transferred to a microkernel stub.
5. The stub can print `hello from kernel` through the serial interface.
6. Trait-level unit tests run using mock hardware.
7. QEMU integration tests run in CI.

## Repository Scope

This repository contains only the HAL.

The microkernel, kernel subsystems, system services, compatibility runtime, and applications belong to separate repositories.

## License MPL-2.0

See [`LICENSE`](LICENSE).

