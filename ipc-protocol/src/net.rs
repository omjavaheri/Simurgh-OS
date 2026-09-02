//! ============================================================================
//! net.rs
//!
//! Purpose: the control-plane messages for the DPDK-style kernel-bypass
//! networking path (03-Kernel-Subsystems-Layer.md §2.3). This is only the
//! *setup* handshake — once a client holds a `DirectNicHandle` it drives
//! the NIC's rx/tx rings directly through a mapped `SharedRegion` and
//! `hal-direct`, with no further IPC on the data path (§2.3: "بدون عبور از
//! مسیر معمول IPC/Netstack داده می‌فرستد").
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.3
//! (`KernelBypassNetworking` trait), §5.4.1 (MVP: the bypass path is ≥30–40%
//! lower latency than the standard Netstack path).
//!
//! Position in the system: encoded into `kernel_ipc::SmallMessage`. The
//! standard (non-bypass) Netstack path uses ordinary socket-style messages
//! that are out of scope for this MVP module.
//!
//! Safety/invariants: plain integer fields; `Copy`.
//! ============================================================================

/// An opaque per-client handle to a directly-driven NIC, returned by
/// `RequestDirectNic`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirectNicHandle(pub u32);

/// A control-plane request on the kernel-bypass networking path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetBypassRequest {
    /// Ask Netstack for direct access to NIC `nic_id`. Netstack checks the
    /// client's special bypass capability (issued by the layer-4 Security
    /// Broker) and, if valid, sets up rx/tx ring `SharedRegion`s and
    /// replies `Granted`. Reply: `Granted` or `Denied`.
    RequestDirectNic {
        /// Device id of the target NIC (from the Hardware Manifest).
        nic_id: u32,
    },
    /// Relinquish a previously granted `DirectNicHandle`; Netstack tears
    /// down the ring mappings and resumes normal handling of the NIC.
    /// Reply: `Released`.
    Release {
        /// The handle to release.
        handle: DirectNicHandle,
    },
    /// Sends ONE frame via the STANDARD (non-bypass) path: Netstack
    /// itself relays the request to the driver over its own real
    /// `DriverRequest::SendFrame` IPC call and waits for the real
    /// interrupt-driven TX completion (`driver_virtio_net::subsystem_
    /// entry::handle_send_frame`'s own doc comment) — semantically the
    /// SAME "real hardware completion confirmed" endpoint `kernel_arch_
    /// glue::net_bypass_direct_send` waits for, just reached through two
    /// extra real IPC hops (client -> Netstack, Netstack -> driver) the
    /// bypass path skips entirely. Exists purely so §5.4.1's own "the
    /// bypass path is ≥30-40% lower latency than the standard path"
    /// claim has something real to compare against, rather than being
    /// asserted. Reply: `Relayed` or `Denied`.
    RelayFrame,
}

/// A reply on the kernel-bypass control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetBypassResponse {
    /// Direct access granted.
    Granted {
        /// The new handle.
        handle: DirectNicHandle,
        /// Client capability slot naming the rx-ring `SharedRegion`.
        rx_ring_cap: u32,
        /// Client capability slot naming the tx-ring `SharedRegion`.
        tx_ring_cap: u32,
        /// Number of descriptors in each ring.
        ring_len: u32,
    },
    /// The client's bypass capability was missing or invalid.
    Denied,
    /// `Release` completed.
    Released,
    /// `RelayFrame` completed — the driver confirmed the real hardware
    /// TX completion.
    Relayed,
}
