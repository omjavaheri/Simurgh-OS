//! ============================================================================
//! pic.rs — 8259 Programmable Interrupt Controller (legacy ISA IRQ routing)
//!
//! Purpose: this project has no I/O APIC / MADT infrastructure at all yet
//! (confirmed by a repo-wide search before writing this file) — only PCI
//! MSI/MSI-X (`peripheral.rs`'s own `X86_64_VIRTIO_BLK_MSI_VECTOR`/
//! `X86_64_VIRTIO_NET_MSI_VECTOR`) and the Local APIC timer
//! (`interrupt::TIMER_VECTOR`) are wired to a CPU vector today. The i8042
//! PS/2 keyboard has no PCI config space, no BAR, and its IRQ line (ISA
//! IRQ1) is only ever routed through the legacy 8259 PIC pair — this file
//! is the smallest real path to get that one line delivering to a CPU
//! vector at all. QEMU's own `q35` machine type keeps the PIC feeding the
//! CPU's INTR pin unless an OS explicitly switches to APIC-based routing
//! (via ACPI/IMCR), which nothing in this project does — so a remapped
//! PIC vector reaches `interrupt::dispatch_vector` exactly like an MSI
//! vector does; that function doesn't know or care which mechanism
//! signaled it.
//!
//! Building an I/O APIC path instead would need new MADT parsing, I/O
//! APIC MMIO window discovery, redirection-table programming, and IMCR
//! handling — a much larger, less-reviewable diff for a feature whose
//! entire hardware surface is one legacy ISA line. See this project's own
//! session record for the full comparison; PIC remap was the deliberate,
//! reasoned choice, not a default.
//!
//! **The one real, non-obvious catch**: a PIC-sourced interrupt must be
//! acknowledged at the PIC itself (`outb(0x20, 0x20)` for a master-line
//! IRQ), not only at the Local APIC — `interrupt::dispatch_vector`'s own
//! unconditional Local-APIC EOI tail is harmless (a no-op for a vector the
//! Local APIC's own ISR never actually latched) but is NOT sufficient on
//! its own: without a PIC-level EOI, the PIC's internal ISR bit for that
//! line never clears and it stops firing after the first interrupt. The
//! i8042 IRQ handler (`kernel_arch_glue`'s own trampoline, not this file)
//! is responsible for calling [`send_eoi`] — this file only remaps and
//! masks, it does not itself handle any interrupt.
//!
//! Scope: remap + mask-all + selective-unmask + EOI only. This file does
//! not touch the IMCR (port 0x22/0x23, "disconnect the legacy PIC in
//! favor of the I/O APIC") — nothing in this project ever enables I/O
//! APIC routing, so there is nothing to disconnect from.
//! ============================================================================

// ----------------------------------------------------------------------------
// Port I/O — this file's own private copies, not a shared import from
// `power.rs`. Mirrors this crate's own established convention
// (`interrupt.rs`'s `initial_apic_id` doc comment: a small, self-contained
// helper costs less than a cross-module visibility change) rather than
// making `power.rs`'s `inb`/`outb` `pub(crate)`.
// ----------------------------------------------------------------------------

/// # Safety
/// `port` must name a port whose read has no side effect the caller does
/// not want — every call site in this file reads a PIC data/command
/// register, architecturally safe to poll.
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value);
    }
    value
}

/// # Safety
/// `port`/`value` must be a combination the caller has verified is safe
/// to write — every call site in this file is documented with the exact
/// port and value it writes and why.
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value);
    }
}

// ----------------------------------------------------------------------------
// 8259 PIC ports and ICW/OCW constants (Intel 8259A datasheet; this exact
// remap sequence is the long-standing, well-documented convention every
// small/hobby x86 kernel uses).
// ----------------------------------------------------------------------------

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const ICW1_INIT: u8 = 0x11; // ICW1: edge-triggered, cascade mode, ICW4 needed
const ICW4_8086: u8 = 0x01; // ICW4: 8086/88 mode (not 8080 mode)
const PIC2_CASCADE_IDENTITY: u8 = 0x02; // slave's own cascade identity (line 2)
const PIC1_CASCADE_LINE_MASK: u8 = 0x04; // tells master: slave lives on IRQ2

/// Vector offset the master PIC's lines (IRQ0-7) are remapped to. Chosen
/// to avoid every vector this project already reserves:
/// `interrupt::TIMER_VECTOR = 32`, and `peripheral.rs`'s own
/// `X86_64_VIRTIO_BLK_MSI_VECTOR = 44` / `X86_64_VIRTIO_NET_MSI_VECTOR =
/// 45` (plus that file's own `+ 1 = 46` fallback for any other
/// peripheral kind) — 80 is clear of all of them with wide margin.
pub const PIC1_OFFSET: u8 = 80;
/// Vector offset the slave PIC's lines (IRQ8-15) are remapped to. Must be
/// distinct from [`PIC1_OFFSET`] by at least 8 (one vector per line);
/// this project's only slave-side use today is none at all (i8042's own
/// IRQ1 is a master-line IRQ), but the slave is still remapped (not left
/// at its power-on default of vector 8, which would collide with the
/// CPU's own double-fault vector) since a remap must always be done as a
/// cascaded pair.
pub const PIC2_OFFSET: u8 = 88;

/// The i8042 keyboard's own CPU vector after remap — `PIC1_OFFSET + 1`
/// (ISA IRQ1 is the master PIC's line 1). The single source of truth
/// both [`init`]/[`unmask_irq1`] and `kernel_arch_glue`'s own synthetic
/// `MmioRegionDescriptor` construction (for `SyscallOp::IrqBind`) import
/// from.
pub const KEYBOARD_IRQ_VECTOR: u32 = PIC1_OFFSET as u32 + 1;

/// Clears bit `line` (0-7) in a PIC interrupt-mask byte — pure logic,
/// exercised by this file's own unit tests below without touching real
/// hardware ports.
const fn unmask_bit(mask: u8, line: u8) -> u8 {
    mask & !(1 << line)
}

/// Remaps both PICs to [`PIC1_OFFSET`]/[`PIC2_OFFSET`], then masks every
/// line. Callers must follow with [`unmask_irq1`] (or any other specific
/// line they actually intend to service) — nothing is usable until then.
///
/// Must run exactly once, after the IDT is loaded (so a remapped vector
/// has a valid gate the moment it can fire) and before `sti` is ever
/// issued (boot.S never does so before `kernel_main` drops to Ring 3) —
/// same ordering contract `hal_x86_64_rust_entry`'s own `interrupt::
/// set_global_controller` call already documents for interrupt setup.
///
/// # Safety
/// Must be called on the boot core, exactly once, before any code enables
/// interrupts — same precondition every other one-time hardware-init
/// function in this crate carries (e.g. `InterruptCtrl::bootstrap_
/// current_core`).
pub unsafe fn init() {
    // SAFETY: forwarded from this function's own contract; this is the
    // standard 4-byte ICW1/ICW2/ICW3/ICW4 remap sequence, issued to both
    // PICs in the documented order (master before slave for each step).
    unsafe {
        outb(PIC1_COMMAND, ICW1_INIT);
        outb(PIC2_COMMAND, ICW1_INIT);
        outb(PIC1_DATA, PIC1_OFFSET);
        outb(PIC2_DATA, PIC2_OFFSET);
        outb(PIC1_DATA, PIC1_CASCADE_LINE_MASK);
        outb(PIC2_DATA, PIC2_CASCADE_IDENTITY);
        outb(PIC1_DATA, ICW4_8086);
        outb(PIC2_DATA, ICW4_8086);

        // Mask every line on both PICs — callers unmask exactly the
        // lines they intend to service (`unmask_irq1` below), nothing is
        // live by default.
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

/// Unmasks IRQ1 (the i8042 keyboard's own line) on the master PIC. Must
/// run after [`init`].
///
/// # Safety
/// Same one-time-hardware-init contract as [`init`] — must not race a
/// concurrent PIC register access (single-core boot sequencing, same as
/// every other call site in this file).
pub unsafe fn unmask_irq1() {
    // SAFETY: forwarded from this function's own contract. Read-modify-
    // write of the master PIC's own mask register — safe to read back
    // immediately after `init`'s own write above, nothing else touches
    // this port between them.
    unsafe {
        let mask = inb(PIC1_DATA);
        outb(PIC1_DATA, unmask_bit(mask, 1));
    }
}

/// The i8042 controller's own data port — where a keyboard scancode byte
/// lands once IRQ1 fires. Colocated here (not a separate module) since
/// every real caller reads this port and sends the PIC EOI ([`send_eoi`])
/// together, in the same IRQ handler.
const I8042_DATA_PORT: u16 = 0x60;

/// Reads the i8042 keyboard's own pending scancode byte. Must be called
/// from the IRQ1 handler itself (reading this port is how the real
/// hardware clears its own "data ready" condition — there is no separate
/// device-side ack the way `virtio_net_irq_trampoline`'s own MMIO
/// `INTERRUPT_ACK` write is; the read IS the ack, at the device level —
/// [`send_eoi`] is the separate, additional ack the PIC ITSELF still
/// needs regardless).
///
/// # Safety
/// Must only be called from the IRQ handler currently servicing IRQ1 —
/// reading this port outside that context (e.g. when no byte is actually
/// pending) reads undefined/stale hardware state.
pub unsafe fn read_scancode() -> u8 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { inb(I8042_DATA_PORT) }
}

/// Acknowledges a master-PIC-line interrupt (IRQ0-7) — must be called by
/// the servicing `IrqHandler` itself, in kernel/interrupt context, for
/// every PIC-routed interrupt this project services (see this file's own
/// module doc comment for why this is not optional). This file only
/// covers the master line since i8042's own IRQ1 never routes through
/// the slave PIC; a slave-line EOI would additionally need a `PIC2_
/// COMMAND` write before this one, per the 8259 cascade convention — not
/// implemented here since nothing in this project uses a slave line yet.
///
/// # Safety
/// Must only be called from the IRQ handler actually servicing the
/// master-PIC-sourced interrupt currently being acknowledged — an
/// out-of-context call would prematurely clear the PIC's in-service bit.
pub unsafe fn send_eoi() {
    const OCW2_EOI: u8 = 0x20;
    // SAFETY: forwarded from this function's own contract.
    unsafe { outb(PIC1_COMMAND, OCW2_EOI) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmask_bit_clears_only_the_named_line() {
        assert_eq!(unmask_bit(0xFF, 1), 0b1111_1101);
        assert_eq!(unmask_bit(0xFF, 0), 0b1111_1110);
        assert_eq!(unmask_bit(0b1111_1101, 1), 0b1111_1101); // idempotent
    }

    #[test]
    fn keyboard_irq_vector_is_master_offset_plus_one() {
        assert_eq!(KEYBOARD_IRQ_VECTOR, PIC1_OFFSET as u32 + 1);
    }

    #[test]
    fn pic_offsets_do_not_collide_with_reserved_vectors() {
        // TIMER_VECTOR = 32, virtio MSI vectors 44/45/46 (peripheral.rs).
        const RESERVED: [u32; 4] = [32, 44, 45, 46];
        for v in [PIC1_OFFSET as u32, PIC1_OFFSET as u32 + 7, PIC2_OFFSET as u32, PIC2_OFFSET as u32 + 7] {
            assert!(!RESERVED.contains(&v), "vector {v} collides with a reserved vector");
        }
    }
}
