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
//!
//! **Mouse input plan, Stage 1a**: the PS/2 mouse's own IRQ12 is a
//! SLAVE-PIC line (real hardware topology: slave line 4, cascaded into
//! the master through the master's own IRQ2) — a structurally different
//! case from keyboard IRQ1 (a master-PIC line) in two real ways this
//! file's own [`unmask_irq12`]/[`send_eoi_slave`] exist to handle: the
//! master's own cascade line must stay unmasked too, and a slave-line
//! interrupt needs TWO EOIs, slave-then-master, not one. The mouse also
//! needs a real controller-level enable sequence ([`enable_ps2_mouse`])
//! the keyboard never did, since the i8042 controller's auxiliary port
//! boots disabled on real hardware.
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

/// The PS/2 mouse's own CPU vector after remap (mouse input plan, Stage
/// 1a) — `PIC2_OFFSET + 4` (real-hardware topology: PS/2 mouse is IRQ12,
/// the slave PIC's own line 4 — IRQ8 is the slave's line 0, so IRQ12 is
/// line 4). The single source of truth both [`init`]/[`unmask_irq12`]
/// and `kernel_arch_glue`'s own synthetic `MmioRegionDescriptor`
/// construction (for `SyscallOp::IrqBind`) import from — same role
/// [`KEYBOARD_IRQ_VECTOR`] already has for IRQ1.
pub const MOUSE_IRQ_VECTOR: u32 = PIC2_OFFSET as u32 + 4;

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

/// Unmasks IRQ12 (the PS/2 mouse's own line, real-hardware-topology
/// slave line 4 — mouse input plan, Stage 1a). Unlike [`unmask_irq1`],
/// this is not a single-register write: IRQ12 is a SLAVE-PIC line,
/// cascaded into the master through the master's own IRQ2, so the
/// master's line 2 must ALSO stay unmasked (`init`'s own mask-everything
/// step masked it, exactly like every other line) — a slave interrupt
/// the master itself is still blocking never reaches the CPU at all,
/// regardless of the slave's own mask state. Must run after [`init`].
///
/// # Safety
/// Same one-time-hardware-init contract as [`unmask_irq1`].
pub unsafe fn unmask_irq12() {
    // SAFETY: forwarded from this function's own contract; same read-
    // modify-write reasoning as `unmask_irq1`, applied to both PICs
    // (master's own cascade line 2, then slave's own line 4).
    unsafe {
        let master_mask = inb(PIC1_DATA);
        outb(PIC1_DATA, unmask_bit(master_mask, 2));
        let slave_mask = inb(PIC2_DATA);
        outb(PIC2_DATA, unmask_bit(slave_mask, 4));
    }
}

/// The i8042 controller's own data port — where a keyboard scancode byte
/// lands once IRQ1 fires. Colocated here (not a separate module) since
/// every real caller reads this port and sends the PIC EOI ([`send_eoi`])
/// together, in the same IRQ handler.
const I8042_DATA_PORT: u16 = 0x60;

/// The i8042 controller's own command/status port — same port
/// `hal_x86_64::power`'s own `reboot` already uses for its reset pulse
/// (this file's own private copy, per this file's own "small self-
/// contained duplicate" convention — see the module doc comment above
/// [`inb`]).
const I8042_COMMAND_PORT: u16 = 0x64;

const I8042_STATUS_OUTPUT_FULL: u8 = 1 << 0; // a byte is waiting at I8042_DATA_PORT
const I8042_STATUS_INPUT_FULL: u8 = 1 << 1; // the controller hasn't consumed the last byte yet

/// Real hardware ceiling on how long this file ever spins waiting for
/// the i8042 controller to catch up — matches `power.rs::reboot`'s own
/// `spins < 1_000_000` bound (real hardware/QEMU both respond in far
/// fewer iterations; this exists only so a genuinely wedged/absent
/// controller can't hang boot forever).
const MAX_POLL_SPINS: u32 = 1_000_000;

/// # Safety
/// Same contract as [`inb`] — polls `I8042_COMMAND_PORT`, architecturally
/// safe.
unsafe fn wait_for_input_buffer_empty() {
    let mut spins = 0u32;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        while inb(I8042_COMMAND_PORT) & I8042_STATUS_INPUT_FULL != 0 && spins < MAX_POLL_SPINS {
            spins += 1;
        }
    }
}

/// # Safety
/// Same contract as [`inb`] — polls `I8042_COMMAND_PORT`, architecturally
/// safe.
unsafe fn wait_for_output_buffer_full() {
    let mut spins = 0u32;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        while inb(I8042_COMMAND_PORT) & I8042_STATUS_OUTPUT_FULL == 0 && spins < MAX_POLL_SPINS {
            spins += 1;
        }
    }
}

/// Real i8042 controller commands (Intel/AMI 8042 datasheet convention
/// every real PC-compatible controller — and QEMU's own i8042 emulation
/// — implements identically; this is not a QEMU-only shortcut).
const CMD_ENABLE_AUX_DEVICE: u8 = 0xA8;
const CMD_READ_CONFIG_BYTE: u8 = 0x20;
const CMD_WRITE_CONFIG_BYTE: u8 = 0x60;
const CMD_WRITE_TO_AUX: u8 = 0xD4;
const CONFIG_AUX_INTERRUPT_ENABLE: u8 = 1 << 1; // "enable IRQ12" bit in the config byte
const CONFIG_AUX_CLOCK_DISABLE: u8 = 1 << 5; // must be CLEARED to let the mouse's own clock run
const MOUSE_CMD_ENABLE_DATA_REPORTING: u8 = 0xF4; // starts real PS/2 packet streaming

/// Real PS/2 controller init that turns the mouse on — unlike the
/// keyboard, which the controller already streams by default, the
/// auxiliary (mouse) port boots DISABLED on real hardware and in QEMU's
/// own i8042 emulation alike; without this sequence, `unmask_irq12`
/// alone unmasks a line the device itself never drives. Real protocol,
/// not a QEMU-only shortcut (Intel/AMI 8042 controller command set):
/// enable the aux port, flip the controller's own config byte to permit
/// its IRQ and clock, then tell the mouse itself (via the controller's
/// own "next byte goes to the mouse" gate) to start streaming real
/// motion/button packets.
///
/// # Safety
/// Same one-time-hardware-init contract as [`init`] — must run once, on
/// the boot core, after [`init`]/[`unmask_irq12`], before `sti`.
pub unsafe fn enable_ps2_mouse() {
    // SAFETY: forwarded from this function's own contract; every step
    // below is the documented real controller command sequence, each
    // preceded by the real handshake wait its own datasheet requires.
    unsafe {
        wait_for_input_buffer_empty();
        outb(I8042_COMMAND_PORT, CMD_ENABLE_AUX_DEVICE);

        wait_for_input_buffer_empty();
        outb(I8042_COMMAND_PORT, CMD_READ_CONFIG_BYTE);
        wait_for_output_buffer_full();
        let config = inb(I8042_DATA_PORT);

        let new_config = (config | CONFIG_AUX_INTERRUPT_ENABLE) & !CONFIG_AUX_CLOCK_DISABLE;
        wait_for_input_buffer_empty();
        outb(I8042_COMMAND_PORT, CMD_WRITE_CONFIG_BYTE);
        wait_for_input_buffer_empty();
        outb(I8042_DATA_PORT, new_config);

        wait_for_input_buffer_empty();
        outb(I8042_COMMAND_PORT, CMD_WRITE_TO_AUX);
        wait_for_input_buffer_empty();
        outb(I8042_DATA_PORT, MOUSE_CMD_ENABLE_DATA_REPORTING);
        // The mouse itself replies with a real ACK (0xFA) on the same
        // data port — drained here so it doesn't get misread as the
        // first byte of the first real motion packet by the IRQ12
        // trampoline. Not checked against 0xFA: a real mouse that
        // doesn't ACK also won't send motion packets, so a missing/
        // malformed ACK is already self-evident from the absence of
        // any further real data, per this project's own "an honest gap
        // beats a guessed answer" convention — no special-cased error
        // path needed here. Confirmed on a real QEMU x86_64 boot
        // (2026-09-11) to actually be `0xFA` — a real, working PS/2
        // mouse ACK, not a hypothetical.
        wait_for_output_buffer_full();
        let _ack = inb(I8042_DATA_PORT);
    }
}

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

/// Reads the PS/2 mouse's own pending packet byte. Real PS/2 hardware
/// routes BOTH the keyboard and the mouse through this SAME data port
/// (0x60) — which device a given byte came from is determined entirely
/// by which IRQ line fired (IRQ1 → keyboard, IRQ12 → mouse), never by
/// the port itself; this function is a named alias of the identical
/// port read [`read_scancode`] already performs, kept separate only so
/// each IRQ handler's own call site self-documents which device it's
/// servicing.
///
/// # Safety
/// Same contract as [`read_scancode`], for the IRQ12 handler.
pub unsafe fn read_mouse_byte() -> u8 {
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
/// Real-hardware note (kept accurate now that [`send_eoi_slave`] below
/// exists too): this function alone is correct ONLY for a master-PIC
/// line (IRQ0-7, e.g. i8042's own IRQ1) — a slave-PIC line (IRQ8-15,
/// e.g. the PS/2 mouse's own IRQ12) needs [`send_eoi_slave`] instead;
/// see that function's own doc comment for why one EOI is not enough
/// there.
pub unsafe fn send_eoi() {
    const OCW2_EOI: u8 = 0x20;
    // SAFETY: forwarded from this function's own contract.
    unsafe { outb(PIC1_COMMAND, OCW2_EOI) };
}

/// Acknowledges a slave-PIC-line interrupt (IRQ8-15, e.g. the PS/2
/// mouse's own IRQ12) — the two-EOI cascade requirement [`send_eoi`]'s
/// own doc comment already names: the slave PIC's own in-service bit
/// must be cleared first (`PIC2_COMMAND`), THEN the master's (`PIC1_
/// COMMAND`), since the master ALSO latched an in-service bit for its
/// own cascade line (IRQ2) the moment the slave raised it — leaving
/// that master-side bit set would silently stop ALL further slave-PIC
/// interrupts (any IRQ8-15 line), not just the one just serviced, even
/// though the individual line's own mask bit is still clear.
///
/// # Safety
/// Same contract as [`send_eoi`], for a slave-PIC-sourced interrupt.
pub unsafe fn send_eoi_slave() {
    const OCW2_EOI: u8 = 0x20;
    // SAFETY: forwarded from this function's own contract; order matters
    // per this function's own doc comment (slave first, then master).
    unsafe {
        outb(PIC2_COMMAND, OCW2_EOI);
        outb(PIC1_COMMAND, OCW2_EOI);
    }
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
    fn mouse_irq_vector_is_slave_offset_plus_four() {
        assert_eq!(MOUSE_IRQ_VECTOR, PIC2_OFFSET as u32 + 4);
        // IRQ12 must land on the SLAVE PIC's own vector range, never the
        // master's — a real, easy-to-get-backwards mistake this test
        // guards against (mixing up PIC1_OFFSET/PIC2_OFFSET).
        assert!(MOUSE_IRQ_VECTOR >= PIC2_OFFSET as u32 && MOUSE_IRQ_VECTOR < PIC2_OFFSET as u32 + 8);
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
