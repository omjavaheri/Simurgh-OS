//! ============================================================================
//! verb.rs — HDA codec command (verb) encoding, spec section 7.
//!
//! Purpose: pure functions building the 32-bit CORB command words and decoding
//! parameter responses. Two command shapes exist (section 7.3): a 12-bit verb
//! with an 8-bit payload, and a 4-bit verb with a 16-bit payload (amp gain and
//! stream format). Word layout: bits 31:28 codec address, 27:20 node id
//! (bit 27 = "indirect" flag, unused), then the verb and payload.
//! ============================================================================

/// Get Parameter verb (12-bit form); the payload is a parameter id below.
pub const GET_PARAM: u16 = 0xF00;
/// Get Connection Select Control.
pub const GET_CONN_SEL: u16 = 0xF01;
/// Set Connection Select Control (payload = connection index).
pub const SET_CONN_SEL: u16 = 0x701;
/// Get Connection List Entry (payload = first index).
pub const GET_CONN_LIST: u16 = 0xF02;
/// Set Power State (payload 0 = D0).
pub const SET_POWER: u16 = 0x705;
/// Set Converter Stream, Channel (payload = stream << 4 | channel).
pub const SET_STREAM_CHAN: u16 = 0x706;
/// Set Pin Widget Control (bit 6 = output enable, bit 7 = headphone enable).
pub const SET_PIN_CTL: u16 = 0x707;
/// Set EAPD/BTL Enable (bit 1 = EAPD).
pub const SET_EAPD: u16 = 0x70C;
/// Get Pin Configuration Default.
pub const GET_PIN_CFG: u16 = 0xF1C;
/// Set Amplifier Gain/Mute (4-bit verb form, section 7.3.3.7).
pub const SET_AMP: u8 = 0x3;
/// Set Converter Format (4-bit verb form, section 7.3.3.8).
pub const SET_FMT: u8 = 0x2;

/// Parameter ids for `GET_PARAM` (section 7.3.4).
pub mod param {
    /// Vendor id (high 16) and device id (low 16).
    pub const VENDOR_ID: u8 = 0x00;
    /// Subordinate node count: start nid << 16 | count.
    pub const NODE_COUNT: u8 = 0x04;
    /// Function group type (low 8 bits; 1 = audio function group).
    pub const FG_TYPE: u8 = 0x05;
    /// Audio widget capabilities.
    pub const WIDGET_CAP: u8 = 0x09;
    /// Pin capabilities.
    pub const PIN_CAP: u8 = 0x0C;
    /// Connection list length.
    pub const CONN_LEN: u8 = 0x0E;
    /// Output amplifier capabilities.
    pub const AMP_OUT_CAP: u8 = 0x12;
}

/// Builds a 12-bit-verb command word.
pub fn verb12(cad: u8, nid: u8, verb: u16, payload: u8) -> u32 {
    ((cad as u32 & 0xF) << 28) | ((nid as u32) << 20) | ((verb as u32 & 0xFFF) << 8) | payload as u32
}

/// Builds a 4-bit-verb command word (16-bit payload).
pub fn verb4(cad: u8, nid: u8, verb: u8, payload: u16) -> u32 {
    ((cad as u32 & 0xF) << 28) | ((nid as u32) << 20) | ((verb as u32 & 0xF) << 16) | payload as u32
}

/// `GET_PARAM` for parameter `p` of node `nid`.
pub fn get_param(cad: u8, nid: u8, p: u8) -> u32 {
    verb12(cad, nid, GET_PARAM, p)
}

/// Payload of `SET_AMP` (section 7.3.3.7): bit 15 output amp, bit 14 input
/// amp, bit 13 left, bit 12 right, bits 11:8 index, bit 7 mute, bits 6:0 gain.
pub fn amp_payload(output: bool, left: bool, right: bool, mute: bool, gain: u8) -> u16 {
    ((output as u16) << 15)
        | ((!output as u16) << 14)
        | ((left as u16) << 13)
        | ((right as u16) << 12)
        | ((mute as u16) << 7)
        | (gain as u16 & 0x7F)
}

/// Decoded widget type (bits 23:20 of the widget capabilities).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidgetType {
    /// Audio output converter (DAC).
    AudioOut,
    /// Audio input converter (ADC).
    AudioIn,
    /// Audio mixer.
    Mixer,
    /// Audio selector.
    Selector,
    /// Pin complex.
    Pin,
    /// Power widget, volume knob, beep generator, vendor-defined: not used.
    Other,
}

/// Widget type from the `WIDGET_CAP` parameter.
pub fn widget_type(caps: u32) -> WidgetType {
    match (caps >> 20) & 0xF {
        0 => WidgetType::AudioOut,
        1 => WidgetType::AudioIn,
        2 => WidgetType::Mixer,
        3 => WidgetType::Selector,
        4 => WidgetType::Pin,
        _ => WidgetType::Other,
    }
}

/// Widget has an output amplifier (caps bit 2).
pub fn has_out_amp(caps: u32) -> bool {
    caps & (1 << 2) != 0
}
/// Widget's amp parameters override the function group's (caps bit 3).
pub fn amp_override(caps: u32) -> bool {
    caps & (1 << 3) != 0
}
/// Widget has a connection list (caps bit 8).
pub fn has_conn_list(caps: u32) -> bool {
    caps & (1 << 8) != 0
}

/// Decoded output amplifier capabilities (parameter 0x12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AmpCaps {
    /// Gain step that is 0 dB.
    pub offset: u8,
    /// Number of steps (0-based: valid gains are `0..=num_steps`).
    pub num_steps: u8,
    /// The amp has a mute bit.
    pub mute: bool,
}

/// Decodes an amp capabilities response. `None` when the amp is not
/// adjustable at all (zero steps and no mute).
pub fn decode_amp_caps(v: u32) -> Option<AmpCaps> {
    let c = AmpCaps {
        offset: (v & 0x7F) as u8,
        num_steps: ((v >> 8) & 0x7F) as u8,
        mute: v & (1 << 31) != 0,
    };
    if c.num_steps == 0 && !c.mute {
        None
    } else {
        Some(c)
    }
}

/// `(start nid, count)` from a `NODE_COUNT` response.
pub fn decode_node_count(v: u32) -> (u8, u8) {
    (((v >> 16) & 0xFF) as u8, (v & 0xFF) as u8)
}

/// Pin default-configuration fields (section 7.3.3.31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinConfig {
    /// Port connectivity: 0 jack, 1 none, 2 fixed function, 3 jack + internal.
    pub connectivity: u8,
    /// Default device: 0 line out, 1 speaker, 2 headphone out, 8 line in, ...
    pub device: u8,
}

/// Decodes a `GET_PIN_CFG` response.
pub fn decode_pin_config(v: u32) -> PinConfig {
    PinConfig { connectivity: (v >> 30) as u8, device: ((v >> 20) & 0xF) as u8 }
}

/// Pin can drive an output (pin capabilities bit 4).
pub fn pin_output_capable(pin_caps: u32) -> bool {
    pin_caps & (1 << 4) != 0
}
/// Pin has an EAPD external amplifier control (pin capabilities bit 16).
pub fn pin_has_eapd(pin_caps: u32) -> bool {
    pin_caps & (1 << 16) != 0
}

/// Short human name for a codec vendor id (upper 16 bits of the vendor
/// parameter). Unknown vendors get `None`; the caller prints the hex id.
pub fn vendor_name(vendor: u16) -> Option<&'static str> {
    Some(match vendor {
        0x1af4 => "QEMU",
        0x10ec => "Realtek",
        0x8086 => "Intel",
        0x111d => "IDT",
        0x14f1 => "Conexant",
        0x1106 => "VIA",
        0x10de => "NVIDIA",
        0x1002 => "AMD",
        0x11d4 => "Analog Devices",
        0x1057 => "Motorola",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn get_param_word_matches_spec_example() {
        // Codec 0, root node 0, vendor id: 0x000F0000 (a well-known first CORB word).
        assert_eq!(get_param(0, 0, param::VENDOR_ID), 0x000F_0000);
        // Codec 0, nid 1, node count: 0x001F0004.
        assert_eq!(get_param(0, 1, param::NODE_COUNT), 0x001F_0004);
        // Codec 2, nid 0x1F, widget caps.
        assert_eq!(get_param(2, 0x1F, param::WIDGET_CAP), 0x21FF_0009);
    }

    #[test]
    fn twelve_bit_verbs() {
        assert_eq!(verb12(0, 2, SET_STREAM_CHAN, 0x10), 0x0027_0610);
        assert_eq!(verb12(0, 3, SET_PIN_CTL, 0x40), 0x0037_0740);
        assert_eq!(verb12(1, 0x0A, SET_POWER, 0), 0x10A7_0500);
        assert_eq!(verb12(0, 4, GET_PIN_CFG, 0), 0x004F_1C00);
    }

    #[test]
    fn four_bit_verbs() {
        assert_eq!(verb4(0, 2, SET_FMT, 0x0011), 0x0022_0011);
        // Output amp, both channels, unmuted, gain 0x4A: 0xB04A? no: bit15 out,
        // bit13 left, bit12 right => 0xB000 | 0x4A.
        let p = amp_payload(true, true, true, false, 0x4A);
        assert_eq!(p, 0xB04A);
        assert_eq!(verb4(0, 2, SET_AMP, p), 0x0023_B04A);
        // Muted, gain ignored bits beyond 7.
        assert_eq!(amp_payload(true, true, true, true, 0xFF), 0xB0FF);
        // Input amp sets bit 14, not 15.
        assert_eq!(amp_payload(false, true, false, false, 1), 0x6001);
    }

    #[test]
    fn widget_caps_decode() {
        let dac = 0x0000_000D | (0 << 20);
        assert_eq!(widget_type(dac), WidgetType::AudioOut);
        assert!(has_out_amp(dac) && amp_override(dac));
        assert_eq!(widget_type(4 << 20), WidgetType::Pin);
        assert_eq!(widget_type(2 << 20), WidgetType::Mixer);
        assert_eq!(widget_type(9 << 20), WidgetType::Other);
        assert!(has_conn_list(1 << 8));
    }

    #[test]
    fn amp_caps_decode() {
        // QEMU hda-duplex: offset 0x4a, 0x4a steps, mute capable.
        let v = 0x4A | (0x4A << 8) | (1 << 31);
        assert_eq!(decode_amp_caps(v), Some(AmpCaps { offset: 0x4A, num_steps: 0x4A, mute: true }));
        assert_eq!(decode_amp_caps(0x0000_0000), None);
        assert_eq!(decode_amp_caps(1 << 31).map(|c| c.mute), Some(true));
    }

    #[test]
    fn node_count_and_pin_config() {
        assert_eq!(decode_node_count(0x0001_0001), (1, 1));
        assert_eq!(decode_node_count(0x0002_0004), (2, 4));
        // Fixed-function speaker: connectivity 2, device 1.
        let c = decode_pin_config((2 << 30) | (1 << 20) | 0x4010);
        assert_eq!(c, PinConfig { connectivity: 2, device: 1 });
        assert!(pin_output_capable(1 << 4) && !pin_output_capable(1 << 5));
        assert!(pin_has_eapd(1 << 16));
    }

    #[test]
    fn vendor_names() {
        assert_eq!(vendor_name(0x10ec), Some("Realtek"));
        assert_eq!(vendor_name(0x1234), None);
    }
}
