//! ============================================================================
//! codec.rs — codec discovery and widget graph walk (spec sections 6 and 7).
//!
//! Purpose: given a way to send one verb and get its response, find the audio
//! function group, then the best output pin that reaches a DAC, and report the
//! path (DAC first, pin last), the connection selections needed along it and
//! the adjustable output amps on it.
//!
//! Pure: no MMIO here, so the whole walk is host-tested against a fake codec.
//! Route policy (TODO(spec) 3 in docs/audio-plan.md): pins are ranked
//! speaker, line out, headphone, other; the first ranked pin with a path wins.
//! ============================================================================

use crate::verb::*;

/// Longest DAC-to-pin path the walk follows (DAC, up to four mixers or
/// selectors, pin).
pub const MAX_PATH: usize = 6;
/// Most connection-list entries read per widget.
const MAX_CONN: usize = 16;

/// Why a walk found nothing to play through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// The codec did not answer the very first verb.
    NoResponse,
    /// No audio function group under the root node.
    NoAudioFunction,
    /// No output-capable pin reaches a DAC.
    NoOutputPath,
}

/// The chosen output route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputPath {
    /// Codec address (0..14).
    pub cad: u8,
    /// Audio function group node id.
    pub afg: u8,
    /// Vendor id (high 16) / device id (low 16) of the codec.
    pub vendor: u32,
    /// Path nodes, DAC first, pin last; only `..len` is valid.
    pub nodes: [u8; MAX_PATH],
    /// Number of valid entries in `nodes` (at least 2).
    pub len: usize,
    /// For `nodes[i]`, i >= 1: connection index that selects `nodes[i-1]`.
    pub conn_sel: [u8; MAX_PATH],
    /// Adjustable output amp of `nodes[i]`, if it has one.
    pub amps: [Option<AmpCaps>; MAX_PATH],
    /// The pin has an EAPD line that must be switched on.
    pub pin_eapd: bool,
}

impl OutputPath {
    /// The DAC (first path node).
    pub fn dac(&self) -> u8 {
        self.nodes[0]
    }
    /// The output pin (last path node).
    pub fn pin(&self) -> u8 {
        self.nodes[self.len - 1]
    }
    /// Index of the path node whose amp carries the master volume: the first
    /// node (DAC side first) with an adjustable amp that has gain steps, else
    /// the first with any adjustable amp (mute only). `None` = no amp at all.
    pub fn volume_node(&self) -> Option<usize> {
        (0..self.len)
            .find(|&i| self.amps[i].map_or(false, |a| a.num_steps > 0))
            .or_else(|| (0..self.len).find(|&i| self.amps[i].is_some()))
    }
}

type SendFn<'a> = &'a mut dyn FnMut(u32) -> Option<u32>;

fn q(send: SendFn, cad: u8, nid: u8, p: u8) -> Option<u32> {
    send(get_param(cad, nid, p))
}

/// Reads the (range-expanded) connection list of `nid` into `out`.
fn conn_list(send: SendFn, cad: u8, nid: u8, out: &mut [u8; MAX_CONN]) -> usize {
    let Some(lenv) = q(send, cad, nid, param::CONN_LEN) else { return 0 };
    let n = (lenv & 0x7F) as usize;
    let long = lenv & 0x80 != 0;
    let (per, bits) = if long { (2usize, 16u32) } else { (4usize, 8u32) };
    let mut count = 0usize;
    let mut prev: Option<u16> = None;
    let mut i = 0usize;
    while i < n {
        let Some(v) = send(verb12(cad, nid, GET_CONN_LIST, i as u8)) else { break };
        for k in 0..per {
            if i + k >= n {
                break;
            }
            let raw = (v >> (bits * k as u32)) & ((1u32 << bits) - 1);
            let range_end = raw & (1 << (bits - 1)) != 0;
            let val = (raw & ((1u32 << (bits - 1)) - 1)) as u16;
            if range_end {
                // "previous+1 ..= val" (section 7.3.3.3).
                let start = prev.map_or(val, |p| p + 1);
                for x in start..=val {
                    if count < MAX_CONN {
                        out[count] = x as u8;
                        count += 1;
                    }
                }
            } else if count < MAX_CONN {
                out[count] = val as u8;
                count += 1;
            }
            prev = Some(val);
        }
        i += per;
    }
    count
}

/// Depth-first search from `nid` toward a DAC. Fills `path` (pin first) and
/// `sel` (index chosen at each node) and returns the number of path nodes.
fn dfs(send: SendFn, cad: u8, nid: u8, depth: usize, path: &mut [u8; MAX_PATH], sel: &mut [u8; MAX_PATH]) -> Option<usize> {
    path[depth] = nid;
    let mut list = [0u8; MAX_CONN];
    let n = conn_list(send, cad, nid, &mut list);
    for (idx, &child) in list[..n].iter().enumerate() {
        let Some(caps) = q(send, cad, child, param::WIDGET_CAP) else { continue };
        match widget_type(caps) {
            WidgetType::AudioOut => {
                if depth + 1 < MAX_PATH {
                    path[depth + 1] = child;
                    sel[depth] = idx as u8;
                    return Some(depth + 2);
                }
            }
            WidgetType::Mixer | WidgetType::Selector if depth + 2 < MAX_PATH => {
                sel[depth] = idx as u8;
                if let Some(len) = dfs(send, cad, child, depth + 1, path, sel) {
                    return Some(len);
                }
            }
            _ => {}
        }
    }
    None
}

/// Discovers the output route of the codec at address `cad`.
pub fn walk(cad: u8, send: SendFn) -> Result<OutputPath, WalkError> {
    let Some(vendor) = q(send, cad, 0, param::VENDOR_ID) else { return Err(WalkError::NoResponse) };
    let (fg_start, fg_count) = decode_node_count(q(send, cad, 0, param::NODE_COUNT).ok_or(WalkError::NoResponse)?);
    let mut afg = None;
    for fg in fg_start..fg_start.saturating_add(fg_count) {
        if q(send, cad, fg, param::FG_TYPE).map_or(false, |t| t & 0xFF == 1) {
            afg = Some(fg);
            break;
        }
    }
    let afg = afg.ok_or(WalkError::NoAudioFunction)?;
    let (w_start, w_count) = decode_node_count(q(send, cad, afg, param::NODE_COUNT).unwrap_or(0));
    let afg_amp = q(send, cad, afg, param::AMP_OUT_CAP).and_then(decode_amp_caps);

    // Rank output pins, best first.
    let mut cands = [(u8::MAX, 0u8, 0u32); 32];
    let mut nc = 0usize;
    for nid in w_start..w_start.saturating_add(w_count) {
        let Some(caps) = q(send, cad, nid, param::WIDGET_CAP) else { continue };
        if widget_type(caps) != WidgetType::Pin {
            continue;
        }
        let pcaps = q(send, cad, nid, param::PIN_CAP).unwrap_or(0);
        let cfg = decode_pin_config(send(verb12(cad, nid, GET_PIN_CFG, 0)).unwrap_or(0));
        if !pin_output_capable(pcaps) || cfg.connectivity == 1 {
            continue;
        }
        let rank = match cfg.device {
            1 => 0,
            0 => 1,
            2 => 2,
            _ => 3,
        };
        if nc < cands.len() {
            cands[nc] = (rank, nid, pcaps);
            nc += 1;
        }
    }
    for rank in 0..=3u8 {
        for &(r, pin, pcaps) in cands[..nc].iter().filter(|c| c.0 == rank) {
            let _ = r;
            let mut rev = [0u8; MAX_PATH];
            let mut rsel = [0u8; MAX_PATH];
            let Some(len) = dfs(send, cad, pin, 0, &mut rev, &mut rsel) else { continue };
            let mut p = OutputPath {
                cad,
                afg,
                vendor,
                nodes: [0; MAX_PATH],
                len,
                conn_sel: [0; MAX_PATH],
                amps: [None; MAX_PATH],
                pin_eapd: pin_has_eapd(pcaps),
            };
            for j in 0..len {
                p.nodes[j] = rev[len - 1 - j];
                if j >= 1 {
                    p.conn_sel[j] = rsel[len - 1 - j];
                }
                let caps = q(send, cad, p.nodes[j], param::WIDGET_CAP).unwrap_or(0);
                if has_out_amp(caps) {
                    p.amps[j] = if amp_override(caps) {
                        q(send, cad, p.nodes[j], param::AMP_OUT_CAP).and_then(decode_amp_caps)
                    } else {
                        afg_amp
                    };
                }
            }
            return Ok(p);
        }
    }
    Err(WalkError::NoOutputPath)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[derive(Clone, Default)]
    struct Node {
        caps: u32,
        pin_caps: u32,
        pin_cfg: u32,
        conn: Vec<u8>, // raw short-form bytes as stored in the codec
        amp: u32,
        fg_type: u32,
        subs: (u8, u8),
    }

    struct Fake {
        nodes: std::collections::BTreeMap<u8, Node>,
        long_form: bool,
    }

    impl Fake {
        fn respond(&self, cmd: u32) -> Option<u32> {
            let nid = ((cmd >> 20) & 0xFF) as u8;
            let verb = ((cmd >> 8) & 0xFFF) as u16;
            let payload = (cmd & 0xFF) as u8;
            let n = self.nodes.get(&nid)?;
            match (verb, payload) {
                (GET_PARAM, param::VENDOR_ID) => Some(0x1af4_0011),
                (GET_PARAM, param::NODE_COUNT) => Some(((n.subs.0 as u32) << 16) | n.subs.1 as u32),
                (GET_PARAM, param::FG_TYPE) => Some(n.fg_type),
                (GET_PARAM, param::WIDGET_CAP) => Some(n.caps),
                (GET_PARAM, param::PIN_CAP) => Some(n.pin_caps),
                (GET_PARAM, param::AMP_OUT_CAP) => Some(n.amp),
                (GET_PARAM, param::CONN_LEN) => {
                    Some(n.conn.len() as u32 | if self.long_form { 0x80 } else { 0 })
                }
                (GET_CONN_LIST, i) => {
                    let mut v = 0u32;
                    if self.long_form {
                        for k in 0..2 {
                            v |= (*n.conn.get(i as usize + k).unwrap_or(&0) as u32) << (16 * k);
                        }
                    } else {
                        for k in 0..4 {
                            v |= (*n.conn.get(i as usize + k).unwrap_or(&0) as u32) << (8 * k);
                        }
                    }
                    Some(v)
                }
                (GET_PIN_CFG, _) => Some(n.pin_cfg),
                _ => Some(0),
            }
        }
    }

    const DAC: u32 = (0 << 20) | (1 << 2) | (1 << 3) | 1;
    const PIN: u32 = (4 << 20) | (1 << 8);
    const MIX: u32 = (2 << 20) | (1 << 8);
    const AMP: u32 = 0x4A | (0x4A << 8) | (1 << 31);

    /// QEMU hda-duplex-like: AFG 1 with DAC 2, output pin 3, ADC 4, input pin 5.
    fn duplex() -> Fake {
        let mut m = std::collections::BTreeMap::new();
        m.insert(0, Node { subs: (1, 1), ..Default::default() });
        m.insert(1, Node { fg_type: 1, subs: (2, 4), ..Default::default() });
        m.insert(2, Node { caps: DAC, amp: AMP, ..Default::default() });
        m.insert(3, Node { caps: PIN, pin_caps: 1 << 4, pin_cfg: (2 << 30) | (1 << 20), conn: std::vec![2], ..Default::default() });
        m.insert(4, Node { caps: 1 << 20, ..Default::default() });
        m.insert(5, Node { caps: PIN, pin_caps: 1 << 5, pin_cfg: (2 << 30) | (0xA << 20), conn: std::vec![4], ..Default::default() });
        Fake { nodes: m, long_form: false }
    }

    fn run(f: &Fake) -> Result<OutputPath, WalkError> {
        walk(0, &mut |c| f.respond(c))
    }

    #[test]
    fn finds_dac_and_pin_on_a_duplex_codec() {
        let p = run(&duplex()).unwrap();
        assert_eq!(p.afg, 1);
        assert_eq!(p.vendor, 0x1af4_0011);
        assert_eq!(&p.nodes[..p.len], &[2, 3]);
        assert_eq!(p.dac(), 2);
        assert_eq!(p.pin(), 3);
        assert_eq!(p.conn_sel[1], 0);
        assert_eq!(p.amps[0], Some(AmpCaps { offset: 0x4A, num_steps: 0x4A, mute: true }));
        assert_eq!(p.amps[1], None);
        assert_eq!(p.volume_node(), Some(0));
        assert!(!p.pin_eapd);
    }

    #[test]
    fn follows_a_mixer_and_records_the_selection() {
        let mut f = duplex();
        // Pin 3 <- mixer 6 <- (DAC 2, ADC 4): selecting index 0 is the DAC.
        f.nodes.insert(6, Node { caps: MIX, conn: std::vec![2, 4], ..Default::default() });
        f.nodes.get_mut(&3).unwrap().conn = std::vec![6];
        f.nodes.get_mut(&1).unwrap().subs = (2, 5);
        let p = run(&f).unwrap();
        assert_eq!(&p.nodes[..p.len], &[2, 6, 3]);
        assert_eq!(p.conn_sel[1], 0, "mixer 6 takes the DAC at index 0");
        assert_eq!(p.conn_sel[2], 0, "pin takes the mixer at index 0");
    }

    #[test]
    fn connection_index_and_ranges_and_long_form() {
        // Selector 6 lists [4 (ADC), 2 (DAC)] in the short form: DAC is index 1.
        let mut f = duplex();
        f.nodes.insert(6, Node { caps: (3 << 20) | (1 << 8), conn: std::vec![4, 2], ..Default::default() });
        f.nodes.get_mut(&3).unwrap().conn = std::vec![6];
        f.nodes.get_mut(&1).unwrap().subs = (2, 5);
        let p = run(&f).unwrap();
        assert_eq!(p.conn_sel[1], 1);
        // Same in the long form.
        f.long_form = true;
        let p = run(&f).unwrap();
        assert_eq!(&p.nodes[..p.len], &[2, 6, 3]);
        assert_eq!(p.conn_sel[1], 1);
        // Range entry: 0x84 after 0x02 means 3..=4 (index 1 = nid 3, 2 = nid 4).
        f.long_form = false;
        let mut list = [0u8; MAX_CONN];
        f.nodes.insert(7, Node { conn: std::vec![2, 0x84], ..Default::default() });
        let n = conn_list(&mut |c| f.respond(c), 0, 7, &mut list);
        assert_eq!(&list[..n], &[2, 3, 4]);
    }

    #[test]
    fn prefers_speaker_over_headphone_and_skips_unconnected_pins() {
        let mut f = duplex();
        // Add headphone pin 6 (jack, device 2) and an unconnected line-out pin 7.
        f.nodes.insert(6, Node { caps: PIN, pin_caps: 1 << 4, pin_cfg: (0 << 30) | (2 << 20), conn: std::vec![2], ..Default::default() });
        f.nodes.insert(7, Node { caps: PIN, pin_caps: 1 << 4, pin_cfg: (1 << 30), conn: std::vec![2], ..Default::default() });
        f.nodes.get_mut(&1).unwrap().subs = (2, 6);
        assert_eq!(run(&f).unwrap().pin(), 3, "speaker beats headphone");
        // Without the speaker the headphone pin wins, and the unconnected one never does.
        f.nodes.get_mut(&3).unwrap().pin_caps = 0;
        assert_eq!(run(&f).unwrap().pin(), 6);
    }

    #[test]
    fn reports_missing_pieces() {
        let mut f = duplex();
        f.nodes.get_mut(&1).unwrap().fg_type = 2; // modem, not audio
        assert_eq!(run(&f), Err(WalkError::NoAudioFunction));
        let mut f = duplex();
        f.nodes.get_mut(&3).unwrap().conn = std::vec![4]; // pin only reaches the ADC
        assert_eq!(run(&f), Err(WalkError::NoOutputPath));
        assert_eq!(walk(0, &mut |_| None), Err(WalkError::NoResponse));
    }

    #[test]
    fn amp_falls_back_to_the_function_group_and_pin_eapd_is_noted() {
        let mut f = duplex();
        // DAC without its own amp params: use AFG's.
        f.nodes.get_mut(&2).unwrap().caps = (1 << 2) | 1;
        f.nodes.get_mut(&1).unwrap().amp = 0x20 | (0x10 << 8);
        f.nodes.get_mut(&3).unwrap().pin_caps = (1 << 4) | (1 << 16);
        let p = run(&f).unwrap();
        assert_eq!(p.amps[0], Some(AmpCaps { offset: 0x20, num_steps: 0x10, mute: false }));
        assert!(p.pin_eapd);
    }
}
