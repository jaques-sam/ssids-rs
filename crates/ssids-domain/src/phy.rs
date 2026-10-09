//! What a BSS looks like on the air: channel width, occupied spectrum and
//! 802.11 generation, derived from its operation/capability elements.

use std::fmt;

use crate::channel::{Band, Channel};
use crate::ie::{Elements, ext_id, id};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChannelWidth {
    Mhz20,
    Mhz40,
    Mhz80,
    Mhz160,
    Mhz320,
    Mhz80Plus80,
}

impl ChannelWidth {
    /// Width of one contiguous segment.
    fn segment_mhz(self) -> u32 {
        match self {
            Self::Mhz20 => 20,
            Self::Mhz40 => 40,
            Self::Mhz80 | Self::Mhz80Plus80 => 80,
            Self::Mhz160 => 160,
            Self::Mhz320 => 320,
        }
    }
}

impl fmt::Display for ChannelWidth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mhz80Plus80 => f.write_str("80+80 MHz"),
            other => write!(f, "{} MHz", other.segment_mhz()),
        }
    }
}

/// The spectrum a BSS transmits on: one segment, or two for 80+80 MHz.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelSpan {
    pub width: ChannelWidth,
    pub center_mhz: u32,
    pub second_center_mhz: Option<u32>,
}

impl ChannelSpan {
    /// Derives the operating span from the most capable operation element
    /// present (EHT > HE 6 GHz > VHT > HT). An element that contradicts the
    /// primary channel the kernel reported is ignored rather than believed.
    pub fn detect(primary: Channel, elements: &Elements<'_>) -> Self {
        let parsers: [fn(Channel, &Elements<'_>) -> Option<Self>; 4] =
            [eht_span, he_6ghz_span, vht_span, ht_span];
        parsers
            .into_iter()
            .find_map(|parse| parse(primary, elements).filter(|span| span.covers(primary)))
            .unwrap_or_else(|| Self::twenty(primary))
    }

    fn twenty(primary: Channel) -> Self {
        Self::single(ChannelWidth::Mhz20, primary.center_freq())
    }

    fn single(width: ChannelWidth, center_mhz: u32) -> Self {
        Self {
            width,
            center_mhz,
            second_center_mhz: None,
        }
    }

    /// `(low, high)` MHz edges of each occupied segment.
    pub fn segments(&self) -> impl Iterator<Item = (u32, u32)> + use<> {
        let half = self.width.segment_mhz() / 2;
        [Some(self.center_mhz), self.second_center_mhz]
            .into_iter()
            .flatten()
            .map(move |center| (center.saturating_sub(half), center + half))
    }

    fn covers(&self, primary: Channel) -> bool {
        let f = primary.center_freq();
        self.segments()
            .any(|(low, high)| low + 10 <= f && f + 10 <= high)
    }
}

/// Interprets a VHT-style CCFS0/CCFS1 pair (80, 160 or 80+80 MHz).
fn vht_style_span(band: Band, ccfs0: u8, ccfs1: u8) -> ChannelSpan {
    let center = |n| band.channel_center_freq(n);
    match ccfs1.abs_diff(ccfs0) {
        _ if ccfs1 == 0 => ChannelSpan::single(ChannelWidth::Mhz80, center(ccfs0)),
        8 => ChannelSpan::single(ChannelWidth::Mhz160, center(ccfs1)),
        d if d > 16 => ChannelSpan {
            width: ChannelWidth::Mhz80Plus80,
            center_mhz: center(ccfs0),
            second_center_mhz: Some(center(ccfs1)),
        },
        _ => ChannelSpan::single(ChannelWidth::Mhz80, center(ccfs0)),
    }
}

fn eht_span(primary: Channel, elements: &Elements<'_>) -> Option<ChannelSpan> {
    // Parameters(1), basic EHT-MCS/NSS set(4), then the optional operation info.
    let [params, _, _, _, _, control, ccfs0, ccfs1, ..] =
        *elements.get_ext(ext_id::EHT_OPERATION)?
    else {
        return None;
    };
    if params & 0x01 == 0 {
        return None;
    }
    let center = |n| primary.band.channel_center_freq(n);
    Some(match control & 0x07 {
        0 => ChannelSpan::twenty(primary),
        1 => ChannelSpan::single(ChannelWidth::Mhz40, center(ccfs0)),
        2 => ChannelSpan::single(ChannelWidth::Mhz80, center(ccfs0)),
        3 => ChannelSpan::single(ChannelWidth::Mhz160, center(ccfs1)),
        4 => ChannelSpan::single(ChannelWidth::Mhz320, center(ccfs1)),
        _ => return None,
    })
}

fn he_6ghz_span(primary: Channel, elements: &Elements<'_>) -> Option<ChannelSpan> {
    if primary.band != Band::Ghz6 {
        return None;
    }
    // Parameters(3), BSS colour(1), basic HE-MCS/NSS set(2), then optional fields.
    let [p0, p1, p2, _, _, _, ref rest @ ..] = *elements.get_ext(ext_id::HE_OPERATION)? else {
        return None;
    };
    let params = u32::from_le_bytes([p0, p1, p2, 0]);
    let mut rest = rest;
    if params & (1 << 14) != 0 {
        rest = rest.get(3..)?; // VHT operation information
    }
    if params & (1 << 15) != 0 {
        rest = rest.get(1..)?; // max co-hosted BSSID indicator
    }
    if params & (1 << 17) == 0 {
        return None;
    }
    let [_primary, control, ccfs0, ccfs1, ..] = *rest else {
        return None;
    };
    let center = |n| primary.band.channel_center_freq(n);
    Some(match control & 0x03 {
        0 => ChannelSpan::twenty(primary),
        1 => ChannelSpan::single(ChannelWidth::Mhz40, center(ccfs0)),
        2 => ChannelSpan::single(ChannelWidth::Mhz80, center(ccfs0)),
        _ => vht_style_span(primary.band, ccfs0, ccfs1),
    })
}

fn vht_span(primary: Channel, elements: &Elements<'_>) -> Option<ChannelSpan> {
    if primary.band != Band::Ghz5 {
        return None;
    }
    let [width, ccfs0, ccfs1, ..] = *elements.get(id::VHT_OPERATION)? else {
        return None;
    };
    let center = |n| primary.band.channel_center_freq(n);
    match width {
        1 => Some(vht_style_span(primary.band, ccfs0, ccfs1)),
        // Deprecated encodings, still sent by older APs.
        2 => Some(ChannelSpan::single(ChannelWidth::Mhz160, center(ccfs0))),
        3 => Some(ChannelSpan {
            width: ChannelWidth::Mhz80Plus80,
            center_mhz: center(ccfs0),
            second_center_mhz: Some(center(ccfs1)),
        }),
        // 0 means "20 or 40 MHz": the HT operation element decides.
        _ => None,
    }
}

fn ht_span(primary: Channel, elements: &Elements<'_>) -> Option<ChannelSpan> {
    let [_primary, info, ..] = *elements.get(id::HT_OPERATION)? else {
        return None;
    };
    let f = primary.center_freq();
    match info & 0x03 {
        1 => Some(ChannelSpan::single(ChannelWidth::Mhz40, f + 10)),
        3 => Some(ChannelSpan::single(ChannelWidth::Mhz40, f - 10)),
        _ => None,
    }
}

/// The 802.11 amendment a BSS supports at best.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Standard {
    B,
    A,
    G,
    N,
    Ac,
    Ax,
    Be,
}

impl Standard {
    pub fn detect(band: Band, elements: &Elements<'_>) -> Self {
        if elements.has_ext(ext_id::EHT_CAPABILITIES) {
            Self::Be
        } else if elements.has_ext(ext_id::HE_CAPABILITIES) {
            Self::Ax
        } else if band == Band::Ghz5 && elements.has(id::VHT_CAPABILITIES) {
            // Some 2.4 GHz chipsets advertise VHT for vendor 256-QAM; that is still 11n.
            Self::Ac
        } else if elements.has(id::HT_CAPABILITIES) {
            Self::N
        } else if band != Band::Ghz2_4 {
            Self::A
        } else if elements.max_legacy_rate_mbps().is_some_and(|r| r <= 11.0) {
            Self::B
        } else {
            Self::G
        }
    }

    /// Wi-Fi Alliance generation number, for HT and later.
    pub fn generation(self) -> Option<u8> {
        match self {
            Self::B | Self::A | Self::G => None,
            Self::N => Some(4),
            Self::Ac => Some(5),
            Self::Ax => Some(6),
            Self::Be => Some(7),
        }
    }
}

impl fmt::Display for Standard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::B => "802.11b",
            Self::A => "802.11a",
            Self::G => "802.11g",
            Self::N => "802.11n",
            Self::Ac => "802.11ac",
            Self::Ax => "802.11ax",
            Self::Be => "802.11be",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie::tests::{DECO_BE65, arbitrary_buffers, hex};

    fn span(freq: u32, ies: &[u8]) -> ChannelSpan {
        let primary = Channel::from_freq(freq).expect("valid test frequency");
        ChannelSpan::detect(primary, &Elements::new(ies))
    }

    fn segments(span: ChannelSpan) -> Vec<(u32, u32)> {
        span.segments().collect()
    }

    #[test]
    fn real_beacon_is_160mhz_wifi7() {
        let bytes = hex(DECO_BE65);
        let s = span(5200, &bytes);
        assert_eq!(s.width, ChannelWidth::Mhz160);
        assert_eq!(segments(s), [(5170, 5330)]);
        assert_eq!(
            Standard::detect(Band::Ghz5, &Elements::new(&bytes)),
            Standard::Be
        );
    }

    #[test]
    fn no_operation_elements_means_20mhz() {
        let s = span(2437, &[]);
        assert_eq!(
            (s.width, segments(s)),
            (ChannelWidth::Mhz20, vec![(2427, 2447)])
        );
    }

    #[test]
    fn ht40_above_and_below() {
        assert_eq!(segments(span(2412, &[61, 2, 1, 0x05])), [(2402, 2442)]);
        assert_eq!(segments(span(2462, &[61, 2, 11, 0x07])), [(2432, 2472)]);
    }

    #[test]
    fn vht_80_and_80_plus_80() {
        assert_eq!(segments(span(5180, &[192, 3, 1, 42, 0])), [(5170, 5250)]);
        let s = span(5180, &[192, 3, 1, 42, 155]);
        assert_eq!(s.width, ChannelWidth::Mhz80Plus80);
        assert_eq!(segments(s), [(5170, 5250), (5735, 5815)]);
    }

    #[test]
    fn vht_width_zero_defers_to_ht() {
        let ies = [192, 3, 0, 0, 0, 61, 2, 36, 0x05];
        assert_eq!(span(5180, &ies).width, ChannelWidth::Mhz40);
    }

    #[test]
    fn contradictory_element_falls_back() {
        // VHT claims 80 MHz around channel 155 while the primary is 36: ignored, HT used.
        let ies = [192, 3, 1, 155, 0, 61, 2, 36, 0x05];
        assert_eq!(segments(span(5180, &ies)), [(5170, 5210)]);
    }

    #[test]
    fn he_6ghz_operation_info() {
        // Params with the 6 GHz info bit (17), colour, MCS, then primary 5, width 80 @ 7.
        let ies = [255, 12, 36, 0, 0, 0x02, 0, 0, 0, 5, 0x02, 7, 0, 0];
        assert_eq!(segments(span(5975, &ies)), [(5945, 6025)]);
    }

    #[test]
    fn he_6ghz_skips_optional_fields_before_info() {
        // VHT info (bit 14) and co-hosted (bit 15) present before the 6 GHz info.
        let ies = [
            255, 16, 36, 0, 0xc0, 0x02, 0, 0, 0, 0, 0, 0, 0, 5, 0x02, 7, 0, 0,
        ];
        assert_eq!(span(5975, &ies).width, ChannelWidth::Mhz80);
    }

    #[test]
    fn eht_320mhz() {
        let ies = [255, 9, 106, 0x01, 0, 0, 0, 0, 0x04, 7, 31];
        let s = span(5955, &ies);
        assert_eq!(
            (s.width, segments(s)),
            (ChannelWidth::Mhz320, vec![(5945, 6265)])
        );
    }

    #[test]
    fn legacy_standards() {
        let b_rates = [1, 4, 0x82, 0x84, 0x8b, 0x96];
        assert_eq!(
            Standard::detect(Band::Ghz2_4, &Elements::new(&b_rates)),
            Standard::B
        );
        let g_rates = [1, 2, 0x82, 0x6c];
        assert_eq!(
            Standard::detect(Band::Ghz2_4, &Elements::new(&g_rates)),
            Standard::G
        );
        assert_eq!(
            Standard::detect(Band::Ghz5, &Elements::new(&[])),
            Standard::A
        );
        assert_eq!(
            Standard::detect(Band::Ghz2_4, &Elements::new(&[191, 0])),
            Standard::G
        );
    }

    #[test]
    fn detected_span_always_covers_primary() {
        let primaries =
            [2412, 2484, 5180, 5825, 5955, 7115].map(|f| Channel::from_freq(f).expect("valid"));
        for bytes in arbitrary_buffers() {
            for primary in primaries {
                let s = ChannelSpan::detect(primary, &Elements::new(&bytes));
                assert!(s.covers(primary), "{s:?} for {primary:?} from {bytes:02x?}");
            }
        }
    }
}
