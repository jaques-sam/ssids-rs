//! 802.11 information elements (IEs): the TLV list carried in beacons and
//! probe responses. Input comes straight from the air, so everything here is
//! total: malformed or truncated data is skipped, never trusted or panicked on.

/// Element IDs (IEEE 802.11-2020 table 9-92) used by this crate.
pub(crate) mod id {
    pub const SSID: u8 = 0;
    pub const SUPPORTED_RATES: u8 = 1;
    pub const HT_CAPABILITIES: u8 = 45;
    pub const RSN: u8 = 48;
    pub const EXTENDED_SUPPORTED_RATES: u8 = 50;
    pub const HT_OPERATION: u8 = 61;
    pub const VHT_CAPABILITIES: u8 = 191;
    pub const VHT_OPERATION: u8 = 192;
    pub const VENDOR_SPECIFIC: u8 = 221;
    pub const EXTENSION: u8 = 255;
}

/// Element ID extensions, carried as the first data byte of an `EXTENSION` element.
pub(crate) mod ext_id {
    pub const HE_CAPABILITIES: u8 = 35;
    pub const HE_OPERATION: u8 = 36;
    pub const EHT_OPERATION: u8 = 106;
    pub const EHT_CAPABILITIES: u8 = 108;
}

/// One element. For extension elements, `ext_id` is set and `data` excludes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Element<'a> {
    pub id: u8,
    pub ext_id: Option<u8>,
    pub data: &'a [u8],
}

/// Iterator over the elements of a raw IE buffer. Stops at the first element
/// whose declared length overruns the buffer.
#[derive(Clone, Debug)]
pub struct Elements<'a>(&'a [u8]);

impl<'a> Elements<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn get(&self, id: u8) -> Option<&'a [u8]> {
        self.clone()
            .find(|e| e.id == id && e.ext_id.is_none())
            .map(|e| e.data)
    }

    pub(crate) fn get_ext(&self, ext_id: u8) -> Option<&'a [u8]> {
        self.clone()
            .find(|e| e.ext_id == Some(ext_id))
            .map(|e| e.data)
    }

    pub(crate) fn has(&self, id: u8) -> bool {
        self.get(id).is_some()
    }

    pub(crate) fn has_ext(&self, ext_id: u8) -> bool {
        self.get_ext(ext_id).is_some()
    }

    /// Network name. `None` for hidden networks, which beacon an empty or
    /// all-zero SSID. Non-UTF-8 bytes are replaced rather than rejected,
    /// since the SSID is just an octet string on the wire.
    pub fn ssid(&self) -> Option<String> {
        let ssid = self.get(id::SSID)?;
        if ssid.iter().all(|&b| b == 0) {
            return None;
        }
        Some(String::from_utf8_lossy(ssid).into_owned())
    }

    /// Highest legacy (non-HT) rate in Mbit/s from (Extended) Supported Rates.
    pub fn max_legacy_rate_mbps(&self) -> Option<f32> {
        // Values 122..=127 are BSS membership selectors (HT/VHT/SAE...), not rates.
        let rates = [id::SUPPORTED_RATES, id::EXTENDED_SUPPORTED_RATES]
            .into_iter()
            .filter_map(|id| self.get(id))
            .flatten()
            .map(|b| b & 0x7f)
            .filter(|&r| r != 0 && r < 122);
        rates.max().map(|half_mbps| f32::from(half_mbps) / 2.0)
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = Element<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let [id, len, rest @ ..] = self.0 else {
            self.0 = &[];
            return None;
        };
        let Some((data, remaining)) = rest.split_at_checked(usize::from(*len)) else {
            self.0 = &[];
            return None;
        };
        self.0 = remaining;
        Some(match (*id, data) {
            (id::EXTENSION, [ext_id, data @ ..]) => Element {
                id: *id,
                ext_id: Some(*ext_id),
                data,
            },
            _ => Element {
                id: *id,
                ext_id: None,
                data,
            },
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn hex(s: &str) -> Vec<u8> {
        let s = s.trim();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex fixture"))
            .collect()
    }

    pub(crate) const DECO_BE65: &str =
        include_str!("../fixtures/deco-be65-5ghz-160mhz-wpa2-wpa3.hex");

    #[test]
    fn iterates_real_beacon() {
        let bytes = hex(DECO_BE65);
        let elements = Elements::new(&bytes);
        assert_eq!(elements.ssid().as_deref(), Some("MenS7"));
        assert_eq!(elements.max_legacy_rate_mbps(), Some(54.0));
        assert!(elements.has_ext(ext_id::EHT_CAPABILITIES));
        let total: usize = elements
            .map(|e| 2 + e.data.len() + usize::from(e.ext_id.is_some()))
            .sum();
        assert_eq!(
            total,
            bytes.len(),
            "every byte belongs to exactly one element"
        );
    }

    #[test]
    fn hidden_ssids() {
        assert_eq!(Elements::new(&[0, 0]).ssid(), None);
        assert_eq!(Elements::new(&[0, 3, 0, 0, 0]).ssid(), None);
        assert_eq!(Elements::new(&[]).ssid(), None);
    }

    #[test]
    fn non_utf8_ssid_is_kept_lossily() {
        assert_eq!(
            Elements::new(&[0, 2, b'a', 0xff]).ssid().as_deref(),
            Some("a\u{fffd}")
        );
    }

    #[test]
    fn truncated_element_ends_iteration() {
        let bytes = [0, 1, b'x', 1, 9, 0x82];
        let ids: Vec<u8> = Elements::new(&bytes).map(|e| e.id).collect();
        assert_eq!(ids, [0]);
    }

    #[test]
    fn empty_extension_element_is_plain() {
        let e = Elements::new(&[255, 0]).next();
        assert_eq!(
            e,
            Some(Element {
                id: 255,
                ext_id: None,
                data: &[]
            })
        );
    }

    #[test]
    fn membership_selectors_are_not_rates() {
        // 1, 2 Mbit/s plus the HT-PHY selector (0xff = basic | 127).
        assert_eq!(
            Elements::new(&[1, 3, 0x82, 0x84, 0xff]).max_legacy_rate_mbps(),
            Some(2.0)
        );
    }

    /// Deterministic pseudo-random IE buffers for robustness tests. Valid TLV
    /// headers with random ids/payloads exercise the parsers far deeper than
    /// raw random bytes, which almost never form a well-formed element.
    pub(crate) fn arbitrary_buffers() -> impl Iterator<Item = Vec<u8>> {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let interesting_ids = [0, 1, 45, 48, 50, 61, 191, 192, 221, 255];
        (0..20_000).map(move |_| {
            let mut bytes = Vec::new();
            for _ in 0..next() % 4 {
                let r = next();
                let id = interesting_ids[(r % 10) as usize];
                let len = (r >> 8) % 32;
                bytes.push(id);
                bytes.push(len as u8);
                let start = bytes.len();
                bytes.extend((0..len).map(|_| next() as u8));
                if id == 255 && len > 0 {
                    bytes[start] = [35, 36, 106, 108][(r >> 16) as usize % 4];
                }
            }
            if next() % 4 == 0 {
                bytes.truncate((next() as usize) % (bytes.len() + 1));
            }
            bytes
        })
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        for bytes in arbitrary_buffers() {
            let elements = Elements::new(&bytes);
            let _ = (
                elements.ssid(),
                elements.max_legacy_rate_mbps(),
                elements.count(),
            );
        }
    }
}
