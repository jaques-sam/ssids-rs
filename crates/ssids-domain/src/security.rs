//! Network security as users name it ("WPA2/WPA3-Personal"), derived from
//! the RSN element, the legacy WPA vendor element and the privacy bit.

use std::fmt;

use crate::ie::{Elements, id};

/// Privacy bit of the 802.11 capability information field.
const CAPABILITY_PRIVACY: u16 = 0x0010;
const IEEE_OUI: [u8; 3] = [0x00, 0x0f, 0xac];
const MICROSOFT_OUI: [u8; 3] = [0x00, 0x50, 0xf2];
const WPA_OUI_TYPE: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cipher {
    Wep40,
    Wep104,
    Tkip,
    Ccmp128,
    Ccmp256,
    Gcmp128,
    Gcmp256,
}

impl Cipher {
    /// RSN and WPA share the cipher suite type numbers, under different OUIs.
    fn from_suite([a, b, c, kind]: [u8; 4]) -> Option<Self> {
        if [a, b, c] != IEEE_OUI && [a, b, c] != MICROSOFT_OUI {
            return None;
        }
        Some(match kind {
            1 => Self::Wep40,
            2 => Self::Tkip,
            4 => Self::Ccmp128,
            5 => Self::Wep104,
            8 => Self::Gcmp128,
            9 => Self::Gcmp256,
            10 => Self::Ccmp256,
            _ => return None,
        })
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wep40 => "WEP-40",
            Self::Wep104 => "WEP-104",
            Self::Tkip => "TKIP",
            Self::Ccmp128 => "CCMP",
            Self::Ccmp256 => "CCMP-256",
            Self::Gcmp128 => "GCMP",
            Self::Gcmp256 => "GCMP-256",
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Security {
    pub wep: bool,
    pub wpa: bool,
    pub wpa2: bool,
    pub wpa3: bool,
    pub owe: bool,
    /// 802.1X/EAP authentication rather than a shared passphrase.
    pub enterprise: bool,
    /// Pairwise (unicast) ciphers offered, sorted and deduplicated.
    pub ciphers: Vec<Cipher>,
}

impl Security {
    pub fn detect(capability: u16, elements: &Elements<'_>) -> Self {
        let mut security = Self::default();
        if let Some(rsn) = elements.get(id::RSN).and_then(|data| strip_version(data)) {
            security.apply_rsn(rsn);
        }
        let wpa = elements
            .clone()
            .filter(|e| e.id == id::VENDOR_SPECIFIC)
            .find_map(|e| {
                let rest = e
                    .data
                    .strip_prefix(&MICROSOFT_OUI)?
                    .strip_prefix(&[WPA_OUI_TYPE])?;
                strip_version(rest)
            });
        if let Some(wpa) = wpa {
            security.apply_wpa(wpa);
        }
        if !security.is_wpa_family() && !security.owe {
            security.wep = capability & CAPABILITY_PRIVACY != 0;
        }
        security.ciphers.sort_unstable();
        security.ciphers.dedup();
        security
    }

    /// No encryption at all (OWE is unauthenticated but still encrypted).
    pub fn is_open(&self) -> bool {
        !self.wep && !self.owe && !self.is_wpa_family()
    }

    fn is_wpa_family(&self) -> bool {
        self.wpa || self.wpa2 || self.wpa3
    }

    fn apply_rsn(&mut self, body: &[u8]) {
        let suites = SuiteLists::parse(body);
        self.ciphers.extend(
            suites
                .pairwise
                .iter()
                .filter_map(|&s| Cipher::from_suite(s)),
        );
        if suites.akms.is_empty() {
            self.wpa2 = true; // AKM list omitted: defaults to 802.1X
            self.enterprise = true;
        }
        for [a, b, c, kind] in suites.akms {
            if [a, b, c] != IEEE_OUI {
                self.wpa2 = true; // vendor AKM (e.g. DPP): still an RSN network
                continue;
            }
            match kind {
                1 | 3 | 5 | 14 | 15 | 16 | 17 => (self.wpa2, self.enterprise) = (true, true),
                11..=13 => (self.wpa3, self.enterprise) = (true, true),
                8 | 9 | 24 | 25 => self.wpa3 = true,
                18 => self.owe = true,
                _ => self.wpa2 = true,
            }
        }
    }

    fn apply_wpa(&mut self, body: &[u8]) {
        let suites = SuiteLists::parse(body);
        self.wpa = true;
        self.ciphers.extend(
            suites
                .pairwise
                .iter()
                .filter_map(|&s| Cipher::from_suite(s)),
        );
        if suites.akms.iter().any(|&[.., kind]| kind == 1) {
            self.enterprise = true;
        }
    }
}

impl fmt::Display for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_wpa_family() {
            let names = [(self.wpa, "WPA"), (self.wpa2, "WPA2"), (self.wpa3, "WPA3")];
            let names: Vec<&str> = names
                .into_iter()
                .filter(|(on, _)| *on)
                .map(|(_, n)| n)
                .collect();
            let auth = if self.enterprise {
                "Enterprise"
            } else {
                "Personal"
            };
            write!(f, "{}-{auth}", names.join("/"))?;
            if self.owe {
                f.write_str("/OWE")?;
            }
            Ok(())
        } else if self.owe {
            f.write_str("OWE")
        } else if self.wep {
            f.write_str("WEP")
        } else {
            f.write_str("Open")
        }
    }
}

/// Body of a version-1 RSN/WPA element (after the version field).
fn strip_version(data: &[u8]) -> Option<&[u8]> {
    data.strip_prefix(&[1, 0])
}

/// Pairwise cipher and AKM suite lists shared by the RSN and WPA layouts:
/// group cipher, pairwise count + suites, AKM count + suites. Parsing stops
/// at the first truncated field and keeps what was complete.
#[derive(Default)]
struct SuiteLists {
    pairwise: Vec<[u8; 4]>,
    akms: Vec<[u8; 4]>,
}

impl SuiteLists {
    fn parse(body: &[u8]) -> Self {
        let mut lists = Self::default();
        let Some(rest) = body.get(4..) else {
            return lists;
        };
        let rest = read_suites(rest, &mut lists.pairwise);
        if let Some(rest) = rest {
            read_suites(rest, &mut lists.akms);
        }
        lists
    }
}

fn read_suites<'a>(data: &'a [u8], out: &mut Vec<[u8; 4]>) -> Option<&'a [u8]> {
    let (count, rest) = data.split_first_chunk::<2>()?;
    let count = usize::from(u16::from_le_bytes(*count));
    let (list, rest) = rest.split_at_checked(count.checked_mul(4)?)?;
    out.extend_from_slice(list.as_chunks::<4>().0);
    Some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ie::tests::{DECO_BE65, arbitrary_buffers, hex};

    fn detect(capability: u16, ies: &[u8]) -> Security {
        Security::detect(capability, &Elements::new(ies))
    }

    const PRIVACY: u16 = 0x0011;

    #[test]
    fn real_beacon_is_wpa2_wpa3_transition() {
        let s = detect(PRIVACY, &hex(DECO_BE65));
        assert_eq!(s.to_string(), "WPA2/WPA3-Personal");
        assert_eq!(s.ciphers, [Cipher::Ccmp128]);
    }

    #[test]
    fn open_and_wep_come_from_privacy_bit() {
        assert_eq!(detect(0x0001, &[]).to_string(), "Open");
        assert!(detect(0x0001, &[]).is_open());
        assert_eq!(detect(PRIVACY, &[]).to_string(), "WEP");
    }

    #[test]
    fn legacy_wpa_vendor_element() {
        let wpa = hex("dd160050f20101000050f20201000050f20201000050f202");
        let s = detect(PRIVACY, &wpa);
        assert_eq!(
            (s.to_string(), s.ciphers),
            ("WPA-Personal".into(), vec![Cipher::Tkip])
        );
    }

    #[test]
    fn mixed_wpa_wpa2() {
        let ies = hex("dd160050f20101000050f20201000050f20201000050f202\
             30180100000fac040200000fac04000fac020100000fac020000");
        let s = detect(PRIVACY, &ies);
        assert_eq!(s.to_string(), "WPA/WPA2-Personal");
        assert_eq!(s.ciphers, [Cipher::Tkip, Cipher::Ccmp128]);
    }

    #[test]
    fn enterprise_variants() {
        let wpa2_eap = hex("30140100000fac040100000fac040100000fac010000");
        assert_eq!(detect(PRIVACY, &wpa2_eap).to_string(), "WPA2-Enterprise");
        let wpa3_192 = hex("30140100000fac090100000fac090100000fac0c0000");
        let s = detect(PRIVACY, &wpa3_192);
        assert_eq!(
            (s.to_string(), s.ciphers),
            ("WPA3-Enterprise".into(), vec![Cipher::Gcmp256])
        );
    }

    #[test]
    fn owe() {
        let owe = hex("30140100000fac040100000fac040100000fac120000");
        let s = detect(PRIVACY, &owe);
        assert_eq!(s.to_string(), "OWE");
        assert!(!s.is_open());
    }

    #[test]
    fn truncated_rsn_keeps_what_is_complete() {
        // Pairwise list complete, AKM count claims 2 suites but carries 1.
        let s = detect(PRIVACY, &hex("30120100000fac040100000fac040200000fac08"));
        assert_eq!(s.ciphers, [Cipher::Ccmp128]);
        assert_eq!(
            s.to_string(),
            "WPA2-Enterprise",
            "AKMs unreadable: RSN default"
        );
    }

    #[test]
    fn unknown_rsn_version_is_ignored() {
        assert_eq!(detect(PRIVACY, &hex("30020200")).to_string(), "WEP");
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        for bytes in arbitrary_buffers() {
            let _ = detect(PRIVACY, &bytes).to_string();
        }
    }
}
