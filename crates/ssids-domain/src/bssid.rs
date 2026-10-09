use std::fmt;
use std::str::FromStr;

/// The MAC address identifying one access point radio (BSS).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bssid(pub [u8; 6]);

impl Bssid {
    /// The IEEE organisationally unique identifier: the first three octets.
    pub fn oui(self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    /// Locally administered addresses (e.g. the extra virtual BSSs of a
    /// multi-SSID AP) are not assigned by the IEEE, so their OUI names no vendor.
    pub fn is_locally_administered(self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for Bssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseBssidError;

impl fmt::Display for ParseBssidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a MAC address like aa:bb:cc:dd:ee:ff")
    }
}

impl std::error::Error for ParseBssidError {}

impl FromStr for Bssid {
    type Err = ParseBssidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 6];
        let mut parts = s.split(':');
        for octet in &mut octets {
            let part = parts.next().ok_or(ParseBssidError)?;
            // from_str_radix alone would also accept a sign, e.g. "+f".
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ParseBssidError);
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| ParseBssidError)?;
        }
        match parts.next() {
            None => Ok(Self(octets)),
            Some(_) => Err(ParseBssidError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_parse_round_trip() {
        let bssid = Bssid([0xc4, 0x47, 0x4e, 0x31, 0x1e, 0x9c]);
        assert_eq!(bssid.to_string(), "c4:47:4e:31:1e:9c");
        assert_eq!("C4:47:4E:31:1E:9C".parse(), Ok(bssid));
    }

    #[test]
    fn rejects_malformed_addresses() {
        for bad in [
            "",
            "c4:47:4e:31:1e",
            "c4:47:4e:31:1e:9c:00",
            "c4:47:4e:31:1e:9",
            "zz:47:4e:31:1e:9c",
            "+f:47:4e:31:1e:9c",
        ] {
            assert_eq!(bad.parse::<Bssid>(), Err(ParseBssidError), "{bad}");
        }
    }

    #[test]
    fn locally_administered_bit() {
        assert!(Bssid([0x02, 0, 0, 0, 0, 0]).is_locally_administered());
        assert!(!Bssid([0xc4, 0x47, 0x4e, 0, 0, 0]).is_locally_administered());
    }
}
