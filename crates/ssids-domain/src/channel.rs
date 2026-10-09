use std::fmt;

/// Frequency band. Channel numbers are only unique within a band.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Band {
    Ghz2_4,
    Ghz5,
    Ghz6,
}

impl Band {
    /// Centre frequency in MHz for a channel number in this band. Also valid
    /// for the numbers 802.11 uses to name the centre of 40/80/160/320 MHz
    /// channels (e.g. 5 GHz "42" = 5210 MHz), which are not 20 MHz channels.
    pub fn channel_center_freq(self, number: u8) -> u32 {
        let n = u32::from(number);
        match self {
            Self::Ghz2_4 if n == 14 => 2484,
            Self::Ghz2_4 => 2407 + 5 * n,
            Self::Ghz5 if n >= 182 => 4000 + 5 * n,
            Self::Ghz5 => 5000 + 5 * n,
            Self::Ghz6 if n == 2 => 5935,
            Self::Ghz6 => 5950 + 5 * n,
        }
    }
}

impl fmt::Display for Band {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ghz2_4 => "2.4 GHz",
            Self::Ghz5 => "5 GHz",
            Self::Ghz6 => "6 GHz",
        })
    }
}

/// A 20 MHz channel, identified the way users read it: band + number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Channel {
    pub band: Band,
    pub number: u8,
}

impl Channel {
    /// Maps a 20 MHz channel centre frequency to its channel. Mirrors the
    /// Linux kernel's `ieee80211_freq_khz_to_channel` for the bands we cover.
    pub fn from_freq(mhz: u32) -> Option<Self> {
        let (band, number) = match mhz {
            2484 => (Band::Ghz2_4, 14),
            2412..=2472 if (mhz - 2407) % 5 == 0 => (Band::Ghz2_4, (mhz - 2407) / 5),
            // 4.9 GHz public-safety / Japan channels, numbered from 4000 MHz.
            4910..=4980 if mhz % 5 == 0 => (Band::Ghz5, (mhz - 4000) / 5),
            5150..=5895 if mhz % 5 == 0 => (Band::Ghz5, (mhz - 5000) / 5),
            5935 => (Band::Ghz6, 2),
            // 6 GHz primary channels sit on a 20 MHz grid (1, 5, 9, ...).
            5955..=7115 if (mhz - 5955) % 20 == 0 => (Band::Ghz6, (mhz - 5950) / 5),
            _ => return None,
        };
        Some(Self {
            band,
            number: u8::try_from(number).ok()?,
        })
    }

    /// Like [`Channel::from_freq`], for a channel number already known to be in `band`.
    pub fn new(band: Band, number: u8) -> Option<Self> {
        let channel = Self { band, number };
        (Self::from_freq(channel.center_freq()) == Some(channel)).then_some(channel)
    }

    /// Centre frequency in MHz of this 20 MHz channel.
    pub fn center_freq(self) -> u32 {
        self.band.channel_center_freq(self.number)
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(band: Band, number: u8) -> Option<Channel> {
        Some(Channel { band, number })
    }

    #[test]
    fn known_frequencies() {
        assert_eq!(Channel::from_freq(2412), ch(Band::Ghz2_4, 1));
        assert_eq!(Channel::from_freq(2437), ch(Band::Ghz2_4, 6));
        assert_eq!(Channel::from_freq(2472), ch(Band::Ghz2_4, 13));
        assert_eq!(Channel::from_freq(2484), ch(Band::Ghz2_4, 14));
        assert_eq!(Channel::from_freq(4920), ch(Band::Ghz5, 184));
        assert_eq!(Channel::from_freq(5180), ch(Band::Ghz5, 36));
        assert_eq!(Channel::from_freq(5825), ch(Band::Ghz5, 165));
        assert_eq!(Channel::from_freq(5935), ch(Band::Ghz6, 2));
        assert_eq!(Channel::from_freq(5955), ch(Band::Ghz6, 1));
        assert_eq!(Channel::from_freq(7115), ch(Band::Ghz6, 233));
    }

    #[test]
    fn rejects_frequencies_outside_wifi_channels() {
        for mhz in [0, 2400, 2413, 2477, 3000, 5000, 5960, 7120, 58320] {
            assert_eq!(Channel::from_freq(mhz), None, "{mhz}");
        }
    }

    #[test]
    fn center_freq_inverts_from_freq_everywhere() {
        let freqs = (2400..=2500).chain(4900..=5000).chain(5100..=7200);
        for mhz in freqs {
            if let Some(channel) = Channel::from_freq(mhz) {
                assert_eq!(channel.center_freq(), mhz, "{channel:?}");
            }
        }
    }

    #[test]
    fn new_validates_number_within_band() {
        assert_eq!(Channel::new(Band::Ghz5, 36), ch(Band::Ghz5, 36));
        assert_eq!(Channel::new(Band::Ghz2_4, 36), None);
        assert_eq!(Channel::new(Band::Ghz6, 0), None);
    }
}
