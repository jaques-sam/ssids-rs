use std::collections::VecDeque;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{Bssid, Channel, ChannelSpan, Elements, Security, Standard, vendor};

/// One BSS exactly as a scan backend reported it, before interpretation.
/// This is the unit that crosses every boundary (adapters, recordings, the
/// agent's wire protocol), so it carries raw facts only and the IE bytes
/// are parsed in exactly one place: [`AccessPoint::from_observation`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub bssid: Bssid,
    pub freq_mhz: u32,
    pub signal_dbm: Option<f32>,
    /// How long ago the backend last heard this BSS, if it knows.
    pub seen_ms_ago: Option<u32>,
    /// 802.11 capability information field.
    pub capability: u16,
    #[serde(with = "hex_bytes")]
    pub ies: Vec<u8>,
    /// Whether this machine is associated to the BSS.
    pub associated: bool,
}

/// An observation interpreted into what users care about.
#[derive(Clone, Debug, PartialEq)]
pub struct AccessPoint {
    pub bssid: Bssid,
    /// `None` for hidden networks.
    pub ssid: Option<String>,
    pub channel: Channel,
    pub span: ChannelSpan,
    pub standard: Standard,
    pub security: Security,
    pub vendor: Option<&'static str>,
    pub max_rate_mbps: Option<f32>,
    pub signal_dbm: Option<f32>,
    pub associated: bool,
}

impl AccessPoint {
    /// `None` when the frequency is not a 2.4/5/6 GHz Wi-Fi channel.
    pub fn from_observation(observation: &Observation) -> Option<Self> {
        let channel = Channel::from_freq(observation.freq_mhz)?;
        let elements = Elements::new(&observation.ies);
        Some(Self {
            bssid: observation.bssid,
            ssid: elements.ssid(),
            channel,
            span: ChannelSpan::detect(channel, &elements),
            standard: Standard::detect(channel.band, &elements),
            security: Security::detect(observation.capability, &elements),
            vendor: vendor(observation.bssid),
            max_rate_mbps: elements.max_legacy_rate_mbps(),
            signal_dbm: observation.signal_dbm,
            associated: observation.associated,
        })
    }
}

/// Signal samples over time for one BSS, oldest first. Times are offsets
/// from an arbitrary epoch chosen by the caller (the domain owns no clock).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignalHistory(VecDeque<(Duration, f32)>);

impl SignalHistory {
    /// Receptions closer together than this are the same beacon reported
    /// again by a cached scan dump, not a new measurement.
    const SAME_RECEPTION: Duration = Duration::from_millis(500);

    /// Records a measurement unless it repeats or predates the latest one.
    pub fn record(&mut self, at: Duration, dbm: f32) {
        if self
            .latest()
            .is_some_and(|(t, _)| at < t + Self::SAME_RECEPTION)
        {
            return;
        }
        self.0.push_back((at, dbm));
    }

    /// Drops samples taken before `cutoff`.
    pub fn forget_before(&mut self, cutoff: Duration) {
        while self.0.front().is_some_and(|&(t, _)| t < cutoff) {
            self.0.pop_front();
        }
    }

    pub fn latest(&self) -> Option<(Duration, f32)> {
        self.0.back().copied()
    }

    pub fn samples(&self) -> impl ExactSizeIterator<Item = (Duration, f32)> + '_ {
        self.0.iter().copied()
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let hex = String::deserialize(deserializer)?;
        if hex.len() % 2 != 0 || !hex.is_ascii() {
            return Err(D::Error::custom(
                "hex string must have an even number of ASCII digits",
            ));
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(D::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChannelWidth;
    use crate::ie::tests::{DECO_BE65, hex};

    fn deco() -> Observation {
        Observation {
            bssid: "58:04:4f:da:89:97".parse().expect("valid"),
            freq_mhz: 5200,
            signal_dbm: Some(-43.0),
            seen_ms_ago: Some(198_486),
            capability: 0x0011,
            ies: hex(DECO_BE65),
            associated: true,
        }
    }

    #[test]
    fn interprets_real_observation() {
        let ap = AccessPoint::from_observation(&deco()).expect("5 GHz channel");
        assert_eq!(ap.ssid.as_deref(), Some("MenS7"));
        assert_eq!(ap.channel.number, 40);
        assert_eq!(ap.span.width, ChannelWidth::Mhz160);
        assert_eq!(ap.standard, Standard::Be);
        assert_eq!(ap.security.to_string(), "WPA2/WPA3-Personal");
        assert_eq!(ap.vendor, Some("TP-Link Systems Inc."));
    }

    #[test]
    fn unknown_frequency_is_not_an_access_point() {
        let observation = Observation {
            freq_mhz: 58_320,
            ..deco()
        };
        assert_eq!(AccessPoint::from_observation(&observation), None);
    }

    #[test]
    fn observation_json_round_trip() {
        let json = serde_json::to_string(&deco()).expect("serializable");
        assert!(json.contains(r#""bssid":"58:04:4f:da:89:97""#), "{json}");
        assert!(json.contains(r#""ies":"00054d656e5337"#), "{json}");
        let back: Observation = serde_json::from_str(&json).expect("deserializable");
        assert_eq!(back, deco());
    }

    #[test]
    fn rejects_bad_hex() {
        let json = serde_json::to_string(&deco())
            .expect("serializable")
            .replace("\"ies\":\"00", "\"ies\":\"0");
        assert!(serde_json::from_str::<Observation>(&json).is_err());
    }

    #[test]
    fn history_skips_repeated_receptions_and_forgets_old_ones() {
        let s = Duration::from_secs;
        let mut history = SignalHistory::default();
        history.record(s(10), -50.0);
        history.record(s(10) + Duration::from_millis(3), -50.0); // same beacon, re-dumped
        history.record(s(9), -60.0); // older than what we have
        history.record(s(12), -55.0);
        assert_eq!(
            history.samples().collect::<Vec<_>>(),
            [(s(10), -50.0), (s(12), -55.0)]
        );
        history.forget_before(s(11));
        assert_eq!(history.samples().collect::<Vec<_>>(), [(s(12), -55.0)]);
    }
}
