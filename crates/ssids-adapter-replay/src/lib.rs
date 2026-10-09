//! A [`ScanSource`] that plays back a recording, looping at the end.
//!
//! Recordings are JSON Lines: one serialised [`Scan`] per line, the format
//! the CLI's `--record` writes. Each `request` yields the next scan.

use std::fmt;

use ssids_app::{Scan, ScanReply, ScanSource};

/// The synthetic neighbourhood shown by [`ReplaySource::demo`].
const DEMO_RECORDING: &str = include_str!("../recordings/demo.jsonl");

#[derive(Debug)]
pub struct ReplaySource {
    scans: Vec<Scan>,
    next: usize,
    pending: Option<ScanReply>,
}

impl ReplaySource {
    /// The bundled synthetic neighbourhood (see `scripts/make-demo-recording.py`),
    /// for the browser and for trying the UI without Wi-Fi hardware.
    pub fn demo() -> Self {
        Self::from_jsonl(DEMO_RECORDING).expect("bundled demo recording is valid (tested)")
    }

    pub fn from_jsonl(recording: &str) -> Result<Self, RecordingError> {
        let scans = recording
            .lines()
            .enumerate()
            .filter(|(_, line)| !line.trim().is_empty())
            .map(|(index, line)| {
                serde_json::from_str(line).map_err(|source| RecordingError {
                    line: index + 1,
                    source,
                })
            })
            .collect::<Result<Vec<Scan>, _>>()?;
        Ok(Self {
            scans,
            next: 0,
            pending: None,
        })
    }
}

impl ScanSource for ReplaySource {
    fn request(&mut self) {
        if self.scans.is_empty() || self.pending.is_some() {
            return;
        }
        self.pending = Some(Ok(self.scans[self.next].clone()));
        self.next = (self.next + 1) % self.scans.len();
    }

    fn take(&mut self) -> Option<ScanReply> {
        self.pending.take()
    }
}

/// A line of a recording that is not a valid scan.
#[derive(Debug)]
pub struct RecordingError {
    pub line: usize,
    pub source: serde_json::Error,
}

impl fmt::Display for RecordingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "recording line {}: {}", self.line, self.source)
    }
}

impl std::error::Error for RecordingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(test)]
mod tests {
    use ssids_domain::AccessPoint;

    use super::*;

    #[test]
    fn plays_scans_in_order_and_loops() {
        let mut source = ReplaySource::from_jsonl(
            "{\"observations\":[],\"passive_reason\":\"a\"}\n\n{\"observations\":[],\"passive_reason\":\"b\"}\n",
        )
        .expect("valid recording");
        let mut reasons = Vec::new();
        for _ in 0..3 {
            source.request();
            source.request(); // a second request while one is pending is ignored
            let scan = source.take().expect("reply").expect("scan");
            reasons.push(scan.passive_reason.expect("set"));
            assert!(source.take().is_none());
        }
        assert_eq!(reasons, ["a", "b", "a"]);
    }

    #[test]
    fn empty_recording_never_replies() {
        let mut source = ReplaySource::from_jsonl("").expect("valid");
        source.request();
        assert!(source.take().is_none());
    }

    #[test]
    fn reports_the_bad_line() {
        let error =
            ReplaySource::from_jsonl("{\"observations\":[]}\nnot json").expect_err("invalid");
        assert_eq!(error.line, 2);
    }

    #[test]
    fn demo_recording_is_valid_and_varied() {
        let source = ReplaySource::demo();
        assert!(source.scans.len() >= 30);
        let aps: std::collections::BTreeSet<_> = source
            .scans
            .iter()
            .flat_map(|s| s.observations.iter().map(|o| o.bssid))
            .collect();
        assert!(aps.len() >= 8, "demo should show a busy neighbourhood");
        let security: std::collections::BTreeSet<String> = source
            .scans
            .iter()
            .flat_map(|s| &s.observations)
            .map(|o| {
                AccessPoint::from_observation(o)
                    .expect("Wi-Fi channel")
                    .security
                    .to_string()
            })
            .collect();
        let expected = [
            "OWE",
            "Open",
            "WEP",
            "WPA/WPA2-Personal",
            "WPA2-Enterprise",
            "WPA2-Personal",
            "WPA2/WPA3-Personal",
            "WPA3-Enterprise",
            "WPA3-Personal",
        ];
        assert_eq!(security, expected.map(String::from).into());
    }
}
