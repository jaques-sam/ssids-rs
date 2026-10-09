//! Which access points the table shows, in which order. Pure functions over
//! session entries, kept apart from egui so they are unit-testable.

use std::cmp::Ordering;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ssids_app::Entry;
use ssids_domain::Band;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Column {
    Ssid,
    Bssid,
    Signal,
    Channel,
    Width,
    Security,
    Cipher,
    Standard,
    Rate,
    Vendor,
    LastSeen,
}

impl Column {
    pub const ALL: [Self; 11] = [
        Self::Ssid,
        Self::Bssid,
        Self::Signal,
        Self::Channel,
        Self::Width,
        Self::Security,
        Self::Cipher,
        Self::Standard,
        Self::Rate,
        Self::Vendor,
        Self::LastSeen,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Ssid => "SSID",
            Self::Bssid => "BSSID",
            Self::Signal => "Signal",
            Self::Channel => "Channel",
            Self::Width => "Width",
            Self::Security => "Security",
            Self::Cipher => "Cipher",
            Self::Standard => "Standard",
            Self::Rate => "Max rate",
            Self::Vendor => "Vendor",
            Self::LastSeen => "Last seen",
        }
    }

    /// Whether the entry lacks a value for this column. Such rows always
    /// sort last, whichever direction the user picked.
    fn is_missing(self, entry: &Entry) -> bool {
        let ap = &entry.ap;
        match self {
            Self::Ssid => ap.ssid.is_none(),
            Self::Signal => ap.signal_dbm.is_none(),
            Self::Rate => ap.max_rate_mbps.is_none(),
            Self::Vendor => ap.vendor.is_none(),
            _ => false,
        }
    }

    /// Ascending order for this column.
    fn compare(self, a: &Entry, b: &Entry) -> Ordering {
        let (a, b, ea, eb) = (&a.ap, &b.ap, a, b);
        match self {
            Self::Ssid => missing_last(a.ssid.as_deref(), b.ssid.as_deref(), |x, y| {
                x.to_lowercase().cmp(&y.to_lowercase())
            }),
            Self::Bssid => a.bssid.cmp(&b.bssid),
            Self::Signal => missing_last(a.signal_dbm, b.signal_dbm, f32::total_cmp),
            Self::Channel => a.channel.cmp(&b.channel),
            Self::Width => a.span.width.cmp(&b.span.width),
            Self::Security => a.security.to_string().cmp(&b.security.to_string()),
            Self::Cipher => a.security.ciphers.cmp(&b.security.ciphers),
            Self::Standard => a.standard.cmp(&b.standard),
            Self::Rate => missing_last(a.max_rate_mbps, b.max_rate_mbps, f32::total_cmp),
            Self::Vendor => missing_last(a.vendor, b.vendor, Ord::cmp),
            // Most recently heard first; same `now` for both, so any instant works.
            Self::LastSeen => ea
                .heard_ago(Duration::ZERO)
                .cmp(&eb.heard_ago(Duration::ZERO)),
        }
    }
}

fn missing_last<T>(a: Option<T>, b: Option<T>, cmp: impl Fn(&T, &T) -> Ordering) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => cmp(&a, &b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sort {
    pub column: Column,
    pub descending: bool,
}

impl Default for Sort {
    fn default() -> Self {
        Self {
            column: Column::Signal,
            descending: true,
        }
    }
}

impl Sort {
    /// Header click: flip direction on the active column, else switch to it.
    pub fn toggle(&mut self, column: Column) {
        if self.column == column {
            self.descending = !self.descending;
        } else {
            *self = Self {
                column,
                descending: false,
            };
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    /// Case-insensitive substring of SSID, BSSID or vendor.
    pub text: String,
    pub bands: [(Band, bool); 3],
    pub hide_absent: bool,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            text: String::new(),
            bands: [(Band::Ghz2_4, true), (Band::Ghz5, true), (Band::Ghz6, true)],
            hide_absent: false,
        }
    }
}

impl Filter {
    pub fn matches(&self, entry: &Entry) -> bool {
        let ap = &entry.ap;
        let band_shown = self
            .bands
            .iter()
            .any(|&(band, shown)| shown && band == ap.channel.band);
        let needle = self.text.trim().to_lowercase();
        let text_matches = needle.is_empty()
            || [ap.ssid.as_deref(), Some(&ap.bssid.to_string()), ap.vendor]
                .into_iter()
                .flatten()
                .any(|haystack| haystack.to_lowercase().contains(&needle));
        band_shown && text_matches && (entry.present || !self.hide_absent)
    }
}

/// Entries passing `filter`, ordered by `sort` with BSSID as tie-breaker so
/// rows never jump around between frames.
pub fn visible<'a>(
    entries: impl Iterator<Item = &'a Entry>,
    filter: &Filter,
    sort: Sort,
) -> Vec<&'a Entry> {
    let mut rows: Vec<&Entry> = entries.filter(|e| filter.matches(e)).collect();
    let column = sort.column;
    rows.sort_by(|a, b| {
        let order = column.compare(a, b);
        let order = if sort.descending {
            order.reverse()
        } else {
            order
        };
        (column.is_missing(a).cmp(&column.is_missing(b)))
            .then(order)
            .then(a.ap.bssid.cmp(&b.ap.bssid))
    });
    rows
}

/// "3 s", "2 min" style age for the Last seen column.
pub fn age(ago: Duration) -> String {
    let secs = ago.as_secs();
    if secs < 60 {
        format!("{secs} s")
    } else {
        format!("{} min", secs / 60)
    }
}

#[cfg(test)]
mod tests {
    use ssids_domain::{AccessPoint, Bssid, Observation, SignalHistory};

    use super::*;

    fn entry(
        ssid: Option<&str>,
        last_octet: u8,
        freq_mhz: u32,
        dbm: Option<f32>,
        present: bool,
    ) -> Entry {
        let name = ssid.unwrap_or("");
        let mut ies = vec![0, u8::try_from(name.len()).expect("short")];
        ies.extend(name.as_bytes());
        let observation = Observation {
            bssid: Bssid([0x00, 0x00, 0x0c, 0, 0, last_octet]),
            freq_mhz,
            signal_dbm: dbm,
            seen_ms_ago: None,
            capability: 0x0001,
            ies,
            associated: false,
        };
        Entry {
            ap: AccessPoint::from_observation(&observation).expect("valid channel"),
            history: SignalHistory::default(),
            listed_at: Duration::ZERO,
            age: Duration::from_secs(u64::from(last_octet)),
            present,
        }
    }

    fn ssids(rows: &[&Entry]) -> Vec<Option<String>> {
        rows.iter().map(|e| e.ap.ssid.clone()).collect()
    }

    fn sample() -> Vec<Entry> {
        vec![
            entry(Some("beta"), 1, 2412, Some(-70.0), true),
            entry(Some("Alpha"), 2, 5180, Some(-40.0), true),
            entry(None, 3, 2437, None, true),
            entry(Some("gamma"), 4, 5955, Some(-55.0), false),
        ]
    }

    #[test]
    fn default_sort_is_strongest_first_with_unknown_signal_last() {
        let entries = sample();
        let rows = visible(entries.iter(), &Filter::default(), Sort::default());
        let expected =
            [Some("Alpha"), Some("gamma"), Some("beta"), None].map(|s| s.map(String::from));
        assert_eq!(ssids(&rows), expected);
    }

    #[test]
    fn ssid_sort_is_case_insensitive_and_hidden_last() {
        let entries = sample();
        let mut sort = Sort::default();
        sort.toggle(Column::Ssid);
        let rows = visible(entries.iter(), &Filter::default(), sort);
        let expected =
            [Some("Alpha"), Some("beta"), Some("gamma"), None].map(|s| s.map(String::from));
        assert_eq!(ssids(&rows), expected);
        sort.toggle(Column::Ssid);
        let rows = visible(entries.iter(), &Filter::default(), sort);
        let expected =
            [Some("gamma"), Some("beta"), Some("Alpha"), None].map(|s| s.map(String::from));
        assert_eq!(ssids(&rows), expected, "descending keeps hidden last");
    }

    #[test]
    fn filters_combine() {
        let entries = sample();
        let mut filter = Filter {
            text: "ALP".into(),
            ..Filter::default()
        };
        assert_eq!(visible(entries.iter(), &filter, Sort::default()).len(), 1);
        filter.text = "00:00:0c".into();
        assert_eq!(
            visible(entries.iter(), &filter, Sort::default()).len(),
            4,
            "BSSID match"
        );
        filter.text = "cisco".into();
        assert_eq!(
            visible(entries.iter(), &filter, Sort::default()).len(),
            4,
            "vendor match"
        );
        filter.bands[0].1 = false;
        assert_eq!(
            visible(entries.iter(), &filter, Sort::default()).len(),
            2,
            "2.4 GHz hidden"
        );
        filter.hide_absent = true;
        assert_eq!(
            visible(entries.iter(), &filter, Sort::default()).len(),
            1,
            "gamma absent"
        );
    }

    #[test]
    fn ages() {
        let s = Duration::from_secs;
        assert_eq!(age(s(3)), "3 s");
        assert_eq!(age(s(190)), "3 min");
    }
}
