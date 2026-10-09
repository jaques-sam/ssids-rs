use std::collections::BTreeMap;
use std::time::Duration;

use ssids_domain::{AccessPoint, Bssid, Observation, SignalHistory};

use crate::{ScanError, ScanReply, ScanSource};

/// How long an access point is remembered after scans stop listing it, and
/// how much signal history is kept.
pub const RETENTION: Duration = Duration::from_secs(300);

/// Requests faster than this only load the radio without adding information.
const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Everything known about one BSS.
#[derive(Clone, Debug)]
pub struct Entry {
    pub ap: AccessPoint,
    pub history: SignalHistory,
    /// Session time of the latest scan that listed the BSS.
    pub listed_at: Duration,
    /// How long before `listed_at` the backend had last heard it. Cached
    /// results can be minutes old, i.e. from before the session started,
    /// which a session timestamp could not express.
    pub age: Duration,
    /// Whether the most recent successful scan still listed it.
    pub present: bool,
}

impl Entry {
    /// How long ago the BSS was last heard.
    pub fn heard_ago(&self, now: Duration) -> Duration {
        now.saturating_sub(self.listed_at) + self.age
    }

    /// Whether this is the network the machine is connected to. A BSS that
    /// dropped out of the scans keeps its last `associated` flag, which no
    /// longer says anything, so only one still in range counts.
    pub fn connected(&self) -> bool {
        self.present && self.ap.associated
    }
}

/// State of one scanning session. Time is passed in by the caller as an
/// offset from session start, keeping this layer clock-free and testable.
#[derive(Debug)]
pub struct Session {
    entries: BTreeMap<Bssid, Entry>,
    interval: Duration,
    next_request: Duration,
    last_error: Option<ScanError>,
    passive_reason: Option<String>,
}

impl Session {
    pub fn new(interval: Duration) -> Self {
        Self {
            entries: BTreeMap::new(),
            interval: interval.max(MIN_INTERVAL),
            next_request: Duration::ZERO,
            last_error: None,
            passive_reason: None,
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval.max(MIN_INTERVAL);
    }

    /// Drives the session; call it often (e.g. every UI frame). Requests a
    /// scan when one is due and applies any replies. Returns whether the
    /// state changed.
    pub fn tick(&mut self, now: Duration, source: &mut dyn ScanSource) -> bool {
        if now >= self.next_request {
            source.request();
            self.next_request = now + self.interval;
        }
        let mut changed = false;
        while let Some(reply) = source.take() {
            self.apply(now, reply);
            changed = true;
        }
        changed
    }

    /// Applies one scan reply received at `now`.
    pub fn apply(&mut self, now: Duration, reply: ScanReply) {
        match reply {
            Ok(scan) => {
                self.last_error = None;
                self.passive_reason = scan.passive_reason;
                self.ingest(now, &scan.observations);
            }
            // Keep showing what we had: a failed scan says nothing about the APs.
            Err(error) => self.last_error = Some(error),
        }
    }

    fn ingest(&mut self, now: Duration, observations: &[Observation]) {
        for entry in self.entries.values_mut() {
            entry.present = false;
        }
        for observation in observations {
            let Some(ap) = AccessPoint::from_observation(observation) else {
                continue;
            };
            let age = Duration::from_millis(observation.seen_ms_ago.unwrap_or(0).into());
            let entry = self.entries.entry(ap.bssid).or_insert_with(|| Entry {
                ap: ap.clone(),
                history: SignalHistory::default(),
                listed_at: now,
                age,
                present: true,
            });
            if let Some(dbm) = observation.signal_dbm {
                // Before session start the plot has no time axis, so pin to 0;
                // the history still dedupes repeats of that cached beacon.
                entry.history.record(now.saturating_sub(age), dbm);
            }
            entry.ap = ap;
            entry.listed_at = now;
            entry.age = age;
            entry.present = true;
        }
        // Retention counts from when scans stopped listing a BSS, not from
        // when it was heard: a listed BSS is never dropped, however stale
        // the backend's cache entry for it is.
        self.entries
            .retain(|_, entry| now.saturating_sub(entry.listed_at) <= RETENTION);
        let cutoff = now.saturating_sub(RETENTION);
        for entry in self.entries.values_mut() {
            entry.history.forget_before(cutoff);
        }
    }

    /// All remembered access points, ordered by BSSID.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &Entry> {
        self.entries.values()
    }

    /// The error of the latest scan, if it failed.
    pub fn last_error(&self) -> Option<&ScanError> {
        self.last_error.as_ref()
    }

    /// Why the latest successful scan was passive, if it was.
    pub fn passive_reason(&self) -> Option<&str> {
        self.passive_reason.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::Scan;

    #[derive(Debug, Default)]
    struct FakeSource {
        requests: usize,
        replies: VecDeque<ScanReply>,
    }

    impl ScanSource for FakeSource {
        fn request(&mut self) {
            self.requests += 1;
        }

        fn take(&mut self) -> Option<ScanReply> {
            self.replies.pop_front()
        }
    }

    fn observation(last_octet: u8, dbm: f32, seen_ms_ago: u32) -> Observation {
        Observation {
            bssid: Bssid([0x00, 0x00, 0x0c, 0, 0, last_octet]),
            freq_mhz: 2437,
            signal_dbm: Some(dbm),
            seen_ms_ago: Some(seen_ms_ago),
            capability: 0x0001,
            ies: vec![0, 4, b'h', b'o', b'm', b'e'],
            associated: false,
        }
    }

    fn scan(observations: Vec<Observation>) -> ScanReply {
        Ok(Scan {
            observations,
            passive_reason: None,
        })
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn requests_once_per_interval_and_applies_replies() {
        let mut session = Session::new(secs(2));
        let mut source = FakeSource::default();
        assert!(!session.tick(secs(0), &mut source));
        assert!(!session.tick(secs(1), &mut source));
        assert_eq!(source.requests, 1);
        source
            .replies
            .push_back(scan(vec![observation(1, -40.0, 0)]));
        assert!(session.tick(secs(2), &mut source));
        assert_eq!(source.requests, 2);
        let entry = session.entries().next().expect("one AP");
        assert_eq!(entry.ap.ssid.as_deref(), Some("home"));
        assert_eq!(entry.history.latest(), Some((secs(2), -40.0)));
    }

    #[test]
    fn interval_has_a_floor() {
        assert_eq!(Session::new(Duration::ZERO).interval(), MIN_INTERVAL);
    }

    #[test]
    fn sample_time_accounts_for_backend_age() {
        let mut session = Session::new(secs(5));
        session.apply(secs(10), scan(vec![observation(1, -40.0, 3_000)]));
        let entry = session.entries().next().expect("one AP");
        assert_eq!(entry.heard_ago(secs(10)), secs(3));
        assert_eq!(entry.heard_ago(secs(12)), secs(5));
        assert_eq!(entry.history.latest(), Some((secs(7), -40.0)));
    }

    #[test]
    fn listed_ap_with_stale_cache_entry_is_kept_and_aged_correctly() {
        // Some drivers keep the associated BSS's cache entry minutes old.
        let mut session = Session::new(secs(5));
        session.apply(secs(1), scan(vec![observation(1, -40.0, 200_000)]));
        let later = RETENTION + secs(60);
        let age_then = u32::try_from((later + secs(199)).as_millis()).expect("fits");
        session.apply(later, scan(vec![observation(1, -40.0, age_then)]));
        let entry = session
            .entries()
            .next()
            .expect("still listed, so still shown");
        assert_eq!(entry.heard_ago(later), later + secs(199));
        assert_eq!(
            entry.history.samples().len(),
            0,
            "its only measurement predates the history window"
        );
    }

    #[test]
    fn cached_repeat_adds_no_sample() {
        let mut session = Session::new(secs(5));
        session.apply(secs(10), scan(vec![observation(1, -40.0, 1_000)]));
        session.apply(secs(15), scan(vec![observation(1, -40.0, 6_000)]));
        let entry = session.entries().next().expect("one AP");
        assert_eq!(entry.history.samples().len(), 1);
    }

    #[test]
    fn missing_aps_stay_until_retention_expires() {
        let mut session = Session::new(secs(5));
        session.apply(
            secs(0),
            scan(vec![observation(1, -40.0, 0), observation(2, -70.0, 0)]),
        );
        session.apply(secs(5), scan(vec![observation(1, -41.0, 0)]));
        let present: Vec<bool> = session.entries().map(|e| e.present).collect();
        assert_eq!(present, [true, false]);
        session.apply(RETENTION + secs(1), scan(vec![observation(1, -42.0, 0)]));
        assert_eq!(session.entries().len(), 1);
        let samples = session
            .entries()
            .next()
            .expect("AP 1")
            .history
            .samples()
            .len();
        assert_eq!(samples, 2, "the sample at t=0 aged out");
    }

    #[test]
    fn connected_only_while_listed() {
        let mut session = Session::new(secs(5));
        let associated = Observation {
            associated: true,
            ..observation(1, -40.0, 0)
        };
        session.apply(secs(0), scan(vec![associated, observation(2, -70.0, 0)]));
        let connected: Vec<bool> = session.entries().map(Entry::connected).collect();
        assert_eq!(connected, [true, false]);
        session.apply(secs(5), scan(vec![observation(2, -70.0, 0)]));
        assert!(
            session.entries().all(|e| !e.connected()),
            "out of range, so its stale associated flag no longer counts"
        );
    }

    #[test]
    fn errors_keep_data_and_clear_on_success() {
        let mut session = Session::new(secs(5));
        session.apply(secs(0), scan(vec![observation(1, -40.0, 0)]));
        session.apply(secs(5), Err(ScanError("radio off".into())));
        assert_eq!(
            session.last_error().map(ToString::to_string).as_deref(),
            Some("radio off")
        );
        assert_eq!(session.entries().len(), 1);
        assert!(session.entries().all(|e| e.present));
        session.apply(secs(10), scan(vec![]));
        assert_eq!(session.last_error(), None);
    }

    #[test]
    fn passive_reason_follows_latest_scan() {
        let mut session = Session::new(secs(5));
        let passive = Scan {
            observations: vec![],
            passive_reason: Some("no CAP_NET_ADMIN".into()),
        };
        session.apply(secs(0), Ok(passive));
        assert_eq!(session.passive_reason(), Some("no CAP_NET_ADMIN"));
        session.apply(secs(5), scan(vec![]));
        assert_eq!(session.passive_reason(), None);
    }

    #[test]
    fn non_wifi_frequencies_are_skipped() {
        let mut session = Session::new(secs(5));
        let odd = Observation {
            freq_mhz: 58_320,
            ..observation(1, -40.0, 0)
        };
        session.apply(secs(0), scan(vec![odd]));
        assert_eq!(session.entries().len(), 0);
    }
}
