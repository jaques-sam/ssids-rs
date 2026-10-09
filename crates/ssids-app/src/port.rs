use std::fmt;

use serde::{Deserialize, Serialize};
use ssids_domain::Observation;

/// The result of one scan.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Scan {
    pub observations: Vec<Observation>,
    /// Set when the backend could not trigger a fresh sweep and only reports
    /// what the OS already had cached, explaining why (typically missing
    /// privileges). Users must know their view may be stale.
    pub passive_reason: Option<String>,
}

/// A human-readable failure reported by a scan backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanError(pub String);

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScanError {}

/// What a scan produces. It is also the agent's wire message, so a remote
/// source is indistinguishable from a local one to the session.
pub type ScanReply = Result<Scan, ScanError>;

/// Port implemented by every scan backend (nl80211, replay, remote agent).
///
/// Both methods must return immediately: the session drives sources from
/// the UI thread, which in the browser is the only thread there is.
pub trait ScanSource {
    /// Asks for a fresh scan. Ignored if one is already in flight.
    fn request(&mut self);

    /// A reply that arrived since the last call, if any.
    fn take(&mut self) -> Option<ScanReply>;
}
