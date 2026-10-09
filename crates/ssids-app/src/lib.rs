//! Application layer: the use case "watch the Wi-Fi neighbourhood over time".
//!
//! It owns the [`ScanSource`] port that scan backends implement and the
//! [`Session`] state the UI renders. Like the domain it performs no I/O and
//! reads no clock, so it runs unchanged in the browser.

mod port;
mod session;

pub use port::{Scan, ScanError, ScanReply, ScanSource};
pub use session::{Entry, RETENTION, Session};
