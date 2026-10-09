//! Wi-Fi domain model.
//!
//! Everything here is pure computation over bytes and numbers: no I/O, no
//! clocks, no platform APIs. That keeps it testable without hardware and
//! lets it compile unchanged to `wasm32-unknown-unknown`.

mod bssid;
mod channel;
mod ie;
mod phy;

pub use bssid::{Bssid, ParseBssidError};
pub use channel::{Band, Channel};
pub use ie::{Element, Elements};
pub use phy::{ChannelSpan, ChannelWidth, Standard};
