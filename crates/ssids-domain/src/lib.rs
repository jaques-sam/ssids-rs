//! Wi-Fi domain model.
//!
//! Everything here is pure computation over bytes and numbers: no I/O, no
//! clocks, no platform APIs. That keeps it testable without hardware and
//! lets it compile unchanged to `wasm32-unknown-unknown`.

mod ap;
mod bssid;
mod channel;
mod ie;
mod oui;
mod phy;
mod security;

pub use ap::{AccessPoint, Observation, SignalHistory};
pub use bssid::{Bssid, ParseBssidError};
pub use channel::{Band, Channel};
pub use ie::{Element, Elements};
pub use oui::vendor;
pub use phy::{ChannelSpan, ChannelWidth, Standard};
pub use security::{Cipher, Security};
