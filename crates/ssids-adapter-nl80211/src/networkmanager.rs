//! Asking NetworkManager to scan. On desktops polkit lets the active user
//! request Wi-Fi scans, so this gives fresh results without `CAP_NET_ADMIN`.
//! NetworkManager then reports the sweep through the same nl80211 cache we
//! read, so only the trigger goes through D-Bus.

use std::collections::HashMap;

use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, Value};

const SERVICE: &str = "org.freedesktop.NetworkManager";
const PATH: &str = "/org/freedesktop/NetworkManager";
const WIRELESS: &str = "org.freedesktop.NetworkManager.Device.Wireless";

/// Requests a scan on `interface`. Also succeeds when NetworkManager
/// declines because it scanned moments ago, as its results are fresh then.
pub fn request_scan(bus: &Connection, interface: &str) -> zbus::Result<()> {
    let reply = bus.call_method(
        Some(SERVICE),
        PATH,
        Some(SERVICE),
        "GetDeviceByIpIface",
        &(interface,),
    )?;
    let device: OwnedObjectPath = reply.body().deserialize()?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    match bus.call_method(
        Some(SERVICE),
        device.as_ref(),
        Some(WIRELESS),
        "RequestScan",
        &(options,),
    ) {
        Err(zbus::Error::MethodError(_, Some(description), _)) if is_rate_limited(&description) => {
            Ok(())
        }
        result => result.map(drop),
    }
}

/// NetworkManager refuses a request within ~10 s of its previous scan with
/// this message (nm-device-wifi.c, unchanged for a decade). Should it ever
/// change, users merely see a passive-mode notice for those requests.
fn is_rate_limited(description: &str) -> bool {
    description.contains("immediately following previous scan")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_rate_limit_refusal() {
        assert!(is_rate_limited(
            "Scanning not allowed immediately following previous scan"
        ));
        assert!(!is_rate_limited("Scanning not allowed while unavailable"));
    }
}
