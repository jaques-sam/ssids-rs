//! Vendor names for BSSIDs, from the embedded IEEE MA-L registry
//! (regenerate with `scripts/update-oui.py`).

use std::sync::OnceLock;

use crate::Bssid;

const REGISTRY: &str = include_str!("../data/oui.tsv");

/// Sorted `(oui, organisation)` pairs, parsed on first use.
fn table() -> &'static [(u32, &'static str)] {
    static TABLE: OnceLock<Vec<(u32, &'static str)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        REGISTRY
            .lines()
            .filter_map(|line| {
                let (oui, name) = line.split_once('\t')?;
                Some((u32::from_str_radix(oui, 16).ok()?, name))
            })
            .collect()
    })
}

/// The organisation the BSSID's OUI is registered to, if any.
pub fn vendor(bssid: Bssid) -> Option<&'static str> {
    if bssid.is_locally_administered() {
        return None;
    }
    let [a, b, c] = bssid.oui();
    let key = u32::from_be_bytes([0, a, b, c]);
    let table = table();
    table
        .binary_search_by_key(&key, |&(oui, _)| oui)
        .ok()
        .map(|i| table[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_sorted_and_parses_completely() {
        let table = table();
        assert_eq!(table.len(), REGISTRY.lines().count());
        assert!(
            table.windows(2).all(|w| w[0].0 < w[1].0),
            "binary search needs sorted keys"
        );
    }

    #[test]
    fn known_vendor() {
        let bssid: Bssid = "00:00:0c:12:34:56".parse().expect("valid");
        assert_eq!(vendor(bssid), Some("Cisco Systems, Inc"));
        // The BSSID of the captured fixture beacon.
        let bssid: Bssid = "58:04:4f:da:89:97".parse().expect("valid");
        assert_eq!(vendor(bssid), Some("TP-Link Systems Inc."));
    }

    #[test]
    fn locally_administered_has_no_vendor() {
        let bssid: Bssid = "02:00:0c:12:34:56".parse().expect("valid");
        assert_eq!(vendor(bssid), None);
    }
}
