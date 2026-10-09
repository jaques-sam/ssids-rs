use eframe::egui::Color32;
use eframe::egui::ecolor::Hsva;
use ssids_domain::Bssid;

/// A stable colour per BSSID, so an AP keeps its colour in the table and in
/// every graph, across frames and restarts.
pub fn of(bssid: Bssid) -> Color32 {
    // FNV-1a spreads neighbouring BSSIDs (same OUI, consecutive suffix) apart.
    let hash = bssid.0.iter().fold(0x811c_9dc5_u32, |h, &b| {
        (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
    });
    let hue = (hash % 360) as f32 / 360.0;
    Hsva::new(hue, 0.75, 0.9, 1.0).into()
}

pub const GOOD: Color32 = Color32::from_rgb(0x3c, 0xb3, 0x71);
pub const FAIR: Color32 = Color32::from_rgb(0xe0, 0xa8, 0x2e);
pub const BAD: Color32 = Color32::from_rgb(0xd9, 0x53, 0x4f);

/// Traffic-light colour for a signal level.
pub fn signal(dbm: f32) -> Color32 {
    match dbm {
        d if d >= -60.0 => GOOD,
        d if d >= -75.0 => FAIR,
        _ => BAD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbouring_bssids_get_different_colours() {
        let a = of(Bssid([0, 0, 0x0c, 0, 0, 1]));
        let b = of(Bssid([0, 0, 0x0c, 0, 0, 2]));
        assert_ne!(a, b);
        assert_eq!(a, of(Bssid([0, 0, 0x0c, 0, 0, 1])), "deterministic");
    }
}
