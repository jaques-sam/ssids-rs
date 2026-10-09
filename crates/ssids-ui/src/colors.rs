use std::collections::HashMap;

use eframe::egui::Color32;
use eframe::egui::ecolor::Hsva;
use ssids_domain::Bssid;

/// One colour per BSSID, used for its table swatch and every graph.
///
/// Colours are handed out in order of first appearance along the golden
/// angle, which keeps any number of APs maximally apart in hue; hashing the
/// BSSID instead made unrelated APs collide on near-identical colours.
#[derive(Debug, Default)]
pub struct Palette(HashMap<Bssid, Color32>);

impl Palette {
    pub fn assign(&mut self, bssid: Bssid) {
        let next = self.0.len();
        self.0.entry(bssid).or_insert_with(|| {
            let hue = (next as f32 * 0.618_034).fract();
            // Alternate brightness so neighbours in hue still differ.
            let value = if next.is_multiple_of(2) { 0.95 } else { 0.75 };
            Hsva::new(hue, 0.7, value, 1.0).into()
        });
    }

    pub fn of(&self, bssid: Bssid) -> Color32 {
        self.0.get(&bssid).copied().unwrap_or(Color32::GRAY)
    }
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
    fn colours_are_stable_and_distinct() {
        let mut palette = Palette::default();
        let bssids: Vec<Bssid> = (0..12).map(|n| Bssid([0, 0, 0x0c, 0, 0, n])).collect();
        for &bssid in &bssids {
            palette.assign(bssid);
        }
        palette.assign(bssids[0]);
        let colours: std::collections::HashSet<Color32> =
            bssids.iter().map(|&b| palette.of(b)).collect();
        assert_eq!(colours.len(), 12);
        assert_eq!(palette.of(Bssid([9; 6])), Color32::GRAY, "unknown BSSID");
    }
}
