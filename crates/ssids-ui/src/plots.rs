//! The graphs below the table. They plot the same rows the table shows,
//! minus the APs the user unticked, in each AP's table colour.

use std::time::Duration;

use eframe::egui::Ui;
use egui_plot::{Corner, Legend, Line, Plot};
use ssids_app::{Entry, RETENTION};
use ssids_domain::SignalHistory;

use crate::colors::Palette;

/// Signal scale shared by the graphs: from the noise floor to a strong AP.
pub const FLOOR_DBM: f64 = -100.0;
const CEILING_DBM: f64 = -20.0;

/// Legend/hover name; includes the BSSID because SSIDs repeat across APs.
pub fn label(entry: &Entry) -> String {
    let ssid = entry.ap.ssid.as_deref().unwrap_or("<hidden>");
    format!("{ssid} ({})", entry.ap.bssid)
}

/// Samples as `[seconds relative to now, dBm]` points.
fn history_points(history: &SignalHistory, now: Duration) -> Vec<[f64; 2]> {
    let now = now.as_secs_f64();
    history
        .samples()
        .map(|(at, dbm)| [at.as_secs_f64() - now, f64::from(dbm)])
        .collect()
}

pub fn signal_history(ui: &mut Ui, rows: &[&Entry], palette: &Palette, now: Duration) {
    Plot::new("signal-history")
        .legend(Legend::default().position(Corner::LeftTop))
        .x_axis_label("seconds ago")
        .y_axis_label("dBm")
        .x_axis_formatter(|mark, _| format!("{:.0}", (-mark.value).max(0.0)))
        .include_x(-RETENTION.as_secs_f64())
        .include_x(0.0)
        .include_y(FLOOR_DBM)
        .include_y(CEILING_DBM)
        .show(ui, |plot| {
            for entry in rows {
                let points = history_points(&entry.history, now);
                plot.line(
                    Line::new(label(entry), points)
                        .color(palette.of(entry.ap.bssid))
                        .width(1.5),
                );
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_is_plotted_relative_to_now() {
        let mut history = SignalHistory::default();
        history.record(Duration::from_secs(10), -50.0);
        history.record(Duration::from_secs(15), -55.0);
        let points = history_points(&history, Duration::from_secs(20));
        assert_eq!(points, [[-10.0, -50.0], [-5.0, -55.0]]);
    }
}
