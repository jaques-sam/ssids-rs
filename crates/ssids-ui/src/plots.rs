//! The graphs below the table. They plot the same rows the table shows,
//! minus the APs the user unticked, in each AP's table colour.

use std::time::Duration;

use eframe::egui::{Align2, Stroke, Ui};
use egui_plot::{Corner, GridMark, Legend, Line, Plot, PlotPoint, Polygon, Text};
use ssids_app::{Entry, RETENTION};
use ssids_domain::{Band, Channel, SignalHistory};

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

/// Frequency range in MHz shown for a band.
fn band_range(band: Band) -> (f64, f64) {
    match band {
        Band::Ghz2_4 => (2397.0, 2497.0),
        Band::Ghz5 => (5150.0, 5895.0),
        Band::Ghz6 => (5925.0, 7125.0),
    }
}

/// Axis marks on 20 MHz channel centres. A coarser tier (the classic
/// non-overlapping 1/6/11 on 2.4 GHz, every 80 MHz elsewhere) keeps labels
/// readable when zoomed out: egui_plot drops the finer tier first.
fn channel_marks(band: Band) -> Vec<GridMark> {
    let numbers: Vec<u8> = match band {
        Band::Ghz2_4 => (1..=14).collect(),
        Band::Ghz5 => (32..=177).step_by(4).collect(),
        Band::Ghz6 => (1..=233).step_by(4).collect(),
    };
    numbers
        .into_iter()
        .filter_map(|n| Channel::new(band, n))
        .map(|channel| GridMark {
            value: f64::from(channel.center_freq()),
            step_size: mark_step(channel),
        })
        .collect()
}

fn mark_step(channel: Channel) -> f64 {
    let n = channel.number;
    match channel.band {
        Band::Ghz2_4 if matches!(n, 1 | 6 | 11) => 25.0,
        Band::Ghz2_4 => 5.0,
        Band::Ghz5 if n >= 36 && (n - 36).is_multiple_of(16) => 80.0,
        Band::Ghz6 if (n - 1).is_multiple_of(16) => 80.0,
        Band::Ghz5 | Band::Ghz6 => 20.0,
    }
}

/// A trapezoid approximating an occupied segment's spectral mask.
fn outline((low, high): (u32, u32), dbm: f64) -> Vec<[f64; 2]> {
    let (low, high) = (f64::from(low), f64::from(high));
    let ramp = ((high - low) * 0.1).min(4.0);
    vec![
        [low, FLOOR_DBM],
        [low + ramp, dbm],
        [high - ramp, dbm],
        [high, FLOOR_DBM],
    ]
}

/// Which APs share spectrum in `band`: each AP currently in range is drawn
/// over its full width at its current signal level.
pub fn channel_usage(ui: &mut Ui, band: Band, rows: &[&Entry], palette: &Palette) {
    let (min, max) = band_range(band);
    Plot::new(("channel-usage", band))
        .x_grid_spacer(move |_| channel_marks(band))
        .x_axis_formatter(move |mark, _| {
            Channel::from_freq(mark.value.round() as u32)
                .filter(|c| c.band == band)
                .map(|c| c.number.to_string())
                .unwrap_or_default()
        })
        .x_axis_label("channel")
        .y_axis_label("dBm")
        .include_x(min)
        .include_x(max)
        .include_y(FLOOR_DBM)
        .include_y(CEILING_DBM)
        .show(ui, |plot| {
            for entry in rows
                .iter()
                .filter(|e| e.present && e.ap.channel.band == band)
            {
                let Some(dbm) = entry.ap.signal_dbm.map(f64::from) else {
                    continue;
                };
                let color = palette.of(entry.ap.bssid);
                let name = label(entry);
                for segment in entry.ap.span.segments() {
                    plot.polygon(
                        Polygon::new(&name, outline(segment, dbm))
                            .fill_color(color.gamma_multiply(0.15))
                            .stroke(Stroke::new(1.5, color)),
                    );
                }
                let ssid = entry.ap.ssid.as_deref().unwrap_or("<hidden>");
                let top = PlotPoint::new(entry.ap.span.center_mhz, dbm + 1.0);
                plot.text(
                    Text::new(&name, top, ssid)
                        .color(color)
                        .anchor(Align2::CENTER_BOTTOM),
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

    #[test]
    fn channel_marks_sit_on_channel_centres() {
        let marks = channel_marks(Band::Ghz2_4);
        assert_eq!(marks.len(), 14);
        assert_eq!((marks[0].value, marks[0].step_size), (2412.0, 25.0));
        assert_eq!((marks[1].value, marks[1].step_size), (2417.0, 5.0));
        assert_eq!(marks[13].value, 2484.0);
        let five = channel_marks(Band::Ghz5);
        assert!(
            five.iter()
                .any(|m| m.value == 5180.0 && m.step_size == 80.0),
            "channel 36"
        );
        let six = channel_marks(Band::Ghz6);
        assert_eq!(six.len(), 59);
        let (min, max) = band_range(Band::Ghz6);
        assert!(six.iter().all(|m| (min..=max).contains(&m.value)));
    }

    #[test]
    fn outline_spans_the_segment_from_the_floor() {
        assert_eq!(
            outline((2402, 2422), -40.0),
            [
                [2402.0, FLOOR_DBM],
                [2404.0, -40.0],
                [2420.0, -40.0],
                [2422.0, FLOOR_DBM]
            ]
        );
    }
}
