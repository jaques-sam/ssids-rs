//! The ssids graphical interface.
//!
//! [`SsidsApp`] only knows the [`ScanSource`] port; the composition roots
//! (the native `main`, the web entry point) decide which backend feeds it.

mod colors;
mod plots;
mod rows;
mod table;

use std::collections::BTreeSet;
use std::time::Duration;

use eframe::egui::{self, RichText, Ui};
use ssids_app::{Entry, ScanSource, Session};
use ssids_domain::{Band, Bssid};

use crate::colors::Palette;
use crate::rows::{Filter, Sort};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

/// Which graph the bottom panel shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Graph {
    SignalHistory,
    Channels(Band),
}

impl Graph {
    const ALL: [Self; 4] = [
        Self::SignalHistory,
        Self::Channels(Band::Ghz2_4),
        Self::Channels(Band::Ghz5),
        Self::Channels(Band::Ghz6),
    ];

    fn title(self) -> String {
        match self {
            Self::SignalHistory => "Signal over time".into(),
            Self::Channels(band) => format!("{band} channels"),
        }
    }
}

#[derive(Debug)]
pub struct SsidsApp {
    session: Session,
    source: Box<dyn ScanSource>,
    /// Where the data comes from, shown to the user.
    source_label: String,
    filter: Filter,
    sort: Sort,
    /// APs the user excluded from the graphs.
    hidden: BTreeSet<Bssid>,
    palette: Palette,
    graph: Graph,
    /// Session clock: time since the app started.
    now: Duration,
}

impl SsidsApp {
    pub fn new(source: Box<dyn ScanSource>, source_label: impl Into<String>) -> Self {
        Self {
            session: Session::new(DEFAULT_INTERVAL),
            source,
            source_label: source_label.into(),
            filter: Filter::default(),
            sort: Sort::default(),
            hidden: BTreeSet::new(),
            palette: Palette::default(),
            graph: Graph::SignalHistory,
            now: Duration::ZERO,
        }
    }

    fn toolbar(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("ssids").strong());
            ui.label(RichText::new(&self.source_label).weak());
            ui.separator();
            let mut secs = self.session.interval().as_secs();
            ui.label("Scan every");
            if ui
                .add(egui::DragValue::new(&mut secs).range(1..=60).suffix(" s"))
                .changed()
            {
                self.session.set_interval(Duration::from_secs(secs));
            }
            ui.separator();
            ui.add(
                egui::TextEdit::singleline(&mut self.filter.text)
                    .hint_text("Filter SSID, BSSID, vendor")
                    .desired_width(200.0),
            );
            for (band, shown) in &mut self.filter.bands {
                ui.checkbox(shown, band.to_string());
            }
            ui.checkbox(&mut self.filter.hide_absent, "Hide gone");
        });
    }

    fn status(&self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            let total = self.session.entries().len();
            let present = self.session.entries().filter(|e| e.present).count();
            ui.label(format!(
                "{present} access points in range, {total} remembered"
            ));
            if let Some(error) = self.session.last_error() {
                ui.separator();
                ui.label(RichText::new(format!("Scan failed: {error}")).color(colors::BAD));
            } else if let Some(reason) = self.session.passive_reason() {
                ui.separator();
                ui.label(RichText::new(format!("Passive: {reason}")).color(colors::FAIR));
            }
        });
    }
}

impl eframe::App for SsidsApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.now = Duration::from_secs_f64(ctx.input(|i| i.time));
        if self.session.tick(self.now, self.source.as_mut()) {
            for entry in self.session.entries() {
                self.palette.assign(entry.ap.bssid);
            }
        }
        // Keep ticking while idle so scans continue without user input.
        ctx.request_repaint_after(Duration::from_millis(250));
    }

    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("toolbar").show(ui, |ui| self.toolbar(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.status(ui));
        let rows = rows::visible(self.session.entries(), &self.filter, self.sort);
        egui::Panel::bottom("graphs")
            .resizable(true)
            .default_size(320.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for graph in Graph::ALL {
                        ui.selectable_value(&mut self.graph, graph, graph.title());
                    }
                });
                let plotted: Vec<&Entry> = rows
                    .iter()
                    .copied()
                    .filter(|e| !self.hidden.contains(&e.ap.bssid))
                    .collect();
                match self.graph {
                    Graph::SignalHistory => {
                        plots::signal_history(ui, &plotted, &self.palette, self.now)
                    }
                    Graph::Channels(band) => {
                        plots::channel_usage(ui, band, &plotted, &self.palette)
                    }
                }
            });
        egui::CentralPanel::default().show(ui, |ui| {
            table::show(
                ui,
                &rows,
                &self.palette,
                &mut self.sort,
                &mut self.hidden,
                self.now,
            );
        });
    }
}
