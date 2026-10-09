use std::collections::BTreeSet;
use std::time::Duration;

use eframe::egui::{self, Color32, RichText, Ui};
use egui_extras::{Column as Width, TableBuilder};
use ssids_app::Entry;
use ssids_domain::Bssid;

use crate::colors::{self, Palette};
use crate::fonts;
use crate::rows::{Column, Sort, age};

const ROW_HEIGHT: f32 = 20.0;

/// The access point table. Header clicks re-sort; the first column toggles
/// whether an AP is drawn in the graphs and shows its graph colour. The
/// connected network's row is highlighted and in bold.
pub fn show(
    ui: &mut Ui,
    rows: &[&Entry],
    palette: &Palette,
    sort: &mut Sort,
    hidden: &mut BTreeSet<Bssid>,
    now: Duration,
) {
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Width::exact(36.0))
        .columns(Width::auto().at_least(50.0), Column::ALL.len() - 1)
        .column(Width::remainder().at_least(60.0))
        .header(ROW_HEIGHT, |mut header| {
            header.col(|_| {});
            for column in Column::ALL {
                header.col(|ui| {
                    let arrow = match (sort.column == column, sort.descending) {
                        (false, _) => "",
                        (true, false) => " ⏶",
                        (true, true) => " ⏷",
                    };
                    let title = RichText::new(format!("{}{arrow}", column.title())).strong();
                    if ui.add(egui::Button::new(title).frame(false)).clicked() {
                        sort.toggle(column);
                    }
                });
            }
        })
        .body(|body| {
            body.rows(ROW_HEIGHT, rows.len(), |mut row| {
                let entry = rows[row.index()];
                let bssid = entry.ap.bssid;
                let connected = entry.connected();
                row.set_selected(connected);
                row.col(|ui| {
                    let mut shown = !hidden.contains(&bssid);
                    let swatch = RichText::new("■").color(palette.of(bssid));
                    if ui
                        .checkbox(&mut shown, swatch)
                        .on_hover_text("Show in graphs")
                        .changed()
                    {
                        if shown {
                            hidden.remove(&bssid);
                        } else {
                            hidden.insert(bssid);
                        }
                    }
                });
                let weak = (!entry.present).then(|| ui_weak_color(&row));
                for column in Column::ALL {
                    row.col(|ui| {
                        let mut text = cell(entry, column, now);
                        if let Some(weak) = weak {
                            text = text.color(weak);
                        }
                        // The BSSID keeps its monospace font, aligned with the rows above.
                        if connected && column != Column::Bssid {
                            text = fonts::bold(text);
                        }
                        ui.label(text);
                    });
                }
            });
        });
}

fn ui_weak_color(row: &egui_extras::TableRow<'_, '_>) -> Color32 {
    row.response().ctx.global_style().visuals.weak_text_color()
}

fn cell(entry: &Entry, column: Column, now: Duration) -> RichText {
    let ap = &entry.ap;
    match column {
        Column::Ssid => match &ap.ssid {
            Some(ssid) => RichText::new(ssid),
            None => RichText::new("<hidden>").italics(),
        },
        Column::Bssid => RichText::new(ap.bssid.to_string()).monospace(),
        Column::Signal => match ap.signal_dbm {
            Some(dbm) => RichText::new(format!("{dbm:.0} dBm")).color(colors::signal(dbm)),
            None => RichText::new("?"),
        },
        Column::Channel => RichText::new(format!("{} ({})", ap.channel, ap.channel.band)),
        Column::Width => RichText::new(ap.span.width.to_string()),
        Column::Security => RichText::new(ap.security.to_string()),
        Column::Cipher => {
            let ciphers: Vec<String> = ap
                .security
                .ciphers
                .iter()
                .map(ToString::to_string)
                .collect();
            RichText::new(ciphers.join("+"))
        }
        Column::Standard => RichText::new(match ap.standard.wifi_name(ap.channel.band) {
            Some(name) => format!("{} ({name})", ap.standard),
            None => ap.standard.to_string(),
        }),
        Column::Rate => RichText::new(
            ap.max_rate_mbps
                .map(|r| format!("{r} Mb/s"))
                .unwrap_or_default(),
        ),
        Column::Vendor => RichText::new(ap.vendor.unwrap_or("")),
        Column::LastSeen => RichText::new(age(entry.heard_ago(now))),
    }
}
