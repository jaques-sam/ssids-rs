use ssids_domain::AccessPoint;

const HEADERS: [&str; 9] = [
    "SSID", "BSSID", "dBm", "CH", "BAND", "WIDTH", "SECURITY", "STANDARD", "VENDOR",
];

fn cells(ap: &AccessPoint) -> [String; 9] {
    let associated = if ap.associated { "*" } else { "" };
    [
        format!("{associated}{}", ap.ssid.as_deref().unwrap_or("<hidden>")),
        ap.bssid.to_string(),
        ap.signal_dbm
            .map_or_else(|| "?".into(), |dbm| format!("{dbm:.0}")),
        ap.channel.to_string(),
        ap.channel.band.to_string(),
        ap.span.width.to_string(),
        ap.security.to_string(),
        ap.standard.to_string(),
        ap.vendor.unwrap_or("").to_owned(),
    ]
}

/// Plain-text table, strongest signal first; `*` marks the associated BSS.
pub fn render(aps: &[AccessPoint]) -> String {
    let mut aps: Vec<&AccessPoint> = aps.iter().collect();
    aps.sort_by(|a, b| {
        b.signal_dbm
            .unwrap_or(f32::MIN)
            .total_cmp(&a.signal_dbm.unwrap_or(f32::MIN))
    });
    let rows: Vec<[String; 9]> = aps.into_iter().map(cells).collect();
    let mut widths = HEADERS.map(|h| h.chars().count());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: &[&str]| {
        let padded: Vec<String> = cells
            .iter()
            .zip(widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        padded.join("  ").trim_end().to_owned() + "\n"
    };
    let mut out = line(&HEADERS);
    for row in &rows {
        out += &line(&row.each_ref().map(String::as_str));
    }
    out
}

#[cfg(test)]
mod tests {
    use ssids_domain::Observation;

    use super::*;

    fn ap(ssid: &str, last_octet: u8, dbm: f32, associated: bool) -> AccessPoint {
        let mut ies = vec![0, u8::try_from(ssid.len()).expect("short")];
        ies.extend(ssid.as_bytes());
        let observation = Observation {
            bssid: ssids_domain::Bssid([0x00, 0x00, 0x0c, 0, 0, last_octet]),
            freq_mhz: 2412,
            signal_dbm: Some(dbm),
            seen_ms_ago: None,
            capability: 0x0001,
            ies,
            associated,
        };
        AccessPoint::from_observation(&observation).expect("valid channel")
    }

    #[test]
    fn sorted_by_signal_and_aligned() {
        let table = render(&[
            ap("weak", 1, -80.0, false),
            ap("strong", 2, -40.0, true),
            ap("", 3, -60.0, false),
        ]);
        let lines: Vec<&str> = table.lines().collect();
        assert!(lines[0].starts_with("SSID      BSSID"), "{table}");
        assert!(
            lines[1].starts_with("*strong   00:00:0c:00:00:02  -40"),
            "{table}"
        );
        assert!(lines[2].starts_with("<hidden>"), "{table}");
        assert!(lines[3].starts_with("weak"), "{table}");
        assert!(lines[1].ends_with("Cisco Systems, Inc"), "{table}");
    }
}
