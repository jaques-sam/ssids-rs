//! `ssids`: Wi-Fi scanning from the terminal.

mod table;

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand};
use ssids_adapter_nl80211::Nl80211;
use ssids_app::Scan;
use ssids_domain::AccessPoint;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Wireless interface to use (default: the first one found).
    #[arg(short, long, global = true)]
    interface: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan once and print the access points.
    Scan {
        /// Print the raw scan as one JSON line instead of a table.
        #[arg(long)]
        json: bool,

        /// Seconds to let the radio sweep after triggering a scan.
        #[arg(long, default_value_t = 5)]
        settle: u64,
    },
    /// Append scans to a JSON Lines recording that the UI can replay.
    Record {
        /// Recording file; created if missing, appended to otherwise.
        #[arg(short, long)]
        output: PathBuf,

        /// Number of scans to record.
        #[arg(long, default_value_t = 60)]
        count: u32,

        /// Seconds between scans.
        #[arg(long, default_value_t = 5)]
        interval: u64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ssids: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> io::Result<()> {
    let mut nl = Nl80211::connect()?;
    let interface = nl.interface(cli.interface.as_deref())?;
    match cli.command {
        Command::Scan { json, settle } => {
            let scan = nl.scan(&interface, Duration::from_secs(settle))?;
            warn_if_passive(&scan);
            let mut stdout = io::stdout().lock();
            if json {
                writeln!(stdout, "{}", serde_json::to_string(&scan)?)
            } else {
                let aps: Vec<AccessPoint> = scan
                    .observations
                    .iter()
                    .filter_map(AccessPoint::from_observation)
                    .collect();
                stdout.write_all(table::render(&aps).as_bytes())
            }
        }
        Command::Record {
            output,
            count,
            interval,
        } => {
            let mut file = OpenOptions::new().create(true).append(true).open(&output)?;
            let interval = Duration::from_secs(interval);
            for n in 1..=count {
                if n > 1 {
                    // Also lets the sweep triggered by the previous scan complete.
                    thread::sleep(interval);
                }
                let scan = nl.scan(&interface, Duration::ZERO)?;
                if n == 1 {
                    warn_if_passive(&scan);
                }
                writeln!(file, "{}", serde_json::to_string(&scan)?)?;
                eprintln!(
                    "recorded scan {n}/{count}: {} BSSs",
                    scan.observations.len()
                );
            }
            Ok(())
        }
    }
}

fn warn_if_passive(scan: &Scan) {
    if let Some(reason) = &scan.passive_reason {
        eprintln!("ssids: note: {reason}");
    }
}
