//! Native entry point: picks the scan backend from the command line.

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    native::main()
}

/// The browser build starts from the library's web entry point instead.
#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use clap::Parser;
    use ssids_adapter_replay::{DEMO_RECORDING, ReplaySource};
    use ssids_app::ScanSource;
    use ssids_ui::SsidsApp;

    #[derive(Parser)]
    #[command(version, about = "Graphical Wi-Fi scanner")]
    struct Args {
        /// Wireless interface to scan (default: the first one found).
        #[arg(short, long, conflicts_with_all = ["replay", "demo"])]
        interface: Option<String>,

        /// Replay a recording made with `ssids record` instead of scanning.
        #[arg(long, conflicts_with = "demo")]
        replay: Option<PathBuf>,

        /// Show the bundled synthetic demo instead of scanning.
        #[arg(long)]
        demo: bool,
    }

    type Source = (Box<dyn ScanSource>, String);

    pub fn main() -> ExitCode {
        let args = Args::parse();
        let (source, label) = match pick_source(args) {
            Ok(picked) => picked,
            Err(error) => {
                eprintln!("ssids-gui: {error}");
                return ExitCode::FAILURE;
            }
        };
        let options = eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
                .with_title("ssids")
                .with_inner_size([1200.0, 760.0]),
            ..Default::default()
        };
        let app = SsidsApp::new(source, label);
        match eframe::run_native("ssids", options, Box::new(|_| Ok(Box::new(app)))) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("ssids-gui: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn pick_source(args: Args) -> Result<Source, Box<dyn std::error::Error>> {
        if let Some(path) = args.replay {
            let recording = std::fs::read_to_string(&path)?;
            let label = format!("replay of {}", path.display());
            return Ok((Box::new(ReplaySource::from_jsonl(&recording)?), label));
        }
        if args.demo {
            return Ok(demo());
        }
        live(args.interface)
    }

    fn demo() -> Source {
        let source =
            ReplaySource::from_jsonl(DEMO_RECORDING).expect("bundled demo is valid (tested)");
        (Box::new(source), "synthetic demo".into())
    }

    #[cfg(target_os = "linux")]
    fn live(interface: Option<String>) -> Result<Source, Box<dyn std::error::Error>> {
        let label = format!(
            "nl80211 · {}",
            interface.as_deref().unwrap_or("first wireless interface")
        );
        let source = ssids_adapter_nl80211::LiveSource::spawn(interface)?;
        Ok((Box::new(source), label))
    }

    #[cfg(not(target_os = "linux"))]
    fn live(_interface: Option<String>) -> Result<Source, Box<dyn std::error::Error>> {
        eprintln!("ssids-gui: live scanning is only implemented for Linux; showing the demo");
        Ok(demo())
    }
}
