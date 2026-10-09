//! Native entry point: picks the scan backend from the command line.

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    native::main()
}

#[cfg(target_arch = "wasm32")]
fn main() {
    web::main();
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use clap::Parser;
    use ssids_adapter_remote::RemoteSource;
    use ssids_adapter_replay::ReplaySource;
    use ssids_app::ScanSource;
    use ssids_ui::SsidsApp;

    #[derive(Parser)]
    #[command(version, about = "Graphical Wi-Fi scanner")]
    struct Args {
        /// Wireless interface to scan (default: the first one found).
        #[arg(short, long, conflicts_with_all = ["agent", "replay", "demo"])]
        interface: Option<String>,

        /// Show scans from an `ssids serve` agent, e.g. ws://192.0.2.7:7878.
        #[arg(long, conflicts_with_all = ["replay", "demo"])]
        agent: Option<String>,

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
        let create = Box::new(|cc: &eframe::CreationContext<'_>| {
            Ok(Box::new(SsidsApp::new(source, label, cc.storage)) as Box<dyn eframe::App>)
        });
        match eframe::run_native("ssids", options, create) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("ssids-gui: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn pick_source(args: Args) -> Result<Source, Box<dyn std::error::Error>> {
        if let Some(url) = args.agent {
            let label = format!("agent {url}");
            return Ok((Box::new(RemoteSource::new(url)), label));
        }
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
        (Box::new(ReplaySource::demo()), "synthetic demo".into())
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

/// Browser entry point. Browsers cannot scan Wi-Fi: with `?agent=<ws url>`
/// the page shows live scans from an `ssids serve` agent, otherwise the
/// bundled demo.
#[cfg(target_arch = "wasm32")]
mod web {
    use eframe::wasm_bindgen::JsCast as _;
    use ssids_adapter_remote::RemoteSource;
    use ssids_adapter_replay::ReplaySource;
    use ssids_app::ScanSource;
    use ssids_ui::SsidsApp;

    pub fn main() {
        // Routes `log` records (e.g. WebSocket errors) to the browser console.
        let _ = eframe::WebLogger::init(log::LevelFilter::Warn);
        wasm_bindgen_futures::spawn_local(async {
            let Some(canvas) = element("ssids").and_then(|e| e.dyn_into().ok()) else {
                return set_status("ssids: page has no <canvas id=\"ssids\">");
            };
            let (source, label): (Box<dyn ScanSource>, String) = match agent_url() {
                Some(url) => (Box::new(RemoteSource::new(url.clone())), format!("agent {url}")),
                None => (
                    Box::new(ReplaySource::demo()),
                    "synthetic demo · for live data run `ssids serve` and add ?agent=ws://127.0.0.1:7878".into(),
                ),
            };
            let create = Box::new(|cc: &eframe::CreationContext<'_>| {
                Ok(Box::new(SsidsApp::new(source, label, cc.storage)) as Box<dyn eframe::App>)
            });
            let started = eframe::WebRunner::new()
                .start(canvas, eframe::WebOptions::default(), create)
                .await;
            match started {
                Ok(()) => {
                    if let Some(status) = element("status") {
                        status.remove();
                    }
                }
                Err(error) => set_status(&format!("ssids failed to start: {error:?}")),
            }
        });
    }

    fn agent_url() -> Option<String> {
        let href = web_sys::window()?.location().href().ok()?;
        web_sys::Url::new(&href).ok()?.search_params().get("agent")
    }

    fn element(id: &str) -> Option<web_sys::Element> {
        web_sys::window()?.document()?.get_element_by_id(id)
    }

    /// Reports in the page itself: users have no console to read.
    fn set_status(message: &str) {
        if let Some(status) = element("status") {
            status.set_text_content(Some(message));
        }
    }
}
