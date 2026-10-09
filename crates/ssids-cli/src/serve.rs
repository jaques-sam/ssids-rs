//! `ssids serve`: hands scan results to the browser UI over WebSocket.
//!
//! Protocol: each text message from the client requests one scan; the
//! reply is one JSON-encoded `ScanReply`. Nothing else is accepted, so a
//! client can read scans but never change anything on this machine.
//!
//! Scan results are sensitive: BSSIDs locate a machine to within metres via
//! public Wi-Fi databases, and any web page may try to open a WebSocket to
//! 127.0.0.1. Browsers always send an `Origin` header that pages cannot
//! forge, so only allow-listed origins are accepted; clients without one are
//! native programs, which could read nl80211 themselves anyway.

use std::error::Error;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ssids_adapter_nl80211::Scanner;
use tungstenite::Message;
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::http::StatusCode;

/// Scans are paced to at most one per second per client, whatever it asks.
const MIN_SCAN_GAP: Duration = Duration::from_secs(1);

/// Serves clients until the process ends, one thread per client.
pub fn serve(
    listener: TcpListener,
    interface: Option<String>,
    allowed_origins: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let listen = listener.local_addr()?;
    eprintln!("ssids: serving scans on ws://{listen}");
    eprintln!(
        "ssids: accepting browser pages from: {}",
        allowed_origins.join(", ")
    );
    if !listen.ip().is_loopback() {
        eprintln!(
            "ssids: warning: listening beyond this machine; scan results reveal its location"
        );
    }
    let allowed_origins = Arc::new(allowed_origins);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("ssids: accept failed: {error}");
                continue;
            }
        };
        let (allowed_origins, interface) = (Arc::clone(&allowed_origins), interface.clone());
        thread::spawn(move || {
            let peer = stream
                .peer_addr()
                .map_or_else(|_| "?".into(), |a| a.to_string());
            match handle(stream, &allowed_origins, interface) {
                Ok(()) => eprintln!("ssids: {peer} disconnected"),
                Err(error) => eprintln!("ssids: {peer}: {error}"),
            }
        });
    }
    Ok(())
}

/// Whether a WebSocket handshake with this `Origin` header may proceed.
fn origin_allowed(origin: Option<&str>, allowed: &[String]) -> bool {
    origin.is_none_or(|origin| allowed.iter().any(|a| a == origin))
}

fn handle(
    stream: TcpStream,
    allowed_origins: &[String],
    interface: Option<String>,
) -> Result<(), Box<dyn Error>> {
    #[expect(
        clippy::result_large_err,
        reason = "the Err type is fixed by tungstenite's callback"
    )]
    let check_origin = |request: &Request, response: Response| {
        let origin = request
            .headers()
            .get("origin")
            .map(|o| o.to_str().unwrap_or("<invalid>"));
        if origin_allowed(origin, allowed_origins) {
            Ok(response)
        } else {
            let mut refusal =
                ErrorResponse::new(Some(format!("origin {} not allowed", origin.unwrap_or(""))));
            *refusal.status_mut() = StatusCode::FORBIDDEN;
            Err(refusal)
        }
    };
    // The handshake error borrows the origin check, so keep only its message.
    let mut socket =
        tungstenite::accept_hdr(stream, check_origin).map_err(|e| format!("handshake: {e}"))?;
    let mut scanner = Scanner::new(interface);
    let mut last_scan: Option<Instant> = None;
    loop {
        match socket.read()? {
            Message::Text(_) => {
                if let Some(last) = last_scan {
                    thread::sleep(MIN_SCAN_GAP.saturating_sub(last.elapsed()));
                }
                last_scan = Some(Instant::now());
                let reply = serde_json::to_string(&scanner.scan())?;
                socket.send(Message::text(reply))?;
            }
            Message::Close(_) => return Ok(()),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_browser_origins_and_native_clients_are_accepted() {
        let allowed = vec!["http://127.0.0.1:8080".to_owned()];
        assert!(origin_allowed(None, &allowed), "native client");
        assert!(origin_allowed(Some("http://127.0.0.1:8080"), &allowed));
        assert!(!origin_allowed(Some("https://evil.example"), &allowed));
        assert!(!origin_allowed(Some("http://127.0.0.1:8081"), &allowed));
        assert!(!origin_allowed(Some("<invalid>"), &allowed));
    }

    /// Full round trip through a real agent. The interface does not exist,
    /// so the test needs no Wi-Fi: the agent still answers, with an nl80211
    /// error, which proves the reply crossed the wire intact.
    #[test]
    fn agent_serves_remote_source_and_refuses_foreign_origins() {
        use ssids_adapter_remote::RemoteSource;
        use ssids_app::{ScanError, ScanSource};
        use tungstenite::client::IntoClientRequest;

        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
        let url = format!("ws://{}", listener.local_addr().expect("bound"));
        let allowed = vec!["http://allowed.test".to_owned()];
        thread::spawn(move || {
            let _ = serve(listener, Some("ssids-test-missing0".into()), allowed);
        });

        let mut source = RemoteSource::new(url.clone());
        source.request();
        let deadline = Instant::now() + Duration::from_secs(10);
        let reply = loop {
            if let Some(reply) = source.take() {
                break reply;
            }
            assert!(Instant::now() < deadline, "no reply from agent");
            thread::sleep(Duration::from_millis(20));
        };
        match reply {
            Err(ScanError(message)) => assert!(message.starts_with("nl80211:"), "{message}"),
            Ok(scan) => panic!("missing interface cannot scan: {scan:?}"),
        }

        let mut request = url.into_client_request().expect("valid url");
        let origin = "https://evil.example".parse().expect("valid header");
        request.headers_mut().insert("origin", origin);
        match tungstenite::connect(request) {
            Err(tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), StatusCode::FORBIDDEN)
            }
            other => panic!(
                "foreign origin must be refused, got {:?}",
                other.map(|_| ())
            ),
        }
    }
}
