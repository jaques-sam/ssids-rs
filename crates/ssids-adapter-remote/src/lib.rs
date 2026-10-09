//! A [`ScanSource`] fed by an `ssids serve` agent over WebSocket.
//!
//! This is how the browser build shows live data: the page cannot touch
//! the radio, but a native agent on the same machine can. Protocol: the
//! client sends any text message to request a scan; the agent answers each
//! with one JSON-encoded [`ScanReply`].

use std::fmt;

use ewebsock::{Options, WsEvent, WsMessage, WsReceiver, WsSender};
use ssids_app::{ScanError, ScanReply, ScanSource};

/// The text the client sends to request a scan. Agents accept any text;
/// a fixed word just makes traffic readable.
pub const SCAN_REQUEST: &str = "scan";

pub struct RemoteSource {
    url: String,
    connection: Option<Connection>,
    in_flight: bool,
    /// A failure detected in `request`, reported by the next `take`.
    pending_error: Option<ScanError>,
}

struct Connection {
    sender: WsSender,
    receiver: WsReceiver,
    open: bool,
}

impl fmt::Debug for RemoteSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSource")
            .field("url", &self.url)
            .field(
                "connected",
                &self.connection.as_ref().is_some_and(|c| c.open),
            )
            .field("in_flight", &self.in_flight)
            .finish()
    }
}

impl RemoteSource {
    /// Connects lazily: the first `request` opens the socket, and a dropped
    /// connection is re-opened on the next request.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            connection: None,
            in_flight: false,
            pending_error: None,
        }
    }

    /// Drops the connection (the next request reconnects) and reports why.
    fn fail(&mut self, message: impl fmt::Display) -> ScanError {
        self.connection = None;
        self.in_flight = false;
        ScanError(format!("agent {}: {message}", self.url))
    }
}

impl ScanSource for RemoteSource {
    fn request(&mut self) {
        match &mut self.connection {
            None => match ewebsock::connect(&self.url, Options::default()) {
                Ok((sender, receiver)) => {
                    self.connection = Some(Connection {
                        sender,
                        receiver,
                        open: false,
                    });
                    self.in_flight = true; // sent as soon as the socket opens
                }
                Err(error) => self.pending_error = Some(self.fail(error)),
            },
            Some(connection) if connection.open && !self.in_flight => {
                connection.sender.send(WsMessage::Text(SCAN_REQUEST.into()));
                self.in_flight = true;
            }
            Some(_) => {}
        }
    }

    fn take(&mut self) -> Option<ScanReply> {
        if let Some(error) = self.pending_error.take() {
            return Some(Err(error));
        }
        loop {
            let event = self.connection.as_ref()?.receiver.try_recv()?;
            match event {
                WsEvent::Opened => {
                    if let Some(connection) = &mut self.connection {
                        connection.open = true;
                        connection.sender.send(WsMessage::Text(SCAN_REQUEST.into()));
                    }
                }
                WsEvent::Message(WsMessage::Text(json)) => {
                    self.in_flight = false;
                    return Some(
                        serde_json::from_str::<ScanReply>(&json)
                            .map_err(|error| self.fail(format!("unreadable reply: {error}")))
                            .and_then(|reply| reply),
                    );
                }
                WsEvent::Message(_) => {}
                WsEvent::Error(error) => return Some(Err(self.fail(error))),
                WsEvent::Closed => return Some(Err(self.fail("connection closed"))),
            }
        }
    }
}
