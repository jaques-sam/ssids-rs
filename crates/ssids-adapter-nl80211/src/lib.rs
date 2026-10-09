//! Linux scan backend speaking nl80211 over generic netlink.
//!
//! Reading the kernel's scan results needs no privileges. Triggering a fresh
//! scan needs `CAP_NET_ADMIN`; without it the backend still works but reports
//! its scans as passive (results cached from scans the system ran itself).
#![cfg(target_os = "linux")]

mod netlink;

use std::io;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ssids_app::{Scan, ScanError, ScanReply, ScanSource};
use ssids_domain::{Bssid, Observation};

use crate::netlink::{Attrs, GenlSocket, NLM_F_DUMP, attr};

const CMD_GET_INTERFACE: u8 = 5;
const CMD_GET_SCAN: u8 = 32;
const CMD_TRIGGER_SCAN: u8 = 33;

const ATTR_IFINDEX: u16 = 3;
const ATTR_IFNAME: u16 = 4;
const ATTR_BSS: u16 = 47;

const BSS_BSSID: u16 = 1;
const BSS_FREQUENCY: u16 = 2;
const BSS_CAPABILITY: u16 = 5;
const BSS_INFORMATION_ELEMENTS: u16 = 6;
const BSS_SIGNAL_MBM: u16 = 7;
const BSS_STATUS: u16 = 9;
const BSS_SEEN_MS_AGO: u16 = 10;
const BSS_BEACON_IES: u16 = 11;
const BSS_STATUS_ASSOCIATED: u32 = 1;

/// How often an interrupted dump (scan table changed meanwhile) is retried.
const DUMP_ATTEMPTS: usize = 3;

/// A wireless network interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub name: String,
}

/// A connection to the kernel's nl80211 family.
#[derive(Debug)]
pub struct Nl80211 {
    socket: GenlSocket,
    family: u16,
}

impl Nl80211 {
    pub fn connect() -> io::Result<Self> {
        let mut socket = GenlSocket::connect()?;
        let family = socket.resolve_family("nl80211")?;
        Ok(Self { socket, family })
    }

    /// Wireless interfaces that have a network device (skips P2P devices).
    pub fn interfaces(&mut self) -> io::Result<Vec<Interface>> {
        let replies = self
            .socket
            .request(self.family, CMD_GET_INTERFACE, NLM_F_DUMP, &[])?;
        let mut interfaces: Vec<Interface> = replies
            .iter()
            .filter_map(|blob| {
                let attrs = Attrs::new(blob);
                Some(Interface {
                    index: attrs.u32(ATTR_IFINDEX)?,
                    name: attrs.string(ATTR_IFNAME)?,
                })
            })
            .collect();
        interfaces.sort_by_key(|i| i.index);
        interfaces.dedup();
        Ok(interfaces)
    }

    /// The interface named `name`, or the first one when `None`.
    pub fn interface(&mut self, name: Option<&str>) -> io::Result<Interface> {
        let interfaces = self.interfaces()?;
        let found = match name {
            Some(name) => interfaces.into_iter().find(|i| i.name == name),
            None => interfaces.into_iter().next(),
        };
        found.ok_or_else(|| {
            let what = name.map_or("any wireless interface".into(), |n| {
                format!("wireless interface {n}")
            });
            io::Error::new(io::ErrorKind::NotFound, format!("no {what} found"))
        })
    }

    /// Asks the kernel to start a scan. Needs `CAP_NET_ADMIN`.
    pub fn trigger_scan(&mut self, interface: &Interface) -> io::Result<()> {
        let attrs = attr(ATTR_IFINDEX, &interface.index.to_ne_bytes());
        self.socket
            .request(self.family, CMD_TRIGGER_SCAN, 0, &attrs)
            .map(drop)
    }

    /// The kernel's current scan results. Needs no privileges.
    pub fn scan_results(&mut self, interface: &Interface) -> io::Result<Vec<Observation>> {
        let attrs = attr(ATTR_IFINDEX, &interface.index.to_ne_bytes());
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self
                .socket
                .request(self.family, CMD_GET_SCAN, NLM_F_DUMP, &attrs)
            {
                Ok(replies) => {
                    return Ok(replies.iter().filter_map(|blob| parse_bss(blob)).collect());
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted && attempt < DUMP_ATTEMPTS => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// One complete scan: trigger if permitted, optionally wait for the
    /// radio to sweep, then read the results. A refused trigger downgrades
    /// the scan to passive instead of failing it.
    pub fn scan(&mut self, interface: &Interface, settle: Duration) -> io::Result<Scan> {
        let passive_reason = match self.trigger_scan(interface) {
            Ok(()) => {
                thread::sleep(settle);
                None
            }
            // A scan is already running (ours or the system's): results are fresh anyway.
            Err(e) if e.kind() == io::ErrorKind::ResourceBusy => None,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Some(
                "showing results cached by the system: triggering scans needs CAP_NET_ADMIN \
                 (e.g. sudo setcap cap_net_admin+ep <binary>)"
                    .to_owned(),
            ),
            Err(e) => Some(format!(
                "showing cached results: could not trigger a scan: {e}"
            )),
        };
        Ok(Scan {
            observations: self.scan_results(interface)?,
            passive_reason,
        })
    }
}

/// Converts one GET_SCAN reply into an observation. `None` if the kernel
/// omitted the BSSID or frequency, without which a BSS cannot be placed.
fn parse_bss(blob: &[u8]) -> Option<Observation> {
    let bss = Attrs::new(Attrs::new(blob).get(ATTR_BSS)?);
    let bssid: [u8; 6] = *bss.get(BSS_BSSID)?.first_chunk()?;
    let ies = bss
        .get(BSS_INFORMATION_ELEMENTS)
        .or_else(|| bss.get(BSS_BEACON_IES));
    Some(Observation {
        bssid: Bssid(bssid),
        freq_mhz: bss.u32(BSS_FREQUENCY)?,
        signal_dbm: bss.i32(BSS_SIGNAL_MBM).map(|mbm| mbm as f32 / 100.0),
        seen_ms_ago: bss.u32(BSS_SEEN_MS_AGO),
        capability: bss.u16(BSS_CAPABILITY).unwrap_or(0),
        ies: ies.unwrap_or_default().to_vec(),
        associated: bss.u32(BSS_STATUS) == Some(BSS_STATUS_ASSOCIATED),
    })
}

/// [`ScanSource`] running nl80211 scans on a worker thread, so a slow
/// kernel round trip never blocks the UI.
#[derive(Debug)]
pub struct LiveSource {
    requests: mpsc::Sender<()>,
    replies: mpsc::Receiver<ScanReply>,
    in_flight: bool,
}

impl LiveSource {
    /// Scans `interface`, or the first wireless interface when `None`. The
    /// interface is looked up on every scan, so unplugging and replugging a
    /// USB adapter recovers by itself.
    pub fn spawn(interface: Option<String>) -> io::Result<Self> {
        let (requests, request_rx) = mpsc::channel::<()>();
        let (reply_tx, replies) = mpsc::channel();
        thread::Builder::new()
            .name("nl80211-scan".into())
            .spawn(move || {
                let mut connection = None;
                // Ends when the LiveSource (and with it the sender) is dropped.
                for () in request_rx {
                    let reply = scan_once(&mut connection, interface.as_deref());
                    if reply_tx.send(reply).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            requests,
            replies,
            in_flight: false,
        })
    }
}

/// One scan on a lazily (re)established connection. Results reflect the
/// sweep triggered by the previous request: waiting here would only delay
/// the reply, while the session asks again one interval later anyway.
fn scan_once(connection: &mut Option<Nl80211>, interface: Option<&str>) -> ScanReply {
    let result = (|| {
        let nl = match connection {
            Some(nl) => nl,
            None => connection.insert(Nl80211::connect()?),
        };
        let interface = nl.interface(interface)?;
        nl.scan(&interface, Duration::ZERO)
    })();
    result.map_err(|e| {
        *connection = None; // reconnect next time rather than reuse a broken socket
        ScanError(format!("nl80211: {e}"))
    })
}

impl ScanSource for LiveSource {
    fn request(&mut self) {
        if !self.in_flight {
            self.in_flight = self.requests.send(()).is_ok();
        }
    }

    fn take(&mut self) -> Option<ScanReply> {
        match self.replies.try_recv() {
            Ok(reply) => {
                self.in_flight = false;
                Some(reply)
            }
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.in_flight = false;
                Some(Err(ScanError("nl80211 worker thread stopped".into())))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bss_reply(fields: &[Vec<u8>]) -> Vec<u8> {
        attr(ATTR_BSS | 0x8000, &fields.concat())
    }

    #[test]
    fn parses_a_kernel_bss_record() {
        let blob = bss_reply(&[
            attr(BSS_BSSID, &[0x58, 0x04, 0x4f, 0xda, 0x89, 0x97]),
            attr(BSS_FREQUENCY, &5200u32.to_ne_bytes()),
            attr(BSS_CAPABILITY, &0x0011u16.to_ne_bytes()),
            attr(BSS_INFORMATION_ELEMENTS, &[0, 2, b'h', b'i']),
            attr(BSS_SIGNAL_MBM, &(-4300i32).to_ne_bytes()),
            attr(BSS_STATUS, &1u32.to_ne_bytes()),
            attr(BSS_SEEN_MS_AGO, &250u32.to_ne_bytes()),
        ]);
        let observation = parse_bss(&blob).expect("complete record");
        assert_eq!(observation.bssid.to_string(), "58:04:4f:da:89:97");
        assert_eq!(observation.freq_mhz, 5200);
        assert_eq!(observation.signal_dbm, Some(-43.0));
        assert_eq!(observation.seen_ms_ago, Some(250));
        assert_eq!(observation.capability, 0x0011);
        assert_eq!(observation.ies, [0, 2, b'h', b'i']);
        assert!(observation.associated);
    }

    #[test]
    fn falls_back_to_beacon_ies_and_tolerates_missing_optionals() {
        let blob = bss_reply(&[
            attr(BSS_BSSID, &[2, 0, 0, 0, 0, 1]),
            attr(BSS_FREQUENCY, &2412u32.to_ne_bytes()),
            attr(BSS_BEACON_IES, &[0, 0]),
        ]);
        let observation = parse_bss(&blob).expect("minimal record");
        assert_eq!(observation.ies, [0, 0]);
        assert_eq!(
            (observation.signal_dbm, observation.seen_ms_ago),
            (None, None)
        );
        assert!(!observation.associated);
    }

    #[test]
    fn records_without_bssid_or_frequency_are_dropped() {
        let no_freq = bss_reply(&[attr(BSS_BSSID, &[0; 6])]);
        assert_eq!(parse_bss(&no_freq), None);
        let short_bssid = bss_reply(&[
            attr(BSS_BSSID, &[0; 5]),
            attr(BSS_FREQUENCY, &2412u32.to_ne_bytes()),
        ]);
        assert_eq!(parse_bss(&short_bssid), None);
        assert_eq!(parse_bss(&[]), None);
    }

    /// Talks to the real kernel; run with `cargo test -- --ignored` on a
    /// machine with Wi-Fi.
    #[test]
    #[ignore = "needs a wireless interface"]
    fn dumps_real_scan_results() {
        let mut nl = Nl80211::connect().expect("nl80211 available");
        let interface = nl.interface(None).expect("a wireless interface");
        let scan = nl
            .scan(&interface, Duration::ZERO)
            .expect("dump works unprivileged");
        assert!(!scan.observations.is_empty(), "{scan:?}");
    }
}
