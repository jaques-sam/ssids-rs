//! The slice of generic netlink nl80211 needs: framing, attributes, and a
//! blocking request/reply exchange. Replies are kernel data, but parsing is
//! still total: malformed lengths end iteration instead of panicking.

use std::io;

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_GENERIC};

const NLMSG_HDR_LEN: usize = 16;
const GENL_HDR_LEN: usize = 4;
const NLA_HDR_LEN: usize = 4;
/// Attribute type bits; the top two are the nested / byte-order flags.
const NLA_TYPE_MASK: u16 = 0x3fff;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_DUMP: u16 = 0x0300;
/// Set by the kernel when the dumped table changed mid-dump.
const NLM_F_DUMP_INTR: u16 = 0x0010;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Encodes one attribute, padded to 4 bytes.
pub fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = NLA_HDR_LEN + payload.len();
    let mut out = Vec::with_capacity(align4(len));
    out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align4(len), 0);
    out
}

/// Iterator over `(type, payload)` attributes in a buffer.
#[derive(Clone, Debug)]
pub struct Attrs<'a>(&'a [u8]);

impl<'a> Attrs<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub fn get(&self, kind: u16) -> Option<&'a [u8]> {
        self.clone()
            .find(|&(k, _)| k == kind)
            .map(|(_, payload)| payload)
    }

    pub fn u16(&self, kind: u16) -> Option<u16> {
        self.get(kind)?
            .first_chunk()
            .map(|b| u16::from_ne_bytes(*b))
    }

    pub fn u32(&self, kind: u16) -> Option<u32> {
        self.get(kind)?
            .first_chunk()
            .map(|b| u32::from_ne_bytes(*b))
    }

    pub fn i32(&self, kind: u16) -> Option<i32> {
        self.get(kind)?
            .first_chunk()
            .map(|b| i32::from_ne_bytes(*b))
    }

    /// A NUL-terminated string attribute.
    pub fn string(&self, kind: u16) -> Option<String> {
        let bytes = self.get(kind)?;
        let bytes = bytes.split(|&b| b == 0).next().unwrap_or(bytes);
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let (header, _) = self.0.split_first_chunk::<NLA_HDR_LEN>()?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let kind = u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK;
        let Some(payload) = self.0.get(NLA_HDR_LEN..len) else {
            self.0 = &[];
            return None;
        };
        self.0 = self.0.get(align4(len)..).unwrap_or(&[]);
        Some((kind, payload))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    kind: u16,
    flags: u16,
    seq: u32,
}

/// Iterator over the netlink messages packed into one datagram.
struct Messages<'a>(&'a [u8]);

impl<'a> Iterator for Messages<'a> {
    type Item = (Header, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let (h, _) = self.0.split_first_chunk::<NLMSG_HDR_LEN>()?;
        let len = u32::from_ne_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let header = Header {
            kind: u16::from_ne_bytes([h[4], h[5]]),
            flags: u16::from_ne_bytes([h[6], h[7]]),
            seq: u32::from_ne_bytes([h[8], h[9], h[10], h[11]]),
        };
        let Some(payload) = self.0.get(NLMSG_HDR_LEN..len) else {
            self.0 = &[];
            return None;
        };
        self.0 = self.0.get(align4(len)..).unwrap_or(&[]);
        Some((header, payload))
    }
}

fn encode(family: u16, flags: u16, seq: u32, cmd: u8, attrs: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDR_LEN + GENL_HDR_LEN + attrs.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_ne_bytes());
    out.extend_from_slice(&family.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes()); // port id: let the kernel fill it in
    out.extend_from_slice(&[cmd, 1, 0, 0]); // genl: command, version, reserved
    out.extend_from_slice(attrs);
    out
}

/// What the kernel said about one request, given the messages so far.
#[derive(Debug)]
enum Progress {
    More,
    Done,
    Failed(io::Error),
}

/// Folds one reply message into `replies` (attribute blobs of data messages).
fn absorb(
    header: Header,
    payload: &[u8],
    replies: &mut Vec<Vec<u8>>,
    interrupted: &mut bool,
) -> Progress {
    *interrupted |= header.flags & NLM_F_DUMP_INTR != 0;
    let code = payload
        .first_chunk()
        .map(|b| i32::from_ne_bytes(*b))
        .unwrap_or(0);
    match header.kind {
        NLMSG_ERROR | NLMSG_DONE if code < 0 => {
            Progress::Failed(io::Error::from_raw_os_error(-code))
        }
        NLMSG_ERROR | NLMSG_DONE if *interrupted => {
            Progress::Failed(io::ErrorKind::Interrupted.into())
        }
        NLMSG_ERROR | NLMSG_DONE => Progress::Done,
        _ => {
            replies.push(payload.get(GENL_HDR_LEN..).unwrap_or_default().to_vec());
            Progress::More
        }
    }
}

/// A generic netlink socket used for one request at a time.
#[derive(Debug)]
pub struct GenlSocket {
    socket: Socket,
    seq: u32,
}

impl GenlSocket {
    pub fn connect() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_GENERIC)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self { socket, seq: 0 })
    }

    /// Sends a request and returns the attribute blob of every reply. Always
    /// asks for an ACK so a non-dump request has a definite end. A dump the
    /// kernel flags as interrupted fails with [`io::ErrorKind::Interrupted`].
    pub fn request(
        &mut self,
        family: u16,
        cmd: u8,
        flags: u16,
        attrs: &[u8],
    ) -> io::Result<Vec<Vec<u8>>> {
        self.seq = self.seq.wrapping_add(1);
        let message = encode(
            family,
            NLM_F_REQUEST | NLM_F_ACK | flags,
            self.seq,
            cmd,
            attrs,
        );
        self.socket.send(&message, 0)?;
        let mut replies = Vec::new();
        let mut interrupted = false;
        loop {
            let (datagram, _) = self.socket.recv_from_full()?;
            for (header, payload) in Messages(&datagram) {
                if header.seq != self.seq {
                    continue; // late reply to an earlier request
                }
                match absorb(header, payload, &mut replies, &mut interrupted) {
                    Progress::More => {}
                    Progress::Done => return Ok(replies),
                    Progress::Failed(error) => return Err(error),
                }
            }
        }
    }

    /// Looks up the numeric id of a generic netlink family such as "nl80211".
    pub fn resolve_family(&mut self, name: &str) -> io::Result<u16> {
        let mut name = name.as_bytes().to_vec();
        name.push(0);
        let replies = self.request(
            GENL_ID_CTRL,
            CTRL_CMD_GETFAMILY,
            0,
            &attr(CTRL_ATTR_FAMILY_NAME, &name),
        )?;
        replies
            .iter()
            .find_map(|blob| Attrs::new(blob).u16(CTRL_ATTR_FAMILY_ID))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "generic netlink family not found")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: u16, flags: u16) -> Header {
        Header {
            kind,
            flags,
            seq: 1,
        }
    }

    #[test]
    fn attribute_round_trip_with_padding() {
        let mut bytes = attr(4, b"wlan0\0");
        bytes.extend(attr(3, &7u32.to_ne_bytes()));
        assert_eq!(bytes.len(), 12 + 8, "6-byte payload padded to 8");
        let attrs = Attrs::new(&bytes);
        assert_eq!(attrs.string(4).as_deref(), Some("wlan0"));
        assert_eq!(attrs.u32(3), Some(7));
        assert_eq!(attrs.u32(9), None);
    }

    #[test]
    fn nested_flag_is_masked() {
        let bytes = attr(0x8000 | 47, &[]);
        assert_eq!(Attrs::new(&bytes).next(), Some((47, &[][..])));
    }

    #[test]
    fn malformed_attribute_lengths_end_iteration() {
        assert_eq!(
            Attrs::new(&[2, 0, 1, 0]).count(),
            0,
            "length shorter than header"
        );
        assert_eq!(
            Attrs::new(&[9, 0, 1, 0, 0]).count(),
            0,
            "length beyond buffer"
        );
        assert_eq!(Attrs::new(&[5, 0, 1, 0]).count(), 0);
        assert_eq!(Attrs::new(&[4, 0, 1]).count(), 0);
    }

    #[test]
    fn short_numeric_payload_is_none() {
        let bytes = attr(3, &[1, 2]);
        assert_eq!(Attrs::new(&bytes).u32(3), None);
    }

    #[test]
    fn messages_split_a_datagram() {
        let mut datagram = encode(30, 0, 1, 32, &attr(3, &1u32.to_ne_bytes()));
        datagram.extend(encode(NLMSG_DONE, 0, 1, 0, &[]));
        let kinds: Vec<u16> = Messages(&datagram).map(|(h, _)| h.kind).collect();
        assert_eq!(kinds, [30, NLMSG_DONE]);
        assert_eq!(Messages(&datagram[..10]).count(), 0);
    }

    #[test]
    fn absorb_collects_data_and_ends_on_done_or_ack() {
        let (mut replies, mut interrupted) = (Vec::new(), false);
        let data = [32, 1, 0, 0, 0xaa];
        assert!(matches!(
            absorb(header(30, 0), &data, &mut replies, &mut interrupted),
            Progress::More
        ));
        assert_eq!(replies, [vec![0xaa]]);
        assert!(matches!(
            absorb(
                header(NLMSG_DONE, 0),
                &[0; 4],
                &mut replies,
                &mut interrupted
            ),
            Progress::Done
        ));
        assert!(matches!(
            absorb(
                header(NLMSG_ERROR, 0),
                &[0; 20],
                &mut replies,
                &mut interrupted
            ),
            Progress::Done
        ));
    }

    #[test]
    fn absorb_maps_kernel_errors() {
        let (mut replies, mut interrupted) = (Vec::new(), false);
        let eperm = (-1i32).to_ne_bytes();
        let Progress::Failed(error) = absorb(
            header(NLMSG_ERROR, 0),
            &eperm,
            &mut replies,
            &mut interrupted,
        ) else {
            panic!("EPERM must fail");
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn interrupted_dump_fails_so_it_can_be_retried() {
        let (mut replies, mut interrupted) = (Vec::new(), false);
        absorb(
            header(30, NLM_F_DUMP_INTR),
            &[32, 1, 0, 0],
            &mut replies,
            &mut interrupted,
        );
        let Progress::Failed(error) = absorb(
            header(NLMSG_DONE, 0),
            &[0; 4],
            &mut replies,
            &mut interrupted,
        ) else {
            panic!("interrupted dump must fail");
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    }
}
