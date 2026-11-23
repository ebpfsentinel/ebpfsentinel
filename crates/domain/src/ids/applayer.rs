//! A flow's application protocol, found from its bytes the way Suricata 8
//! finds it rather than assumed from a port, and the packets it is said on.
//!
//! On TCP a side's bytes reach the application layer once the other side
//! acknowledges them, in order. The first bytes of each direction are
//! compared with the protocols' opening patterns: a request method or an
//! HTTP status line, a TLS record, an SSH banner, an SMTP greeting command,
//! an FTP command or, on port 21, a reply code. DNS is the one protocol
//! taken from the port, 53, over TCP and UDP alike. Bytes that are only the
//! start of a pattern wait for more.
//!
//! Once one direction names the protocol it is the flow's, and the other
//! direction takes it with its first bytes. A connection whose client sent
//! at least 16 bytes and whose server sent at least 10 without either
//! naming a protocol is `failed` from its first FIN or RST; one with less
//! stays unknown.
//!
//! Detection is announced on one packet per direction, which only
//! `app-layer-protocol` rules of nothing else alert on:
//!
//! - when the bytes that settle a direction arrive on a packet of that
//!   direction (a datagram, the FIN that fails a connection), on it;
//! - otherwise on the next packet that direction sends.
//!
//! A protocol whose parser asks for it has its side's stream inspected on
//! that side's next packet, without waiting for a chunk or a close: HTTP
//! once a message's header is whole, TLS, SSH, SMTP and DNS with each
//! piece of data. FTP does not ask.
//!
//! These rules are held to Suricata by
//! `tests/fixtures/suricata/applayer-verdicts.txt`.

use super::dns::{self, Dns};
use super::http1::{Http1, Ready};

/// An application protocol the agent finds, or the verdict that none was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppProto {
    Http,
    Tls,
    Ssh,
    Smtp,
    Ftp,
    Dns,
    /// Both directions spoke and neither named a protocol.
    Failed,
}

impl AppProto {
    /// The protocol a Suricata name stands for, `None` for a name the agent
    /// does not detect. `unknown` is not a protocol and is `None` too.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Some(match name {
            "http" | "http1" => Self::Http,
            "tls" | "ssl" => Self::Tls,
            "ssh" => Self::Ssh,
            "smtp" => Self::Smtp,
            "ftp" => Self::Ftp,
            "dns" => Self::Dns,
            "failed" => Self::Failed,
            _ => return None,
        })
    }

    /// Whether the protocol's parser has its side's stream inspected as
    /// data arrives.
    const fn triggers(self) -> bool {
        matches!(
            self,
            Self::Http | Self::Tls | Self::Ssh | Self::Smtp | Self::Dns
        )
    }
}

/// Bytes of the client a connection must have sent with no protocol named
/// before it can be `failed`.
const CLIENT_SEARCHED: u64 = 16;

/// The same for the server.
const SERVER_SEARCHED: u64 = 10;

/// The first bytes of a direction kept to compare with the patterns.
const HEAD: usize = 32;

/// Which directions a pattern is looked for in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Way {
    ToServer,
    ToClient,
    Both,
}

/// The opening bytes that name a protocol. Letters match in either case.
const PATTERNS: &[(Way, &[u8], AppProto)] = &[
    (Way::ToServer, b"GET ", AppProto::Http),
    (Way::ToServer, b"POST ", AppProto::Http),
    (Way::ToServer, b"HEAD ", AppProto::Http),
    (Way::ToServer, b"PUT ", AppProto::Http),
    (Way::ToServer, b"DELETE ", AppProto::Http),
    (Way::ToServer, b"OPTIONS ", AppProto::Http),
    (Way::ToServer, b"CONNECT ", AppProto::Http),
    (Way::ToServer, b"TRACE ", AppProto::Http),
    (Way::ToServer, b"PATCH ", AppProto::Http),
    (Way::ToServer, b"PROPFIND ", AppProto::Http),
    (Way::ToClient, b"HTTP/1.", AppProto::Http),
    (Way::Both, b"\x16\x03\x00", AppProto::Tls),
    (Way::Both, b"\x16\x03\x01", AppProto::Tls),
    (Way::Both, b"\x16\x03\x02", AppProto::Tls),
    (Way::Both, b"\x16\x03\x03", AppProto::Tls),
    (Way::Both, b"\x16\x03\x04", AppProto::Tls),
    (Way::Both, b"SSH-", AppProto::Ssh),
    (Way::ToServer, b"EHLO", AppProto::Smtp),
    (Way::ToServer, b"HELO", AppProto::Smtp),
    (Way::ToServer, b"USER ", AppProto::Ftp),
    (Way::ToServer, b"PASS ", AppProto::Ftp),
    (Way::ToServer, b"PORT ", AppProto::Ftp),
    (Way::ToServer, b"AUTH ", AppProto::Ftp),
    (Way::ToServer, b"FEAT", AppProto::Ftp),
];

/// What a direction's first bytes say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Found(AppProto),
    /// The bytes are the start of a pattern.
    Wait,
    None,
}

/// A UDP flow to port 53 is DNS when its first datagram parses as a DNS
/// message, and has failed when it does not, as Suricata's probe decides.
fn detect_datagram(udp: bool, server_port: u16, datagram: &[u8]) -> Option<Verdict> {
    (udp && server_port == 53).then(|| {
        if dns::parse(datagram).is_some() {
            Verdict::Found(AppProto::Dns)
        } else {
            Verdict::None
        }
    })
}

fn detect(side: usize, head: &[u8], server_port: u16, udp: bool) -> Verdict {
    if server_port == 53 {
        return Verdict::Found(AppProto::Dns);
    }
    if udp {
        return Verdict::None;
    }
    if side == 1 && server_port == 21 {
        match head.get(..3) {
            None => return Verdict::Wait,
            Some(code) if code.iter().all(u8::is_ascii_digit) => {
                return Verdict::Found(AppProto::Ftp);
            }
            Some(_) => {}
        }
    }
    let mut wait = false;
    for &(way, pattern, proto) in PATTERNS {
        let here = match way {
            Way::ToServer => side == 0,
            Way::ToClient => side == 1,
            Way::Both => true,
        };
        let n = head.len().min(pattern.len());
        if !here || !head[..n].eq_ignore_ascii_case(&pattern[..n]) {
            continue;
        }
        if n == pattern.len() {
            return Verdict::Found(proto);
        }
        wait = true;
    }
    if wait { Verdict::Wait } else { Verdict::None }
}

/// One direction of the flow, client first.
#[derive(Debug, Clone, Default)]
struct Direction {
    proto: Option<AppProto>,
    /// Bytes handed to the application layer.
    fed: u64,
    /// The first bytes, while the protocol is not named.
    head: Vec<u8>,
    /// Whether the next packet of this direction announces its detection.
    announce: bool,
    /// The last bytes seen, to find a message header's end across packets.
    tail: Vec<u8>,
    /// Every byte the direction sent while its protocol is not named, for
    /// the protocol's parser once it is.
    raw: Vec<u8>,
}

/// The most a direction holds while its protocol is not named.
const RAW_LIMIT: usize = 64 * 1024;

/// What the application layer knows of a flow.
#[derive(Debug, Clone)]
pub struct AppLayer {
    flow: Option<AppProto>,
    dirs: [Direction; 2],
    server_port: u16,
    udp: bool,
    closed: bool,
    /// The HTTP/1 parser, once the flow speaks it.
    http: Option<Box<Http1>>,
    /// The DNS parser, once the flow speaks it.
    dns: Option<Box<Dns>>,
}

/// What the application layer says of one packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppView {
    /// The flow's protocol, `None` while unknown.
    pub flow: Option<AppProto>,
    /// Each direction's protocol, client first.
    pub dirs: [Option<AppProto>; 2],
    /// Whether the packet announces its direction's detection.
    pub announced: bool,
}

/// What handing bytes to the application layer did.
#[derive(Debug, Clone, Default)]
pub struct Fed {
    /// The packet the bytes were handed on announces a detection.
    pub announced: bool,
    /// The direction's stream is to be inspected on its next packet.
    pub inspect: bool,
    /// The transaction sides the bytes completed.
    pub txs: Vec<Ready>,
}

impl AppLayer {
    /// A flow over UDP or TCP whose server listens on `server_port`.
    #[must_use]
    pub fn new(udp: bool, server_port: u16) -> Self {
        Self {
            flow: None,
            dirs: [Direction::default(), Direction::default()],
            server_port,
            udp,
            closed: false,
            http: None,
            dns: None,
        }
    }

    /// What the layer says of a packet of `side`, `announced` being whether
    /// the packet announces a detection.
    #[must_use]
    pub fn view(&self, announced: bool) -> AppView {
        AppView {
            flow: self.flow,
            dirs: [self.dirs[0].proto, self.dirs[1].proto],
            announced,
        }
    }

    /// Whether a packet of `side`, before its bytes are handed over,
    /// announces a detection made on an earlier packet.
    pub fn begin(&mut self, side: usize) -> bool {
        std::mem::take(&mut self.dirs[side].announce)
    }

    /// Settle `side` on `proto`, announced on the packet if it travels that
    /// way, else on the next one that does.
    fn settle(&mut self, side: usize, proto: AppProto, packet_side: usize) -> bool {
        let dir = &mut self.dirs[side];
        dir.proto = Some(proto);
        dir.head = Vec::new();
        if packet_side == side {
            true
        } else {
            dir.announce = true;
            false
        }
    }

    /// Hand the bytes `side` sent, in order, on a packet of `packet_side`.
    pub fn feed(&mut self, side: usize, bytes: &[u8], packet_side: usize) -> Fed {
        let mut fed = Fed::default();
        if bytes.is_empty() {
            return fed;
        }
        let dir = &mut self.dirs[side];
        dir.fed = dir.fed.saturating_add(bytes.len() as u64);
        let mut tail = std::mem::take(&mut dir.tail);
        tail.extend_from_slice(bytes);
        let known = dir.proto.is_some();
        if !known {
            let room = RAW_LIMIT.saturating_sub(dir.raw.len());
            dir.raw.extend_from_slice(&bytes[..bytes.len().min(room)]);
        }
        if dir.proto.is_none() {
            let room = HEAD.saturating_sub(dir.head.len());
            dir.head.extend_from_slice(&bytes[..bytes.len().min(room)]);
            let proto = match self.flow {
                Some(AppProto::Failed) => None,
                Some(known) => Some(known),
                None => {
                    match detect_datagram(self.udp, self.server_port, bytes).unwrap_or_else(|| {
                        detect(side, &self.dirs[side].head, self.server_port, self.udp)
                    }) {
                        Verdict::Found(found) => {
                            self.flow = Some(found);
                            let other = &mut self.dirs[1 - side];
                            if other.proto.is_none() && other.fed > 0 {
                                other.proto = Some(found);
                                other.head = Vec::new();
                                other.announce = true;
                            }
                            Some(found)
                        }
                        Verdict::Wait | Verdict::None if self.udp => {
                            self.flow.get_or_insert(AppProto::Failed);
                            Some(AppProto::Failed)
                        }
                        Verdict::Wait | Verdict::None => None,
                    }
                }
            };
            if let Some(proto) = proto {
                fed.announced = self.settle(side, proto, packet_side);
            }
        }
        if let Some(proto) = self.dirs[side].proto.filter(|p| p.triggers()) {
            fed.inspect = proto != AppProto::Http || tail.windows(4).any(|w| w == b"\r\n\r\n");
        }
        let keep = tail.len().saturating_sub(3);
        self.dirs[side].tail = tail.split_off(keep);
        if known {
            fed.txs = self.parse(side, bytes);
        }
        for d in 0..2 {
            if self.dirs[d].proto.is_some() && !self.dirs[d].raw.is_empty() {
                let raw = std::mem::take(&mut self.dirs[d].raw);
                fed.txs.extend(self.parse(d, &raw));
            }
        }
        fed
    }

    /// Hand a direction's bytes to its protocol's parser, if the agent has
    /// one for it.
    fn parse(&mut self, side: usize, bytes: &[u8]) -> Vec<Ready> {
        match self.dirs[side].proto {
            Some(AppProto::Http) => self.http.get_or_insert_with(Box::default).feed(side, bytes),
            Some(AppProto::Dns) => {
                let dns = self.dns.get_or_insert_with(Box::default);
                if self.udp {
                    dns.datagram(side, bytes)
                } else {
                    dns.stream(side, bytes)
                }
            }
            _ => Vec::new(),
        }
    }

    /// The connection ended: what each direction's parser still held to the
    /// close is complete.
    pub fn end(&mut self) -> Vec<Ready> {
        let Some(http) = self.http.as_mut() else {
            return Vec::new();
        };
        let mut txs = http.close(0);
        txs.extend(http.close(1));
        txs
    }

    /// A connection's first FIN or RST, sent by `side`: one whose two
    /// directions spoke enough without naming a protocol fails, announced on
    /// this packet and on the other direction's next.
    pub fn close(&mut self, side: usize) -> bool {
        if std::mem::replace(&mut self.closed, true) {
            return false;
        }
        if self.flow.is_some()
            || self.dirs[0].fed < CLIENT_SEARCHED
            || self.dirs[1].fed < SERVER_SEARCHED
        {
            return false;
        }
        self.flow = Some(AppProto::Failed);
        for dir in &mut self.dirs {
            dir.proto = Some(AppProto::Failed);
            dir.head = Vec::new();
            dir.raw = Vec::new();
        }
        self.dirs[1 - side].announce = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: usize = 0;
    const SERVER: usize = 1;

    #[test]
    fn patterns_name_the_protocol_whatever_the_port() {
        assert_eq!(
            detect(CLIENT, b"GET / HTTP/1.1", 8443, false),
            Verdict::Found(AppProto::Http)
        );
        assert_eq!(
            detect(SERVER, b"HTTP/1.1 200", 1, false),
            Verdict::Found(AppProto::Http)
        );
        assert_eq!(
            detect(CLIENT, b"\x16\x03\x01\x00", 80, false),
            Verdict::Found(AppProto::Tls)
        );
        assert_eq!(detect(CLIENT, b"GE", 80, false), Verdict::Wait);
        assert_eq!(detect(CLIENT, b"hello there", 80, false), Verdict::None);
        assert_eq!(
            detect(SERVER, b"220 ready", 21, false),
            Verdict::Found(AppProto::Ftp)
        );
        assert_eq!(detect(SERVER, b"220 ready", 2121, false), Verdict::None);
        assert_eq!(
            detect(CLIENT, b"\x12\x34", 53, true),
            Verdict::Found(AppProto::Dns)
        );
    }

    #[test]
    fn a_direction_settles_on_the_bytes_the_other_side_acknowledged() {
        let mut app = AppLayer::new(false, 80);
        let fed = app.feed(CLIENT, b"GET / HTTP/1.1\r\n\r\n", SERVER);
        assert!(!fed.announced && fed.inspect);
        assert!(app.begin(CLIENT));
        assert!(!app.begin(CLIENT));
        assert_eq!(app.view(false).flow, Some(AppProto::Http));
    }

    #[test]
    fn the_waiting_direction_takes_the_protocol_on_its_next_packet() {
        let mut app = AppLayer::new(false, 2121);
        app.feed(SERVER, b"220 FTP ready\r\n", CLIENT);
        assert_eq!(app.view(false).dirs[SERVER], None);
        app.feed(CLIENT, b"USER anonymous\r\n", SERVER);
        assert_eq!(app.view(false).dirs, [Some(AppProto::Ftp); 2]);
        assert!(app.begin(SERVER));
    }

    #[test]
    fn a_connection_fails_at_its_first_close_once_both_sides_spoke_enough() {
        let mut short = AppLayer::new(false, 81);
        short.feed(CLIENT, &[b'A'; 14], SERVER);
        short.feed(SERVER, &[b'B'; 10], CLIENT);
        assert!(!short.close(CLIENT));
        assert_eq!(short.view(false).flow, None);

        let mut app = AppLayer::new(false, 81);
        app.feed(CLIENT, &[b'A'; 16], SERVER);
        app.feed(SERVER, &[b'B'; 10], CLIENT);
        assert!(app.close(SERVER));
        assert_eq!(app.view(false).flow, Some(AppProto::Failed));
        assert!(app.begin(CLIENT));
        assert!(!app.close(CLIENT));
    }

    #[test]
    fn http_asks_for_inspection_once_a_header_is_whole() {
        let mut app = AppLayer::new(false, 80);
        assert!(
            !app.feed(CLIENT, b"GET / HTTP/1.1\r\nHost: a\r\n\r", SERVER)
                .inspect
        );
        assert!(app.feed(CLIENT, b"\n", SERVER).inspect);
        let mut ftp = AppLayer::new(false, 21);
        assert!(!ftp.feed(CLIENT, b"USER a\r\n", SERVER).inspect);
    }
}
