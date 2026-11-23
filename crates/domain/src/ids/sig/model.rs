//! A Suricata rule as typed values: the header, the meta options, and the
//! options that match, in the lists (buffers) they inspect and the order the
//! rule writes them.

use super::int::IntMatch;
use crate::ids::entity::AddressMatch;

/// What a rule does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Alert,
    Pass,
    Drop,
    Reject,
    RejectSrc,
    RejectDst,
    RejectBoth,
}

impl Action {
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "alert" => Self::Alert,
            "pass" => Self::Pass,
            "drop" => Self::Drop,
            "reject" => Self::Reject,
            "rejectsrc" => Self::RejectSrc,
            "rejectdst" => Self::RejectDst,
            "rejectboth" => Self::RejectBoth,
            _ => return None,
        })
    }

    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Pass => "pass",
            Self::Drop => "drop",
            Self::Reject => "reject",
            Self::RejectSrc => "rejectsrc",
            Self::RejectDst => "rejectdst",
            Self::RejectBoth => "rejectboth",
        }
    }
}

/// The protocol a rule's header names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleProto {
    Ip,
    Ipv4,
    Ipv6,
    Tcp,
    /// TCP, inspected packet by packet only.
    TcpPkt,
    /// TCP, inspected on the reassembled stream only.
    TcpStream,
    Udp,
    Icmp,
    Icmpv4,
    Icmpv6,
    Sctp,
    /// An application-layer protocol, by its Suricata name.
    App(String),
}

/// The application-layer protocol names Suricata 8 accepts in a header and in
/// `app-layer-protocol`.
pub const APP_PROTOCOLS: &[&str] = &[
    "http",
    "http1",
    "http2",
    "ftp",
    "ftp-data",
    "smtp",
    "tls",
    "ssl",
    "ssh",
    "imap",
    "pop3",
    "smb",
    "dcerpc",
    "dns",
    "doh2",
    "modbus",
    "enip",
    "dnp3",
    "nfs",
    "ntp",
    "tftp",
    "ike",
    "krb5",
    "quic",
    "dhcp",
    "snmp",
    "sip",
    "rfb",
    "mqtt",
    "pgsql",
    "telnet",
    "websocket",
    "ldap",
    "rdp",
    "irc",
    "bittorrent-dht",
    "mdns",
    "llmnr",
    "pop3s",
    "failed",
    "unknown",
];

impl RuleProto {
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        let word = word.to_ascii_lowercase();
        Some(match word.as_str() {
            "ip" | "pkthdr" => Self::Ip,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "tcp" => Self::Tcp,
            "tcp-pkt" => Self::TcpPkt,
            "tcp-stream" => Self::TcpStream,
            "udp" => Self::Udp,
            "icmp" => Self::Icmp,
            "icmpv4" => Self::Icmpv4,
            "icmpv6" => Self::Icmpv6,
            "sctp" => Self::Sctp,
            other if APP_PROTOCOLS.contains(&other) && other != "failed" && other != "unknown" => {
                Self::App(other.to_string())
            }
            _ => return None,
        })
    }
}

/// `->` matches one way; `<>` both; `=>` a request and its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    OneWay,
    Both,
    Transactional,
}

/// A port set: any port, or ranges within and ranges outside.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortMatch {
    pub any: bool,
    pub within: Vec<(u16, u16)>,
    pub outside: Vec<(u16, u16)>,
}

impl PortMatch {
    #[must_use]
    pub fn matches(&self, port: u16) -> bool {
        let inside = |ranges: &[(u16, u16)]| ranges.iter().any(|(l, h)| (*l..=*h).contains(&port));
        (self.any || self.within.is_empty() || inside(&self.within)) && !inside(&self.outside)
    }

    /// The ports the set names explicitly, or `None` when it reaches every
    /// port or more than `limit`.
    #[must_use]
    pub fn listed(&self, limit: usize) -> Option<Vec<u16>> {
        if self.any || self.within.is_empty() || !self.outside.is_empty() {
            return None;
        }
        let mut ports = Vec::new();
        for (low, high) in &self.within {
            for port in *low..=*high {
                if ports.len() == limit {
                    return None;
                }
                ports.push(port);
            }
        }
        ports.sort_unstable();
        ports.dedup();
        Some(ports)
    }
}

/// The parsed header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub action: Action,
    pub proto: RuleProto,
    pub src: AddressMatch,
    pub src_ports: PortMatch,
    pub direction: Direction,
    pub dst: AddressMatch,
    pub dst_ports: PortMatch,
}

/// A number written in the rule, or the name of a `byte_extract` or
/// `byte_math` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Lit(i64),
    Var(String),
}

/// `fast_pattern` and its two arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastPattern {
    Whole,
    Only,
    Slice { offset: u16, length: u16 },
}

/// One `content` with its modifiers: each flag is a keyword of the rule.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Content {
    pub bytes: Vec<u8>,
    pub negated: bool,
    pub nocase: bool,
    pub offset: Option<Value>,
    pub depth: Option<Value>,
    pub distance: Option<Value>,
    pub within: Option<Value>,
    pub startswith: bool,
    pub endswith: bool,
    pub rawbytes: bool,
    pub fast_pattern: Option<FastPattern>,
}

impl Content {
    #[must_use]
    pub fn is_relative(&self) -> bool {
        self.distance.is_some() || self.within.is_some()
    }
    /// Whether any of offset, depth, distance or within is set.
    #[must_use]
    pub fn has_position(&self) -> bool {
        self.offset.is_some() || self.depth.is_some() || self.is_relative()
    }
}

/// Where a `pcre` capture is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub scope: String,
    pub name: String,
}

/// One `pcre`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcre {
    pub expression: String,
    /// The PCRE flags among `i s m x A E G O B`.
    pub flags: String,
    pub relative: bool,
    pub negated: bool,
    pub captures: Vec<Capture>,
}

/// Byte order, or DCE/RPC's, which follows the request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Endian {
    #[default]
    Big,
    Little,
    Dce,
}

/// The base of a number written as text in the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumBase {
    Hex,
    Dec,
    Oct,
}

/// How bytes are read into a number: the shared options of the `byte_*`
/// keywords.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ByteRead {
    pub endian: Endian,
    pub string: Option<NumBase>,
    pub relative: bool,
    pub bitmask: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteOp {
    Lt,
    Gt,
    Eq,
    Le,
    Ge,
    And,
    Xor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteTest {
    pub nbytes: Value,
    pub negated: bool,
    pub op: ByteOp,
    pub value: Value,
    pub offset: Value,
    pub read: ByteRead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteJump {
    pub nbytes: Value,
    pub offset: Value,
    pub read: ByteRead,
    pub multiplier: u32,
    pub align: bool,
    pub from_beginning: bool,
    pub from_end: bool,
    pub post_offset: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteExtract {
    pub nbytes: u8,
    pub offset: i64,
    pub name: String,
    pub read: ByteRead,
    pub multiplier: u32,
    pub align: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MathOp {
    Add,
    Sub,
    Mul,
    Div,
    Shl,
    Shr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteMath {
    pub nbytes: Value,
    pub offset: i64,
    pub oper: MathOp,
    pub rvalue: Value,
    pub result: String,
    pub read: ByteRead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsDataAt {
    pub negated: bool,
    pub at: Value,
    pub relative: bool,
    pub rawbytes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Base64Decode {
    pub bytes: Option<u32>,
    pub offset: u32,
    pub relative: bool,
}

/// A float comparison, for `entropy`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FloatMatch {
    pub op: super::int::IntOp,
    pub value: f64,
    pub high: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Entropy {
    pub bytes: Option<u32>,
    pub offset: i64,
    pub value: FloatMatch,
}

/// A buffer value looked up in a dataset or a reputation set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatasetMatch {
    pub keyword: String,
    pub command: String,
    pub name: String,
    pub options: Vec<(String, String)>,
}

/// A transform applied to a buffer before its matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub name: String,
    pub argument: Option<String>,
}

/// One match inside a buffer, in the rule's order.
#[derive(Debug, Clone, PartialEq)]
pub enum Match {
    Content(Content),
    Pcre(Pcre),
    IsDataAt(IsDataAt),
    Bsize(IntMatch),
    ByteTest(ByteTest),
    ByteJump(ByteJump),
    ByteExtract(ByteExtract),
    ByteMath(ByteMath),
    Entropy(Entropy),
    Base64Decode(Base64Decode),
    Asn1(Vec<(String, Option<i64>)>),
    Absent {
        or_else: bool,
    },
    Dataset(DatasetMatch),
    /// A keyword that compares the whole buffer, such as `filename`.
    Field {
        keyword: String,
        argument: String,
    },
}

/// The buffer a list inspects: the packet payload, or a sticky buffer by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Buffer {
    Payload,
    Base64Data,
    Sticky(&'static str),
}

/// One buffer's transforms and matches.
#[derive(Debug, Clone, PartialEq)]
pub struct BufferList {
    pub buffer: Buffer,
    pub transforms: Vec<Transform>,
    pub matches: Vec<Match>,
}

/// `flow` options, one flag per word the documentation lists.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowMatch {
    pub established: bool,
    pub not_established: bool,
    pub stateless: bool,
    pub to_server: bool,
    pub to_client: bool,
    pub only_stream: bool,
    pub no_stream: bool,
    pub only_frag: bool,
    pub no_frag: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOp {
    Set,
    Unset,
    Toggle,
    IsSet,
    IsNotSet,
}

/// Where a bit lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitScope {
    Flow,
    IpSrc,
    IpDst,
    IpPair,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bits {
    pub keyword: &'static str,
    pub op: BitOp,
    pub scope: BitScope,
    pub names: Vec<String>,
    /// `a|b` checks any; `a&b` checks all.
    pub any: bool,
    pub expire: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowintOp {
    Set,
    Add,
    Sub,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    IsSet,
    IsNotSet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flowint {
    pub name: String,
    pub op: FlowintOp,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSide {
    Server,
    Client,
    Both,
    Either,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    BySrc,
    ByDst,
    ByRule,
    ByBoth,
    ByFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdKind {
    Limit,
    Threshold,
    Both,
    Backoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub kind: ThresholdKind,
    pub track: Track,
    pub count: u32,
    pub seconds: u32,
    pub multiplier: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpFlagsMode {
    /// Exactly these flags (among those not ignored).
    Exact,
    /// These flags and any others.
    Plus,
    /// Any of these flags.
    Any,
    /// None of these flags.
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub flags: u8,
    pub mode: TcpFlagsMode,
    pub ignore: u8,
}

/// A packet header field compared as an integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderField {
    Dsize,
    Ttl,
    IpId,
    Tos,
    Seq,
    Ack,
    Window,
    TcpMss,
    TcpWscale,
    FragOffset,
    IpProto,
    Itype,
    Icode,
    IcmpId,
    IcmpSeq,
    Icmpv6Mtu,
    VlanId,
    VlanLayers,
    IgmpType,
    L3Proto,
}

/// A counter the flow keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowCounter {
    Age,
    Pkts,
    PktsToServer,
    PktsToClient,
    Bytes,
    BytesToServer,
    BytesToClient,
}

/// A condition on the packet or the flow, outside any buffer.
#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    Header(HeaderField, IntMatch),
    Flags(TcpFlags),
    FragBits {
        flags: u8,
        mode: TcpFlagsMode,
    },
    IpOpts(String),
    SameIp,
    Bits(Bits),
    Flowint(Flowint),
    /// `flowvar` or `pktvar`: a variable compared with bytes.
    Var {
        keyword: &'static str,
        name: String,
        bytes: Vec<u8>,
    },
    Counter(FlowCounter, IntMatch),
    StreamSize {
        side: StreamSide,
        value: IntMatch,
    },
    AppLayerProtocol {
        negated: bool,
        proto: String,
    },
    Event {
        keyword: &'static str,
        name: String,
        negated: bool,
    },
    /// An application field compared by its keyword's own syntax.
    Field {
        keyword: &'static str,
        argument: String,
    },
    Iprep {
        side: String,
        category: String,
        value: IntMatch,
    },
    Geoip {
        side: String,
        countries: Vec<String>,
        negated: bool,
    },
    Datarep(DatasetMatch),
    Elephant(String),
    Requires(Vec<(String, String)>),
}

/// `tag` options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub scope: String,
    pub count: u32,
    pub metric: String,
    pub direction: Option<String>,
}

/// One parsed rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub header: Header,
    pub sid: u32,
    pub rev: u32,
    pub gid: u32,
    pub msg: String,
    pub classtype: Option<String>,
    pub priority: Option<u8>,
    pub references: Vec<String>,
    pub metadata: Vec<String>,
    pub target: Option<String>,
    pub flow: FlowMatch,
    pub lists: Vec<BufferList>,
    pub checks: Vec<Check>,
    pub noalert: bool,
    pub threshold: Option<Threshold>,
    pub detection_filter: Option<Threshold>,
    pub tag: Option<Tag>,
    /// Every keyword the rule writes, lowercase, in order, for the import
    /// report.
    pub keywords: Vec<String>,
}

impl Signature {
    /// The payload list, when the rule matches the packet payload.
    #[must_use]
    pub fn payload(&self) -> Option<&BufferList> {
        self.lists.iter().find(|l| l.buffer == Buffer::Payload)
    }
}
