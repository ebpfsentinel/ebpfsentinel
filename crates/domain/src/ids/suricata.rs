//! Suricata rules, compiled into native IDS rules or refused in writing.
//!
//! A ruleset written for Suricata is compiled one rule at a time. A rule whose
//! every keyword falls inside the subset below becomes one native rule per
//! port it names; any other rule is refused, and the refusal names the
//! keyword that stopped it and why. Nothing is approximated: a rule either
//! means here what it means in Suricata, or it does not load.
//!
//! The subset is what the agent can decide on a captured TCP payload: the
//! header (addresses, one side's ports, direction), contents with their
//! position modifiers, `pcre` without buffer flags, and `threshold`. What
//! needs state across packets, a reassembled application-layer buffer or a
//! decoded protocol field is outside it.
//!
//! The compiler is a pure function of the rule text and the variables it is
//! given, so it is fuzzed and tested against real rules without an agent.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::entity::{
    AddressMatch, IdsRule, ImportedRule, Inspection, ThresholdConfig, ThresholdType, TrackBy,
};
use crate::common::entity::{DomainMode, Protocol, RuleId, Severity};
use crate::firewall::entity::IpNetwork;

/// The most ports one rule may name. Each port is a native rule of its own,
/// because the classifier keys on one port, so a range would multiply into
/// thousands of rules nobody wrote.
pub const MAX_PORTS_PER_RULE: usize = 16;

/// How deep one variable may refer to another before the chain is refused.
pub(crate) const MAX_VARIABLE_DEPTH: usize = 8;

// ── Keyword table ────────────────────────────────────────────────

/// What the compiler does with a keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    /// The keyword is compiled and means here what it means in Suricata.
    Compiled,
    /// The keyword is accepted and changes nothing, because the agent
    /// already behaves the way it asks for.
    Accepted,
    /// The keyword is parsed and its arguments checked, and a rule carrying
    /// it is refused until the engine inspects what it asks for.
    Pending,
    /// The keyword is out of scope: a rule carrying it is refused.
    Refused,
}

/// One row of the published keyword table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeywordSupport {
    pub keyword: &'static str,
    pub support: Support,
    pub note: &'static str,
}

/// Every keyword the compiler names, with what it does with it. A keyword
/// absent from this table is refused as outside the compiled subset. The
/// documentation's keyword table is generated from this list.
pub const KEYWORDS: &[KeywordSupport] = &[
    KeywordSupport {
        keyword: "msg",
        support: Support::Compiled,
        note: "Becomes the rule description.",
    },
    KeywordSupport {
        keyword: "sid",
        support: Support::Compiled,
        note: "Required. Names the rule `suricata-<sid>`, with `-<port>` when it names several ports.",
    },
    KeywordSupport {
        keyword: "rev",
        support: Support::Compiled,
        note: "Kept with the rule.",
    },
    KeywordSupport {
        keyword: "gid",
        support: Support::Compiled,
        note: "Only generator 1, the rule engine's own.",
    },
    KeywordSupport {
        keyword: "classtype",
        support: Support::Compiled,
        note: "Kept with the rule, and sets the severity from the stock classification priorities.",
    },
    KeywordSupport {
        keyword: "priority",
        support: Support::Compiled,
        note: "Sets the severity: 1 is high, 2 medium, 3 and above low.",
    },
    KeywordSupport {
        keyword: "reference",
        support: Support::Compiled,
        note: "Kept with the rule.",
    },
    KeywordSupport {
        keyword: "metadata",
        support: Support::Accepted,
        note: "Read and not kept.",
    },
    KeywordSupport {
        keyword: "target",
        support: Support::Accepted,
        note: "Read and not kept.",
    },
    KeywordSupport {
        keyword: "flow",
        support: Support::Compiled,
        note: "`established`, `stateless` and the four direction words. A payload is only captured on an established connection, and direction is already the header's port side.",
    },
    KeywordSupport {
        keyword: "content",
        support: Support::Compiled,
        note: "Literal and `|hex|` bytes, negated with `!`. A match moves the cursor to its end, and when a later match fails the engine tries the next occurrence, as Suricata does.",
    },
    KeywordSupport {
        keyword: "nocase",
        support: Support::Compiled,
        note: "ASCII case-insensitive match of the content before it.",
    },
    KeywordSupport {
        keyword: "offset",
        support: Support::Compiled,
        note: "From the start of the buffer.",
    },
    KeywordSupport {
        keyword: "depth",
        support: Support::Compiled,
        note: "Counted from `offset`, as Suricata counts it.",
    },
    KeywordSupport {
        keyword: "distance",
        support: Support::Compiled,
        note: "From the cursor the previous content or pcre left, negative included.",
    },
    KeywordSupport {
        keyword: "within",
        support: Support::Compiled,
        note: "From the cursor the previous content or pcre left. A window shorter than the content is refused, as Suricata refuses it.",
    },
    KeywordSupport {
        keyword: "startswith",
        support: Support::Compiled,
        note: "Anchors the content to the start of the buffer.",
    },
    KeywordSupport {
        keyword: "endswith",
        support: Support::Compiled,
        note: "Anchors the content to the end of the buffer.",
    },
    KeywordSupport {
        keyword: "fast_pattern",
        support: Support::Compiled,
        note: "Names the content the prefilter looks for, `chop` naming a slice of it; without it the longest content of the payload is the one. A payload without that content runs no more of the rule, and the rule is then matched in full.",
    },
    KeywordSupport {
        keyword: "rawbytes",
        support: Support::Accepted,
        note: "The payload is already matched as raw bytes.",
    },
    KeywordSupport {
        keyword: "pkt_data",
        support: Support::Accepted,
        note: "The payload is the only buffer there is.",
    },
    KeywordSupport {
        keyword: "pcre",
        support: Support::Compiled,
        note: "PCRE2, on bytes. Flags `i`, `s`, `m`, `x`, `A`, `E`, `G` and `R`, and the buffer flags of the buffers the engine inspects; lookarounds and back-references run as Suricata runs them.",
    },
    KeywordSupport {
        keyword: "threshold",
        support: Support::Compiled,
        note: "Types `limit`, `threshold` and `both`, tracked by source, destination or both.",
    },
    KeywordSupport {
        keyword: "requires",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the requirements it states are checked against the engine.",
    },
    KeywordSupport {
        keyword: "isdataat",
        support: Support::Compiled,
        note: "Absolute or relative to the cursor, negated with `!`.",
    },
    KeywordSupport {
        keyword: "bsize",
        support: Support::Compiled,
        note: "The length of the buffer it follows.",
    },
    KeywordSupport {
        keyword: "dsize",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "byte_test",
        support: Support::Compiled,
        note: "Every operator, string and binary reads, endianness, `dce` read little-endian, bitmask, relative.",
    },
    KeywordSupport {
        keyword: "byte_jump",
        support: Support::Compiled,
        note: "Every option: multiplier, align, from_beginning, from_end, post_offset, relative, bitmask.",
    },
    KeywordSupport {
        keyword: "byte_extract",
        support: Support::Compiled,
        note: "Sets a variable that a later offset, depth, distance, within, isdataat or byte keyword reads. A variable read before it is set refuses the rule.",
    },
    KeywordSupport {
        keyword: "byte_math",
        support: Support::Compiled,
        note: "Every operator; a division by zero does not match. Sets a variable as byte_extract does.",
    },
    KeywordSupport {
        keyword: "entropy",
        support: Support::Compiled,
        note: "Shannon entropy in bits per byte over the bytes named; a window past the buffer does not match.",
    },
    KeywordSupport {
        keyword: "absent",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the inspection engine evaluates it.",
    },
    KeywordSupport {
        keyword: "base64_decode",
        support: Support::Compiled,
        note: "Decodes from the start of the buffer or from the cursor, padding optional.",
    },
    KeywordSupport {
        keyword: "base64_data",
        support: Support::Compiled,
        note: "Inspects what the last base64_decode produced.",
    },
    KeywordSupport {
        keyword: "asn1",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the inspection engine evaluates it.",
    },
    KeywordSupport {
        keyword: "urilen",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "uricontent",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "flowbits",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "xbits",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "hostbits",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flowint",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flowvar",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "pktvar",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "noalert",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "detection_filter",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flow.age",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flow.pkts",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flow.pkts_toserver",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flow.pkts_toclient",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flow.bytes",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flow.bytes_toserver",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flow.bytes_toclient",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "flow.elephant",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the flow table keeps the state it reads.",
    },
    KeywordSupport {
        keyword: "stream_size",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until TCP is reassembled by sequence number.",
    },
    KeywordSupport {
        keyword: "tcp.session",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until TCP is reassembled by sequence number.",
    },
    KeywordSupport {
        keyword: "dataset",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the datasets the configuration names are loaded.",
    },
    KeywordSupport {
        keyword: "datarep",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the datasets the configuration names are loaded.",
    },
    KeywordSupport {
        keyword: "iprep",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the reputation lists the configuration names are loaded.",
    },
    KeywordSupport {
        keyword: "geoip",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the GeoIP database answers it.",
    },
    KeywordSupport {
        keyword: "flags",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "tcp.flags",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "seq",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "tcp.seq",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "ack",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "tcp.ack",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "window",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "tcp.window",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "tcp.mss",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "tcp.wscale",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "ttl",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "id",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "tos",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "ipopts",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "fragbits",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "fragoffset",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "sameip",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "ip_proto",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "l3_proto",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "itype",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "icode",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "icmp_id",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "icmp_seq",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "icmpv6.mtu",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "vlan.id",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "vlan.layers",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "igmp.type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "decode-event",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the engine reports the events it names.",
    },
    KeywordSupport {
        keyword: "stream-event",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the engine reports the events it names.",
    },
    KeywordSupport {
        keyword: "engine-event",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the engine reports the events it names.",
    },
    KeywordSupport {
        keyword: "app-layer-event",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the engine reports the events it names.",
    },
    KeywordSupport {
        keyword: "app-layer-protocol",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the application protocol is detected from the traffic.",
    },
    KeywordSupport {
        keyword: "app-layer-state",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the application protocol is detected from the traffic.",
    },
    KeywordSupport {
        keyword: "ftpbounce",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "filename",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "fileext",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "filemd5",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "filesha1",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "filesha256",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "filesize",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "to_lowercase",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "to_uppercase",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "to_md5",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "to_sha1",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "to_sha256",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "strip_whitespace",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "compress_whitespace",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "url_decode",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "header_lowercase",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "pcrexform",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "from_base64",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "dotprefix",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "strip_pseudo_headers",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "xor",
        support: Support::Compiled,
        note: "Runs in the inspection engine on the buffer it follows, as Suricata 8 transforms it; a rule loads once that buffer is inspected.",
    },
    KeywordSupport {
        keyword: "gunzip",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until transforms run on a buffer.",
    },
    KeywordSupport {
        keyword: "zlib_deflate",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until transforms run on a buffer.",
    },
    KeywordSupport {
        keyword: "domain",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until transforms run on a buffer.",
    },
    KeywordSupport {
        keyword: "tld",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until transforms run on a buffer.",
    },
    KeywordSupport {
        keyword: "file.data",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "file_data",
        support: Support::Pending,
        note: "The older name of `file.data`. Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "file.name",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until files are extracted from the protocols that carry them.",
    },
    KeywordSupport {
        keyword: "http.uri",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.uri.normalized",
        support: Support::Pending,
        note: "The older name of `http.uri`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_uri",
        support: Support::Pending,
        note: "Moves the content before it into `http.uri`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.uri.raw",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_raw_uri",
        support: Support::Pending,
        note: "Moves the content before it into `http.uri.raw`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.method",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_method",
        support: Support::Pending,
        note: "Moves the content before it into `http.method`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.request_line",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_request_line",
        support: Support::Pending,
        note: "The older name of `http.request_line`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.request_body",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_client_body",
        support: Support::Pending,
        note: "Moves the content before it into `http.request_body`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.header",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_header",
        support: Support::Pending,
        note: "Moves the content before it into `http.header`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.header.raw",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_raw_header",
        support: Support::Pending,
        note: "Moves the content before it into `http.header.raw`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.cookie",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_cookie",
        support: Support::Pending,
        note: "Moves the content before it into `http.cookie`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.user_agent",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_user_agent",
        support: Support::Pending,
        note: "Moves the content before it into `http.user_agent`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.host",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_host",
        support: Support::Pending,
        note: "Moves the content before it into `http.host`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.host.raw",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_raw_host",
        support: Support::Pending,
        note: "Moves the content before it into `http.host.raw`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.accept",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_accept",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.accept_enc",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_accept_enc",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.accept_lang",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_accept_lang",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.referer",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_referer",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.connection",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_connection",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.content_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_content_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.content_len",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_content_len",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.start",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_start",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.protocol",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_protocol",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.header_names",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_header_names",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.request_header",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.response_header",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.stat_code",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_stat_code",
        support: Support::Pending,
        note: "Moves the content before it into `http.stat_code`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.stat_msg",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_stat_msg",
        support: Support::Pending,
        note: "Moves the content before it into `http.stat_msg`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.response_line",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_response_line",
        support: Support::Pending,
        note: "The older name of `http.response_line`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.response_body",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http_server_body",
        support: Support::Pending,
        note: "Moves the content before it into `http.response_body`. Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.server",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http.location",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the HTTP/1 parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http2.header_name",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until an HTTP/2 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dns.query",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "dns_query",
        support: Support::Pending,
        note: "The older name of `dns.query`. Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "dns.queries.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "dns.answers.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "dns.authorities.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "dns.additionals.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "dns.response.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mdns.queries.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for mDNS.",
    },
    KeywordSupport {
        keyword: "mdns.answers.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for mDNS.",
    },
    KeywordSupport {
        keyword: "mdns.authorities.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for mDNS.",
    },
    KeywordSupport {
        keyword: "mdns.additionals.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for mDNS.",
    },
    KeywordSupport {
        keyword: "mdns.response.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for mDNS.",
    },
    KeywordSupport {
        keyword: "llmnr.queries.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for LLMNR.",
    },
    KeywordSupport {
        keyword: "llmnr.answers.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for LLMNR.",
    },
    KeywordSupport {
        keyword: "llmnr.authorities.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for LLMNR.",
    },
    KeywordSupport {
        keyword: "llmnr.additionals.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for LLMNR.",
    },
    KeywordSupport {
        keyword: "llmnr.response.rrname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers for LLMNR.",
    },
    KeywordSupport {
        keyword: "tls.sni",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_sni",
        support: Support::Pending,
        note: "The older name of `tls.sni`. Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.cert_subject",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_cert_subject",
        support: Support::Pending,
        note: "The older name of `tls.cert_subject`. Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.cert_issuer",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_cert_issuer",
        support: Support::Pending,
        note: "The older name of `tls.cert_issuer`. Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.cert_serial",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_cert_serial",
        support: Support::Pending,
        note: "The older name of `tls.cert_serial`. Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.cert_fingerprint",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_cert_fingerprint",
        support: Support::Pending,
        note: "The older name of `tls.cert_fingerprint`. Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.certs",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.subjectaltname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.alpn",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.random",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.random_time",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.random_bytes",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ja3.hash",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ja3_hash",
        support: Support::Pending,
        note: "The older name of `ja3.hash`. Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ja3.string",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ja3_string",
        support: Support::Pending,
        note: "The older name of `ja3.string`. Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ja3s.hash",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ja3s.string",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ja4.hash",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ja4_hash",
        support: Support::Pending,
        note: "The older name of `ja4.hash`. Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh.proto",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh_proto",
        support: Support::Pending,
        note: "The older name of `ssh.proto`. Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh.software",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh_software",
        support: Support::Pending,
        note: "The older name of `ssh.software`. Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh.hassh",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh.hassh.string",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh.hassh.server",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh.hassh.server.string",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ftp.command",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ftp.command_data",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ftp.completion_code",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ftp.reply",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "smtp.helo",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "smtp.mail_from",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "smtp.rcpt_to",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.from",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.to",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.cc",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.subject",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.date",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.message_id",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.x_mailer",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.url",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.received",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "email.body_md5",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "smb.named_pipe",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "smb_named_pipe",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "smb.share",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "smb_share",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "smb.ntlmssp_user",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "smb.ntlmssp_domain",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "dcerpc.stub_data",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "dce_stub_data",
        support: Support::Pending,
        note: "The older name of `dcerpc.stub_data`. Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "krb5_cname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the Kerberos parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "krb5_sname",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the Kerberos parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "snmp.community",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SNMP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "snmp.usm",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SNMP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "snmp.trap_oid",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SNMP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "snmp.trap_address",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SNMP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.method",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.uri",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.request_line",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.stat_code",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.stat_msg",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.response_line",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.protocol",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.from",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.to",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.via",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.user_agent",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.content_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "sip.content_length",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SIP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "quic.sni",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the QUIC parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "quic.ua",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the QUIC parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "quic.version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the QUIC parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "quic.cyu.hash",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the QUIC parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "quic.cyu.string",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the QUIC parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.connect.clientid",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.connect.username",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.connect.password",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.connect.willtopic",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.connect.willmessage",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.connect.protocol_string",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.publish.topic",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.publish.message",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.subscribe.topic",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.unsubscribe.topic",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.request.dn",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.request.attribute_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.responses.dn",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.responses.message",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.responses.attribute_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.bind_request.sasl.mechanism",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.bind_request.sasl.credentials",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ike.vendor",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a IKE parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ike.key_exchange_payload",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a IKE parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ike.nonce_payload",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a IKE parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "pgsql.query",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a PostgreSQL parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "rfb.name",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a RFB parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "websocket.payload",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a WebSocket parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dnp3_data",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DNP3 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dnp3.data",
        support: Support::Pending,
        note: "The older name of `dnp3_data`. Parsed and checked; a rule carrying it is refused until a DNP3 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "enip.product_name",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a ENIP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "enip.service_name",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a ENIP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ntp.reference_id",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a NTP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.origin",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.session_name",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.session_info",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.uri",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.email",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.phone_number",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.connection_data",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.bandwidth",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.time",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.repeat_time",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.timezone",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.encryption_key",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.attribute",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.media.media",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.media.session_info",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.media.connection_data",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sdp.media.encryption_key",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a SDP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ipv4.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "ipv6.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "tcp.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "udp.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "icmpv4.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "icmpv6.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "sctp.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "igmp.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "ether.hdr",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "dns.opcode",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "dns.rcode",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "dns.rrtype",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the DNS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssl_version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssl_state",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.cert_chain_len",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_cert_expired",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_cert_valid",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_cert_notbefore",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls_cert_notafter",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.fingerprint",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.subject",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "tls.issuerdn",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the TLS parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh.protoversion",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ssh.softwareversion",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SSH parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "http2.frametype",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until an HTTP/2 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "http2.errorcode",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until an HTTP/2 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "http2.priority",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until an HTTP/2 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "http2.window",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until an HTTP/2 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "http2.size_update",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until an HTTP/2 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "http2.settings",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until an HTTP/2 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dcerpc.iface",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "dcerpc.opnum",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "smb.version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SMB and DCE/RPC parsers expose their buffers.",
    },
    KeywordSupport {
        keyword: "krb5_err_code",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the Kerberos parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "krb5_msg_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the Kerberos parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "krb5.ticket_encryption",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the Kerberos parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "krb5.weak_encryption",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the Kerberos parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "snmp.version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SNMP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "snmp.pdu_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the SNMP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ftp.dynamic_port",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ftp.mode",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ftp.reply_received",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ftpdata_command",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the FTP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.flags",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.qos",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.protocol_version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.reason_code",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.connack.session_present",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "mqtt.connect.flags",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the MQTT parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.request.operation",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.responses.operation",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.responses.count",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.responses.result_code",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.bind_request.authentication",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "ldap.bind_request.version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the LDAP parser exposes its buffers.",
    },
    KeywordSupport {
        keyword: "modbus",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a Modbus parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dnp3_func",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DNP3 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dnp3.func",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DNP3 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dnp3_ind",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DNP3 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dnp3.ind",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DNP3 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dnp3_obj",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DNP3 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dnp3.obj",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DNP3 parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "enip_command",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a ENIP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "cip_service",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a ENIP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "enip.status",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a ENIP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "enip.vendor_id",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a ENIP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "enip.product_code",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a ENIP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "enip.device_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a ENIP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "nfs_procedure",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a NFS parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "nfs.version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a NFS parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "rpc",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a RPC parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ntp.mode",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a NTP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ntp.stratum",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a NTP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ntp.version",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a NTP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "rfb.secresult",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a RFB parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "rfb.sectype",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a RFB parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ike.exchtype",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a IKE parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ike.chosen_sa_attribute",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a IKE parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ike.key_exchange_payload_length",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a IKE parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "ike.nonce_payload_length",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a IKE parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "websocket.flags",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a WebSocket parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "websocket.mask",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a WebSocket parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "websocket.opcode",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a WebSocket parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dhcp.leasetime",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DHCP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dhcp.rebinding_time",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DHCP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "dhcp.renewal_time",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until a DHCP parser exposes its fields.",
    },
    KeywordSupport {
        keyword: "sctp.chunk_type",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "sctp.vtag",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "sctp.chunk_cnt",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the kernel hands over the packet header it reads.",
    },
    KeywordSupport {
        keyword: "frame",
        support: Support::Pending,
        note: "Parsed and checked; a rule carrying it is refused until the application protocol is detected from the traffic.",
    },
    KeywordSupport {
        keyword: "tag",
        support: Support::Accepted,
        note: "Packets after the alert are not logged; the alert itself is raised.",
    },
    KeywordSupport {
        keyword: "prefilter",
        support: Support::Accepted,
        note: "A prefilter hint; the engine chooses its own prefilter.",
    },
    KeywordSupport {
        keyword: "lua",
        support: Support::Refused,
        note: "Runs a Lua script; the agent embeds no interpreter.",
    },
    KeywordSupport {
        keyword: "luajit",
        support: Support::Refused,
        note: "Runs a Lua script; the agent embeds no interpreter.",
    },
    KeywordSupport {
        keyword: "luaxform",
        support: Support::Refused,
        note: "Transforms a buffer with a Lua script; the agent embeds no interpreter.",
    },
    KeywordSupport {
        keyword: "replace",
        support: Support::Refused,
        note: "Rewrites the packet in flight; the agent matches a copy and never rewrites traffic.",
    },
    KeywordSupport {
        keyword: "filestore",
        support: Support::Refused,
        note: "Writes files to disk; the agent stores no payload.",
    },
    KeywordSupport {
        keyword: "filemagic",
        support: Support::Refused,
        note: "Needs libmagic, which the agent does not link.",
    },
    KeywordSupport {
        keyword: "file.magic",
        support: Support::Refused,
        note: "Needs libmagic, which the agent does not link.",
    },
    KeywordSupport {
        keyword: "bypass",
        support: Support::Refused,
        note: "Hands the flow to a bypass path the agent does not have.",
    },
    KeywordSupport {
        keyword: "nfq_set_mark",
        support: Support::Refused,
        note: "Marks a packet in an NFQUEUE the agent does not read.",
    },
    KeywordSupport {
        keyword: "tls_store",
        support: Support::Refused,
        note: "Writes certificates to disk; the agent stores no payload.",
    },
    KeywordSupport {
        keyword: "tls.store",
        support: Support::Refused,
        note: "Writes certificates to disk; the agent stores no payload.",
    },
    KeywordSupport {
        keyword: "config",
        support: Support::Refused,
        note: "Changes how Suricata logs and bypasses a flow, which the agent does not imitate.",
    },
];

fn table_row(keyword: &str) -> Option<&'static KeywordSupport> {
    KEYWORDS.iter().find(|row| row.keyword == keyword)
}

// ── Variables ────────────────────────────────────────────────────

/// The address and port variables a ruleset refers to.
///
/// The defaults are the ones Suricata ships in its own `suricata.yaml`, so a
/// ruleset written against a stock install compiles to the same networks; an
/// operator replaces `HOME_NET` with theirs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuricataVars {
    pub addresses: BTreeMap<String, String>,
    pub ports: BTreeMap<String, String>,
}

impl Default for SuricataVars {
    fn default() -> Self {
        let home_servers = [
            "HTTP_SERVERS",
            "SMTP_SERVERS",
            "SQL_SERVERS",
            "DNS_SERVERS",
            "TELNET_SERVERS",
            "DC_SERVERS",
            "DNP3_SERVER",
            "DNP3_CLIENT",
            "MODBUS_CLIENT",
            "MODBUS_SERVER",
            "ENIP_CLIENT",
            "ENIP_SERVER",
        ];
        let mut addresses: BTreeMap<String, String> = home_servers
            .iter()
            .map(|name| ((*name).to_string(), "$HOME_NET".to_string()))
            .collect();
        addresses.insert(
            "HOME_NET".to_string(),
            "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]".to_string(),
        );
        addresses.insert("EXTERNAL_NET".to_string(), "!$HOME_NET".to_string());
        addresses.insert("AIM_SERVERS".to_string(), "$EXTERNAL_NET".to_string());
        let ports = [
            ("HTTP_PORTS", "80"),
            ("SHELLCODE_PORTS", "!80"),
            ("ORACLE_PORTS", "1521"),
            ("SSH_PORTS", "22"),
            ("DNP3_PORTS", "20000"),
            ("MODBUS_PORTS", "502"),
            ("FILE_DATA_PORTS", "[$HTTP_PORTS,110,143]"),
            ("FTP_PORTS", "21"),
            ("GENEVE_PORTS", "6081"),
            ("VXLAN_PORTS", "4789"),
            ("TEREDO_PORTS", "3544"),
            ("SIP_PORTS", "[5060,5061]"),
        ]
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect();
        Self { addresses, ports }
    }
}

impl SuricataVars {
    /// The stock variables with the given ones laid over them.
    pub fn with_overrides(
        addresses: &BTreeMap<String, String>,
        ports: &BTreeMap<String, String>,
    ) -> Self {
        let mut vars = Self::default();
        for (name, value) in addresses {
            vars.addresses.insert(name.clone(), value.clone());
        }
        for (name, value) in ports {
            vars.ports.insert(name.clone(), value.clone());
        }
        vars
    }
}

// ── Results ──────────────────────────────────────────────────────

/// Why one rule did not compile: the keyword that stopped it and the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    /// The rule's sid, when the compiler got far enough to read one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,
    /// The line of the ruleset the rule starts on, counted from 1.
    pub line: usize,
    pub keyword: String,
    pub reason: String,
}

/// What importing one ruleset produced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    /// Rules the ruleset enables, compiled or not.
    pub total: usize,
    /// Rules that compiled.
    pub compiled: usize,
    /// Native rules the compiled ones became, one per port.
    pub native_rules: usize,
    /// Rules present but commented out, which are not read.
    pub disabled: usize,
    pub refused: Vec<Refusal>,
}

impl ImportReport {
    /// The share of enabled rules that were refused, from 0 to 1.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // counts far below 2^52
    pub fn refused_share(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.refused.len() as f64 / self.total as f64
        }
    }

    /// The refusals counted by keyword, most frequent first, ties by name.
    #[must_use]
    pub fn refusals_by_keyword(&self) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for refusal in &self.refused {
            *counts.entry(refusal.keyword.as_str()).or_default() += 1;
        }
        let mut ranked: Vec<(String, usize)> = counts
            .into_iter()
            .map(|(keyword, count)| (keyword.to_string(), count))
            .collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        ranked
    }
}

/// A compiled ruleset: the native rules and the report on how they came.
#[derive(Debug, Clone, Default)]
pub struct CompiledRuleset {
    pub rules: Vec<IdsRule>,
    pub report: ImportReport,
}

/// One ruleset of an import and what came of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesetImport {
    /// Where the ruleset was read from, as the configuration names it.
    pub source: String,
    #[serde(flatten)]
    pub report: ImportReport,
}

/// Several rulesets compiled together: every native rule and one report per
/// ruleset, in the order they were given.
#[derive(Debug, Clone, Default)]
pub struct ImportedRulesets {
    pub rules: Vec<IdsRule>,
    pub rulesets: Vec<RulesetImport>,
}

impl ImportedRulesets {
    /// The first ruleset refusing a larger share of its rules than allowed,
    /// which fails the import rather than loading a fraction of a corpus.
    #[must_use]
    pub fn over_share(&self, max_refused_share: f64) -> Option<&RulesetImport> {
        self.rulesets
            .iter()
            .find(|ruleset| ruleset.report.refused_share() > max_refused_share)
    }
}

/// One rule's refusal before the line is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub sid: Option<u32>,
    pub keyword: String,
    pub reason: String,
}

impl Refused {
    pub(crate) fn new(keyword: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            sid: None,
            keyword: keyword.into(),
            reason: reason.into(),
        }
    }
}

pub(crate) type Compiled<T> = Result<T, Refused>;

// ── Ruleset ──────────────────────────────────────────────────────

/// Compile a whole ruleset file.
///
/// Blank lines and comments are skipped; a comment that is itself a rule is
/// counted as disabled. A rule continued over several lines with a trailing
/// backslash is read as one. A sid seen twice refuses the second rule.
pub fn compile_ruleset(text: &str, vars: &SuricataVars) -> CompiledRuleset {
    compile_ruleset_after(text, vars, &mut HashSet::new())
}

/// Compile several rulesets as one import. A sid is one rule across all of
/// them, so a sid an earlier ruleset compiled is refused in a later one
/// rather than loaded twice.
pub fn compile_rulesets<'a>(
    sources: impl IntoIterator<Item = (String, &'a str)>,
    vars: &SuricataVars,
) -> ImportedRulesets {
    let mut seen: HashSet<u32> = HashSet::new();
    let mut out = ImportedRulesets::default();
    for (source, text) in sources {
        let compiled = compile_ruleset_after(text, vars, &mut seen);
        out.rules.extend(compiled.rules);
        out.rulesets.push(RulesetImport {
            source,
            report: compiled.report,
        });
    }
    out
}

fn compile_ruleset_after(
    text: &str,
    vars: &SuricataVars,
    seen: &mut HashSet<u32>,
) -> CompiledRuleset {
    let mut out = CompiledRuleset::default();
    let mut pending = String::new();
    let mut start_line = 0;

    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if pending.is_empty() {
            if line.is_empty() {
                continue;
            }
            if let Some(comment) = line.strip_prefix('#') {
                if looks_like_rule(comment.trim_start()) {
                    out.report.disabled += 1;
                }
                continue;
            }
            start_line = index + 1;
        }
        if let Some(continued) = line.strip_suffix('\\') {
            pending.push_str(continued);
            continue;
        }
        pending.push_str(line);
        let rule = std::mem::take(&mut pending);
        compile_into(&rule, start_line, vars, seen, &mut out);
    }
    if !pending.is_empty() {
        compile_into(&pending, start_line, vars, seen, &mut out);
    }
    out
}

fn looks_like_rule(text: &str) -> bool {
    ["alert ", "drop ", "reject ", "pass "]
        .iter()
        .any(|action| text.starts_with(action))
        && text.contains('(')
}

fn compile_into(
    text: &str,
    line: usize,
    vars: &SuricataVars,
    seen: &mut HashSet<u32>,
    out: &mut CompiledRuleset,
) {
    out.report.total += 1;
    let refuse = |out: &mut CompiledRuleset, refused: Refused| {
        out.report.refused.push(Refusal {
            sid: refused.sid,
            line,
            keyword: refused.keyword,
            reason: refused.reason,
        });
    };
    match compile_rule(text, vars) {
        Ok(rules) => {
            let sid = rules
                .first()
                .and_then(|rule| rule.imported.as_ref())
                .map_or(0, |imported| imported.sid);
            if !seen.insert(sid) {
                refuse(
                    out,
                    Refused {
                        sid: Some(sid),
                        keyword: "sid".to_string(),
                        reason: "the sid is already used by an earlier rule of the import"
                            .to_string(),
                    },
                );
                return;
            }
            out.report.compiled += 1;
            out.report.native_rules += rules.len();
            out.rules.extend(rules);
        }
        Err(refused) => refuse(out, refused),
    }
}

// ── One rule ─────────────────────────────────────────────────────

/// Compile one rule, returning the native rules it becomes (one per port it
/// names) or the refusal.
pub fn compile_rule(text: &str, vars: &SuricataVars) -> Compiled<Vec<IdsRule>> {
    let text = text.trim();
    // A rule that is not valid Suricata is refused by the parser; a valid one
    // naming a keyword the engine does not inspect yet, or never will, is
    // refused by the keyword table.
    let signature = super::sig::parse_signature(text, vars)?;
    for keyword in &signature.keywords {
        if let Some(row) = table_row(keyword)
            && matches!(row.support, Support::Pending | Support::Refused)
        {
            let mut refused = Refused::new(keyword, row.note);
            refused.sid = Some(signature.sid);
            return Err(refused);
        }
    }
    let open = text
        .find('(')
        .ok_or_else(|| Refused::new("rule", "has no option list in parentheses"))?;
    let close = text
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or_else(|| Refused::new("rule", "has an option list that is never closed"))?;
    if !text[close + 1..].trim().is_empty() {
        return Err(Refused::new("rule", "has text after its option list"));
    }

    let options = parse_options(&text[open + 1..close])?;
    let sid = options
        .iter()
        .find(|(key, _)| key == "sid")
        .ok_or_else(|| Refused::new("sid", "is missing, and a rule is named by it"))?;
    let sid = sid
        .1
        .trim()
        .parse::<u32>()
        .map_err(|_| Refused::new("sid", format!("'{}' is not a number", sid.1.trim())))?;

    let inspection = super::sig::inspect::Program::compile(&signature).map_err(|mut refused| {
        refused.sid = Some(sid);
        refused
    })?;
    let pattern = label(&signature).ok_or_else(|| {
        let mut refused = Refused::new(
            "content",
            "names no content or pcre; a rule on the port alone is written natively",
        );
        refused.sid = Some(sid);
        refused
    })?;
    let inspection = Inspection(std::sync::Arc::new(inspection));
    compile_parts(&text[..open], &options, vars, &pattern, inspection).map_err(|mut refused| {
        refused.sid = Some(sid);
        refused
    })
}

fn compile_parts(
    header: &str,
    options: &[(String, String)],
    vars: &SuricataVars,
    pattern: &str,
    inspection: Inspection,
) -> Compiled<Vec<IdsRule>> {
    let header = parse_header(header, vars)?;
    let body = compile_options(options)?;

    let (ports, on_destination) = match (&header.src_ports, &header.dst_ports) {
        (PortSpec::Any, PortSpec::Any) => {
            return Err(Refused::new(
                "port",
                "names no port on either side, and the classifier keys on one",
            ));
        }
        (PortSpec::Any, PortSpec::Set(ports)) => (ports, true),
        (PortSpec::Set(ports), PortSpec::Any) => (ports, false),
        (PortSpec::Set(_), PortSpec::Set(_)) => {
            return Err(Refused::new(
                "port",
                "names ports on both sides, and a rule is keyed on one",
            ));
        }
    };

    let imported = ImportedRule {
        sid: body.sid,
        rev: body.rev,
        classtype: body.classtype.clone(),
        references: body.references.clone(),
        src: header.src,
        dst: header.dst,
        inspection: Some(inspection),
    };
    let several = ports.len() > 1;
    let rules = ports
        .iter()
        .map(|port| {
            let id = if several {
                format!("suricata-{}-{port}", body.sid)
            } else {
                format!("suricata-{}", body.sid)
            };
            IdsRule {
                id: RuleId(id),
                description: body.msg.clone(),
                severity: body.severity,
                mode: DomainMode::Alert,
                protocol: Protocol::Tcp,
                dst_port: on_destination.then_some(*port),
                src_port: (!on_destination).then_some(*port),
                pattern: pattern.to_string(),
                enabled: true,
                threshold: body.threshold.clone(),
                domain_pattern: None,
                domain_match_mode: None,
                country_thresholds: None,
                group_mask: 0,
                tenant_id: 0,
                workload: None,
                kill_process: false,
                imported: Some(Box::new(imported.clone())),
            }
        })
        .collect();
    Ok(rules)
}

/// What a reader sees as the rule's pattern: its first content, printable
/// bytes as they are and the others in Suricata's `|hex|` notation, or its
/// first pcre. The inspection program decides the rule; this only names it.
fn label(signature: &super::sig::model::Signature) -> Option<String> {
    use super::sig::model::Match;
    let matches = || signature.lists.iter().flat_map(|l| l.matches.iter());
    if let Some(bytes) = matches().find_map(|m| match m {
        Match::Content(c) if !c.negated => Some(&c.bytes),
        _ => None,
    }) {
        let mut out = String::with_capacity(bytes.len());
        let mut hex = false;
        for b in bytes {
            let plain =
                b.is_ascii_graphic() && !matches!(b, b'|' | b'"' | b'\\' | b';') || *b == b' ';
            if plain == hex {
                out.push('|');
                hex = !hex;
            } else if hex {
                out.push(' ');
            }
            if plain {
                out.push(char::from(*b));
            } else {
                let _ = write!(out, "{b:02X}");
            }
        }
        if hex {
            out.push('|');
        }
        return Some(out);
    }
    matches().find_map(|m| match m {
        Match::Pcre(p) => Some(format!("/{}/{}", p.expression, p.flags)),
        Match::Content(c) => Some(format!("!{}", String::from_utf8_lossy(&c.bytes))),
        _ => None,
    })
}

// ── Header ───────────────────────────────────────────────────────

struct Header {
    src: AddressMatch,
    src_ports: PortSpec,
    dst: AddressMatch,
    dst_ports: PortSpec,
}

fn parse_header(text: &str, vars: &SuricataVars) -> Compiled<Header> {
    let tokens = split_header(text)?;
    let [action, protocol, src, src_ports, direction, dst, dst_ports] = tokens.as_slice() else {
        return Err(Refused::new(
            "header",
            "is not 'action protocol source port direction destination port'",
        ));
    };

    match action.as_str() {
        "alert" => {}
        "drop" | "reject" | "rejectsrc" | "rejectdst" | "rejectboth" => {
            return Err(Refused::new(
                action.as_str(),
                "would drop on the port before the content is seen; imported rules alert only",
            ));
        }
        "pass" => {
            return Err(Refused::new(
                "pass",
                "exempts traffic from other rules, which the engine does not order",
            ));
        }
        other => return Err(Refused::new(other, "is not a rule action")),
    }

    match protocol.as_str() {
        "tcp" => {}
        "udp" | "icmp" | "ip" | "icmpv6" | "sctp" => {
            return Err(Refused::new(
                protocol.as_str(),
                "only TCP segments carry a captured payload",
            ));
        }
        "tcp-pkt" | "tcp-stream" => {
            return Err(Refused::new(
                protocol.as_str(),
                "selects packets or the reassembled stream, and the agent matches segments",
            ));
        }
        other => {
            return Err(Refused::new(
                other,
                "is an application-layer protocol the agent does not parse",
            ));
        }
    }

    match direction.as_str() {
        "->" => {}
        "<>" => {
            return Err(Refused::new(
                "<>",
                "matches both directions, and a rule is keyed on one side's port",
            ));
        }
        other => return Err(Refused::new(other, "is not a direction")),
    }

    Ok(Header {
        src: parse_addresses(src, vars, 0)?.into_match(src)?,
        src_ports: parse_ports(src_ports, vars, 0)?,
        dst: parse_addresses(dst, vars, 0)?.into_match(dst)?,
        dst_ports: parse_ports(dst_ports, vars, 0)?,
    })
}

/// Split the header on whitespace, keeping a bracketed list whole.
pub(crate) fn split_header(text: &str) -> Compiled<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for ch in text.chars() {
        match ch {
            '[' => {
                depth += 1;
                current.push(ch);
            }
            ']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| Refused::new("header", "closes a list it never opened"))?;
                current.push(ch);
            }
            c if c.is_whitespace() && depth == 0 => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c if c.is_whitespace() => {}
            c => current.push(c),
        }
    }
    if depth != 0 {
        return Err(Refused::new("header", "opens a list it never closes"));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

/// Split a bracketed list's body on the commas at its own level.
pub(crate) fn split_list(body: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    for (index, ch) in body.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                items.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    items.push(&body[start..]);
    items.into_iter().filter(|item| !item.is_empty()).collect()
}

#[derive(Default)]
pub(crate) struct AddressSet {
    any: bool,
    within: Vec<IpNetwork>,
    outside: Vec<IpNetwork>,
}

impl AddressSet {
    pub(crate) fn into_match(self, written: &str) -> Compiled<AddressMatch> {
        if self.any && !self.within.is_empty() {
            return Ok(AddressMatch {
                within: Vec::new(),
                outside: self.outside,
            });
        }
        if !self.any && self.within.is_empty() && self.outside.is_empty() {
            return Err(Refused::new(written, "names no address at all"));
        }
        Ok(AddressMatch {
            within: self.within,
            outside: self.outside,
        })
    }
}

pub(crate) fn parse_addresses(
    token: &str,
    vars: &SuricataVars,
    depth: usize,
) -> Compiled<AddressSet> {
    if depth > MAX_VARIABLE_DEPTH {
        return Err(Refused::new(
            token,
            "refers through more variables than are followed",
        ));
    }
    let token = token.trim();
    if token == "any" {
        return Ok(AddressSet {
            any: true,
            ..AddressSet::default()
        });
    }
    if let Some(negated) = token.strip_prefix('!') {
        let inner = parse_addresses(negated, vars, depth + 1)?;
        if inner.any {
            return Err(Refused::new(token, "negates every address"));
        }
        if !inner.outside.is_empty() {
            return Err(Refused::new(
                token,
                "negates a list that already holds a negation",
            ));
        }
        return Ok(AddressSet {
            any: false,
            within: Vec::new(),
            outside: inner.within,
        });
    }
    if let Some(body) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        let mut set = AddressSet::default();
        for item in split_list(body) {
            let part = parse_addresses(item, vars, depth + 1)?;
            set.any |= part.any;
            set.within.extend(part.within);
            set.outside.extend(part.outside);
        }
        return Ok(set);
    }
    if let Some(name) = token.strip_prefix('$') {
        let value = vars
            .addresses
            .get(name)
            .ok_or_else(|| Refused::new(token, "names an address variable that has no value"))?;
        return parse_addresses(value, vars, depth + 1);
    }
    let network = parse_network(token)
        .ok_or_else(|| Refused::new(token, "is not an address, a network or a variable"))?;
    Ok(AddressSet {
        any: false,
        within: vec![network],
        outside: Vec::new(),
    })
}

/// Parses an address or a CIDR network, masking the host bits away.
#[must_use]
pub fn parse_network(text: &str) -> Option<IpNetwork> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let address: IpAddr = address.parse().ok()?;
    let widest = if address.is_ipv4() { 32 } else { 128 };
    let prefix_len = match prefix {
        Some(prefix) => prefix.parse::<u8>().ok().filter(|len| *len <= widest)?,
        None => widest,
    };
    Some(match address {
        IpAddr::V4(v4) => {
            let raw = u32::from(v4);
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            IpNetwork::V4 {
                addr: raw & mask,
                prefix_len,
            }
        }
        IpAddr::V6(v6) => IpNetwork::V6 {
            addr: v6.octets(),
            prefix_len,
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PortSpec {
    Any,
    Set(BTreeSet<u16>),
}

fn parse_ports(token: &str, vars: &SuricataVars, depth: usize) -> Compiled<PortSpec> {
    let mut ports = BTreeSet::new();
    if collect_ports(token, vars, depth, &mut ports)? {
        return Ok(PortSpec::Any);
    }
    Ok(PortSpec::Set(ports))
}

/// Add the ports a token names to `ports`, returning `true` for `any`.
fn collect_ports(
    token: &str,
    vars: &SuricataVars,
    depth: usize,
    ports: &mut BTreeSet<u16>,
) -> Compiled<bool> {
    if depth > MAX_VARIABLE_DEPTH {
        return Err(Refused::new(
            token,
            "refers through more variables than are followed",
        ));
    }
    let token = token.trim();
    if token == "any" {
        return Ok(true);
    }
    if token.starts_with('!') {
        return Err(Refused::new(
            token,
            "negates a port, and a rule is keyed on the ports it names",
        ));
    }
    if let Some(body) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        let mut any = false;
        for item in split_list(body) {
            any |= collect_ports(item, vars, depth + 1, ports)?;
        }
        return Ok(any);
    }
    if let Some(name) = token.strip_prefix('$') {
        let value = vars
            .ports
            .get(name)
            .ok_or_else(|| Refused::new(token, "names a port variable that has no value"))?;
        return collect_ports(value, vars, depth + 1, ports);
    }
    let not_a_port = || Refused::new(token, "is not a port, a range or a variable");
    let bound = |text: &str, empty: u16| -> Compiled<u16> {
        if text.is_empty() {
            Ok(empty)
        } else {
            text.parse::<u16>().map_err(|_| not_a_port())
        }
    };
    let (low, high) = if let Some((low, high)) = token.split_once(':') {
        (bound(low, 0)?, bound(high, u16::MAX)?)
    } else {
        let port = token.parse::<u16>().map_err(|_| not_a_port())?;
        (port, port)
    };
    if low > high {
        return Err(Refused::new(token, "is a range that ends before it starts"));
    }
    let span = usize::from(high - low) + 1;
    if ports.len() + span > MAX_PORTS_PER_RULE {
        return Err(Refused::new(
            token,
            format!(
                "names more than {MAX_PORTS_PER_RULE} ports, and each port is a rule of its own"
            ),
        ));
    }
    ports.extend(low..=high);
    Ok(false)
}

// ── Options ──────────────────────────────────────────────────────

/// Split the option list into `(keyword, value)` pairs. A value runs to the
/// first semicolon outside quotes; a backslash escapes the next character.
pub(crate) fn parse_options(text: &str) -> Compiled<Vec<(String, String)>> {
    // Suricata ends an option at the first `;` that no backslash escapes,
    // quotes or not: a `;` inside a content is written `\;` or `|3b|`.
    let mut options = Vec::new();
    let mut current = String::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                current.push(ch);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ';' => {
                push_option(&mut options, &current)?;
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    push_option(&mut options, &current)?;
    Ok(options)
}

fn push_option(options: &mut Vec<(String, String)>, raw: &str) -> Compiled<()> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(());
    }
    let (key, value) = match raw.split_once(':') {
        Some((key, value)) => (key.trim(), value.trim()),
        None => (raw, ""),
    };
    if key.is_empty() || key.chars().any(char::is_whitespace) {
        return Err(Refused::new(
            "rule",
            format!("has '{raw}' where an option goes"),
        ));
    }
    options.push((key.to_string(), value.to_string()));
    Ok(())
}

/// A quoted option value with its quotes taken off. Escapes are kept for the
/// caller, which knows which ones it reads.
pub(crate) fn unquote<'a>(keyword: &str, value: &'a str) -> Compiled<&'a str> {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(|| Refused::new(keyword, "takes a quoted value"))
}

/// Remove the escapes Suricata defines inside a quoted value.
pub(crate) fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// One option list's compiled meaning.
struct Body {
    sid: u32,
    rev: u32,
    msg: String,
    classtype: Option<String>,
    references: Vec<String>,
    severity: Severity,
    threshold: Option<ThresholdConfig>,
}

#[allow(clippy::too_many_lines)] // one arm per keyword reads better than a dispatch table
fn compile_options(options: &[(String, String)]) -> Compiled<Body> {
    let mut sid = 0;
    let mut rev = 0;
    let mut msg = String::new();
    let mut classtype = None;
    let mut references = Vec::new();
    let mut priority: Option<u8> = None;
    let mut threshold = None;

    for (key, value) in options {
        let key = key.as_str();
        let value = value.as_str();
        match key {
            "sid" => {
                sid = value
                    .parse()
                    .map_err(|_| Refused::new("sid", "is not a number"))?;
            }
            "rev" => {
                rev = value
                    .parse()
                    .map_err(|_| Refused::new("rev", "is not a number"))?;
            }
            "gid" => {
                if value != "1" {
                    return Err(Refused::new(
                        "gid",
                        "names a generator other than the rule engine",
                    ));
                }
            }
            "msg" => msg = unescape(unquote(key, value)?),
            "classtype" => classtype = Some(value.to_string()),
            "priority" => {
                priority = Some(
                    value
                        .parse()
                        .map_err(|_| Refused::new("priority", "is not a number"))?,
                );
            }
            "reference" => references.push(value.to_string()),
            "flow" => check_flow(value)?,
            "threshold" => threshold = Some(parse_threshold(value)?),
            // The matches were compiled from the parsed signature, and the
            // keyword table has already refused what the engine does not run.
            _ => {}
        }
    }

    let severity = match priority.or_else(|| classtype.as_deref().map(classtype_priority)) {
        Some(1) => Severity::High,
        Some(2) | None => Severity::Medium,
        Some(_) => Severity::Low,
    };

    Ok(Body {
        sid,
        rev,
        msg,
        classtype,
        references,
        severity,
        threshold,
    })
}

fn check_flow(value: &str) -> Compiled<()> {
    for word in value.split(',').map(str::trim) {
        match word {
            "established" | "stateless" | "to_server" | "from_client" | "to_client"
            | "from_server" => {}
            "not_established" => {
                return Err(Refused::new(
                    "flow",
                    "'not_established' matches before a connection is up, and no payload is captured then",
                ));
            }
            other => {
                return Err(Refused::new(
                    "flow",
                    format!("'{other}' needs stream or fragment state the agent does not keep"),
                ));
            }
        }
    }
    Ok(())
}

/// Decode a content value: `|41 42|` sections are hex bytes, a backslash
/// escapes the next character, and the rest is literal.
pub(crate) fn decode_content(value: &str) -> Compiled<Vec<u8>> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut hex = false;
    let mut digits = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if hex {
            match ch {
                '|' => {
                    if !digits.is_empty() {
                        return Err(Refused::new("content", "has an odd number of hex digits"));
                    }
                    hex = false;
                }
                c if c.is_ascii_hexdigit() => {
                    digits.push(c);
                    if digits.len() == 2 {
                        let byte = u8::from_str_radix(&digits, 16)
                            .map_err(|_| Refused::new("content", "has a malformed hex byte"))?;
                        bytes.push(byte);
                        digits.clear();
                    }
                }
                c if c.is_whitespace() => {}
                _ => {
                    return Err(Refused::new(
                        "content",
                        "has a character inside a hex section",
                    ));
                }
            }
            continue;
        }
        match ch {
            '|' => hex = true,
            '\\' => {
                let next = chars
                    .next()
                    .ok_or_else(|| Refused::new("content", "ends on an escape"))?;
                push_char(&mut bytes, next);
            }
            c => push_char(&mut bytes, c),
        }
    }
    if hex {
        return Err(Refused::new(
            "content",
            "opens a hex section it never closes",
        ));
    }
    Ok(bytes)
}

fn push_char(bytes: &mut Vec<u8>, ch: char) {
    let mut buf = [0u8; 4];
    bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
}

fn parse_threshold(value: &str) -> Compiled<ThresholdConfig> {
    let mut kind = None;
    let mut track = None;
    let mut count = None;
    let mut seconds = None;
    for part in value.split(',') {
        let mut words = part.split_whitespace();
        let (Some(name), Some(setting), None) = (words.next(), words.next(), words.next()) else {
            return Err(Refused::new("threshold", format!("has '{}'", part.trim())));
        };
        match name {
            "type" => {
                kind = Some(match setting {
                    "limit" => ThresholdType::Limit,
                    "threshold" => ThresholdType::Threshold,
                    "both" => ThresholdType::Both,
                    other => {
                        return Err(Refused::new(
                            "threshold",
                            format!("type '{other}' is not in the compiled subset"),
                        ));
                    }
                });
            }
            "track" => {
                track = Some(match setting {
                    "by_src" => TrackBy::SrcIp,
                    "by_dst" => TrackBy::DstIp,
                    "by_both" => TrackBy::Both,
                    other => {
                        return Err(Refused::new(
                            "threshold",
                            format!("track '{other}' is not in the compiled subset"),
                        ));
                    }
                });
            }
            "count" => count = setting.parse::<u32>().ok().filter(|c| *c > 0),
            "seconds" => seconds = setting.parse::<u64>().ok().filter(|s| *s > 0),
            other => {
                return Err(Refused::new(
                    "threshold",
                    format!("'{other}' is not a threshold setting"),
                ));
            }
        }
    }
    match (kind, track, count, seconds) {
        (Some(threshold_type), Some(track_by), Some(count), Some(window_secs)) => {
            Ok(ThresholdConfig {
                threshold_type,
                count,
                window_secs,
                track_by,
            })
        }
        _ => Err(Refused::new(
            "threshold",
            "needs a type, a track, a positive count and positive seconds",
        )),
    }
}

/// The priority Suricata's stock `classification.config` gives a class.
/// A class it does not list is priority 2.
fn classtype_priority(classtype: &str) -> u8 {
    match classtype {
        "attempted-user"
        | "unsuccessful-user"
        | "successful-user"
        | "attempted-admin"
        | "successful-admin"
        | "shellcode-detect"
        | "trojan-activity"
        | "web-application-attack"
        | "policy-violation"
        | "targeted-activity"
        | "exploit-kit"
        | "domain-c2"
        | "credential-theft"
        | "command-and-control" => 1,
        "not-suspicious"
        | "unknown"
        | "string-detect"
        | "network-scan"
        | "protocol-command-decode"
        | "misc-activity"
        | "icmp-event" => 3,
        "tcp-connection" => 4,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::engine::IdsEngine;
    use ebpf_common::event::PacketEvent;

    /// Rules from Emerging Threats Open, sids 2000000 to 2799999, which are
    /// published under the BSD licence.
    const ET_SMTP_EXPN: &str = r#"alert tcp $EXTERNAL_NET any -> $SMTP_SERVERS 25 (msg:"GPL SMTP expn root"; flow:established,to_server; content:"expn"; nocase; content:"root"; fast_pattern; distance:0; nocase; pcre:"/^expn\s+root/smi"; reference:arachnids,31; reference:cve,1999-0531; reference:nessus,10249; classtype:attempted-recon; sid:2100660; rev:14; metadata:created_at 2010_09_23, cve CVE_1999_0531;)"#;
    const ET_PCANYWHERE: &str = r#"alert tcp $HOME_NET 5631:5632 -> $EXTERNAL_NET any (msg:"GPL INFO PCAnywhere Failed Login"; flow:established,to_client; content:"Invalid login"; depth:16; reference:arachnids,240; classtype:unsuccessful-user; sid:2100512; rev:6; metadata:created_at 2010_09_23, confidence Medium;)"#;
    const ET_SMB_POWERSHELL: &str = r#"alert tcp any any -> $HOME_NET 445 (msg:"ET INFO Powershell Command With Hidden Window Argument Over SMB - Likely Lateral Movement"; flow:established,to_server; content:"SMB"; depth:8; content:"powershell"; nocase; distance:0; content:"-w"; distance:0; content:"hidden"; nocase; within:17; classtype:bad-unknown; sid:2027170; rev:1;)"#;
    const ET_RDP_COOKIE: &str = r#"alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"ET MALWARE MS Remote Desktop edc User Login Request"; flow:established,to_server; content:"|03 00 00|"; depth:3; content:"|e0 00 00 00 00 00|"; distance:2; within:6; content:"Cookie|3a| mstshash=edc|0d 0a|"; nocase; reference:url,intelcrawler.com/about/press08; classtype:protocol-command-decode; sid:2018116; rev:2;)"#;
    const ET_SCREENOS: &str = r#"alert tcp any any -> $HOME_NET 23 (msg:"ET EXPLOIT Juniper ScreenOS telnet Backdoor Default Password Attempt"; flow:established,to_server; content:"|3c 3c 3c 20 25 73 28 75 6e 3d 27 25 73 27 29 20 3d 20 25 75|"; fast_pattern; threshold: type limit, count 1, seconds 60, track by_src; reference:cve,2015-7755; classtype:attempted-admin; sid:2022291; rev:2;)"#;
    const ET_FOKIRTOR: &str = r#"alert tcp $EXTERNAL_NET any -> any 22 (msg:"ET MALWARE Possible SSH Linux.Fokirtor backchannel command"; flow:established,to_server; content:"|3a 21 3b 2e|"; pcre:"/^(?:[A-Za-z0-9\+\/]{4})*(?:[A-Za-z0-9\+\/]{2}==|[A-Za-z0-9\+\/]{3}=|[A-Za-z0-9\+\/]{4})/R"; classtype:trojan-activity; sid:2017727; rev:6;)"#;
    const ET_ORACLE_BACKREF: &str = r#"alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:"GPL SQL dbms_repcat.add_column_group_to_flavor buffer overflow attempt"; flow:established,to_server; content:"dbms_repcat.add_column_group_to_flavor"; nocase; fast_pattern; pcre:"/((\w+)[\r\n\s]*\x3a=[\r\n\s]*\x27[^\x27]{10,}\x27[\r\n\s]*\x3b.*gname[\r\n\s]*=>[\r\n\s]*\2)/si"; classtype:attempted-user; sid:2102850; rev:5;)"#;
    const ET_HTTP: &str = r#"alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Example"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/x.php"; classtype:bad-unknown; sid:2030000; rev:1;)"#;
    const ET_FLOWBITS: &str = r#"alert tcp $EXTERNAL_NET 21 -> $HOME_NET any (msg:"ET FTP Example"; flow:established,to_client; flowbits:isset,ET.ftp; content:"230 "; depth:4; classtype:misc-activity; sid:2030001; rev:1;)"#;

    fn vars() -> SuricataVars {
        SuricataVars::default()
    }

    fn compile(text: &str) -> Vec<IdsRule> {
        match compile_rule(text, &vars()) {
            Ok(rules) => rules,
            Err(refused) => panic!("refused: {} {}", refused.keyword, refused.reason),
        }
    }

    fn refusal(text: &str) -> Refused {
        match compile_rule(text, &vars()) {
            Ok(_) => panic!("compiled a rule that should be refused"),
            Err(refused) => refused,
        }
    }

    fn v4(octets: [u8; 4]) -> [u32; 4] {
        [u32::from_be_bytes(octets), 0, 0, 0]
    }

    fn event(src: [u8; 4], src_port: u16, dst: [u8; 4], dst_port: u16) -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: v4(src),
            dst_addr: v4(dst),
            src_port,
            dst_port,
            protocol: 6,
            event_type: 0,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            cgroup1_id: 0,
            rss_hash: 0,
            rss_hash_type: 0,
            rx_hw_timestamp_ns: 0,
            pkt_len: 0,
            _pad: 0,
        }
    }

    fn engine(rules: Vec<IdsRule>) -> IdsEngine {
        let mut engine = IdsEngine::new();
        match engine.reload(rules) {
            Ok(()) => engine,
            Err(e) => panic!("engine refused compiled rules: {e}"),
        }
    }

    const OUTSIDE: [u8; 4] = [203, 0, 113, 9];
    const INSIDE: [u8; 4] = [10, 1, 2, 3];

    #[test]
    fn compiles_a_chained_content_rule_and_matches_what_it_describes() {
        let rules = compile(ET_SMTP_EXPN);
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.id.0, "suricata-2100660");
        assert_eq!(rule.dst_port, Some(25));
        assert_eq!(rule.src_port, None);
        assert_eq!(rule.mode, DomainMode::Alert);
        assert_eq!(rule.severity, Severity::Medium);
        let imported = rule
            .imported
            .as_ref()
            .map(|i| (i.sid, i.rev, i.references.len()));
        assert_eq!(imported, Some((2_100_660, 14, 3)));

        let engine = engine(rules);
        let from_outside = event(OUTSIDE, 40000, INSIDE, 25);
        assert!(
            !engine
                .evaluate_payload_with_context(&from_outside, b"EXPN   root\r\n", None)
                .is_empty()
        );
        // The pcre is anchored to the start of a line, so the words alone do not match.
        assert!(
            engine
                .evaluate_payload_with_context(&from_outside, b"HELO root expn\r\n", None)
                .is_empty()
        );
        // The source must be outside the home networks.
        let from_inside = event([10, 9, 9, 9], 40000, INSIDE, 25);
        assert!(
            engine
                .evaluate_payload_with_context(&from_inside, b"expn root\r\n", None)
                .is_empty()
        );
    }

    #[test]
    fn expands_a_port_range_into_one_rule_per_port_on_the_source_side() {
        let rules = compile(ET_PCANYWHERE);
        let ids: Vec<&str> = rules.iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(ids, ["suricata-2100512-5631", "suricata-2100512-5632"]);
        assert!(rules.iter().all(|r| r.dst_port.is_none()));
        assert_eq!(rules[0].severity, Severity::High);

        let engine = engine(rules);
        let reply = event(INSIDE, 5632, OUTSIDE, 50000);
        assert!(
            !engine
                .evaluate_payload_with_context(&reply, b"\x00\x00Invalid login\r\n", None)
                .is_empty()
        );
        // depth 16 from offset 0: the content must start within the first 3 bytes.
        assert!(
            engine
                .evaluate_payload_with_context(&reply, b"0123456789Invalid login", None)
                .is_empty()
        );
    }

    #[test]
    fn honours_within_relative_to_the_content_before() {
        let engine = engine(compile(ET_SMB_POWERSHELL));
        let to_smb = event(OUTSIDE, 50000, INSIDE, 445);
        let near = b"\x00\x00\x00\x00\xffSMBxx PowerShell.exe -w   Hidden";
        assert!(
            !engine
                .evaluate_payload_with_context(&to_smb, near, None)
                .is_empty()
        );
        let far = b"\x00\x00\x00\x00\xffSMBxx PowerShell.exe -w                     hidden";
        assert!(
            engine
                .evaluate_payload_with_context(&to_smb, far, None)
                .is_empty()
        );
        // SMB past depth 8 does not anchor the chain.
        let late = b"0123456789SMB powershell -w hidden";
        assert!(
            engine
                .evaluate_payload_with_context(&to_smb, late, None)
                .is_empty()
        );
    }

    #[test]
    fn compiles_hex_contents_and_an_independent_content() {
        let rules = compile(ET_RDP_COOKIE);
        assert!(
            rules[0]
                .imported
                .as_ref()
                .is_some_and(|i| i.inspection.is_some())
        );
        assert_eq!(rules[0].severity, Severity::Low);
        let engine = engine(rules);
        let to_rdp = event(OUTSIDE, 50000, INSIDE, 3389);
        let hit = b"\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00COOKIE: MSTSHASH=EDC\r\n";
        assert!(
            !engine
                .evaluate_payload_with_context(&to_rdp, hit, None)
                .is_empty()
        );
        let wrong_gap = b"\x03\x00\x00\x2b\x26\x26\xe0\x00\x00\x00\x00\x00Cookie: mstshash=edc\r\n";
        assert!(
            engine
                .evaluate_payload_with_context(&to_rdp, wrong_gap, None)
                .is_empty()
        );
    }

    #[test]
    fn compiles_a_threshold() {
        let rules = compile(ET_SCREENOS);
        assert_eq!(
            rules[0].threshold,
            Some(ThresholdConfig {
                threshold_type: ThresholdType::Limit,
                count: 1,
                window_secs: 60,
                track_by: TrackBy::SrcIp,
            })
        );
        assert_eq!(rules[0].severity, Severity::High);
    }

    #[test]
    fn runs_a_pcre_from_the_cursor_and_a_back_reference() {
        let fokirtor = engine(compile(ET_FOKIRTOR));
        let to_ssh = event(OUTSIDE, 50000, INSIDE, 22);
        let hit = |engine: &IdsEngine, e: &PacketEvent, payload: &[u8]| {
            !engine
                .evaluate_payload_with_context(e, payload, None)
                .is_empty()
        };
        assert!(hit(&fokirtor, &to_ssh, b"xx:!;.aGVsbG8="));
        // The pcre is anchored at the cursor the content left.
        assert!(!hit(&fokirtor, &to_ssh, b"xx:!;. aGVsbG8="));

        let oracle = engine(compile(ET_ORACLE_BACKREF));
        let to_sql = event(OUTSIDE, 50000, INSIDE, 1521);
        let call = b"DBMS_REPCAT.ADD_COLUMN_GROUP_TO_FLAVOR v := 'aaaaaaaaaaaa'; gname => v";
        assert!(hit(&oracle, &to_sql, call));
        let other = b"DBMS_REPCAT.ADD_COLUMN_GROUP_TO_FLAVOR v := 'aaaaaaaaaaaa'; gname => w";
        assert!(!hit(&oracle, &to_sql, other));
    }

    #[test]
    fn refuses_what_it_does_not_implement_and_names_the_keyword() {
        let cases = [
            (ET_HTTP, "http.method", "HTTP/1 parser"),
            (ET_FLOWBITS, "flowbits", "flow table"),
        ];
        for (text, keyword, reason) in cases {
            let refused = refusal(text);
            assert_eq!(refused.keyword, keyword, "{text}");
            assert!(refused.reason.contains(reason), "{}", refused.reason);
            assert!(refused.sid.is_some());
        }
    }

    #[test]
    fn refuses_headers_it_cannot_key_on() {
        let base = "(msg:\"x\"; content:\"abc\"; sid:1;)";
        let cases = [
            ("drop tcp any any -> any 80", "drop"),
            ("alert udp any any -> any 53", "udp"),
            ("alert tcp any any -> any any", "port"),
            ("alert tcp any 80 -> any 80", "port"),
            ("alert tcp any any <> any 80", "<>"),
            ("alert tcp any any -> any !80", "!80"),
            ("alert tcp any any -> any 1:1024", "1:1024"),
            ("alert tcp !any any -> any 80", "!any"),
            ("alert tcp $NOPE any -> any 80", "$NOPE"),
            ("alert tcp any any -> any $SHELLCODE_PORTS", "!80"),
        ];
        for (header, keyword) in cases {
            let refused = refusal(&format!("{header} {base}"));
            assert_eq!(refused.keyword, keyword, "{header}: {}", refused.reason);
            assert_eq!(refused.sid, Some(1));
        }
    }

    #[test]
    fn refuses_options_outside_the_subset() {
        let cases = [
            ("content:\"abcdef\"; depth:3;", "depth"),
            ("content:\"abc\"; dsize:>10;", "dsize"),
            ("content:\"abc\"; http.uri;", "http.uri"),
            ("content:\"abc\"; http_uri;", "http_uri"),
            ("content:\"abc\"; frobnicate;", "frobnicate"),
            ("flow:established;", "content"),
            (
                "content:\"abc\"; threshold: type limit, track by_rule, count 1, seconds 5;",
                "threshold",
            ),
            ("content:\"abc\"; flow:only_stream;", "flow"),
            ("content:\"abc\"; gid:3;", "gid"),
        ];
        for (options, keyword) in cases {
            let rule = format!("alert tcp any any -> any 80 (msg:\"x\"; {options} sid:7;)");
            let refused = refusal(&rule);
            assert_eq!(refused.keyword, keyword, "{options}: {}", refused.reason);
        }
    }

    #[test]
    fn anchors_startswith_and_endswith() {
        let rules = compile(
            "alert tcp any any -> any 80 (msg:\"x\"; content:\"GET \"; startswith; content:\"!\"; endswith; sid:9;)",
        );
        let engine = engine(rules);
        let e = event(OUTSIDE, 1, INSIDE, 80);
        assert!(
            !engine
                .evaluate_payload_with_context(&e, b"GET /now!", None)
                .is_empty()
        );
        assert!(
            engine
                .evaluate_payload_with_context(&e, b" GET /now!", None)
                .is_empty()
        );
        assert!(
            engine
                .evaluate_payload_with_context(&e, b"GET /now!.", None)
                .is_empty()
        );
    }

    #[test]
    fn independent_contents_match_in_either_order() {
        let engine = engine(compile(
            "alert tcp any any -> any 80 (msg:\"x\"; content:\"alpha\"; content:\"beta\"; sid:10;)",
        ));
        let e = event(OUTSIDE, 1, INSIDE, 80);
        assert!(
            !engine
                .evaluate_payload_with_context(&e, b"beta..alpha", None)
                .is_empty()
        );
        assert!(
            engine
                .evaluate_payload_with_context(&e, b"alpha only", None)
                .is_empty()
        );
    }

    #[test]
    fn variables_can_be_overridden() {
        let mut addresses = BTreeMap::new();
        addresses.insert("HOME_NET".to_string(), "[198.51.100.0/24]".to_string());
        let vars = SuricataVars::with_overrides(&addresses, &BTreeMap::new());
        let rules = match compile_rule(ET_SMTP_EXPN, &vars) {
            Ok(rules) => rules,
            Err(refused) => panic!("{}", refused.reason),
        };
        let engine = engine(rules);
        let into_home = event(INSIDE, 1, [198, 51, 100, 7], 25);
        assert!(
            !engine
                .evaluate_payload_with_context(&into_home, b"expn root", None)
                .is_empty()
        );
    }

    #[test]
    fn a_ruleset_reports_every_refusal_with_its_line() {
        let text = format!(
            "# a comment\n\n{ET_SMTP_EXPN}\n#{ET_PCANYWHERE}\n{ET_FLOWBITS}\nalert tcp any any -> any 80 (msg:\"cont\"; \\\n content:\"abc\"; sid:42;)\n{ET_SMTP_EXPN}\n"
        );
        let ruleset = compile_ruleset(&text, &vars());
        let report = &ruleset.report;
        assert_eq!(report.total, 4);
        assert_eq!(report.compiled, 2);
        assert_eq!(report.native_rules, 2);
        assert_eq!(report.disabled, 1);
        let lines: Vec<(usize, &str)> = report
            .refused
            .iter()
            .map(|r| (r.line, r.keyword.as_str()))
            .collect();
        assert_eq!(lines, [(5, "flowbits"), (8, "sid")]);
        assert!((report.refused_share() - 0.5).abs() < f64::EPSILON);
        assert_eq!(
            report.refusals_by_keyword(),
            [("flowbits".to_string(), 1), ("sid".to_string(), 1)]
        );
        assert_eq!(ruleset.rules.len(), 2);
    }

    #[test]
    fn a_sid_is_one_rule_across_the_rulesets_of_an_import() {
        let first = format!("{ET_SMTP_EXPN}\n");
        let second = format!("{ET_SMTP_EXPN}\n{ET_FLOWBITS}\n");
        let import = compile_rulesets(
            [
                ("smtp.rules".to_string(), first.as_str()),
                ("mixed.rules".to_string(), second.as_str()),
            ],
            &vars(),
        );
        assert_eq!(import.rules.len(), 1);
        let sources: Vec<&str> = import.rulesets.iter().map(|r| r.source.as_str()).collect();
        assert_eq!(sources, ["smtp.rules", "mixed.rules"]);
        assert_eq!(import.rulesets[0].report.compiled, 1);
        let later = &import.rulesets[1].report;
        assert_eq!(later.compiled, 0);
        assert_eq!(later.refused.len(), 2);
        assert_eq!(later.refused[0].keyword, "sid");

        // The first ruleset loads whole, the second refuses every rule.
        assert_eq!(
            import.over_share(0.5).map(|r| r.source.as_str()),
            Some("mixed.rules")
        );
        assert!(import.over_share(1.0).is_none());
    }

    #[test]
    fn an_imported_content_rule_holds_no_kernel_slot() {
        let rules = compile_rule(ET_SMTP_EXPN, &vars()).unwrap();
        assert!(!rules[0].pattern.is_empty());
        assert!(rules[0].to_ebpf_keys().is_empty());
        assert!(rules[0].to_ebpf_src_keys().is_empty());
    }

    #[test]
    fn a_ruleset_report_serialises_flat_with_its_source() {
        let import = compile_rulesets([("x.rules".to_string(), ET_FLOWBITS)], &vars());
        let json = serde_json::to_value(&import.rulesets[0]).unwrap();
        assert_eq!(json["source"], "x.rules");
        assert_eq!(json["total"], 1);
        assert_eq!(json["refused"][0]["keyword"], "flowbits");
    }

    #[test]
    fn every_keyword_row_is_named_once() {
        let mut seen = HashSet::new();
        for row in KEYWORDS {
            assert!(seen.insert(row.keyword), "{} twice", row.keyword);
            assert!(!row.note.is_empty());
        }
    }

    #[test]
    fn every_keyword_the_parser_reads_has_a_row() {
        use crate::ids::sig::{buffers, parse};
        let mut names: Vec<&str> = Vec::new();
        for def in buffers::BUFFERS {
            names.push(def.name);
            names.extend(def.aliases);
            names.extend(def.modifier);
        }
        names.extend(buffers::FIELDS.iter().map(|field| field.name));
        names.extend(parse::TRANSFORMS.iter().map(|(name, _)| *name));
        let missing: Vec<&str> = names
            .into_iter()
            .filter(|name| table_row(name).is_none())
            .collect();
        assert!(missing.is_empty(), "no row for {missing:?}");
    }

    #[test]
    fn garbage_is_refused_never_a_panic() {
        for text in [
            "",
            "alert",
            "alert tcp any any -> any 80 (",
            "alert tcp any any -> any 80 (sid:1; content:\"|4|\";)",
            "alert tcp any any -> any 80 (sid:1; content:\"abc)",
            "alert tcp [any any -> any 80 (sid:1;)",
            "alert tcp any any -> any 80 (sid:x;)",
            "alert tcp 1.2.3.4/40 any -> any 80 (sid:1; content:\"a\";)",
            "alert tcp any any -> any 80 (sid:1; pcre:\"/(/\";)",
            "alert tcp any any -> any 80 (sid:1; nocase;)",
        ] {
            assert!(compile_rule(text, &vars()).is_err(), "{text}");
        }
    }
}
