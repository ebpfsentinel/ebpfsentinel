//! From the text of a rule to a [`Signature`]: every keyword of the Suricata 8
//! documentation is read into a typed value and its arguments are checked the
//! way the documentation states them. A rule that is not valid Suricata is
//! refused here, naming the keyword; whether the engine can inspect what a
//! valid rule asks for is decided after, from the keyword table.

use std::collections::BTreeSet;

use super::buffers::{self, BufferDef, FieldArg};
use super::int::{IntMatch, IntOp, number, signed};
use super::model::{
    APP_PROTOCOLS, Action, Base64Decode, BitOp, BitScope, Bits, Buffer, BufferList, ByteExtract,
    ByteJump, ByteMath, ByteOp, ByteRead, ByteTest, Capture, Check, Content, DatasetMatch,
    Direction, Endian, Entropy, FastPattern, FloatMatch, FlowCounter, FlowMatch, Flowint,
    FlowintOp, Header, HeaderField, IsDataAt, Match, MathOp, NumBase, Pcre, PortMatch, PortSide,
    ProtoMode, RuleProto, Signature, StreamSide, Tag, TcpFlags, TcpFlagsMode, Threshold,
    ThresholdKind, Track, Transform, Value,
};
use crate::ids::suricata::{
    Compiled, MAX_VARIABLE_DEPTH, Refused, SuricataVars, decode_content, parse_addresses,
    parse_options, split_header, split_list, unescape, unquote,
};

/// The transforms that take an argument, and whether it is required.
pub(crate) const TRANSFORMS: &[(&str, Option<bool>)] = &[
    ("to_lowercase", None),
    ("to_uppercase", None),
    ("to_md5", None),
    ("to_sha1", None),
    ("to_sha256", None),
    ("strip_whitespace", None),
    ("compress_whitespace", None),
    ("url_decode", None),
    ("header_lowercase", None),
    ("dotprefix", None),
    ("strip_pseudo_headers", None),
    ("gunzip", Some(false)),
    ("zlib_deflate", Some(false)),
    ("domain", None),
    ("tld", None),
    ("from_base64", Some(false)),
    ("pcrexform", Some(true)),
    ("xor", Some(true)),
    ("luaxform", Some(true)),
];

/// The keywords that are out of scope: read without their arguments being
/// typed, refused afterwards by the keyword table.
const UNTYPED: &[&str] = &[
    "lua",
    "luajit",
    "replace",
    "filestore",
    "filemagic",
    "file.magic",
    "bypass",
    "nfq_set_mark",
    "config",
    "tls_store",
    "tls.store",
];

/// The PCRE flags, buffer flags included.
const PCRE_FLAGS: &str = "ismxAEGRUIPHDMCSYVWBOQ";

/// The largest `byte_*` read.
const MAX_BYTES: u64 = 10;
/// The largest `byte_*` read of a number written as text.
const MAX_STRING_BYTES: u64 = 23;

fn bad(keyword: &str, reason: impl Into<String>) -> Refused {
    Refused::new(keyword, reason)
}

/// Parse one rule.
///
/// # Errors
///
/// The refusal naming the keyword (or the header part) that is not valid
/// Suricata, with the rule's sid when it was read.
pub fn parse_signature(text: &str, vars: &SuricataVars) -> Compiled<Signature> {
    let text = text.trim();
    let open = text
        .find('(')
        .ok_or_else(|| bad("rule", "has no option list in parentheses"))?;
    let close = text
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or_else(|| bad("rule", "has an option list that is never closed"))?;
    if !text[close + 1..].trim().is_empty() {
        return Err(bad("rule", "has text after its option list"));
    }
    let options = parse_options(&text[open + 1..close])?;
    let sid = options
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("sid"))
        .ok_or_else(|| bad("sid", "is missing, and a rule is named by it"))?;
    let sid = sid
        .1
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|sid| *sid != 0)
        .ok_or_else(|| bad("sid", format!("'{}' is not a number from 1", sid.1.trim())))?;
    let with_sid = |mut refused: Refused| {
        refused.sid = Some(sid);
        refused
    };
    let header = parse_header(&text[..open], vars).map_err(with_sid)?;
    let mut builder = Builder::new(header, sid);
    for (key, value) in &options {
        builder.option(key, value).map_err(with_sid)?;
    }
    builder.finish().map_err(with_sid)
}

// ── Header ───────────────────────────────────────────────────────

fn parse_header(text: &str, vars: &SuricataVars) -> Compiled<Header> {
    let tokens = split_header(text)?;
    let [action, proto, src, src_ports, direction, dst, dst_ports] = tokens.as_slice() else {
        return Err(bad(
            "header",
            "is not 'action protocol source port direction destination port'",
        ));
    };
    let action = Action::parse(action).ok_or_else(|| bad(action, "is not a rule action"))?;
    let proto = RuleProto::parse(proto).ok_or_else(|| bad(proto, "is not a rule protocol"))?;
    let direction = match direction.as_str() {
        "->" => Direction::OneWay,
        "<>" => Direction::Both,
        "=>" => Direction::Transactional,
        other => return Err(bad(other, "is not a direction")),
    };
    Ok(Header {
        action,
        proto,
        src: parse_addresses(src, vars, 0)?.into_match(src)?,
        src_ports: parse_ports(src_ports, vars, 0)?,
        direction,
        dst: parse_addresses(dst, vars, 0)?.into_match(dst)?,
        dst_ports: parse_ports(dst_ports, vars, 0)?,
    })
}

/// A port set with variables, lists, ranges and negation.
pub(crate) fn parse_ports(token: &str, vars: &SuricataVars, depth: usize) -> Compiled<PortMatch> {
    if depth > MAX_VARIABLE_DEPTH {
        return Err(bad(
            token,
            "refers through more variables than are followed",
        ));
    }
    let token = token.trim();
    if token == "any" {
        return Ok(PortMatch {
            any: true,
            ..PortMatch::default()
        });
    }
    if let Some(negated) = token.strip_prefix('!') {
        let inner = parse_ports(negated, vars, depth + 1)?;
        if inner.any {
            return Err(bad(token, "negates every port"));
        }
        if !inner.outside.is_empty() {
            return Err(bad(token, "negates a list that already holds a negation"));
        }
        return Ok(PortMatch {
            any: false,
            within: Vec::new(),
            outside: inner.within,
        });
    }
    if let Some(body) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        let mut set = PortMatch::default();
        for item in split_list(body) {
            let part = parse_ports(item, vars, depth + 1)?;
            set.any |= part.any;
            set.within.extend(part.within);
            set.outside.extend(part.outside);
        }
        if set.any && set.within.is_empty() && set.outside.is_empty() {
            return Ok(set);
        }
        if !set.any && set.within.is_empty() && set.outside.is_empty() {
            return Err(bad(token, "names no port at all"));
        }
        return Ok(set);
    }
    if let Some(name) = token.strip_prefix('$') {
        let value = vars
            .ports
            .get(name)
            .ok_or_else(|| bad(token, "names a port variable that has no value"))?;
        return parse_ports(value, vars, depth + 1);
    }
    let not_a_port = || bad(token, "is not a port, a range or a variable");
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
        return Err(bad(token, "is a range that ends before it starts"));
    }
    Ok(PortMatch {
        any: false,
        within: vec![(low, high)],
        outside: Vec::new(),
    })
}

// ── Options ──────────────────────────────────────────────────────

/// Where the last content or pcre sits, for the modifiers after it.
#[derive(Clone, Copy)]
struct Last {
    list: usize,
    index: usize,
}

struct Builder {
    sig: Signature,
    /// The list new matches go to.
    current: usize,
    last: Option<Last>,
    /// Names `byte_extract` and `byte_math` have defined so far.
    defined: BTreeSet<String>,
    seen_sid: bool,
    /// The keywords Suricata accepts once per rule, seen so far.
    once: BTreeSet<&'static str>,
}

impl Builder {
    fn new(header: Header, sid: u32) -> Self {
        Self {
            sig: Signature {
                header,
                sid,
                rev: 0,
                gid: 1,
                msg: String::new(),
                classtype: None,
                priority: None,
                references: Vec::new(),
                metadata: Vec::new(),
                target: None,
                flow: FlowMatch::default(),
                lists: vec![BufferList {
                    buffer: Buffer::Payload,
                    transforms: Vec::new(),
                    matches: Vec::new(),
                }],
                checks: Vec::new(),
                noalert: false,
                threshold: None,
                detection_filter: None,
                tag: None,
                keywords: Vec::new(),
            },
            current: 0,
            last: None,
            defined: BTreeSet::new(),
            seen_sid: false,
            once: BTreeSet::new(),
        }
    }

    fn finish(mut self) -> Compiled<Signature> {
        for list in &self.sig.lists {
            if let Buffer::Sticky(name) = list.buffer
                && list.matches.is_empty()
            {
                return Err(bad(name, "is selected and no match follows it"));
            }
            if list.matches.len() > 1
                && list
                    .matches
                    .iter()
                    .any(|m| matches!(m, Match::Absent { or_else: false }))
            {
                return Err(bad(
                    "absent",
                    "is followed by a match in its buffer without 'or_else'",
                ));
            }
        }
        self.sig.lists.retain(|list| {
            list.buffer != Buffer::Payload
                || !list.matches.is_empty()
                || !list.transforms.is_empty()
        });
        Ok(self.sig)
    }

    /// Refuse a keyword Suricata accepts once per rule, the second time.
    fn once(&mut self, k: &str) -> Compiled<()> {
        let name = match k {
            "flow" => "flow",
            "dsize" => "dsize",
            _ => return Ok(()),
        };
        if !self.once.insert(name) {
            return Err(bad(k, "is written twice"));
        }
        Ok(())
    }

    fn option(&mut self, key: &str, value: &str) -> Compiled<()> {
        let keyword = key.to_ascii_lowercase();
        let k = keyword.as_str();
        self.sig.keywords.push(keyword.clone());
        if self.meta(k, value)?
            || self.content_modifier(k, value)?
            || self.payload(k, value)?
            || self.bytes(k, value)?
            || self.flow_state(k, value)?
            || self.packet(k, value)?
            || self.application(k, value)?
        {
            return Ok(());
        }
        if UNTYPED.contains(&k) {
            return Ok(());
        }
        Err(bad(k, "is not a Suricata keyword"))
    }

    fn list(&mut self) -> &mut BufferList {
        let index = self.current.min(self.sig.lists.len().saturating_sub(1));
        &mut self.sig.lists[index]
    }

    fn push_match(&mut self, item: Match) {
        let is_anchor = matches!(item, Match::Content(_));
        let list = self.current;
        let matches = &mut self.sig.lists[list].matches;
        matches.push(item);
        if is_anchor {
            self.last = Some(Last {
                list,
                index: matches.len() - 1,
            });
        }
    }

    fn select(&mut self, buffer: Buffer) {
        self.sig.lists.push(BufferList {
            buffer,
            transforms: Vec::new(),
            matches: Vec::new(),
        });
        self.current = self.sig.lists.len() - 1;
    }

    fn select_payload(&mut self) {
        if let Some(index) = self
            .sig
            .lists
            .iter()
            .position(|l| l.buffer == Buffer::Payload)
        {
            self.current = index;
        } else {
            self.select(Buffer::Payload);
        }
    }

    fn value(&self, keyword: &str, text: &str) -> Compiled<Value> {
        let text = text.trim();
        if let Ok(n) = signed(text) {
            return Ok(Value::Lit(n));
        }
        if self.defined.contains(text) {
            return Ok(Value::Var(text.to_string()));
        }
        Err(bad(
            keyword,
            format!(
                "'{text}' is neither a number nor a name byte_extract or byte_math defined before"
            ),
        ))
    }

    /// A content position: a number, as Suricata reads it from the start of
    /// the argument and ignoring what follows, or a defined name.
    fn position(&self, keyword: &str, text: &str) -> Compiled<Value> {
        let text = text.trim();
        if self.defined.contains(text) {
            return Ok(Value::Var(text.to_string()));
        }
        let lead = if let Some(hex) = text.strip_prefix("0x") {
            let end = hex
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(hex.len());
            &text[..2 + end]
        } else {
            let sign = usize::from(text.starts_with('-'));
            let end = text[sign..]
                .find(|c: char| !c.is_ascii_digit())
                .map_or(text.len(), |i| i + sign);
            &text[..end]
        };
        signed(lead).map(Value::Lit).map_err(|_| {
            bad(
                keyword,
                format!(
                    "'{text}' is neither a number nor a name byte_extract or byte_math defined before"
                ),
            )
        })
    }

    // ── meta ─────────────────────────────────────────────────────

    fn meta(&mut self, k: &str, value: &str) -> Compiled<bool> {
        match k {
            "msg" => self.sig.msg = unescape(unquote(k, value)?),
            "sid" => {
                if self.seen_sid {
                    return Err(bad(k, "is written twice"));
                }
                self.seen_sid = true;
            }
            "rev" => self.sig.rev = plain_u32(k, value)?,
            "gid" => self.sig.gid = plain_u32(k, value)?,
            "classtype" => {
                if value.is_empty()
                    || !value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Err(bad(k, format!("'{value}' is not a classification name")));
                }
                self.sig.classtype = Some(value.to_string());
            }
            "priority" => {
                let p = plain_u32(k, value)?;
                self.sig.priority = Some(u8::try_from(p).unwrap_or(u8::MAX));
            }
            "reference" => {
                let (kind, id) = value
                    .split_once(',')
                    .ok_or_else(|| bad(k, "is not 'type, identifier'"))?;
                if kind.trim().is_empty() || id.trim().is_empty() {
                    return Err(bad(k, "is not 'type, identifier'"));
                }
                self.sig.references.push(value.to_string());
            }
            "metadata" => self.sig.metadata.push(value.to_string()),
            "target" => match value {
                "src_ip" | "dest_ip" => self.sig.target = Some(value.to_string()),
                _ => return Err(bad(k, "is neither 'src_ip' nor 'dest_ip'")),
            },
            "threshold" | "detection_filter" => {
                let parsed = parse_threshold(k, value)?;
                // Suricata keeps one of either per rule, and refuses a second
                // only when no sticky buffer is selected as it is read.
                if self.sig.threshold.is_some() || self.sig.detection_filter.is_some() {
                    if self.list().buffer == Buffer::Payload {
                        return Err(bad(
                            k,
                            "is a second threshold or detection_filter on one rule",
                        ));
                    }
                } else if k == "threshold" {
                    self.sig.threshold = Some(parsed);
                } else {
                    self.sig.detection_filter = Some(parsed);
                }
            }
            "tag" => self.sig.tag = Some(parse_tag(value)?),
            "noalert" => {
                expect_empty(k, value)?;
                self.sig.noalert = true;
            }
            "prefilter" => expect_empty(k, value)?,
            "requires" => {
                let pairs = word_pairs(k, value)?;
                self.sig.checks.push(Check::Requires(pairs));
            }
            "flow" => {
                self.once(k)?;
                parse_flow(&mut self.sig.flow, value)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    // ── content and its modifiers ───────────────────────────────

    fn last_content(&mut self, k: &str) -> Compiled<&mut Content> {
        let Some(last) = self.last else {
            return Err(bad(k, "modifies no content before it"));
        };
        match self.sig.lists[last.list].matches.get_mut(last.index) {
            Some(Match::Content(content)) => Ok(content),
            _ => Err(bad(k, "modifies no content before it")),
        }
    }

    fn content_modifier(&mut self, k: &str, value: &str) -> Compiled<bool> {
        match k {
            "nocase" => {
                expect_empty(k, value)?;
                let content = self.last_content(k)?;
                if content.nocase {
                    return Err(bad(k, "is written twice on one content"));
                }
                content.nocase = true;
            }
            "rawbytes" => {
                expect_empty(k, value)?;
                let content = self.last_content(k)?;
                if content.rawbytes {
                    return Err(bad(k, "is written twice on one content"));
                }
                content.rawbytes = true;
            }
            "startswith" | "endswith" => {
                expect_empty(k, value)?;
                let content = self.last_content(k)?;
                if content.startswith && k == "startswith" || content.endswith && k == "endswith" {
                    return Err(bad(k, "is written twice on one content"));
                }
                if k == "startswith" {
                    if content.offset.is_some() || content.depth.is_some() || content.is_relative()
                    {
                        return Err(bad(
                            k,
                            "cannot be combined with offset, depth, distance or within",
                        ));
                    }
                    content.startswith = true;
                } else {
                    content.endswith = true;
                }
            }
            "offset" | "depth" | "distance" | "within" => {
                let v = self.position(k, value)?;
                let content = self.last_content(k)?;
                set_position(content, k, v)?;
            }
            "fast_pattern" => {
                let fp = parse_fast_pattern(value)?;
                let others = self
                    .sig
                    .lists
                    .iter()
                    .flat_map(|l| &l.matches)
                    .filter(|m| matches!(m, Match::Content(c) if c.fast_pattern.is_some()))
                    .count();
                let content = self.last_content(k)?;
                if content.fast_pattern.is_some() {
                    return Err(bad(k, "is written twice on one content"));
                }
                if others > 0 {
                    return Err(bad(k, "is set on a second content of the rule"));
                }
                if content.negated && fp != FastPattern::Whole {
                    return Err(bad(k, "takes no argument on a negated content"));
                }
                if fp == FastPattern::Only && content.has_position() {
                    return Err(bad(
                        k,
                        "'only' cannot be combined with offset, depth, distance or within",
                    ));
                }
                if let FastPattern::Slice { offset, length } = fp
                    && usize::from(offset) + usize::from(length) > content.bytes.len()
                {
                    return Err(bad(k, "takes a slice longer than its content"));
                }
                content.fast_pattern = Some(fp);
            }
            other => {
                let Some(def) = buffers::modifier(other) else {
                    return Ok(false);
                };
                expect_empty(k, value)?;
                self.move_last(k, def)?;
            }
        }
        Ok(true)
    }

    /// A legacy content modifier: the content before it moves into the
    /// buffer it names.
    fn move_last(&mut self, k: &str, def: &'static BufferDef) -> Compiled<()> {
        let Some(last) = self.last else {
            return Err(bad(k, "modifies no content before it"));
        };
        if self.sig.lists[last.list].buffer != Buffer::Payload {
            return Err(bad(k, "follows a content already in a sticky buffer"));
        }
        if last.index + 1 != self.sig.lists[last.list].matches.len() {
            return Err(bad(k, "modifies a content that is not the last match"));
        }
        let Some(item) = self.sig.lists[last.list].matches.pop() else {
            return Err(bad(k, "modifies no content before it"));
        };
        if !matches!(item, Match::Content(_)) {
            return Err(bad(k, "modifies no content before it"));
        }
        let buffer = Buffer::Sticky(def.name);
        let list = if let Some(index) = self
            .sig
            .lists
            .iter()
            .rposition(|l| l.buffer == buffer && l.transforms.is_empty())
        {
            index
        } else {
            self.sig.lists.push(BufferList {
                buffer,
                transforms: Vec::new(),
                matches: Vec::new(),
            });
            self.sig.lists.len() - 1
        };
        self.sig.lists[list].matches.push(item);
        self.last = Some(Last {
            list,
            index: self.sig.lists[list].matches.len() - 1,
        });
        Ok(())
    }

    // ── payload matches, buffers and transforms ─────────────────

    fn payload(&mut self, k: &str, value: &str) -> Compiled<bool> {
        match k {
            "content" | "uricontent" => {
                let content = parse_content(k, value)?;
                if k == "uricontent" {
                    self.select(Buffer::Sticky("http.uri"));
                }
                if matches!(self.list().buffer, Buffer::Sticky("ja3.hash" | "ja3s.hash"))
                    && content.bytes.len() != 32
                {
                    return Err(bad(
                        k,
                        "is not the 32 hexadecimal digits of an MD5 in a JA3 hash buffer",
                    ));
                }
                self.push_match(Match::Content(content));
            }
            "pcre" => self.pcre(value)?,
            "pkt_data" => {
                expect_empty(k, value)?;
                self.select_payload();
            }
            "base64_data" => {
                expect_empty(k, value)?;
                self.select(Buffer::Base64Data);
            }
            "base64_decode" => {
                let decode = parse_base64_decode(value)?;
                self.push_match(Match::Base64Decode(decode));
            }
            "isdataat" => {
                let mut parts = split_args(value);
                let first = parts.next().unwrap_or_default();
                let (negated, at) = match first.strip_prefix('!') {
                    Some(rest) => (true, rest),
                    None => (false, first),
                };
                let at = self.value(k, at)?;
                let (mut relative, mut rawbytes) = (false, false);
                for word in parts {
                    match word {
                        "relative" => relative = true,
                        "rawbytes" => rawbytes = true,
                        other => return Err(bad(k, format!("'{other}' is not an option of it"))),
                    }
                }
                self.push_match(Match::IsDataAt(IsDataAt {
                    negated,
                    at,
                    relative,
                    rawbytes,
                }));
            }
            "bsize" => {
                if self.list().buffer == Buffer::Payload {
                    return Err(bad(k, "measures a sticky buffer, and none is selected"));
                }
                let m = IntMatch::parse(value, u64::MAX).map_err(|e| bad(k, e))?;
                self.push_match(Match::Bsize(m));
            }
            "urilen" => {
                let (spec, raw) = match value.split_once(',') {
                    Some((spec, kind)) => match kind.trim() {
                        "norm" => (spec, false),
                        "raw" => (spec, true),
                        other => {
                            return Err(bad(k, format!("'{other}' is neither 'norm' nor 'raw'")));
                        }
                    },
                    None => (value, false),
                };
                let m = IntMatch::parse(spec, u64::from(u16::MAX)).map_err(|e| bad(k, e))?;
                // urilen measures the URI without selecting it: the matches
                // after it stay where they were.
                let buffer = Buffer::Sticky(if raw { "http.uri.raw" } else { "http.uri" });
                let list = if let Some(index) = self
                    .sig
                    .lists
                    .iter()
                    .rposition(|l| l.buffer == buffer && l.transforms.is_empty())
                {
                    index
                } else {
                    self.sig.lists.push(BufferList {
                        buffer,
                        transforms: Vec::new(),
                        matches: Vec::new(),
                    });
                    self.sig.lists.len() - 1
                };
                self.sig.lists[list].matches.push(Match::Bsize(m));
            }
            _ => return self.payload_extra(k, value),
        }
        Ok(true)
    }

    /// The payload keywords that are not a content, a pcre or a buffer
    /// switch.
    fn payload_extra(&mut self, k: &str, value: &str) -> Compiled<bool> {
        match k {
            "entropy" => {
                let entropy = parse_entropy(value)?;
                self.push_match(Match::Entropy(entropy));
            }
            "absent" => {
                let or_else = match value {
                    "" => false,
                    "or_else" => true,
                    other => return Err(bad(k, format!("'{other}' is not 'or_else'"))),
                };
                let list = self.list();
                if list.buffer == Buffer::Payload || !list.matches.is_empty() {
                    return Err(bad(k, "must directly follow a sticky buffer"));
                }
                self.push_match(Match::Absent { or_else });
            }
            "asn1" => {
                let options = parse_asn1(value)?;
                self.push_match(Match::Asn1(options));
            }
            "dataset" | "datarep" => {
                if self.list().buffer == Buffer::Payload {
                    return Err(bad(k, "looks up a sticky buffer, and none is selected"));
                }
                let m = parse_dataset(k, value, k == "datarep")?;
                self.push_match(Match::Dataset(m));
            }
            _ => {
                if let Some(def) = buffers::sticky(k) {
                    expect_empty(k, value)?;
                    self.select(Buffer::Sticky(def.name));
                    return Ok(true);
                }
                if let Some((_, takes)) = TRANSFORMS.iter().find(|(name, _)| *name == k) {
                    self.transform(k, value, *takes)?;
                    return Ok(true);
                }
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn transform(&mut self, k: &str, value: &str, takes: Option<bool>) -> Compiled<()> {
        let argument = match (takes, value.is_empty()) {
            (None | Some(false), true) => None,
            (None, false) => return Err(bad(k, "takes no argument")),
            (Some(true), true) => return Err(bad(k, "needs an argument")),
            (Some(_), false) => Some(value.to_string()),
        };
        match (k, argument.as_deref()) {
            ("xor", Some(key)) => {
                let key = unquote(k, key)?;
                if key.is_empty()
                    || key.len() % 2 != 0
                    || !key.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(bad(k, "takes a quoted even-length hex key"));
                }
            }
            ("pcrexform", Some(expr)) => {
                super::inspect::check_pcrexform(unquote(k, expr)?)?;
            }
            _ => {}
        }
        let list = self.list();
        if list.buffer == Buffer::Payload {
            return Err(bad(k, "transforms a sticky buffer, and none is selected"));
        }
        list.transforms.push(Transform {
            name: k.to_string(),
            argument,
        });
        Ok(())
    }

    fn pcre(&mut self, value: &str) -> Compiled<()> {
        let k = "pcre";
        let (negated, quoted) = match value.strip_prefix('!') {
            Some(rest) => (true, rest.trim_start()),
            None => (false, value),
        };
        let inner = if quoted.starts_with('"') {
            unquote(k, quoted)?
        } else {
            quoted
        };
        let (expression, flags, captures) = split_pcre(inner)?;
        let mut buffer_flag: Option<&'static BufferDef> = None;
        for flag in flags.chars() {
            if let Some(def) = buffers::pcre_flag(flag) {
                if buffer_flag.is_some_and(|b| b != def) {
                    return Err(bad(k, "names two buffers in its flags"));
                }
                buffer_flag = Some(def);
            }
        }
        let relative = flags.contains('R');
        let pcre = Pcre {
            expression,
            flags: flags.chars().filter(|c| "ismxAEGOB".contains(*c)).collect(),
            relative,
            negated,
            captures,
        };
        // PCRE2 refuses what Suricata, built on it, refuses.
        super::inspect::check_pcre(&pcre)?;
        let target = match buffer_flag {
            Some(def) => Buffer::Sticky(def.name),
            None => self.list().buffer.clone(),
        };
        // Inside a sticky buffer `R` may open it; outside, it needs a match
        // before it in the buffer it reads.
        let in_sticky = self.list().buffer != Buffer::Payload;
        if relative
            && !in_sticky
            && !self
                .sig
                .lists
                .iter()
                .any(|l| l.buffer == target && !l.matches.is_empty())
        {
            return Err(bad(
                k,
                "is relative ('R') with no match before it in its buffer",
            ));
        }
        let current = self.list().buffer.clone();
        if let Some(def) = buffer_flag
            && current != Buffer::Payload
        {
            // file.data is the response body when the flow is HTTP.
            let same = current == Buffer::Sticky(def.name)
                || current == Buffer::Sticky("file.data") && def.name == "http.response_body";
            if !same {
                return Err(bad(
                    k,
                    "names a buffer in its flags other than the sticky buffer it is in",
                ));
            }
            self.push_match(Match::Pcre(pcre));
        } else if let Some(def) = buffer_flag {
            let buffer = Buffer::Sticky(def.name);
            let previous = self.current;
            if let Some(index) = self.sig.lists.iter().rposition(|l| l.buffer == buffer) {
                self.current = index;
            } else {
                self.select(buffer);
            }
            self.push_match(Match::Pcre(pcre));
            self.current = previous;
        } else {
            self.push_match(Match::Pcre(pcre));
        }
        Ok(())
    }

    // ── byte_* ───────────────────────────────────────────────────

    fn bytes(&mut self, k: &str, value: &str) -> Compiled<bool> {
        match k {
            "byte_test" => {
                let test = self.parse_byte_test(value)?;
                self.push_match(Match::ByteTest(test));
            }
            "byte_jump" => {
                let jump = self.parse_byte_jump(value)?;
                self.push_match(Match::ByteJump(jump));
            }
            "byte_extract" => {
                let extract = parse_byte_extract(value)?;
                self.defined.insert(extract.name.clone());
                self.push_match(Match::ByteExtract(extract));
            }
            "byte_math" => {
                let math = self.parse_byte_math(value)?;
                self.defined.insert(math.result.clone());
                self.push_match(Match::ByteMath(math));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn nbytes(&self, k: &str, text: &str) -> Compiled<Value> {
        let v = self.value(k, text)?;
        if let Value::Lit(n) = v
            && !(0..=i64::try_from(MAX_STRING_BYTES).unwrap_or(i64::MAX)).contains(&n)
        {
            return Err(bad(
                k,
                format!("reads {n} bytes, outside 0 to {MAX_STRING_BYTES}"),
            ));
        }
        Ok(v)
    }

    fn parse_byte_test(&self, value: &str) -> Compiled<ByteTest> {
        let k = "byte_test";
        let args: Vec<&str> = split_args(value).collect();
        let [nbytes, op, test, offset, rest @ ..] = args.as_slice() else {
            return Err(bad(k, "is not 'bytes, operator, value, offset'"));
        };
        let nbytes = self.nbytes(k, nbytes)?;
        let (negated, op) = match op.strip_prefix('!') {
            Some(rest) => (true, rest.trim()),
            None => (false, *op),
        };
        let op = match op {
            "<" => ByteOp::Lt,
            ">" => ByteOp::Gt,
            "=" | "" if !op.is_empty() || negated => ByteOp::Eq,
            "<=" => ByteOp::Le,
            ">=" => ByteOp::Ge,
            "&" => ByteOp::And,
            "^" => ByteOp::Xor,
            other => return Err(bad(k, format!("'{other}' is not an operator"))),
        };
        let test = self.value(k, test)?;
        let offset = self.value(k, offset)?;
        let mut read = ByteRead::default();
        let mut words = rest.iter().copied();
        while let Some(word) = words.next() {
            if !read_option(&mut read, word, &mut words, k)? {
                return Err(bad(k, format!("'{word}' is not an option of it")));
            }
        }
        check_width(k, &nbytes, &read)?;
        Ok(ByteTest {
            nbytes,
            negated,
            op,
            value: test,
            offset,
            read,
        })
    }

    fn parse_byte_jump(&self, value: &str) -> Compiled<ByteJump> {
        let k = "byte_jump";
        let args: Vec<&str> = split_args(value).collect();
        let [nbytes, offset, rest @ ..] = args.as_slice() else {
            return Err(bad(k, "is not 'bytes, offset'"));
        };
        let mut jump = ByteJump {
            nbytes: self.nbytes(k, nbytes)?,
            offset: self.value(k, offset)?,
            read: ByteRead::default(),
            multiplier: 1,
            align: false,
            from_beginning: false,
            from_end: false,
            post_offset: 0,
        };
        let mut words = rest.iter().copied();
        while let Some(word) = words.next() {
            if read_option(&mut jump.read, word, &mut words, k)? {
                continue;
            }
            let (name, arg) = word
                .split_once(' ')
                .map_or((word, ""), |(n, a)| (n, a.trim()));
            match name {
                "align" => jump.align = true,
                "from_beginning" => jump.from_beginning = true,
                "from_end" => jump.from_end = true,
                "multiplier" => {
                    jump.multiplier = u32::try_from(number(arg).map_err(|e| bad(k, e))?)
                        .ok()
                        .filter(|m| (1..=65535).contains(m))
                        .ok_or_else(|| bad(k, "has a multiplier outside 1 to 65535"))?;
                }
                "post_offset" => jump.post_offset = signed(arg).map_err(|e| bad(k, e))?,
                _ => return Err(bad(k, format!("'{word}' is not an option of it"))),
            }
        }
        if jump.from_beginning && jump.from_end {
            return Err(bad(k, "cannot jump from both the beginning and the end"));
        }
        if !jump.from_end {
            check_width(k, &jump.nbytes, &jump.read)?;
        }
        Ok(jump)
    }

    fn parse_byte_math(&self, value: &str) -> Compiled<ByteMath> {
        let k = "byte_math";
        let mut nbytes = None;
        let mut offset = None;
        let mut oper = None;
        let mut rvalue = None;
        let mut result = None;
        let mut read = ByteRead::default();
        let args: Vec<&str> = split_args(value).collect();
        let mut words = args.iter().copied();
        while let Some(word) = words.next() {
            let (name, arg) = word
                .split_once(' ')
                .map_or((word, ""), |(n, a)| (n, a.trim()));
            match name {
                "bytes" => {
                    let n = self.nbytes(k, arg)?;
                    if let Value::Lit(n) = n
                        && !(1..=10).contains(&n)
                    {
                        return Err(bad(k, format!("reads {n} bytes, outside 1 to 10")));
                    }
                    nbytes = Some(n);
                }
                "offset" => offset = Some(signed(arg).map_err(|e| bad(k, e))?),
                "oper" => {
                    oper = Some(match arg {
                        "+" => MathOp::Add,
                        "-" => MathOp::Sub,
                        "*" => MathOp::Mul,
                        "/" => MathOp::Div,
                        "<<" => MathOp::Shl,
                        ">>" => MathOp::Shr,
                        other => return Err(bad(k, format!("'{other}' is not an operator"))),
                    });
                }
                "rvalue" => rvalue = Some(self.value(k, arg)?),
                "result" => {
                    if !is_name(arg) {
                        return Err(bad(k, format!("'{arg}' is not a variable name")));
                    }
                    result = Some(arg.to_string());
                }
                "endian" => {
                    read.endian = match arg {
                        "big" => Endian::Big,
                        "little" => Endian::Little,
                        "dce" => Endian::Dce,
                        other => return Err(bad(k, format!("'{other}' is not an endianness"))),
                    };
                }
                "string" => read.string = Some(num_base(k, arg)?),
                _ => {
                    if !read_option(&mut read, word, &mut words, k)? {
                        return Err(bad(k, format!("'{word}' is not an option of it")));
                    }
                }
            }
        }
        let missing = |what: &str| bad(k, format!("has no '{what}'"));
        let math = ByteMath {
            nbytes: nbytes.ok_or_else(|| missing("bytes"))?,
            offset: offset.ok_or_else(|| missing("offset"))?,
            oper: oper.ok_or_else(|| missing("oper"))?,
            rvalue: rvalue.ok_or_else(|| missing("rvalue"))?,
            result: result.ok_or_else(|| missing("result"))?,
            read,
        };
        check_width(k, &math.nbytes, &math.read)?;
        Ok(math)
    }

    // ── flow state ───────────────────────────────────────────────

    fn flow_state(&mut self, k: &str, value: &str) -> Compiled<bool> {
        let check = match k {
            "flowbits" => {
                if value == "noalert" {
                    self.sig.noalert = true;
                    return Ok(true);
                }
                Check::Bits(parse_bits("flowbits", value)?)
            }
            "xbits" | "hostbits" if value == "noalert" => {
                self.sig.noalert = true;
                return Ok(true);
            }
            "xbits" => Check::Bits(parse_bits("xbits", value)?),
            "hostbits" => Check::Bits(parse_bits("hostbits", value)?),
            "flowint" => Check::Flowint(Self::parse_flowint(value)?),
            "flowvar" | "pktvar" => {
                let (name, content) = value
                    .split_once(',')
                    .ok_or_else(|| bad(k, "is not 'name, \"content\"'"))?;
                if !is_name(name.trim()) {
                    return Err(bad(k, format!("'{}' is not a variable name", name.trim())));
                }
                let bytes = decode_content(unquote(k, content.trim())?)?;
                Check::Var {
                    keyword: if k == "flowvar" { "flowvar" } else { "pktvar" },
                    name: name.trim().to_string(),
                    bytes,
                }
            }
            "flow.age" => Check::Counter(FlowCounter::Age, int(k, value, u64::from(u32::MAX))?),
            "flow.pkts" | "flow.bytes" => {
                let (side, spec) = value
                    .split_once(',')
                    .ok_or_else(|| bad(k, "is not 'direction, number'"))?;
                let bytes = k == "flow.bytes";
                let counter = match (side.trim(), bytes) {
                    ("toserver", false) => FlowCounter::PktsToServer,
                    ("toclient", false) => FlowCounter::PktsToClient,
                    ("either", false) => FlowCounter::Pkts,
                    ("toserver", true) => FlowCounter::BytesToServer,
                    ("toclient", true) => FlowCounter::BytesToClient,
                    ("either", true) => FlowCounter::Bytes,
                    (other, _) => return Err(bad(k, format!("'{other}' is not a direction"))),
                };
                Check::Counter(counter, int(k, spec, u64::MAX)?)
            }
            "flow.pkts_toserver" => {
                Check::Counter(FlowCounter::PktsToServer, int(k, value, u64::MAX)?)
            }
            "flow.pkts_toclient" => {
                Check::Counter(FlowCounter::PktsToClient, int(k, value, u64::MAX)?)
            }
            "flow.bytes_toserver" => {
                Check::Counter(FlowCounter::BytesToServer, int(k, value, u64::MAX)?)
            }
            "flow.bytes_toclient" => {
                Check::Counter(FlowCounter::BytesToClient, int(k, value, u64::MAX)?)
            }
            "flow.elephant" => match value {
                "toserver" | "toclient" | "either" | "both" => Check::Elephant(value.to_string()),
                other => return Err(bad(k, format!("'{other}' is not a direction"))),
            },
            "stream_size" => parse_stream_size(value)?,
            "tcp.session" => {
                for phase in split_args(value) {
                    if !matches!(phase, "setup" | "established" | "closing" | "closed") {
                        return Err(bad(k, format!("'{phase}' is not a session phase")));
                    }
                }
                Check::Field {
                    keyword: "tcp.session",
                    argument: value.to_string(),
                }
            }
            "iprep" => parse_iprep(value)?,
            "geoip" => parse_geoip(value)?,
            _ => return Ok(false),
        };
        self.sig.checks.push(check);
        Ok(true)
    }

    fn parse_flowint(value: &str) -> Compiled<Flowint> {
        let k = "flowint";
        let args: Vec<&str> = split_args(value).collect();
        let (name, op, operand) = match args.as_slice() {
            [name, op] => (*name, *op, None),
            [name, op, operand] => (*name, *op, Some(*operand)),
            _ => return Err(bad(k, "is not 'name, operator[, value]'")),
        };
        if !is_name(name) || name.len() < 2 {
            return Err(bad(
                k,
                format!("'{name}' is not a variable name of two characters or more"),
            ));
        }
        let op = match op {
            "=" => FlowintOp::Set,
            "+" => FlowintOp::Add,
            "-" => FlowintOp::Sub,
            "==" => FlowintOp::Eq,
            "!=" => FlowintOp::Ne,
            "<" => FlowintOp::Lt,
            "<=" => FlowintOp::Le,
            ">" => FlowintOp::Gt,
            ">=" => FlowintOp::Ge,
            "isset" => FlowintOp::IsSet,
            "notset" | "isnotset" => FlowintOp::IsNotSet,
            other => return Err(bad(k, format!("'{other}' is not an operator"))),
        };
        let needs_value = !matches!(op, FlowintOp::IsSet | FlowintOp::IsNotSet);
        let value = match (needs_value, operand) {
            (true, Some(v)) => {
                let v = v.trim();
                Some(if let Ok(n) = signed(v) {
                    Value::Lit(n)
                } else if is_name(v) {
                    Value::Var(v.to_string())
                } else {
                    return Err(bad(k, format!("'{v}' is neither a number nor a variable")));
                })
            }
            (true, None) => return Err(bad(k, "needs a value after its operator")),
            (false, Some(_)) => return Err(bad(k, "takes no value after isset or notset")),
            (false, None) => None,
        };
        Ok(Flowint {
            name: name.to_string(),
            op,
            value,
        })
    }

    // ── packet header ────────────────────────────────────────────

    fn packet(&mut self, k: &str, value: &str) -> Compiled<bool> {
        let header =
            |field, max| -> Compiled<Check> { Ok(Check::Header(field, int(k, value, max)?)) };
        if k == "dsize" {
            self.once(k)?;
        }
        let check = match k {
            "dsize" => header(HeaderField::Dsize, u64::from(u16::MAX))?,
            "ttl" => header(HeaderField::Ttl, u64::from(u8::MAX))?,
            "id" => Check::Header(HeaderField::IpId, plain(k, value, u64::from(u16::MAX))?),
            "tos" => Check::Header(
                HeaderField::Tos,
                plain_or_not(k, value, u64::from(u8::MAX))?,
            ),
            "seq" | "tcp.seq" => {
                Check::Header(HeaderField::Seq, plain(k, value, u64::from(u32::MAX))?)
            }
            "ack" | "tcp.ack" => {
                Check::Header(HeaderField::Ack, plain(k, value, u64::from(u32::MAX))?)
            }
            "window" | "tcp.window" => Check::Header(
                HeaderField::Window,
                plain_or_not(k, value, u64::from(u16::MAX))?,
            ),
            "tcp.mss" => header(HeaderField::TcpMss, u64::from(u16::MAX))?,
            "tcp.wscale" => header(HeaderField::TcpWscale, u64::from(u8::MAX))?,
            "fragoffset" => Check::Header(HeaderField::FragOffset, frag_offset(value)?),
            "itype" => header(HeaderField::Itype, u64::from(u8::MAX))?,
            "icode" => header(HeaderField::Icode, u64::from(u8::MAX))?,
            "icmp_id" => Check::Header(HeaderField::IcmpId, plain(k, value, u64::from(u16::MAX))?),
            "icmp_seq" => {
                Check::Header(HeaderField::IcmpSeq, plain(k, value, u64::from(u16::MAX))?)
            }
            "icmpv6.mtu" => header(HeaderField::Icmpv6Mtu, u64::from(u32::MAX))?,
            "vlan.layers" => header(HeaderField::VlanLayers, 3)?,
            "igmp.type" => header(HeaderField::IgmpType, u64::from(u8::MAX))?,
            "vlan.id" => {
                let spec = value.split_once(',').map_or(value, |(spec, layer)| {
                    let _ = layer;
                    spec
                });
                Check::Header(HeaderField::VlanId, int(k, spec, 4095)?)
            }
            "ip_proto" => Check::Header(HeaderField::IpProto, parse_ip_proto(value)?),
            "l3_proto" => Check::Header(
                HeaderField::L3Proto,
                match value {
                    "ipv4" | "ip4" => IntMatch::eq(0x0800),
                    "ipv6" | "ip6" => IntMatch::eq(0x86dd),
                    other => int(k, other, u64::from(u16::MAX))?,
                },
            ),
            "flags" | "tcp.flags" => Check::Flags(parse_tcp_flags(k, value)?),
            "fragbits" => parse_fragbits(value)?,
            "ipopts" => match value {
                "rr" | "eol" | "nop" | "ts" | "sec" | "esec" | "lsrr" | "ssrr" | "satid"
                | "any" => Check::IpOpts(value.to_string()),
                other => return Err(bad(k, format!("'{other}' is not an IP option"))),
            },
            "sameip" => {
                expect_empty(k, value)?;
                Check::SameIp
            }
            "decode-event" | "stream-event" | "engine-event" | "app-layer-event" => {
                let (negated, name) = match value.strip_prefix('!') {
                    Some(rest) => (true, rest),
                    None => (false, value),
                };
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
                {
                    return Err(bad(k, format!("'{value}' is not an event name")));
                }
                Check::Event {
                    keyword: event_keyword(k),
                    name: name.to_string(),
                    negated,
                }
            }
            _ => return Ok(false),
        };
        self.sig.checks.push(check);
        Ok(true)
    }

    // ── application layer ────────────────────────────────────────

    fn application(&mut self, k: &str, value: &str) -> Compiled<bool> {
        let check = match k {
            "app-layer-protocol" => {
                let (negated, proto) = match value.strip_prefix('!') {
                    Some(rest) => (true, rest),
                    None => (false, value),
                };
                let mut parts = proto.split(',');
                let proto = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
                if !APP_PROTOCOLS.contains(&proto.as_str()) {
                    return Err(bad(k, format!("'{proto}' is not an application protocol")));
                }
                let mode = match parts.next().map(str::trim) {
                    None | Some("direction") => ProtoMode::Direction,
                    Some("to_server") => ProtoMode::ToServer,
                    Some("to_client") => ProtoMode::ToClient,
                    Some("either") => ProtoMode::Either,
                    Some("final") => ProtoMode::Final,
                    Some("original") => ProtoMode::Original,
                    Some(other) => {
                        return Err(bad(k, format!("'{other}' is not a protocol mode")));
                    }
                };
                if parts.next().is_some() {
                    return Err(bad(k, "takes a protocol and at most one mode"));
                }
                Check::AppLayerProtocol {
                    negated,
                    proto,
                    mode,
                }
            }
            "app-layer-state" | "ftpbounce" | "filename" | "fileext" | "filemd5" | "filesha1"
            | "filesha256" | "filesize" => Self::file_or_state(k, value)?,
            _ => {
                let Some(def) = buffers::field(k) else {
                    return Ok(false);
                };
                check_field(def.name, def.arg, value)?;
                Check::Field {
                    keyword: def.name,
                    argument: value.to_string(),
                }
            }
        };
        self.sig.checks.push(check);
        Ok(true)
    }

    fn file_or_state(k: &str, value: &str) -> Compiled<Check> {
        let keyword: &'static str = match k {
            "app-layer-state" => "app-layer-state",
            "ftpbounce" => {
                expect_empty(k, value)?;
                "ftpbounce"
            }
            "filename" | "fileext" => {
                let (_, quoted) = value
                    .strip_prefix('!')
                    .map_or((false, value), |rest| (true, rest.trim_start()));
                decode_content(unquote(k, quoted)?)?;
                if k == "filename" {
                    "filename"
                } else {
                    "fileext"
                }
            }
            "filesize" => {
                int(k, value, u64::MAX)?;
                "filesize"
            }
            "filemd5" => "filemd5",
            "filesha1" => "filesha1",
            _ => "filesha256",
        };
        if value.is_empty() && keyword != "ftpbounce" {
            return Err(bad(k, "needs an argument"));
        }
        Ok(Check::Field {
            keyword,
            argument: value.to_string(),
        })
    }
}

// ── Option helpers ───────────────────────────────────────────────

fn expect_empty(k: &str, value: &str) -> Compiled<()> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(bad(k, "takes no argument"))
    }
}

fn plain_u32(k: &str, value: &str) -> Compiled<u32> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| bad(k, format!("'{value}' is not a number")))
}

fn int(k: &str, value: &str, max: u64) -> Compiled<IntMatch> {
    IntMatch::parse(value, max).map_err(|e| bad(k, e))
}

/// Comma-separated arguments, trimmed, empty ones dropped.
fn split_args(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-.:/".contains(c))
}

fn word_pairs(k: &str, value: &str) -> Compiled<Vec<(String, String)>> {
    split_args(value)
        .map(|part| {
            let (name, arg) = part
                .split_once(' ')
                .ok_or_else(|| bad(k, format!("'{part}' is not 'name value'")))?;
            Ok((name.to_string(), arg.trim().to_string()))
        })
        .collect()
}

fn event_keyword(k: &str) -> &'static str {
    match k {
        "decode-event" => "decode-event",
        "stream-event" => "stream-event",
        "engine-event" => "engine-event",
        _ => "app-layer-event",
    }
}

fn parse_flow(flow: &mut FlowMatch, value: &str) -> Compiled<()> {
    let k = "flow";
    for word in split_args(value) {
        match word {
            "established" => flow.established = true,
            "not_established" => flow.not_established = true,
            "stateless" => flow.stateless = true,
            "to_server" | "from_client" => flow.to_server = true,
            "to_client" | "from_server" => flow.to_client = true,
            "only_stream" => flow.only_stream = true,
            "no_stream" => flow.no_stream = true,
            "only_frag" => flow.only_frag = true,
            "no_frag" => flow.no_frag = true,
            other => return Err(bad(k, format!("'{other}' is not a flow option"))),
        }
    }
    if flow.to_server && flow.to_client {
        return Err(bad(k, "asks for both directions"));
    }
    if flow.established && flow.not_established {
        return Err(bad(k, "asks for established and not established"));
    }
    if flow.only_stream && flow.no_stream {
        return Err(bad(k, "asks for only_stream and no_stream"));
    }
    if flow.only_frag && flow.no_frag {
        return Err(bad(k, "asks for only_frag and no_frag"));
    }
    Ok(())
}

fn parse_content(k: &str, value: &str) -> Compiled<Content> {
    let (negated, value) = match value.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, value),
    };
    let bytes = decode_content(unquote(k, value)?)?;
    if bytes.is_empty() {
        return Err(bad(k, "is empty"));
    }
    Ok(Content {
        bytes,
        negated,
        ..Content::default()
    })
}

fn set_position(content: &mut Content, k: &str, v: Value) -> Compiled<()> {
    if content.startswith {
        return Err(bad(k, "cannot follow startswith"));
    }
    if content.fast_pattern == Some(FastPattern::Only) {
        return Err(bad(k, "cannot follow fast_pattern:only"));
    }
    let absolute = matches!(k, "offset" | "depth");
    if absolute && content.is_relative()
        || !absolute && (content.offset.is_some() || content.depth.is_some())
    {
        return Err(bad(
            k,
            "mixes offset or depth with distance or within on one content",
        ));
    }
    let len = i64::try_from(content.bytes.len()).unwrap_or(i64::MAX);
    if let Value::Lit(n) = v {
        match k {
            "offset" | "depth" if n < 0 => return Err(bad(k, "is negative")),
            "offset" | "depth" if n > i64::from(u16::MAX) => {
                return Err(bad(k, format!("{n} is above 65535")));
            }
            "depth" | "within" if n < len => {
                return Err(bad(
                    k,
                    format!("{n} is shorter than the {len} bytes of its content"),
                ));
            }
            _ => {}
        }
    }
    let slot = match k {
        "offset" => &mut content.offset,
        "depth" => &mut content.depth,
        "distance" => &mut content.distance,
        _ => &mut content.within,
    };
    if slot.is_some() {
        return Err(bad(k, "is written twice on one content"));
    }
    *slot = Some(v);
    Ok(())
}

fn parse_fast_pattern(value: &str) -> Compiled<FastPattern> {
    let k = "fast_pattern";
    match value {
        "" => Ok(FastPattern::Whole),
        "only" => Ok(FastPattern::Only),
        spec => {
            let (offset, length) = spec
                .split_once(',')
                .ok_or_else(|| bad(k, "is neither 'only' nor 'offset,length'"))?;
            let parse = |t: &str| {
                t.trim()
                    .parse::<u16>()
                    .map_err(|_| bad(k, format!("'{t}' is not a number")))
            };
            Ok(FastPattern::Slice {
                offset: parse(offset)?,
                length: parse(length)?,
            })
        }
    }
}

/// Split the inside of a `pcre` value into expression, flags and captures.
fn split_pcre(inner: &str) -> Compiled<(String, String, Vec<Capture>)> {
    let k = "pcre";
    let body = inner
        .strip_prefix('/')
        .ok_or_else(|| bad(k, "does not open with '/'"))?;
    for (index, _) in body.rmatch_indices('/') {
        let rest = &body[index + 1..];
        let (flags, tail) = rest
            .split_once(',')
            .map_or((rest, None), |(f, t)| (f, Some(t)));
        let flags = flags.trim();
        if !flags.chars().all(|c| PCRE_FLAGS.contains(c)) {
            continue;
        }
        let Some(mut captures) = tail.map_or(Some(Vec::new()), parse_captures) else {
            continue;
        };
        let expression = &body[..index];
        captures.extend(named_captures(expression));
        return Ok((expression.to_string(), flags.to_string(), captures));
    }
    Err(bad(k, "is not '/expression/flags'"))
}

fn parse_captures(tail: &str) -> Option<Vec<Capture>> {
    split_args(tail)
        .map(|part| {
            let (scope, name) = part.split_once(':')?;
            matches!(scope, "flow" | "pkt" | "alert").then(|| Capture {
                scope: scope.to_string(),
                name: name.to_string(),
                named: false,
            })
        })
        .collect()
}

/// The groups an expression names `flow_x`, `pkt_x` or `alert_x`, in
/// either of PCRE2's spellings, `(?P<name>` and `(?<name>`.
fn named_captures(expression: &str) -> Vec<Capture> {
    let mut found = Vec::new();
    for (at, _) in expression.match_indices("(?") {
        let rest = &expression[at + 2..];
        let Some(rest) = rest.strip_prefix("P<").or_else(|| rest.strip_prefix('<')) else {
            continue;
        };
        let Some((group, _)) = rest.split_once('>') else {
            continue;
        };
        for scope in ["flow", "pkt", "alert"] {
            if let Some(name) = group.strip_prefix(scope).and_then(|n| n.strip_prefix('_'))
                && !name.is_empty()
            {
                found.push(Capture {
                    scope: scope.to_string(),
                    name: name.to_string(),
                    named: true,
                });
            }
        }
    }
    found
}

fn parse_base64_decode(value: &str) -> Compiled<Base64Decode> {
    let k = "base64_decode";
    let mut decode = Base64Decode {
        bytes: None,
        offset: 0,
        relative: false,
    };
    for part in split_args(value) {
        let (name, arg) = part
            .split_once(' ')
            .map_or((part, ""), |(n, a)| (n, a.trim()));
        let num = || -> Compiled<u32> {
            u32::try_from(number(arg).map_err(|e| bad(k, e))?).map_err(|_| bad(k, "is too large"))
        };
        match name {
            "bytes" => {
                let n = num()?;
                if n == 0 {
                    return Err(bad(k, "decodes zero bytes"));
                }
                decode.bytes = Some(n);
            }
            "offset" => decode.offset = num()?,
            "relative" => decode.relative = true,
            other => return Err(bad(k, format!("'{other}' is not an option of it"))),
        }
    }
    Ok(decode)
}

fn parse_entropy(value: &str) -> Compiled<Entropy> {
    let k = "entropy";
    let mut bytes = None;
    let mut offset = 0;
    let mut spec = None;
    for part in split_args(value) {
        let (name, arg) = part
            .split_once(' ')
            .map_or((part, ""), |(n, a)| (n, a.trim()));
        match name {
            "bytes" => {
                bytes = Some(
                    u32::try_from(number(arg).map_err(|e| bad(k, e))?)
                        .map_err(|_| bad(k, "is too large"))?,
                );
            }
            "offset" => offset = signed(arg).map_err(|e| bad(k, e))?,
            "value" => spec = Some(parse_float_match(arg)?),
            other => return Err(bad(k, format!("'{other}' is not an option of it"))),
        }
    }
    Ok(Entropy {
        bytes,
        offset,
        value: spec.ok_or_else(|| bad(k, "has no 'value'"))?,
    })
}

fn parse_float_match(text: &str) -> Compiled<FloatMatch> {
    let k = "entropy";
    let text = text.trim();
    let float = |t: &str| -> Compiled<f64> {
        t.trim()
            .parse::<f64>()
            .ok()
            .filter(|v| *v >= 0.0)
            .ok_or_else(|| bad(k, format!("'{t}' is not a positive entropy")))
    };
    for (prefix, op) in [
        (">=", IntOp::Ge),
        ("<=", IntOp::Le),
        ("!=", IntOp::Ne),
        (">", IntOp::Gt),
        ("<", IntOp::Lt),
        ("=", IntOp::Eq),
        ("!", IntOp::Ne),
    ] {
        if let Some(rest) = text.strip_prefix(prefix) {
            return Ok(FloatMatch {
                op,
                value: float(rest)?,
                high: 0.0,
            });
        }
    }
    if let Some((low, high)) = text.split_once("<>").or_else(|| text.split_once('-')) {
        let (low, high) = (float(low)?, float(high)?);
        if low >= high {
            return Err(bad(
                k,
                "is a range whose low bound is not below its high one",
            ));
        }
        return Ok(FloatMatch {
            op: IntOp::Range,
            value: low,
            high,
        });
    }
    Ok(FloatMatch {
        op: IntOp::Eq,
        value: float(text)?,
        high: 0.0,
    })
}

fn parse_asn1(value: &str) -> Compiled<Vec<(String, Option<i64>)>> {
    let k = "asn1";
    let mut options = Vec::new();
    for part in split_args(value) {
        let (name, arg) = part
            .split_once(' ')
            .map_or((part, None), |(n, a)| (n, Some(a.trim())));
        let arg = match (name, arg) {
            ("bitstring_overflow" | "double_overflow", None) => None,
            ("oversize_length" | "absolute_offset" | "relative_offset", Some(a)) => {
                Some(signed(a).map_err(|e| bad(k, e))?)
            }
            _ => return Err(bad(k, format!("'{part}' is not an option of it"))),
        };
        options.push((name.to_string(), arg));
    }
    if options.is_empty() {
        return Err(bad(k, "needs an option"));
    }
    Ok(options)
}

fn parse_dataset(k: &str, value: &str, reputation: bool) -> Compiled<DatasetMatch> {
    let args: Vec<&str> = split_args(value).collect();
    let (command, name, rest) = if reputation {
        let [name, op, score, rest @ ..] = args.as_slice() else {
            return Err(bad(k, "is not 'name, operator, value'"));
        };
        if !matches!(*op, "<" | ">" | "==" | "=" | "<=" | ">=" | "!=") {
            return Err(bad(k, format!("'{op}' is not an operator")));
        }
        number(score).map_err(|e| bad(k, e))?;
        (format!("{op}{score}"), *name, rest)
    } else {
        let [command, name, rest @ ..] = args.as_slice() else {
            return Err(bad(k, "is not 'command, name'"));
        };
        if !matches!(*command, "set" | "unset" | "isset" | "isnotset") {
            return Err(bad(k, format!("'{command}' is not a dataset command")));
        }
        ((*command).to_string(), *name, rest)
    };
    if !is_name(name) {
        return Err(bad(k, format!("'{name}' is not a set name")));
    }
    let mut options = Vec::new();
    for part in rest {
        let (key, arg) = part
            .split_once(' ')
            .map_or((*part, ""), |(n, a)| (n, a.trim()));
        if !matches!(
            key,
            "type"
                | "save"
                | "load"
                | "state"
                | "memcap"
                | "hashsize"
                | "format"
                | "context_key"
                | "value_key"
                | "array_key"
                | "remove_key"
                | "enrichment_key"
        ) {
            return Err(bad(k, format!("'{key}' is not an option of it")));
        }
        if key == "type" && !matches!(arg, "string" | "md5" | "sha256" | "ipv4" | "ipv6" | "ip") {
            return Err(bad(k, format!("'{arg}' is not a dataset type")));
        }
        options.push((key.to_string(), arg.to_string()));
    }
    Ok(DatasetMatch {
        keyword: k.to_string(),
        command,
        name: name.to_string(),
        options,
    })
}

fn read_option<'a>(
    read: &mut ByteRead,
    word: &'a str,
    words: &mut impl Iterator<Item = &'a str>,
    k: &str,
) -> Compiled<bool> {
    let (name, arg) = word
        .split_once(' ')
        .map_or((word, ""), |(n, a)| (n, a.trim()));
    match name {
        "relative" => read.relative = true,
        "big" => read.endian = Endian::Big,
        "little" => read.endian = Endian::Little,
        "dce" => read.endian = Endian::Dce,
        "string" => {
            let base = if arg.is_empty() {
                // `string, dec` or a bare `string` that defaults to decimal.
                None
            } else {
                Some(num_base(k, arg)?)
            };
            read.string = Some(base.unwrap_or(NumBase::Dec));
            if base.is_none() {
                let mut peek = words.by_ref().peekable();
                if let Some(next) = peek.peek().copied()
                    && matches!(next, "hex" | "dec" | "oct")
                {
                    read.string = Some(num_base(k, next)?);
                    peek.next();
                }
            }
        }
        "hex" | "dec" | "oct" if read.string.is_some() => read.string = Some(num_base(k, name)?),
        "bitmask" => {
            let mask = number(arg).map_err(|e| bad(k, e))?;
            if mask == 0 {
                return Err(bad(k, "has a zero bitmask"));
            }
            read.bitmask = Some(mask);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn num_base(k: &str, text: &str) -> Compiled<NumBase> {
    match text {
        "hex" => Ok(NumBase::Hex),
        "dec" => Ok(NumBase::Dec),
        "oct" => Ok(NumBase::Oct),
        other => Err(bad(k, format!("'{other}' is not hex, dec or oct"))),
    }
}

fn check_width(k: &str, nbytes: &Value, read: &ByteRead) -> Compiled<()> {
    if let Value::Lit(n) = nbytes {
        let max = if read.string.is_some() {
            MAX_STRING_BYTES
        } else {
            MAX_BYTES
        };
        if *n < 0 || n.unsigned_abs() > max {
            return Err(bad(k, format!("reads {n} bytes, outside 0 to {max}")));
        }
        if read.string.is_none() && !matches!(n, 0..=8) {
            return Err(bad(
                k,
                format!("reads {n} bytes as a binary number, outside 0 to 8"),
            ));
        }
    }
    Ok(())
}

fn parse_byte_extract(value: &str) -> Compiled<ByteExtract> {
    let k = "byte_extract";
    let args: Vec<&str> = split_args(value).collect();
    let [nbytes, offset, name, rest @ ..] = args.as_slice() else {
        return Err(bad(k, "is not 'bytes, offset, name'"));
    };
    let nbytes = number(nbytes).map_err(|e| bad(k, e))?;
    if !is_name(name) {
        return Err(bad(k, format!("'{name}' is not a variable name")));
    }
    let mut extract = ByteExtract {
        nbytes: u8::try_from(nbytes).map_err(|_| bad(k, "reads too many bytes"))?,
        offset: signed(offset).map_err(|e| bad(k, e))?,
        name: (*name).to_string(),
        read: ByteRead::default(),
        multiplier: 1,
        align: 0,
    };
    let mut words = rest.iter().copied();
    while let Some(word) = words.next() {
        if read_option(&mut extract.read, word, &mut words, k)? {
            continue;
        }
        let (opt, arg) = word
            .split_once(' ')
            .map_or((word, ""), |(n, a)| (n, a.trim()));
        match opt {
            "multiplier" => {
                extract.multiplier = u32::try_from(number(arg).map_err(|e| bad(k, e))?)
                    .ok()
                    .filter(|m| (1..=65535).contains(m))
                    .ok_or_else(|| bad(k, "has a multiplier outside 1 to 65535"))?;
            }
            "align" => {
                extract.align = match arg {
                    "2" => 2,
                    "4" => 4,
                    other => return Err(bad(k, format!("aligns on '{other}', neither 2 nor 4"))),
                };
            }
            _ => return Err(bad(k, format!("'{word}' is not an option of it"))),
        }
    }
    check_width(k, &Value::Lit(i64::from(extract.nbytes)), &extract.read)?;
    Ok(extract)
}

fn parse_bits(keyword: &'static str, value: &str) -> Compiled<Bits> {
    let k = keyword;
    let args: Vec<&str> = split_args(value).collect();
    let (op, rest) = args
        .split_first()
        .ok_or_else(|| bad(k, "needs a command"))?;
    let op = match *op {
        "set" => BitOp::Set,
        "unset" => BitOp::Unset,
        "toggle" => BitOp::Toggle,
        "isset" => BitOp::IsSet,
        "isnotset" => BitOp::IsNotSet,
        other => return Err(bad(k, format!("'{other}' is not a bit command"))),
    };
    let (names, options) = rest
        .split_first()
        .ok_or_else(|| bad(k, "needs a bit name"))?;
    // Suricata reads `|` as "any of" when a flow bit is tested, and nowhere
    // else: a bit set as `a|b` or `a&b` is one bit of that name, which a test
    // naming it then reads as the names around the `|`.
    let flow = keyword == "flowbits";
    let any = flow && matches!(op, BitOp::IsSet | BitOp::IsNotSet) && names.contains('|');
    let names: Vec<String> = if any {
        names
            .split('|')
            .map(str::trim)
            .map(str::to_string)
            .collect()
    } else {
        vec![names.to_string()]
    };
    let malformed = |n: &String| {
        if flow {
            n.is_empty() || n.contains(char::is_whitespace)
        } else {
            !is_name(n)
        }
    };
    if names.iter().any(malformed) {
        return Err(bad(k, "has an empty or malformed bit name"));
    }
    let mut scope = if keyword == "xbits" {
        BitScope::Untracked
    } else {
        BitScope::Flow
    };
    let mut expire = None;
    for option in options {
        let (name, arg) = option
            .split_once(' ')
            .map_or((*option, ""), |(n, a)| (n, a.trim()));
        match name {
            "src" | "dst" | "both" if keyword == "hostbits" && arg.is_empty() => {
                scope = match name {
                    "src" => BitScope::IpSrc,
                    "dst" => BitScope::IpDst,
                    _ => BitScope::IpPair,
                };
            }
            "track" if keyword == "xbits" => {
                scope = match arg {
                    "ip_src" | "by_src" => BitScope::IpSrc,
                    "ip_dst" | "by_dst" => BitScope::IpDst,
                    "ip_pair" | "by_both" => BitScope::IpPair,
                    "tx" => BitScope::Transaction,
                    other => return Err(bad(k, format!("'{other}' is not a track"))),
                };
            }
            "expire" if keyword != "flowbits" => {
                expire = Some(
                    u32::try_from(number(arg).map_err(|e| bad(k, e))?)
                        .map_err(|_| bad(k, "expires too late"))?,
                );
            }
            _ => return Err(bad(k, format!("'{option}' is not an option of it"))),
        }
    }
    if keyword == "hostbits" && scope == BitScope::Flow {
        scope = BitScope::IpSrc;
    }
    Ok(Bits {
        keyword,
        op,
        scope,
        names,
        any,
        expire,
    })
}

fn parse_stream_size(value: &str) -> Compiled<Check> {
    let k = "stream_size";
    let args: Vec<&str> = split_args(value).collect();
    let [side, op, n] = args.as_slice() else {
        return Err(bad(k, "is not 'side, operator, number'"));
    };
    let side = match *side {
        "server" => StreamSide::Server,
        "client" => StreamSide::Client,
        "both" => StreamSide::Both,
        "either" => StreamSide::Either,
        other => return Err(bad(k, format!("'{other}' is not a side"))),
    };
    let n = number(n).map_err(|e| bad(k, e))?;
    if n > u64::from(u32::MAX) {
        return Err(bad(k, "is above a 32-bit size"));
    }
    let op = match *op {
        "<" => IntOp::Lt,
        "<=" => IntOp::Le,
        ">" => IntOp::Gt,
        ">=" => IntOp::Ge,
        "=" | "==" => IntOp::Eq,
        "!=" => IntOp::Ne,
        other => return Err(bad(k, format!("'{other}' is not an operator"))),
    };
    Ok(Check::StreamSize {
        side,
        value: IntMatch { op, a: n, b: 0 },
    })
}

fn parse_iprep(value: &str) -> Compiled<Check> {
    let k = "iprep";
    let args: Vec<&str> = split_args(value).collect();
    let (side, category, cmp) = match args.as_slice() {
        [side, category, op, score] => {
            let n = number(score).map_err(|e| bad(k, e))?;
            if n > 127 {
                return Err(bad(k, "scores above 127"));
            }
            let op = match *op {
                "<" => IntOp::Lt,
                ">" => IntOp::Gt,
                "=" => IntOp::Eq,
                other => return Err(bad(k, format!("'{other}' is not an operator"))),
            };
            (*side, *category, IntMatch { op, a: n, b: 0 })
        }
        [side, category, "isset"] => (
            *side,
            *category,
            IntMatch {
                op: IntOp::Ge,
                a: 0,
                b: 0,
            },
        ),
        [side, category, "isnotset"] => (
            *side,
            *category,
            IntMatch {
                op: IntOp::Lt,
                a: 0,
                b: 0,
            },
        ),
        _ => return Err(bad(k, "is not 'side, category, operator, score'")),
    };
    if !matches!(side, "any" | "src" | "dst" | "both") {
        return Err(bad(k, format!("'{side}' is not a side")));
    }
    if !is_name(category) {
        return Err(bad(k, format!("'{category}' is not a category")));
    }
    Ok(Check::Iprep {
        side: side.to_string(),
        category: category.to_string(),
        value: cmp,
    })
}

fn parse_geoip(value: &str) -> Compiled<Check> {
    let k = "geoip";
    let mut args = split_args(value);
    let first = args.next().ok_or_else(|| bad(k, "needs countries"))?;
    let (side, first_country) = match first {
        "src" | "dst" | "both" | "any" => (first.to_string(), None),
        _ => ("any".to_string(), Some(first)),
    };
    let mut negated = false;
    let mut countries = Vec::new();
    for country in first_country.into_iter().chain(args) {
        let country = match country.strip_prefix('!') {
            Some(rest) => {
                negated = true;
                rest
            }
            None => country,
        };
        if country.len() != 2 || !country.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(bad(
                k,
                format!("'{country}' is not a two-letter country code"),
            ));
        }
        countries.push(country.to_ascii_uppercase());
    }
    if countries.is_empty() {
        return Err(bad(k, "needs countries"));
    }
    Ok(Check::Geoip {
        side,
        countries,
        negated,
    })
}

fn parse_threshold(k: &str, value: &str) -> Compiled<Threshold> {
    let mut kind = if k == "detection_filter" {
        Some(ThresholdKind::Threshold)
    } else {
        None
    };
    let mut track = None;
    let mut count = None;
    let mut seconds = None;
    let mut multiplier = None;
    let mut unique_on = None;
    for part in split_args(value) {
        let (name, arg) = part
            .split_once(' ')
            .map(|(n, a)| (n, a.trim()))
            .ok_or_else(|| bad(k, format!("'{part}' is not 'name value'")))?;
        let num = || -> Compiled<u32> {
            u32::try_from(number(arg).map_err(|e| bad(k, e))?).map_err(|_| bad(k, "is too large"))
        };
        match name {
            "type" if k == "threshold" => {
                kind = Some(match arg {
                    "limit" => ThresholdKind::Limit,
                    "threshold" => ThresholdKind::Threshold,
                    "both" => ThresholdKind::Both,
                    "backoff" => ThresholdKind::Backoff,
                    other => return Err(bad(k, format!("'{other}' is not a threshold type"))),
                });
            }
            "track" => {
                track = Some(match arg {
                    "by_src" => Track::BySrc,
                    "by_dst" => Track::ByDst,
                    "by_rule" => Track::ByRule,
                    "by_both" => Track::ByBoth,
                    "by_flow" => Track::ByFlow,
                    other => return Err(bad(k, format!("'{other}' is not a track"))),
                });
            }
            "count" => count = Some(num()?),
            "seconds" => seconds = Some(num()?),
            "multiplier" => multiplier = Some(num()?),
            "unique_on" if k == "detection_filter" => {
                unique_on = Some(match arg {
                    "src_port" => PortSide::Src,
                    "dst_port" => PortSide::Dst,
                    _ => return Err(bad(k, format!("'{arg}' is neither src_port nor dst_port"))),
                });
            }
            _ => return Err(bad(k, format!("'{name}' is not an option of it"))),
        }
    }
    let kind = kind.ok_or_else(|| bad(k, "has no 'type'"))?;
    let count = count.ok_or_else(|| bad(k, "has no 'count'"))?;
    if count == 0 {
        return Err(bad(k, "counts to zero"));
    }
    let seconds = match (kind, seconds, multiplier) {
        (ThresholdKind::Backoff, None, Some(_)) => 0,
        (ThresholdKind::Backoff, _, None) => {
            return Err(bad(k, "of type backoff needs a multiplier"));
        }
        (_, Some(s), _) => s,
        (_, None, _) => return Err(bad(k, "has no 'seconds'")),
    };
    Ok(Threshold {
        kind,
        track: track.ok_or_else(|| bad(k, "has no 'track'"))?,
        count,
        seconds,
        multiplier,
        unique_on,
    })
}

fn parse_tag(value: &str) -> Compiled<Tag> {
    let k = "tag";
    let args: Vec<&str> = split_args(value).collect();
    let (scope, rest) = args.split_first().ok_or_else(|| bad(k, "needs a scope"))?;
    if !matches!(*scope, "session" | "host") {
        return Err(bad(k, format!("'{scope}' is neither session nor host")));
    }
    let mut tag = Tag {
        scope: (*scope).to_string(),
        count: 256,
        metric: "packets".to_string(),
        direction: None,
    };
    match rest {
        [] => {}
        [count, metric, direction @ ..] => {
            tag.count = u32::try_from(number(count).map_err(|e| bad(k, e))?)
                .map_err(|_| bad(k, "is too large"))?;
            if !matches!(*metric, "packets" | "seconds" | "bytes") {
                return Err(bad(
                    k,
                    format!("'{metric}' is not packets, seconds or bytes"),
                ));
            }
            tag.metric = (*metric).to_string();
            match direction {
                [] => {}
                [d] if matches!(*d, "src" | "dst") => tag.direction = Some((*d).to_string()),
                _ => return Err(bad(k, "has a direction other than src or dst")),
            }
        }
        _ => return Err(bad(k, "is not 'scope[, count, metric[, direction]]'")),
    }
    Ok(tag)
}

fn parse_ip_proto(value: &str) -> Compiled<IntMatch> {
    let k = "ip_proto";
    if let Ok(m) = IntMatch::parse(value, u64::from(u8::MAX)) {
        return Ok(m);
    }
    let (prefix, name) = value
        .find(|c: char| c.is_ascii_alphabetic())
        .map_or(("", value), |at| value.split_at(at));
    let number = match name.to_ascii_lowercase().as_str() {
        "ip" | "hopopt" => 0,
        "icmp" => 1,
        "igmp" => 2,
        "ggp" => 3,
        "ipencap" | "ipip" => 4,
        "tcp" => 6,
        "egp" => 8,
        "igp" => 9,
        "pup" => 12,
        "udp" => 17,
        "idp" => 22,
        "ipv6" => 41,
        "ipv6-route" => 43,
        "ipv6-frag" => 44,
        "rsvp" => 46,
        "gre" => 47,
        "esp" | "ipv6-crypt" => 50,
        "ah" | "ipv6-auth" => 51,
        "icmpv6" | "ipv6-icmp" => 58,
        "ipv6-nonxt" => 59,
        "ipv6-opts" => 60,
        "eigrp" => 88,
        "ospf" | "ospfigp" => 89,
        "pim" => 103,
        "vrrp" => 112,
        "l2tp" => 115,
        "sctp" => 132,
        "udplite" => 136,
        _ => {
            return Err(bad(
                k,
                format!("'{value}' is neither a protocol number nor a known name"),
            ));
        }
    };
    IntMatch::parse(&format!("{prefix}{number}"), u64::from(u8::MAX)).map_err(|e| bad(k, e))
}

/// TCP flag letters to bits, and `0` for no flag at all.
fn tcp_flag_bits(k: &str, letters: &str) -> Compiled<(u8, bool)> {
    let mut bits = 0u8;
    let mut zero = false;
    for c in letters.chars() {
        bits |= match c.to_ascii_uppercase() {
            'F' => 0x01,
            'S' => 0x02,
            'R' => 0x04,
            'P' => 0x08,
            'A' => 0x10,
            'U' => 0x20,
            'E' | '2' => 0x40,
            'C' | '1' => 0x80,
            '0' => {
                zero = true;
                0
            }
            other => return Err(bad(k, format!("'{other}' is not a TCP flag"))),
        };
    }
    Ok((bits, zero))
}

fn flags_mode(k: &str, text: &str) -> Compiled<(TcpFlagsMode, String)> {
    let mut mode = TcpFlagsMode::Exact;
    let mut letters = String::new();
    for c in text.trim().chars() {
        let next = match c {
            '+' => Some(TcpFlagsMode::Plus),
            '*' => Some(TcpFlagsMode::Any),
            '!' | '-' => Some(TcpFlagsMode::Not),
            '=' => Some(TcpFlagsMode::Exact),
            _ => None,
        };
        match next {
            Some(m) => {
                if mode != TcpFlagsMode::Exact && m != mode {
                    return Err(bad(k, "has two modifiers"));
                }
                mode = m;
            }
            None => letters.push(c),
        }
    }
    if letters.is_empty() {
        return Err(bad(k, "names no flag"));
    }
    Ok((mode, letters))
}

fn parse_tcp_flags(k: &str, value: &str) -> Compiled<TcpFlags> {
    let (test, ignore) = value
        .split_once(',')
        .map_or((value, None), |(t, i)| (t, Some(i)));
    let (mode, letters) = flags_mode(k, test)?;
    let (flags, zero) = tcp_flag_bits(k, &letters)?;
    if zero && flags != 0 {
        return Err(bad(k, "asks for no flag and some flags at once"));
    }
    let ignore = match ignore {
        Some(i) => {
            let (bits, zero) = tcp_flag_bits(k, i.trim())?;
            if zero {
                return Err(bad(k, "ignores '0'"));
            }
            bits
        }
        None => 0,
    };
    Ok(TcpFlags {
        flags,
        mode,
        ignore,
    })
}

/// A keyword Suricata reads as one decimal number and nothing else: no
/// comparison, no range, no hexadecimal.
fn plain(k: &str, value: &str, max: u64) -> Compiled<IntMatch> {
    let text = value.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(k, format!("'{value}' is not a plain decimal number")));
    }
    int(k, text, max)
}

/// A keyword Suricata reads as a decimal number, or `!` and one.
fn plain_or_not(k: &str, value: &str, max: u64) -> Compiled<IntMatch> {
    let text = value.trim();
    match text.strip_prefix('!') {
        Some(rest) => {
            let m = plain(k, rest, max)?;
            Ok(IntMatch { op: IntOp::Ne, ..m })
        }
        None => plain(k, text, max),
    }
}

/// `fragoffset`: a number, `<` one or `>` one. Suricata also reads a range
/// there; it is refused rather than given a meaning nobody tested.
fn frag_offset(value: &str) -> Compiled<IntMatch> {
    let k = "fragoffset";
    let text = value.trim();
    let (op, rest) = if let Some(rest) = text.strip_prefix('<') {
        (IntOp::Lt, rest)
    } else if let Some(rest) = text.strip_prefix('>') {
        (IntOp::Gt, rest)
    } else {
        (IntOp::Eq, text)
    };
    let m = plain(k, rest, 8191)?;
    Ok(IntMatch { op, ..m })
}

fn parse_fragbits(value: &str) -> Compiled<Check> {
    let k = "fragbits";
    let (mode, letters) = flags_mode(k, value)?;
    let mut flags = 0u8;
    for c in letters.chars() {
        flags |= match c.to_ascii_uppercase() {
            'M' => 0x01,
            'D' => 0x02,
            'R' => 0x04,
            other => return Err(bad(k, format!("'{other}' is not M, D or R"))),
        };
    }
    Ok(Check::FragBits { flags, mode })
}

/// Check an application field's argument against how it is written.
fn check_field(k: &str, arg: FieldArg, value: &str) -> Compiled<()> {
    match arg {
        FieldArg::Flag => expect_empty(k, value),
        FieldArg::Int => {
            let spec = value
                .split_once(',')
                .map_or(value, |(first, _)| first)
                .trim();
            int(k, spec, u64::MAX).map(|_| ())
        }
        FieldArg::Words => {
            let body = value.strip_prefix('!').unwrap_or(value);
            if IntMatch::parse(body, u64::MAX).is_ok() {
                return Ok(());
            }
            if split_args(body).next().is_none()
                || !split_args(body).all(|w| {
                    w.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-. ".contains(c))
                })
            {
                return Err(bad(k, format!("'{value}' is neither a number nor names")));
            }
            Ok(())
        }
        FieldArg::Raw => {
            if value.trim().is_empty() {
                return Err(bad(k, "needs an argument"));
            }
            check_raw_field(k, value)
        }
    }
}

fn check_raw_field(k: &str, value: &str) -> Compiled<()> {
    match k {
        "tls.version" => {
            let v = value.strip_prefix('!').unwrap_or(value);
            if !matches!(
                v,
                "1.0" | "1.1" | "1.2" | "1.3" | "2.0" | "3.0" | "ssl3" | "ssl2"
            ) && number(v).is_err()
            {
                return Err(bad(k, format!("'{value}' is not a TLS version")));
            }
        }
        "ssl_version" => {
            for word in split_args(value) {
                let word = word.strip_prefix('!').unwrap_or(word);
                if !matches!(
                    word,
                    "sslv2" | "sslv3" | "tls1.0" | "tls1.1" | "tls1.2" | "tls1.3"
                ) {
                    return Err(bad(k, format!("'{word}' is not an SSL version")));
                }
            }
        }
        "ssl_state" => {
            for word in value.split([',', '|']).map(str::trim) {
                let word = word.strip_prefix('!').unwrap_or(word);
                if !matches!(
                    word,
                    "client_hello" | "server_hello" | "client_keyx" | "server_keyx" | "unknown"
                ) {
                    return Err(bad(k, format!("'{word}' is not an SSL state")));
                }
            }
        }
        "dcerpc.iface" => {
            let mut parts = split_args(value);
            let uuid = parts.next().unwrap_or_default();
            let groups: Vec<usize> = uuid.split('-').map(str::len).collect();
            if groups != [8, 4, 4, 4, 12]
                || !uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            {
                return Err(bad(k, format!("'{uuid}' is not a UUID")));
            }
            for option in parts {
                if option != "any_frag" {
                    let spec = option.strip_prefix('!').unwrap_or(option);
                    IntMatch::parse(spec, u64::from(u16::MAX)).map_err(|e| bad(k, e))?;
                }
            }
        }
        "dcerpc.opnum" => {
            for part in split_args(value) {
                let ok = match part.split_once('-') {
                    Some((low, high)) => number(low).is_ok() && number(high).is_ok(),
                    None => number(part).is_ok(),
                };
                if !ok {
                    return Err(bad(k, format!("'{part}' is not an opnum or a range")));
                }
            }
        }
        _ => {}
    }
    Ok(())
}
