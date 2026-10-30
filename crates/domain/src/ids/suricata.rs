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

use ebpf_common::event::MAX_L7_PAYLOAD;

use super::engine::compile_pattern;
use super::entity::{AddressMatch, IdsRule, ImportedRule, ThresholdConfig, ThresholdType, TrackBy};
use crate::common::entity::{DomainMode, Protocol, RuleId, Severity};
use crate::firewall::entity::IpNetwork;

/// The most ports one rule may name. Each port is a native rule of its own,
/// because the classifier keys on one port, so a range would multiply into
/// thousands of rules nobody wrote.
pub const MAX_PORTS_PER_RULE: usize = 16;

/// How deep one variable may refer to another before the chain is refused.
const MAX_VARIABLE_DEPTH: usize = 8;

/// The longest payload the agent captures, which bounds every offset.
const PAYLOAD_LIMIT: usize = MAX_L7_PAYLOAD;

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
    /// A rule carrying the keyword is refused.
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
        note: "Literal and `|hex|` bytes. Contents chained by `distance` or `within` compile into one expression; independent contents must each match.",
    },
    KeywordSupport {
        keyword: "nocase",
        support: Support::Compiled,
        note: "ASCII case-insensitive match of the content before it.",
    },
    KeywordSupport {
        keyword: "offset",
        support: Support::Compiled,
        note: "From the start of the captured payload, up to its 2048-byte limit.",
    },
    KeywordSupport {
        keyword: "depth",
        support: Support::Compiled,
        note: "Counted from `offset`, as Suricata counts it.",
    },
    KeywordSupport {
        keyword: "distance",
        support: Support::Compiled,
        note: "Relative to the previous content. A negative distance is refused.",
    },
    KeywordSupport {
        keyword: "within",
        support: Support::Compiled,
        note: "Relative to the previous content. A window shorter than the content is refused.",
    },
    KeywordSupport {
        keyword: "startswith",
        support: Support::Compiled,
        note: "Anchors the content to the start of the payload.",
    },
    KeywordSupport {
        keyword: "endswith",
        support: Support::Compiled,
        note: "Anchors the content to the end of the payload, only as the last of its chain.",
    },
    KeywordSupport {
        keyword: "fast_pattern",
        support: Support::Accepted,
        note: "A prefilter hint; every pattern is matched in full.",
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
        note: "Flags `i`, `s`, `m`, `x`, `A` and `E`. A construct the matcher does not implement, such as a backreference or a lookaround, refuses the rule; so does a buffer or relative flag.",
    },
    KeywordSupport {
        keyword: "threshold",
        support: Support::Compiled,
        note: "Types `limit`, `threshold` and `both`, tracked by source, destination or both.",
    },
    KeywordSupport {
        keyword: "flowbits",
        support: Support::Refused,
        note: "State carried from one rule to another is not kept.",
    },
    KeywordSupport {
        keyword: "xbits",
        support: Support::Refused,
        note: "State carried from one rule to another is not kept.",
    },
    KeywordSupport {
        keyword: "flowint",
        support: Support::Refused,
        note: "State carried from one rule to another is not kept.",
    },
    KeywordSupport {
        keyword: "noalert",
        support: Support::Refused,
        note: "A rule that never alerts only sets state for another.",
    },
    KeywordSupport {
        keyword: "dsize",
        support: Support::Refused,
        note: "The captured payload is cut at 2048 bytes, so its size is not the segment's.",
    },
    KeywordSupport {
        keyword: "isdataat",
        support: Support::Refused,
        note: "Not in the compiled subset.",
    },
    KeywordSupport {
        keyword: "byte_test",
        support: Support::Refused,
        note: "Decoding a field out of the payload is not in the compiled subset.",
    },
    KeywordSupport {
        keyword: "byte_jump",
        support: Support::Refused,
        note: "Decoding a field out of the payload is not in the compiled subset.",
    },
    KeywordSupport {
        keyword: "byte_extract",
        support: Support::Refused,
        note: "Decoding a field out of the payload is not in the compiled subset.",
    },
    KeywordSupport {
        keyword: "byte_math",
        support: Support::Refused,
        note: "Decoding a field out of the payload is not in the compiled subset.",
    },
    KeywordSupport {
        keyword: "bsize",
        support: Support::Refused,
        note: "Measures an application-layer buffer.",
    },
    KeywordSupport {
        keyword: "stream_size",
        support: Support::Refused,
        note: "Streams are not reassembled.",
    },
    KeywordSupport {
        keyword: "flags",
        support: Support::Refused,
        note: "A payload is matched per segment, without its TCP flags.",
    },
    KeywordSupport {
        keyword: "detection_filter",
        support: Support::Refused,
        note: "Not in the compiled subset; `threshold` is.",
    },
    KeywordSupport {
        keyword: "http.uri",
        support: Support::Refused,
        note: "Inspects an application-layer buffer; so does every sticky buffer and every `http_`, `tls`, `dns`, `ja3`, `file` and `smb` keyword.",
    },
];

/// The keywords that select an application-layer buffer: everything with a
/// dot in it, and the older modifier spellings by prefix.
fn is_application_buffer(keyword: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "http_",
        "tls_",
        "dns_",
        "ja3",
        "ja4",
        "file_",
        "file",
        "smb",
        "ssh_",
        "ssl_",
        "krb5",
        "dcerpc",
        "sip_",
        "smtp_",
        "ftp",
        "nfs",
        "dnp3",
        "modbus",
        "enip",
        "base64_",
        "uricontent",
        "urilen",
    ];
    keyword.contains('.') || PREFIXES.iter().any(|prefix| keyword.starts_with(prefix))
}

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
    fn new(keyword: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            sid: None,
            keyword: keyword.into(),
            reason: reason.into(),
        }
    }
}

type Compiled<T> = Result<T, Refused>;

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

    compile_parts(&text[..open], &options, vars).map_err(|mut refused| {
        refused.sid = Some(sid);
        refused
    })
}

fn compile_parts(
    header: &str,
    options: &[(String, String)],
    vars: &SuricataVars,
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
        also_patterns: body.also_patterns,
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
                pattern: body.pattern.clone(),
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
fn split_header(text: &str) -> Compiled<Vec<String>> {
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
fn split_list(body: &str) -> Vec<&str> {
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
struct AddressSet {
    any: bool,
    within: Vec<IpNetwork>,
    outside: Vec<IpNetwork>,
}

impl AddressSet {
    fn into_match(self, written: &str) -> Compiled<AddressMatch> {
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

fn parse_addresses(token: &str, vars: &SuricataVars, depth: usize) -> Compiled<AddressSet> {
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
fn parse_options(text: &str) -> Compiled<Vec<(String, String)>> {
    let mut options = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                current.push(ch);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            ';' if !quoted => {
                push_option(&mut options, &current)?;
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if quoted {
        return Err(Refused::new("rule", "opens a quoted value it never closes"));
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
fn unquote<'a>(keyword: &str, value: &'a str) -> Compiled<&'a str> {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(|| Refused::new(keyword, "takes a quoted value"))
}

/// Remove the escapes Suricata defines inside a quoted value.
fn unescape(value: &str) -> String {
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

#[derive(Debug, Default)]
struct Content {
    bytes: Vec<u8>,
    nocase: bool,
    offset: Option<usize>,
    depth: Option<usize>,
    distance: Option<usize>,
    within: Option<usize>,
    startswith: bool,
    endswith: bool,
}

impl Content {
    fn is_relative(&self) -> bool {
        self.distance.is_some() || self.within.is_some()
    }
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
    pattern: String,
    also_patterns: Vec<String>,
}

/// A content or a pcre, in the order the rule writes them.
enum Matcher {
    Content(Content),
    Pcre(String),
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
    let mut matchers: Vec<Matcher> = Vec::new();

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
            "metadata" | "target" | "fast_pattern" | "rawbytes" | "pkt_data" => {}
            "flow" => check_flow(value)?,
            "content" => {
                let (negated, value) = match value.strip_prefix('!') {
                    Some(rest) => (true, rest.trim_start()),
                    None => (false, value),
                };
                if negated {
                    return Err(Refused::new(
                        "content",
                        "is negated, and a payload is matched for what it holds",
                    ));
                }
                let bytes = decode_content(unquote(key, value)?)?;
                if bytes.is_empty() {
                    return Err(Refused::new("content", "is empty"));
                }
                matchers.push(Matcher::Content(Content {
                    bytes,
                    ..Content::default()
                }));
            }
            "nocase" | "offset" | "depth" | "distance" | "within" | "startswith" | "endswith" => {
                let Some(Matcher::Content(content)) = matchers.last_mut() else {
                    return Err(Refused::new(key, "modifies no content before it"));
                };
                apply_modifier(content, key, value)?;
            }
            "pcre" => matchers.push(Matcher::Pcre(compile_pcre(unquote(key, value)?)?)),
            "threshold" => threshold = Some(parse_threshold(value)?),
            other => return Err(refuse_keyword(other)),
        }
    }

    let groups = build_groups(matchers)?;
    let mut groups = groups.into_iter();
    let pattern = groups.next().ok_or_else(|| {
        Refused::new(
            "content",
            "names no content or pcre; a rule on the port alone is written natively",
        )
    })?;
    for group in std::iter::once(&pattern) {
        compile_pattern(group).map_err(|e| Refused::new("content", e.to_string()))?;
    }
    let also_patterns: Vec<String> = groups.collect();
    for group in &also_patterns {
        compile_pattern(group).map_err(|e| Refused::new("content", e.to_string()))?;
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
        pattern,
        also_patterns,
    })
}

fn refuse_keyword(keyword: &str) -> Refused {
    if let Some(row) = table_row(keyword) {
        return Refused::new(keyword, row.note);
    }
    if is_application_buffer(keyword) {
        return Refused::new(
            keyword,
            "inspects an application-layer buffer the agent does not reassemble",
        );
    }
    Refused::new(keyword, "is not in the compiled subset")
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

fn apply_modifier(content: &mut Content, key: &str, value: &str) -> Compiled<()> {
    let number = || -> Compiled<usize> {
        let parsed: i64 = value
            .parse()
            .map_err(|_| Refused::new(key, format!("'{value}' is not a number")))?;
        let parsed = usize::try_from(parsed)
            .map_err(|_| Refused::new(key, "is negative, which the matcher does not implement"))?;
        if parsed > PAYLOAD_LIMIT {
            return Err(Refused::new(
                key,
                format!("reaches past the {PAYLOAD_LIMIT} bytes of payload captured"),
            ));
        }
        Ok(parsed)
    };
    match key {
        "nocase" => content.nocase = true,
        "offset" => content.offset = Some(number()?),
        "depth" => content.depth = Some(number()?),
        "distance" => content.distance = Some(number()?),
        "within" => content.within = Some(number()?),
        "startswith" => content.startswith = true,
        _ => content.endswith = true,
    }
    Ok(())
}

/// Decode a content value: `|41 42|` sections are hex bytes, a backslash
/// escapes the next character, and the rest is literal.
fn decode_content(value: &str) -> Compiled<Vec<u8>> {
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

/// The bytes of a content as a regex literal that means exactly them.
fn literal(content: &Content) -> String {
    let mut out = String::with_capacity(content.bytes.len() * 4);
    for byte in &content.bytes {
        if byte.is_ascii_alphanumeric() {
            out.push(char::from(*byte));
        } else {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\x{byte:02X}");
        }
    }
    if content.nocase {
        format!("(?i:{out})")
    } else {
        out
    }
}

/// Any `low` to `high` bytes, or `low` or more when there is no ceiling.
fn gap(low: usize, high: Option<usize>) -> String {
    match high {
        Some(high) if high == low => format!("(?s:.){{{low}}}"),
        Some(high) => format!("(?s:.){{{low},{high}}}"),
        None if low == 0 => "(?s:.)*".to_string(),
        None => format!("(?s:.){{{low},}}"),
    }
}

/// Turn the rule's contents and pcres into the byte expressions that must all
/// match. A content chained to the one before it by `distance` or `within`
/// extends that content's expression; any other content starts its own, and
/// each pcre is its own.
fn build_groups(matchers: Vec<Matcher>) -> Compiled<Vec<String>> {
    let mut groups: Vec<String> = Vec::new();
    let mut open: Option<(String, bool)> = None;
    for matcher in matchers {
        match matcher {
            Matcher::Pcre(expression) => {
                if let Some((group, _)) = open.take() {
                    groups.push(group);
                }
                groups.push(expression);
            }
            Matcher::Content(content) => {
                let len = content.bytes.len();
                if content.is_relative() && (content.offset.is_some() || content.depth.is_some()) {
                    return Err(Refused::new(
                        "distance",
                        "is mixed with offset or depth on one content",
                    ));
                }
                let chained = content.is_relative() && open.is_some();
                if chained {
                    let Some((group, ended)) = open.as_mut() else {
                        continue;
                    };
                    if *ended {
                        return Err(Refused::new(
                            "endswith",
                            "anchors a content to the end that another content follows",
                        ));
                    }
                    let low = content.distance.unwrap_or(0);
                    let high = match content.within {
                        Some(within) if within < len => {
                            return Err(Refused::new(
                                "within",
                                "is shorter than the content it bounds",
                            ));
                        }
                        Some(within) => Some(low + within - len),
                        None => None,
                    };
                    group.push_str(&gap(low, high));
                    group.push_str(&literal(&content));
                    if content.endswith {
                        group.push_str("\\z");
                        *ended = true;
                    }
                    continue;
                }
                if let Some((group, _)) = open.take() {
                    groups.push(group);
                }
                // A relative content with nothing before it counts from the
                // start of the payload, so its distance is an offset.
                let offset = content.offset.or(content.distance);
                let depth = content.depth.or(content.within);
                let mut group = String::from("(?-u)");
                if content.startswith {
                    group.push_str("\\A");
                } else if offset.is_some() || depth.is_some() {
                    let low = offset.unwrap_or(0);
                    let high = match depth {
                        Some(depth) if depth < len => {
                            return Err(Refused::new(
                                "depth",
                                "is shorter than the content it bounds",
                            ));
                        }
                        Some(depth) => Some(low + depth - len),
                        None => None,
                    };
                    group.push_str("\\A");
                    group.push_str(&gap(low, high));
                }
                group.push_str(&literal(&content));
                if content.endswith {
                    group.push_str("\\z");
                }
                open = Some((group, content.endswith));
            }
        }
    }
    if let Some((group, _)) = open {
        groups.push(group);
    }
    Ok(groups)
}

/// Translate a `pcre` value, `/expression/flags`, into a byte expression.
fn compile_pcre(value: &str) -> Compiled<String> {
    let value = value.strip_prefix('!').map_or(Ok(value), |_| {
        Err(Refused::new(
            "pcre",
            "is negated, and a payload is matched for what it holds",
        ))
    })?;
    // Only the escapes of the rule syntax itself are removed here; the
    // expression's own backslashes stay.
    let value = value.replace("\\;", ";").replace("\\\"", "\"");
    let body = value
        .strip_prefix('/')
        .ok_or_else(|| Refused::new("pcre", "does not start with '/'"))?;
    let end = body
        .rfind('/')
        .ok_or_else(|| Refused::new("pcre", "has no closing '/'"))?;
    let (expression, flags) = (&body[..end], &body[end + 1..]);

    let mut inline = String::new();
    let mut anchored = false;
    for flag in flags.chars() {
        match flag {
            'i' | 's' | 'm' | 'x' => inline.push(flag),
            'A' => anchored = true,
            'E' => {}
            'R' => {
                return Err(Refused::new(
                    "pcre",
                    "flag 'R' matches relative to the previous content, which the matcher does not implement",
                ));
            }
            other => {
                return Err(Refused::new(
                    "pcre",
                    format!(
                        "flag '{other}' selects a buffer or behaviour the matcher does not implement"
                    ),
                ));
            }
        }
    }
    let mut out = String::from("(?-u)");
    if !inline.is_empty() {
        let _ = write!(out, "(?{inline})");
    }
    if anchored {
        out.push_str("\\A");
    }
    let _ = write!(out, "(?:{expression})");
    compile_pattern(&out).map_err(|_| {
        Refused::new(
            "pcre",
            "uses a construct the matcher does not implement, such as a backreference or a lookaround",
        )
    })?;
    Ok(out)
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
            engine
                .evaluate_payload_with_context(&from_outside, b"EXPN   root\r\n", None)
                .is_some()
        );
        // The pcre is anchored to the start of a line, so the words alone do not match.
        assert!(
            engine
                .evaluate_payload_with_context(&from_outside, b"HELO root expn\r\n", None)
                .is_none()
        );
        // The source must be outside the home networks.
        let from_inside = event([10, 9, 9, 9], 40000, INSIDE, 25);
        assert!(
            engine
                .evaluate_payload_with_context(&from_inside, b"expn root\r\n", None)
                .is_none()
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
            engine
                .evaluate_payload_with_context(&reply, b"\x00\x00Invalid login\r\n", None)
                .is_some()
        );
        // depth 16 from offset 0: the content must start within the first 3 bytes.
        assert!(
            engine
                .evaluate_payload_with_context(&reply, b"0123456789Invalid login", None)
                .is_none()
        );
    }

    #[test]
    fn honours_within_relative_to_the_content_before() {
        let engine = engine(compile(ET_SMB_POWERSHELL));
        let to_smb = event(OUTSIDE, 50000, INSIDE, 445);
        let near = b"\x00\x00\x00\x00\xffSMBxx PowerShell.exe -w   Hidden";
        assert!(
            engine
                .evaluate_payload_with_context(&to_smb, near, None)
                .is_some()
        );
        let far = b"\x00\x00\x00\x00\xffSMBxx PowerShell.exe -w                     hidden";
        assert!(
            engine
                .evaluate_payload_with_context(&to_smb, far, None)
                .is_none()
        );
        // SMB past depth 8 does not anchor the chain.
        let late = b"0123456789SMB powershell -w hidden";
        assert!(
            engine
                .evaluate_payload_with_context(&to_smb, late, None)
                .is_none()
        );
    }

    #[test]
    fn compiles_hex_contents_and_an_independent_group() {
        let rules = compile(ET_RDP_COOKIE);
        let imported = rules[0].imported.as_ref().map(|i| i.also_patterns.len());
        assert_eq!(imported, Some(1));
        assert_eq!(rules[0].severity, Severity::Low);
        let engine = engine(rules);
        let to_rdp = event(OUTSIDE, 50000, INSIDE, 3389);
        let hit = b"\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00COOKIE: MSTSHASH=EDC\r\n";
        assert!(
            engine
                .evaluate_payload_with_context(&to_rdp, hit, None)
                .is_some()
        );
        let wrong_gap = b"\x03\x00\x00\x2b\x26\x26\xe0\x00\x00\x00\x00\x00Cookie: mstshash=edc\r\n";
        assert!(
            engine
                .evaluate_payload_with_context(&to_rdp, wrong_gap, None)
                .is_none()
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
    fn refuses_what_it_does_not_implement_and_names_the_keyword() {
        let cases = [
            (ET_FOKIRTOR, "pcre", "flag 'R'"),
            (ET_ORACLE_BACKREF, "pcre", "backreference"),
            (ET_HTTP, "http", "application-layer protocol"),
            (ET_FLOWBITS, "flowbits", "State carried"),
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
            ("content:!\"abc\";", "content"),
            ("content:\"abc\"; distance:-2;", "distance"),
            ("content:\"abcdef\"; depth:3;", "depth"),
            ("content:\"abc\"; offset:4096;", "offset"),
            ("content:\"abc\"; dsize:>10;", "dsize"),
            ("content:\"abc\"; http.uri;", "http.uri"),
            ("content:\"abc\"; http_uri;", "http_uri"),
            ("content:\"abc\"; frobnicate;", "frobnicate"),
            ("flow:established;", "content"),
            (
                "content:\"abc\"; endswith; content:\"d\"; distance:0;",
                "endswith",
            ),
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
            engine
                .evaluate_payload_with_context(&e, b"GET /now!", None)
                .is_some()
        );
        assert!(
            engine
                .evaluate_payload_with_context(&e, b" GET /now!", None)
                .is_none()
        );
        assert!(
            engine
                .evaluate_payload_with_context(&e, b"GET /now!.", None)
                .is_none()
        );
    }

    #[test]
    fn independent_contents_match_in_either_order() {
        let engine = engine(compile(
            "alert tcp any any -> any 80 (msg:\"x\"; content:\"alpha\"; content:\"beta\"; sid:10;)",
        ));
        let e = event(OUTSIDE, 1, INSIDE, 80);
        assert!(
            engine
                .evaluate_payload_with_context(&e, b"beta..alpha", None)
                .is_some()
        );
        assert!(
            engine
                .evaluate_payload_with_context(&e, b"alpha only", None)
                .is_none()
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
            engine
                .evaluate_payload_with_context(&into_home, b"expn root", None)
                .is_some()
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
