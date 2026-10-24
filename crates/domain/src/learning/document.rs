//! Turning what a window observed into a document somebody can read.
//!
//! The aggregate is a description of a window; this is the allow-list that
//! describes it in the product's own rule language, so an operator reviews a
//! policy rather than a table of flows. Three things are deliberate:
//!
//! - **Every rule comes out in `observe` mode.** A document generated from a
//!   reading must never be able to refuse traffic the moment it is applied.
//! - **Every rule is written in the schema the agent already loads**, so the
//!   document is diffable against the configuration the node runs today and
//!   can be applied by the ordinary reload path.
//! - **What the document cannot say is written at the top of it.** A
//!   destination the node did not reach during the window is not in here, and
//!   a reader who takes it for a specification will refuse traffic that was
//!   simply never seen.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use crate::common::entity::Protocol;

use super::aggregate::LearningEdge;
use super::engine::LearningSession;
use super::entity::WorkloadKey;

/// How many addresses of one workload must share a prefix before the document
/// writes the prefix instead of the addresses.
///
/// Collapsing widens a rule past what was observed, which is why it takes a
/// handful of addresses rather than two, and why every collapsed rule carries
/// the addresses it was built from in a comment above it.
pub const PREFIX_COLLAPSE_MIN_ADDRESSES: usize = 4;

/// The IPv4 prefix length addresses are collapsed to.
pub const COLLAPSE_PREFIX_V4: u8 = 24;

/// The IPv6 prefix length addresses are collapsed to.
pub const COLLAPSE_PREFIX_V6: u8 = 64;

/// The priority the first generated rule takes.
///
/// Well clear of zero, which the rule language reserves, and high enough in
/// number that a hand-written rule keeps winning against a generated one
/// unless somebody renumbers deliberately.
pub const FIRST_GENERATED_PRIORITY: u32 = 1_000;

/// A rendered document, with what it took to render it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    /// The document itself, YAML the agent loads.
    pub yaml: String,
    /// Workloads it speaks for.
    pub workloads: usize,
    /// Rules written, the closing deny of each workload included.
    pub rules: usize,
    /// Rules whose destination is a prefix rather than an address.
    pub collapsed_rules: usize,
    /// Edges the document could not write, which is an edge whose workload
    /// stopped being expressible as a selector.
    pub skipped_edges: usize,
}

/// One rule, before it is written out.
pub(super) struct DraftRule {
    pub(super) id: String,
    pub(super) priority: u32,
    pub(super) allow: bool,
    pub(super) protocol: Protocol,
    pub(super) destination: Option<String>,
    pub(super) ports: Option<(u16, u16)>,
    pub(super) selector_key: String,
    pub(super) selector_value: String,
    pub(super) comment: Option<String>,
}

/// Render the allow-list this session's aggregate describes.
///
/// `now_ns` is only used for the elapsed figures in the header, so a document
/// rendered from a closed window is stable whenever it is asked for.
#[must_use]
pub fn render_policy(session: &LearningSession, now_ns: u64) -> PolicyDocument {
    let edges = session.aggregate.edges();
    let mut by_workload: BTreeMap<WorkloadKey, Vec<&LearningEdge>> = BTreeMap::new();
    for edge in &edges {
        by_workload
            .entry(edge.workload.clone())
            .or_default()
            .push(edge);
    }

    let mut drafts = Vec::new();
    let mut skipped_edges = 0;
    let mut priority = FIRST_GENERATED_PRIORITY;
    let mut workloads = 0;

    for (workload, edges) in &by_workload {
        let Ok(selector) = workload.to_selector() else {
            // A key that no longer writes as a selector cannot be a rule, and
            // a rule naming no workload would be about every workload.
            skipped_edges += edges.len();
            continue;
        };
        let (selector_key, selector_value) = selector_pair(&selector);
        workloads += 1;
        let slug = slug_of(&selector_value);
        let mut index = 0;

        for (protocol, group) in group_by_protocol(edges) {
            for (ports, addresses) in group_by_port_set(&group) {
                for destination in collapse_addresses(&addresses) {
                    for range in ports.iter() {
                        index += 1;
                        drafts.push(DraftRule {
                            id: format!("learn-{slug}-{index}"),
                            priority,
                            allow: true,
                            protocol,
                            destination: Some(destination.text.clone()),
                            ports: Some(*range),
                            selector_key: selector_key.to_string(),
                            selector_value: selector_value.clone(),
                            comment: destination.comment.clone(),
                        });
                        priority += 1;
                    }
                }
            }
        }

        index += 1;
        drafts.push(DraftRule {
            id: format!("learn-{slug}-{index}-deny-rest"),
            priority,
            allow: false,
            protocol: Protocol::Any,
            destination: None,
            ports: None,
            selector_key: selector_key.to_string(),
            selector_value: selector_value.clone(),
            comment: Some(
                "what makes the rules above an allow-list: everything else this workload\n\
                 opens. It counts while the mode is observe, and refuses the day somebody\n\
                 moves it to enforce."
                    .to_string(),
            ),
        });
        priority += 1;
    }

    let collapsed_rules = drafts
        .iter()
        .filter(|rule| {
            rule.destination
                .as_deref()
                .is_some_and(|dst| !dst.ends_with("/32") && !dst.ends_with("/128"))
        })
        .count();

    let mut yaml = header(
        session,
        now_ns,
        &edges,
        drafts.len(),
        workloads,
        skipped_edges,
    );
    yaml.push_str("firewall:\n  rules:\n");
    if drafts.is_empty() {
        yaml.push_str(
            "    # The window observed nothing it could write a rule for. An empty\n    \
             # allow-list is not a policy, so nothing is proposed here.\n    []\n",
        );
    }
    for draft in &drafts {
        write_rule(&mut yaml, draft);
    }

    PolicyDocument {
        yaml,
        workloads,
        rules: drafts.len(),
        collapsed_rules,
        skipped_edges,
    }
}

fn header(
    session: &LearningSession,
    now_ns: u64,
    edges: &[LearningEdge],
    rules: usize,
    workloads: usize,
    skipped_edges: usize,
) -> String {
    let progress = session.progress(now_ns);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# What this node reached, written as the rules that would allow it."
    );
    let _ = writeln!(out, "#");
    let _ = writeln!(out, "# Window:       {}", session.id);
    let _ = writeln!(out, "# Scope:        {}", progress.scope_description);
    let _ = writeln!(
        out,
        "# Observed:     {}s of the {}s asked for, status {}",
        progress.elapsed_secs,
        progress.requested_duration_secs,
        progress.status.as_str()
    );
    if progress.gap_secs > 0 || !progress.continuous {
        let _ = writeln!(
            out,
            "# Gap:          {}s of that window the agent was not running for",
            progress.gap_secs
        );
    }
    let _ = writeln!(
        out,
        "# Flows folded: {} readings, {} of them naming no workload, {} outside the scope",
        progress.observations, progress.unattributed, progress.out_of_scope
    );
    let _ = writeln!(
        out,
        "# Destinations: {} distinct, across {workloads} workloads, written as {rules} rules",
        edges.len()
    );
    if progress.dropped_edges > 0 {
        let _ = writeln!(
            out,
            "# Refused:      {} destinations the window had no room for. This document is",
            progress.dropped_edges
        );
        let _ = writeln!(
            out,
            "#               incomplete by that many destinations at least."
        );
    }
    if skipped_edges > 0 {
        let _ = writeln!(
            out,
            "# Unwritable:   {skipped_edges} destinations whose workload cannot be named by a rule"
        );
    }
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# A destination this node did not reach during the window is not in this"
    );
    let _ = writeln!(
        out,
        "# document. That is what the document is: a reading of one window, not a"
    );
    let _ = writeln!(
        out,
        "# specification of what the node is allowed to do. Read it, cut what should"
    );
    let _ = writeln!(out, "# not be there, add what the window did not catch.");
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# Every rule below is in observe mode, so applying this document refuses"
    );
    let _ = writeln!(
        out,
        "# nothing: it counts what it would have refused. Moving a rule to enforce is"
    );
    let _ = writeln!(out, "# a decision somebody takes, never a default.");
    let _ = writeln!(out, "#");
    out
}

/// A destination as the document writes it, with what it cost to write it
/// that way.
struct Destination {
    text: String,
    comment: Option<String>,
}

fn group_by_protocol<'a>(edges: &[&'a LearningEdge]) -> Vec<(Protocol, Vec<&'a LearningEdge>)> {
    let mut by_protocol: BTreeMap<u8, Vec<&'a LearningEdge>> = BTreeMap::new();
    for edge in edges {
        by_protocol
            .entry(edge.protocol.to_u8())
            .or_default()
            .push(edge);
    }
    by_protocol
        .into_iter()
        .map(|(proto, edges)| (Protocol::from_u8(proto), edges))
        .collect()
}

/// The ports one address was reached on, collapsed into contiguous ranges.
///
/// A rule carries one range and not a list, so 80 and 443 are two rules while
/// 8080 and 8081 are one. Grouping the addresses by their whole port set
/// first is what keeps those two rules about the same set of addresses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PortSet(Vec<(u16, u16)>);

impl PortSet {
    pub(super) fn of(ports: &[u16]) -> Self {
        let mut sorted: Vec<u16> = ports.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        for port in sorted {
            match ranges.last_mut() {
                Some(last) if port == last.1 + 1 => last.1 = port,
                _ => ranges.push((port, port)),
            }
        }
        Self(ranges)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &(u16, u16)> {
        self.0.iter()
    }
}

fn group_by_port_set(edges: &[&LearningEdge]) -> Vec<(PortSet, Vec<IpAddr>)> {
    let mut ports_by_address: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
    for edge in edges {
        ports_by_address
            .entry(edge.destination)
            .or_default()
            .push(edge.port);
    }
    let mut by_set: BTreeMap<PortSet, Vec<IpAddr>> = BTreeMap::new();
    for (address, ports) in ports_by_address {
        by_set.entry(PortSet::of(&ports)).or_default().push(address);
    }
    by_set.into_iter().collect()
}

/// Write a handful of addresses sharing a prefix as that prefix.
///
/// The collapse is what keeps a document about a node talking to a /24 of
/// backends from being thirty rules nobody reads. It also allows addresses
/// inside the prefix that were never observed, which is why it needs
/// [`PREFIX_COLLAPSE_MIN_ADDRESSES`] of them and why the rule it produces
/// says which addresses it came from.
fn collapse_addresses(addresses: &[IpAddr]) -> Vec<Destination> {
    let mut buckets: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    for address in addresses {
        buckets
            .entry(prefix_of(*address))
            .or_default()
            .push(*address);
    }
    let mut out = Vec::new();
    for (prefix, members) in buckets {
        if members.len() >= PREFIX_COLLAPSE_MIN_ADDRESSES {
            let observed: Vec<String> = members.iter().map(ToString::to_string).collect();
            out.push(Destination {
                text: prefix,
                comment: Some(format!(
                    "{} addresses in this prefix were reached: {}.\nThe rule allows the whole \
                     prefix, which is wider than what was observed.",
                    members.len(),
                    observed.join(", ")
                )),
            });
        } else {
            for address in members {
                out.push(Destination {
                    text: host_prefix(address),
                    comment: None,
                });
            }
        }
    }
    out
}

fn prefix_of(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/{COLLAPSE_PREFIX_V4}", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}::/{COLLAPSE_PREFIX_V6}",
                s[0], s[1], s[2], s[3]
            )
        }
    }
}

pub(super) fn host_prefix(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    }
}

pub(super) fn selector_pair(
    selector: &crate::firewall::workload::WorkloadSelector,
) -> (&'static str, String) {
    if let Some(container) = &selector.container {
        return ("container", container.clone());
    }
    if let Some(unit) = &selector.unit {
        return ("unit", unit.clone());
    }
    if let Some(exe) = &selector.exe {
        return ("exe", exe.clone());
    }
    // A selector with none of the three does not exist: `to_selector` refuses
    // it before a rule is drafted.
    ("cgroup", selector.cgroup.clone().unwrap_or_default())
}

/// An id a human can read and the rule language accepts.
pub(super) fn slug_of(value: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = true;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
        if slug.len() >= 48 {
            break;
        }
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "workload".to_string()
    } else {
        slug
    }
}

fn protocol_name(protocol: Protocol) -> String {
    match protocol {
        Protocol::Tcp => "tcp".to_string(),
        Protocol::Udp => "udp".to_string(),
        Protocol::Icmp => "icmp".to_string(),
        Protocol::Any => "any".to_string(),
        Protocol::Other(n) => n.to_string(),
    }
}

pub(super) fn write_rule(out: &mut String, rule: &DraftRule) {
    if let Some(comment) = &rule.comment {
        for line in comment.lines() {
            let _ = writeln!(out, "    # {}", line.trim());
        }
    }
    let _ = writeln!(out, "    - id: {}", rule.id);
    let _ = writeln!(out, "      priority: {}", rule.priority);
    let _ = writeln!(
        out,
        "      action: {}",
        if rule.allow { "allow" } else { "deny" }
    );
    let _ = writeln!(out, "      protocol: {}", protocol_name(rule.protocol));
    if let Some(destination) = &rule.destination {
        let _ = writeln!(out, "      dst_ip: {destination}");
    }
    if let Some((start, end)) = rule.ports {
        if start == end {
            let _ = writeln!(out, "      dst_port: {start}");
        } else {
            let _ = writeln!(out, "      dst_port: \"{start}-{end}\"");
        }
    }
    let _ = writeln!(out, "      workload:");
    let _ = writeln!(
        out,
        "        {}: {}",
        rule.selector_key,
        quote_if_needed(&rule.selector_value)
    );
    let _ = writeln!(out, "        mode: observe");
}

/// YAML quoting, for the values a selector can carry.
///
/// A unit name, a container name and a path are plain scalars in almost every
/// case, and the exceptions are what this is for: a value starting with a
/// character YAML reads as structure, or one carrying a colon followed by a
/// space.
fn quote_if_needed(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value.contains(": ")
        || value.ends_with(':')
        || value
            .chars()
            .next()
            .is_some_and(|c| "-?:,[]{}#&*!|>'\"%@` ".contains(c))
        || value.ends_with(' ');
    if needs_quotes {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::entity::{LearningScope, ObservedFlow, ObservedWorkload};

    fn flow(unit: &str, destination: &str, port: u16) -> ObservedFlow {
        ObservedFlow {
            workload: ObservedWorkload {
                exe: None,
                unit: Some(unit.to_string()),
                cgroup: None,
                container_id: None,
                container_name: None,
            },
            destination: destination.parse().expect("an address"),
            port,
            protocol: Protocol::Tcp,
        }
    }

    fn session_of(flows: &[ObservedFlow]) -> LearningSession {
        let mut session =
            LearningSession::new("l-1".to_string(), LearningScope::Node, 3_600, 1_024, 0)
                .expect("a window opens");
        for (i, flow) in flows.iter().enumerate() {
            session.observe(flow, (i as u64 + 1) * 1_000_000_000);
        }
        session
    }

    #[test]
    fn a_window_that_saw_nothing_proposes_nothing() {
        let document = render_policy(&session_of(&[]), 1_000_000_000);
        assert_eq!(document.rules, 0);
        assert_eq!(document.workloads, 0);
        assert!(document.yaml.contains("An empty"));
    }

    #[test]
    fn one_workload_becomes_its_allows_and_one_closing_deny() {
        let document = render_policy(
            &session_of(&[
                flow("nginx.service", "10.0.0.1", 443),
                flow("nginx.service", "10.0.0.1", 443),
                flow("nginx.service", "10.0.0.2", 5432),
            ]),
            10_000_000_000,
        );
        assert_eq!(document.workloads, 1);
        assert_eq!(document.rules, 3, "two allows and the closing deny");
        assert!(document.yaml.contains("dst_ip: 10.0.0.1/32"));
        assert!(document.yaml.contains("dst_port: 443"));
        assert!(document.yaml.contains("unit: nginx.service"));
        assert!(document.yaml.contains("action: deny"));
    }

    #[test]
    fn every_generated_rule_is_in_observe_mode() {
        let document = render_policy(
            &session_of(&[flow("nginx.service", "10.0.0.1", 443)]),
            10_000_000_000,
        );
        assert_eq!(
            document.yaml.matches("mode: observe").count(),
            document.rules
        );
        assert!(!document.yaml.contains("mode: enforce"));
    }

    #[test]
    fn contiguous_ports_become_one_range_and_the_rest_do_not() {
        let document = render_policy(
            &session_of(&[
                flow("api.service", "10.0.0.1", 8080),
                flow("api.service", "10.0.0.1", 8081),
                flow("api.service", "10.0.0.1", 8082),
                flow("api.service", "10.0.0.1", 9000),
            ]),
            10_000_000_000,
        );
        assert!(document.yaml.contains("dst_port: \"8080-8082\""));
        assert!(document.yaml.contains("dst_port: 9000"));
    }

    #[test]
    fn a_handful_of_addresses_in_one_prefix_collapse_and_say_so() {
        let document = render_policy(
            &session_of(&[
                flow("api.service", "10.0.0.1", 443),
                flow("api.service", "10.0.0.2", 443),
                flow("api.service", "10.0.0.3", 443),
                flow("api.service", "10.0.0.4", 443),
            ]),
            10_000_000_000,
        );
        assert!(document.yaml.contains("dst_ip: 10.0.0.0/24"));
        assert_eq!(document.collapsed_rules, 1);
        assert!(
            document.yaml.contains("wider than what was observed"),
            "a collapsed rule says what it cost"
        );
    }

    #[test]
    fn three_addresses_are_written_one_by_one() {
        let document = render_policy(
            &session_of(&[
                flow("api.service", "10.0.0.1", 443),
                flow("api.service", "10.0.0.2", 443),
                flow("api.service", "10.0.0.3", 443),
            ]),
            10_000_000_000,
        );
        assert_eq!(document.collapsed_rules, 0);
        assert!(document.yaml.contains("dst_ip: 10.0.0.1/32"));
        assert!(document.yaml.contains("dst_ip: 10.0.0.3/32"));
    }

    #[test]
    fn the_header_says_what_the_document_cannot_say() {
        let document = render_policy(
            &session_of(&[flow("nginx.service", "10.0.0.1", 443)]),
            10_000_000_000,
        );
        assert!(
            document
                .yaml
                .contains("did not reach during the window is not in this")
        );
        assert!(document.yaml.contains("# Window:       l-1"));
        assert!(document.yaml.contains("# Scope:"));
    }

    #[test]
    fn two_workloads_each_get_their_own_closing_deny() {
        let document = render_policy(
            &session_of(&[
                flow("a.service", "10.0.0.1", 443),
                flow("b.service", "10.0.0.2", 443),
            ]),
            10_000_000_000,
        );
        assert_eq!(document.workloads, 2);
        assert_eq!(document.yaml.matches("action: deny").count(), 2);
    }

    #[test]
    fn the_same_aggregate_renders_the_same_document_twice() {
        let session = session_of(&[
            flow("a.service", "10.0.0.2", 443),
            flow("b.service", "10.0.0.1", 80),
            flow("a.service", "10.0.0.1", 443),
        ]);
        assert_eq!(
            render_policy(&session, 10_000_000_000).yaml,
            render_policy(&session, 10_000_000_000).yaml
        );
    }

    #[test]
    fn a_priority_is_never_zero_because_the_language_reserves_it() {
        let document = render_policy(
            &session_of(&[flow("nginx.service", "10.0.0.1", 443)]),
            10_000_000_000,
        );
        assert!(!document.yaml.contains("priority: 0\n"));
        assert!(
            document
                .yaml
                .contains(&format!("priority: {FIRST_GENERATED_PRIORITY}"))
        );
    }

    #[test]
    fn a_name_with_spaces_is_quoted() {
        assert_eq!(quote_if_needed("nginx.service"), "nginx.service");
        assert_eq!(quote_if_needed("- odd"), "\"- odd\"");
        assert_eq!(quote_if_needed(""), "\"\"");
    }
}
