//! Segmenting the containers on a bridge from what a window saw them reach.
//!
//! Docker leaves every container on a bridge free to open a connection to
//! every other one. This turns a learning window into the rules that close
//! that: each container on a bridge keeps the peers it was seen reaching and
//! is refused the rest of the bridge's subnet. Three things are deliberate:
//!
//! - **Docker's embedded resolver and the bridge's gateway are written out
//!   explicitly**, ahead of the closing deny, because a container that cannot
//!   resolve a name or reach the host is broken in a way nobody connects to a
//!   firewall document. The resolver answers on `127.0.0.11` inside every
//!   container on a user-defined network, and the default bridge has none.
//! - **Only what is on the bridge is decided here.** A destination outside the
//!   bridge's subnet falls through to whatever comes after, which is the
//!   allow-list a window also produces, so the two documents load together.
//! - **A container the window never saw gets no rule.** Writing a closing deny
//!   for a container nothing is known about would cut every peer it has; it is
//!   named at the top of the document instead, so the operator widens the
//!   window or writes its rules by hand.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use ebpf_common::workload_policy::WORKLOAD_POLICY_MAX_RULES;

use crate::common::entity::Protocol;
use crate::firewall::workload::WorkloadSelector;

use super::aggregate::LearningEdge;
use super::document::{DraftRule, PortSet, host_prefix, selector_pair, slug_of, write_rule};
use super::engine::LearningSession;
use super::entity::WorkloadKey;

/// The priority the first segmentation rule takes.
///
/// Below the allow-list's first rule, so loading both documents puts the
/// bridge's closing deny ahead of an allow-list rule that would otherwise
/// admit a peer the segmentation refuses.
pub const FIRST_SEGMENTATION_PRIORITY: u32 = 100;

/// Where Docker's embedded resolver answers, inside every container on a
/// user-defined network.
pub const DOCKER_EMBEDDED_DNS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 11);

/// One subnet a bridge network carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeSubnet {
    /// The network address.
    pub network: IpAddr,
    /// Its prefix length.
    pub prefix_len: u8,
    /// The bridge's own address on it, which is the host.
    pub gateway: Option<IpAddr>,
}

impl BridgeSubnet {
    /// Whether `address` is on this subnet.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let len = u32::from(self.prefix_len.min(32));
                let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let len = u32::from(self.prefix_len.min(128));
                let mask = if len == 0 {
                    0
                } else {
                    u128::MAX << (128 - len)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }

    /// The subnet as a rule writes it.
    #[must_use]
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network, self.prefix_len)
    }
}

/// One container attached to a bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeMember {
    /// Container id, in full.
    pub id: String,
    /// Container name, without the leading slash.
    pub name: String,
    /// Its addresses on this bridge.
    pub addresses: Vec<IpAddr>,
}

/// One bridge network and the containers on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeNetwork {
    /// The network's name.
    pub name: String,
    /// The subnets it carries.
    pub subnets: Vec<BridgeSubnet>,
    /// Whether the runtime answers names on [`DOCKER_EMBEDDED_DNS`] for the
    /// containers on it, which is every user-defined network and not the
    /// default bridge.
    pub embedded_dns: bool,
    /// Containers attached to it.
    pub members: Vec<BridgeMember>,
}

/// A rendered segmentation document, with what it took to render it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentationDocument {
    /// The document itself, YAML the agent loads.
    pub yaml: String,
    /// Bridges that carried at least one container.
    pub bridges: usize,
    /// Containers given rules, counted once per bridge they sit on.
    pub containers: usize,
    /// Rules written.
    pub rules: usize,
    /// Rules letting a container through to a peer on its bridge.
    pub peer_rules: usize,
    /// Containers on a bridge the window never saw, by name.
    pub unlearned: Vec<String>,
    /// Containers the window saw under a name no rule can select them by.
    pub unnamed: Vec<String>,
}

/// Render the rules that segment `bridges` from what `session` saw.
///
/// `now_ns` is only used for the elapsed figures in the header.
#[must_use]
pub fn render_segmentation(
    session: &LearningSession,
    bridges: &[BridgeNetwork],
    now_ns: u64,
) -> SegmentationDocument {
    let edges = session.aggregate.edges();
    let seen: BTreeSet<&WorkloadKey> = edges.iter().map(|edge| &edge.workload).collect();

    let mut drafts = Vec::new();
    let mut priority = FIRST_SEGMENTATION_PRIORITY;
    let mut containers = 0;
    let mut peer_rules = 0;
    let mut used_bridges = 0;
    let mut unlearned = BTreeSet::new();
    let mut unnamed = BTreeSet::new();

    for bridge in bridges {
        if bridge.members.is_empty() || bridge.subnets.is_empty() {
            continue;
        }
        used_bridges += 1;
        for member in &bridge.members {
            let Some(key) = key_of(member, &seen) else {
                unlearned.insert(member.name.clone());
                continue;
            };
            let Ok(selector) = key.to_selector() else {
                unnamed.insert(member.name.clone());
                continue;
            };
            containers += 1;
            peer_rules += draft_member(
                bridge,
                member,
                key,
                &selector,
                &edges,
                &mut priority,
                &mut drafts,
            );
        }
    }

    let unlearned: Vec<String> = unlearned.into_iter().collect();
    let unnamed: Vec<String> = unnamed.into_iter().collect();
    let mut yaml = header(
        session,
        now_ns,
        used_bridges,
        containers,
        drafts.len(),
        &unlearned,
        &unnamed,
    );
    yaml.push_str("firewall:\n  rules:\n");
    if drafts.is_empty() {
        yaml.push_str(
            "    # No container on a bridge was seen during the window, so there is\n    \
             # nothing to segment from.\n    []\n",
        );
    }
    for draft in &drafts {
        write_rule(&mut yaml, draft);
    }

    SegmentationDocument {
        yaml,
        bridges: used_bridges,
        containers,
        rules: drafts.len(),
        peer_rules,
        unlearned,
        unnamed,
    }
}

/// The rules for one container on one bridge, pushed onto `drafts`; returns
/// how many of them let it through to a peer.
fn draft_member(
    bridge: &BridgeNetwork,
    member: &BridgeMember,
    key: &WorkloadKey,
    selector: &WorkloadSelector,
    edges: &[LearningEdge],
    priority: &mut u32,
    drafts: &mut Vec<DraftRule>,
) -> usize {
    let peers: BTreeMap<IpAddr, &str> = bridge
        .members
        .iter()
        .flat_map(|member| {
            member
                .addresses
                .iter()
                .map(move |address| (*address, member.name.as_str()))
        })
        .collect();
    let mut peer_rules = 0;
    let (selector_key, selector_value) = selector_pair(selector);
    let mut rules = MemberRules {
        id_base: format!("seg-{}-{}", slug_of(&selector_value), slug_of(&bridge.name)),
        selector_key,
        selector_value,
        index: 0,
    };
    let own: BTreeSet<IpAddr> = member.addresses.iter().copied().collect();

    if bridge.embedded_dns {
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            drafts.push(
                rules.draft(
                    priority,
                    true,
                    protocol,
                    Some(format!("{DOCKER_EMBEDDED_DNS}/32")),
                    Some((53, 53)),
                    Some(
                        "Docker's embedded resolver. Every name this container resolves\n\
                         goes here first, so refusing it breaks the container outright."
                            .to_string(),
                    ),
                ),
            );
        }
    }
    for gateway in bridge.subnets.iter().filter_map(|subnet| subnet.gateway) {
        drafts.push(rules.draft(
            priority,
            true,
            Protocol::Any,
            Some(host_prefix(gateway)),
            None,
            Some(format!(
                "the gateway of {}, which is the host itself. What this container\n\
                     may reach on the host is the allow-list's question, not the bridge's.",
                bridge.name
            )),
        ));
    }
    for ((protocol, peer), ports) in peer_edges(edges, key, bridge, &own) {
        let protocol = Protocol::from_u8(protocol);
        let name = peers
            .get(&peer)
            .copied()
            .unwrap_or("an address no container holds");
        for range in PortSet::of(&ports).iter() {
            drafts.push(rules.draft(
                priority,
                true,
                protocol,
                Some(host_prefix(peer)),
                Some(*range),
                Some(format!("{name}, reached during the window")),
            ));
            peer_rules += 1;
        }
    }
    for subnet in &bridge.subnets {
        drafts.push(rules.draft(
            priority,
            false,
            Protocol::Any,
            Some(subnet.cidr()),
            None,
            Some(format!(
                "every other container on {}. It counts while the mode is observe,\n\
                     and refuses the day somebody moves it to enforce.",
                bridge.name
            )),
        ));
    }
    peer_rules
}

/// The key the window filed `member` under, by name first and then by id.
fn key_of<'a>(member: &BridgeMember, seen: &BTreeSet<&'a WorkloadKey>) -> Option<&'a WorkloadKey> {
    [member.name.as_str(), member.id.as_str()]
        .into_iter()
        .filter(|value| !value.is_empty())
        .find_map(|value| {
            seen.get(&WorkloadKey::Container(value.to_string()))
                .copied()
        })
}

/// The peers on `bridge` this workload reached, with the ports it reached
/// them on. Its own addresses and the gateway are left out: the first is not
/// a peer and the second has its own rule.
fn peer_edges(
    edges: &[LearningEdge],
    key: &WorkloadKey,
    bridge: &BridgeNetwork,
    own: &BTreeSet<IpAddr>,
) -> BTreeMap<(u8, IpAddr), Vec<u16>> {
    let gateways: BTreeSet<IpAddr> = bridge.subnets.iter().filter_map(|s| s.gateway).collect();
    let mut out: BTreeMap<(u8, IpAddr), Vec<u16>> = BTreeMap::new();
    for edge in edges.iter().filter(|edge| &edge.workload == key) {
        let on_bridge = bridge.subnets.iter().any(|s| s.contains(edge.destination));
        if !on_bridge || own.contains(&edge.destination) || gateways.contains(&edge.destination) {
            continue;
        }
        out.entry((edge.protocol.to_u8(), edge.destination))
            .or_default()
            .push(edge.port);
    }
    out
}

/// The rules of one container on one bridge, numbered as they are drafted.
struct MemberRules {
    id_base: String,
    selector_key: &'static str,
    selector_value: String,
    index: usize,
}

impl MemberRules {
    fn draft(
        &mut self,
        priority: &mut u32,
        allow: bool,
        protocol: Protocol,
        destination: Option<String>,
        ports: Option<(u16, u16)>,
        comment: Option<String>,
    ) -> DraftRule {
        self.index += 1;
        let rule = DraftRule {
            id: format!("{}-{}", self.id_base, self.index),
            priority: *priority,
            allow,
            protocol,
            destination,
            ports,
            selector_key: self.selector_key.to_string(),
            selector_value: self.selector_value.clone(),
            comment,
        };
        *priority += 1;
        rule
    }
}

fn header(
    session: &LearningSession,
    now_ns: u64,
    bridges: usize,
    containers: usize,
    rules: usize,
    unlearned: &[String],
    unnamed: &[String],
) -> String {
    let progress = session.progress(now_ns);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# The containers on this node's bridges, kept to the peers they reached."
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
    let _ = writeln!(
        out,
        "# Segmented:    {containers} containers across {bridges} bridges, written as {rules} rules"
    );
    if !unlearned.is_empty() {
        let _ = writeln!(
            out,
            "# Not seen:     {}. The window holds nothing about these, so they",
            unlearned.join(", ")
        );
        let _ = writeln!(
            out,
            "#               get no rule and can still reach every peer on their bridge."
        );
    }
    if !unnamed.is_empty() {
        let _ = writeln!(
            out,
            "# Unwritable:   {}. The window saw these under a name no rule can select,",
            unnamed.join(", ")
        );
        let _ = writeln!(out, "#               so they get no rule either.");
    }
    if rules > WORKLOAD_POLICY_MAX_RULES {
        let _ = writeln!(
            out,
            "# Too many:     the kernel walks {WORKLOAD_POLICY_MAX_RULES} workload rules on a node and this document"
        );
        let _ = writeln!(
            out,
            "#               has {rules}. Load it for the containers that matter most."
        );
    }
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# Each rule decides what a container opens, so a container left out of"
    );
    let _ = writeln!(
        out,
        "# this document can still open a connection toward one that is in it."
    );
    let _ = writeln!(
        out,
        "# Destinations off the bridge are not decided here: they fall through to"
    );
    let _ = writeln!(out, "# the allow-list the same window writes.");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::entity::{LearningScope, ObservedFlow, ObservedWorkload};

    fn flow(container: &str, destination: &str, port: u16, protocol: Protocol) -> ObservedFlow {
        ObservedFlow {
            workload: ObservedWorkload {
                exe: None,
                unit: None,
                cgroup: None,
                container_id: None,
                container_name: Some(container.to_string()),
            },
            destination: destination.parse().expect("an address"),
            port,
            protocol,
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

    fn member(name: &str, address: &str) -> BridgeMember {
        BridgeMember {
            id: format!("{name}-id"),
            name: name.to_string(),
            addresses: vec![address.parse().expect("an address")],
        }
    }

    fn app_network(members: Vec<BridgeMember>) -> BridgeNetwork {
        BridgeNetwork {
            name: "app".to_string(),
            subnets: vec![BridgeSubnet {
                network: "172.18.0.0".parse().expect("an address"),
                prefix_len: 16,
                gateway: Some("172.18.0.1".parse().expect("an address")),
            }],
            embedded_dns: true,
            members,
        }
    }

    #[test]
    fn a_container_keeps_the_peer_it_reached_and_is_refused_the_rest_of_the_bridge() {
        let session = session_of(&[
            flow("web", "172.18.0.3", 5432, Protocol::Tcp),
            flow("web", "93.184.216.34", 443, Protocol::Tcp),
            flow("postgres", "172.18.0.1", 123, Protocol::Udp),
        ]);
        let network = app_network(vec![
            member("web", "172.18.0.2"),
            member("postgres", "172.18.0.3"),
        ]);
        let document = render_segmentation(&session, &[network], 10_000_000_000);

        assert_eq!(document.containers, 2);
        assert_eq!(
            document.peer_rules, 1,
            "web reached postgres, postgres reached no peer"
        );
        assert!(document.yaml.contains("dst_ip: 172.18.0.3/32"));
        assert!(document.yaml.contains("dst_port: 5432"));
        assert!(
            document
                .yaml
                .contains("postgres, reached during the window")
        );
        assert_eq!(document.yaml.matches("dst_ip: 172.18.0.0/16").count(), 2);
        assert!(
            !document.yaml.contains("93.184.216.34"),
            "a destination off the bridge is the allow-list's business"
        );
    }

    #[test]
    fn the_embedded_resolver_and_the_gateway_come_before_the_closing_deny() {
        let session = session_of(&[flow("web", "172.18.0.3", 80, Protocol::Tcp)]);
        let network = app_network(vec![member("web", "172.18.0.2")]);
        let yaml = render_segmentation(&session, &[network], 10_000_000_000).yaml;

        let dns = yaml
            .find("dst_ip: 127.0.0.11/32")
            .expect("the resolver is allowed");
        let gateway = yaml
            .find("dst_ip: 172.18.0.1/32")
            .expect("the gateway is allowed");
        let deny = yaml
            .find("dst_ip: 172.18.0.0/16")
            .expect("the bridge is closed");
        assert!(dns < deny && gateway < deny);
        assert_eq!(
            yaml.matches("dst_ip: 127.0.0.11/32").count(),
            2,
            "udp and tcp"
        );
    }

    #[test]
    fn the_default_bridge_has_no_embedded_resolver_rule() {
        let session = session_of(&[flow("web", "172.17.0.3", 80, Protocol::Tcp)]);
        let network = BridgeNetwork {
            name: "bridge".to_string(),
            subnets: vec![BridgeSubnet {
                network: "172.17.0.0".parse().expect("an address"),
                prefix_len: 16,
                gateway: Some("172.17.0.1".parse().expect("an address")),
            }],
            embedded_dns: false,
            members: vec![member("web", "172.17.0.2")],
        };
        let yaml = render_segmentation(&session, &[network], 10_000_000_000).yaml;
        assert!(!yaml.contains("127.0.0.11"));
        assert!(yaml.contains("dst_ip: 172.17.0.1/32"));
    }

    #[test]
    fn a_container_the_window_never_saw_gets_no_rule_and_is_named() {
        let session = session_of(&[flow("web", "172.18.0.3", 80, Protocol::Tcp)]);
        let network = app_network(vec![
            member("web", "172.18.0.2"),
            member("cache", "172.18.0.4"),
        ]);
        let document = render_segmentation(&session, &[network], 10_000_000_000);

        assert_eq!(document.containers, 1);
        assert_eq!(document.unlearned, vec!["cache".to_string()]);
        assert!(document.yaml.contains("Not seen:     cache"));
        assert!(!document.yaml.contains("container: cache"));
    }

    #[test]
    fn a_container_seen_under_a_name_no_selector_takes_is_named_as_unwritable() {
        let session = session_of(&[flow("db", "172.18.0.3", 80, Protocol::Tcp)]);
        let network = app_network(vec![member("db", "172.18.0.2")]);
        let document = render_segmentation(&session, &[network], 10_000_000_000);
        assert_eq!(document.containers, 0);
        assert_eq!(document.unnamed, vec!["db".to_string()]);
        assert!(document.yaml.contains("Unwritable:   db"));
        assert!(document.unlearned.is_empty(), "the window did see it");
    }

    #[test]
    fn a_container_filed_under_its_id_is_still_found() {
        let session = session_of(&[flow("web-id", "172.18.0.3", 80, Protocol::Tcp)]);
        let network = app_network(vec![member("web", "172.18.0.2")]);
        let document = render_segmentation(&session, &[network], 10_000_000_000);
        assert_eq!(document.containers, 1);
        assert!(document.yaml.contains("container: web-id"));
    }

    #[test]
    fn every_rule_is_in_observe_mode_and_sorts_ahead_of_the_allow_list() {
        let session = session_of(&[flow("web", "172.18.0.3", 80, Protocol::Tcp)]);
        let network = app_network(vec![member("web", "172.18.0.2")]);
        let document = render_segmentation(&session, &[network], 10_000_000_000);
        assert_eq!(
            document.yaml.matches("mode: observe").count(),
            document.rules
        );
        assert!(
            document
                .yaml
                .contains(&format!("priority: {FIRST_SEGMENTATION_PRIORITY}"))
        );
        assert!(
            FIRST_SEGMENTATION_PRIORITY + u32::try_from(document.rules).expect("small")
                < super::super::document::FIRST_GENERATED_PRIORITY
        );
    }

    #[test]
    fn no_bridge_container_seen_proposes_nothing() {
        let document = render_segmentation(&session_of(&[]), &[], 1_000_000_000);
        assert_eq!(document.rules, 0);
        assert!(document.yaml.contains("nothing to segment"));
    }

    #[test]
    fn a_subnet_contains_only_its_own_family_and_prefix() {
        let subnet = BridgeSubnet {
            network: "172.18.0.0".parse().expect("an address"),
            prefix_len: 16,
            gateway: None,
        };
        assert!(subnet.contains("172.18.255.4".parse().expect("an address")));
        assert!(!subnet.contains("172.19.0.4".parse().expect("an address")));
        assert!(!subnet.contains("fd00::1".parse().expect("an address")));
        let v6 = BridgeSubnet {
            network: "fd00:1::".parse().expect("an address"),
            prefix_len: 64,
            gateway: None,
        };
        assert!(v6.contains("fd00:1::9".parse().expect("an address")));
        assert!(!v6.contains("fd00:2::9".parse().expect("an address")));
    }
}
