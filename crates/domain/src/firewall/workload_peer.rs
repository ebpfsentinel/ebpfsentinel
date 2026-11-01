//! A workload rule whose destination is a workload on another node.
//!
//! The address of a pod on another node says nothing on its own, and a rule
//! written against an address range goes stale the moment the pod moves.
//! The console hands every node the identities behind its peers' addresses,
//! so a rule can name the workload it reaches the way it names the workload
//! it is about: by its pod and namespace labels, its service account, its
//! container or its guest.
//!
//! Two ends can decide such a rule. The source always can: the node the
//! connection leaves knows the calling workload and looks the destination
//! address up in the list. The destination can only where the address the
//! connection arrives from is still the address of the workload that opened
//! it, and where the rule's source half is something an address carries. A
//! connection translated on its way (a source NAT, an egress gateway, a node
//! masquerading what leaves it) arrives from an address that names the node
//! or the gateway, so the destination cannot know whose it is and decides
//! nothing about it. Which rules are decided at both ends and which at the
//! source alone is computed here, with the reason, so the status an operator
//! reads says it rather than leaving it to be found the day a node without
//! the agent connects.

use serde::{Deserialize, Serialize};

use crate::common::entity::{Protocol, RuleId};
use crate::identity::{AddressIdentity, IdentityKind};
use crate::netpol::LabelSelector;

use super::entity::FirewallAction;
use super::error::FirewallError;
use super::workload::{
    WORKLOAD_MATCHER_MAX_LEN, WorkloadFacts, WorkloadPolicy, WorkloadRule, WorkloadSelector,
    is_id_like,
};

/// Which workload on another node a rule reaches.
///
/// Every matcher that is set has to match, and an identity that does not
/// carry the fact a matcher asks for is a mismatch, as for the source half.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSelector {
    /// What sits behind the address: a host, a container, a pod or a guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<IdentityKind>,
    /// The container, by name or by an id prefix of at least twelve
    /// characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Labels of the pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pods: Option<LabelSelector>,
    /// Labels of the pod's namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<LabelSelector>,
    /// The service account the pod runs as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    /// The guest, by the name its hypervisor gives it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<String>,
}

impl PeerSelector {
    /// Check every matcher this selector carries.
    ///
    /// # Errors
    ///
    /// [`FirewallError::InvalidWorkloadSelector`] for a selector naming
    /// nothing, an empty or oversized matcher, or a label selector Kubernetes
    /// itself would refuse.
    pub fn validate(&self) -> Result<(), FirewallError> {
        let refuse = |reason: String| Err(FirewallError::InvalidWorkloadSelector { reason });
        if self.kind.is_none()
            && self.container.is_none()
            && self.pods.is_none()
            && self.namespaces.is_none()
            && self.service_account.is_none()
            && self.guest.is_none()
        {
            return refuse(
                "workload.peer must name at least one of kind, container, pods, namespaces, \
                 service_account or guest"
                    .to_string(),
            );
        }
        for (field, value) in [
            ("peer.container", self.container.as_deref()),
            ("peer.service_account", self.service_account.as_deref()),
            ("peer.guest", self.guest.as_deref()),
        ] {
            let Some(value) = value else { continue };
            if value.is_empty() {
                return refuse(format!("{field} must not be empty"));
            }
            if value.len() > WORKLOAD_MATCHER_MAX_LEN {
                return refuse(format!(
                    "{field} is {} bytes, more than the {WORKLOAD_MATCHER_MAX_LEN} a matcher may \
                     carry",
                    value.len()
                ));
            }
            if value.contains(['\n', '\r', '\0']) {
                return refuse(format!("{field} contains a control character"));
            }
        }
        for (field, selector) in [
            ("peer.pods", self.pods.as_ref()),
            ("peer.namespaces", self.namespaces.as_ref()),
        ] {
            if let Some(selector) = selector
                && let Err(reason) = selector.validate()
            {
                return refuse(format!("{field}: {reason}"));
            }
        }
        if self.guest.is_some() && self.names_kubernetes_or_container() {
            return refuse(
                "peer.guest names a virtual machine and cannot be combined with a container or \
                 a pod matcher"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn names_kubernetes_or_container(&self) -> bool {
        self.container.is_some()
            || self.pods.is_some()
            || self.namespaces.is_some()
            || self.service_account.is_some()
    }

    /// Whether the workload the list names at an address is this one.
    #[must_use]
    pub fn matches_remote(&self, identity: &AddressIdentity) -> bool {
        if let Some(kind) = self.kind
            && kind != identity.kind
        {
            return false;
        }
        if let Some(guest) = self.guest.as_deref() {
            return identity.kind == IdentityKind::Guest
                && identity.guest.as_deref() == Some(guest);
        }
        let facts = RemoteFacts::of(identity);
        if let Some(container) = self.container.as_deref()
            && !facts.container_matches(container)
        {
            return false;
        }
        self.kubernetes_match(&facts.facts())
    }

    /// Whether a workload of this node is this one, for a connection arriving
    /// at it.
    ///
    /// A guest's sockets are in its own kernel, so a guest is never matched
    /// here; a rule naming one is decided at the source alone.
    #[must_use]
    pub fn matches_local(&self, facts: &WorkloadFacts<'_>) -> bool {
        if self.guest.is_some() {
            return false;
        }
        if let Some(kind) = self.kind {
            let local = if facts.pod_labels.is_some() {
                IdentityKind::Pod
            } else if facts.container_id.is_some() {
                IdentityKind::Container
            } else {
                IdentityKind::Host
            };
            if kind != local {
                return false;
            }
        }
        if let Some(container) = self.container.as_deref() {
            let named = facts.container_name == Some(container)
                || facts.container_id.is_some_and(|id| {
                    id == container || (is_id_like(container) && id.starts_with(container))
                });
            if !named {
                return false;
            }
        }
        self.kubernetes_match(facts)
    }

    fn kubernetes_match(&self, facts: &WorkloadFacts<'_>) -> bool {
        if let Some(pods) = self.pods.as_ref()
            && !facts.pod_labels.is_some_and(|labels| pods.matches(labels))
        {
            return false;
        }
        if let Some(namespaces) = self.namespaces.as_ref()
            && !facts
                .namespace_labels
                .is_some_and(|labels| namespaces.matches(labels))
        {
            return false;
        }
        if let Some(account) = self.service_account.as_deref()
            && facts.service_account != Some(account)
        {
            return false;
        }
        true
    }

    /// The selector as one line, for the command line and an alert.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(kind) = self.kind {
            parts.push(format!("kind={}", kind.as_str()));
        }
        for (field, value) in [
            ("container", self.container.as_deref()),
            ("service_account", self.service_account.as_deref()),
            ("guest", self.guest.as_deref()),
        ] {
            if let Some(value) = value {
                parts.push(format!("{field}={value}"));
            }
        }
        for (field, selector) in [
            ("pods", self.pods.as_ref()),
            ("namespaces", self.namespaces.as_ref()),
        ] {
            if let Some(selector) = selector {
                if selector.is_empty() {
                    parts.push(format!("{field}=*"));
                } else {
                    parts.push(format!("{field}={{{}}}", selector.describe()));
                }
            }
        }
        format!("peer {}", parts.join(" "))
    }
}

/// What an identity in the list offers a selector, in the form the source
/// half is matched against.
struct RemoteFacts<'a> {
    identity: &'a AddressIdentity,
}

impl<'a> RemoteFacts<'a> {
    fn of(identity: &'a AddressIdentity) -> Self {
        Self { identity }
    }

    fn container_matches(&self, wanted: &str) -> bool {
        let Some(container) = self.identity.container.as_deref() else {
            return false;
        };
        container == wanted
            || (is_id_like(wanted) && is_id_like(container) && container.starts_with(wanted))
    }

    fn facts(&self) -> WorkloadFacts<'a> {
        let identity = self.identity;
        let pod = identity.kind == IdentityKind::Pod;
        let container = identity.container.as_deref();
        WorkloadFacts {
            container_name: container,
            container_id: container.filter(|value| is_id_like(value)),
            pod_labels: pod.then_some(&identity.pod_labels),
            namespace_labels: (pod && identity.namespace.is_some())
                .then_some(&identity.namespace_labels),
            service_account: identity.service_account.as_deref(),
            ..WorkloadFacts::default()
        }
    }
}

/// Whether the source half of a rule names the workload the list carries at
/// an address, for a connection arriving from it.
///
/// Only the matchers an address carries are read; a selector naming anything
/// else is never decided at the destination, see [`source_unreadable`].
#[must_use]
pub fn source_matches_remote(selector: &WorkloadSelector, identity: &AddressIdentity) -> bool {
    if let Some(guest) = selector.guest.as_deref() {
        return identity.kind == IdentityKind::Guest && identity.guest.as_deref() == Some(guest);
    }
    let facts = RemoteFacts::of(identity);
    if let Some(container) = selector.container.as_deref()
        && !facts.container_matches(container)
    {
        return false;
    }
    let without_container = WorkloadSelector {
        container: None,
        ..selector.clone()
    };
    if without_container.is_empty() {
        return true;
    }
    without_container.matches_besides_lineage(&facts.facts())
}

/// The matcher of a source selector no address carries, if it has one.
#[must_use]
pub fn source_unreadable(selector: &WorkloadSelector) -> Option<&'static str> {
    [
        ("exe", selector.exe.is_some()),
        ("unit", selector.unit.is_some()),
        ("cgroup", selector.cgroup.is_some()),
        ("parent", selector.parent.is_some()),
        ("ancestor", selector.ancestor.is_some()),
    ]
    .into_iter()
    .find_map(|(field, set)| set.then_some(field))
}

/// Which ends decide a rule naming a remote workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerEnds {
    /// The node the connection leaves and the node it arrives at.
    Both,
    /// The node the connection leaves, and no other.
    Source,
}

impl PeerEnds {
    /// The word the API and the command line use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Source => "source",
        }
    }
}

/// One rule naming a remote workload, and where it is decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerRuleEnds {
    pub rule: RuleId,
    /// The rule's position among the enabled rules, which is its kernel slot.
    pub slot: usize,
    pub ends: PeerEnds,
    /// Why the destination cannot decide it, for a rule decided at the
    /// source alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl WorkloadPolicy {
    /// Every enabled rule naming a remote workload, with the ends that decide
    /// it, in slot order.
    ///
    /// The destination walks only the rules it can decide, so a rule is
    /// decided there only if no rule above it that the destination cannot
    /// read would have let the connection through first at the source: the
    /// destination refusing what the source allowed would be a rule meaning
    /// two things depending on where it is read.
    #[must_use]
    pub fn peer_ends(&self) -> Vec<PeerRuleEnds> {
        let mut above: Vec<&WorkloadRule> = Vec::new();
        let mut ends = Vec::new();
        for (slot, rule) in self.in_slot_order().enumerate() {
            if let Some(peer) = rule.dst_peer.as_ref() {
                let reason = destination_refusal(rule, peer, &above);
                ends.push(PeerRuleEnds {
                    rule: rule.id.clone(),
                    slot,
                    ends: if reason.is_some() {
                        PeerEnds::Source
                    } else {
                        PeerEnds::Both
                    },
                    reason,
                });
            }
            above.push(rule);
        }
        ends
    }

    /// The slots the destination decides, as a mask.
    #[must_use]
    pub fn destination_slots(&self) -> u64 {
        self.peer_ends()
            .iter()
            .filter(|ends| ends.ends == PeerEnds::Both)
            .fold(0, |mask, ends| mask | (1u64 << (ends.slot & 63)))
    }

    /// Whether any enabled rule names a remote workload.
    #[must_use]
    pub fn names_peers(&self) -> bool {
        self.in_slot_order().any(|rule| rule.dst_peer.is_some())
    }
}

fn destination_refusal(
    rule: &WorkloadRule,
    peer: &PeerSelector,
    above: &[&WorkloadRule],
) -> Option<String> {
    if let Some(field) = source_unreadable(&rule.selector) {
        return Some(format!(
            "the source is named by {field}, which no address carries"
        ));
    }
    if rule.protocol == Protocol::Udp {
        return Some("a datagram opens no connection the destination could decide on".to_string());
    }
    if peer.guest.is_some() {
        return Some(
            "a guest's sockets are in its own kernel, out of the node's reach".to_string(),
        );
    }
    for earlier in above {
        let decided_there = earlier
            .dst_peer
            .as_ref()
            .is_some_and(|p| destination_refusal(earlier, p, &[]).is_none());
        if earlier.action == FirewallAction::Allow
            && !decided_there
            && overlaps(earlier.protocol, rule.protocol)
        {
            return Some(format!(
                "rule {} above it may allow the connection at the source, and the destination \
                 cannot read it",
                earlier.id.0
            ));
        }
    }
    None
}

fn overlaps(a: Protocol, b: Protocol) -> bool {
    a == Protocol::Any || b == Protocol::Any || a == b
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use super::*;
    use crate::firewall::workload::{DestinationAddr, WorkloadDestination, WorkloadMode};

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn pods(pairs: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: labels(pairs),
            match_expressions: Vec::new(),
        }
    }

    fn pod(address: &str, app: &str, account: &str) -> AddressIdentity {
        AddressIdentity {
            address: address.parse::<IpAddr>().expect("an address"),
            kind: IdentityKind::Pod,
            container: Some("app".to_string()),
            image: None,
            pod: Some(format!("{app}-0")),
            namespace: Some("shop".to_string()),
            service_account: Some(account.to_string()),
            guest: None,
            pod_labels: labels(&[("app", app)]),
            namespace_labels: labels(&[("team", "shop")]),
            services: Vec::new(),
        }
    }

    fn peer_rule(
        id: &str,
        priority: u32,
        selector: WorkloadSelector,
        peer: PeerSelector,
    ) -> WorkloadRule {
        WorkloadRule {
            id: RuleId(id.to_string()),
            priority,
            action: FirewallAction::Allow,
            mode: WorkloadMode::Enforce,
            selector,
            protocol: Protocol::Tcp,
            dst_ip: None,
            dst_port: None,
            dst_fqdn: Vec::new(),
            dst_peer: Some(peer),
            enabled: true,
        }
    }

    fn by_pods(pairs: &[(&str, &str)]) -> WorkloadSelector {
        WorkloadSelector {
            pods: Some(pods(pairs)),
            ..WorkloadSelector::default()
        }
    }

    fn to_db() -> PeerSelector {
        PeerSelector {
            pods: Some(pods(&[("app", "db")])),
            ..PeerSelector::default()
        }
    }

    #[test]
    fn a_selector_naming_nothing_is_refused() {
        assert!(PeerSelector::default().validate().is_err());
        assert!(to_db().validate().is_ok());
    }

    #[test]
    fn a_guest_is_never_combined_with_a_pod_matcher() {
        let selector = PeerSelector {
            guest: Some("vm1".to_string()),
            pods: Some(pods(&[("app", "db")])),
            ..PeerSelector::default()
        };
        assert!(selector.validate().is_err());
    }

    #[test]
    fn an_empty_matcher_is_refused() {
        let selector = PeerSelector {
            service_account: Some(String::new()),
            ..PeerSelector::default()
        };
        assert!(selector.validate().is_err());
    }

    #[test]
    fn a_remote_pod_is_matched_by_its_labels_and_account() {
        let db = pod("10.1.0.5", "db", "db-sa");
        assert!(to_db().matches_remote(&db));
        assert!(!to_db().matches_remote(&pod("10.1.0.6", "web", "web-sa")));
        let account = PeerSelector {
            service_account: Some("db-sa".to_string()),
            namespaces: Some(pods(&[("team", "shop")])),
            ..PeerSelector::default()
        };
        assert!(account.matches_remote(&db));
        let other_kind = PeerSelector {
            kind: Some(IdentityKind::Host),
            ..to_db()
        };
        assert!(!other_kind.matches_remote(&db));
    }

    #[test]
    fn a_host_address_carries_no_pod_label() {
        let mut node = pod("10.1.0.1", "db", "db-sa");
        node.kind = IdentityKind::Host;
        assert!(!to_db().matches_remote(&node));
    }

    #[test]
    fn a_local_pod_is_matched_and_a_guest_never_is() {
        let pod_labels = labels(&[("app", "db")]);
        let facts = WorkloadFacts {
            container_id: Some("0123456789abcdef0123"),
            pod_labels: Some(&pod_labels),
            ..WorkloadFacts::default()
        };
        assert!(to_db().matches_local(&facts));
        let host = PeerSelector {
            kind: Some(IdentityKind::Host),
            ..PeerSelector::default()
        };
        assert!(!host.matches_local(&facts));
        assert!(host.matches_local(&WorkloadFacts::default()));
        let guest = PeerSelector {
            guest: Some("vm1".to_string()),
            ..PeerSelector::default()
        };
        assert!(!guest.matches_local(&WorkloadFacts::default()));
    }

    #[test]
    fn the_source_half_is_read_from_the_address_it_arrives_from() {
        let web = pod("10.1.0.6", "web", "web-sa");
        assert!(source_matches_remote(&by_pods(&[("app", "web")]), &web));
        assert!(!source_matches_remote(&by_pods(&[("app", "db")]), &web));
        let exe = WorkloadSelector {
            exe: Some("/usr/bin/curl".to_string()),
            ..WorkloadSelector::default()
        };
        assert_eq!(source_unreadable(&exe), Some("exe"));
        assert_eq!(source_unreadable(&by_pods(&[("app", "web")])), None);
    }

    #[test]
    fn a_rule_on_labels_is_decided_at_both_ends() {
        let policy = WorkloadPolicy::new(vec![peer_rule(
            "web-to-db",
            10,
            by_pods(&[("app", "web")]),
            to_db(),
        )])
        .expect("a valid policy");
        let ends = policy.peer_ends();
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].ends, PeerEnds::Both);
        assert_eq!(ends[0].reason, None);
        assert_eq!(policy.destination_slots(), 1);
        assert!(policy.names_peers());
        let rule = policy.rule_in_slot(0).expect("one rule");
        assert!(rule.describe_destination().contains("peer"));
        assert!(!rule.admits_destination(&WorkloadDestination {
            addr: DestinationAddr::V4(u32::from_be_bytes([10, 1, 0, 5])),
            port: 5432,
            protocol: Protocol::Tcp,
        }));
    }

    #[test]
    fn a_source_no_address_carries_is_decided_at_the_source_alone() {
        let exe = WorkloadSelector {
            exe: Some("/usr/bin/curl".to_string()),
            ..WorkloadSelector::default()
        };
        let policy = WorkloadPolicy::new(vec![peer_rule("curl-to-db", 10, exe, to_db())])
            .expect("a valid policy");
        let ends = policy.peer_ends();
        assert_eq!(ends[0].ends, PeerEnds::Source);
        assert!(ends[0].reason.as_deref().is_some_and(|r| r.contains("exe")));
        assert_eq!(policy.destination_slots(), 0);
    }

    #[test]
    fn a_datagram_rule_is_decided_at_the_source_alone() {
        let mut rule = peer_rule("dns", 10, by_pods(&[("app", "web")]), to_db());
        rule.protocol = Protocol::Udp;
        let policy = WorkloadPolicy::new(vec![rule]).expect("a valid policy");
        assert_eq!(policy.peer_ends()[0].ends, PeerEnds::Source);
    }

    #[test]
    fn an_allow_above_the_destination_cannot_read_moves_a_rule_to_the_source() {
        let exe = WorkloadSelector {
            exe: Some("/usr/bin/curl".to_string()),
            ..WorkloadSelector::default()
        };
        let mut wide = peer_rule("curl-anywhere", 5, exe, to_db());
        wide.dst_peer = None;
        wide.dst_port = None;
        let mut deny = peer_rule("web-not-db", 10, by_pods(&[("app", "web")]), to_db());
        deny.action = FirewallAction::Deny;
        let policy = WorkloadPolicy::new(vec![wide, deny]).expect("a valid policy");
        let ends = policy.peer_ends();
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].slot, 1);
        assert_eq!(ends[0].ends, PeerEnds::Source);
        assert!(
            ends[0]
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("curl-anywhere"))
        );
    }

    #[test]
    fn a_disabled_rule_holds_no_slot() {
        let mut off = peer_rule("off", 5, by_pods(&[("app", "web")]), to_db());
        off.enabled = false;
        let on = peer_rule("on", 10, by_pods(&[("app", "web")]), to_db());
        let policy = WorkloadPolicy::new(vec![off, on]).expect("a valid policy");
        let ends = policy.peer_ends();
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].rule.0, "on");
        assert_eq!(ends[0].slot, 0);
    }

    #[test]
    fn the_description_names_every_matcher() {
        let selector = PeerSelector {
            kind: Some(IdentityKind::Pod),
            service_account: Some("db-sa".to_string()),
            pods: Some(pods(&[("app", "db")])),
            ..PeerSelector::default()
        };
        let line = selector.describe();
        assert!(line.starts_with("peer "));
        assert!(line.contains("kind=pod"));
        assert!(line.contains("service_account=db-sa"));
        assert!(line.contains("app=db"));
    }
}
