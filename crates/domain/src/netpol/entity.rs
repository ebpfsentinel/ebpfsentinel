//! The cluster as a Kubernetes `NetworkPolicy` reads it.
//!
//! These are views rather than the API objects: only the fields the policy
//! model consults, so the compile is a pure function of what the API server
//! said and can be asserted case by case without a cluster.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Which way a connection goes, seen from the selected pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

/// The three transports a `NetworkPolicy` port can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

impl Protocol {
    /// The IP protocol number, as the kernel compares it.
    pub fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Sctp => 132,
        }
    }

    /// The protocol a Kubernetes object spells `TCP`, `UDP` or `SCTP`, with
    /// `TCP` for an absent one, which is the API's own default.
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value.unwrap_or("TCP") {
            "TCP" => Some(Self::Tcp),
            "UDP" => Some(Self::Udp),
            "SCTP" => Some(Self::Sctp),
            _ => None,
        }
    }
}

/// An address prefix of either family.
///
/// The address is stored masked, in network order, an IPv4 one in the first
/// four bytes. Two prefixes of different families never contain each other,
/// which is what keeps `::/0` from quietly covering every IPv4 peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetPrefix {
    v6: bool,
    addr: [u8; 16],
    len: u8,
}

impl NetPrefix {
    /// A prefix of `len` bits starting at `ip`, or `None` past the family's
    /// width. The host bits are cleared.
    pub fn new(ip: IpAddr, len: u8) -> Option<Self> {
        let (v6, mut addr, width) = match ip.to_canonical() {
            IpAddr::V4(v4) => {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&v4.octets());
                (false, addr, 32)
            }
            IpAddr::V6(v6) => (true, v6.octets(), 128),
        };
        if len > width {
            return None;
        }
        for (index, byte) in addr.iter_mut().enumerate() {
            let start = u8::try_from(index * 8).unwrap_or(u8::MAX);
            if start >= len {
                *byte = 0;
            } else if len - start < 8 {
                *byte &= 0xffu8 << (8 - (len - start));
            }
        }
        Some(Self { v6, addr, len })
    }

    /// The one address `ip`, as a prefix of the family's full width.
    pub fn host(ip: IpAddr) -> Self {
        let ip = ip.to_canonical();
        let width = if ip.is_ipv6() { 128 } else { 32 };
        // The width is the family's own, so the constructor cannot refuse it.
        Self::new(ip, width).unwrap_or(Self {
            v6: false,
            addr: [0; 16],
            len: 0,
        })
    }

    /// `a.b.c.d/n` or `x::y/n`, the way an `ipBlock` writes it.
    pub fn parse(value: &str) -> Option<Self> {
        let (ip, len) = value.trim().split_once('/')?;
        Self::new(ip.parse().ok()?, len.parse().ok()?)
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    pub fn len(&self) -> u8 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The masked address, network order, an IPv4 one in the first four bytes.
    pub fn octets(&self) -> [u8; 16] {
        self.addr
    }

    /// Whether every address of `other` is inside this prefix.
    pub fn contains(&self, other: &Self) -> bool {
        if self.v6 != other.v6 || other.len < self.len {
            return false;
        }
        Self::new(other.ip(), self.len).is_some_and(|narrowed| narrowed.addr == self.addr)
    }

    /// Whether `ip` is inside this prefix.
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.contains(&Self::host(ip))
    }

    fn ip(&self) -> IpAddr {
        if self.v6 {
            IpAddr::from(self.addr)
        } else {
            IpAddr::from([self.addr[0], self.addr[1], self.addr[2], self.addr[3]])
        }
    }
}

impl fmt::Display for NetPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip(), self.len)
    }
}

/// How a label selector requirement compares a key, spelt the way the
/// Kubernetes API spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectorOperator {
    In,
    NotIn,
    Exists,
    DoesNotExist,
}

/// One `matchExpressions` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelRequirement {
    pub key: String,
    pub operator: SelectorOperator,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

/// A Kubernetes label selector. The empty one selects everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelSelector {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub match_labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_expressions: Vec<LabelRequirement>,
}

impl LabelSelector {
    /// Check the selector the way the API server checks one: a key is never
    /// blank, `In` and `NotIn` carry at least one value, and `Exists` and
    /// `DoesNotExist` carry none.
    ///
    /// # Errors
    ///
    /// The first requirement that breaks one of those, in words.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(key) = self.match_labels.keys().find(|key| key.trim().is_empty()) {
            return Err(format!("matchLabels carries a blank key '{key}'"));
        }
        for requirement in &self.match_expressions {
            if requirement.key.trim().is_empty() {
                return Err("a matchExpressions entry carries a blank key".to_string());
            }
            let wants_values = matches!(
                requirement.operator,
                SelectorOperator::In | SelectorOperator::NotIn
            );
            if wants_values && requirement.values.is_empty() {
                return Err(format!(
                    "matchExpressions on '{}' uses {:?} with no values",
                    requirement.key, requirement.operator
                ));
            }
            if !wants_values && !requirement.values.is_empty() {
                return Err(format!(
                    "matchExpressions on '{}' uses {:?}, which takes no values",
                    requirement.key, requirement.operator
                ));
            }
        }
        Ok(())
    }

    /// Whether the selector carries no requirement, and so selects every
    /// object of its kind.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.match_labels.is_empty() && self.match_expressions.is_empty()
    }

    /// The selector in the API server's own query syntax, such as
    /// `app=web,tier in (a,b),!legacy`, for a log line and the command line.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = self
            .match_labels
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        for requirement in &self.match_expressions {
            parts.push(match requirement.operator {
                SelectorOperator::In => {
                    format!("{} in ({})", requirement.key, requirement.values.join(","))
                }
                SelectorOperator::NotIn => {
                    format!(
                        "{} notin ({})",
                        requirement.key,
                        requirement.values.join(",")
                    )
                }
                SelectorOperator::Exists => requirement.key.clone(),
                SelectorOperator::DoesNotExist => format!("!{}", requirement.key),
            });
        }
        parts.join(",")
    }

    /// Whether `labels` satisfies every requirement. `NotIn` holds for an
    /// object that does not carry the key at all, as the API server reads it.
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        self.match_labels
            .iter()
            .all(|(key, value)| labels.get(key) == Some(value))
            && self.match_expressions.iter().all(|requirement| {
                let present = labels.get(&requirement.key);
                match requirement.operator {
                    SelectorOperator::In => {
                        present.is_some_and(|value| requirement.values.contains(value))
                    }
                    SelectorOperator::NotIn => {
                        present.is_none_or(|value| !requirement.values.contains(value))
                    }
                    SelectorOperator::Exists => present.is_some(),
                    SelectorOperator::DoesNotExist => present.is_none(),
                }
            })
    }
}

/// A port as a policy names it: a number, or the name of a container port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortRef {
    Number(u16),
    Name(String),
}

/// One `ports` entry of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPort {
    pub protocol: Protocol,
    /// `None` is every port of the protocol.
    pub port: Option<PortRef>,
    /// The last port of a range starting at a numbered `port`.
    pub end_port: Option<u16>,
}

/// An `ipBlock`: a prefix, less the prefixes it excepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpBlock {
    pub cidr: NetPrefix,
    pub except: Vec<NetPrefix>,
}

/// One `from` or `to` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peer {
    /// Pods, chosen by a namespace selector, a pod selector, or both.
    /// A pod selector alone stays in the policy's own namespace.
    Pods {
        namespaces: Option<LabelSelector>,
        pods: Option<LabelSelector>,
    },
    Block(IpBlock),
}

/// One ingress or egress rule. An empty `peers` is every peer and an empty
/// `ports` is every port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyRule {
    pub peers: Vec<Peer>,
    pub ports: Vec<PolicyPort>,
}

/// A `networking.k8s.io/v1` `NetworkPolicy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub namespace: String,
    pub name: String,
    pub pod_selector: LabelSelector,
    pub ingress: Vec<PolicyRule>,
    pub egress: Vec<PolicyRule>,
    /// `None` when the object leaves `policyTypes` out.
    pub policy_types: Option<Vec<Direction>>,
}

impl NetworkPolicy {
    /// Whether this policy isolates the pods it selects in `direction`.
    ///
    /// With `policyTypes` absent, the API server's own default: ingress
    /// always, egress only when the policy carries an egress rule.
    pub fn governs(&self, direction: Direction) -> bool {
        match &self.policy_types {
            Some(types) => types.contains(&direction),
            None => match direction {
                Direction::Ingress => true,
                Direction::Egress => !self.egress.is_empty(),
            },
        }
    }

    pub fn rules(&self, direction: Direction) -> &[PolicyRule] {
        match direction {
            Direction::Ingress => &self.ingress,
            Direction::Egress => &self.egress,
        }
    }
}

/// A container port a policy can name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPort {
    pub name: String,
    pub port: u16,
    pub protocol: Protocol,
}

/// A pod, as far as policy is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodView {
    pub uid: String,
    pub namespace: String,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub ips: Vec<IpAddr>,
    pub ports: Vec<NamedPort>,
    /// The addresses of the node the pod runs on, whose traffic to the pod
    /// no policy can close.
    pub host_ips: Vec<IpAddr>,
    pub host_network: bool,
    /// `Succeeded` or `Failed`: its addresses may already belong to another.
    pub terminal: bool,
}

impl PodView {
    /// Whether a policy can select this pod as a peer at all.
    pub fn is_peer(&self) -> bool {
        !self.host_network && !self.terminal && !self.ips.is_empty()
    }
}

pub(crate) fn resolve_named(ports: &[NamedPort], name: &str, protocol: Protocol) -> Option<u16> {
    ports
        .iter()
        .find(|port| port.name == name && port.protocol == protocol)
        .map(|port| port.port)
}

/// A namespace and its labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceView {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

/// One port of a Service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePort {
    /// The port's name, which is what an endpoint slice port is keyed by.
    pub name: String,
    pub port: u16,
    pub protocol: Protocol,
}

/// One ready endpoint behind a Service, with the ports its slice names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceBackend {
    pub ip: IpAddr,
    pub ports: Vec<NamedPort>,
}

/// A Service with a cluster address, and its ready backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceView {
    pub namespace: String,
    pub name: String,
    pub cluster_ips: Vec<IpAddr>,
    pub ports: Vec<ServicePort>,
    pub backends: Vec<ServiceBackend>,
}

/// Everything the compile reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterView {
    pub policies: Vec<NetworkPolicy>,
    pub pods: Vec<PodView>,
    pub namespaces: Vec<NamespaceView>,
    pub services: Vec<ServiceView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn a_prefix_is_masked_and_contains_only_its_own_family() {
        let net = NetPrefix::parse("10.1.2.3/8").unwrap();
        assert_eq!(net.to_string(), "10.0.0.0/8");
        assert!(net.contains_ip("10.200.0.1".parse().unwrap()));
        assert!(!net.contains_ip("11.0.0.1".parse().unwrap()));
        let all6 = NetPrefix::parse("::/0").unwrap();
        assert!(!all6.contains_ip("10.0.0.1".parse().unwrap()));
        assert!(all6.contains_ip("fd00::1".parse().unwrap()));
        assert!(NetPrefix::parse("10.0.0.0/33").is_none());
        assert_eq!(
            NetPrefix::parse("fd00:1234::/20").unwrap().to_string(),
            "fd00:1000::/20"
        );
    }

    #[test]
    fn a_mapped_address_is_read_as_the_ipv4_one() {
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(
            NetPrefix::host(mapped),
            NetPrefix::parse("10.0.0.1/32").unwrap()
        );
    }

    #[test]
    fn selector_operators_read_as_the_api_server_reads_them() {
        let pod = labels(&[("app", "web"), ("tier", "front")]);
        let mut selector = LabelSelector::default();
        assert!(selector.matches(&pod), "the empty selector selects all");
        selector.match_expressions.push(LabelRequirement {
            key: "env".into(),
            operator: SelectorOperator::NotIn,
            values: vec!["prod".into()],
        });
        assert!(selector.matches(&pod), "NotIn holds for an absent key");
        selector.match_expressions.push(LabelRequirement {
            key: "tier".into(),
            operator: SelectorOperator::In,
            values: vec!["front".into(), "back".into()],
        });
        assert!(selector.matches(&pod));
        selector.match_expressions.push(LabelRequirement {
            key: "app".into(),
            operator: SelectorOperator::DoesNotExist,
            values: vec![],
        });
        assert!(!selector.matches(&pod));
    }

    #[test]
    fn a_selector_reads_back_in_the_api_server_syntax() {
        let selector: LabelSelector = serde_json::from_str(
            r#"{"match_labels":{"app":"web"},"match_expressions":[
                {"key":"tier","operator":"In","values":["a","b"]},
                {"key":"env","operator":"NotIn","values":["prod"]},
                {"key":"canary","operator":"Exists"},
                {"key":"legacy","operator":"DoesNotExist"}]}"#,
        )
        .unwrap();
        assert!(selector.validate().is_ok());
        assert_eq!(
            selector.describe(),
            "app=web,tier in (a,b),env notin (prod),canary,!legacy"
        );
        assert!(LabelSelector::default().is_empty());
        assert!(!selector.is_empty());
    }

    #[test]
    fn a_requirement_the_api_server_refuses_is_refused() {
        for json in [
            r#"{"match_expressions":[{"key":"tier","operator":"NotIn"}]}"#,
            r#"{"match_expressions":[{"key":"tier","operator":"DoesNotExist","values":["x"]}]}"#,
            r#"{"match_expressions":[{"key":"","operator":"Exists"}]}"#,
        ] {
            let selector: LabelSelector = serde_json::from_str(json).unwrap();
            assert!(selector.validate().is_err(), "{json}");
        }
        assert!(
            serde_json::from_str::<LabelSelector>(
                r#"{"match_expressions":[{"key":"a","operator":"in"}]}"#
            )
            .is_err(),
            "the operator is spelt the way the API spells it"
        );
    }

    #[test]
    fn policy_types_default_to_ingress_and_egress_only_when_written() {
        let mut policy = NetworkPolicy {
            namespace: "a".into(),
            name: "p".into(),
            pod_selector: LabelSelector::default(),
            ingress: vec![],
            egress: vec![],
            policy_types: None,
        };
        assert!(policy.governs(Direction::Ingress));
        assert!(!policy.governs(Direction::Egress));
        policy.egress.push(PolicyRule::default());
        assert!(policy.governs(Direction::Egress));
        policy.policy_types = Some(vec![Direction::Egress]);
        assert!(!policy.governs(Direction::Ingress));
    }
}
