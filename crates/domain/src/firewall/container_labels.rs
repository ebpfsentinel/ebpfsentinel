//! A workload policy written on the container it is about.
//!
//! The person who knows what a container may reach is usually the person
//! who wrote its compose file, and that file already carries labels. So a
//! container can carry its own egress policy under the `io.ebpfsentinel.`
//! prefix, and what this module turns it into is a list of ordinary workload
//! rules whose selector is that container's id - decided in the same socket
//! hooks, counted by the same counters, listed by the same command.
//!
//! The vocabulary is four labels:
//!
//! - `io.ebpfsentinel.policy.mode`: `observe` (the default) or `enforce`.
//! - `io.ebpfsentinel.policy.egress.deny`: destinations refused.
//! - `io.ebpfsentinel.policy.egress.allow`: destinations let through.
//! - `io.ebpfsentinel.policy.egress.default`: `allow` (the default) or
//!   `deny`, what happens to a destination neither list names.
//!
//! A destination is `<protocol>[/<port>[-<port>]][@<address>[/<prefix>]]`,
//! the protocol being `tcp`, `udp` or `any`, and a list separates them with
//! commas: `tcp/443, udp/53@10.0.0.2, any@192.168.0.0/16`. The deny list is
//! examined first, then the allow list, then the default.
//!
//! A label that cannot be read is never skipped over. A policy with one
//! entry left out is a different policy from the one written, and the
//! difference is always the entry somebody cared about, so a container with
//! any problem in its labels gets no label rule at all, and the problem is
//! reported against it.

use std::net::IpAddr;

use serde::Serialize;

use crate::common::entity::{Protocol, RuleId};

use super::entity::{FirewallAction, IpNetwork, PortRange};
use super::workload::{WorkloadMode, WorkloadRule, WorkloadSelector};

/// Every label this module reads starts with this.
pub const LABEL_PREFIX: &str = "io.ebpfsentinel.";

/// Whether a refusal is carried out or only reported.
pub const LABEL_MODE: &str = "io.ebpfsentinel.policy.mode";

/// Destinations the container may reach.
pub const LABEL_EGRESS_ALLOW: &str = "io.ebpfsentinel.policy.egress.allow";

/// Destinations the container may not reach.
pub const LABEL_EGRESS_DENY: &str = "io.ebpfsentinel.policy.egress.deny";

/// What happens to a destination neither list names.
pub const LABEL_EGRESS_DEFAULT: &str = "io.ebpfsentinel.policy.egress.default";

/// Priority of a container's first label rule.
///
/// High enough that a rule in the configuration file, written with the
/// priorities people actually write, is examined before any label: the file
/// is the node owner's word and a label is the container author's.
pub const LABEL_PRIORITY_BASE: u32 = 1_000_000;

/// Most destinations one container may name across both lists.
///
/// The kernel walks at most 64 workload rules for the whole node, so one
/// container listing forty destinations would leave nothing for the others.
pub const MAX_LABEL_DESTINATIONS: usize = 16;

/// One container as a runtime lists it: id, name, and every label it
/// carries.
pub type ListedContainer = (String, String, Vec<(String, String)>);

/// Characters of the container id a rule identifier carries, the length a
/// runtime prints.
const RULE_ID_CONTAINER_CHARS: usize = 12;

/// One label that could not be read, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LabelProblem {
    /// The label key as the container carries it.
    pub label: String,
    /// What is wrong with it, in words that say how to fix it.
    pub reason: String,
}

/// What one container's labels say, read once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerLabelPolicy {
    /// Container id, in full.
    pub container_id: String,
    /// Name the runtime gave the container, empty when it gave none.
    pub container_name: String,
    /// Mode every rule of this container runs in.
    pub mode: WorkloadMode,
    /// The rules the labels make, in the order they are examined. Empty
    /// whenever `problems` is not.
    pub rules: Vec<WorkloadRule>,
    /// Every label that could not be read.
    pub problems: Vec<LabelProblem>,
}

impl ContainerLabelPolicy {
    /// Read the policy `labels` carry for the container `container_id`.
    ///
    /// Labels outside [`LABEL_PREFIX`] are the container's own business and
    /// are not looked at. A key inside it that this vocabulary does not
    /// have is a problem rather than noise, because a misspelt key is a
    /// policy its author believes is in force.
    #[must_use]
    pub fn from_labels(
        container_id: &str,
        container_name: &str,
        labels: &[(String, String)],
    ) -> Self {
        let mut reader = Reader::default();
        for (key, value) in labels {
            if !key.starts_with(LABEL_PREFIX) {
                continue;
            }
            reader.read(key, value);
        }
        let mut policy = Self {
            container_id: container_id.to_string(),
            container_name: container_name.to_string(),
            mode: reader.mode,
            rules: Vec::new(),
            problems: reader.problems,
        };
        let named = reader.deny.len() + reader.allow.len();
        if named > MAX_LABEL_DESTINATIONS {
            policy.problems.push(LabelProblem {
                label: LABEL_EGRESS_ALLOW.to_string(),
                reason: format!(
                    "the two lists name {named} destinations, more than the \
                     {MAX_LABEL_DESTINATIONS} one container may name; widen an address prefix \
                     or a port range"
                ),
            });
        }
        if !policy.problems.is_empty() {
            return policy;
        }
        match WorkloadSelector::new(None, None, None, Some(container_id.to_string())) {
            Ok(selector) => {
                policy.rules = build_rules(
                    container_id,
                    &selector,
                    reader.mode,
                    &reader.deny,
                    &reader.allow,
                    reader.default_deny,
                );
            }
            Err(e) => policy.problems.push(LabelProblem {
                label: LABEL_PREFIX.to_string(),
                reason: format!("the container id cannot name a workload: {e}"),
            }),
        }
        policy
    }

    /// Whether the labels say nothing at all, which is every container that
    /// carries no label under the prefix.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.problems.is_empty()
    }

    /// Mark the policy unusable for `reason`, dropping its rules.
    pub fn refuse(&mut self, label: &str, reason: String) {
        self.rules.clear();
        self.problems.push(LabelProblem {
            label: label.to_string(),
            reason,
        });
    }
}

/// One destination as a list entry names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelDestination {
    /// Protocol of the socket, or [`Protocol::Any`].
    pub protocol: Protocol,
    /// Destination port range, absent for every port.
    pub port: Option<PortRange>,
    /// Destination network, absent for every address.
    pub network: Option<IpNetwork>,
}

impl LabelDestination {
    /// Read one entry of a list.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the entry, naming the entry.
    pub fn parse(entry: &str) -> Result<Self, String> {
        let entry = entry.trim();
        let (head, address) = match entry.split_once('@') {
            Some((head, address)) => (head, Some(address)),
            None => (entry, None),
        };
        let (protocol_word, port) = match head.split_once('/') {
            Some((protocol, port)) => (protocol, Some(port)),
            None => (head, None),
        };
        let protocol = match protocol_word.trim().to_ascii_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "any" => Protocol::Any,
            other => {
                return Err(format!(
                    "'{entry}' starts with '{other}', which is not tcp, udp or any"
                ));
            }
        };
        let port = port.map(|text| parse_ports(entry, text)).transpose()?;
        if port.is_some() && protocol == Protocol::Any {
            return Err(format!(
                "'{entry}' names a port with any protocol; a port belongs to tcp or udp"
            ));
        }
        let network = address.map(|text| parse_network(entry, text)).transpose()?;
        Ok(Self {
            protocol,
            port,
            network,
        })
    }
}

#[derive(Default)]
struct Reader {
    mode: WorkloadMode,
    deny: Vec<LabelDestination>,
    allow: Vec<LabelDestination>,
    default_deny: bool,
    problems: Vec<LabelProblem>,
}

impl Reader {
    fn read(&mut self, key: &str, value: &str) {
        let problem = match key {
            LABEL_MODE => match WorkloadMode::parse(value) {
                Ok(mode) => {
                    self.mode = mode;
                    None
                }
                Err(word) => Some(format!("'{word}' is not observe or enforce")),
            },
            LABEL_EGRESS_DEFAULT => match value.trim() {
                "allow" => None,
                "deny" => {
                    self.default_deny = true;
                    None
                }
                other => Some(format!("'{other}' is not allow or deny")),
            },
            LABEL_EGRESS_ALLOW => read_list(value, &mut self.allow),
            LABEL_EGRESS_DENY => read_list(value, &mut self.deny),
            _ => Some(format!(
                "this label is not part of the policy vocabulary: {LABEL_MODE}, \
                 {LABEL_EGRESS_DENY}, {LABEL_EGRESS_ALLOW} and {LABEL_EGRESS_DEFAULT} are"
            )),
        };
        if let Some(reason) = problem {
            self.problems.push(LabelProblem {
                label: key.to_string(),
                reason,
            });
        }
    }
}

/// Read a comma-separated list into `into`, or say what is wrong with it.
fn read_list(value: &str, into: &mut Vec<LabelDestination>) -> Option<String> {
    let entries: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();
    if entries.is_empty() {
        return Some("the list is empty; remove the label or name a destination".to_string());
    }
    let mut errors = Vec::new();
    for entry in entries {
        match LabelDestination::parse(entry) {
            Ok(destination) => into.push(destination),
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    }
}

fn parse_ports(entry: &str, text: &str) -> Result<PortRange, String> {
    let number = |part: &str| {
        part.trim()
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("'{entry}' has '{part}' where a port from 1 to 65535 goes"))
    };
    let range = if let Some((start, end)) = text.split_once('-') {
        PortRange {
            start: number(start)?,
            end: number(end)?,
        }
    } else {
        let port = number(text)?;
        PortRange {
            start: port,
            end: port,
        }
    };
    if range.start > range.end {
        return Err(format!(
            "'{entry}' has a port range that ends before it starts"
        ));
    }
    Ok(range)
}

fn parse_network(entry: &str, text: &str) -> Result<IpNetwork, String> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (text, None),
    };
    let address: IpAddr = address
        .trim()
        .parse()
        .map_err(|_| format!("'{entry}' has '{address}' where an address goes"))?;
    let widest: u8 = if address.is_ipv4() { 32 } else { 128 };
    let prefix_len = match prefix {
        Some(prefix) => prefix
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|len| *len <= widest)
            .ok_or_else(|| {
                format!("'{entry}' has '/{prefix}' where a prefix from 0 to {widest} goes")
            })?,
        None => widest,
    };
    Ok(match address {
        IpAddr::V4(v4) => IpNetwork::V4 {
            addr: u32::from(v4),
            prefix_len,
        },
        IpAddr::V6(v6) => IpNetwork::V6 {
            addr: v6.octets(),
            prefix_len,
        },
    })
}

/// The rules one container's labels make, deny list first.
fn build_rules(
    container_id: &str,
    selector: &WorkloadSelector,
    mode: WorkloadMode,
    deny: &[LabelDestination],
    allow: &[LabelDestination],
    default_deny: bool,
) -> Vec<WorkloadRule> {
    let short: String = container_id.chars().take(RULE_ID_CONTAINER_CHARS).collect();
    let mut rules = Vec::new();
    let mut push = |kind: &str, index: usize, action, destination: Option<&LabelDestination>| {
        let priority = LABEL_PRIORITY_BASE.saturating_add(u32::try_from(rules.len()).unwrap_or(0));
        rules.push(WorkloadRule {
            id: RuleId(format!("label-{short}-{kind}-{index}")),
            priority,
            action,
            mode,
            selector: selector.clone(),
            protocol: destination.map_or(Protocol::Any, |d| d.protocol),
            dst_ip: destination.and_then(|d| d.network),
            dst_port: destination.and_then(|d| d.port),
            dst_fqdn: Vec::new(),
            enabled: true,
        });
    };
    for (index, destination) in deny.iter().enumerate() {
        push("deny", index, FirewallAction::Deny, Some(destination));
    }
    for (index, destination) in allow.iter().enumerate() {
        push("allow", index, FirewallAction::Allow, Some(destination));
    }
    if default_deny {
        push("default", 0, FirewallAction::Deny, None);
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f1c2a9b8e7d6c5b4a3928170615f4e3d2c1b0a99887766554433221100ffeed";

    fn labels(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn a_container_without_policy_labels_says_nothing() {
        let policy = ContainerLabelPolicy::from_labels(
            ID,
            "web",
            &labels(&[("com.docker.compose.service", "web")]),
        );
        assert!(policy.is_empty());
    }

    #[test]
    fn the_lists_become_rules_deny_first_then_the_default() {
        let policy = ContainerLabelPolicy::from_labels(
            ID,
            "web",
            &labels(&[
                (LABEL_MODE, "enforce"),
                (LABEL_EGRESS_ALLOW, "tcp/443, udp/53@10.0.0.2"),
                (LABEL_EGRESS_DENY, "any@169.254.169.254"),
                (LABEL_EGRESS_DEFAULT, "deny"),
            ]),
        );
        assert!(policy.problems.is_empty(), "{:?}", policy.problems);
        let ids: Vec<&str> = policy.rules.iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(
            ids,
            [
                "label-4f1c2a9b8e7d-deny-0",
                "label-4f1c2a9b8e7d-allow-0",
                "label-4f1c2a9b8e7d-allow-1",
                "label-4f1c2a9b8e7d-default-0",
            ]
        );
        assert!(policy.rules.iter().all(|r| r.mode == WorkloadMode::Enforce));
        assert!(
            policy
                .rules
                .iter()
                .all(|r| r.selector.container.as_deref() == Some(ID))
        );
        let priorities: Vec<u32> = policy.rules.iter().map(|r| r.priority).collect();
        assert!(priorities.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(
            policy.rules[1].dst_port,
            Some(PortRange {
                start: 443,
                end: 443
            })
        );
        assert_eq!(
            policy.rules[2].dst_ip,
            Some(IpNetwork::V4 {
                addr: 0x0a00_0002,
                prefix_len: 32
            })
        );
        assert_eq!(policy.rules[3].action, FirewallAction::Deny);
        assert_eq!(policy.rules[3].dst_ip, None);
        assert!(policy.rules.iter().all(|r| r.id.validate().is_ok()));
    }

    #[test]
    fn the_mode_defaults_to_observe() {
        let policy =
            ContainerLabelPolicy::from_labels(ID, "", &labels(&[(LABEL_EGRESS_DENY, "tcp/25")]));
        assert_eq!(policy.mode, WorkloadMode::Observe);
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn one_bad_entry_withholds_every_rule_and_names_the_label() {
        let policy = ContainerLabelPolicy::from_labels(
            ID,
            "web",
            &labels(&[
                (LABEL_EGRESS_ALLOW, "tcp/443, tpc/80"),
                (LABEL_EGRESS_DEFAULT, "deny"),
            ]),
        );
        assert!(policy.rules.is_empty());
        assert_eq!(policy.problems.len(), 1);
        assert_eq!(policy.problems[0].label, LABEL_EGRESS_ALLOW);
        assert!(policy.problems[0].reason.contains("tpc/80"));
    }

    #[test]
    fn an_unknown_key_under_the_prefix_is_a_problem() {
        let policy = ContainerLabelPolicy::from_labels(
            ID,
            "web",
            &labels(&[("io.ebpfsentinel.policy.egres.allow", "tcp/443")]),
        );
        assert!(policy.rules.is_empty());
        assert_eq!(
            policy.problems[0].label,
            "io.ebpfsentinel.policy.egres.allow"
        );
    }

    #[test]
    fn bad_words_are_reported() {
        let policy = ContainerLabelPolicy::from_labels(
            ID,
            "web",
            &labels(&[(LABEL_MODE, "block"), (LABEL_EGRESS_DEFAULT, "drop")]),
        );
        assert_eq!(policy.problems.len(), 2);
    }

    #[test]
    fn too_many_destinations_are_refused() {
        let list = (1..=17)
            .map(|port| format!("tcp/{port}"))
            .collect::<Vec<_>>()
            .join(",");
        let policy =
            ContainerLabelPolicy::from_labels(ID, "web", &labels(&[(LABEL_EGRESS_ALLOW, &list)]));
        assert!(policy.rules.is_empty());
        assert!(policy.problems[0].reason.contains("17 destinations"));
    }

    #[test]
    fn an_empty_list_is_a_problem() {
        let policy =
            ContainerLabelPolicy::from_labels(ID, "web", &labels(&[(LABEL_EGRESS_DENY, " , ")]));
        assert_eq!(policy.problems.len(), 1);
    }

    #[test]
    fn destinations_parse() {
        let range = LabelDestination::parse("tcp/8000-8100@2001:db8::/32").unwrap();
        assert_eq!(range.protocol, Protocol::Tcp);
        assert_eq!(
            range.port,
            Some(PortRange {
                start: 8000,
                end: 8100
            })
        );
        assert!(matches!(
            range.network,
            Some(IpNetwork::V6 { prefix_len: 32, .. })
        ));
        let anywhere = LabelDestination::parse("any@0.0.0.0/0").unwrap();
        assert_eq!(anywhere.protocol, Protocol::Any);
        assert_eq!(anywhere.port, None);

        for bad in [
            "any/80",
            "tcp/0",
            "tcp/90-80",
            "tcp/http",
            "udp@10.0.0.300",
            "udp@10.0.0.0/33",
            "icmp",
        ] {
            assert!(LabelDestination::parse(bad).is_err(), "{bad} parsed");
        }
    }

    #[test]
    fn a_refused_policy_drops_its_rules() {
        let mut policy =
            ContainerLabelPolicy::from_labels(ID, "web", &labels(&[(LABEL_EGRESS_DENY, "tcp/25")]));
        policy.refuse(LABEL_PREFIX, "no room".to_string());
        assert!(policy.rules.is_empty());
        assert!(!policy.is_empty());
    }
}
