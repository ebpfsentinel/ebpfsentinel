//! Who may reach a listener, read from the rules the packet firewall holds.
//!
//! A listening socket is only half of an exposure: the other half is whether
//! anything off the node is let through to it. This walks the loaded rules in
//! the order the datapath evaluates them and stops at the first one that
//! decides every packet bound for the listener, so the answer is the
//! firewall's own and not a second opinion beside it.
//!
//! Every uncertainty is resolved towards open. A rule that matches only some
//! packets (a source range, a VLAN, a connection state, an interface) cannot
//! close a listener on its own; if it allows, it opens the listener to the
//! sources it names, and if it denies, it narrows nothing this reading can
//! state, so it is passed over. Saying a socket is closed when it is not is
//! the one answer this module must never give.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::common::entity::{DomainMode, Protocol, RuleId};
use crate::firewall::entity::{FirewallAction, FirewallRule, IpNetwork, Scope};

use super::entity::{ListenerProtocol, ListenerScope};

/// What the packet firewall is doing, as one reading.
#[derive(Debug, Clone)]
pub struct FirewallPosture {
    /// The loaded rules, in any order: they are sorted by priority here.
    pub rules: Vec<FirewallRule>,
    /// Whether the firewall is enabled at all.
    pub enabled: bool,
    /// Alert mode logs what a rule would drop and lets it through.
    pub mode: DomainMode,
    /// Whether a packet no rule matched is dropped.
    pub default_drop: bool,
}

impl FirewallPosture {
    /// Whether a deny written in the rules is a packet dropped on the wire.
    #[must_use]
    pub fn enforcing(&self) -> bool {
        self.enabled && self.mode == DomainMode::Block
    }
}

/// What decided the reach of a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachDecision {
    /// The first rule that matches every packet bound for the listener.
    Rule { id: RuleId, action: FirewallAction },
    /// No rule matches every packet, so the catch-all policy does.
    DefaultPolicy { drop: bool },
    /// The firewall is disabled or in alert mode: nothing is dropped.
    NotEnforcing,
    /// A loopback address: nothing off the node reaches it, whatever the rules.
    Loopback,
}

/// The reach of one listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach {
    /// Whether some source off the node can reach the listener.
    pub open: bool,
    /// The sources let through, when the listener is open to only some of
    /// them. Empty means every source when `open`, and none when not.
    pub allowed_from: Vec<String>,
    pub decided_by: ReachDecision,
}

impl Reach {
    /// Open to everything, or to the listed sources only.
    #[must_use]
    pub fn restricted(&self) -> bool {
        self.open && !self.allowed_from.is_empty()
    }
}

/// The listener half of the question: an address, a port and a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerEndpoint {
    pub address: IpAddr,
    pub port: u16,
    pub protocol: ListenerProtocol,
}

/// Who may reach `listener` under `posture`.
#[must_use]
pub fn reach_of(listener: ListenerEndpoint, posture: &FirewallPosture) -> Reach {
    if ListenerScope::of(listener.address) == ListenerScope::Loopback {
        return Reach {
            open: false,
            allowed_from: Vec::new(),
            decided_by: ReachDecision::Loopback,
        };
    }
    if !posture.enforcing() {
        return Reach {
            open: true,
            allowed_from: Vec::new(),
            decided_by: ReachDecision::NotEnforcing,
        };
    }

    let mut rules: Vec<&FirewallRule> = posture
        .rules
        .iter()
        .filter(|rule| rule.enabled && rule.workload.is_none() && applies(rule, listener))
        .collect();
    rules.sort_by_key(|rule| rule.priority);

    let mut allowed_from: Vec<String> = Vec::new();
    for rule in rules {
        let passes = matches!(rule.action, FirewallAction::Allow | FirewallAction::Log);
        if decides_every_packet(rule, listener) {
            if passes {
                // Open to everything: the sources allowed earlier are a
                // subset of what this rule lets through.
                return Reach {
                    open: true,
                    allowed_from: Vec::new(),
                    decided_by: ReachDecision::Rule {
                        id: rule.id.clone(),
                        action: rule.action,
                    },
                };
            }
            return Reach {
                open: !allowed_from.is_empty(),
                allowed_from,
                decided_by: ReachDecision::Rule {
                    id: rule.id.clone(),
                    action: rule.action,
                },
            };
        }
        if passes {
            let source = source_of(rule);
            if !allowed_from.contains(&source) {
                allowed_from.push(source);
            }
        }
    }

    if posture.default_drop {
        Reach {
            open: !allowed_from.is_empty(),
            allowed_from,
            decided_by: ReachDecision::DefaultPolicy { drop: true },
        }
    } else {
        Reach {
            open: true,
            allowed_from: Vec::new(),
            decided_by: ReachDecision::DefaultPolicy { drop: false },
        }
    }
}

/// Whether the rule can match at least one packet bound for the listener.
fn applies(rule: &FirewallRule, listener: ListenerEndpoint) -> bool {
    let protocol_matches = match rule.protocol {
        Protocol::Any => true,
        Protocol::Tcp => listener.protocol == ListenerProtocol::Tcp,
        Protocol::Udp => listener.protocol == ListenerProtocol::Udp,
        _ => false,
    };
    if !protocol_matches {
        return false;
    }
    if let Some(range) = rule.dst_port
        && !range.contains(listener.port)
    {
        return false;
    }
    if let Some(network) = rule.dst_ip
        && !rule.negate_dst
        && !reaches_address(&network, listener.address)
    {
        return false;
    }
    if rule.src_ip.is_none() && rule.dst_ip.is_none() {
        return true;
    }
    // A rule naming addresses of one family matches only packets of that
    // family, and a socket bound on `::` takes both.
    let rule_v6 = rule.is_v6();
    match listener.address {
        IpAddr::V4(_) => !rule_v6,
        IpAddr::V6(v6) => rule_v6 || v6.is_unspecified(),
    }
}

/// Whether the rule matches every packet bound for the listener, which is
/// what makes its action the listener's verdict.
fn decides_every_packet(rule: &FirewallRule, listener: ListenerEndpoint) -> bool {
    let narrower = rule.src_ip.is_some()
        || rule.src_alias.is_some()
        || rule.src_port.is_some()
        || rule.src_port_alias.is_some()
        || rule.dst_port_alias.is_some()
        || rule.dst_alias.is_some()
        || rule.src_mac.is_some()
        || rule.dst_mac.is_some()
        || rule.src_mac_alias.is_some()
        || rule.dst_mac_alias.is_some()
        || rule.ct_states.is_some()
        || rule.tcp_flags.is_some()
        || rule.icmp_type.is_some()
        || rule.icmp_code.is_some()
        || rule.dscp_match.is_some()
        || rule.vlan_id.is_some()
        || rule.schedule.is_some()
        || rule.group_mask != 0
        || rule.tenant_id != 0
        || matches!(rule.scope, Scope::Interface(_));
    if narrower {
        return false;
    }
    match rule.dst_ip {
        None => true,
        Some(network) => {
            !rule.negate_dst
                && ListenerScope::of(listener.address) == ListenerScope::Address
                && reaches_address(&network, listener.address)
        }
    }
}

/// Whether `network` holds `address`, or any address when it is unspecified.
fn reaches_address(network: &IpNetwork, address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) if v4.is_unspecified() => !network.is_v6(),
        IpAddr::V6(v6) if v6.is_unspecified() => true,
        IpAddr::V4(v4) => network.contains_v4(u32::from(v4)),
        IpAddr::V6(v6) => network.contains_v6(&v6.octets()),
    }
}

/// The sources an allowing rule names, written the way an operator wrote them.
fn source_of(rule: &FirewallRule) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(network) = rule.src_ip {
        let cidr = cidr(&network);
        parts.push(if rule.negate_src {
            format!("not {cidr}")
        } else {
            cidr
        });
    }
    if let Some(alias) = &rule.src_alias {
        parts.push(format!("alias {alias}"));
    }
    if parts.is_empty() {
        // An allow narrowed by something other than its source (a VLAN, a
        // state, an interface) lets some packets of every source through.
        parts.push(format!("any (rule {})", rule.id));
    }
    parts.join(", ")
}

fn cidr(network: &IpNetwork) -> String {
    match *network {
        IpNetwork::V4 { addr, prefix_len } => format!("{}/{prefix_len}", Ipv4Addr::from(addr)),
        IpNetwork::V6 { addr, prefix_len } => format!("{}/{prefix_len}", Ipv6Addr::from(addr)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::entity::PortRange;

    fn rule(id: &str, priority: u32, action: FirewallAction) -> FirewallRule {
        FirewallRule {
            id: RuleId(id.to_string()),
            priority,
            action,
            protocol: Protocol::Any,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            scope: Scope::Global,
            enabled: true,
            vlan_id: None,
            src_alias: None,
            dst_alias: None,
            src_port_alias: None,
            dst_port_alias: None,
            src_mac_alias: None,
            dst_mac_alias: None,
            ct_states: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            negate_src: false,
            negate_dst: false,
            dscp_match: None,
            dscp_mark: None,
            max_states: None,
            src_mac: None,
            dst_mac: None,
            schedule: None,
            system: false,
            group_mask: 0,
            tenant_id: 0,
            workload: None,
        }
    }

    fn posture(rules: Vec<FirewallRule>, default_drop: bool) -> FirewallPosture {
        FirewallPosture {
            rules,
            enabled: true,
            mode: DomainMode::Block,
            default_drop,
        }
    }

    fn tcp(address: &str, port: u16) -> ListenerEndpoint {
        ListenerEndpoint {
            address: address.parse().unwrap(),
            port,
            protocol: ListenerProtocol::Tcp,
        }
    }

    fn v4(addr: [u8; 4], prefix_len: u8) -> IpNetwork {
        IpNetwork::V4 {
            addr: u32::from(Ipv4Addr::from(addr)),
            prefix_len,
        }
    }

    #[test]
    fn no_rule_and_a_passing_default_leaves_every_listener_open() {
        let reach = reach_of(tcp("0.0.0.0", 22), &posture(vec![], false));
        assert!(reach.open);
        assert!(!reach.restricted());
        assert_eq!(
            reach.decided_by,
            ReachDecision::DefaultPolicy { drop: false }
        );
    }

    #[test]
    fn a_dropping_default_with_no_rule_closes_the_listener() {
        let reach = reach_of(tcp("0.0.0.0", 22), &posture(vec![], true));
        assert!(!reach.open);
        assert_eq!(
            reach.decided_by,
            ReachDecision::DefaultPolicy { drop: true }
        );
    }

    #[test]
    fn an_allow_from_one_range_before_a_drop_opens_the_listener_to_that_range_only() {
        let mut admin = rule("ssh-admin", 10, FirewallAction::Allow);
        admin.dst_port = Some(PortRange { start: 22, end: 22 });
        admin.src_ip = Some(v4([10, 0, 0, 0], 8));
        let reach = reach_of(tcp("0.0.0.0", 22), &posture(vec![admin], true));
        assert!(reach.open);
        assert!(reach.restricted());
        assert_eq!(reach.allowed_from, ["10.0.0.0/8"]);
    }

    #[test]
    fn a_deny_on_the_port_closes_it_and_the_first_rule_by_priority_wins() {
        let mut deny = rule("no-redis", 20, FirewallAction::Deny);
        deny.dst_port = Some(PortRange {
            start: 6379,
            end: 6379,
        });
        let allow_all = rule("allow-all", 30, FirewallAction::Allow);
        let reach = reach_of(
            tcp("0.0.0.0", 6379),
            &posture(vec![allow_all.clone(), deny.clone()], false),
        );
        assert!(!reach.open);
        assert_eq!(
            reach.decided_by,
            ReachDecision::Rule {
                id: RuleId("no-redis".into()),
                action: FirewallAction::Deny
            }
        );
        deny.priority = 40;
        let reach = reach_of(tcp("0.0.0.0", 6379), &posture(vec![allow_all, deny], false));
        assert!(reach.open);
    }

    #[test]
    fn a_rule_narrowed_by_something_other_than_its_source_never_closes_a_listener() {
        let mut deny = rule("vlan-deny", 10, FirewallAction::Deny);
        deny.vlan_id = Some(30);
        let reach = reach_of(tcp("0.0.0.0", 80), &posture(vec![deny], false));
        assert!(reach.open);
        let mut deny = rule("iface-deny", 10, FirewallAction::Deny);
        deny.scope = Scope::Interface("eth1".into());
        let reach = reach_of(tcp("0.0.0.0", 80), &posture(vec![deny], false));
        assert!(reach.open);
    }

    #[test]
    fn a_deny_on_one_address_does_not_close_a_socket_bound_on_all_of_them() {
        let mut deny = rule("one-address", 10, FirewallAction::Deny);
        deny.dst_ip = Some(v4([10, 0, 0, 7], 32));
        let open = reach_of(tcp("0.0.0.0", 80), &posture(vec![deny.clone()], false));
        assert!(open.open);
        let closed = reach_of(tcp("10.0.0.7", 80), &posture(vec![deny], false));
        assert!(!closed.open);
    }

    #[test]
    fn a_rule_for_another_port_protocol_or_family_is_not_read() {
        let mut udp = rule("udp", 10, FirewallAction::Deny);
        udp.protocol = Protocol::Udp;
        let mut port = rule("port", 11, FirewallAction::Deny);
        port.dst_port = Some(PortRange { start: 1, end: 21 });
        let mut v6 = rule("v6", 12, FirewallAction::Deny);
        v6.dst_ip = Some(IpNetwork::V6 {
            addr: [0; 16],
            prefix_len: 0,
        });
        let reach = reach_of(tcp("10.0.0.7", 22), &posture(vec![udp, port, v6], false));
        assert!(reach.open);
        assert_eq!(
            reach.decided_by,
            ReachDecision::DefaultPolicy { drop: false }
        );
    }

    #[test]
    fn a_firewall_that_drops_nothing_closes_nothing() {
        let mut alerting = posture(vec![rule("deny-all", 1, FirewallAction::Deny)], true);
        alerting.mode = DomainMode::Alert;
        let reach = reach_of(tcp("0.0.0.0", 22), &alerting);
        assert!(reach.open);
        assert_eq!(reach.decided_by, ReachDecision::NotEnforcing);
        let mut disabled = posture(vec![], true);
        disabled.enabled = false;
        assert!(reach_of(tcp("0.0.0.0", 22), &disabled).open);
    }

    #[test]
    fn a_loopback_listener_is_reached_by_nothing_off_the_node() {
        let reach = reach_of(tcp("127.0.0.1", 5432), &posture(vec![], false));
        assert!(!reach.open);
        assert_eq!(reach.decided_by, ReachDecision::Loopback);
    }

    #[test]
    fn a_log_rule_passes_the_packet_it_matches() {
        let log = rule("log-all", 1, FirewallAction::Log);
        let reach = reach_of(tcp("0.0.0.0", 22), &posture(vec![log], true));
        assert!(reach.open);
        assert!(!reach.restricted());
    }

    #[test]
    fn an_allow_by_alias_or_negated_range_is_named_as_written() {
        let mut alias = rule("office", 1, FirewallAction::Allow);
        alias.src_alias = Some("office_nets".into());
        let mut negated = rule("not-guest", 2, FirewallAction::Allow);
        negated.src_ip = Some(v4([192, 168, 50, 0], 24));
        negated.negate_src = true;
        let reach = reach_of(tcp("0.0.0.0", 443), &posture(vec![alias, negated], true));
        assert_eq!(
            reach.allowed_from,
            ["alias office_nets", "not 192.168.50.0/24"]
        );
    }

    #[test]
    fn a_disabled_rule_is_not_read() {
        let mut deny = rule("off", 1, FirewallAction::Deny);
        deny.enabled = false;
        assert!(reach_of(tcp("0.0.0.0", 22), &posture(vec![deny], false)).open);
    }
}
