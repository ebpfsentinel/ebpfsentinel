//! Which processes may resolve.
//!
//! A tunnel over DNS needs a process that speaks DNS to the network, and on a
//! node configured the usual way only one or two do: the local stub resolver,
//! the cluster's DNS server, a monitoring probe. Everything else asks one of
//! those. This block says so as policy: the listed clients may send DNS
//! anywhere, every task may send it to the listed resolvers, and every other
//! DNS packet a task sends is refused, or reported while the mode is observe.
//!
//! The block is not a mechanism of its own. It is expanded into ordinary
//! workload rules, decided by the same socket hooks at `connect()` and
//! `sendmsg()`, and listed beside the operator's own rules under ids starting
//! with [`DNS_CLIENTS_RULE_PREFIX`]. DNS here is what the port says it is:
//! 53 over UDP and TCP, and 853 for DNS over TLS and over QUIC. A query
//! carried inside HTTPS, or handed to a proxy, is another protocol on another
//! port and is outside the rule.

use super::entity::{FirewallAction, FirewallRule, IpNetwork, PortRange, Scope};
use super::error::FirewallError;
use super::workload::{WorkloadMatch, WorkloadMode, WorkloadSelector};
use crate::common::entity::{Protocol, RuleId};

/// What every rule the block expands into is named after.
pub const DNS_CLIENTS_RULE_PREFIX: &str = "dns-clients";

/// The ports a DNS client is recognised by: 53 for DNS over UDP and TCP, 853
/// for DNS over TLS and over QUIC.
pub const DNS_PORTS: [u16; 2] = [53, 853];

/// The priority the allowances take when the block does not say.
pub const DEFAULT_DNS_CLIENTS_PRIORITY: u32 = 1;

/// What a rule decided by the DNS port does not see, one sentence each.
///
/// Published beside the block wherever its state is reported, so a policy
/// on the DNS ports never reads as a policy on DNS as a whole.
pub const DNS_CLIENTS_NOT_COVERED: [&str; 4] = [
    "DNS over HTTPS is HTTPS on port 443, decided by the rules on that port and not by this block",
    "a query handed to a proxy leaves the node as the proxy's own connection, so this block \
     decides the proxy and not the process that asked it",
    "a resolver listening on a port other than 53 or 853 is not recognised as one",
    "a listed resolver forwards whatever names it is asked, so what goes out through it is \
     decided by the resolver and not by this block",
];

/// The cgroup every task on the node sits under.
const EVERY_TASK: &str = "/";

/// The block as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsClients {
    /// Observe or enforce, for every rule the block expands into.
    pub mode: WorkloadMode,
    /// Priority of the allowances. The refusal sits one below them, so a rule
    /// of the operator's at a priority between the two is decided first.
    pub priority: u32,
    /// Resolvers every task may send DNS to, such as the node's stub at
    /// `127.0.0.53` or the cluster DNS Service.
    pub resolvers: Vec<IpNetwork>,
    /// Workloads that may send DNS anywhere.
    pub clients: Vec<WorkloadSelector>,
}

impl DnsClients {
    /// Check the block before it is expanded.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::InvalidDnsClients`] for a priority the
    /// operator's rules cannot be ordered around, and for a block naming
    /// neither a resolver nor a client, which in enforce mode would cut DNS
    /// off from every task on the node but the agent.
    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.priority == 0 || self.priority == u32::MAX {
            return Err(FirewallError::InvalidDnsClients {
                reason: format!(
                    "priority must be between 1 and {}, since 0 belongs to the anti-lockout rules \
                     and the refusal takes the priority after it",
                    u32::MAX - 1
                ),
            });
        }
        if self.resolvers.is_empty() && self.clients.is_empty() {
            return Err(FirewallError::InvalidDnsClients {
                reason: "the block names neither a resolver nor a client, so no task but the \
                         agent could resolve"
                    .to_string(),
            });
        }
        for selector in &self.clients {
            selector.validate()?;
        }
        Ok(())
    }

    /// The workload rules the block stands for, allowances first.
    ///
    /// `agent` names the agent itself, which resolves its own feeds and
    /// endpoints and must not be cut off by a block that does not list it.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate`] refuses, and whatever a generated rule's
    /// own validation refuses.
    pub fn rules(
        &self,
        agent: Option<&WorkloadSelector>,
    ) -> Result<Vec<FirewallRule>, FirewallError> {
        self.validate()?;
        let every_task = WorkloadSelector::new(None, None, Some(EVERY_TASK.to_string()), None)?;
        let mut rules = Vec::new();

        for (index, resolver) in self.resolvers.iter().enumerate() {
            for port in DNS_PORTS {
                rules.push(self.rule(
                    format!("{DNS_CLIENTS_RULE_PREFIX}-resolver-{index}-{port}"),
                    self.priority,
                    FirewallAction::Allow,
                    Some(*resolver),
                    port,
                    every_task.clone(),
                ));
            }
        }
        for (index, client) in self.clients.iter().enumerate() {
            for port in DNS_PORTS {
                rules.push(self.rule(
                    format!("{DNS_CLIENTS_RULE_PREFIX}-client-{index}-{port}"),
                    self.priority,
                    FirewallAction::Allow,
                    None,
                    port,
                    client.clone(),
                ));
            }
        }
        if let Some(agent) = agent {
            for port in DNS_PORTS {
                rules.push(self.rule(
                    format!("{DNS_CLIENTS_RULE_PREFIX}-agent-{port}"),
                    self.priority,
                    FirewallAction::Allow,
                    None,
                    port,
                    agent.clone(),
                ));
            }
        }
        for port in DNS_PORTS {
            rules.push(self.rule(
                format!("{DNS_CLIENTS_RULE_PREFIX}-rest-{port}"),
                self.priority + 1,
                FirewallAction::Deny,
                None,
                port,
                every_task.clone(),
            ));
        }

        for rule in &rules {
            rule.validate()?;
        }
        Ok(rules)
    }

    fn rule(
        &self,
        id: String,
        priority: u32,
        action: FirewallAction,
        dst_ip: Option<IpNetwork>,
        port: u16,
        selector: WorkloadSelector,
    ) -> FirewallRule {
        FirewallRule {
            mode: crate::firewall::entity::RuleMode::Enforce,
            id: RuleId(id),
            priority,
            action,
            // Both transports on either port: 53 is UDP and TCP, and 853 is
            // DNS over TLS on TCP and DNS over QUIC on UDP.
            protocol: Protocol::Any,
            src_ip: None,
            dst_ip,
            src_port: None,
            dst_port: Some(PortRange {
                start: port,
                end: port,
            }),
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
            workload: Some(WorkloadMatch {
                peer: None,
                selector,
                mode: self.mode,
                fqdn: Vec::new(),
                // The block decides what a task sends to the DNS ports, and a
                // server on the node taking one of them as its own address is
                // not a client sending DNS.
                outbound_only: true,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::workload::{DestinationAddr, WorkloadDestination, WorkloadPolicy};

    fn exe(path: &str) -> WorkloadSelector {
        WorkloadSelector::new(Some(path.to_string()), None, None, None).unwrap()
    }

    fn stub() -> IpNetwork {
        IpNetwork::V4 {
            addr: u32::from_be_bytes([127, 0, 0, 53]),
            prefix_len: 32,
        }
    }

    fn block() -> DnsClients {
        DnsClients {
            mode: WorkloadMode::Enforce,
            priority: DEFAULT_DNS_CLIENTS_PRIORITY,
            resolvers: vec![stub()],
            clients: vec![exe("/usr/lib/systemd/systemd-resolved")],
        }
    }

    fn ids(rules: &[FirewallRule]) -> Vec<&str> {
        rules.iter().map(|r| r.id.0.as_str()).collect()
    }

    #[test]
    fn expands_into_allowances_then_one_refusal_per_port() {
        let agent = exe("/usr/local/bin/ebpfsentinel-agent");
        let rules = block().rules(Some(&agent)).unwrap();
        assert_eq!(
            ids(&rules),
            vec![
                "dns-clients-resolver-0-53",
                "dns-clients-resolver-0-853",
                "dns-clients-client-0-53",
                "dns-clients-client-0-853",
                "dns-clients-agent-53",
                "dns-clients-agent-853",
                "dns-clients-rest-53",
                "dns-clients-rest-853",
            ]
        );
        for rule in &rules[..6] {
            assert_eq!(rule.action, FirewallAction::Allow);
            assert_eq!(rule.priority, 1);
        }
        for rule in &rules[6..] {
            assert_eq!(rule.action, FirewallAction::Deny);
            assert_eq!(rule.priority, 2);
            assert_eq!(
                rule.workload.as_ref().unwrap().selector.cgroup.as_deref(),
                Some("/")
            );
        }
        assert!(rules.iter().all(|r| r.protocol == Protocol::Any));
        assert!(
            rules
                .iter()
                .all(|r| r.workload.as_ref().unwrap().mode == WorkloadMode::Enforce)
        );
        // A resolver is reachable by everybody, at that address only; a
        // client anywhere.
        assert_eq!(rules[0].dst_ip, Some(stub()));
        assert_eq!(rules[2].dst_ip, None);
    }

    #[test]
    fn a_policy_reads_the_block_as_its_rules() {
        let rules = block().rules(None).unwrap();
        let policy = WorkloadPolicy::from_rules(&rules).unwrap();
        // The kernel walks allowances before the refusal, whichever order
        // the ids sort in.
        let order: Vec<&str> = policy.rules().iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(order.last(), Some(&"dns-clients-rest-853"));
        let rest = policy
            .rules()
            .iter()
            .find(|r| r.id.0 == "dns-clients-rest-53")
            .unwrap();
        let elsewhere = WorkloadDestination {
            addr: DestinationAddr::V4(u32::from_be_bytes([8, 8, 8, 8])),
            port: 53,
            protocol: Protocol::Udp,
        };
        assert!(rest.admits_destination(&elsewhere));
        assert!(rest.enforces());
    }

    #[test]
    fn every_rule_of_the_block_leaves_a_server_binding_the_dns_ports_alone() {
        let agent = exe("/usr/local/bin/ebpfsentinel-agent");
        let rules = block().rules(Some(&agent)).unwrap();
        assert!(
            rules
                .iter()
                .all(|r| r.workload.as_ref().unwrap().outbound_only)
        );
        let policy = WorkloadPolicy::from_rules(&rules).unwrap();
        assert!(policy.rules().iter().all(|r| r.outbound_only));
    }

    #[test]
    fn leaves_out_the_agent_when_it_is_not_named() {
        let rules = block().rules(None).unwrap();
        assert!(!ids(&rules).iter().any(|id| id.contains("agent")));
    }

    #[test]
    fn observe_mode_refuses_nothing() {
        let mut observing = block();
        observing.mode = WorkloadMode::Observe;
        let rules = observing.rules(None).unwrap();
        let policy = WorkloadPolicy::from_rules(&rules).unwrap();
        assert!(policy.rules().iter().all(|r| !r.enforces()));
    }

    #[test]
    fn refuses_a_block_naming_nobody() {
        let empty = DnsClients {
            resolvers: Vec::new(),
            clients: Vec::new(),
            ..block()
        };
        assert!(matches!(
            empty.rules(None),
            Err(FirewallError::InvalidDnsClients { .. })
        ));
    }

    #[test]
    fn refuses_a_priority_nothing_can_be_ordered_around() {
        for priority in [0, u32::MAX] {
            let wrong = DnsClients {
                priority,
                ..block()
            };
            assert!(matches!(
                wrong.validate(),
                Err(FirewallError::InvalidDnsClients { .. })
            ));
        }
    }

    #[test]
    fn a_resolver_list_alone_is_enough() {
        let resolvers_only = DnsClients {
            clients: Vec::new(),
            ..block()
        };
        assert_eq!(resolvers_only.rules(None).unwrap().len(), 4);
    }
}
