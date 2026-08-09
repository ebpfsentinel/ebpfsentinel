//! Bind the firewall rule criteria that are named by an alias to something the
//! data plane can match.
//!
//! A rule names an alias instead of spelling out addresses, ports or MAC
//! addresses. The kernel knows nothing about alias names, so each reference is
//! resolved before the rule reaches the rule table:
//!
//! - an alias whose content lives in the kernel IP set map (the dynamic and
//!   external kinds, refreshed on their own schedule) binds the rule to that
//!   set id, and the datapath looks the packet address up in the map;
//! - a statically resolved alias is expanded into one installed rule per
//!   member, since the rule table matches a single CIDR, port range or MAC per
//!   entry.
//!
//! A reference that resolves to nothing drops its rule rather than installing
//! it with the criterion left out, which would widen the rule instead of
//! restricting it.

use std::collections::HashMap;

use domain::firewall::entity::{FirewallRule, IpNetwork, MacAddress, PortRange};

use crate::alias_service_impl::AliasAppService;

/// Upper bound on the rules one authored rule may expand into.
///
/// The rule table holds a few thousand entries shared by every rule, so a
/// single alias with a large membership must not be allowed to fill it.
const MAX_EXPANSION: usize = 256;

/// A rule as the data plane will hold it, with its alias references resolved.
#[derive(Debug, Clone)]
pub struct KernelRule {
    /// The rule with literal match criteria, alias references cleared.
    pub rule: FirewallRule,
    /// Kernel IP set to match the source against, 0 when unused.
    pub src_set_id: u8,
    /// Kernel IP set to match the destination against, 0 when unused.
    pub dst_set_id: u8,
}

/// What every alias a rule may name resolves to.
///
/// Collected from the alias service and handed to the firewall service, which
/// holds no reference to the alias service itself.
#[derive(Debug, Clone, Default)]
pub struct AliasBindings {
    ips: HashMap<String, Vec<IpNetwork>>,
    ports: HashMap<String, Vec<PortRange>>,
    macs: HashMap<String, Vec<MacAddress>>,
    set_ids: HashMap<String, u8>,
}

impl AliasBindings {
    /// Number of aliases with usable content, for logging.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ips.len() + self.ports.len() + self.macs.len() + self.set_ids.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bind an alias to the kernel IP set that holds its addresses.
    pub fn bind_set(&mut self, name: impl Into<String>, set_id: u8) {
        self.set_ids.insert(name.into(), set_id);
    }

    /// Bind an alias to the networks it resolves to.
    pub fn bind_ips(&mut self, name: impl Into<String>, ips: Vec<IpNetwork>) {
        self.ips.insert(name.into(), ips);
    }

    /// Bind an alias to the port ranges it resolves to.
    pub fn bind_ports(&mut self, name: impl Into<String>, ports: Vec<PortRange>) {
        self.ports.insert(name.into(), ports);
    }

    /// Bind an alias to the MAC addresses it resolves to.
    pub fn bind_macs(&mut self, name: impl Into<String>, macs: Vec<MacAddress>) {
        self.macs.insert(name.into(), macs);
    }
}

/// Resolve every loaded alias once, so rule binding needs no further lookup.
///
/// Aliases already loaded into the kernel IP set map are bound by set id: their
/// content is fetched on a schedule and is not available here. The rest are
/// resolved statically.
#[must_use]
pub fn collect_bindings(aliases: &AliasAppService) -> AliasBindings {
    let mut bindings = AliasBindings::default();

    for name in aliases.alias_names() {
        if let Some(set_id) = aliases.assigned_set_id(&name) {
            bindings.bind_set(name, set_id);
            continue;
        }
        if let Ok(ips) = aliases.resolve_ips(&name)
            && !ips.is_empty()
        {
            bindings.bind_ips(name.clone(), ips);
        }
        if let Ok(ports) = aliases.resolve_ports(&name)
            && !ports.is_empty()
        {
            bindings.bind_ports(name.clone(), ports);
        }
        if let Ok(macs) = aliases.resolve_macs(&name)
            && !macs.is_empty()
        {
            bindings.bind_macs(name, macs);
        }
    }

    bindings
}

/// One side of an address criterion once its alias reference is resolved.
#[derive(Debug, Clone)]
enum IpSide {
    /// A literal network, or no restriction at all.
    Literal(Option<IpNetwork>),
    /// A kernel IP set holding IPv4 host addresses.
    Set(u8),
}

impl IpSide {
    /// The literal network and the set id this side installs, one of which is
    /// always empty.
    fn parts(&self) -> (Option<IpNetwork>, u8) {
        match self {
            Self::Literal(net) => (*net, 0),
            Self::Set(id) => (None, *id),
        }
    }
}

/// Every criterion of a rule once its alias references are resolved.
struct Sides {
    src_ips: Vec<IpSide>,
    dst_ips: Vec<IpSide>,
    src_ports: Vec<Option<PortRange>>,
    dst_ports: Vec<Option<PortRange>>,
    src_macs: Vec<Option<MacAddress>>,
    dst_macs: Vec<Option<MacAddress>>,
}

impl Sides {
    fn resolve(rule: &FirewallRule, bindings: &AliasBindings) -> Result<Self, String> {
        Ok(Self {
            src_ips: ip_side(
                rule,
                "src",
                rule.src_ip,
                rule.src_alias.as_deref(),
                bindings,
            )?,
            dst_ips: ip_side(
                rule,
                "dst",
                rule.dst_ip,
                rule.dst_alias.as_deref(),
                bindings,
            )?,
            src_ports: port_side(
                rule,
                "src_port",
                rule.src_port,
                rule.src_port_alias.as_deref(),
                bindings,
            )?,
            dst_ports: port_side(
                rule,
                "dst_port",
                rule.dst_port,
                rule.dst_port_alias.as_deref(),
                bindings,
            )?,
            src_macs: mac_side(
                rule,
                "src_mac",
                rule.src_mac,
                rule.src_mac_alias.as_deref(),
                bindings,
            )?,
            dst_macs: mac_side(
                rule,
                "dst_mac",
                rule.dst_mac,
                rule.dst_mac_alias.as_deref(),
                bindings,
            )?,
        })
    }

    /// How many rules the criteria expand into before the family guard.
    fn combinations(&self) -> usize {
        self.src_ips.len()
            * self.dst_ips.len()
            * self.src_ports.len()
            * self.dst_ports.len()
            * self.src_macs.len()
            * self.dst_macs.len()
    }

    fn build(&self, rule: &FirewallRule) -> Vec<KernelRule> {
        let mut out = Vec::with_capacity(self.combinations());
        for src_ip in &self.src_ips {
            for dst_ip in &self.dst_ips {
                let (src_net, src_set_id) = src_ip.parts();
                let (dst_net, dst_set_id) = dst_ip.parts();
                // A criterion pairing an IPv4 side with an IPv6 one matches
                // nothing, and the two live in different rule tables. The IP
                // set map is IPv4 only, so it pairs with IPv4 alone.
                if !families_agree(src_net, src_set_id, dst_net, dst_set_id) {
                    continue;
                }
                for src_port in &self.src_ports {
                    for dst_port in &self.dst_ports {
                        for src_mac in &self.src_macs {
                            for dst_mac in &self.dst_macs {
                                let mut expanded = rule.clone();
                                expanded.src_ip = src_net;
                                expanded.dst_ip = dst_net;
                                expanded.src_port = *src_port;
                                expanded.dst_port = *dst_port;
                                expanded.src_mac = *src_mac;
                                expanded.dst_mac = *dst_mac;
                                expanded.src_alias = None;
                                expanded.dst_alias = None;
                                expanded.src_port_alias = None;
                                expanded.dst_port_alias = None;
                                expanded.src_mac_alias = None;
                                expanded.dst_mac_alias = None;
                                out.push(KernelRule {
                                    rule: expanded,
                                    src_set_id,
                                    dst_set_id,
                                });
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

/// Resolve a rule into the rules the data plane will hold.
///
/// Returns an error describing why the rule cannot be installed, which the
/// caller logs; an unresolvable reference never yields a rule with the
/// criterion dropped.
pub fn expand_for_kernel(
    rule: &FirewallRule,
    bindings: &AliasBindings,
) -> Result<Vec<KernelRule>, String> {
    let sides = Sides::resolve(rule, bindings)?;

    let combinations = sides.combinations();
    if combinations > MAX_EXPANSION {
        return Err(format!(
            "aliases expand this rule into {combinations} rules, over the {MAX_EXPANSION} allowed; \
             an alias of this size belongs to a dynamic or external kind, whose members the kernel \
             IP set matches without expansion"
        ));
    }

    let out = sides.build(rule);
    if out.is_empty() {
        return Err(
            "the rule address criteria mix IPv4 and IPv6, so no combination can be installed"
                .to_string(),
        );
    }
    Ok(out)
}

/// Whether both sides of a rule belong to the same address family.
fn families_agree(
    src_net: Option<IpNetwork>,
    src_set_id: u8,
    dst_net: Option<IpNetwork>,
    dst_set_id: u8,
) -> bool {
    let src_v6 = src_net.as_ref().is_some_and(IpNetwork::is_v6);
    let dst_v6 = dst_net.as_ref().is_some_and(IpNetwork::is_v6);
    if src_net.is_some() && dst_net.is_some() && src_v6 != dst_v6 {
        return false;
    }
    // An IP set only holds IPv4 addresses.
    if (src_set_id != 0 && dst_v6) || (dst_set_id != 0 && src_v6) {
        return false;
    }
    true
}

fn ip_side(
    rule: &FirewallRule,
    field: &str,
    literal: Option<IpNetwork>,
    alias: Option<&str>,
    bindings: &AliasBindings,
) -> Result<Vec<IpSide>, String> {
    let Some(name) = alias else {
        return Ok(vec![IpSide::Literal(literal)]);
    };
    if literal.is_some() {
        warn_literal_wins(rule, field, name);
        return Ok(vec![IpSide::Literal(literal)]);
    }
    if let Some(&set_id) = bindings.set_ids.get(name) {
        return Ok(vec![IpSide::Set(set_id)]);
    }
    match bindings.ips.get(name) {
        Some(nets) => Ok(nets.iter().map(|n| IpSide::Literal(Some(*n))).collect()),
        None => Err(format!(
            "{field} alias '{name}' resolves to no address the data plane can match"
        )),
    }
}

fn port_side(
    rule: &FirewallRule,
    field: &str,
    literal: Option<PortRange>,
    alias: Option<&str>,
    bindings: &AliasBindings,
) -> Result<Vec<Option<PortRange>>, String> {
    let Some(name) = alias else {
        return Ok(vec![literal]);
    };
    if literal.is_some() {
        warn_literal_wins(rule, field, name);
        return Ok(vec![literal]);
    }
    match bindings.ports.get(name) {
        Some(ranges) => Ok(ranges.iter().map(|r| Some(*r)).collect()),
        None => Err(format!("{field} alias '{name}' resolves to no port range")),
    }
}

fn mac_side(
    rule: &FirewallRule,
    field: &str,
    literal: Option<MacAddress>,
    alias: Option<&str>,
    bindings: &AliasBindings,
) -> Result<Vec<Option<MacAddress>>, String> {
    let Some(name) = alias else {
        return Ok(vec![literal]);
    };
    if literal.is_some() {
        warn_literal_wins(rule, field, name);
        return Ok(vec![literal]);
    }
    match bindings.macs.get(name) {
        Some(macs) => Ok(macs.iter().map(|m| Some(*m)).collect()),
        None => Err(format!("{field} alias '{name}' resolves to no MAC address")),
    }
}

/// Both spellings set is a configuration mistake rather than an intersection:
/// the literal is the narrower, explicit intent.
fn warn_literal_wins(rule: &FirewallRule, field: &str, alias: &str) {
    tracing::warn!(
        component = "firewall",
        rule = %rule.id.0,
        field,
        alias,
        "rule sets both a literal criterion and an alias, the alias is ignored"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{Protocol, RuleId};
    use domain::firewall::entity::{FirewallAction, Scope};

    fn v4(addr: u32, prefix_len: u8) -> IpNetwork {
        IpNetwork::V4 { addr, prefix_len }
    }

    fn v6() -> IpNetwork {
        IpNetwork::V6 {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            prefix_len: 128,
        }
    }

    fn rule() -> FirewallRule {
        FirewallRule {
            id: RuleId("r1".to_string()),
            priority: 100,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
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
            route_action: None,
            group_mask: 0,
        }
    }

    fn bindings_with_ips(name: &str, nets: Vec<IpNetwork>) -> AliasBindings {
        let mut b = AliasBindings::default();
        b.bind_ips(name, nets);
        b
    }

    #[test]
    fn rule_without_alias_is_installed_as_written() {
        let mut r = rule();
        r.src_ip = Some(v4(0x0A00_0001, 32));
        let out = expand_for_kernel(&r, &AliasBindings::default()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule.src_ip, r.src_ip);
        assert_eq!(out[0].src_set_id, 0);
    }

    #[test]
    fn static_alias_expands_into_one_rule_per_network() {
        let mut r = rule();
        r.src_alias = Some("lan".to_string());
        let b = bindings_with_ips("lan", vec![v4(0x0A00_0000, 24), v4(0xC0A8_0000, 16)]);

        let out = expand_for_kernel(&r, &b).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].rule.src_ip, Some(v4(0x0A00_0000, 24)));
        assert_eq!(out[1].rule.src_ip, Some(v4(0xC0A8_0000, 16)));
        assert!(out.iter().all(|k| k.rule.src_alias.is_none()));
    }

    #[test]
    fn set_backed_alias_binds_the_set_id_without_expanding() {
        let mut r = rule();
        r.src_alias = Some("blocklist".to_string());
        let mut b = AliasBindings::default();
        b.bind_set("blocklist", 4);

        let out = expand_for_kernel(&r, &b).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].src_set_id, 4);
        assert_eq!(out[0].rule.src_ip, None);
    }

    #[test]
    fn both_sides_named_produce_the_cross_product() {
        let mut r = rule();
        r.src_alias = Some("lan".to_string());
        r.dst_alias = Some("web".to_string());
        let mut b = bindings_with_ips("lan", vec![v4(0x0A00_0000, 24), v4(0x0A01_0000, 24)]);
        b.ips.insert(
            "web".to_string(),
            vec![v4(0xC000_0201, 32), v4(0xC000_0202, 32)],
        );

        assert_eq!(expand_for_kernel(&r, &b).unwrap().len(), 4);
    }

    #[test]
    fn combinations_mixing_families_are_skipped() {
        let mut r = rule();
        r.src_alias = Some("lan".to_string());
        r.dst_alias = Some("mixed".to_string());
        let mut b = bindings_with_ips("lan", vec![v4(0x0A00_0000, 24)]);
        b.bind_ips("mixed", vec![v6(), v4(0xC000_0201, 32)]);

        let out = expand_for_kernel(&r, &b).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule.dst_ip, Some(v4(0xC000_0201, 32)));
    }

    #[test]
    fn a_set_never_pairs_with_an_ipv6_criterion() {
        let mut r = rule();
        r.src_alias = Some("blocklist".to_string());
        r.dst_ip = Some(v6());
        let mut b = AliasBindings::default();
        b.bind_set("blocklist", 4);

        assert!(expand_for_kernel(&r, &b).is_err());
    }

    #[test]
    fn unresolvable_alias_drops_the_rule() {
        let mut r = rule();
        r.src_alias = Some("typo".to_string());
        assert!(expand_for_kernel(&r, &AliasBindings::default()).is_err());
    }

    #[test]
    fn literal_wins_over_the_alias() {
        let mut r = rule();
        r.src_ip = Some(v4(0x0A00_0001, 32));
        r.src_alias = Some("lan".to_string());
        let b = bindings_with_ips("lan", vec![v4(0xC0A8_0000, 16)]);

        let out = expand_for_kernel(&r, &b).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule.src_ip, Some(v4(0x0A00_0001, 32)));
    }

    #[test]
    fn port_and_mac_aliases_expand_too() {
        let mut r = rule();
        r.dst_port_alias = Some("web-ports".to_string());
        r.src_mac_alias = Some("printers".to_string());
        let mut b = AliasBindings::default();
        b.bind_ports(
            "web-ports",
            vec![
                PortRange { start: 80, end: 80 },
                PortRange {
                    start: 443,
                    end: 443,
                },
            ],
        );
        b.bind_macs("printers", vec![MacAddress([0xAA, 0xBB, 0xCC, 0, 0, 1])]);

        let out = expand_for_kernel(&r, &b).unwrap();
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|k| k.rule.src_mac == Some(MacAddress([0xAA, 0xBB, 0xCC, 0, 0, 1])))
        );
        assert_eq!(
            out[1].rule.dst_port,
            Some(PortRange {
                start: 443,
                end: 443
            })
        );
    }

    #[test]
    fn an_alias_too_large_to_expand_is_reported() {
        let mut r = rule();
        r.src_alias = Some("huge".to_string());
        let nets: Vec<IpNetwork> = (0..=(MAX_EXPANSION as u32))
            .map(|i| v4(0x0A00_0000 + i, 32))
            .collect();
        let b = bindings_with_ips("huge", nets);

        assert!(expand_for_kernel(&r, &b).is_err());
    }

    #[test]
    fn expansion_is_idempotent_once_applied() {
        let mut r = rule();
        r.src_alias = Some("lan".to_string());
        let b = bindings_with_ips("lan", vec![v4(0x0A00_0000, 24)]);

        let first = expand_for_kernel(&r, &b).unwrap();
        let second = expand_for_kernel(&first[0].rule, &b).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].rule.src_ip, first[0].rule.src_ip);
    }
}
