//! Resolve the NAT rule match criteria that are named by an alias.
//!
//! `match_src` and `match_dst` hold literal CIDRs, which the configuration
//! layer parses on its own. `match_src_alias` and `match_dst_alias` name alias
//! objects instead, and those are only known once the alias service has loaded
//! them. The data plane matches CIDRs, so an alias-named rule is expanded here
//! into one rule per resolved network before it reaches the kernel maps.

use std::net::{Ipv4Addr, Ipv6Addr};

use domain::firewall::entity::IpNetwork;
use domain::nat::entity::NatRule;

use crate::alias_service_impl::AliasAppService;
use crate::nat_service_impl::NatAppService;

/// What expanding the alias-named rules produced.
#[derive(Debug, Clone, Default)]
pub struct ExpandedRules {
    /// Rules to install, with every alias reference replaced by a CIDR.
    pub rules: Vec<NatRule>,
    /// Rules dropped because an alias could not be resolved, with the reason.
    ///
    /// Dropped rather than installed unrestricted: a NAT rule whose source
    /// restriction silently disappeared would translate traffic it was never
    /// meant to touch.
    pub failures: Vec<(String, String)>,
}

/// Expand every alias-named match criterion into literal CIDRs.
///
/// A rule that names no alias is returned untouched. A rule that names one on
/// both sides is expanded into the cross product of the two resolutions, minus
/// the combinations that mix address families, since those can never match.
/// Expanded rules keep the id of the rule they came from: the NAT service
/// addresses rules positionally, and they remain one rule to the operator.
#[must_use]
pub fn expand_rule_aliases(rules: Vec<NatRule>, aliases: &AliasAppService) -> ExpandedRules {
    let mut out = ExpandedRules::default();
    for rule in rules {
        if rule.match_src_alias.is_none() && rule.match_dst_alias.is_none() {
            out.rules.push(rule);
            continue;
        }
        match expand_one(&rule, aliases) {
            Ok(expanded) => out.rules.extend(expanded),
            Err(reason) => out.failures.push((rule.id.0.clone(), reason)),
        }
    }
    out
}

/// Report every rule an unresolved alias took out of the rule set.
pub fn log_failures(failures: &[(String, String)]) {
    for (rule, reason) in failures {
        tracing::warn!(
            component = "nat",
            rule = %rule,
            error = %reason,
            "NAT rule dropped: alias could not be resolved"
        );
    }
}

/// Re-expand the rules a NAT service already holds against the alias service.
///
/// Startup builds the NAT service before the alias service exists, so the rules
/// are installed with their alias references intact and this runs once aliases
/// have loaded. Expansion is idempotent, so a rule that names no alias, or one
/// that was expanded already, survives a second pass unchanged.
pub fn apply_rule_aliases(nat: &mut NatAppService, aliases: &AliasAppService) {
    let dnat = expand_rule_aliases(nat.dnat_rules().to_vec(), aliases);
    let snat = expand_rule_aliases(nat.snat_rules().to_vec(), aliases);
    log_failures(&dnat.failures);
    log_failures(&snat.failures);
    if let Err(e) = nat.reload_dnat_rules(dnat.rules) {
        tracing::warn!(component = "nat", error = %e, "DNAT alias expansion not applied");
    }
    if let Err(e) = nat.reload_snat_rules(snat.rules) {
        tracing::warn!(component = "nat", error = %e, "SNAT alias expansion not applied");
    }
}

/// Expand a single rule, or explain why it cannot be installed.
fn expand_one(rule: &NatRule, aliases: &AliasAppService) -> Result<Vec<NatRule>, String> {
    let src = side_cidrs(
        rule.match_src.as_deref(),
        rule.match_src_alias.as_deref(),
        &rule.id.0,
        "match_src",
        aliases,
    )?;
    let dst = side_cidrs(
        rule.match_dst.as_deref(),
        rule.match_dst_alias.as_deref(),
        &rule.id.0,
        "match_dst",
        aliases,
    )?;

    let mut expanded = Vec::new();
    for s in &src {
        for d in &dst {
            // A rule matching an IPv4 source and an IPv6 destination matches
            // nothing, so the combination is skipped rather than installed.
            if let (Some(s), Some(d)) = (s.as_deref(), d.as_deref())
                && s.contains(':') != d.contains(':')
            {
                continue;
            }
            let mut out = rule.clone();
            out.match_src.clone_from(s);
            out.match_dst.clone_from(d);
            out.match_src_alias = None;
            out.match_dst_alias = None;
            expanded.push(out);
        }
    }

    if expanded.is_empty() {
        return Err("alias expansion left no address family in common".to_string());
    }
    Ok(expanded)
}

/// Resolve one side of a rule into the CIDRs it should match.
///
/// `None` inside the returned vector means "any", which is what an absent
/// literal and an absent alias together mean.
fn side_cidrs(
    literal: Option<&str>,
    alias: Option<&str>,
    rule_id: &str,
    field: &str,
    aliases: &AliasAppService,
) -> Result<Vec<Option<String>>, String> {
    let Some(name) = alias else {
        return Ok(vec![literal.map(ToString::to_string)]);
    };
    if let Some(cidr) = literal {
        // Both spellings set is a configuration mistake rather than an
        // intersection: the literal is the narrower, explicit intent.
        tracing::warn!(
            component = "nat",
            rule = %rule_id,
            field,
            alias = %name,
            "NAT rule sets both a literal CIDR and an alias, the alias is ignored"
        );
        return Ok(vec![Some(cidr.to_string())]);
    }
    let networks = aliases.resolve_ips(name).map_err(|e| e.to_string())?;
    if networks.is_empty() {
        return Err(format!("alias '{name}' resolves to no network"));
    }
    Ok(networks.iter().map(|n| Some(format_cidr(n))).collect())
}

/// Render an alias network as the CIDR string the NAT rules carry.
fn format_cidr(network: &IpNetwork) -> String {
    match *network {
        IpNetwork::V4 { addr, prefix_len } => {
            format!("{}/{prefix_len}", Ipv4Addr::from(addr))
        }
        IpNetwork::V6 { addr, prefix_len } => {
            format!("{}/{prefix_len}", Ipv6Addr::from(addr))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use domain::alias::entity::{Alias, AliasId, AliasKind};
    use domain::common::entity::RuleId;
    use domain::nat::entity::NatType;
    use ports::test_utils::NoopMetrics;

    use super::*;

    fn alias_service(aliases: Vec<Alias>) -> AliasAppService {
        let mut svc = AliasAppService::new(Arc::new(NoopMetrics));
        svc.reload_aliases(aliases).expect("aliases are valid");
        svc
    }

    fn ip_alias(id: &str, values: Vec<IpNetwork>) -> Alias {
        Alias {
            id: AliasId(id.to_string()),
            kind: AliasKind::IpSet {
                values,
                exclude: Vec::new(),
            },
            description: None,
        }
    }

    fn v4(addr: u32, prefix_len: u8) -> IpNetwork {
        IpNetwork::V4 { addr, prefix_len }
    }

    fn rule(id: &str) -> NatRule {
        NatRule {
            id: RuleId(id.to_string()),
            priority: 100,
            nat_type: NatType::Snat {
                addr: IpAddr::V4("203.0.113.1".parse().unwrap()),
                port_range: None,
            },
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            match_src_alias: None,
            match_dst_alias: None,
            enabled: true,
            group_mask: 0,
            tenant_id: 0,
            xfrm_if_id: 0,
            xfrm_link: 0,
            fou_sport: 0,
            fou_dport: 0,
            fou_type: 0,
        }
    }

    #[test]
    fn a_rule_without_alias_is_untouched() {
        let svc = alias_service(Vec::new());
        let mut r = rule("snat-1");
        r.match_src = Some("10.0.0.0/8".to_string());

        let out = expand_rule_aliases(vec![r], &svc);

        assert!(out.failures.is_empty());
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.rules[0].match_src.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn a_source_alias_becomes_one_rule_per_network() {
        let svc = alias_service(vec![ip_alias(
            "lan",
            vec![v4(0x0A00_0000, 8), v4(0xC0A8_0000, 16)],
        )]);
        let mut r = rule("snat-1");
        r.match_src_alias = Some("lan".to_string());

        let out = expand_rule_aliases(vec![r], &svc);

        assert!(out.failures.is_empty());
        assert_eq!(out.rules.len(), 2);
        assert_eq!(out.rules[0].match_src.as_deref(), Some("10.0.0.0/8"));
        assert_eq!(out.rules[1].match_src.as_deref(), Some("192.168.0.0/16"));
        assert!(out.rules.iter().all(|r| r.match_src_alias.is_none()));
        assert!(out.rules.iter().all(|r| r.id.0 == "snat-1"));
    }

    #[test]
    fn both_sides_expand_into_a_cross_product() {
        let svc = alias_service(vec![
            ip_alias("lan", vec![v4(0x0A00_0000, 8), v4(0xC0A8_0000, 16)]),
            ip_alias("web", vec![v4(0xC000_0201, 32)]),
        ]);
        let mut r = rule("dnat-1");
        r.match_src_alias = Some("lan".to_string());
        r.match_dst_alias = Some("web".to_string());

        let out = expand_rule_aliases(vec![r], &svc);

        assert_eq!(out.rules.len(), 2);
        assert!(
            out.rules
                .iter()
                .all(|r| r.match_dst.as_deref() == Some("192.0.2.1/32"))
        );
    }

    #[test]
    fn a_family_mismatch_is_dropped_rather_than_installed() {
        let mut v6_addr = [0u8; 16];
        v6_addr[0] = 0x20;
        v6_addr[1] = 0x01;
        let svc = alias_service(vec![
            ip_alias("lan", vec![v4(0x0A00_0000, 8)]),
            ip_alias(
                "v6-only",
                vec![IpNetwork::V6 {
                    addr: v6_addr,
                    prefix_len: 32,
                }],
            ),
        ]);
        let mut r = rule("dnat-1");
        r.match_src_alias = Some("lan".to_string());
        r.match_dst_alias = Some("v6-only".to_string());

        let out = expand_rule_aliases(vec![r], &svc);

        assert!(out.rules.is_empty());
        assert_eq!(out.failures.len(), 1);
        assert_eq!(out.failures[0].0, "dnat-1");
    }

    #[test]
    fn an_unknown_alias_drops_only_its_own_rule() {
        let svc = alias_service(vec![ip_alias("lan", vec![v4(0x0A00_0000, 8)])]);
        let mut good = rule("snat-1");
        good.match_src_alias = Some("lan".to_string());
        let mut bad = rule("snat-2");
        bad.match_src_alias = Some("typo".to_string());

        let out = expand_rule_aliases(vec![good, bad], &svc);

        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.rules[0].id.0, "snat-1");
        assert_eq!(out.failures.len(), 1);
        assert_eq!(out.failures[0].0, "snat-2");
    }

    #[test]
    fn a_literal_cidr_wins_over_an_alias_on_the_same_side() {
        let svc = alias_service(vec![ip_alias("lan", vec![v4(0x0A00_0000, 8)])]);
        let mut r = rule("snat-1");
        r.match_src = Some("172.16.0.0/12".to_string());
        r.match_src_alias = Some("lan".to_string());

        let out = expand_rule_aliases(vec![r], &svc);

        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.rules[0].match_src.as_deref(), Some("172.16.0.0/12"));
        assert!(out.rules[0].match_src_alias.is_none());
    }

    #[test]
    fn expansion_is_idempotent() {
        let svc = alias_service(vec![ip_alias("lan", vec![v4(0x0A00_0000, 8)])]);
        let mut r = rule("snat-1");
        r.match_src_alias = Some("lan".to_string());

        let once = expand_rule_aliases(vec![r], &svc);
        let twice = expand_rule_aliases(once.rules.clone(), &svc);

        assert_eq!(twice.rules.len(), once.rules.len());
        assert_eq!(twice.rules[0].match_src, once.rules[0].match_src);
    }
}
