//! Resolve the L7 rule criteria that are named by an alias.
//!
//! `src_ip`, `dst_ip` and `dst_port` hold literal criteria, which the
//! configuration layer parses on its own. `src_ip_alias`, `dst_ip_alias` and
//! `dst_port_alias` name alias objects instead, and those are only known once
//! the alias service has loaded them. Until this pass runs, a rule that names
//! nothing but an alias carries no criterion at all, which is not a rule
//! waiting to be resolved: it is a rule matching every address there is.
//!
//! An L7 rule holds one address criterion per side and one port range, so an
//! alias naming several networks has nowhere to go. Such a rule is dropped
//! with its reason rather than installed unrestricted, the way an unresolvable
//! NAT rule is: a rule whose source restriction silently disappeared acts on
//! traffic it was never meant to touch.

use domain::firewall::entity::{IpNetwork, PortRange};
use domain::l7::entity::L7Rule;

use crate::alias_service_impl::AliasAppService;
use crate::l7_service_impl::L7AppService;

/// What resolving the alias-named rules produced.
#[derive(Debug, Clone, Default)]
pub struct ResolvedRules {
    /// Rules to install, with every alias reference turned into a criterion.
    pub rules: Vec<L7Rule>,
    /// Rules dropped because an alias could not be applied, with the reason.
    pub failures: Vec<(String, String)>,
}

/// Turn every alias-named criterion into the literal it stands for.
///
/// A rule that names no alias is returned untouched. The alias name is kept on
/// the rule it resolved, since that is the word the configuration file used and
/// the listing reads it back.
#[must_use]
pub fn resolve_rule_aliases(rules: Vec<L7Rule>, aliases: &AliasAppService) -> ResolvedRules {
    let mut out = ResolvedRules::default();
    for rule in rules {
        if rule.src_ip_alias.is_none()
            && rule.dst_ip_alias.is_none()
            && rule.dst_port_alias.is_none()
        {
            out.rules.push(rule);
            continue;
        }
        match resolve_one(&rule, aliases) {
            Ok(resolved) => out.rules.push(resolved),
            Err(reason) => out.failures.push((rule.id.0.clone(), reason)),
        }
    }
    out
}

/// Report every rule an alias took out of the rule set.
pub fn log_failures(failures: &[(String, String)]) {
    for (rule, reason) in failures {
        tracing::warn!(
            component = "l7",
            rule = %rule,
            error = %reason,
            "L7 rule dropped: alias could not be applied"
        );
    }
}

/// Re-resolve the rules an L7 service already holds against the alias service.
///
/// Startup builds the L7 service before the alias service exists, so the rules
/// are installed with their alias references intact and this runs once aliases
/// have loaded. Resolution is idempotent: a rule that names no alias, and one
/// whose criterion is already set, survive a second pass unchanged.
pub fn apply_rule_aliases(l7: &mut L7AppService, aliases: &AliasAppService) {
    let resolved = resolve_rule_aliases(l7.rules().to_vec(), aliases);
    log_failures(&resolved.failures);
    if let Err(e) = l7.reload_rules(resolved.rules) {
        tracing::warn!(component = "l7", error = %e, "L7 alias resolution not applied");
    }
}

/// Resolve a single rule, or explain why it cannot be installed.
fn resolve_one(rule: &L7Rule, aliases: &AliasAppService) -> Result<L7Rule, String> {
    let mut out = rule.clone();
    out.src_ip = ip_side(
        rule.src_ip,
        rule.src_ip_alias.as_deref(),
        &rule.id.0,
        "src_ip",
        aliases,
    )?;
    out.dst_ip = ip_side(
        rule.dst_ip,
        rule.dst_ip_alias.as_deref(),
        &rule.id.0,
        "dst_ip",
        aliases,
    )?;
    out.dst_port = port_side(
        rule.dst_port,
        rule.dst_port_alias.as_deref(),
        &rule.id.0,
        aliases,
    )?;
    Ok(out)
}

/// The network one side of the rule matches, resolved from its alias.
fn ip_side(
    literal: Option<IpNetwork>,
    alias: Option<&str>,
    rule_id: &str,
    field: &str,
    aliases: &AliasAppService,
) -> Result<Option<IpNetwork>, String> {
    let Some(name) = alias else {
        return Ok(literal);
    };
    if let Some(network) = literal {
        // Both spellings set is a configuration mistake rather than an
        // intersection: the literal is the narrower, explicit intent.
        tracing::warn!(
            component = "l7",
            rule = %rule_id,
            field,
            alias = %name,
            "L7 rule sets both a literal address and an alias, the alias is ignored"
        );
        return Ok(Some(network));
    }
    let networks = aliases.resolve_ips(name).map_err(|e| e.to_string())?;
    match networks.len() {
        0 => Err(format!("alias '{name}' resolves to no network")),
        1 => Ok(Some(networks[0])),
        n => Err(format!(
            "alias '{name}' resolves to {n} networks and an L7 rule matches one"
        )),
    }
}

/// The same, on the destination port.
fn port_side(
    literal: Option<PortRange>,
    alias: Option<&str>,
    rule_id: &str,
    aliases: &AliasAppService,
) -> Result<Option<PortRange>, String> {
    let Some(name) = alias else {
        return Ok(literal);
    };
    if let Some(range) = literal {
        tracing::warn!(
            component = "l7",
            rule = %rule_id,
            field = "dst_port",
            alias = %name,
            "L7 rule sets both a literal port and an alias, the alias is ignored"
        );
        return Ok(Some(range));
    }
    let ranges = aliases.resolve_ports(name).map_err(|e| e.to_string())?;
    match ranges.len() {
        0 => Err(format!("alias '{name}' resolves to no port")),
        1 => Ok(Some(ranges[0])),
        n => Err(format!(
            "alias '{name}' resolves to {n} port ranges and an L7 rule matches one"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use domain::alias::entity::{Alias, AliasId, AliasKind};
    use domain::common::entity::RuleId;
    use domain::firewall::entity::FirewallAction;
    use domain::l7::entity::L7Matcher;
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

    fn port_alias(id: &str, values: Vec<PortRange>) -> Alias {
        Alias {
            id: AliasId(id.to_string()),
            kind: AliasKind::PortSet { values },
            description: None,
        }
    }

    fn v4(addr: u32, prefix_len: u8) -> IpNetwork {
        IpNetwork::V4 { addr, prefix_len }
    }

    fn rule(id: &str) -> L7Rule {
        L7Rule {
            id: RuleId(id.to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Http {
                method: None,
                path_pattern: None,
                host_pattern: None,
                content_type: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
            src_country_codes: None,
            dst_country_codes: None,
            src_ip_alias: None,
            dst_ip_alias: None,
            dst_port_alias: None,
        }
    }

    #[test]
    fn a_rule_naming_no_alias_is_untouched() {
        let svc = alias_service(Vec::new());
        let resolved = resolve_rule_aliases(vec![rule("l7-001")], &svc);
        assert_eq!(resolved.rules.len(), 1);
        assert!(resolved.rules[0].src_ip.is_none());
        assert!(resolved.failures.is_empty());
    }

    #[test]
    fn an_alias_becomes_the_criterion_the_rule_matches_on() {
        let svc = alias_service(vec![
            ip_alias("corp-nets", vec![v4(0x0A00_0000, 8)]),
            port_alias("web-ports", vec![PortRange { start: 80, end: 80 }]),
        ]);
        let mut r = rule("l7-001");
        r.src_ip_alias = Some("corp-nets".to_string());
        r.dst_port_alias = Some("web-ports".to_string());

        let resolved = resolve_rule_aliases(vec![r], &svc);
        assert!(resolved.failures.is_empty());
        assert_eq!(resolved.rules[0].src_ip, Some(v4(0x0A00_0000, 8)));
        assert_eq!(
            resolved.rules[0].dst_port,
            Some(PortRange { start: 80, end: 80 })
        );
        // The word the file used is kept, since the listing reads it back.
        assert_eq!(resolved.rules[0].src_ip_alias.as_deref(), Some("corp-nets"));
    }

    #[test]
    fn an_alias_naming_several_networks_drops_the_rule() {
        let svc = alias_service(vec![ip_alias(
            "corp-nets",
            vec![v4(0x0A00_0000, 8), v4(0xC0A8_0000, 16)],
        )]);
        let mut r = rule("l7-001");
        r.src_ip_alias = Some("corp-nets".to_string());

        let resolved = resolve_rule_aliases(vec![r], &svc);
        assert!(resolved.rules.is_empty());
        assert_eq!(resolved.failures.len(), 1);
        assert!(resolved.failures[0].1.contains("2 networks"));
    }

    #[test]
    fn an_alias_nothing_declared_drops_the_rule() {
        let svc = alias_service(Vec::new());
        let mut r = rule("l7-001");
        r.dst_ip_alias = Some("nowhere".to_string());

        let resolved = resolve_rule_aliases(vec![r], &svc);
        assert!(resolved.rules.is_empty());
        assert_eq!(resolved.failures.len(), 1);
    }

    #[test]
    fn a_literal_wins_over_the_alias_beside_it() {
        let svc = alias_service(vec![ip_alias("corp-nets", vec![v4(0x0A00_0000, 8)])]);
        let mut r = rule("l7-001");
        r.src_ip = Some(v4(0xC0A8_0100, 24));
        r.src_ip_alias = Some("corp-nets".to_string());

        let resolved = resolve_rule_aliases(vec![r], &svc);
        assert_eq!(resolved.rules[0].src_ip, Some(v4(0xC0A8_0100, 24)));
    }

    #[test]
    fn resolving_twice_changes_nothing() {
        let svc = alias_service(vec![ip_alias("corp-nets", vec![v4(0x0A00_0000, 8)])]);
        let mut r = rule("l7-001");
        r.src_ip_alias = Some("corp-nets".to_string());

        let once = resolve_rule_aliases(vec![r], &svc);
        let twice = resolve_rule_aliases(once.rules.clone(), &svc);
        assert_eq!(twice.rules[0].src_ip, once.rules[0].src_ip);
        assert!(twice.failures.is_empty());
    }
}
