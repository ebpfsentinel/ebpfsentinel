//! Resolve the IPS whitelist entries that are named by an alias.
//!
//! `ips.whitelist` holds literal addresses, which the configuration layer can
//! parse on its own. `ips.whitelist_aliases` names alias objects instead, and
//! those are only known once the alias service has loaded them, so the two
//! halves of the whitelist are assembled here rather than in the config layer.

use std::sync::Arc;

use arc_swap::ArcSwap;
use domain::firewall::entity::IpNetwork;
use domain::ips::entity::WhitelistEntry;

use crate::alias_service_impl::AliasAppService;
use crate::ips_service_impl::IpsAppService;

/// What resolving the alias-named half of the whitelist produced.
#[derive(Debug, Clone, Default)]
pub struct AliasWhitelist {
    /// Entries to add to the whitelist.
    pub entries: Vec<WhitelistEntry>,
    /// Aliases that could not be resolved, with the reason.
    ///
    /// Reported rather than fatal: an unknown alias is a configuration
    /// mistake, and refusing to start over it would leave every other
    /// whitelisted source unprotected too.
    pub failures: Vec<(String, String)>,
}

/// Resolve every alias named by `names` into whitelist entries.
///
/// An alias resolving to no network contributes nothing and is not a failure:
/// a dynamic alias legitimately starts empty and fills in later.
#[must_use]
pub fn resolve_whitelist_aliases(names: &[String], aliases: &AliasAppService) -> AliasWhitelist {
    let mut result = AliasWhitelist::default();
    for name in names {
        match aliases.resolve_ips(name) {
            Ok(networks) => {
                for network in networks {
                    match whitelist_entry(&network) {
                        Ok(entry) => result.entries.push(entry),
                        Err(e) => result.failures.push((name.clone(), e)),
                    }
                }
            }
            Err(e) => result.failures.push((name.clone(), e.to_string())),
        }
    }
    result
}

/// Merge the literal and alias-named halves of the whitelist into a service.
///
/// Startup builds the IPS service before the alias service exists, so the
/// literal half is installed first and this runs once aliases have loaded.
/// Failures are logged and skipped: an alias that names nothing must not take
/// the whitelisted sources that do resolve down with it.
pub fn apply_whitelist_aliases(
    ips: &ArcSwap<IpsAppService>,
    literal: Vec<WhitelistEntry>,
    names: &[String],
    aliases: &AliasAppService,
) {
    if names.is_empty() {
        return;
    }
    let resolved = resolve_whitelist_aliases(names, aliases);
    for (name, reason) in &resolved.failures {
        tracing::warn!(
            component = "ips",
            alias = %name,
            error = %reason,
            "IPS whitelist alias could not be resolved"
        );
    }
    if resolved.entries.is_empty() {
        return;
    }
    let alias_count = resolved.entries.len();
    let mut whitelist = literal;
    whitelist.extend(resolved.entries);
    let total = whitelist.len();
    let mut svc = (**ips.load()).clone();
    svc.reload_whitelist(whitelist);
    ips.store(Arc::new(svc));
    tracing::info!(
        component = "ips",
        alias_count,
        total,
        "IPS whitelist extended with alias-resolved entries"
    );
}

/// Convert one alias network into a whitelist entry.
fn whitelist_entry(network: &IpNetwork) -> Result<WhitelistEntry, String> {
    let (ip, prefix_len) = match *network {
        IpNetwork::V4 { addr, prefix_len } => {
            (std::net::IpAddr::V4(addr.into()), u32::from(prefix_len))
        }
        IpNetwork::V6 { addr, prefix_len } => {
            (std::net::IpAddr::V6(addr.into()), u32::from(prefix_len))
        }
    };
    // A host route carries no prefix so the entry matches the address alone,
    // which is how a literal `whitelist` entry without a `/` is parsed.
    let cidr = match (ip, prefix_len) {
        (std::net::IpAddr::V4(_), 32) | (std::net::IpAddr::V6(_), 128) => None,
        _ => Some(
            u8::try_from(prefix_len).map_err(|_| format!("prefix {prefix_len} out of range"))?,
        ),
    };
    WhitelistEntry::new(ip, cidr).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use domain::alias::entity::{Alias, AliasId, AliasKind};
    use ports::test_utils::NoopMetrics;

    use super::*;

    fn service(aliases: Vec<Alias>) -> AliasAppService {
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

    #[test]
    fn a_network_alias_becomes_a_cidr_whitelist_entry() {
        let svc = service(vec![ip_alias(
            "mgmt",
            vec![IpNetwork::V4 {
                addr: 0x0A00_0000,
                prefix_len: 8,
            }],
        )]);

        let resolved = resolve_whitelist_aliases(&["mgmt".to_string()], &svc);

        assert!(resolved.failures.is_empty());
        assert_eq!(resolved.entries.len(), 1);
        assert!(resolved.entries[0].matches("10.1.2.3".parse().unwrap()));
        assert!(!resolved.entries[0].matches("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn a_host_alias_matches_only_that_address() {
        let svc = service(vec![ip_alias(
            "jump",
            vec![IpNetwork::V4 {
                addr: 0xC0A8_010A,
                prefix_len: 32,
            }],
        )]);

        let resolved = resolve_whitelist_aliases(&["jump".to_string()], &svc);

        assert_eq!(resolved.entries.len(), 1);
        assert!(resolved.entries[0].matches("192.168.1.10".parse().unwrap()));
        assert!(!resolved.entries[0].matches("192.168.1.11".parse().unwrap()));
    }

    #[test]
    fn an_ipv6_host_alias_matches_only_that_address() {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[15] = 0x01;
        let svc = service(vec![ip_alias(
            "v6",
            vec![IpNetwork::V6 {
                addr,
                prefix_len: 128,
            }],
        )]);

        let resolved = resolve_whitelist_aliases(&["v6".to_string()], &svc);

        assert_eq!(resolved.entries.len(), 1);
        assert!(resolved.entries[0].matches("2001::1".parse().unwrap()));
        assert!(!resolved.entries[0].matches("2001::2".parse().unwrap()));
    }

    #[test]
    fn an_unknown_alias_is_reported_and_the_others_still_resolve() {
        let svc = service(vec![ip_alias(
            "mgmt",
            vec![IpNetwork::V4 {
                addr: 0x0A00_0000,
                prefix_len: 8,
            }],
        )]);

        let resolved = resolve_whitelist_aliases(&["mgmt".to_string(), "typo".to_string()], &svc);

        assert_eq!(resolved.entries.len(), 1);
        assert_eq!(resolved.failures.len(), 1);
        assert_eq!(resolved.failures[0].0, "typo");
    }
}
