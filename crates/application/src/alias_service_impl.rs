use std::collections::HashMap;
use std::sync::Arc;

use domain::alias::entity::Alias;
use domain::alias::resolver::AliasResolver;
use domain::common::error::DomainError;
use domain::firewall::entity::{IpNetwork, PortRange};
use ports::secondary::alias_resolution_port::AliasResolutionPort;
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::nat_map_port::IpSetMapPort;

/// Application-level alias service.
///
/// Orchestrates alias resolution across static, nested, URL table,
/// `GeoIP`, and dynamic DNS sources. Manages IP set map synchronisation
/// for large alias sets that need kernel-side O(1) lookup.
pub struct AliasAppService {
    resolver: AliasResolver,
    resolution_port: Option<Arc<dyn AliasResolutionPort>>,
    ipset_port: Option<Box<dyn IpSetMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    /// Maps alias name → `set_id` for eBPF IP set maps.
    set_id_map: HashMap<String, u8>,
    next_set_id: u8,
}

impl AliasAppService {
    pub fn new(metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            resolver: AliasResolver::new(),
            resolution_port: None,
            ipset_port: None,
            metrics,
            set_id_map: HashMap::new(),
            next_set_id: 1,
        }
    }

    /// Set the alias resolution port (HTTP/DNS/`GeoIP` adapter).
    pub fn set_resolution_port(&mut self, port: Arc<dyn AliasResolutionPort>) {
        self.resolution_port = Some(port);
    }

    /// Set the eBPF IP set map port.
    pub fn set_ipset_port(&mut self, port: Box<dyn IpSetMapPort + Send>) {
        self.ipset_port = Some(port);
    }

    /// Reload all aliases from config. Validates and loads into the resolver.
    pub fn reload_aliases(&mut self, aliases: Vec<Alias>) -> Result<(), DomainError> {
        self.resolver
            .load(aliases)
            .map_err(|e| DomainError::InvalidRule(e.to_string()))?;
        self.update_metrics();
        Ok(())
    }

    /// Resolve an alias to IP networks (static resolution only).
    pub fn resolve_ips(&self, alias_name: &str) -> Result<Vec<IpNetwork>, DomainError> {
        self.resolver
            .resolve_ips(alias_name)
            .map_err(|e| DomainError::InvalidRule(e.to_string()))
    }

    /// Resolve an alias to port ranges (static resolution only).
    pub fn resolve_ports(&self, alias_name: &str) -> Result<Vec<PortRange>, DomainError> {
        self.resolver
            .resolve_ports(alias_name)
            .map_err(|e| DomainError::InvalidRule(e.to_string()))
    }

    /// Get or assign a `set_id` for an alias name (for eBPF IP set maps).
    pub fn get_or_assign_set_id(&mut self, alias_name: &str) -> u8 {
        if let Some(&id) = self.set_id_map.get(alias_name) {
            return id;
        }
        let id = self.next_set_id;
        self.set_id_map.insert(alias_name.to_string(), id);
        self.next_set_id = self.next_set_id.wrapping_add(1);
        id
    }

    /// Refresh dynamic aliases (URL tables, DNS, `GeoIP`) using the resolution port.
    /// Returns the number of aliases refreshed.
    pub fn refresh_dynamic(&mut self) -> Result<usize, DomainError> {
        let Some(resolution_port) = self.resolution_port.clone() else {
            return Ok(0);
        };

        let mut refreshed = 0;
        let aliases = self.resolver.aliases().clone();

        for (name, alias) in &aliases {
            let ips = Self::resolve_dynamic_alias(alias, resolution_port.as_ref());
            if ips.is_empty() {
                continue;
            }

            // Get set_id before borrowing ipset_port to avoid double mutable borrow
            let set_id = self.get_or_assign_set_id(name);

            // If we have an IP set port, load into eBPF
            if let Some(ref mut ipset_port) = self.ipset_port {
                let addrs: Vec<u32> = ips
                    .iter()
                    .filter_map(|ip| match ip {
                        IpNetwork::V4 { addr, .. } => Some(*addr),
                        IpNetwork::V6 { .. } => None, // V6 handled separately
                    })
                    .collect();

                if let Err(e) = ipset_port.load_ipset_v4(set_id, &addrs) {
                    tracing::warn!(alias = name, "failed to load IP set: {e}");
                }
            }

            refreshed += 1;
        }

        self.update_metrics();
        Ok(refreshed)
    }

    /// Return the number of loaded aliases.
    pub fn alias_count(&self) -> usize {
        self.resolver.aliases().len()
    }

    /// Resolve a single dynamic alias using the resolution port.
    fn resolve_dynamic_alias(alias: &Alias, port: &dyn AliasResolutionPort) -> Vec<IpNetwork> {
        use domain::alias::entity::AliasKind;

        match &alias.kind {
            AliasKind::UrlTable { url, .. } => match port.fetch_url_table(url) {
                Ok(ips) => ips,
                Err(e) => {
                    tracing::warn!(alias = %alias.id, "URL table fetch failed: {e}");
                    Vec::new()
                }
            },
            AliasKind::DynamicDns { hostnames, .. } => {
                let mut result = Vec::new();
                for hostname in hostnames {
                    match port.resolve_dns(hostname) {
                        Ok(ips) => result.extend(ips),
                        Err(e) => {
                            tracing::warn!(
                                alias = %alias.id, hostname, "DNS resolution failed: {e}"
                            );
                        }
                    }
                }
                result
            }
            AliasKind::GeoIp { country_codes } => match port.lookup_geoip(country_codes) {
                Ok(ips) => ips,
                Err(e) => {
                    tracing::warn!(alias = %alias.id, "GeoIP lookup failed: {e}");
                    Vec::new()
                }
            },
            _ => Vec::new(),
        }
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("aliases", self.resolver.aliases().len() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::alias::entity::{AliasId, AliasKind};
    use ports::test_utils::NoopMetrics;

    fn make_service() -> AliasAppService {
        AliasAppService::new(Arc::new(NoopMetrics))
    }

    fn ip_set_alias(id: &str) -> Alias {
        Alias {
            id: AliasId(id.to_string()),
            kind: AliasKind::IpSet {
                values: vec![IpNetwork::V4 {
                    addr: 0xC0A80000,
                    prefix_len: 16,
                }],
            },
            description: None,
        }
    }

    fn port_set_alias(id: &str) -> Alias {
        Alias {
            id: AliasId(id.to_string()),
            kind: AliasKind::PortSet {
                values: vec![PortRange {
                    start: 80,
                    end: 443,
                }],
            },
            description: None,
        }
    }

    #[test]
    fn reload_and_resolve_ips() {
        let mut svc = make_service();
        svc.reload_aliases(vec![ip_set_alias("test")]).unwrap();
        let ips = svc.resolve_ips("test").unwrap();
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn reload_and_resolve_ports() {
        let mut svc = make_service();
        svc.reload_aliases(vec![port_set_alias("ports")]).unwrap();
        let ports = svc.resolve_ports("ports").unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].start, 80);
        assert_eq!(ports[0].end, 443);
    }

    #[test]
    fn resolve_nonexistent_fails() {
        let svc = make_service();
        assert!(svc.resolve_ips("nonexistent").is_err());
    }

    #[test]
    fn alias_count() {
        let mut svc = make_service();
        assert_eq!(svc.alias_count(), 0);
        svc.reload_aliases(vec![ip_set_alias("a"), port_set_alias("b")])
            .unwrap();
        assert_eq!(svc.alias_count(), 2);
    }

    #[test]
    fn set_id_assignment() {
        let mut svc = make_service();
        let id1 = svc.get_or_assign_set_id("alias-a");
        let id2 = svc.get_or_assign_set_id("alias-b");
        let id1_again = svc.get_or_assign_set_id("alias-a");
        assert_ne!(id1, id2);
        assert_eq!(id1, id1_again);
    }

    #[test]
    fn refresh_without_port_returns_zero() {
        let mut svc = make_service();
        assert_eq!(svc.refresh_dynamic().unwrap(), 0);
    }
}
