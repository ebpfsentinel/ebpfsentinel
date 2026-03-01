use std::collections::HashMap;
use std::sync::Arc;

use domain::alias::entity::Alias;
use domain::alias::resolver::AliasResolver;
use domain::common::error::DomainError;
use domain::firewall::entity::{IpNetwork, PortRange};
use ebpf_common::firewall::{ACTION_DROP, FirewallLpmEntryV4, FirewallLpmEntryV6};
use ports::secondary::alias_resolution_port::AliasResolutionPort;
use ports::secondary::geoip_lpm_port::GeoIpLpmPort;
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::nat_map_port::IpSetMapPort;

/// Application-level alias service.
///
/// Orchestrates alias resolution across static, nested, URL table,
/// `GeoIP`, and dynamic DNS sources. Manages IP set map synchronisation
/// for large alias sets that need kernel-side O(1) lookup, and LPM Trie
/// maps for `GeoIP` CIDR-based blocking.
pub struct AliasAppService {
    resolver: AliasResolver,
    resolution_port: Option<Arc<dyn AliasResolutionPort>>,
    ipset_port: Option<Box<dyn IpSetMapPort + Send>>,
    geoip_lpm_port: Option<Box<dyn GeoIpLpmPort>>,
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
            geoip_lpm_port: None,
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

    /// Set the eBPF LPM Trie map port for `GeoIP` CIDR blocking.
    pub fn set_geoip_lpm_port(&mut self, port: Box<dyn GeoIpLpmPort>) {
        self.geoip_lpm_port = Some(port);
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
        use domain::alias::entity::AliasKind;

        let Some(resolution_port) = self.resolution_port.clone() else {
            return Ok(0);
        };

        let mut refreshed = 0;
        let aliases = self.resolver.aliases().clone();

        // Accumulate all GeoIP CIDRs across aliases for a single bulk load
        let mut all_geoip_v4_src: Vec<FirewallLpmEntryV4> = Vec::new();
        let mut all_geoip_v6_src: Vec<FirewallLpmEntryV6> = Vec::new();

        for (name, alias) in &aliases {
            let ips = Self::resolve_dynamic_alias(alias, resolution_port.as_ref());
            if ips.is_empty() {
                continue;
            }

            let is_geoip = matches!(&alias.kind, AliasKind::GeoIp { .. });

            if is_geoip {
                // GeoIP CIDRs → LPM Trie maps (block inbound from country)
                let (v4_entries, v6_entries) = convert_to_lpm_entries(&ips, ACTION_DROP);
                all_geoip_v4_src.extend(v4_entries);
                all_geoip_v6_src.extend(v6_entries);
            } else {
                // Other dynamic aliases → IP set maps
                let set_id = self.get_or_assign_set_id(name);

                if let Some(ref mut ipset_port) = self.ipset_port {
                    let addrs: Vec<u32> = ips
                        .iter()
                        .filter_map(|ip| match ip {
                            IpNetwork::V4 { addr, .. } => Some(*addr),
                            IpNetwork::V6 { .. } => None,
                        })
                        .collect();

                    if let Err(e) = ipset_port.load_ipset_v4(set_id, &addrs) {
                        tracing::warn!(alias = name, "failed to load IP set: {e}");
                    }
                }
            }

            refreshed += 1;
        }

        // Bulk-load accumulated GeoIP CIDRs into LPM maps
        if !all_geoip_v4_src.is_empty() || !all_geoip_v6_src.is_empty() {
            if let Some(ref mut lpm_port) = self.geoip_lpm_port {
                // Load as source rules (blocking inbound traffic from these countries)
                if let Err(e) = lpm_port.load_lpm_v4_rules(&all_geoip_v4_src, &[]) {
                    tracing::warn!("failed to load GeoIP LPM V4 rules: {e}");
                }
                if let Err(e) = lpm_port.load_lpm_v6_rules(&all_geoip_v6_src, &[]) {
                    tracing::warn!("failed to load GeoIP LPM V6 rules: {e}");
                }
                tracing::info!(
                    v4 = all_geoip_v4_src.len(),
                    v6 = all_geoip_v6_src.len(),
                    "GeoIP CIDRs loaded into LPM Trie maps"
                );
            } else {
                tracing::warn!("GeoIP CIDRs resolved but no LPM port configured; rules not loaded");
            }
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

/// Convert domain `IpNetwork` CIDRs to eBPF LPM Trie entry types.
///
/// IPv4 addresses are converted from host byte order (`u32`) to network
/// byte order (`[u8; 4]`) as required by the LPM Trie key format.
fn convert_to_lpm_entries(
    ips: &[IpNetwork],
    action: u8,
) -> (Vec<FirewallLpmEntryV4>, Vec<FirewallLpmEntryV6>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        match ip {
            IpNetwork::V4 { addr, prefix_len } => {
                v4.push(FirewallLpmEntryV4 {
                    prefix_len: u32::from(*prefix_len),
                    addr: addr.to_be_bytes(),
                    action,
                });
            }
            IpNetwork::V6 { addr, prefix_len } => {
                v6.push(FirewallLpmEntryV6 {
                    prefix_len: u32::from(*prefix_len),
                    addr: *addr,
                    action,
                });
            }
        }
    }
    (v4, v6)
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

    #[test]
    fn convert_to_lpm_entries_v4() {
        let ips = vec![IpNetwork::V4 {
            addr: 0xC0A80100, // 192.168.1.0 in host byte order
            prefix_len: 24,
        }];
        let (v4, v6) = convert_to_lpm_entries(&ips, ACTION_DROP);
        assert_eq!(v4.len(), 1);
        assert!(v6.is_empty());
        assert_eq!(v4[0].prefix_len, 24);
        assert_eq!(v4[0].addr, [0xC0, 0xA8, 0x01, 0x00]); // network byte order
        assert_eq!(v4[0].action, ACTION_DROP);
    }

    #[test]
    fn convert_to_lpm_entries_v6() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ips = vec![IpNetwork::V6 {
            addr,
            prefix_len: 32,
        }];
        let (v4, v6) = convert_to_lpm_entries(&ips, ACTION_DROP);
        assert!(v4.is_empty());
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].prefix_len, 32);
        assert_eq!(v6[0].addr, addr);
        assert_eq!(v6[0].action, ACTION_DROP);
    }

    #[test]
    fn convert_to_lpm_entries_mixed() {
        let ips = vec![
            IpNetwork::V4 {
                addr: 0x0A000000,
                prefix_len: 8,
            },
            IpNetwork::V6 {
                addr: [0xFF; 16],
                prefix_len: 128,
            },
            IpNetwork::V4 {
                addr: 0xAC100000,
                prefix_len: 12,
            },
        ];
        let (v4, v6) = convert_to_lpm_entries(&ips, ACTION_DROP);
        assert_eq!(v4.len(), 2);
        assert_eq!(v6.len(), 1);
    }

    /// Mock `GeoIpLpmPort` that records calls.
    struct MockGeoIpLpmPort {
        v4_src_count: usize,
        v6_src_count: usize,
    }

    impl MockGeoIpLpmPort {
        fn new() -> Self {
            Self {
                v4_src_count: 0,
                v6_src_count: 0,
            }
        }
    }

    impl GeoIpLpmPort for MockGeoIpLpmPort {
        fn load_lpm_v4_rules(
            &mut self,
            src_rules: &[FirewallLpmEntryV4],
            _dst_rules: &[FirewallLpmEntryV4],
        ) -> Result<(), DomainError> {
            self.v4_src_count = src_rules.len();
            Ok(())
        }

        fn load_lpm_v6_rules(
            &mut self,
            src_rules: &[FirewallLpmEntryV6],
            _dst_rules: &[FirewallLpmEntryV6],
        ) -> Result<(), DomainError> {
            self.v6_src_count = src_rules.len();
            Ok(())
        }
    }

    /// Mock resolution port that returns fixed IPs for GeoIP lookups.
    struct MockResolutionPort;

    impl ports::secondary::alias_resolution_port::AliasResolutionPort for MockResolutionPort {
        fn fetch_url_table(&self, _url: &str) -> Result<Vec<IpNetwork>, DomainError> {
            Ok(Vec::new())
        }
        fn resolve_dns(&self, _hostname: &str) -> Result<Vec<IpNetwork>, DomainError> {
            Ok(Vec::new())
        }
        fn lookup_geoip(&self, _codes: &[String]) -> Result<Vec<IpNetwork>, DomainError> {
            Ok(vec![
                IpNetwork::V4 {
                    addr: 0x01020300,
                    prefix_len: 24,
                },
                IpNetwork::V6 {
                    addr: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    prefix_len: 32,
                },
            ])
        }
    }

    #[test]
    fn refresh_dynamic_routes_geoip_to_lpm() {
        let mut svc = make_service();
        svc.set_resolution_port(Arc::new(MockResolutionPort));

        // Load a GeoIP alias
        let geoip_alias = Alias {
            id: AliasId("block-cn".to_string()),
            kind: AliasKind::GeoIp {
                country_codes: vec!["CN".to_string()],
            },
            description: None,
        };
        svc.reload_aliases(vec![geoip_alias]).unwrap();

        // Set up mock LPM port
        let mock_lpm = MockGeoIpLpmPort::new();
        svc.set_geoip_lpm_port(Box::new(mock_lpm));

        // Refresh should route GeoIP CIDRs through LPM port
        let refreshed = svc.refresh_dynamic().unwrap();
        assert_eq!(refreshed, 1);
    }
}
