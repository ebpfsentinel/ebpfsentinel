use std::net::IpAddr;
use std::sync::Arc;

use domain::alert::entity::Alert;
use ports::secondary::alert_enrichment_port::AlertEnrichmentPort;
use ports::secondary::dns_cache_port::DnsCachePort;
use ports::secondary::domain_reputation_port::DomainReputationPort;

/// Alert enricher that adds DNS reverse-lookup data and reputation scores.
pub struct DnsAlertEnricher {
    dns_cache: Arc<dyn DnsCachePort>,
    reputation: Option<Arc<dyn DomainReputationPort>>,
}

impl DnsAlertEnricher {
    pub fn new(
        dns_cache: Arc<dyn DnsCachePort>,
        reputation: Option<Arc<dyn DomainReputationPort>>,
    ) -> Self {
        Self {
            dns_cache,
            reputation,
        }
    }
}

impl AlertEnrichmentPort for DnsAlertEnricher {
    fn enrich_alert(&self, alert: &mut Alert) {
        // Source IP → domain
        let src_ip = addr_to_ip(alert.src_addr, alert.is_ipv6);
        if let Some(ip) = src_ip {
            let domains = self.dns_cache.lookup_ip(&ip);
            if let Some(domain) = pick_most_recent(&domains, &*self.dns_cache) {
                if let Some(ref rep_port) = self.reputation {
                    alert.src_domain_score = rep_port.get_score(&domain);
                }
                alert.src_domain = Some(domain);
            }
        }

        // Destination IP → domain
        let dst_ip = addr_to_ip(alert.dst_addr, alert.is_ipv6);
        if let Some(ip) = dst_ip {
            let domains = self.dns_cache.lookup_ip(&ip);
            if let Some(domain) = pick_most_recent(&domains, &*self.dns_cache) {
                if let Some(ref rep_port) = self.reputation {
                    alert.dst_domain_score = rep_port.get_score(&domain);
                }
                alert.dst_domain = Some(domain);
            }
        }
    }
}

/// Convert a `[u32; 4]` address to `IpAddr`.
fn addr_to_ip(addr: [u32; 4], is_ipv6: bool) -> Option<IpAddr> {
    if is_ipv6 {
        let mut bytes = [0u8; 16];
        for (i, word) in addr.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        Some(IpAddr::V6(bytes.into()))
    } else {
        let v4 = addr[0];
        if v4 == 0 {
            return None;
        }
        // addr[0] stores IPv4 in host byte order (MSB = first octet),
        // matching Ipv4Addr::from(u32) convention.
        Some(IpAddr::V4(std::net::Ipv4Addr::from(v4)))
    }
}

/// Pick the most recently queried domain from a list.
fn pick_most_recent(domains: &[String], cache: &dyn DnsCachePort) -> Option<String> {
    if domains.is_empty() {
        return None;
    }
    if domains.len() == 1 {
        return Some(domains[0].clone());
    }
    // Pick the one with the highest last_queried_ns
    domains
        .iter()
        .filter_map(|d| {
            let entry = cache.lookup_domain(d)?;
            Some((d.clone(), entry.last_queried_ns))
        })
        .max_by_key(|(_, ts)| *ts)
        .map(|(d, _)| d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, RuleId, Severity};
    use domain::dns::entity::{
        DnsCacheEntry, DnsCacheStats, DomainReputation, ReputationFactor, ReputationStats,
    };

    struct MockDnsCache {
        entries: Vec<(String, Vec<IpAddr>, DnsCacheEntry)>,
    }

    impl DnsCachePort for MockDnsCache {
        fn lookup_domain(&self, domain: &str) -> Option<DnsCacheEntry> {
            self.entries
                .iter()
                .find(|(d, _, _)| d == domain)
                .map(|(_, _, e)| e.clone())
        }

        fn lookup_ip(&self, ip: &IpAddr) -> Vec<String> {
            self.entries
                .iter()
                .filter(|(_, ips, _)| ips.contains(ip))
                .map(|(d, _, _)| d.clone())
                .collect()
        }

        fn lookup_all(&self, _page: usize, _page_size: usize) -> Vec<(String, DnsCacheEntry)> {
            vec![]
        }

        fn insert(&self, _domain: String, _ips: Vec<IpAddr>, _ttl_secs: u64, _timestamp_ns: u64) {}

        fn stats(&self) -> DnsCacheStats {
            DnsCacheStats::default()
        }

        fn flush(&self) {}
    }

    struct MockReputation;

    impl DomainReputationPort for MockReputation {
        fn get_reputation(&self, _domain: &str) -> Option<DomainReputation> {
            None
        }

        fn get_score(&self, domain: &str) -> Option<f64> {
            if domain == "evil.com" {
                Some(0.9)
            } else {
                None
            }
        }

        fn update_reputation(&self, _domain: &str, _factor: ReputationFactor) {}

        fn list_high_risk(&self, _min_score: f64) -> Vec<(DomainReputation, f64)> {
            vec![]
        }

        fn list_all(&self, _page: usize, _page_size: usize) -> Vec<(DomainReputation, f64)> {
            vec![]
        }

        fn stats(&self) -> ReputationStats {
            ReputationStats::default()
        }
    }

    fn make_alert(src_ip: u32, dst_ip: u32) -> Alert {
        Alert {
            id: "test-1".to_string(),
            timestamp_ns: 1_000_000_000,
            component: "ids".to_string(),
            severity: Severity::High,
            rule_id: RuleId("ids-001".to_string()),
            action: DomainMode::Alert,
            src_addr: [src_ip, 0, 0, 0],
            dst_addr: [dst_ip, 0, 0, 0],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            is_ipv6: false,
            message: "test".to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
        }
    }

    #[test]
    fn enrich_with_cache_hit() {
        let ip = "10.0.0.1".parse::<IpAddr>().unwrap();
        let cache = MockDnsCache {
            entries: vec![(
                "evil.com".to_string(),
                vec![ip],
                DnsCacheEntry {
                    ips: vec![ip],
                    ttl_secs: 300,
                    inserted_at_ns: 0,
                    last_queried_ns: 100,
                    query_count: 5,
                },
            )],
        };
        let enricher = DnsAlertEnricher::new(Arc::new(cache), Some(Arc::new(MockReputation)));

        // 10.0.0.1 in big-endian = 0x0A000001
        let mut alert = make_alert(0, 0x0A00_0001);
        enricher.enrich_alert(&mut alert);

        assert_eq!(alert.dst_domain.as_deref(), Some("evil.com"));
        assert!((alert.dst_domain_score.unwrap() - 0.9).abs() < 0.01);
        assert!(alert.src_domain.is_none());
    }

    #[test]
    fn enrich_with_cache_miss() {
        let cache = MockDnsCache { entries: vec![] };
        let enricher = DnsAlertEnricher::new(Arc::new(cache), None);

        let mut alert = make_alert(0xC0A8_0001, 0x0A00_0001);
        enricher.enrich_alert(&mut alert);

        assert!(alert.src_domain.is_none());
        assert!(alert.dst_domain.is_none());
    }

    #[test]
    fn enrich_picks_most_recent_domain() {
        let ip = "10.0.0.1".parse::<IpAddr>().unwrap();
        let cache = MockDnsCache {
            entries: vec![
                (
                    "old.com".to_string(),
                    vec![ip],
                    DnsCacheEntry {
                        ips: vec![ip],
                        ttl_secs: 300,
                        inserted_at_ns: 0,
                        last_queried_ns: 100,
                        query_count: 1,
                    },
                ),
                (
                    "new.com".to_string(),
                    vec![ip],
                    DnsCacheEntry {
                        ips: vec![ip],
                        ttl_secs: 300,
                        inserted_at_ns: 0,
                        last_queried_ns: 500,
                        query_count: 1,
                    },
                ),
            ],
        };
        let enricher = DnsAlertEnricher::new(Arc::new(cache), None);

        let mut alert = make_alert(0, 0x0A00_0001);
        enricher.enrich_alert(&mut alert);

        assert_eq!(alert.dst_domain.as_deref(), Some("new.com"));
    }

    #[test]
    fn enrich_without_reputation() {
        let ip = "10.0.0.1".parse::<IpAddr>().unwrap();
        let cache = MockDnsCache {
            entries: vec![(
                "example.com".to_string(),
                vec![ip],
                DnsCacheEntry {
                    ips: vec![ip],
                    ttl_secs: 300,
                    inserted_at_ns: 0,
                    last_queried_ns: 100,
                    query_count: 1,
                },
            )],
        };
        let enricher = DnsAlertEnricher::new(Arc::new(cache), None);

        let mut alert = make_alert(0, 0x0A00_0001);
        enricher.enrich_alert(&mut alert);

        assert_eq!(alert.dst_domain.as_deref(), Some("example.com"));
        assert!(alert.dst_domain_score.is_none());
    }
}
