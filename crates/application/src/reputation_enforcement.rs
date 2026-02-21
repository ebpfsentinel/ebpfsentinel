use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use domain::dns::entity::ReputationConfig;
use ports::secondary::dns_cache_port::DnsCachePort;
use ports::secondary::ips_blacklist_port::IpsBlacklistPort;
use ports::secondary::metrics_port::MetricsPort;

/// Reputation enforcement service: auto-blocks domains via the IPS
/// blacklist when their reputation score exceeds a threshold.
///
/// Tracks which domains are currently blocked so that it can remove
/// IPS entries when the score decays below the threshold.
pub struct ReputationEnforcementService {
    dns_cache: Arc<dyn DnsCachePort>,
    ips_port: Arc<dyn IpsBlacklistPort>,
    metrics: Arc<dyn MetricsPort>,
    /// Domains currently auto-blocked by reputation.
    blocked_domains: Mutex<HashSet<String>>,
    threshold: f64,
    ttl: Duration,
}

impl ReputationEnforcementService {
    pub fn new(
        config: &ReputationConfig,
        dns_cache: Arc<dyn DnsCachePort>,
        ips_port: Arc<dyn IpsBlacklistPort>,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        Self {
            dns_cache,
            ips_port,
            metrics,
            blocked_domains: Mutex::new(HashSet::new()),
            threshold: config.auto_block_threshold,
            ttl: Duration::from_secs(config.auto_block_ttl_secs),
        }
    }

    /// Called after a domain's reputation score changes.
    ///
    /// If the score is at or above the threshold, resolve the domain's IPs
    /// from DNS cache and inject them into the IPS blacklist. If the score
    /// drops below the threshold, remove previously blocked IPs.
    pub fn on_reputation_change(&self, domain: &str, score: f64) {
        let domain_lower = domain.to_lowercase();

        if score >= self.threshold {
            self.block_domain(&domain_lower);
        } else {
            self.unblock_domain(&domain_lower);
        }
    }

    /// Number of domains currently auto-blocked.
    pub fn blocked_count(&self) -> usize {
        self.blocked_domains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    fn block_domain(&self, domain: &str) {
        let entry = self.dns_cache.lookup_domain(domain);
        let ips = entry.map(|e| e.ips).unwrap_or_default();

        if ips.is_empty() {
            tracing::debug!(
                domain,
                "reputation auto-block: no resolved IPs in DNS cache, skipping"
            );
            return;
        }

        let reason = format!("reputation: {domain}");
        let mut injected = false;

        for ip in &ips {
            if let Err(e) = self
                .ips_port
                .add_to_blacklist(*ip, reason.clone(), self.ttl)
            {
                tracing::warn!(
                    ip = %ip,
                    domain,
                    "failed to inject reputation-blocked IP into IPS blacklist: {e}"
                );
            } else {
                injected = true;
            }
        }

        if injected {
            let mut blocked = self
                .blocked_domains
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if blocked.insert(domain.to_string()) {
                self.metrics.record_reputation_auto_block(domain);
                tracing::info!(
                    domain,
                    ip_count = ips.len(),
                    "reputation auto-block: injected IPs into IPS blacklist"
                );
            }
        }
    }

    fn unblock_domain(&self, domain: &str) {
        let mut blocked = self
            .blocked_domains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if !blocked.remove(domain) {
            return; // wasn't blocked
        }
        drop(blocked);

        let entry = self.dns_cache.lookup_domain(domain);
        let ips = entry.map(|e| e.ips).unwrap_or_default();

        for ip in &ips {
            if let Err(e) = self.ips_port.remove_from_blacklist(ip) {
                tracing::warn!(
                    ip = %ip,
                    domain,
                    "failed to remove reputation-unblocked IP from IPS blacklist: {e}"
                );
            }
        }

        tracing::info!(
            domain,
            ip_count = ips.len(),
            "reputation auto-unblock: removed IPs from IPS blacklist"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::error::DomainError;
    use domain::dns::entity::DnsCacheEntry;
    use std::net::IpAddr;

    struct MockDnsCache {
        entries: Mutex<std::collections::HashMap<String, DnsCacheEntry>>,
    }

    impl MockDnsCache {
        fn new() -> Self {
            Self {
                entries: Mutex::new(std::collections::HashMap::new()),
            }
        }

        fn insert_domain(&self, domain: &str, ips: Vec<IpAddr>) {
            self.entries.lock().unwrap().insert(
                domain.to_lowercase(),
                DnsCacheEntry {
                    ips,
                    ttl_secs: 300,
                    inserted_at_ns: 0,
                    last_queried_ns: 0,
                    query_count: 0,
                },
            );
        }
    }

    impl DnsCachePort for MockDnsCache {
        fn lookup_domain(&self, domain: &str) -> Option<DnsCacheEntry> {
            self.entries
                .lock()
                .unwrap()
                .get(&domain.to_lowercase())
                .cloned()
        }

        fn lookup_ip(&self, _ip: &IpAddr) -> Vec<String> {
            Vec::new()
        }

        fn lookup_all(&self, _page: usize, _page_size: usize) -> Vec<(String, DnsCacheEntry)> {
            Vec::new()
        }

        fn insert(&self, _domain: String, _ips: Vec<IpAddr>, _ttl_secs: u64, _timestamp_ns: u64) {}

        fn stats(&self) -> domain::dns::entity::DnsCacheStats {
            domain::dns::entity::DnsCacheStats::default()
        }

        fn flush(&self) {}
    }

    struct MockIpsBlacklist {
        added: Mutex<Vec<(IpAddr, String)>>,
        removed: Mutex<Vec<IpAddr>>,
    }

    impl MockIpsBlacklist {
        fn new() -> Self {
            Self {
                added: Mutex::new(Vec::new()),
                removed: Mutex::new(Vec::new()),
            }
        }
    }

    impl IpsBlacklistPort for MockIpsBlacklist {
        fn add_to_blacklist(
            &self,
            ip: IpAddr,
            reason: String,
            _ttl: Duration,
        ) -> Result<(), DomainError> {
            self.added.lock().unwrap().push((ip, reason));
            Ok(())
        }

        fn remove_from_blacklist(&self, ip: &IpAddr) -> Result<(), DomainError> {
            self.removed.lock().unwrap().push(*ip);
            Ok(())
        }
    }

    fn test_config() -> ReputationConfig {
        ReputationConfig {
            auto_block_enabled: true,
            auto_block_threshold: 0.8,
            auto_block_ttl_secs: 3600,
            ..ReputationConfig::default()
        }
    }

    fn make_service(
        dns: Arc<MockDnsCache>,
        ips: Arc<MockIpsBlacklist>,
    ) -> ReputationEnforcementService {
        let config = test_config();
        ReputationEnforcementService::new(
            &config,
            dns as Arc<dyn DnsCachePort>,
            ips as Arc<dyn IpsBlacklistPort>,
            Arc::new(ports::test_utils::NoopMetrics) as Arc<dyn MetricsPort>,
        )
    }

    #[test]
    fn score_above_threshold_triggers_block() {
        let dns = Arc::new(MockDnsCache::new());
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        dns.insert_domain("evil.com", vec![ip1, ip2]);

        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = make_service(Arc::clone(&dns), Arc::clone(&ips));

        svc.on_reputation_change("evil.com", 0.9);

        let added = ips.added.lock().unwrap();
        assert_eq!(added.len(), 2);
        assert!(added.iter().any(|(ip, _)| *ip == ip1));
        assert!(added.iter().any(|(ip, _)| *ip == ip2));
        assert!(added[0].1.contains("evil.com"));
        assert_eq!(svc.blocked_count(), 1);
    }

    #[test]
    fn score_below_threshold_removes_block() {
        let dns = Arc::new(MockDnsCache::new());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        dns.insert_domain("evil.com", vec![ip]);

        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = make_service(Arc::clone(&dns), Arc::clone(&ips));

        // First block
        svc.on_reputation_change("evil.com", 0.9);
        assert_eq!(svc.blocked_count(), 1);

        // Then unblock
        svc.on_reputation_change("evil.com", 0.5);
        assert_eq!(svc.blocked_count(), 0);

        let removed = ips.removed.lock().unwrap();
        assert!(removed.contains(&ip));
    }

    #[test]
    fn domain_not_in_cache_skips_without_error() {
        let dns = Arc::new(MockDnsCache::new());
        // No IPs cached for evil.com
        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = make_service(Arc::clone(&dns), Arc::clone(&ips));

        svc.on_reputation_change("evil.com", 0.9);

        assert!(ips.added.lock().unwrap().is_empty());
        assert_eq!(svc.blocked_count(), 0);
    }

    #[test]
    fn duplicate_block_does_not_double_count() {
        let dns = Arc::new(MockDnsCache::new());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        dns.insert_domain("evil.com", vec![ip]);

        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = make_service(Arc::clone(&dns), Arc::clone(&ips));

        svc.on_reputation_change("evil.com", 0.9);
        svc.on_reputation_change("evil.com", 0.95);

        assert_eq!(svc.blocked_count(), 1);
    }

    #[test]
    fn unblock_without_prior_block_is_noop() {
        let dns = Arc::new(MockDnsCache::new());
        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = make_service(Arc::clone(&dns), Arc::clone(&ips));

        svc.on_reputation_change("good.com", 0.2);

        assert!(ips.removed.lock().unwrap().is_empty());
        assert_eq!(svc.blocked_count(), 0);
    }

    #[test]
    fn exact_threshold_triggers_block() {
        let dns = Arc::new(MockDnsCache::new());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        dns.insert_domain("edge.com", vec![ip]);

        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = make_service(Arc::clone(&dns), Arc::clone(&ips));

        svc.on_reputation_change("edge.com", 0.8); // exactly at threshold

        assert_eq!(ips.added.lock().unwrap().len(), 1);
        assert_eq!(svc.blocked_count(), 1);
    }
}
