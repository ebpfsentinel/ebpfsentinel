use std::sync::{Arc, RwLock};
use std::time::Duration;

use domain::dns::blocklist::DomainBlocklistEngine;
use domain::dns::entity::{
    BlocklistAction, DomainBlocklistConfig, DomainBlocklistStats, InjectTarget,
};
use ports::secondary::ebpf_map_write_port::{EbpfMapWritePort, IocMetadata};
use ports::secondary::ips_blacklist_port::IpsBlacklistPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level DNS blocklist service.
///
/// Wraps the domain `DomainBlocklistEngine` with thread-safe access,
/// performs eBPF map writes via `EbpfMapWritePort`, and updates metrics.
pub struct DnsBlocklistAppService {
    engine: RwLock<DomainBlocklistEngine>,
    map_writer: RwLock<Option<Arc<dyn EbpfMapWritePort>>>,
    ips_port: Option<Arc<dyn IpsBlacklistPort>>,
    metrics: Arc<dyn MetricsPort>,
    cleanup_interval: Duration,
}

impl DnsBlocklistAppService {
    pub fn new(
        config: DomainBlocklistConfig,
        map_writer: Option<Arc<dyn EbpfMapWritePort>>,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        Self {
            cleanup_interval: Duration::from_secs(config.grace_period_secs.min(60)),
            engine: RwLock::new(DomainBlocklistEngine::new(config)),
            map_writer: RwLock::new(map_writer),
            ips_port: None,
            metrics,
        }
    }

    /// Set the eBPF map writer for runtime IP injection/removal.
    ///
    /// Called after eBPF programs are loaded and shared map handles are available.
    pub fn set_map_writer(&self, writer: Arc<dyn EbpfMapWritePort>) {
        let mut w = self
            .map_writer
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *w = Some(writer);
    }

    /// Set the IPS blacklist port for `inject_target: ips` injection.
    #[must_use]
    pub fn with_ips_port(mut self, port: Arc<dyn IpsBlacklistPort>) -> Self {
        self.ips_port = Some(port);
        self
    }

    /// Check if a domain is blocklisted and, if so, inject resolved IPs
    /// into the appropriate eBPF map.
    pub fn on_dns_response(
        &self,
        domain: &str,
        resolved_ips: &[std::net::IpAddr],
        ttl_secs: u32,
        now_ns: u64,
    ) {
        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let blocklist_match = engine.evaluate(domain);
        let Some(bm) = blocklist_match else {
            return;
        };

        let delta = engine.on_blocked_resolution(domain, resolved_ips, ttl_secs, now_ns);
        let action = bm.action;
        let inject_target = bm.inject_target;
        let injected_count = engine.injected_ip_count();
        drop(engine);

        self.metrics.increment_dns_blocked_domains();

        if inject_target == InjectTarget::Ips {
            // Route to IPS blacklist
            if let Some(ref ips) = self.ips_port {
                let grace = {
                    let eng = self
                        .engine
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    eng.grace_period_secs()
                };
                let ttl = Duration::from_secs(u64::from(ttl_secs) + grace);
                for ip in &delta.to_inject {
                    let reason = format!("dns-blocklist: {domain}");
                    if let Err(e) = ips.add_to_blacklist(*ip, reason, ttl) {
                        tracing::warn!(
                            ip = %ip,
                            domain = domain,
                            "failed to inject blocklisted IP into IPS blacklist: {e}"
                        );
                    }
                }
                for ip in &delta.to_remove {
                    if let Err(e) = ips.remove_from_blacklist(ip) {
                        tracing::warn!(
                            ip = %ip,
                            domain = domain,
                            "failed to remove stale IP from IPS blacklist: {e}"
                        );
                    }
                }
            } else {
                tracing::debug!(
                    domain = domain,
                    "domain matched blocklist with inject_target=ips but no IPS port configured"
                );
            }
        } else if let Some(ref writer) = *self
            .map_writer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            let metadata = IocMetadata {
                source: "dns-blocklist".to_string(),
                domain: Some(domain.to_string()),
                threat_type: "blocklisted-domain".to_string(),
                confidence: 100,
            };

            for ip in &delta.to_inject {
                let result = match inject_target {
                    InjectTarget::ThreatIntel => writer.inject_threatintel_ip(*ip, &metadata),
                    InjectTarget::Firewall => writer.inject_firewall_drop(*ip),
                    InjectTarget::Ips => unreachable!("handled above"),
                };
                if let Err(e) = result {
                    tracing::warn!(
                        ip = %ip,
                        domain = domain,
                        "failed to inject blocklisted IP into eBPF map: {e}"
                    );
                }
            }

            for ip in &delta.to_remove {
                let result = match inject_target {
                    InjectTarget::ThreatIntel => writer.remove_threatintel_ip(*ip),
                    InjectTarget::Firewall => writer.remove_firewall_drop(*ip),
                    InjectTarget::Ips => unreachable!("handled above"),
                };
                if let Err(e) = result {
                    tracing::warn!(
                        ip = %ip,
                        domain = domain,
                        "failed to remove stale blocklisted IP from eBPF map: {e}"
                    );
                }
            }
        } else if action == BlocklistAction::Block {
            tracing::debug!(
                domain = domain,
                "domain matched blocklist but no eBPF map writer configured"
            );
        }

        self.metrics.set_dns_injected_ips(injected_count as u64);
    }

    /// Run the background cleanup loop for expired injected IPs.
    pub async fn cleanup_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.cleanup_interval);
        loop {
            interval.tick().await;
            self.cleanup_expired();
        }
    }

    /// Remove expired injected IPs from eBPF maps.
    fn cleanup_expired(&self) {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            * 1_000_000_000;

        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expired = engine.collect_expired(now_ns);
        let inject_target = engine.inject_target();
        let injected_count = engine.injected_ip_count();
        drop(engine);

        if !expired.is_empty() {
            if inject_target == InjectTarget::Ips {
                if let Some(ref ips) = self.ips_port {
                    for ip in &expired {
                        if let Err(e) = ips.remove_from_blacklist(ip) {
                            tracing::warn!(ip = %ip, "failed to remove expired IP from IPS blacklist: {e}");
                        }
                    }
                }
            } else if let Some(ref writer) = *self
                .map_writer
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                for ip in &expired {
                    let result = match inject_target {
                        InjectTarget::ThreatIntel => writer.remove_threatintel_ip(*ip),
                        InjectTarget::Firewall => writer.remove_firewall_drop(*ip),
                        InjectTarget::Ips => unreachable!("handled above"),
                    };
                    if let Err(e) = result {
                        tracing::warn!(ip = %ip, "failed to remove expired IP from eBPF map: {e}");
                    }
                }
            }
            tracing::debug!(
                count = expired.len(),
                remaining = injected_count,
                "cleaned up expired DNS blocklist IPs"
            );
        }

        self.metrics.set_dns_injected_ips(injected_count as u64);
    }

    /// Reload blocklist configuration. Returns the number of IPs removed
    /// from eBPF maps due to patterns no longer matching.
    pub fn reload(&self, config: DomainBlocklistConfig) -> usize {
        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let inject_target = engine.inject_target();
        let removed = engine.reload(config);
        let injected_count = engine.injected_ip_count();
        drop(engine);

        if inject_target == InjectTarget::Ips {
            if let Some(ref ips) = self.ips_port {
                for ip in &removed {
                    if let Err(e) = ips.remove_from_blacklist(ip) {
                        tracing::warn!(ip = %ip, "failed to remove IP from IPS blacklist after reload: {e}");
                    }
                }
            }
        } else if let Some(ref writer) = *self
            .map_writer
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            for ip in &removed {
                let result = match inject_target {
                    InjectTarget::ThreatIntel => writer.remove_threatintel_ip(*ip),
                    InjectTarget::Firewall => writer.remove_firewall_drop(*ip),
                    InjectTarget::Ips => unreachable!("handled above"),
                };
                if let Err(e) = result {
                    tracing::warn!(ip = %ip, "failed to remove IP after blocklist reload: {e}");
                }
            }
        }

        self.metrics.set_dns_injected_ips(injected_count as u64);
        removed.len()
    }

    /// List all blocklist patterns with their per-pattern match counts.
    pub fn list_patterns_with_counts(&self) -> Vec<(String, u64)> {
        let engine = self
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine
            .list_patterns_with_counts()
            .into_iter()
            .map(|(p, c)| (p.to_string(), c))
            .collect()
    }

    /// Current blocklist action.
    pub fn action(&self) -> BlocklistAction {
        let engine = self
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.action()
    }

    /// Current blocklist statistics.
    pub fn stats(&self) -> DomainBlocklistStats {
        let engine = self
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.stats()
    }

    /// Add a domain pattern to the runtime blocklist.
    pub fn add_pattern(&self, raw: &str) -> Result<(), String> {
        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.add_pattern(raw).map_err(|e| e.to_string())
    }

    /// Remove a domain pattern from the runtime blocklist.
    pub fn remove_pattern(&self, raw: &str) -> Result<(), String> {
        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.remove_pattern(raw).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::dns::entity::DomainPattern;
    use ports::test_utils::NoopMetrics;
    use std::net::IpAddr;
    use std::sync::Mutex;

    /// Test mock that records injected/removed IPs.
    struct MockMapWriter {
        injected: Mutex<Vec<IpAddr>>,
        removed: Mutex<Vec<IpAddr>>,
    }

    impl MockMapWriter {
        fn new() -> Self {
            Self {
                injected: Mutex::new(Vec::new()),
                removed: Mutex::new(Vec::new()),
            }
        }
    }

    impl EbpfMapWritePort for MockMapWriter {
        fn inject_threatintel_ip(
            &self,
            ip: IpAddr,
            _metadata: &IocMetadata,
        ) -> Result<(), domain::common::error::DomainError> {
            self.injected.lock().unwrap().push(ip);
            Ok(())
        }

        fn remove_threatintel_ip(
            &self,
            ip: IpAddr,
        ) -> Result<(), domain::common::error::DomainError> {
            self.removed.lock().unwrap().push(ip);
            Ok(())
        }

        fn inject_firewall_drop(
            &self,
            ip: IpAddr,
        ) -> Result<(), domain::common::error::DomainError> {
            self.injected.lock().unwrap().push(ip);
            Ok(())
        }

        fn remove_firewall_drop(
            &self,
            ip: IpAddr,
        ) -> Result<(), domain::common::error::DomainError> {
            self.removed.lock().unwrap().push(ip);
            Ok(())
        }
    }

    fn test_config(patterns: Vec<&str>) -> DomainBlocklistConfig {
        DomainBlocklistConfig {
            patterns: patterns
                .into_iter()
                .map(|p| DomainPattern::parse(p).unwrap())
                .collect(),
            action: BlocklistAction::Block,
            inject_target: InjectTarget::ThreatIntel,
            grace_period_secs: 300,
        }
    }

    fn test_config_ips(patterns: Vec<&str>) -> DomainBlocklistConfig {
        DomainBlocklistConfig {
            patterns: patterns
                .into_iter()
                .map(|p| DomainPattern::parse(p).unwrap())
                .collect(),
            action: BlocklistAction::Block,
            inject_target: InjectTarget::Ips,
            grace_period_secs: 300,
        }
    }

    /// Mock IPS blacklist port that records add/remove calls.
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

    impl ports::secondary::ips_blacklist_port::IpsBlacklistPort for MockIpsBlacklist {
        fn add_to_blacklist(
            &self,
            ip: IpAddr,
            reason: String,
            _ttl: std::time::Duration,
        ) -> Result<(), domain::common::error::DomainError> {
            self.added.lock().unwrap().push((ip, reason));
            Ok(())
        }

        fn remove_from_blacklist(
            &self,
            ip: &IpAddr,
        ) -> Result<(), domain::common::error::DomainError> {
            self.removed.lock().unwrap().push(*ip);
            Ok(())
        }
    }

    #[test]
    fn on_dns_response_injects_blocked_domain() {
        let writer = Arc::new(MockMapWriter::new());
        let svc = DnsBlocklistAppService::new(
            test_config(vec!["bad.com"]),
            Some(writer.clone()),
            Arc::new(NoopMetrics),
        );

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        svc.on_dns_response("bad.com", &[ip], 300, 0);

        let injected = writer.injected.lock().unwrap();
        assert_eq!(*injected, vec![ip]);
    }

    #[test]
    fn on_dns_response_ignores_non_blocked() {
        let writer = Arc::new(MockMapWriter::new());
        let svc = DnsBlocklistAppService::new(
            test_config(vec!["bad.com"]),
            Some(writer.clone()),
            Arc::new(NoopMetrics),
        );

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        svc.on_dns_response("good.com", &[ip], 300, 0);

        assert!(writer.injected.lock().unwrap().is_empty());
    }

    #[test]
    fn on_dns_response_handles_reresolution() {
        let writer = Arc::new(MockMapWriter::new());
        let svc = DnsBlocklistAppService::new(
            test_config(vec!["bad.com"]),
            Some(writer.clone()),
            Arc::new(NoopMetrics),
        );

        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        let ip3: IpAddr = "3.3.3.3".parse().unwrap();

        svc.on_dns_response("bad.com", &[ip1, ip2], 300, 0);
        svc.on_dns_response("bad.com", &[ip1, ip3], 300, 10_000_000_000);

        // ip3 was injected, ip2 was removed
        let injected = writer.injected.lock().unwrap();
        assert!(injected.contains(&ip1));
        assert!(injected.contains(&ip2));
        assert!(injected.contains(&ip3));
        let removed = writer.removed.lock().unwrap();
        assert!(removed.contains(&ip2));
    }

    #[test]
    fn works_without_map_writer() {
        let svc =
            DnsBlocklistAppService::new(test_config(vec!["bad.com"]), None, Arc::new(NoopMetrics));

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        svc.on_dns_response("bad.com", &[ip], 300, 0); // should not panic
    }

    #[test]
    fn reload_removes_unblocked_ips() {
        let writer = Arc::new(MockMapWriter::new());
        let svc = DnsBlocklistAppService::new(
            test_config(vec!["bad.com", "evil.org"]),
            Some(writer.clone()),
            Arc::new(NoopMetrics),
        );

        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        svc.on_dns_response("bad.com", &[ip1], 300, 0);
        svc.on_dns_response("evil.org", &[ip2], 300, 0);

        let removed_count = svc.reload(test_config(vec!["bad.com"]));
        assert_eq!(removed_count, 1);

        let removed = writer.removed.lock().unwrap();
        assert!(removed.contains(&ip2));
    }

    #[test]
    fn stats_reports_correctly() {
        let svc = DnsBlocklistAppService::new(
            test_config(vec!["bad.com", "*.evil.org"]),
            None,
            Arc::new(NoopMetrics),
        );

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        svc.on_dns_response("bad.com", &[ip], 300, 0);

        let stats = svc.stats();
        assert_eq!(stats.pattern_count, 2);
        assert_eq!(stats.domains_blocked, 1);
        assert_eq!(stats.ips_injected, 1);
    }

    // ── IPS injection target tests ───────────────────────────────

    #[test]
    fn ips_inject_target_routes_to_ips_port() {
        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = DnsBlocklistAppService::new(
            test_config_ips(vec!["bad.com"]),
            None,
            Arc::new(NoopMetrics),
        )
        .with_ips_port(
            Arc::clone(&ips) as Arc<dyn ports::secondary::ips_blacklist_port::IpsBlacklistPort>
        );

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        svc.on_dns_response("bad.com", &[ip], 300, 0);

        let added = ips.added.lock().unwrap();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].0, ip);
        assert!(added[0].1.contains("bad.com"));
    }

    #[test]
    fn ips_inject_target_does_not_use_ebpf_writer() {
        let writer = Arc::new(MockMapWriter::new());
        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = DnsBlocklistAppService::new(
            test_config_ips(vec!["bad.com"]),
            Some(writer.clone()),
            Arc::new(NoopMetrics),
        )
        .with_ips_port(
            Arc::clone(&ips) as Arc<dyn ports::secondary::ips_blacklist_port::IpsBlacklistPort>
        );

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        svc.on_dns_response("bad.com", &[ip], 300, 0);

        // IPS port should be used, not the eBPF writer
        assert!(writer.injected.lock().unwrap().is_empty());
        assert_eq!(ips.added.lock().unwrap().len(), 1);
    }

    #[test]
    fn ips_inject_target_handles_reresolution() {
        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = DnsBlocklistAppService::new(
            test_config_ips(vec!["bad.com"]),
            None,
            Arc::new(NoopMetrics),
        )
        .with_ips_port(
            Arc::clone(&ips) as Arc<dyn ports::secondary::ips_blacklist_port::IpsBlacklistPort>
        );

        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        let ip3: IpAddr = "3.3.3.3".parse().unwrap();

        svc.on_dns_response("bad.com", &[ip1, ip2], 300, 0);
        svc.on_dns_response("bad.com", &[ip1, ip3], 300, 10_000_000_000);

        // ip2 should have been removed via IPS port
        let removed = ips.removed.lock().unwrap();
        assert!(removed.contains(&ip2));

        // ip3 should have been added
        let added = ips.added.lock().unwrap();
        assert!(added.iter().any(|(ip, _)| *ip == ip3));
    }

    #[test]
    fn ips_inject_target_reload_removes_via_ips_port() {
        let ips = Arc::new(MockIpsBlacklist::new());
        let svc = DnsBlocklistAppService::new(
            test_config_ips(vec!["bad.com", "evil.org"]),
            None,
            Arc::new(NoopMetrics),
        )
        .with_ips_port(
            Arc::clone(&ips) as Arc<dyn ports::secondary::ips_blacklist_port::IpsBlacklistPort>
        );

        let ip1: IpAddr = "1.1.1.1".parse().unwrap();
        let ip2: IpAddr = "2.2.2.2".parse().unwrap();
        svc.on_dns_response("bad.com", &[ip1], 300, 0);
        svc.on_dns_response("evil.org", &[ip2], 300, 0);

        let removed_count = svc.reload(test_config_ips(vec!["bad.com"]));
        assert_eq!(removed_count, 1);

        let removed = ips.removed.lock().unwrap();
        assert!(removed.contains(&ip2));
    }

    #[test]
    fn ips_inject_target_without_port_does_not_panic() {
        let svc = DnsBlocklistAppService::new(
            test_config_ips(vec!["bad.com"]),
            None,
            Arc::new(NoopMetrics),
        );

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        svc.on_dns_response("bad.com", &[ip], 300, 0); // should not panic
    }
}
