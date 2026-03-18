use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use domain::common::entity::DomainMode;
use domain::common::error::DomainError;
use domain::ids::entity::{IdsRule, SamplingMode};
use domain::ips::engine::IpsEngine;
use domain::ips::entity::{BlacklistEntry, EnforcementAction, IpsPolicy, WhitelistEntry};
use ebpf_common::firewall::{ACTION_DROP, FirewallLpmEntryV4, FirewallLpmEntryV6};
use ports::secondary::geoip_port::GeoIpPort;
use ports::secondary::lpm_coordinator_port::LpmCoordinatorPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level IPS service.
///
/// Orchestrates the IPS domain engine (blacklist + detection counting)
/// and metrics updates. Designed to be wrapped in `RwLock` for shared access.
pub struct IpsAppService {
    engine: IpsEngine,
    rules: Vec<IdsRule>,
    metrics: Arc<dyn MetricsPort>,
    mode: DomainMode,
    enabled: bool,
    geoip: Option<Arc<dyn GeoIpPort>>,
    lpm_coordinator: Option<Arc<dyn LpmCoordinatorPort>>,
}

impl IpsAppService {
    pub fn new(engine: IpsEngine, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine,
            rules: Vec::new(),
            metrics,
            mode: DomainMode::default(),
            enabled: true,
            geoip: None,
            lpm_coordinator: None,
        }
    }

    /// Set the `GeoIP` port for country-aware auto-blacklist thresholds.
    pub fn set_geoip_port(&mut self, port: Arc<dyn GeoIpPort>) {
        self.geoip = Some(port);
    }

    /// Set the LPM coordinator for kernel-side /24 subnet enforcement.
    pub fn set_lpm_coordinator(&mut self, coordinator: Arc<dyn LpmCoordinatorPort>) {
        self.lpm_coordinator = Some(coordinator);
    }

    pub fn mode(&self) -> DomainMode {
        self.mode
    }

    pub fn set_mode(&mut self, mode: DomainMode) {
        self.mode = mode;
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        tracing::info!(enabled, "IPS service toggled");
    }

    /// Check if a source IP is blacklisted. Returns `true` if the IP
    /// is actively blocked by the IPS blacklist.
    pub fn is_blacklisted(&mut self, ip: IpAddr) -> bool {
        self.engine.is_blacklisted(ip)
    }

    /// Record a detection event for the given source IP.
    /// Returns enforcement actions if the threshold is reached.
    ///
    /// In `Alert` mode, the detection is still counted and the blacklist
    /// entry is created, but the caller should not enforce the action
    /// (observation only).
    pub fn record_detection(&mut self, ip: IpAddr) -> Vec<EnforcementAction> {
        let src_country = self.resolve_country(&ip);
        let actions = self
            .engine
            .record_detection_with_country(ip, src_country.as_deref());

        if !actions.is_empty() {
            self.metrics.record_ips_block();
            self.update_blacklist_metric();
            self.apply_subnet_enforcements(&actions);
        }

        actions
    }

    /// Manually add an IP to the blacklist.
    pub fn add_to_blacklist(
        &mut self,
        ip: IpAddr,
        reason: String,
        ttl: Duration,
    ) -> Result<(), DomainError> {
        self.engine
            .add_to_blacklist(ip, reason, false, ttl)
            .map_err(DomainError::from)?;
        self.update_blacklist_metric();
        tracing::info!(%ip, "IPS blacklist entry added");
        Ok(())
    }

    /// Remove an IP from the blacklist.
    pub fn remove_from_blacklist(&mut self, ip: IpAddr) -> Result<(), DomainError> {
        self.engine
            .remove_from_blacklist(&ip)
            .map_err(DomainError::from)?;
        self.update_blacklist_metric();
        tracing::info!(%ip, "IPS blacklist entry removed");
        Ok(())
    }

    /// List all current blacklist entries.
    pub fn list_blacklist(&self) -> Vec<BlacklistEntry> {
        self.engine.blacklist_entries().values().cloned().collect()
    }

    /// Remove all entries from the blacklist.
    pub fn clear_blacklist(&mut self) {
        self.engine.clear_blacklist();
        self.update_blacklist_metric();
        tracing::info!("IPS blacklist cleared");
    }

    /// Return the current blacklist size.
    pub fn blacklist_size(&self) -> usize {
        self.engine.blacklist_size()
    }

    /// Run periodic cleanup of expired entries. Returns enforcement actions
    /// for the map updater to remove entries from the eBPF map.
    pub fn cleanup_expired(&mut self) -> Vec<EnforcementAction> {
        let actions = self.engine.cleanup_expired();
        if !actions.is_empty() {
            self.update_blacklist_metric();
            self.apply_subnet_enforcements(&actions);
        }
        actions
    }

    /// Update the IPS policy (e.g., during hot-reload).
    pub fn set_policy(&mut self, policy: IpsPolicy) {
        self.engine.set_policy(policy);
    }

    /// Read-only access to the current policy.
    pub fn policy(&self) -> &IpsPolicy {
        self.engine.policy()
    }

    /// Replace the whitelist entries (delegates to engine).
    pub fn reload_whitelist(&mut self, entries: Vec<WhitelistEntry>) {
        self.engine.set_whitelist(entries);
    }

    /// Set the sampling mode for detection processing.
    pub fn set_sampling(&mut self, mode: SamplingMode) {
        self.engine.set_sampling(mode);
    }

    /// Check whether a packet should be processed based on the sampling mode.
    pub fn should_process(&self, src_ip: u32, dst_ip: u32) -> bool {
        self.engine.should_process(src_ip, dst_ip)
    }

    /// Reload IPS rules. Stores them for per-rule mode tracking.
    /// Returns `Ok(())` on success, or a domain error if rule IDs
    /// are duplicated.
    pub fn reload_rules(&mut self, rules: Vec<IdsRule>) -> Result<(), DomainError> {
        // Check for duplicate IDs
        let mut seen = std::collections::HashSet::new();
        for rule in &rules {
            if !seen.insert(&rule.id) {
                return Err(DomainError::DuplicateRule(rule.id.0.clone()));
            }
        }
        self.rules = rules;
        self.metrics
            .set_rules_loaded("ips", self.rules.len() as u64);
        Ok(())
    }

    /// List all current IPS rules with their modes.
    pub fn list_rules(&self) -> &[IdsRule] {
        &self.rules
    }

    /// Number of IPS rules loaded.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Toggle a single rule's mode. Returns the old mode for logging,
    /// or an error if the rule is not found.
    pub fn update_rule_mode(
        &mut self,
        rule_id: &str,
        new_mode: DomainMode,
    ) -> Result<DomainMode, DomainError> {
        let rule = self
            .rules
            .iter_mut()
            .find(|r| r.id.0 == rule_id)
            .ok_or_else(|| DomainError::RuleNotFound(rule_id.to_string()))?;
        let old_mode = rule.mode;
        rule.mode = new_mode;
        Ok(old_mode)
    }

    /// Apply subnet-related enforcement actions to the LPM coordinator.
    fn apply_subnet_enforcements(&self, actions: &[EnforcementAction]) {
        let Some(ref coordinator) = self.lpm_coordinator else {
            return;
        };

        for action in actions {
            match action {
                EnforcementAction::BlockSubnet {
                    addr, prefix_len, ..
                } => {
                    let (src_v4, src_v6) = Self::ip_to_lpm_entries(*addr, *prefix_len);
                    if let Err(e) = coordinator.insert_entries("ips", &src_v4, &src_v6) {
                        tracing::warn!(
                            addr = %addr,
                            prefix_len,
                            "IPS subnet block: failed to inject LPM entry: {e}"
                        );
                    } else {
                        tracing::info!(
                            addr = %addr,
                            prefix_len,
                            "IPS subnet block: injected LPM entry"
                        );
                    }
                }
                EnforcementAction::UnblockSubnet { addr, prefix_len } => {
                    let (src_v4, src_v6) = Self::ip_to_lpm_entries(*addr, *prefix_len);
                    if let Err(e) = coordinator.remove_entries("ips", &src_v4, &src_v6) {
                        tracing::warn!(
                            addr = %addr,
                            prefix_len,
                            "IPS subnet unblock: failed to remove LPM entry: {e}"
                        );
                    } else {
                        tracing::info!(
                            addr = %addr,
                            prefix_len,
                            "IPS subnet unblock: removed LPM entry"
                        );
                    }
                }
                _ => {}
            }
        }
    }

    /// Convert an IP address + prefix to LPM entry vectors.
    fn ip_to_lpm_entries(
        addr: IpAddr,
        prefix_len: u8,
    ) -> (Vec<FirewallLpmEntryV4>, Vec<FirewallLpmEntryV6>) {
        match addr {
            IpAddr::V4(v4) => {
                let entry = FirewallLpmEntryV4 {
                    prefix_len: u32::from(prefix_len),
                    addr: v4.octets(),
                    action: ACTION_DROP,
                };
                (vec![entry], Vec::new())
            }
            IpAddr::V6(v6) => {
                let entry = FirewallLpmEntryV6 {
                    prefix_len: u32::from(prefix_len),
                    addr: v6.octets(),
                    action: ACTION_DROP,
                };
                (Vec::new(), vec![entry])
            }
        }
    }

    fn update_blacklist_metric(&self) {
        self.metrics
            .set_ips_blacklist_size(self.engine.blacklist_size() as u64);
    }

    /// Resolve the country code for an IP address via `GeoIP`.
    pub fn resolve_country(&self, ip: &IpAddr) -> Option<String> {
        let geoip = self.geoip.as_ref()?;
        geoip.lookup(ip).and_then(|info| info.country_code)
    }
}

/// Thread-safe wrapper implementing `IpsBlacklistPort` for use by the
/// DNS blocklist service. Delegates to the shared `IpsAppService` behind
/// a `tokio::sync::RwLock` so that the same IPS state is used by the
/// main pipeline and the DNS blocklist injection path.
///
/// Uses `try_write()` since the DNS blocklist service calls these methods
/// synchronously from async context. IPS operations are fast (in-memory
/// `HashMap`), so contention is extremely unlikely.
pub struct IpsBlacklistAdapter {
    inner: Arc<tokio::sync::RwLock<IpsAppService>>,
}

impl IpsBlacklistAdapter {
    pub fn new(service: Arc<tokio::sync::RwLock<IpsAppService>>) -> Self {
        Self { inner: service }
    }
}

impl ports::secondary::ips_blacklist_port::IpsBlacklistPort for IpsBlacklistAdapter {
    fn add_to_blacklist(
        &self,
        ip: IpAddr,
        reason: String,
        ttl: Duration,
    ) -> Result<(), DomainError> {
        let mut svc = self
            .inner
            .try_write()
            .map_err(|_| DomainError::EngineError("IPS service lock contention".to_string()))?;
        svc.add_to_blacklist(ip, reason, ttl)
    }

    fn remove_from_blacklist(&self, ip: &IpAddr) -> Result<(), DomainError> {
        let mut svc = self
            .inner
            .try_write()
            .map_err(|_| DomainError::EngineError("IPS service lock contention".to_string()))?;
        svc.remove_from_blacklist(*ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, DdosMetrics, DlpMetrics,
        DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics, FirewallMetrics, IpsMetrics,
        LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
    };
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestMetrics {
        blacklist_size: AtomicU64,
        blocks: AtomicU64,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                blacklist_size: AtomicU64::new(0),
                blocks: AtomicU64::new(0),
            }
        }
    }

    impl PacketMetrics for TestMetrics {}
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {}
    impl IpsMetrics for TestMetrics {
        fn set_ips_blacklist_size(&self, size: u64) {
            self.blacklist_size.store(size, Ordering::Relaxed);
        }
        fn record_ips_block(&self) {
            self.blocks.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl DnsMetrics for TestMetrics {}
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {}
    impl ConfigMetrics for TestMetrics {}
    impl EventMetrics for TestMetrics {}
    impl DlpMetrics for TestMetrics {}
    impl DdosMetrics for TestMetrics {}
    impl ConntrackMetrics for TestMetrics {}
    impl RoutingMetrics for TestMetrics {}
    impl AuditMetrics for TestMetrics {}
    impl LbMetrics for TestMetrics {}
    impl FingerprintMetrics for TestMetrics {}

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn make_service() -> (IpsAppService, Arc<TestMetrics>) {
        let metrics = Arc::new(TestMetrics::new());
        let policy = IpsPolicy {
            max_blacklist_duration: Duration::from_secs(60),
            auto_blacklist_threshold: 3,
            max_blacklist_size: 100,
            country_thresholds: None,
        };
        let engine = IpsEngine::new(policy);
        let svc = IpsAppService::new(engine, Arc::clone(&metrics) as Arc<dyn MetricsPort>);
        (svc, metrics)
    }

    #[test]
    fn mode_and_enabled_defaults() {
        let (svc, _) = make_service();
        assert_eq!(svc.mode(), DomainMode::Alert);
        assert!(svc.enabled());
    }

    #[test]
    fn set_mode_and_enabled() {
        let (mut svc, _) = make_service();
        svc.set_mode(DomainMode::Block);
        svc.set_enabled(false);
        assert_eq!(svc.mode(), DomainMode::Block);
        assert!(!svc.enabled());
    }

    #[test]
    fn blacklisted_ip_detected() {
        let (mut svc, _) = make_service();
        let addr = ip(10, 0, 0, 1);
        svc.add_to_blacklist(addr, "manual".into(), Duration::from_secs(60))
            .unwrap();
        assert!(svc.is_blacklisted(addr));
    }

    #[test]
    fn non_blacklisted_ip() {
        let (mut svc, _) = make_service();
        assert!(!svc.is_blacklisted(ip(10, 0, 0, 1)));
    }

    #[test]
    fn detection_threshold_triggers_enforcement() {
        let (mut svc, metrics) = make_service();
        let addr = ip(192, 168, 1, 100);

        assert!(svc.record_detection(addr).is_empty()); // 1
        assert!(svc.record_detection(addr).is_empty()); // 2
        let actions = svc.record_detection(addr); // 3 = threshold
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], EnforcementAction::BlacklistIp { .. }));

        assert!(svc.is_blacklisted(addr));
        assert_eq!(metrics.blocks.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.blacklist_size.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn blacklist_crud() {
        let (mut svc, metrics) = make_service();
        let addr = ip(10, 0, 0, 1);

        // Add
        svc.add_to_blacklist(addr, "test".into(), Duration::from_secs(60))
            .unwrap();
        assert_eq!(svc.blacklist_size(), 1);
        assert_eq!(metrics.blacklist_size.load(Ordering::Relaxed), 1);

        // List
        let entries = svc.list_blacklist();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, addr);

        // Remove
        svc.remove_from_blacklist(addr).unwrap();
        assert_eq!(svc.blacklist_size(), 0);
        assert_eq!(metrics.blacklist_size.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn clear_blacklist() {
        let (mut svc, metrics) = make_service();
        svc.add_to_blacklist(ip(10, 0, 0, 1), "a".into(), Duration::from_secs(60))
            .unwrap();
        svc.add_to_blacklist(ip(10, 0, 0, 2), "b".into(), Duration::from_secs(60))
            .unwrap();
        svc.clear_blacklist();
        assert_eq!(svc.blacklist_size(), 0);
        assert_eq!(metrics.blacklist_size.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cleanup_expired_updates_metrics() {
        let (mut svc, _) = make_service();
        svc.add_to_blacklist(ip(10, 0, 0, 1), "old".into(), Duration::from_millis(1))
            .unwrap();

        std::thread::sleep(Duration::from_millis(5));
        let actions = svc.cleanup_expired();
        assert_eq!(actions.len(), 1);
        assert_eq!(svc.blacklist_size(), 0);
    }

    #[test]
    fn policy_update() {
        let (mut svc, _) = make_service();
        let new_policy = IpsPolicy {
            max_blacklist_duration: Duration::from_secs(120),
            auto_blacklist_threshold: 5,
            max_blacklist_size: 500,
            country_thresholds: None,
        };
        svc.set_policy(new_policy);
        assert_eq!(svc.policy().auto_blacklist_threshold, 5);
    }

    // ── whitelist + rules ─────────────────────────────────────────

    use domain::common::entity::{Protocol, RuleId, Severity};
    use domain::ips::entity::WhitelistEntry;

    fn make_ips_rule(id: &str, mode: DomainMode) -> IdsRule {
        IdsRule {
            id: RuleId(id.to_string()),
            description: format!("Test {id}"),
            severity: Severity::Medium,
            mode,
            protocol: Protocol::Tcp,
            dst_port: Some(22),
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
            country_thresholds: None,
            group_mask: 0,
        }
    }

    #[test]
    fn reload_whitelist_updates_engine() {
        let (mut svc, _) = make_service();
        let wl = vec![WhitelistEntry::new(ip(10, 0, 0, 1), None).unwrap()];
        svc.reload_whitelist(wl);
        // Whitelisted IP cannot be added to blacklist
        let result = svc.add_to_blacklist(ip(10, 0, 0, 1), "test".into(), Duration::from_secs(60));
        assert!(result.is_err());
    }

    #[test]
    fn reload_rules_stores_rules() {
        let (mut svc, _) = make_service();
        let rules = vec![
            make_ips_rule("ips-001", DomainMode::Alert),
            make_ips_rule("ips-002", DomainMode::Block),
        ];
        svc.reload_rules(rules).unwrap();
        assert_eq!(svc.rule_count(), 2);
    }

    #[test]
    fn reload_rules_duplicate_fails() {
        let (mut svc, _) = make_service();
        let rules = vec![
            make_ips_rule("ips-001", DomainMode::Alert),
            make_ips_rule("ips-001", DomainMode::Block),
        ];
        assert!(svc.reload_rules(rules).is_err());
    }

    #[test]
    fn list_rules_returns_all() {
        let (mut svc, _) = make_service();
        svc.reload_rules(vec![make_ips_rule("ips-001", DomainMode::Alert)])
            .unwrap();
        let rules = svc.list_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id.0, "ips-001");
    }

    #[test]
    fn update_rule_mode_toggles() {
        let (mut svc, _) = make_service();
        svc.reload_rules(vec![make_ips_rule("ips-001", DomainMode::Alert)])
            .unwrap();
        let old = svc.update_rule_mode("ips-001", DomainMode::Block).unwrap();
        assert_eq!(old, DomainMode::Alert);
        assert_eq!(svc.list_rules()[0].mode, DomainMode::Block);
    }

    #[test]
    fn update_rule_mode_nonexistent_fails() {
        let (mut svc, _) = make_service();
        let result = svc.update_rule_mode("ips-999", DomainMode::Block);
        assert!(matches!(result, Err(DomainError::RuleNotFound(_))));
    }
}
