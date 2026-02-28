use std::net::IpAddr;
use std::sync::Arc;

use domain::common::entity::DomainMode;
use domain::common::error::DomainError;
use domain::threatintel::engine::ThreatIntelEngine;
use domain::threatintel::entity::{FeedConfig, Ioc};
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::threatintel_map_port::ThreatIntelMapPort;

/// Application-level threat intelligence service.
///
/// Wraps the domain engine with metrics updates, feed configuration,
/// and optional eBPF map synchronization.
pub struct ThreatIntelAppService {
    engine: ThreatIntelEngine,
    map_port: Option<Box<dyn ThreatIntelMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    feeds: Vec<FeedConfig>,
    mode: DomainMode,
    enabled: bool,
}

impl ThreatIntelAppService {
    pub fn new(
        engine: ThreatIntelEngine,
        metrics: Arc<dyn MetricsPort>,
        feeds: Vec<FeedConfig>,
    ) -> Self {
        Self {
            engine,
            map_port: None,
            metrics,
            feeds,
            mode: DomainMode::default(),
            enabled: true,
        }
    }

    /// Set the eBPF map port and perform an initial sync.
    pub fn set_map_port(&mut self, port: Box<dyn ThreatIntelMapPort + Send>) {
        self.map_port = Some(port);
        self.sync_ebpf_maps();
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
    }

    pub fn add_ioc(&mut self, ioc: Ioc) -> Result<(), DomainError> {
        self.engine.add_ioc(ioc)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    pub fn remove_ioc(&mut self, ip: &IpAddr) -> Result<(), DomainError> {
        self.engine.remove_ioc(ip)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    pub fn reload_iocs(&mut self, iocs: Vec<Ioc>) -> Result<(), DomainError> {
        self.engine.reload(iocs)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        Ok(())
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<&Ioc> {
        self.engine.lookup(ip)
    }

    pub fn ioc_count(&self) -> usize {
        self.engine.ioc_count()
    }

    pub fn list_feeds(&self) -> &[FeedConfig] {
        &self.feeds
    }

    pub fn set_feeds(&mut self, feeds: Vec<FeedConfig>) {
        self.feeds = feeds;
    }

    /// Direct access to the engine (for feed update orchestration).
    pub fn engine(&self) -> &ThreatIntelEngine {
        &self.engine
    }

    /// Mutable access to the engine.
    pub fn engine_mut(&mut self) -> &mut ThreatIntelEngine {
        &mut self.engine
    }

    /// Full-reload sync: bulk-load all engine IOCs into eBPF maps.
    ///
    /// In `Alert` mode, IOCs are loaded with `block_mode = false`
    /// (observation only — traffic is not dropped).
    fn sync_ebpf_maps(&mut self) {
        let Some(ref mut map) = self.map_port else {
            return;
        };

        let block_mode = self.mode != DomainMode::Alert;
        let iocs: Vec<Ioc> = self.engine.all_iocs().cloned().collect();

        if let Err(e) = map.load_all_iocs(&iocs, block_mode) {
            tracing::warn!("failed to sync threat intel IOCs to eBPF maps: {e}");
        }
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("threatintel", self.engine.ioc_count() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::threatintel::entity::{FeedFormat, ThreatType};
    use ports::secondary::metrics_port::{
        AlertMetrics, ConfigMetrics, DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics,
        IpsMetrics, PacketMetrics, SystemMetrics,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestMetrics {
        rules_loaded: AtomicU64,
        last_component: std::sync::Mutex<String>,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                rules_loaded: AtomicU64::new(0),
                last_component: std::sync::Mutex::new(String::new()),
            }
        }
    }

    impl PacketMetrics for TestMetrics {}
    impl FirewallMetrics for TestMetrics {
        fn set_rules_loaded(&self, component: &str, count: u64) {
            self.rules_loaded.store(count, Ordering::Relaxed);
            *self.last_component.lock().unwrap() = component.to_string();
        }
    }
    impl AlertMetrics for TestMetrics {}
    impl IpsMetrics for TestMetrics {}
    impl DnsMetrics for TestMetrics {}
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {}
    impl ConfigMetrics for TestMetrics {}
    impl EventMetrics for TestMetrics {}

    fn make_ioc(ip: &str) -> Ioc {
        Ioc {
            ip: ip.parse().unwrap(),
            feed_id: "test-feed".to_string(),
            confidence: 80,
            threat_type: ThreatType::C2,
            last_seen: 0,
            source_feed: "Test".to_string(),
        }
    }

    fn make_feed() -> FeedConfig {
        FeedConfig {
            id: "test".to_string(),
            name: "Test Feed".to_string(),
            url: "https://example.com".to_string(),
            format: FeedFormat::Plaintext,
            enabled: true,
            refresh_interval_secs: 3600,
            max_iocs: 500_000,
            default_action: None,
            min_confidence: 0,
            field_mapping: None,
            auth_header: None,
        }
    }

    fn make_service() -> (ThreatIntelAppService, Arc<TestMetrics>) {
        let metrics = Arc::new(TestMetrics::new());
        let engine = ThreatIntelEngine::new(1_000_000);
        let svc = ThreatIntelAppService::new(
            engine,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            vec![make_feed()],
        );
        (svc, metrics)
    }

    #[test]
    fn add_and_lookup() {
        let (mut svc, metrics) = make_service();
        svc.add_ioc(make_ioc("10.0.0.1")).unwrap();
        assert_eq!(svc.ioc_count(), 1);
        assert!(svc.lookup(&"10.0.0.1".parse().unwrap()).is_some());
        assert_eq!(metrics.rules_loaded.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "threatintel");
    }

    #[test]
    fn remove_ioc() {
        let (mut svc, metrics) = make_service();
        svc.add_ioc(make_ioc("10.0.0.1")).unwrap();
        svc.remove_ioc(&"10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(svc.ioc_count(), 0);
        assert_eq!(metrics.rules_loaded.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn reload_iocs() {
        let (mut svc, metrics) = make_service();
        svc.add_ioc(make_ioc("1.1.1.1")).unwrap();
        svc.reload_iocs(vec![make_ioc("2.2.2.2"), make_ioc("3.3.3.3")])
            .unwrap();
        assert_eq!(svc.ioc_count(), 2);
        assert!(svc.lookup(&"1.1.1.1".parse().unwrap()).is_none());
        assert_eq!(metrics.rules_loaded.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn list_feeds() {
        let (svc, _) = make_service();
        assert_eq!(svc.list_feeds().len(), 1);
        assert_eq!(svc.list_feeds()[0].id, "test");
    }

    #[test]
    fn mode_and_enabled() {
        let (mut svc, _) = make_service();
        assert_eq!(svc.mode(), DomainMode::Alert);
        assert!(svc.enabled());
        svc.set_mode(DomainMode::Block);
        svc.set_enabled(false);
        assert_eq!(svc.mode(), DomainMode::Block);
        assert!(!svc.enabled());
    }
}
