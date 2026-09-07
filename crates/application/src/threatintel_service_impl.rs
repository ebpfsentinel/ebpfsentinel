use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use domain::common::entity::DomainMode;
use domain::common::error::DomainError;
use domain::threatintel::engine::ThreatIntelEngine;
use domain::threatintel::entity::{CtiUrl, FeedConfig, Ioc};
use ports::secondary::geoip_port::GeoIpPort;
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::threatintel_map_port::ThreatIntelMapPort;

/// Shared handle to the eBPF map port, behind `Arc<Mutex<..>>` so the
/// service can be cheaply cloned (required by the `ArcSwap` pattern)
/// while the map port remains shared across clones.
type SharedMapPort = Arc<Mutex<Box<dyn ThreatIntelMapPort + Send>>>;

/// Application-level threat intelligence service.
///
/// Wraps the domain engine with metrics updates, feed configuration,
/// and optional eBPF map synchronization.
#[derive(Clone)]
pub struct ThreatIntelAppService {
    engine: ThreatIntelEngine,
    map_port: Option<SharedMapPort>,
    geoip: Option<Arc<dyn GeoIpPort>>,
    metrics: Arc<dyn MetricsPort>,
    feeds: Vec<FeedConfig>,
    mode: DomainMode,
    enabled: bool,
    /// Unix-epoch milliseconds of the last completed feed fetch cycle, or
    /// `None` if no fetch has run yet. Shared across all feeds because the
    /// fetcher refreshes every enabled feed in a single cycle.
    last_fetched: Option<u64>,
    /// Malicious URL indicators ingested from CTI feeds. The threat-intel
    /// engine itself is IP-only, so URL indicators are retained here and
    /// surfaced read-only via the API.
    urls: Vec<CtiUrl>,
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
            geoip: None,
            metrics,
            feeds,
            mode: DomainMode::default(),
            enabled: true,
            last_fetched: None,
            urls: Vec::new(),
        }
    }

    /// Replace the retained URL indicators with the latest feed snapshot.
    pub fn reload_urls(&mut self, urls: Vec<CtiUrl>) {
        let count = urls.len();
        self.urls = urls;
        if count > 0 {
            tracing::info!(count, "threat intel URL indicators reloaded");
        }
    }

    /// Read-only view of the retained malicious URL indicators.
    pub fn urls(&self) -> &[CtiUrl] {
        &self.urls
    }

    /// Set the eBPF map port and perform an initial sync.
    pub fn set_map_port(&mut self, port: Box<dyn ThreatIntelMapPort + Send>) {
        self.map_port = Some(Arc::new(Mutex::new(port)));
        self.sync_ebpf_maps();
    }

    /// Clear the eBPF map port (program unloaded).
    pub fn clear_map_port(&mut self) {
        self.map_port = None;
    }

    /// Set the `GeoIP` port for country-based confidence boosting.
    pub fn set_geoip_port(&mut self, port: Arc<dyn GeoIpPort>) {
        self.geoip = Some(port);
    }

    /// Set country confidence boost map on the underlying engine.
    pub fn set_country_confidence_boost(&mut self, boost: std::collections::HashMap<String, i8>) {
        self.engine.set_country_confidence_boost(boost);
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
        tracing::info!(enabled, "threat intel service toggled");
    }

    pub fn add_ioc(&mut self, mut ioc: Ioc) -> Result<(), DomainError> {
        if let Some(ref geoip) = self.geoip {
            let cc = geoip.lookup(&ioc.ip).and_then(|info| info.country_code);
            self.engine.apply_country_boost(&mut ioc, cc.as_deref());
        }
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
        let iocs = self.apply_country_boosts(iocs);
        let count = iocs.len();
        self.engine.reload(iocs)?;
        self.sync_ebpf_maps();
        self.update_metrics();
        tracing::info!(count, "threat intel IOCs reloaded");
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

    /// Unix-epoch milliseconds of the last completed feed fetch, if any.
    pub fn last_fetched(&self) -> Option<u64> {
        self.last_fetched
    }

    /// Stamp the current time as the last completed feed fetch. Called by
    /// the feed fetcher after every fetch cycle (periodic or manual).
    pub fn mark_fetched(&mut self) {
        self.last_fetched = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
            .ok();
    }

    /// Direct access to the engine (for feed update orchestration).
    pub fn engine(&self) -> &ThreatIntelEngine {
        &self.engine
    }

    /// Mutable access to the engine.
    pub fn engine_mut(&mut self) -> &mut ThreatIntelEngine {
        &mut self.engine
    }

    /// Apply country confidence boosts to a batch of IOCs using `GeoIP` lookups.
    fn apply_country_boosts(&self, mut iocs: Vec<Ioc>) -> Vec<Ioc> {
        let Some(ref geoip) = self.geoip else {
            return iocs;
        };
        for ioc in &mut iocs {
            let cc = geoip.lookup(&ioc.ip).and_then(|info| info.country_code);
            self.engine.apply_country_boost(ioc, cc.as_deref());
        }
        iocs
    }

    /// The mode an IOC from `feed_id` is enforced in.
    ///
    /// A feed that sets `default_action` overrides the service mode for its own
    /// indicators and for nothing else. An IOC whose feed is not configured -
    /// one added through the API, or one left behind by a feed removed from the
    /// configuration - inherits the service mode, which is what the operator
    /// asked for globally.
    fn mode_for_feed(&self, feed_id: &str) -> DomainMode {
        self.feeds
            .iter()
            .find(|feed| feed.id == feed_id)
            .and_then(FeedConfig::action_override)
            .unwrap_or(self.mode)
    }

    /// Full-reload sync: bulk-load all engine IOCs into eBPF maps.
    ///
    /// In `Alert` mode, IOCs are loaded as alert-only (observation only -
    /// traffic is not dropped), unless the feed they came from overrides it.
    fn sync_ebpf_maps(&self) {
        let Some(ref map_port) = self.map_port else {
            return;
        };

        let iocs: Vec<(Ioc, DomainMode)> = self
            .engine
            .all_iocs()
            .map(|ioc| {
                let mode = self.mode_for_feed(&ioc.feed_id);
                (ioc.clone(), mode)
            })
            .collect();

        let Ok(mut map) = map_port.lock() else {
            tracing::warn!("threat intel map port lock poisoned, skipping eBPF sync");
            return;
        };

        if let Err(e) = map.load_all_iocs(&iocs) {
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
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics, CtMetrics,
        DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics,
        FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
        ThreatIntelMetrics, ZoneMetrics,
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
    impl DlpMetrics for TestMetrics {}
    impl DdosMetrics for TestMetrics {}
    impl ConntrackMetrics for TestMetrics {}
    impl RoutingMetrics for TestMetrics {}
    impl AuditMetrics for TestMetrics {}
    impl LbMetrics for TestMetrics {}
    impl FingerprintMetrics for TestMetrics {}
    impl ContainerMetrics for TestMetrics {}
    impl CtMetrics for TestMetrics {}
    impl ThreatIntelMetrics for TestMetrics {}
    impl ZoneMetrics for TestMetrics {}

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
    fn reload_urls_retains_and_surfaces() {
        let (mut svc, _) = make_service();
        assert!(svc.urls().is_empty());
        svc.reload_urls(vec![CtiUrl {
            url: "http://malware.test/payload.exe".to_string(),
            feed_id: "test-feed".to_string(),
            confidence: 90,
            threat_type: ThreatType::C2,
            source: None,
        }]);
        assert_eq!(svc.urls().len(), 1);
        assert_eq!(svc.urls()[0].url, "http://malware.test/payload.exe");
        // A subsequent reload replaces the snapshot.
        svc.reload_urls(Vec::new());
        assert!(svc.urls().is_empty());
    }

    /// Records what the last sync handed the map. A per-feed override changes
    /// nothing the service reports about itself, so the map is the only place
    /// it is observable.
    struct RecordingMapPort {
        loaded: Arc<Mutex<Vec<(String, DomainMode)>>>,
    }

    impl ThreatIntelMapPort for RecordingMapPort {
        fn insert_ioc(
            &mut self,
            _key: &ebpf_common::threatintel::ThreatIntelKey,
            _value: &ebpf_common::threatintel::ThreatIntelValue,
        ) -> Result<(), DomainError> {
            Ok(())
        }

        fn remove_ioc(
            &mut self,
            _key: &ebpf_common::threatintel::ThreatIntelKey,
        ) -> Result<(), DomainError> {
            Ok(())
        }

        fn clear_iocs(&mut self) -> Result<(), DomainError> {
            Ok(())
        }

        fn ioc_count(&self) -> Result<usize, DomainError> {
            Ok(self.loaded.lock().unwrap().len())
        }

        fn load_all_iocs(&mut self, iocs: &[(Ioc, DomainMode)]) -> Result<(), DomainError> {
            *self.loaded.lock().unwrap() = iocs
                .iter()
                .map(|(ioc, mode)| (ioc.ip.to_string(), *mode))
                .collect();
            Ok(())
        }
    }

    fn feed_with_action(id: &str, action: Option<&str>) -> FeedConfig {
        FeedConfig {
            id: id.to_string(),
            default_action: action.map(str::to_string),
            ..make_feed()
        }
    }

    fn ioc_from(ip: &str, feed_id: &str) -> Ioc {
        Ioc {
            feed_id: feed_id.to_string(),
            ..make_ioc(ip)
        }
    }

    /// Sync with the given feeds and IOCs, and report the mode each IOC landed
    /// in the map under, keyed by address.
    fn synced_modes(
        mode: DomainMode,
        feeds: Vec<FeedConfig>,
        iocs: Vec<Ioc>,
    ) -> Vec<(String, DomainMode)> {
        let metrics = Arc::new(TestMetrics::new());
        let mut svc = ThreatIntelAppService::new(
            ThreatIntelEngine::new(1_000_000),
            metrics as Arc<dyn MetricsPort>,
            feeds,
        );
        svc.set_mode(mode);
        let loaded = Arc::new(Mutex::new(Vec::new()));
        svc.set_map_port(Box::new(RecordingMapPort {
            loaded: Arc::clone(&loaded),
        }));
        svc.reload_iocs(iocs).unwrap();
        let mut out = loaded.lock().unwrap().clone();
        out.sort_by(|(a, _), (b, _)| a.cmp(b));
        out
    }

    #[test]
    fn a_feed_action_overrides_the_service_mode() {
        let modes = synced_modes(
            DomainMode::Alert,
            vec![
                feed_with_action("blocking", Some("block")),
                feed_with_action("inheriting", None),
            ],
            vec![
                ioc_from("10.0.0.1", "blocking"),
                ioc_from("10.0.0.2", "inheriting"),
            ],
        );
        assert_eq!(
            modes,
            vec![
                ("10.0.0.1".to_string(), DomainMode::Block),
                ("10.0.0.2".to_string(), DomainMode::Alert),
            ]
        );
    }

    #[test]
    fn a_feed_action_holds_a_feed_back_while_the_estate_blocks() {
        let modes = synced_modes(
            DomainMode::Block,
            vec![
                feed_with_action("evaluating", Some("alert")),
                feed_with_action("inheriting", None),
            ],
            vec![
                ioc_from("10.0.0.1", "evaluating"),
                ioc_from("10.0.0.2", "inheriting"),
            ],
        );
        assert_eq!(
            modes,
            vec![
                ("10.0.0.1".to_string(), DomainMode::Alert),
                ("10.0.0.2".to_string(), DomainMode::Block),
            ]
        );
    }

    #[test]
    fn an_ioc_from_no_configured_feed_inherits_the_service_mode() {
        // What an IOC added through the API carries: a feed identifier that no
        // configured feed answers to.
        let modes = synced_modes(
            DomainMode::Block,
            vec![feed_with_action("blocking", Some("alert"))],
            vec![ioc_from("10.0.0.9", "manual")],
        );
        assert_eq!(modes, vec![("10.0.0.9".to_string(), DomainMode::Block)]);
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
