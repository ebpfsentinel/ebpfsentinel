use std::sync::Arc;

use domain::common::entity::{DomainMode, RuleId};
use domain::common::error::DomainError;
use domain::dlp::engine::DlpEngine;
use domain::dlp::entity::{DlpMatch, DlpPattern};
use ports::secondary::metrics_port::MetricsPort;

/// Application-level DLP service.
///
/// Orchestrates the domain engine and metrics updates.
/// Unlike IDS, DLP is purely userspace — no eBPF map synchronization needed.
pub struct DlpAppService {
    engine: DlpEngine,
    metrics: Arc<dyn MetricsPort>,
    mode: DomainMode,
    enabled: bool,
}

impl DlpAppService {
    pub fn new(engine: DlpEngine, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine,
            metrics,
            mode: DomainMode::default(),
            enabled: true,
        }
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

    pub fn add_pattern(&mut self, pattern: DlpPattern) -> Result<(), DomainError> {
        self.engine.add_pattern(pattern)?;
        self.update_metrics();
        Ok(())
    }

    pub fn remove_pattern(&mut self, id: &RuleId) -> Result<(), DomainError> {
        self.engine.remove_pattern(id)?;
        self.update_metrics();
        Ok(())
    }

    pub fn reload_patterns(&mut self, patterns: Vec<DlpPattern>) -> Result<(), DomainError> {
        self.engine.reload(patterns)?;
        self.update_metrics();
        Ok(())
    }

    pub fn list_patterns(&self) -> &[DlpPattern] {
        self.engine.patterns()
    }

    pub fn pattern_count(&self) -> usize {
        self.engine.pattern_count()
    }

    pub fn scan_data(&self, data: &[u8]) -> Vec<DlpMatch> {
        self.engine.scan_data(data)
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("dlp", self.engine.pattern_count() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::Severity;
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

    fn make_pattern(id: &str) -> DlpPattern {
        DlpPattern {
            id: RuleId(id.to_string()),
            name: format!("Test {id}"),
            regex: r"\d{4}".to_string(),
            severity: Severity::High,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            description: String::new(),
            enabled: true,
        }
    }

    fn make_service() -> (DlpAppService, Arc<TestMetrics>) {
        let metrics = Arc::new(TestMetrics::new());
        let svc = DlpAppService::new(
            DlpEngine::new(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        (svc, metrics)
    }

    #[test]
    fn add_and_list_patterns() {
        let (mut svc, metrics) = make_service();
        svc.add_pattern(make_pattern("dlp-001")).unwrap();
        svc.add_pattern(make_pattern("dlp-002")).unwrap();
        assert_eq!(svc.list_patterns().len(), 2);
        assert_eq!(svc.pattern_count(), 2);
        assert_eq!(metrics.rules_loaded.load(Ordering::Relaxed), 2);
        assert_eq!(*metrics.last_component.lock().unwrap(), "dlp");
    }

    #[test]
    fn add_duplicate_fails() {
        let (mut svc, _) = make_service();
        svc.add_pattern(make_pattern("dlp-001")).unwrap();
        assert!(svc.add_pattern(make_pattern("dlp-001")).is_err());
        assert_eq!(svc.pattern_count(), 1);
    }

    #[test]
    fn remove_pattern_succeeds() {
        let (mut svc, metrics) = make_service();
        svc.add_pattern(make_pattern("dlp-001")).unwrap();
        svc.remove_pattern(&RuleId("dlp-001".to_string())).unwrap();
        assert_eq!(svc.pattern_count(), 0);
        assert_eq!(metrics.rules_loaded.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn remove_nonexistent_fails() {
        let (mut svc, _) = make_service();
        assert!(svc.remove_pattern(&RuleId("nope".to_string())).is_err());
    }

    #[test]
    fn reload_replaces_all() {
        let (mut svc, metrics) = make_service();
        svc.add_pattern(make_pattern("old")).unwrap();
        svc.reload_patterns(vec![make_pattern("new-1"), make_pattern("new-2")])
            .unwrap();
        assert_eq!(svc.pattern_count(), 2);
        assert_eq!(svc.list_patterns()[0].id.0, "new-1");
        assert_eq!(metrics.rules_loaded.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn scan_data_delegates() {
        let (mut svc, _) = make_service();
        svc.add_pattern(make_pattern("dlp-001")).unwrap();
        let matches = svc.scan_data(b"code 1234 here");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn mode_and_enabled_getters() {
        let (mut svc, _) = make_service();
        assert_eq!(svc.mode(), DomainMode::Alert);
        assert!(svc.enabled());
        svc.set_mode(DomainMode::Block);
        svc.set_enabled(false);
        assert_eq!(svc.mode(), DomainMode::Block);
        assert!(!svc.enabled());
    }
}
