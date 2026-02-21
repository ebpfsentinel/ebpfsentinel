use std::sync::Arc;

use domain::audit::entity::{AuditAction, AuditComponent, AuditEntry};
use domain::audit::error::AuditError;
use domain::audit::query::AuditQuery;
use domain::audit::rule_change::{ChangeActor, RuleChangeEntry};
use ports::secondary::audit_sink::AuditSink;
use ports::secondary::audit_store::AuditStore;
use ports::secondary::rule_change_store::RuleChangeStore;

/// Application-layer audit service that delegates to a pluggable `AuditSink`
/// and an optional persistent `AuditStore`.
///
/// Manages the enabled/disabled state of audit logging and provides
/// convenience methods for recording security decisions from all engines.
/// When a store is present, entries are dual-written (structured log + store)
/// and can be queried via the REST API.
pub struct AuditAppService {
    sink: Arc<dyn AuditSink>,
    store: Option<Arc<dyn AuditStore>>,
    rule_change_store: Option<Arc<dyn RuleChangeStore>>,
    enabled: bool,
}

impl AuditAppService {
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self {
            sink,
            store: None,
            rule_change_store: None,
            enabled: true,
        }
    }

    /// Attach a persistent audit store for query support.
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn AuditStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Attach a persistent rule change store for version history.
    #[must_use]
    pub fn with_rule_change_store(mut self, store: Arc<dyn RuleChangeStore>) -> Self {
        self.rule_change_store = Some(store);
        self
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether a persistent store is available for queries.
    pub fn has_store(&self) -> bool {
        self.store.is_some()
    }

    /// Whether a rule change store is available for version history.
    pub fn has_rule_change_store(&self) -> bool {
        self.rule_change_store.is_some()
    }

    /// Record a network security decision from any engine.
    ///
    /// This is the primary cross-cutting audit method. It is a no-op
    /// when audit logging is disabled. Errors from the sink are logged
    /// but do not propagate (audit should never block the data path).
    #[allow(clippy::too_many_arguments)]
    pub fn record_security_decision(
        &self,
        component: AuditComponent,
        action: AuditAction,
        timestamp_ns: u64,
        src_addr: [u32; 4],
        dst_addr: [u32; 4],
        is_ipv6: bool,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        rule_id: &str,
        detail: &str,
    ) {
        if !self.enabled {
            return;
        }

        let entry = AuditEntry::security_decision(
            component,
            action,
            timestamp_ns,
            src_addr,
            dst_addr,
            is_ipv6,
            src_port,
            dst_port,
            protocol,
            rule_id,
            detail,
        );

        self.write_entry(&entry);
    }

    /// Record a configuration change (non-network).
    pub fn record_config_change(&self, action: AuditAction, detail: &str) {
        if !self.enabled {
            return;
        }

        let entry = AuditEntry::config_change(action, detail);
        self.write_entry(&entry);
    }

    /// Record a rule change with before/after snapshots and version tracking.
    ///
    /// No-op if disabled or no rule change store is configured.
    /// Also writes a regular audit entry via `write_entry()`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_rule_change(
        &self,
        component: AuditComponent,
        action: AuditAction,
        actor: ChangeActor,
        rule_id: &str,
        before_json: Option<String>,
        after_json: Option<String>,
    ) {
        if !self.enabled {
            return;
        }

        // Write a regular audit entry for the audit log
        let detail = format!("{action} rule {rule_id} by {actor}");
        let entry = AuditEntry::config_change(action, &detail);
        self.write_entry(&entry);

        // Write versioned rule change entry if store is available
        if let Some(ref store) = self.rule_change_store {
            let version = match store.next_version(rule_id) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, rule_id = %rule_id, "rule change store version query failed");
                    return;
                }
            };

            let change_entry = RuleChangeEntry::new(
                rule_id.to_string(),
                version,
                component,
                action,
                actor,
                before_json,
                after_json,
            );

            if let Err(e) = store.store_change(&change_entry) {
                tracing::warn!(error = %e, rule_id = %rule_id, "rule change store write failed");
            }
        }
    }

    /// Query rule version history. Returns an error if no rule change store is configured.
    pub fn query_rule_history(
        &self,
        rule_id: &str,
        limit: usize,
    ) -> Result<Vec<RuleChangeEntry>, AuditError> {
        let store = self.rule_change_store.as_ref().ok_or_else(|| {
            AuditError::StoreUnavailable("no rule change store configured".to_string())
        })?;
        store.query_rule_history(rule_id, limit)
    }

    /// Query stored audit logs. Returns an error if no store is configured.
    pub fn query_logs(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>, AuditError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| AuditError::StoreUnavailable("no audit store configured".to_string()))?;
        store.query_entries(query)
    }

    /// Get the total count of stored audit entries.
    pub fn stored_entry_count(&self) -> Result<usize, AuditError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| AuditError::StoreUnavailable("no audit store configured".to_string()))?;
        store.entry_count()
    }

    /// Internal: write to both sink and store.
    fn write_entry(&self, entry: &AuditEntry) {
        if let Err(e) = self.sink.write_entry(entry) {
            tracing::warn!(error = %e, "audit sink write failed");
        }

        if let Some(ref store) = self.store
            && let Err(e) = store.store_entry(entry)
        {
            tracing::warn!(error = %e, "audit store write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingSink {
        write_calls: AtomicU32,
    }

    impl CountingSink {
        fn new() -> Self {
            Self {
                write_calls: AtomicU32::new(0),
            }
        }
    }

    impl AuditSink for CountingSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            self.write_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct FailingSink;

    impl AuditSink for FailingSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Err(AuditError::WriteFailed("disk full".to_string()))
        }
    }

    struct CountingStore {
        store_calls: AtomicU32,
    }

    impl CountingStore {
        fn new() -> Self {
            Self {
                store_calls: AtomicU32::new(0),
            }
        }
    }

    impl AuditStore for CountingStore {
        fn store_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            self.store_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn query_entries(&self, _query: &AuditQuery) -> Result<Vec<AuditEntry>, AuditError> {
            Ok(vec![])
        }
        fn cleanup_expired(&self, _before_ns: u64) -> Result<usize, AuditError> {
            Ok(0)
        }
        fn entry_count(&self) -> Result<usize, AuditError> {
            Ok(0)
        }
    }

    struct MockRuleChangeStore {
        store_calls: AtomicU32,
        next_ver: u64,
    }

    impl MockRuleChangeStore {
        fn new(next_ver: u64) -> Self {
            Self {
                store_calls: AtomicU32::new(0),
                next_ver,
            }
        }
    }

    impl RuleChangeStore for MockRuleChangeStore {
        fn store_change(&self, _entry: &RuleChangeEntry) -> Result<(), AuditError> {
            self.store_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn query_rule_history(
            &self,
            _rule_id: &str,
            _limit: usize,
        ) -> Result<Vec<RuleChangeEntry>, AuditError> {
            Ok(vec![])
        }
        fn next_version(&self, _rule_id: &str) -> Result<u64, AuditError> {
            Ok(self.next_ver)
        }
    }

    #[test]
    fn records_security_decision() {
        let sink = Arc::new(CountingSink::new());
        let svc = AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>);

        svc.record_security_decision(
            AuditComponent::Firewall,
            AuditAction::Drop,
            1_000_000_000,
            [0xC0A80001, 0, 0, 0],
            [0x0A000001, 0, 0, 0],
            false,
            12345,
            80,
            6,
            "fw-001",
            "Denied by rule",
        );

        assert_eq!(sink.write_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn disabled_service_does_not_write() {
        let sink = Arc::new(CountingSink::new());
        let mut svc = AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>);
        svc.set_enabled(false);

        svc.record_security_decision(
            AuditComponent::Firewall,
            AuditAction::Pass,
            0,
            [0; 4],
            [0; 4],
            false,
            0,
            0,
            0,
            "",
            "",
        );

        assert_eq!(sink.write_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn records_config_change() {
        let sink = Arc::new(CountingSink::new());
        let svc = AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>);

        svc.record_config_change(AuditAction::ConfigChanged, "firewall reloaded");

        assert_eq!(sink.write_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn sink_error_does_not_panic() {
        let sink: Arc<dyn AuditSink> = Arc::new(FailingSink);
        let svc = AuditAppService::new(sink);

        svc.record_security_decision(
            AuditComponent::Ids,
            AuditAction::Alert,
            0,
            [0; 4],
            [0; 4],
            false,
            0,
            0,
            0,
            "ids-001",
            "test",
        );
    }

    #[test]
    fn enabled_defaults_to_true() {
        let sink: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let svc = AuditAppService::new(sink);
        assert!(svc.enabled());
    }

    #[test]
    fn toggle_enabled() {
        let sink: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let mut svc = AuditAppService::new(sink);
        assert!(svc.enabled());
        svc.set_enabled(false);
        assert!(!svc.enabled());
        svc.set_enabled(true);
        assert!(svc.enabled());
    }

    #[test]
    fn dual_writes_to_sink_and_store() {
        let sink = Arc::new(CountingSink::new());
        let store = Arc::new(CountingStore::new());
        let svc = AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>)
            .with_store(Arc::clone(&store) as Arc<dyn AuditStore>);

        svc.record_security_decision(
            AuditComponent::Firewall,
            AuditAction::Drop,
            1_000,
            [0; 4],
            [0; 4],
            false,
            0,
            0,
            0,
            "fw-001",
            "test",
        );

        assert_eq!(sink.write_calls.load(Ordering::Relaxed), 1);
        assert_eq!(store.store_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn query_without_store_returns_error() {
        let sink: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let svc = AuditAppService::new(sink);
        let q = AuditQuery {
            limit: 10,
            ..Default::default()
        };
        assert!(svc.query_logs(&q).is_err());
    }

    #[test]
    fn query_with_store_returns_ok() {
        let sink: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let store: Arc<dyn AuditStore> = Arc::new(CountingStore::new());
        let svc = AuditAppService::new(sink).with_store(store);
        let q = AuditQuery {
            limit: 10,
            ..Default::default()
        };
        assert!(svc.query_logs(&q).is_ok());
    }

    #[test]
    fn has_store_reflects_configuration() {
        let sink: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let svc = AuditAppService::new(sink);
        assert!(!svc.has_store());

        let sink2: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let store: Arc<dyn AuditStore> = Arc::new(CountingStore::new());
        let svc2 = AuditAppService::new(sink2).with_store(store);
        assert!(svc2.has_store());
    }

    #[test]
    fn record_rule_change_writes_to_both_stores() {
        let sink = Arc::new(CountingSink::new());
        let rc_store = Arc::new(MockRuleChangeStore::new(1));
        let svc = AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>)
            .with_rule_change_store(Arc::clone(&rc_store) as Arc<dyn RuleChangeStore>);

        svc.record_rule_change(
            AuditComponent::Firewall,
            AuditAction::RuleAdded,
            ChangeActor::Api,
            "fw-001",
            None,
            Some(r#"{"id":"fw-001"}"#.to_string()),
        );

        // Sink gets the audit entry
        assert_eq!(sink.write_calls.load(Ordering::Relaxed), 1);
        // Rule change store gets the versioned entry
        assert_eq!(rc_store.store_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn record_rule_change_without_store_only_writes_audit() {
        let sink = Arc::new(CountingSink::new());
        let svc = AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>);

        svc.record_rule_change(
            AuditComponent::Firewall,
            AuditAction::RuleAdded,
            ChangeActor::Api,
            "fw-001",
            None,
            Some(r#"{"id":"fw-001"}"#.to_string()),
        );

        // Sink still gets the audit entry
        assert_eq!(sink.write_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn disabled_service_does_not_record_rule_change() {
        let sink = Arc::new(CountingSink::new());
        let rc_store = Arc::new(MockRuleChangeStore::new(1));
        let mut svc = AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>)
            .with_rule_change_store(Arc::clone(&rc_store) as Arc<dyn RuleChangeStore>);
        svc.set_enabled(false);

        svc.record_rule_change(
            AuditComponent::Firewall,
            AuditAction::RuleAdded,
            ChangeActor::Api,
            "fw-001",
            None,
            None,
        );

        assert_eq!(sink.write_calls.load(Ordering::Relaxed), 0);
        assert_eq!(rc_store.store_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn query_rule_history_without_store_returns_error() {
        let sink: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let svc = AuditAppService::new(sink);
        assert!(svc.query_rule_history("fw-001", 50).is_err());
    }

    #[test]
    fn query_rule_history_with_store_returns_ok() {
        let sink: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let rc_store: Arc<dyn RuleChangeStore> = Arc::new(MockRuleChangeStore::new(1));
        let svc = AuditAppService::new(sink).with_rule_change_store(rc_store);
        assert!(svc.query_rule_history("fw-001", 50).is_ok());
    }

    #[test]
    fn has_rule_change_store_reflects_configuration() {
        let sink: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let svc = AuditAppService::new(sink);
        assert!(!svc.has_rule_change_store());

        let sink2: Arc<dyn AuditSink> = Arc::new(CountingSink::new());
        let rc_store: Arc<dyn RuleChangeStore> = Arc::new(MockRuleChangeStore::new(1));
        let svc2 = AuditAppService::new(sink2).with_rule_change_store(rc_store);
        assert!(svc2.has_rule_change_store());
    }
}
