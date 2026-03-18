use domain::alert::entity::Alert;
use domain::alert::error::AlertError;
use domain::alert::query::AlertQuery;

/// Pluggable alert store for persisting alerts and supporting false-positive
/// marking and filtered queries.
///
/// Implementations may use redb, `SQLite`, or in-memory storage.
pub trait AlertStore: Send + Sync {
    /// Persist a processed alert.
    fn store_alert(&self, alert: &Alert) -> Result<(), AlertError>;

    /// Retrieve a single alert by its ID.
    fn get_alert(&self, id: &str) -> Result<Option<Alert>, AlertError>;

    /// Mark an alert as a false positive.
    ///
    /// Returns `true` if the alert was found and updated, `false` if not found.
    fn mark_false_positive(&self, id: &str) -> Result<bool, AlertError>;

    /// Query stored alerts matching the given filters.
    ///
    /// Results are returned in reverse chronological order (newest first).
    fn query_alerts(&self, query: &AlertQuery) -> Result<Vec<Alert>, AlertError>;

    /// Total number of stored alerts.
    fn alert_count(&self) -> Result<usize, AlertError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, RuleId, Severity};
    use std::sync::Mutex;

    struct InMemoryAlertStore {
        alerts: Mutex<Vec<Alert>>,
    }

    impl InMemoryAlertStore {
        fn new() -> Self {
            Self {
                alerts: Mutex::new(Vec::new()),
            }
        }
    }

    impl AlertStore for InMemoryAlertStore {
        fn store_alert(&self, alert: &Alert) -> Result<(), AlertError> {
            self.alerts.lock().unwrap().push(alert.clone());
            Ok(())
        }

        fn get_alert(&self, id: &str) -> Result<Option<Alert>, AlertError> {
            let alerts = self.alerts.lock().unwrap();
            Ok(alerts.iter().find(|a| a.id == id).cloned())
        }

        fn mark_false_positive(&self, id: &str) -> Result<bool, AlertError> {
            let mut alerts = self.alerts.lock().unwrap();
            if let Some(alert) = alerts.iter_mut().find(|a| a.id == id) {
                alert.false_positive = true;
                Ok(true)
            } else {
                Ok(false)
            }
        }

        fn query_alerts(&self, query: &AlertQuery) -> Result<Vec<Alert>, AlertError> {
            let alerts = self.alerts.lock().unwrap();
            let matched: Vec<Alert> = alerts
                .iter()
                .rev()
                .filter(|a| query.matches(a))
                .skip(query.offset)
                .take(if query.limit == 0 {
                    usize::MAX
                } else {
                    query.limit
                })
                .cloned()
                .collect();
            Ok(matched)
        }

        fn alert_count(&self) -> Result<usize, AlertError> {
            Ok(self.alerts.lock().unwrap().len())
        }
    }

    fn make_alert(id: &str, component: &str) -> Alert {
        Alert {
            id: id.to_string(),
            timestamp_ns: 1_000_000_000,
            component: component.to_string(),
            severity: Severity::High,
            rule_id: RuleId(format!("{component}-001")),
            action: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            is_ipv6: false,
            message: "test alert".to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: None,
        }
    }

    #[test]
    fn store_and_get() {
        let store = InMemoryAlertStore::new();
        let alert = make_alert("alert-1", "ids");
        store.store_alert(&alert).unwrap();

        let retrieved = store.get_alert("alert-1").unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, "alert-1");
        assert_eq!(retrieved.component, "ids");
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let store = InMemoryAlertStore::new();
        let result = store.get_alert("does-not-exist").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn mark_false_positive_updates_flag() {
        let store = InMemoryAlertStore::new();
        let alert = make_alert("alert-fp", "ids");
        store.store_alert(&alert).unwrap();

        let updated = store.mark_false_positive("alert-fp").unwrap();
        assert!(updated);

        let retrieved = store.get_alert("alert-fp").unwrap().unwrap();
        assert!(retrieved.false_positive);
    }

    #[test]
    fn mark_false_positive_not_found() {
        let store = InMemoryAlertStore::new();
        let result = store.mark_false_positive("no-such-alert").unwrap();
        assert!(!result);
    }

    #[test]
    fn query_by_component() {
        let store = InMemoryAlertStore::new();
        store.store_alert(&make_alert("a1", "ids")).unwrap();
        store.store_alert(&make_alert("a2", "dlp")).unwrap();

        let query = AlertQuery {
            component: Some("ids".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = store.query_alerts(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "a1");
    }

    #[test]
    fn alert_count() {
        let store = InMemoryAlertStore::new();
        assert_eq!(store.alert_count().unwrap(), 0);

        store.store_alert(&make_alert("a1", "ids")).unwrap();
        store.store_alert(&make_alert("a2", "dlp")).unwrap();
        assert_eq!(store.alert_count().unwrap(), 2);
    }
}
