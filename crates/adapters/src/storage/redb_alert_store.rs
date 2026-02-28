use std::path::Path;
use std::sync::Mutex;

use domain::alert::entity::Alert;
use domain::alert::error::AlertError;
use domain::alert::query::AlertQuery;
use ports::secondary::alert_store::AlertStore;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

/// redb table: key = `alert_id`, value = JSON-serialized `Alert`.
const ALERT_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("alerts");

/// Maximum number of alerts to keep. Oldest are evicted when exceeded.
const DEFAULT_MAX_ALERTS: usize = 50_000;

/// Persistent alert store backed by redb.
///
/// Stores alerts keyed by their unique ID. Supports query with filters,
/// false-positive marking, and automatic eviction when the store exceeds
/// `max_alerts`.
pub struct RedbAlertStore {
    db: Database,
    max_alerts: usize,
    /// Serialize writes so eviction + insert is atomic.
    write_lock: Mutex<()>,
}

impl RedbAlertStore {
    /// Open (or create) a redb database at `path`.
    pub fn open(path: &Path) -> Result<Self, AlertError> {
        Self::open_with_max(path, DEFAULT_MAX_ALERTS)
    }

    /// Open with a custom max alerts limit (useful for testing).
    pub fn open_with_max(path: &Path, max_alerts: usize) -> Result<Self, AlertError> {
        let db = Database::create(path)
            .map_err(|e| AlertError::StoreFailed(format!("redb open failed: {e}")))?;

        // Ensure the table exists.
        let txn = db
            .begin_write()
            .map_err(|e| AlertError::StoreFailed(format!("redb txn begin: {e}")))?;
        {
            let _table = txn
                .open_table(ALERT_TABLE)
                .map_err(|e| AlertError::StoreFailed(format!("redb table create: {e}")))?;
        }
        txn.commit()
            .map_err(|e| AlertError::StoreFailed(format!("redb commit: {e}")))?;

        Ok(Self {
            db,
            max_alerts,
            write_lock: Mutex::new(()),
        })
    }

    /// Evict oldest alerts (by insertion order) if the store exceeds `max_alerts`.
    fn evict_if_needed(&self) -> Result<(), AlertError> {
        let count = self.alert_count()?;
        if count <= self.max_alerts {
            return Ok(());
        }
        let to_remove = count - self.max_alerts;

        // Collect the oldest alerts (by timestamp) and remove them.
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AlertError::StoreFailed(format!("redb evict read: {e}")))?;
        let table = txn
            .open_table(ALERT_TABLE)
            .map_err(|e| AlertError::StoreFailed(format!("redb evict table: {e}")))?;

        // Collect all (id, timestamp_ns) pairs, sort by timestamp, pick oldest.
        let mut entries: Vec<(String, u64)> = table
            .iter()
            .map_err(|e| AlertError::StoreFailed(format!("redb evict iter: {e}")))?
            .filter_map(Result::ok)
            .filter_map(|(k, v)| {
                let alert: Alert = serde_json::from_slice(v.value()).ok()?;
                Some((k.value().to_string(), alert.timestamp_ns))
            })
            .collect();
        entries.sort_by_key(|(_id, ts)| *ts);

        let keys_to_remove: Vec<String> = entries
            .into_iter()
            .take(to_remove)
            .map(|(id, _)| id)
            .collect();
        drop(table);
        drop(txn);

        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| AlertError::StoreFailed(format!("redb evict write: {e}")))?;
        {
            let mut table = wtxn
                .open_table(ALERT_TABLE)
                .map_err(|e| AlertError::StoreFailed(format!("redb evict table: {e}")))?;
            for key in &keys_to_remove {
                let _ = table.remove(key.as_str());
            }
        }
        wtxn.commit()
            .map_err(|e| AlertError::StoreFailed(format!("redb evict commit: {e}")))?;

        Ok(())
    }
}

impl AlertStore for RedbAlertStore {
    fn store_alert(&self, alert: &Alert) -> Result<(), AlertError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| AlertError::StoreFailed(format!("lock poisoned: {e}")))?;

        let value = serde_json::to_vec(alert)
            .map_err(|e| AlertError::StoreFailed(format!("serialize: {e}")))?;

        let txn = self
            .db
            .begin_write()
            .map_err(|e| AlertError::StoreFailed(format!("redb write txn: {e}")))?;
        {
            let mut table = txn
                .open_table(ALERT_TABLE)
                .map_err(|e| AlertError::StoreFailed(format!("redb write table: {e}")))?;
            table
                .insert(alert.id.as_str(), value.as_slice())
                .map_err(|e| AlertError::StoreFailed(format!("redb insert: {e}")))?;
        }
        txn.commit()
            .map_err(|e| AlertError::StoreFailed(format!("redb write commit: {e}")))?;

        self.evict_if_needed()?;

        Ok(())
    }

    fn get_alert(&self, id: &str) -> Result<Option<Alert>, AlertError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AlertError::QueryFailed(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(ALERT_TABLE)
            .map_err(|e| AlertError::QueryFailed(format!("redb read table: {e}")))?;

        let result = table
            .get(id)
            .map_err(|e| AlertError::QueryFailed(format!("redb get: {e}")))?;

        match result {
            Some(guard) => {
                let alert: Alert = serde_json::from_slice(guard.value())
                    .map_err(|e| AlertError::QueryFailed(format!("deserialize: {e}")))?;
                Ok(Some(alert))
            }
            None => Ok(None),
        }
    }

    fn mark_false_positive(&self, id: &str) -> Result<bool, AlertError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| AlertError::StoreFailed(format!("lock poisoned: {e}")))?;

        // Read the existing alert.
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AlertError::QueryFailed(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(ALERT_TABLE)
            .map_err(|e| AlertError::QueryFailed(format!("redb read table: {e}")))?;

        let existing = table
            .get(id)
            .map_err(|e| AlertError::QueryFailed(format!("redb get: {e}")))?;

        let mut alert: Alert = match existing {
            Some(guard) => serde_json::from_slice(guard.value())
                .map_err(|e| AlertError::QueryFailed(format!("deserialize: {e}")))?,
            None => return Ok(false),
        };
        drop(table);
        drop(txn);

        // Update and write back.
        alert.false_positive = true;
        let value = serde_json::to_vec(&alert)
            .map_err(|e| AlertError::StoreFailed(format!("serialize: {e}")))?;

        let wtxn = self
            .db
            .begin_write()
            .map_err(|e| AlertError::StoreFailed(format!("redb write txn: {e}")))?;
        {
            let mut table = wtxn
                .open_table(ALERT_TABLE)
                .map_err(|e| AlertError::StoreFailed(format!("redb write table: {e}")))?;
            table
                .insert(id, value.as_slice())
                .map_err(|e| AlertError::StoreFailed(format!("redb insert: {e}")))?;
        }
        wtxn.commit()
            .map_err(|e| AlertError::StoreFailed(format!("redb write commit: {e}")))?;

        Ok(true)
    }

    fn query_alerts(&self, query: &AlertQuery) -> Result<Vec<Alert>, AlertError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AlertError::QueryFailed(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(ALERT_TABLE)
            .map_err(|e| AlertError::QueryFailed(format!("redb read table: {e}")))?;

        let mut alerts: Vec<Alert> = table
            .iter()
            .map_err(|e| AlertError::QueryFailed(format!("redb iter: {e}")))?
            .filter_map(Result::ok)
            .filter_map(|(_k, v)| serde_json::from_slice::<Alert>(v.value()).ok())
            .filter(|a| query.matches(a))
            .collect();

        // Sort newest first by timestamp.
        alerts.sort_by(|a, b| b.timestamp_ns.cmp(&a.timestamp_ns));

        // Apply offset/limit.
        let total = alerts.len();
        let start = query.offset.min(total);
        let end = (start + query.limit).min(total);

        Ok(alerts.drain(start..end).collect())
    }

    fn alert_count(&self) -> Result<usize, AlertError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AlertError::QueryFailed(format!("redb count txn: {e}")))?;
        let table = txn
            .open_table(ALERT_TABLE)
            .map_err(|e| AlertError::QueryFailed(format!("redb count table: {e}")))?;
        let count = table
            .len()
            .map_err(|e| AlertError::QueryFailed(format!("redb count: {e}")))?;
        #[allow(clippy::cast_possible_truncation)]
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, RuleId, Severity};
    use tempfile::NamedTempFile;

    fn make_store(max: usize) -> (RedbAlertStore, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let store = RedbAlertStore::open_with_max(tmp.path(), max).unwrap();
        (store, tmp)
    }

    fn make_alert(id: &str, component: &str, severity: Severity, rule_id: &str, ts: u64) -> Alert {
        Alert {
            id: id.to_string(),
            timestamp_ns: ts,
            component: component.to_string(),
            severity,
            rule_id: RuleId(rule_id.to_string()),
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
        }
    }

    #[test]
    fn store_and_get_alert() {
        let (store, _tmp) = make_store(100);
        let alert = make_alert("a1", "ids", Severity::High, "ids-001", 1000);
        store.store_alert(&alert).unwrap();

        let result = store.get_alert("a1").unwrap();
        assert!(result.is_some());
        let a = result.unwrap();
        assert_eq!(a.id, "a1");
        assert_eq!(a.component, "ids");
        assert!(!a.false_positive);
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let (store, _tmp) = make_store(100);
        assert!(store.get_alert("missing").unwrap().is_none());
    }

    #[test]
    fn mark_false_positive() {
        let (store, _tmp) = make_store(100);
        let alert = make_alert("a1", "ids", Severity::High, "ids-001", 1000);
        store.store_alert(&alert).unwrap();

        let marked = store.mark_false_positive("a1").unwrap();
        assert!(marked);

        let a = store.get_alert("a1").unwrap().unwrap();
        assert!(a.false_positive);
    }

    #[test]
    fn mark_false_positive_not_found() {
        let (store, _tmp) = make_store(100);
        let marked = store.mark_false_positive("missing").unwrap();
        assert!(!marked);
    }

    #[test]
    fn query_all() {
        let (store, _tmp) = make_store(100);
        store
            .store_alert(&make_alert("a1", "ids", Severity::High, "ids-001", 100))
            .unwrap();
        store
            .store_alert(&make_alert("a2", "dlp", Severity::Low, "dlp-001", 200))
            .unwrap();

        let q = AlertQuery {
            limit: 100,
            ..Default::default()
        };
        let results = store.query_alerts(&q).unwrap();
        assert_eq!(results.len(), 2);
        // Newest first
        assert_eq!(results[0].id, "a2");
        assert_eq!(results[1].id, "a1");
    }

    #[test]
    fn query_with_false_positive_filter() {
        let (store, _tmp) = make_store(100);
        store
            .store_alert(&make_alert("a1", "ids", Severity::High, "ids-001", 100))
            .unwrap();
        store
            .store_alert(&make_alert("a2", "ids", Severity::High, "ids-002", 200))
            .unwrap();
        store.mark_false_positive("a1").unwrap();

        let q = AlertQuery {
            false_positive: Some(true),
            limit: 100,
            ..Default::default()
        };
        let results = store.query_alerts(&q).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "a1");
    }

    #[test]
    fn query_with_component_filter() {
        let (store, _tmp) = make_store(100);
        store
            .store_alert(&make_alert("a1", "ids", Severity::High, "ids-001", 100))
            .unwrap();
        store
            .store_alert(&make_alert("a2", "dlp", Severity::Low, "dlp-001", 200))
            .unwrap();

        let q = AlertQuery {
            component: Some("dlp".to_string()),
            limit: 100,
            ..Default::default()
        };
        let results = store.query_alerts(&q).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].component, "dlp");
    }

    #[test]
    fn query_with_severity_filter() {
        let (store, _tmp) = make_store(100);
        store
            .store_alert(&make_alert("a1", "ids", Severity::Low, "ids-001", 100))
            .unwrap();
        store
            .store_alert(&make_alert("a2", "ids", Severity::High, "ids-002", 200))
            .unwrap();
        store
            .store_alert(&make_alert("a3", "ids", Severity::Critical, "ids-003", 300))
            .unwrap();

        let q = AlertQuery {
            min_severity: Some(Severity::High),
            limit: 100,
            ..Default::default()
        };
        let results = store.query_alerts(&q).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_offset_and_limit() {
        let (store, _tmp) = make_store(100);
        for i in 1..=10 {
            store
                .store_alert(&make_alert(
                    &format!("a{i}"),
                    "ids",
                    Severity::High,
                    "ids-001",
                    i * 100,
                ))
                .unwrap();
        }

        let q = AlertQuery {
            limit: 3,
            offset: 2,
            ..Default::default()
        };
        let results = store.query_alerts(&q).unwrap();
        assert_eq!(results.len(), 3);
        // Newest first: a10(1000), a9(900), a8(800), a7(700)...
        // offset 2: skip a10, a9 → a8, a7, a6
        assert_eq!(results[0].timestamp_ns, 800);
    }

    #[test]
    fn eviction_enforces_max() {
        let (store, _tmp) = make_store(5);
        for i in 1..=10 {
            store
                .store_alert(&make_alert(
                    &format!("a{i}"),
                    "ids",
                    Severity::High,
                    "ids-001",
                    i * 100,
                ))
                .unwrap();
        }
        assert!(store.alert_count().unwrap() <= 5);
    }

    #[test]
    fn alert_count_accurate() {
        let (store, _tmp) = make_store(100);
        assert_eq!(store.alert_count().unwrap(), 0);
        store
            .store_alert(&make_alert("a1", "ids", Severity::High, "ids-001", 100))
            .unwrap();
        assert_eq!(store.alert_count().unwrap(), 1);
        store
            .store_alert(&make_alert("a2", "ids", Severity::High, "ids-002", 200))
            .unwrap();
        assert_eq!(store.alert_count().unwrap(), 2);
    }
}
