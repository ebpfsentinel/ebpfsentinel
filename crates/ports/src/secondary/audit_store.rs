use domain::audit::entity::AuditEntry;
use domain::audit::error::AuditError;
use domain::audit::query::AuditQuery;

/// Pluggable audit log store for persisting and querying audit entries.
///
/// Unlike `AuditSink` (write-only structured log output), `AuditStore`
/// supports both writing and querying, enabling the REST API to retrieve
/// filtered audit logs. Implementations may use redb, `SQLite`, or in-memory
/// storage.
pub trait AuditStore: Send + Sync {
    /// Persist a single audit entry.
    fn store_entry(&self, entry: &AuditEntry) -> Result<(), AuditError>;

    /// Query stored audit entries matching the given filters.
    ///
    /// Results are returned in reverse chronological order (newest first).
    fn query_entries(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>, AuditError>;

    /// Remove entries older than `before_ns` (nanoseconds since epoch).
    ///
    /// Returns the number of entries removed.
    fn cleanup_expired(&self, before_ns: u64) -> Result<usize, AuditError>;

    /// Total number of stored entries.
    fn entry_count(&self) -> Result<usize, AuditError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::entity::{AuditAction, AuditComponent};
    use std::sync::Mutex;

    struct InMemoryAuditStore {
        entries: Mutex<Vec<AuditEntry>>,
    }

    impl InMemoryAuditStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(Vec::new()),
            }
        }
    }

    impl AuditStore for InMemoryAuditStore {
        fn store_entry(&self, entry: &AuditEntry) -> Result<(), AuditError> {
            self.entries.lock().unwrap().push(entry.clone());
            Ok(())
        }

        fn query_entries(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>, AuditError> {
            let entries = self.entries.lock().unwrap();
            let matched: Vec<AuditEntry> = entries
                .iter()
                .rev()
                .filter(|e| query.matches(e))
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

        fn cleanup_expired(&self, before_ns: u64) -> Result<usize, AuditError> {
            let mut entries = self.entries.lock().unwrap();
            let before_len = entries.len();
            entries.retain(|e| e.timestamp_ns >= before_ns);
            Ok(before_len - entries.len())
        }

        fn entry_count(&self) -> Result<usize, AuditError> {
            Ok(self.entries.lock().unwrap().len())
        }
    }

    fn make_entry(component: AuditComponent, ts: u64) -> AuditEntry {
        AuditEntry::security_decision(
            component,
            AuditAction::Drop,
            ts,
            [0xC0A8_0001, 0, 0, 0],
            [0x0A00_0001, 0, 0, 0],
            false,
            12345,
            80,
            6,
            "rule-001",
            "test entry",
        )
    }

    #[test]
    fn store_and_query_all() {
        let store = InMemoryAuditStore::new();
        let entry = make_entry(AuditComponent::Firewall, 1_000_000_000);
        store.store_entry(&entry).unwrap();

        let query = AuditQuery::default();
        let results = store.query_entries(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].component, AuditComponent::Firewall);
    }

    #[test]
    fn query_by_component_filter() {
        let store = InMemoryAuditStore::new();
        store
            .store_entry(&make_entry(AuditComponent::Firewall, 1_000))
            .unwrap();
        store
            .store_entry(&make_entry(AuditComponent::Ids, 2_000))
            .unwrap();

        let query = AuditQuery {
            component: Some(AuditComponent::Ids),
            ..Default::default()
        };
        let results = store.query_entries(&query).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].component, AuditComponent::Ids);
    }

    #[test]
    fn cleanup_expired_removes_old() {
        let store = InMemoryAuditStore::new();
        store
            .store_entry(&make_entry(AuditComponent::Firewall, 100))
            .unwrap();
        store
            .store_entry(&make_entry(AuditComponent::Ids, 500))
            .unwrap();
        store
            .store_entry(&make_entry(AuditComponent::Dlp, 1_000))
            .unwrap();

        let removed = store.cleanup_expired(500).unwrap();
        assert_eq!(removed, 1);
        assert_eq!(store.entry_count().unwrap(), 2);
    }

    #[test]
    fn entry_count() {
        let store = InMemoryAuditStore::new();
        assert_eq!(store.entry_count().unwrap(), 0);

        store
            .store_entry(&make_entry(AuditComponent::Firewall, 1_000))
            .unwrap();
        store
            .store_entry(&make_entry(AuditComponent::Ids, 2_000))
            .unwrap();
        assert_eq!(store.entry_count().unwrap(), 2);
    }
}
