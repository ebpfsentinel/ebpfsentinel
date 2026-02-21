use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use domain::audit::entity::AuditEntry;
use domain::audit::error::AuditError;
use domain::audit::query::AuditQuery;
use ports::secondary::audit_store::AuditStore;
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};

/// redb table: key = `(timestamp_ns, sequence)` to guarantee uniqueness,
/// value = JSON-serialized `AuditEntry`.
const AUDIT_TABLE: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("audit_entries");

/// Persistent audit log store backed by redb.
///
/// Stores entries keyed by `(timestamp_ns, seq)` so that entries with
/// identical timestamps are still unique. Supports configurable buffer
/// size (max entries) — oldest entries are evicted when the limit is
/// reached.
pub struct RedbAuditStore {
    db: Database,
    max_entries: usize,
    seq: AtomicU64,
    /// Serialize writes so eviction + insert is atomic.
    write_lock: Mutex<()>,
}

impl RedbAuditStore {
    /// Open (or create) a redb database at `path`.
    pub fn open(path: &Path, max_entries: usize) -> Result<Self, AuditError> {
        let db = Database::create(path)
            .map_err(|e| AuditError::WriteFailed(format!("redb open failed: {e}")))?;

        // Ensure the table exists.
        let txn = db
            .begin_write()
            .map_err(|e| AuditError::WriteFailed(format!("redb txn begin: {e}")))?;
        {
            let _table = txn
                .open_table(AUDIT_TABLE)
                .map_err(|e| AuditError::WriteFailed(format!("redb table create: {e}")))?;
        }
        txn.commit()
            .map_err(|e| AuditError::WriteFailed(format!("redb commit: {e}")))?;

        Ok(Self {
            db,
            max_entries,
            seq: AtomicU64::new(0),
            write_lock: Mutex::new(()),
        })
    }

    /// Evict oldest entries if the store exceeds `max_entries`.
    fn evict_if_needed(&self) -> Result<(), AuditError> {
        let count = self.entry_count()?;
        if count <= self.max_entries {
            return Ok(());
        }
        let to_remove = count - self.max_entries;

        let txn = self
            .db
            .begin_write()
            .map_err(|e| AuditError::WriteFailed(format!("redb evict txn: {e}")))?;
        {
            let mut table = txn
                .open_table(AUDIT_TABLE)
                .map_err(|e| AuditError::WriteFailed(format!("redb evict table: {e}")))?;

            let keys: Vec<(u64, u64)> = table
                .iter()
                .map_err(|e| AuditError::WriteFailed(format!("redb iter: {e}")))?
                .filter_map(Result::ok)
                .take(to_remove)
                .map(|(k, _v)| k.value())
                .collect();

            for key in keys {
                let _ = table.remove(key);
            }
        }
        txn.commit()
            .map_err(|e| AuditError::WriteFailed(format!("redb evict commit: {e}")))?;

        Ok(())
    }
}

impl AuditStore for RedbAuditStore {
    fn store_entry(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| AuditError::WriteFailed(format!("lock poisoned: {e}")))?;

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let key = (entry.timestamp_ns, seq);
        let value = serde_json::to_vec(entry)
            .map_err(|e| AuditError::WriteFailed(format!("serialize: {e}")))?;

        let txn = self
            .db
            .begin_write()
            .map_err(|e| AuditError::WriteFailed(format!("redb write txn: {e}")))?;
        {
            let mut table = txn
                .open_table(AUDIT_TABLE)
                .map_err(|e| AuditError::WriteFailed(format!("redb write table: {e}")))?;
            table
                .insert(key, value.as_slice())
                .map_err(|e| AuditError::WriteFailed(format!("redb insert: {e}")))?;
        }
        txn.commit()
            .map_err(|e| AuditError::WriteFailed(format!("redb write commit: {e}")))?;

        self.evict_if_needed()?;

        Ok(())
    }

    fn query_entries(&self, query: &AuditQuery) -> Result<Vec<AuditEntry>, AuditError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AuditError::QueryFailed(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(AUDIT_TABLE)
            .map_err(|e| AuditError::QueryFailed(format!("redb read table: {e}")))?;

        // Iterate in reverse (newest first).
        let iter = table
            .iter()
            .map_err(|e| AuditError::QueryFailed(format!("redb iter: {e}")))?;

        let entries: Vec<AuditEntry> = iter
            .filter_map(Result::ok)
            .filter_map(|(_k, v): (_, redb::AccessGuard<'_, &[u8]>)| {
                serde_json::from_slice::<AuditEntry>(v.value()).ok()
            })
            .filter(|e| query.matches(e))
            .collect();

        // Reverse for newest-first, then apply offset/limit.
        let total = entries.len();
        let start = query.offset.min(total);
        let end = (start + query.limit).min(total);

        let mut result: Vec<AuditEntry> = entries.into_iter().rev().collect();
        Ok(result.drain(start..end).collect())
    }

    fn cleanup_expired(&self, before_ns: u64) -> Result<usize, AuditError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| AuditError::WriteFailed(format!("lock poisoned: {e}")))?;

        let txn = self
            .db
            .begin_write()
            .map_err(|e| AuditError::WriteFailed(format!("redb cleanup txn: {e}")))?;
        let removed;
        {
            let mut table = txn
                .open_table(AUDIT_TABLE)
                .map_err(|e| AuditError::WriteFailed(format!("redb cleanup table: {e}")))?;

            let keys: Vec<(u64, u64)> = table
                .iter()
                .map_err(|e| AuditError::WriteFailed(format!("redb cleanup iter: {e}")))?
                .filter_map(Result::ok)
                .take_while(|(k, _v)| k.value().0 < before_ns)
                .map(|(k, _v)| k.value())
                .collect();

            removed = keys.len();
            for key in keys {
                let _ = table.remove(key);
            }
        }
        txn.commit()
            .map_err(|e| AuditError::WriteFailed(format!("redb cleanup commit: {e}")))?;

        Ok(removed)
    }

    fn entry_count(&self) -> Result<usize, AuditError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AuditError::QueryFailed(format!("redb count txn: {e}")))?;
        let table = txn
            .open_table(AUDIT_TABLE)
            .map_err(|e| AuditError::QueryFailed(format!("redb count table: {e}")))?;
        let count = table
            .len()
            .map_err(|e| AuditError::QueryFailed(format!("redb count: {e}")))?;
        #[allow(clippy::cast_possible_truncation)]
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::entity::{AuditAction, AuditComponent};
    use tempfile::NamedTempFile;

    fn make_store(max_entries: usize) -> (RedbAuditStore, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let store = RedbAuditStore::open(tmp.path(), max_entries).unwrap();
        (store, tmp)
    }

    fn make_entry(component: AuditComponent, action: AuditAction, ts: u64) -> AuditEntry {
        AuditEntry::security_decision(
            component,
            action,
            ts,
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            false,
            80,
            443,
            6,
            "fw-001",
            "test",
        )
    }

    #[test]
    fn store_and_query_entry() {
        let (store, _tmp) = make_store(100);
        let entry = make_entry(AuditComponent::Firewall, AuditAction::Drop, 1000);
        store.store_entry(&entry).unwrap();

        let q = AuditQuery {
            limit: 100,
            ..Default::default()
        };
        let results = store.query_entries(&q).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].component, AuditComponent::Firewall);
        assert_eq!(results[0].action, AuditAction::Drop);
    }

    #[test]
    fn query_with_component_filter() {
        let (store, _tmp) = make_store(100);
        store
            .store_entry(&make_entry(AuditComponent::Firewall, AuditAction::Drop, 1))
            .unwrap();
        store
            .store_entry(&make_entry(AuditComponent::Ids, AuditAction::Alert, 2))
            .unwrap();

        let q = AuditQuery {
            component: Some(AuditComponent::Ids),
            limit: 100,
            ..Default::default()
        };
        let results = store.query_entries(&q).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].component, AuditComponent::Ids);
    }

    #[test]
    fn query_with_time_range() {
        let (store, _tmp) = make_store(100);
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                100,
            ))
            .unwrap();
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                200,
            ))
            .unwrap();
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                300,
            ))
            .unwrap();

        let q = AuditQuery {
            from_ns: Some(150),
            to_ns: Some(250),
            limit: 100,
            ..Default::default()
        };
        let results = store.query_entries(&q).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].timestamp_ns, 200);
    }

    #[test]
    fn query_newest_first() {
        let (store, _tmp) = make_store(100);
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                100,
            ))
            .unwrap();
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                300,
            ))
            .unwrap();
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                200,
            ))
            .unwrap();

        let q = AuditQuery {
            limit: 100,
            ..Default::default()
        };
        let results = store.query_entries(&q).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].timestamp_ns, 300);
        assert_eq!(results[1].timestamp_ns, 200);
        assert_eq!(results[2].timestamp_ns, 100);
    }

    #[test]
    fn offset_and_limit() {
        let (store, _tmp) = make_store(100);
        for ts in 1..=10 {
            store
                .store_entry(&make_entry(
                    AuditComponent::Firewall,
                    AuditAction::Drop,
                    ts * 100,
                ))
                .unwrap();
        }

        let q = AuditQuery {
            limit: 3,
            offset: 2,
            ..Default::default()
        };
        let results = store.query_entries(&q).unwrap();
        assert_eq!(results.len(), 3);
        // Newest first: 1000, 900, 800, 700, ...
        // offset 2: skip 1000, 900 → 800, 700, 600
        assert_eq!(results[0].timestamp_ns, 800);
    }

    #[test]
    fn eviction_enforces_max_entries() {
        let (store, _tmp) = make_store(5);
        for ts in 1..=10 {
            store
                .store_entry(&make_entry(AuditComponent::Firewall, AuditAction::Drop, ts))
                .unwrap();
        }
        assert!(store.entry_count().unwrap() <= 5);
    }

    #[test]
    fn cleanup_expired_removes_old_entries() {
        let (store, _tmp) = make_store(100);
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                100,
            ))
            .unwrap();
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                200,
            ))
            .unwrap();
        store
            .store_entry(&make_entry(
                AuditComponent::Firewall,
                AuditAction::Drop,
                300,
            ))
            .unwrap();

        let removed = store.cleanup_expired(250).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(store.entry_count().unwrap(), 1);
    }

    #[test]
    fn entry_count_accurate() {
        let (store, _tmp) = make_store(100);
        assert_eq!(store.entry_count().unwrap(), 0);
        store
            .store_entry(&make_entry(AuditComponent::Firewall, AuditAction::Drop, 1))
            .unwrap();
        assert_eq!(store.entry_count().unwrap(), 1);
    }
}
