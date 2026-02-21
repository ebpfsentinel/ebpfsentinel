use std::path::Path;
use std::sync::Mutex;

use domain::audit::error::AuditError;
use domain::audit::rule_change::RuleChangeEntry;
use ports::secondary::rule_change_store::RuleChangeStore;
use redb::{Database, ReadableDatabase, TableDefinition};

/// redb table: key = `(rule_id, version)`, value = JSON-serialized `RuleChangeEntry`.
const RULE_CHANGES_TABLE: TableDefinition<(&str, u64), &[u8]> =
    TableDefinition::new("rule_changes");

/// Persistent rule change history store backed by redb.
///
/// Stores versioned rule change entries keyed by `(rule_id, version)`.
/// Supports per-rule history queries (newest first) and monotonic
/// version counter retrieval.
pub struct RedbRuleChangeStore {
    db: Database,
    /// Serialize writes to prevent concurrent mutation.
    write_lock: Mutex<()>,
}

impl RedbRuleChangeStore {
    /// Open (or create) a redb database at `path` for rule change history.
    pub fn open(path: &Path) -> Result<Self, AuditError> {
        let db = Database::create(path)
            .map_err(|e| AuditError::WriteFailed(format!("redb open failed: {e}")))?;

        // Ensure the table exists.
        let txn = db
            .begin_write()
            .map_err(|e| AuditError::WriteFailed(format!("redb txn begin: {e}")))?;
        {
            let _table = txn
                .open_table(RULE_CHANGES_TABLE)
                .map_err(|e| AuditError::WriteFailed(format!("redb table create: {e}")))?;
        }
        txn.commit()
            .map_err(|e| AuditError::WriteFailed(format!("redb commit: {e}")))?;

        Ok(Self {
            db,
            write_lock: Mutex::new(()),
        })
    }
}

impl RuleChangeStore for RedbRuleChangeStore {
    fn store_change(&self, entry: &RuleChangeEntry) -> Result<(), AuditError> {
        let _lock = self
            .write_lock
            .lock()
            .map_err(|e| AuditError::WriteFailed(format!("lock poisoned: {e}")))?;

        let key = (entry.rule_id.as_str(), entry.version);
        let value = serde_json::to_vec(entry)
            .map_err(|e| AuditError::WriteFailed(format!("serialize: {e}")))?;

        let txn = self
            .db
            .begin_write()
            .map_err(|e| AuditError::WriteFailed(format!("redb write txn: {e}")))?;
        {
            let mut table = txn
                .open_table(RULE_CHANGES_TABLE)
                .map_err(|e| AuditError::WriteFailed(format!("redb write table: {e}")))?;
            table
                .insert(key, value.as_slice())
                .map_err(|e| AuditError::WriteFailed(format!("redb insert: {e}")))?;
        }
        txn.commit()
            .map_err(|e| AuditError::WriteFailed(format!("redb write commit: {e}")))?;

        Ok(())
    }

    fn query_rule_history(
        &self,
        rule_id: &str,
        limit: usize,
    ) -> Result<Vec<RuleChangeEntry>, AuditError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AuditError::QueryFailed(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(RULE_CHANGES_TABLE)
            .map_err(|e| AuditError::QueryFailed(format!("redb read table: {e}")))?;

        // Scan the range for this rule_id: (rule_id, 0) ..= (rule_id, u64::MAX)
        let range_start = (rule_id, 0u64);
        let range_end = (rule_id, u64::MAX);
        let iter = table
            .range(range_start..=range_end)
            .map_err(|e| AuditError::QueryFailed(format!("redb range: {e}")))?;

        let mut entries: Vec<RuleChangeEntry> = iter
            .filter_map(Result::ok)
            .filter_map(|(_k, v)| serde_json::from_slice::<RuleChangeEntry>(v.value()).ok())
            .collect();

        // Reverse for newest-first ordering, then apply limit.
        entries.reverse();
        entries.truncate(limit);

        Ok(entries)
    }

    fn next_version(&self, rule_id: &str) -> Result<u64, AuditError> {
        let txn = self
            .db
            .begin_read()
            .map_err(|e| AuditError::QueryFailed(format!("redb read txn: {e}")))?;
        let table = txn
            .open_table(RULE_CHANGES_TABLE)
            .map_err(|e| AuditError::QueryFailed(format!("redb read table: {e}")))?;

        // Scan the range for this rule_id and find the max version.
        let range_start = (rule_id, 0u64);
        let range_end = (rule_id, u64::MAX);
        let iter = table
            .range(range_start..=range_end)
            .map_err(|e| AuditError::QueryFailed(format!("redb range: {e}")))?;

        let max_version = iter
            .filter_map(Result::ok)
            .map(|(k, _v)| k.value().1)
            .last() // entries are ordered ascending, last is max
            .unwrap_or(0);

        Ok(max_version + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::entity::{AuditAction, AuditComponent};
    use domain::audit::rule_change::ChangeActor;
    use tempfile::NamedTempFile;

    fn make_store() -> (RedbRuleChangeStore, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let store = RedbRuleChangeStore::open(tmp.path()).unwrap();
        (store, tmp)
    }

    fn make_entry(
        rule_id: &str,
        version: u64,
        component: AuditComponent,
        action: AuditAction,
    ) -> RuleChangeEntry {
        RuleChangeEntry::new(
            rule_id.to_string(),
            version,
            component,
            action,
            ChangeActor::Api,
            None,
            Some(format!(r#"{{"id":"{}"}}"#, rule_id)),
        )
    }

    #[test]
    fn store_and_query_single_entry() {
        let (store, _tmp) = make_store();
        let entry = make_entry(
            "fw-001",
            1,
            AuditComponent::Firewall,
            AuditAction::RuleAdded,
        );
        store.store_change(&entry).unwrap();

        let history = store.query_rule_history("fw-001", 50).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].rule_id, "fw-001");
        assert_eq!(history[0].version, 1);
    }

    #[test]
    fn query_returns_newest_first() {
        let (store, _tmp) = make_store();
        for v in 1..=5 {
            let entry = make_entry(
                "fw-001",
                v,
                AuditComponent::Firewall,
                AuditAction::RuleUpdated,
            );
            store.store_change(&entry).unwrap();
        }

        let history = store.query_rule_history("fw-001", 50).unwrap();
        assert_eq!(history.len(), 5);
        assert_eq!(history[0].version, 5);
        assert_eq!(history[4].version, 1);
    }

    #[test]
    fn query_respects_limit() {
        let (store, _tmp) = make_store();
        for v in 1..=10 {
            let entry = make_entry(
                "fw-001",
                v,
                AuditComponent::Firewall,
                AuditAction::RuleUpdated,
            );
            store.store_change(&entry).unwrap();
        }

        let history = store.query_rule_history("fw-001", 3).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].version, 10);
        assert_eq!(history[2].version, 8);
    }

    #[test]
    fn query_isolates_by_rule_id() {
        let (store, _tmp) = make_store();
        store
            .store_change(&make_entry(
                "fw-001",
                1,
                AuditComponent::Firewall,
                AuditAction::RuleAdded,
            ))
            .unwrap();
        store
            .store_change(&make_entry(
                "rl-001",
                1,
                AuditComponent::Ratelimit,
                AuditAction::RuleAdded,
            ))
            .unwrap();

        let fw_history = store.query_rule_history("fw-001", 50).unwrap();
        assert_eq!(fw_history.len(), 1);
        assert_eq!(fw_history[0].component, AuditComponent::Firewall);

        let rl_history = store.query_rule_history("rl-001", 50).unwrap();
        assert_eq!(rl_history.len(), 1);
        assert_eq!(rl_history[0].component, AuditComponent::Ratelimit);
    }

    #[test]
    fn query_empty_rule_returns_empty() {
        let (store, _tmp) = make_store();
        let history = store.query_rule_history("nonexistent", 50).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn next_version_starts_at_one() {
        let (store, _tmp) = make_store();
        assert_eq!(store.next_version("fw-001").unwrap(), 1);
    }

    #[test]
    fn next_version_increments() {
        let (store, _tmp) = make_store();
        store
            .store_change(&make_entry(
                "fw-001",
                1,
                AuditComponent::Firewall,
                AuditAction::RuleAdded,
            ))
            .unwrap();
        assert_eq!(store.next_version("fw-001").unwrap(), 2);

        store
            .store_change(&make_entry(
                "fw-001",
                2,
                AuditComponent::Firewall,
                AuditAction::RuleUpdated,
            ))
            .unwrap();
        assert_eq!(store.next_version("fw-001").unwrap(), 3);
    }

    #[test]
    fn next_version_isolated_per_rule() {
        let (store, _tmp) = make_store();
        store
            .store_change(&make_entry(
                "fw-001",
                1,
                AuditComponent::Firewall,
                AuditAction::RuleAdded,
            ))
            .unwrap();
        store
            .store_change(&make_entry(
                "fw-001",
                2,
                AuditComponent::Firewall,
                AuditAction::RuleUpdated,
            ))
            .unwrap();

        assert_eq!(store.next_version("fw-001").unwrap(), 3);
        assert_eq!(store.next_version("rl-001").unwrap(), 1);
    }
}
