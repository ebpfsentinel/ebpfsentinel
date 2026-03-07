use domain::audit::error::AuditError;
use domain::audit::rule_change::RuleChangeEntry;

/// Pluggable store for rule version history.
///
/// Tracks structured before/after snapshots for every rule change,
/// enabling the `GET /api/v1/audit/rules/{id}/history` endpoint.
pub trait RuleChangeStore: Send + Sync {
    /// Persist a single rule change entry.
    fn store_change(&self, entry: &RuleChangeEntry) -> Result<(), AuditError>;

    /// Query the version history for a specific rule, newest first.
    ///
    /// Returns up to `limit` entries ordered by version descending.
    fn query_rule_history(
        &self,
        rule_id: &str,
        limit: usize,
    ) -> Result<Vec<RuleChangeEntry>, AuditError>;

    /// Return the next version number for a given `rule_id`.
    ///
    /// Returns the current max version + 1, or 1 if no history exists.
    fn next_version(&self, rule_id: &str) -> Result<u64, AuditError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::entity::{AuditAction, AuditComponent};
    use domain::audit::rule_change::ChangeActor;
    use std::sync::Mutex;

    struct InMemoryRuleChangeStore {
        entries: Mutex<Vec<RuleChangeEntry>>,
    }

    impl InMemoryRuleChangeStore {
        fn new() -> Self {
            Self {
                entries: Mutex::new(Vec::new()),
            }
        }
    }

    impl RuleChangeStore for InMemoryRuleChangeStore {
        fn store_change(&self, entry: &RuleChangeEntry) -> Result<(), AuditError> {
            self.entries.lock().unwrap().push(entry.clone());
            Ok(())
        }

        fn query_rule_history(
            &self,
            rule_id: &str,
            limit: usize,
        ) -> Result<Vec<RuleChangeEntry>, AuditError> {
            let entries = self.entries.lock().unwrap();
            let mut matched: Vec<RuleChangeEntry> = entries
                .iter()
                .filter(|e| e.rule_id == rule_id)
                .cloned()
                .collect();
            matched.sort_by(|a, b| b.version.cmp(&a.version));
            matched.truncate(limit);
            Ok(matched)
        }

        fn next_version(&self, rule_id: &str) -> Result<u64, AuditError> {
            let entries = self.entries.lock().unwrap();
            let max_version = entries
                .iter()
                .filter(|e| e.rule_id == rule_id)
                .map(|e| e.version)
                .max()
                .unwrap_or(0);
            Ok(max_version + 1)
        }
    }

    fn make_change(rule_id: &str, version: u64) -> RuleChangeEntry {
        RuleChangeEntry {
            rule_id: rule_id.to_string(),
            version,
            timestamp_ns: version * 1_000_000,
            component: AuditComponent::Firewall,
            action: AuditAction::RuleAdded,
            actor: ChangeActor::Api,
            before: None,
            after: Some(format!(r#"{{"id":"{rule_id}","v":{version}}}"#)),
        }
    }

    #[test]
    fn store_and_query_history() {
        let store = InMemoryRuleChangeStore::new();
        store.store_change(&make_change("fw-001", 1)).unwrap();
        store.store_change(&make_change("fw-001", 2)).unwrap();

        let history = store.query_rule_history("fw-001", 10).unwrap();
        assert_eq!(history.len(), 2);
        // Newest first
        assert_eq!(history[0].version, 2);
        assert_eq!(history[1].version, 1);
    }

    #[test]
    fn next_version_starts_at_1() {
        let store = InMemoryRuleChangeStore::new();
        let v = store.next_version("fw-new").unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn next_version_increments() {
        let store = InMemoryRuleChangeStore::new();
        store.store_change(&make_change("fw-001", 1)).unwrap();

        let v = store.next_version("fw-001").unwrap();
        assert_eq!(v, 2);
    }
}
