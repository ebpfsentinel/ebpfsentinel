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
