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
