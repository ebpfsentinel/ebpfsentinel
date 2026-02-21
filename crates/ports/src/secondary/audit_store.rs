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
