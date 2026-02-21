use domain::audit::entity::AuditEntry;
use domain::audit::error::AuditError;

/// Pluggable audit sink for persisting audit trail entries.
///
/// Implementations may write to structured logs, a local database (redb),
/// or a remote service. The trait is object-safe for use behind `Arc<dyn AuditSink>`.
pub trait AuditSink: Send + Sync {
    /// Write a single audit entry to the underlying storage.
    fn write_entry(&self, entry: &AuditEntry) -> Result<(), AuditError>;
}
