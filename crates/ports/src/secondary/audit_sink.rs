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

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::entity::{AuditAction, AuditComponent};
    use std::sync::Mutex;

    struct MockAuditSink {
        entries: Mutex<Vec<AuditEntry>>,
    }

    impl MockAuditSink {
        fn new() -> Self {
            Self {
                entries: Mutex::new(Vec::new()),
            }
        }
    }

    impl AuditSink for MockAuditSink {
        fn write_entry(&self, entry: &AuditEntry) -> Result<(), AuditError> {
            self.entries.lock().unwrap().push(entry.clone());
            Ok(())
        }
    }

    #[test]
    fn write_entry_succeeds() {
        let sink = MockAuditSink::new();
        let entry = AuditEntry::security_decision(
            AuditComponent::Firewall,
            AuditAction::Drop,
            1_000_000_000,
            [0xC0A8_0001, 0, 0, 0],
            [0x0A00_0001, 0, 0, 0],
            false,
            12345,
            80,
            6,
            "fw-001",
            "test entry",
        );
        sink.write_entry(&entry).unwrap();

        let stored = sink.entries.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].component, AuditComponent::Firewall);
    }

    #[test]
    fn object_safe() {
        fn _check(_: &dyn AuditSink) {}
    }
}
