use domain::audit::entity::AuditEntry;
use domain::audit::error::AuditError;
use ports::secondary::audit_sink::AuditSink;

/// Audit sink that emits structured JSON log lines via `tracing`.
///
/// Each audit entry is logged at INFO level with `event_type = "audit"`,
/// making it easy to filter audit records in log aggregation systems.
pub struct LogAuditSink;

impl AuditSink for LogAuditSink {
    fn write_entry(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        tracing::info!(
            event_type = "audit",
            timestamp_ns = entry.timestamp_ns,
            component = entry.component.as_str(),
            action = entry.action.as_str(),
            src_ip = entry.src_ip(),
            dst_ip = entry.dst_ip(),
            src_port = entry.src_port,
            dst_port = entry.dst_port,
            protocol = entry.protocol,
            rule_id = %entry.rule_id,
            detail = %entry.detail,
            "audit"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::audit::entity::{AuditAction, AuditComponent};

    #[test]
    fn log_audit_sink_writes_without_error() {
        let sink = LogAuditSink;
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
            "Denied by rule fw-001",
        );
        assert!(sink.write_entry(&entry).is_ok());
    }

    #[test]
    fn log_audit_sink_handles_empty_detail() {
        let sink = LogAuditSink;
        let entry = AuditEntry::security_decision(
            AuditComponent::Ids,
            AuditAction::Alert,
            0,
            [0; 4],
            [0; 4],
            false,
            0,
            0,
            0,
            "",
            "",
        );
        assert!(sink.write_entry(&entry).is_ok());
    }
}
