//! Audit log domain configuration structs.

use serde::{Deserialize, Serialize};

use super::common::default_true;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Retention period in days. Entries older than this are purged.
    /// Default: 90 (PCI-DSS minimum).
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    /// Maximum number of entries kept in the redb buffer.
    /// Default: 100,000.
    #[serde(default = "default_audit_buffer_size")]
    pub buffer_size: usize,

    /// Path to the redb database file. Empty string disables persistent storage.
    #[serde(default = "default_audit_storage_path")]
    pub storage_path: String,
}

fn default_retention_days() -> u32 {
    90
}
fn default_audit_buffer_size() -> usize {
    100_000
}
fn default_audit_storage_path() -> String {
    "data/audit.redb".to_string()
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: default_retention_days(),
            buffer_size: default_audit_buffer_size(),
            storage_path: default_audit_storage_path(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = AuditConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.retention_days, 90);
        assert_eq!(cfg.buffer_size, 100_000);
        assert_eq!(cfg.storage_path, "data/audit.redb");
    }

    #[test]
    fn yaml_with_custom_values() {
        let yaml = r#"
enabled: false
retention_days: 365
buffer_size: 50000
storage_path: /tmp/audit.redb
"#;
        let cfg: AuditConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.retention_days, 365);
        assert_eq!(cfg.buffer_size, 50_000);
        assert_eq!(cfg.storage_path, "/tmp/audit.redb");
    }

    #[test]
    fn optional_fields_use_defaults_when_omitted() {
        let yaml = "enabled: false\n";
        let cfg: AuditConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.retention_days, 90);
        assert_eq!(cfg.buffer_size, 100_000);
        assert_eq!(cfg.storage_path, "data/audit.redb");
    }
}
