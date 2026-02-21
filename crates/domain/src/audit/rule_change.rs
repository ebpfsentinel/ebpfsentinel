use serde::{Deserialize, Serialize};

use super::entity::{AuditAction, AuditComponent};

/// Identifies who initiated a rule change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeActor {
    /// Change made via the REST API.
    Api,
    /// Change made during configuration hot-reload.
    ConfigReload,
    /// Change made via the CLI.
    Cli,
}

impl ChangeActor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::ConfigReload => "config_reload",
            Self::Cli => "cli",
        }
    }
}

impl std::fmt::Display for ChangeActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A versioned record of a rule change (add, update, remove).
///
/// Each rule has its own monotonic version counter. Before/after
/// snapshots are stored as JSON strings to avoid coupling to
/// specific rule types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleChangeEntry {
    /// The rule being changed.
    pub rule_id: String,
    /// Monotonic per-rule version counter (starts at 1).
    pub version: u64,
    /// Wall-clock timestamp in nanoseconds since UNIX epoch.
    pub timestamp_ns: u64,
    /// Which subsystem owns the rule.
    pub component: AuditComponent,
    /// The type of change (`RuleAdded`, `RuleRemoved`, `RuleUpdated`).
    pub action: AuditAction,
    /// Who initiated the change.
    pub actor: ChangeActor,
    /// JSON snapshot of the rule before the change (None for adds).
    pub before: Option<String>,
    /// JSON snapshot of the rule after the change (None for deletes).
    pub after: Option<String>,
}

impl RuleChangeEntry {
    /// Create a new rule change entry with auto-generated timestamp.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_id: String,
        version: u64,
        component: AuditComponent,
        action: AuditAction,
        actor: ChangeActor,
        before: Option<String>,
        after: Option<String>,
    ) -> Self {
        Self {
            rule_id,
            version,
            timestamp_ns: current_timestamp_ns(),
            component,
            action,
            actor,
            before,
            after,
        }
    }
}

/// Returns current wall-clock time as nanoseconds since UNIX epoch.
#[allow(clippy::cast_possible_truncation)]
fn current_timestamp_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_entry_with_timestamp() {
        let entry = RuleChangeEntry::new(
            "fw-001".to_string(),
            1,
            AuditComponent::Firewall,
            AuditAction::RuleAdded,
            ChangeActor::Api,
            None,
            Some(r#"{"id":"fw-001"}"#.to_string()),
        );
        assert_eq!(entry.rule_id, "fw-001");
        assert_eq!(entry.version, 1);
        assert_eq!(entry.component, AuditComponent::Firewall);
        assert_eq!(entry.action, AuditAction::RuleAdded);
        assert_eq!(entry.actor, ChangeActor::Api);
        assert!(entry.before.is_none());
        assert!(entry.after.is_some());
        assert!(entry.timestamp_ns > 0);
    }

    #[test]
    fn change_actor_display() {
        assert_eq!(ChangeActor::Api.as_str(), "api");
        assert_eq!(ChangeActor::ConfigReload.as_str(), "config_reload");
        assert_eq!(ChangeActor::Cli.as_str(), "cli");
        assert_eq!(format!("{}", ChangeActor::Api), "api");
        assert_eq!(format!("{}", ChangeActor::ConfigReload), "config_reload");
    }

    #[test]
    fn serializes_to_json() {
        let entry = RuleChangeEntry::new(
            "rl-001".to_string(),
            3,
            AuditComponent::Ratelimit,
            AuditAction::RuleUpdated,
            ChangeActor::ConfigReload,
            Some(r#"{"rate":100}"#.to_string()),
            Some(r#"{"rate":200}"#.to_string()),
        );
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"rule_id\":\"rl-001\""));
        assert!(json.contains("\"version\":3"));
        assert!(json.contains("\"component\":\"ratelimit\""));
        assert!(json.contains("\"action\":\"rule_updated\""));
        assert!(json.contains("\"actor\":\"config_reload\""));
    }

    #[test]
    fn deserializes_from_json() {
        let json = r#"{
            "rule_id": "fw-001",
            "version": 2,
            "timestamp_ns": 1000000,
            "component": "firewall",
            "action": "rule_removed",
            "actor": "api",
            "before": "{\"id\":\"fw-001\"}",
            "after": null
        }"#;
        let entry: RuleChangeEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.rule_id, "fw-001");
        assert_eq!(entry.version, 2);
        assert_eq!(entry.action, AuditAction::RuleRemoved);
        assert_eq!(entry.actor, ChangeActor::Api);
        assert!(entry.before.is_some());
        assert!(entry.after.is_none());
    }
}
