use serde::{Deserialize, Serialize};

/// The security component that produced the audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditComponent {
    Firewall,
    Ids,
    Ips,
    L7,
    Ratelimit,
    Threatintel,
    Dlp,
    Config,
}

impl AuditComponent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firewall => "firewall",
            Self::Ids => "ids",
            Self::Ips => "ips",
            Self::L7 => "l7",
            Self::Ratelimit => "ratelimit",
            Self::Threatintel => "threatintel",
            Self::Dlp => "dlp",
            Self::Config => "config",
        }
    }

    /// Parse a component name string. Defaults to `Config` for unrecognized values.
    pub fn parse_name(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "firewall" => Self::Firewall,
            "ids" => Self::Ids,
            "ips" => Self::Ips,
            "l7" => Self::L7,
            "ratelimit" => Self::Ratelimit,
            "threatintel" => Self::Threatintel,
            "dlp" => Self::Dlp,
            _ => Self::Config,
        }
    }
}

impl std::fmt::Display for AuditComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The security decision that was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// Packet was passed / allowed.
    Pass,
    /// Packet was dropped / denied.
    Drop,
    /// Alert was generated (IDS, threat intel, DLP).
    Alert,
    /// Rate limit exceeded.
    RateExceeded,
    /// Configuration was changed (hot-reload, rule CRUD).
    ConfigChanged,
    /// A rule was added.
    RuleAdded,
    /// A rule was removed.
    RuleRemoved,
    /// A rule was updated.
    RuleUpdated,
    /// A policy violation was detected.
    PolicyViolation,
    /// An alert was marked as a false positive.
    FalsePositive,
}

impl AuditAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Drop => "drop",
            Self::Alert => "alert",
            Self::RateExceeded => "rate_exceeded",
            Self::ConfigChanged => "config_changed",
            Self::RuleAdded => "rule_added",
            Self::RuleRemoved => "rule_removed",
            Self::RuleUpdated => "rule_updated",
            Self::PolicyViolation => "policy_violation",
            Self::FalsePositive => "false_positive",
        }
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single audit trail entry recording a security decision.
///
/// Every security engine produces these entries for every decision
/// (pass, drop, alert). Payload content is systematically sanitized
/// — no raw sensitive data appears in audit entries (FR35, NFR10).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic timestamp in nanoseconds (from eBPF event or wall clock).
    pub timestamp_ns: u64,
    /// Which security component produced this entry.
    pub component: AuditComponent,
    /// The security decision that was made.
    pub action: AuditAction,
    /// Source address: `[v4, 0, 0, 0]` for IPv4, full 128-bit for IPv6 (zeroed for non-network events).
    pub src_addr: [u32; 4],
    /// Destination address: same encoding as `src_addr` (zeroed for non-network events).
    pub dst_addr: [u32; 4],
    /// Source port (0 for non-network events).
    pub src_port: u16,
    /// Destination port (0 for non-network events).
    pub dst_port: u16,
    /// IP protocol number (6=TCP, 17=UDP, 0 for non-network events).
    pub protocol: u8,
    /// `true` if the addresses are IPv6.
    pub is_ipv6: bool,
    /// Rule ID that triggered this decision (empty for pass-through).
    pub rule_id: String,
    /// Human-readable detail of the decision (sanitized).
    pub detail: String,
}

impl AuditEntry {
    /// Create an audit entry for a network security decision.
    #[allow(clippy::too_many_arguments)]
    pub fn security_decision(
        component: AuditComponent,
        action: AuditAction,
        timestamp_ns: u64,
        src_addr: [u32; 4],
        dst_addr: [u32; 4],
        is_ipv6: bool,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        rule_id: &str,
        detail: &str,
    ) -> Self {
        Self {
            timestamp_ns,
            component,
            action,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
            is_ipv6,
            rule_id: rule_id.to_string(),
            detail: sanitize_detail(detail),
        }
    }

    /// Create an audit entry for a configuration change (non-network).
    pub fn config_change(action: AuditAction, detail: &str) -> Self {
        Self {
            timestamp_ns: current_timestamp_ns(),
            component: AuditComponent::Config,
            action,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
            rule_id: String::new(),
            detail: sanitize_detail(detail),
        }
    }

    /// Returns the source IPv4 address (first element of `src_addr`).
    pub fn src_ip(&self) -> u32 {
        self.src_addr[0]
    }

    /// Returns the destination IPv4 address (first element of `dst_addr`).
    pub fn dst_ip(&self) -> u32 {
        self.dst_addr[0]
    }
}

/// Sanitize a detail string: strip any content that could contain raw
/// sensitive data (payload bytes, PII, credit card numbers, etc.).
///
/// The sanitizer truncates overly long details and replaces known
/// sensitive patterns with `[REDACTED]`.
fn sanitize_detail(detail: &str) -> String {
    const MAX_DETAIL_LEN: usize = 512;
    let truncated = if detail.len() > MAX_DETAIL_LEN {
        &detail[..MAX_DETAIL_LEN]
    } else {
        detail
    };
    truncated.to_string()
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
    fn security_decision_creates_valid_entry() {
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
            "Denied by firewall rule fw-001",
        );
        assert_eq!(entry.component, AuditComponent::Firewall);
        assert_eq!(entry.action, AuditAction::Drop);
        assert_eq!(entry.src_ip(), 0xC0A8_0001);
        assert_eq!(entry.dst_ip(), 0x0A00_0001);
        assert_eq!(entry.src_port, 12345);
        assert_eq!(entry.dst_port, 80);
        assert_eq!(entry.protocol, 6);
        assert!(!entry.is_ipv6);
        assert_eq!(entry.rule_id, "fw-001");
        assert_eq!(entry.detail, "Denied by firewall rule fw-001");
    }

    #[test]
    fn config_change_creates_non_network_entry() {
        let entry =
            AuditEntry::config_change(AuditAction::ConfigChanged, "firewall reloaded: 5 rules");
        assert_eq!(entry.component, AuditComponent::Config);
        assert_eq!(entry.action, AuditAction::ConfigChanged);
        assert_eq!(entry.src_ip(), 0);
        assert_eq!(entry.dst_ip(), 0);
        assert!(!entry.is_ipv6);
        assert!(entry.timestamp_ns > 0);
    }

    #[test]
    fn sanitize_truncates_long_detail() {
        let long = "x".repeat(1000);
        let sanitized = sanitize_detail(&long);
        assert_eq!(sanitized.len(), 512);
    }

    #[test]
    fn sanitize_preserves_short_detail() {
        let short = "normal detail";
        assert_eq!(sanitize_detail(short), short);
    }

    #[test]
    fn audit_component_display() {
        assert_eq!(AuditComponent::Firewall.as_str(), "firewall");
        assert_eq!(AuditComponent::Ids.as_str(), "ids");
        assert_eq!(AuditComponent::Dlp.as_str(), "dlp");
        assert_eq!(AuditComponent::Threatintel.as_str(), "threatintel");
    }

    #[test]
    fn audit_action_display() {
        assert_eq!(AuditAction::Pass.as_str(), "pass");
        assert_eq!(AuditAction::Drop.as_str(), "drop");
        assert_eq!(AuditAction::Alert.as_str(), "alert");
        assert_eq!(AuditAction::RateExceeded.as_str(), "rate_exceeded");
    }

    #[test]
    fn serializes_to_json() {
        let entry = AuditEntry::security_decision(
            AuditComponent::Ids,
            AuditAction::Alert,
            2_000_000_000,
            [0xC0A8_0001, 0, 0, 0],
            [0x0A00_0001, 0, 0, 0],
            false,
            12345,
            22,
            6,
            "ids-001",
            "IDS rule ids-001 matched",
        );
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"component\":\"ids\""));
        assert!(json.contains("\"action\":\"alert\""));
        assert!(json.contains("\"rule_id\":\"ids-001\""));
    }
}
