use serde::{Deserialize, Serialize};

/// Unique identifier for a rule across all domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RuleId(pub String);

impl RuleId {
    /// Validate that the rule ID is non-empty and contains only
    /// alphanumeric characters, dashes, and underscores.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.0.is_empty() {
            return Err("rule ID must not be empty");
        }
        if !self
            .0
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err("rule ID must contain only alphanumeric, dashes, underscores");
        }
        Ok(())
    }
}

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Convert to the u8 value used in eBPF maps.
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }

    /// Create from a u8 value. Unknown values default to Low.
    pub fn from_u8(n: u8) -> Self {
        match n {
            1 => Self::Medium,
            2 => Self::High,
            3 => Self::Critical,
            _ => Self::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Any,
    Other(u8),
}

impl Protocol {
    /// Convert to the u8 IP protocol number used in eBPF maps.
    /// Returns 0 for Any (wildcard).
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
            Self::Any => 0,
            Self::Other(n) => n,
        }
    }

    /// Create from a raw protocol number.
    pub fn from_u8(n: u8) -> Self {
        match n {
            0 => Self::Any,
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }
}

/// Domain operating mode for progressive feature activation (FR50).
///
/// - `Alert`: observation only — deny actions become log (no traffic dropped)
/// - `Block`: full enforcement — deny actions drop traffic
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainMode {
    #[default]
    Alert,
    Block,
}

impl DomainMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Block => "block",
        }
    }
}

impl std::fmt::Display for DomainMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    Firewall,
    Ids,
    Ips,
    Dlp,
    RateLimit,
    ThreatIntel,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RuleId tests ──────────────────────────────────────────────

    #[test]
    fn rule_id_valid() {
        assert!(RuleId("rule-1".to_string()).validate().is_ok());
        assert!(RuleId("rule_2".to_string()).validate().is_ok());
        assert!(RuleId("abc123".to_string()).validate().is_ok());
    }

    #[test]
    fn rule_id_empty() {
        assert!(RuleId(String::new()).validate().is_err());
    }

    #[test]
    fn rule_id_special_chars() {
        assert!(RuleId("rule.1".to_string()).validate().is_err());
        assert!(RuleId("rule 1".to_string()).validate().is_err());
        assert!(RuleId("rule/1".to_string()).validate().is_err());
    }

    #[test]
    fn rule_id_display() {
        let id = RuleId("fw-001".to_string());
        assert_eq!(format!("{id}"), "fw-001");
    }

    // ── Protocol tests ────────────────────────────────────────────

    #[test]
    fn protocol_roundtrip() {
        assert_eq!(Protocol::from_u8(Protocol::Tcp.to_u8()), Protocol::Tcp);
        assert_eq!(Protocol::from_u8(Protocol::Udp.to_u8()), Protocol::Udp);
        assert_eq!(Protocol::from_u8(Protocol::Icmp.to_u8()), Protocol::Icmp);
        assert_eq!(Protocol::from_u8(Protocol::Any.to_u8()), Protocol::Any);
    }

    #[test]
    fn protocol_known_values() {
        assert_eq!(Protocol::Tcp.to_u8(), 6);
        assert_eq!(Protocol::Udp.to_u8(), 17);
        assert_eq!(Protocol::Icmp.to_u8(), 1);
        assert_eq!(Protocol::Any.to_u8(), 0);
    }

    #[test]
    fn protocol_other_roundtrip() {
        let proto = Protocol::Other(47); // GRE
        assert_eq!(proto.to_u8(), 47);
        assert_eq!(Protocol::from_u8(47), Protocol::Other(47));
    }

    // ── Severity tests ────────────────────────────────────────────

    #[test]
    fn severity_to_u8() {
        assert_eq!(Severity::Low.to_u8(), 0);
        assert_eq!(Severity::Medium.to_u8(), 1);
        assert_eq!(Severity::High.to_u8(), 2);
        assert_eq!(Severity::Critical.to_u8(), 3);
    }

    #[test]
    fn severity_roundtrip() {
        for sev in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::from_u8(sev.to_u8()), sev);
        }
    }

    #[test]
    fn severity_from_u8_unknown_defaults_to_low() {
        assert_eq!(Severity::from_u8(255), Severity::Low);
        assert_eq!(Severity::from_u8(42), Severity::Low);
    }

    // ── DomainMode tests ──────────────────────────────────────────

    #[test]
    fn domain_mode_default_is_alert() {
        assert_eq!(DomainMode::default(), DomainMode::Alert);
    }

    #[test]
    fn domain_mode_as_str() {
        assert_eq!(DomainMode::Alert.as_str(), "alert");
        assert_eq!(DomainMode::Block.as_str(), "block");
    }

    #[test]
    fn domain_mode_display() {
        assert_eq!(format!("{}", DomainMode::Alert), "alert");
        assert_eq!(format!("{}", DomainMode::Block), "block");
    }

    #[test]
    fn domain_mode_equality() {
        assert_eq!(DomainMode::Alert, DomainMode::Alert);
        assert_ne!(DomainMode::Alert, DomainMode::Block);
    }
}
