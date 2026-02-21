use serde::{Deserialize, Serialize};

use crate::common::entity::{DomainMode, RuleId, Severity};
use crate::dlp::entity::DlpAlert;
use crate::ids::entity::IdsAlert;
use crate::threatintel::entity::ThreatIntelAlert;

/// Full-context alert with all FR30 fields.
///
/// Contains complete packet context (IPs, ports, protocol), matched rule
/// metadata, severity, action taken, and a human-readable message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp_ns: u64,
    pub component: String,
    pub severity: Severity,
    pub rule_id: RuleId,
    pub action: DomainMode,
    /// Source address: `[v4, 0, 0, 0]` for IPv4, full 128-bit for IPv6.
    pub src_addr: [u32; 4],
    /// Destination address: same encoding as `src_addr`.
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// `true` if the addresses are IPv6.
    pub is_ipv6: bool,
    pub message: String,
    /// Whether this alert has been marked as a false positive by an operator.
    #[serde(default)]
    pub false_positive: bool,
    /// Reverse-DNS domain for source IP (enriched from DNS cache).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_domain: Option<String>,
    /// Reverse-DNS domain for destination IP (enriched from DNS cache).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_domain: Option<String>,
    /// Reputation score for source domain (0.0=clean, 1.0=malicious).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_domain_score: Option<f64>,
    /// Reputation score for destination domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_domain_score: Option<f64>,
}

impl Alert {
    /// Create a domain alert from an IDS alert with a human-readable description.
    pub fn from_ids_alert(ids: &IdsAlert, description: &str) -> Self {
        Self {
            id: Self::generate_id(ids.timestamp_ns, &ids.rule_id),
            timestamp_ns: ids.timestamp_ns,
            component: "ids".to_string(),
            severity: ids.severity,
            rule_id: ids.rule_id.clone(),
            action: ids.mode,
            src_addr: ids.src_addr,
            dst_addr: ids.dst_addr,
            src_port: ids.src_port,
            dst_port: ids.dst_port,
            protocol: ids.protocol,
            is_ipv6: ids.is_ipv6,
            message: description.to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
        }
    }

    /// Create a domain alert from a DLP alert with a human-readable description.
    /// DLP events are process-level (pid/tgid), not network-level, so IP/port
    /// fields are zeroed.
    pub fn from_dlp_alert(dlp: &DlpAlert, description: &str) -> Self {
        Self {
            id: Self::generate_id(dlp.timestamp_ns, &dlp.pattern_id),
            timestamp_ns: dlp.timestamp_ns,
            component: "dlp".to_string(),
            severity: dlp.severity,
            rule_id: dlp.pattern_id.clone(),
            action: dlp.mode,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
            message: description.to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
        }
    }

    /// Create a domain alert from a threat intelligence match.
    pub fn from_threatintel_alert(ti: &ThreatIntelAlert, description: &str) -> Self {
        Self {
            id: Self::generate_id(ti.timestamp_ns, &RuleId(ti.feed_id.clone())),
            timestamp_ns: ti.timestamp_ns,
            component: "threatintel".to_string(),
            severity: Severity::High, // IOC matches are high-severity by default
            rule_id: RuleId(ti.feed_id.clone()),
            action: ti.mode,
            src_addr: ti.src_addr,
            dst_addr: ti.dst_addr,
            src_port: ti.src_port,
            dst_port: ti.dst_port,
            protocol: ti.protocol,
            is_ipv6: ti.is_ipv6,
            message: description.to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
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

    /// Generate a simple unique ID from timestamp and rule ID.
    fn generate_id(timestamp_ns: u64, rule_id: &RuleId) -> String {
        format!("{timestamp_ns}-{rule_id}")
    }
}

/// Routing destination for an alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertDestination {
    Email { to: String },
    Webhook { url: String },
    Log,
}

/// A route that determines which alerts go to which destination,
/// filtered by minimum severity and optional event type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRoute {
    pub name: String,
    pub destination: AlertDestination,
    pub min_severity: Severity,
    /// If `None`, matches all component types. If `Some`, only routes alerts
    /// whose `component` field is in the list (e.g. `["ids"]`).
    pub event_types: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::DomainMode;

    fn sample_dlp_alert() -> DlpAlert {
        DlpAlert {
            pattern_id: RuleId("dlp-pci-visa".to_string()),
            pattern_name: "Visa Card Number".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            pid: 1234,
            tgid: 5678,
            direction: 0,
            redacted_excerpt: "[REDACTED:pci]".to_string(),
            timestamp_ns: 2_000_000_000,
        }
    }

    fn sample_ids_alert() -> IdsAlert {
        IdsAlert {
            rule_id: RuleId("ids-001".to_string()),
            severity: Severity::High,
            mode: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            is_ipv6: false,
            rule_index: 0,
            timestamp_ns: 1_000_000_000,
            matched_domain: None,
        }
    }

    #[test]
    fn alert_from_ids_alert_maps_all_fields() {
        let ids = sample_ids_alert();
        let alert = Alert::from_ids_alert(&ids, "SSH bruteforce detected");

        assert_eq!(alert.component, "ids");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.rule_id.0, "ids-001");
        assert_eq!(alert.action, DomainMode::Alert);
        assert_eq!(alert.src_ip(), 0xC0A8_0001);
        assert_eq!(alert.dst_ip(), 0x0A00_0001);
        assert_eq!(alert.src_port, 12345);
        assert_eq!(alert.dst_port, 22);
        assert_eq!(alert.protocol, 6);
        assert!(!alert.is_ipv6);
        assert_eq!(alert.timestamp_ns, 1_000_000_000);
        assert_eq!(alert.message, "SSH bruteforce detected");
        assert!(alert.id.contains("ids-001"));
    }

    #[test]
    fn alert_from_ids_alert_block_mode() {
        let mut ids = sample_ids_alert();
        ids.mode = DomainMode::Block;
        ids.severity = Severity::Critical;
        let alert = Alert::from_ids_alert(&ids, "Critical threat blocked");

        assert_eq!(alert.action, DomainMode::Block);
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn alert_route_with_event_types_filter() {
        let route = AlertRoute {
            name: "ids-only".to_string(),
            destination: AlertDestination::Log,
            min_severity: Severity::High,
            event_types: Some(vec!["ids".to_string()]),
        };
        assert_eq!(route.event_types.as_ref().unwrap().len(), 1);
        assert_eq!(route.event_types.as_ref().unwrap()[0], "ids");
    }

    #[test]
    fn alert_route_without_event_types_matches_all() {
        let route = AlertRoute {
            name: "all-alerts".to_string(),
            destination: AlertDestination::Log,
            min_severity: Severity::Low,
            event_types: None,
        };
        assert!(route.event_types.is_none());
    }

    // ── DLP Alert tests ──────────────────────────────────────────

    #[test]
    fn alert_from_dlp_alert_maps_all_fields() {
        let dlp = sample_dlp_alert();
        let alert = Alert::from_dlp_alert(&dlp, "Visa card detected in SSL traffic");

        assert_eq!(alert.component, "dlp");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.rule_id.0, "dlp-pci-visa");
        assert_eq!(alert.action, DomainMode::Alert);
        assert_eq!(alert.src_ip(), 0);
        assert_eq!(alert.dst_ip(), 0);
        assert!(!alert.is_ipv6);
        assert_eq!(alert.src_port, 0);
        assert_eq!(alert.dst_port, 0);
        assert_eq!(alert.protocol, 0);
        assert_eq!(alert.timestamp_ns, 2_000_000_000);
        assert_eq!(alert.message, "Visa card detected in SSL traffic");
        assert!(alert.id.contains("dlp-pci-visa"));
    }

    #[test]
    fn alert_from_dlp_alert_block_mode() {
        let mut dlp = sample_dlp_alert();
        dlp.mode = DomainMode::Block;
        let alert = Alert::from_dlp_alert(&dlp, "Blocked");

        assert_eq!(alert.action, DomainMode::Block);
    }

    // ── Threat Intel Alert tests ──────────────────────────────────

    fn sample_ti_alert() -> ThreatIntelAlert {
        use crate::threatintel::entity::ThreatType;
        ThreatIntelAlert {
            feed_id: "alienvault-otx".to_string(),
            confidence: 90,
            threat_type: ThreatType::C2,
            mode: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            is_ipv6: false,
            timestamp_ns: 3_000_000_000,
        }
    }

    #[test]
    fn alert_from_threatintel_maps_all_fields() {
        let ti = sample_ti_alert();
        let alert = Alert::from_threatintel_alert(&ti, "C2 callback detected to known IOC");

        assert_eq!(alert.component, "threatintel");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.rule_id.0, "alienvault-otx");
        assert_eq!(alert.action, DomainMode::Alert);
        assert_eq!(alert.src_ip(), 0xC0A8_0001);
        assert_eq!(alert.dst_ip(), 0x0A00_0001);
        assert_eq!(alert.src_port, 12345);
        assert_eq!(alert.dst_port, 443);
        assert_eq!(alert.protocol, 6);
        assert_eq!(alert.timestamp_ns, 3_000_000_000);
        assert!(alert.id.contains("alienvault-otx"));
    }

    #[test]
    fn alert_from_threatintel_block_mode() {
        let mut ti = sample_ti_alert();
        ti.mode = DomainMode::Block;
        let alert = Alert::from_threatintel_alert(&ti, "Blocked");
        assert_eq!(alert.action, DomainMode::Block);
    }
}
