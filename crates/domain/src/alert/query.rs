use super::entity::Alert;
use crate::common::entity::Severity;

/// Filter parameters for querying stored alerts.
#[derive(Debug, Clone, Default)]
pub struct AlertQuery {
    /// Start of time range (inclusive, nanoseconds since epoch).
    pub from_ns: Option<u64>,
    /// End of time range (inclusive, nanoseconds since epoch).
    pub to_ns: Option<u64>,
    /// Filter by component (exact match, case-insensitive).
    pub component: Option<String>,
    /// Filter by minimum severity.
    pub min_severity: Option<Severity>,
    /// Filter by rule ID (exact match).
    pub rule_id: Option<String>,
    /// Filter by false-positive flag.
    pub false_positive: Option<bool>,
    /// Maximum number of entries to return.
    pub limit: usize,
    /// Number of entries to skip.
    pub offset: usize,
}

impl AlertQuery {
    /// Check whether an `Alert` matches all active filters.
    pub fn matches(&self, alert: &Alert) -> bool {
        if let Some(from) = self.from_ns
            && alert.timestamp_ns < from
        {
            return false;
        }
        if let Some(to) = self.to_ns
            && alert.timestamp_ns > to
        {
            return false;
        }
        if let Some(ref component) = self.component
            && !alert.component.eq_ignore_ascii_case(component)
        {
            return false;
        }
        if let Some(min_sev) = self.min_severity
            && alert.severity.to_u8() < min_sev.to_u8()
        {
            return false;
        }
        if let Some(ref rule_id) = self.rule_id
            && alert.rule_id.0 != *rule_id
        {
            return false;
        }
        if let Some(fp) = self.false_positive
            && alert.false_positive != fp
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::{DomainMode, RuleId};

    fn make_alert(component: &str, severity: Severity, rule_id: &str, fp: bool) -> Alert {
        Alert {
            id: format!("test-{rule_id}"),
            timestamp_ns: 1_000_000_000,
            component: component.to_string(),
            severity,
            rule_id: RuleId(rule_id.to_string()),
            action: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            is_ipv6: false,
            message: "test alert".to_string(),
            false_positive: fp,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
        }
    }

    #[test]
    fn empty_query_matches_everything() {
        let q = AlertQuery::default();
        let a = make_alert("ids", Severity::High, "ids-001", false);
        assert!(q.matches(&a));
    }

    #[test]
    fn from_ns_filters() {
        let q = AlertQuery {
            from_ns: Some(2_000_000_000),
            ..Default::default()
        };
        assert!(!q.matches(&make_alert("ids", Severity::High, "ids-001", false)));

        let q2 = AlertQuery {
            from_ns: Some(500_000_000),
            ..Default::default()
        };
        assert!(q2.matches(&make_alert("ids", Severity::High, "ids-001", false)));
    }

    #[test]
    fn to_ns_filters() {
        let q = AlertQuery {
            to_ns: Some(500_000_000),
            ..Default::default()
        };
        assert!(!q.matches(&make_alert("ids", Severity::High, "ids-001", false)));

        let q2 = AlertQuery {
            to_ns: Some(2_000_000_000),
            ..Default::default()
        };
        assert!(q2.matches(&make_alert("ids", Severity::High, "ids-001", false)));
    }

    #[test]
    fn component_filter() {
        let q = AlertQuery {
            component: Some("dlp".to_string()),
            ..Default::default()
        };
        assert!(!q.matches(&make_alert("ids", Severity::High, "ids-001", false)));
        assert!(q.matches(&make_alert("dlp", Severity::High, "dlp-001", false)));
    }

    #[test]
    fn component_filter_case_insensitive() {
        let q = AlertQuery {
            component: Some("IDS".to_string()),
            ..Default::default()
        };
        assert!(q.matches(&make_alert("ids", Severity::High, "ids-001", false)));
    }

    #[test]
    fn severity_filter() {
        let q = AlertQuery {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        assert!(!q.matches(&make_alert("ids", Severity::Low, "ids-001", false)));
        assert!(!q.matches(&make_alert("ids", Severity::Medium, "ids-001", false)));
        assert!(q.matches(&make_alert("ids", Severity::High, "ids-001", false)));
        assert!(q.matches(&make_alert("ids", Severity::Critical, "ids-001", false)));
    }

    #[test]
    fn rule_id_filter() {
        let q = AlertQuery {
            rule_id: Some("ids-001".to_string()),
            ..Default::default()
        };
        assert!(q.matches(&make_alert("ids", Severity::High, "ids-001", false)));
        assert!(!q.matches(&make_alert("ids", Severity::High, "ids-002", false)));
    }

    #[test]
    fn false_positive_filter() {
        let q = AlertQuery {
            false_positive: Some(true),
            ..Default::default()
        };
        assert!(!q.matches(&make_alert("ids", Severity::High, "ids-001", false)));
        assert!(q.matches(&make_alert("ids", Severity::High, "ids-001", true)));

        let q2 = AlertQuery {
            false_positive: Some(false),
            ..Default::default()
        };
        assert!(q2.matches(&make_alert("ids", Severity::High, "ids-001", false)));
        assert!(!q2.matches(&make_alert("ids", Severity::High, "ids-001", true)));
    }

    #[test]
    fn combined_filters() {
        let q = AlertQuery {
            component: Some("ids".to_string()),
            min_severity: Some(Severity::High),
            false_positive: Some(false),
            ..Default::default()
        };
        assert!(q.matches(&make_alert("ids", Severity::High, "ids-001", false)));
        assert!(!q.matches(&make_alert("dlp", Severity::High, "dlp-001", false)));
        assert!(!q.matches(&make_alert("ids", Severity::Low, "ids-001", false)));
        assert!(!q.matches(&make_alert("ids", Severity::High, "ids-001", true)));
    }
}
