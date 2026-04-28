//! Pure-domain alert filter used by the SSE alerts stream and the
//! historical alert query.
//!
//! Lives in `domain` so the adapter (HTTP/SSE handler), the application
//! pipeline (replay buffer scan), and the fuzz harness can all share the
//! exact same matching semantics. No I/O, no external deps beyond
//! `domain::common`.

use thiserror::Error;

use crate::alert::entity::Alert;
use crate::common::entity::Severity;

/// Compile errors surfaced when turning raw query parameters into an
/// [`AlertFilter`]. Carries a stable code so the HTTP layer can return a
/// deterministic 400 response.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FilterError {
    #[error("severity_min must be one of low|medium|high|critical, got {value:?}")]
    InvalidSeverity { value: String },
}

impl FilterError {
    /// Stable error code used by HTTP / API responses.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidSeverity { .. } => "INVALID_SEVERITY",
        }
    }
}

/// Server-side alert filter. Empty fields mean "do not filter on this
/// dimension". Matching is `AND` across fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AlertFilter {
    pub severity_min: Option<Severity>,
    pub component: Option<String>,
    pub mitre_tactic: Option<String>,
}

impl AlertFilter {
    /// Compile a filter from raw query-parameter strings. Returns the
    /// first validation error encountered.
    pub fn compile(
        severity_min: Option<&str>,
        component: Option<String>,
        mitre_tactic: Option<String>,
    ) -> Result<Self, FilterError> {
        let severity_min = match severity_min {
            None => None,
            Some(s) => match parse_severity(s) {
                Some(sev) => Some(sev),
                None => {
                    return Err(FilterError::InvalidSeverity {
                        value: s.to_owned(),
                    });
                }
            },
        };
        Ok(Self {
            severity_min,
            component,
            mitre_tactic,
        })
    }

    /// True when `alert` satisfies every filter dimension.
    #[must_use]
    pub fn matches(&self, alert: &Alert) -> bool {
        if let Some(min) = self.severity_min
            && severity_rank(alert.severity) < severity_rank(min)
        {
            return false;
        }
        if let Some(ref component) = self.component
            && !alert.component.eq_ignore_ascii_case(component)
        {
            return false;
        }
        if let Some(ref tactic) = self.mitre_tactic {
            let ok = alert
                .mitre_attack
                .as_ref()
                .is_some_and(|m| m.tactic.eq_ignore_ascii_case(tactic));
            if !ok {
                return false;
            }
        }
        true
    }
}

/// Map a textual severity (case-insensitive) onto the domain enum.
#[must_use]
pub fn parse_severity(value: &str) -> Option<Severity> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

#[inline]
fn severity_rank(severity: Severity) -> u8 {
    severity.to_u8()
}

#[cfg(test)]
mod tests {
    use super::{AlertFilter, FilterError, parse_severity};
    use crate::alert::entity::Alert;
    use crate::alert::mitre::MitreAttackInfo;
    use crate::common::entity::{DomainMode, RuleId, Severity};

    fn alert(component: &str, severity: Severity, tactic: Option<&str>) -> Alert {
        Alert {
            id: "id-1".to_string(),
            timestamp_ns: 0,
            component: component.to_string(),
            severity,
            rule_id: RuleId(String::new()),
            action: DomainMode::Alert,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
            message: String::new(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
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
            mitre_attack: tactic.map(|t| MitreAttackInfo {
                technique_id: "T0000".to_string(),
                technique_name: "Test".to_string(),
                tactic: t.to_string(),
            }),
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
            container_metadata: None,
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        let filter = AlertFilter::default();
        assert!(filter.matches(&alert("ids", Severity::Low, None)));
    }

    #[test]
    fn severity_floor_filters_below() {
        let filter = AlertFilter::compile(Some("high"), None, None).unwrap();
        assert!(!filter.matches(&alert("ids", Severity::Medium, None)));
        assert!(filter.matches(&alert("ids", Severity::High, None)));
        assert!(filter.matches(&alert("ids", Severity::Critical, None)));
    }

    #[test]
    fn component_match_is_case_insensitive() {
        let filter = AlertFilter::compile(None, Some("IDS".to_string()), None).unwrap();
        assert!(filter.matches(&alert("ids", Severity::Low, None)));
        assert!(!filter.matches(&alert("dlp", Severity::Low, None)));
    }

    #[test]
    fn tactic_filter_requires_mitre_metadata() {
        let filter = AlertFilter::compile(None, None, Some("exfiltration".to_string())).unwrap();
        assert!(!filter.matches(&alert("ids", Severity::Low, None)));
        assert!(filter.matches(&alert("ids", Severity::Low, Some("Exfiltration"))));
        assert!(!filter.matches(&alert("ids", Severity::Low, Some("impact"))));
    }

    #[test]
    fn invalid_severity_min_rejected() {
        let err = AlertFilter::compile(Some("urgent"), None, None).unwrap_err();
        assert_eq!(
            err,
            FilterError::InvalidSeverity {
                value: "urgent".to_string()
            }
        );
        assert_eq!(err.code(), "INVALID_SEVERITY");
    }

    #[test]
    fn parse_severity_handles_case() {
        assert_eq!(parse_severity("LOW"), Some(Severity::Low));
        assert_eq!(parse_severity("Medium"), Some(Severity::Medium));
        assert_eq!(parse_severity("HiGh"), Some(Severity::High));
        assert_eq!(parse_severity("critical"), Some(Severity::Critical));
        assert_eq!(parse_severity("urgent"), None);
        assert_eq!(parse_severity(""), None);
    }
}
