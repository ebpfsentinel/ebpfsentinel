use domain::alert::entity::Alert;

/// Secondary port for enriching alerts with additional context.
///
/// Implementations may add DNS reverse-lookup data, reputation scores,
/// or other contextual information to an alert before dispatch.
pub trait AlertEnrichmentPort: Send + Sync {
    /// Enrich an alert in place with additional context.
    ///
    /// Best-effort: if enrichment data is unavailable, fields remain `None`.
    fn enrich_alert(&self, alert: &mut Alert);
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, RuleId, Severity};

    struct MockEnricher;

    impl AlertEnrichmentPort for MockEnricher {
        fn enrich_alert(&self, alert: &mut Alert) {
            alert.src_domain = Some("enriched.example.com".to_string());
        }
    }

    fn sample_alert() -> Alert {
        Alert {
            id: "test-1".to_string(),
            timestamp_ns: 1000,
            component: "ids".to_string(),
            severity: Severity::Medium,
            rule_id: RuleId("rule-1".to_string()),
            action: DomainMode::Alert,
            src_addr: [0x0A00_0001, 0, 0, 0],
            dst_addr: [0x0A00_0002, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            is_ipv6: false,
            message: "test alert".to_string(),
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
            mitre_attack: None,
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
        }
    }

    #[test]
    fn enrich_alert_adds_context() {
        let enricher = MockEnricher;
        let mut alert = sample_alert();
        assert!(alert.src_domain.is_none());

        enricher.enrich_alert(&mut alert);
        assert_eq!(alert.src_domain, Some("enriched.example.com".to_string()));
    }

    #[test]
    fn object_safe() {
        fn _check(_: &dyn AlertEnrichmentPort) {}
    }
}
