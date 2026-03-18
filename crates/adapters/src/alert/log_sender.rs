use std::future::Future;
use std::pin::Pin;

use domain::alert::entity::{Alert, AlertRoute};
use domain::common::error::DomainError;
use ports::secondary::alert_sender::AlertSender;

/// Alert sender that logs alerts via tracing.
///
/// Used as the default sender when no external destination (email/webhook)
/// is configured.
pub struct LogAlertSender;

impl AlertSender for LogAlertSender {
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
        route: &'a AlertRoute,
    ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(
                alert_id = %alert.id,
                rule_id = %alert.rule_id,
                severity = ?alert.severity,
                component = %alert.component,
                route = %route.name,
                src_ip = alert.src_ip(),
                dst_ip = alert.dst_ip(),
                src_port = alert.src_port,
                dst_port = alert.dst_port,
                protocol = alert.protocol,
                action = %alert.action,
                message = %alert.message,
                "alert sent to log"
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::alert::entity::AlertDestination;
    use domain::common::entity::{DomainMode, RuleId, Severity};

    fn sample_alert() -> Alert {
        Alert {
            id: "1000000000-ids-001".to_string(),
            timestamp_ns: 1_000_000_000,
            component: "ids".to_string(),
            severity: Severity::High,
            rule_id: RuleId("ids-001".to_string()),
            action: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            is_ipv6: false,
            message: "SSH bruteforce detected".to_string(),
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
        }
    }

    fn sample_route() -> AlertRoute {
        AlertRoute {
            name: "log-all".to_string(),
            destination: AlertDestination::Log,
            min_severity: Severity::Low,
            event_types: None,
        }
    }

    #[tokio::test]
    async fn log_sender_succeeds() {
        let sender = LogAlertSender;
        let result = sender.send(&sample_alert(), &sample_route()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn log_sender_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LogAlertSender>();
    }

    #[tokio::test]
    async fn log_sender_returns_ok_for_any_severity() {
        let sender = LogAlertSender;
        let route = sample_route();
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let mut alert = sample_alert();
            alert.severity = severity;
            let result = sender.send(&alert, &route).await;
            assert!(result.is_ok(), "failed for severity {severity:?}");
        }
    }

    #[tokio::test]
    async fn log_sender_handles_alert_with_optional_fields() {
        let sender = LogAlertSender;
        let route = sample_route();
        let mut alert = sample_alert();
        alert.src_domain = Some("src.example.com".to_string());
        alert.dst_domain = Some("dst.example.com".to_string());
        alert.confidence = Some(95);
        alert.threat_type = Some("bruteforce".to_string());
        alert.data_type = Some("credential".to_string());
        alert.pid = Some(1234);
        alert.tgid = Some(5678);
        alert.direction = Some(0); // 0 = ingress
        alert.matched_domain = Some("evil.example.com".to_string());
        alert.attack_type = Some("syn_flood".to_string());
        alert.peak_pps = Some(100_000);
        alert.current_pps = Some(50_000);
        alert.mitigation_status = Some("active".to_string());
        alert.total_packets = Some(1_000_000);
        let result = sender.send(&alert, &route).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn log_sender_handles_ipv6_alert() {
        let sender = LogAlertSender;
        let route = sample_route();
        let mut alert = sample_alert();
        alert.is_ipv6 = true;
        // 2001:db8::1
        alert.src_addr = [0x2001_0db8, 0, 0, 1];
        // 2001:db8::2
        alert.dst_addr = [0x2001_0db8, 0, 0, 2];
        let result = sender.send(&alert, &route).await;
        assert!(result.is_ok());
    }
}
