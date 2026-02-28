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
}
