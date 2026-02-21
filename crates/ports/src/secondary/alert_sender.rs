use std::future::Future;
use std::pin::Pin;

use domain::alert::entity::{Alert, AlertRoute};
use domain::common::error::DomainError;

/// Secondary port for sending alerts to external destinations.
///
/// Uses `Pin<Box<dyn Future>>` return type (instead of RPITIT) so the trait
/// is dyn-compatible and can be used as `Arc<dyn AlertSender>`.
pub trait AlertSender: Send + Sync {
    /// Send an alert to the destination specified by the route.
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
        route: &'a AlertRoute,
    ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::alert::entity::AlertDestination;
    use domain::common::entity::Severity;

    struct DummySender;
    impl AlertSender for DummySender {
        fn send<'a>(
            &'a self,
            _alert: &'a Alert,
            _route: &'a AlertRoute,
        ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn alert_sender_trait_is_implementable() {
        fn _assert_send_sync<T: AlertSender>() {}
        _assert_send_sync::<DummySender>();
    }

    #[test]
    fn alert_sender_is_dyn_compatible() {
        let sender: Box<dyn AlertSender> = Box::new(DummySender);
        let _ = sender;
    }

    #[test]
    fn alert_sender_types_compile() {
        let _alert = Alert {
            id: "test".to_string(),
            timestamp_ns: 0,
            component: "ids".to_string(),
            severity: Severity::Low,
            rule_id: domain::common::entity::RuleId("r1".to_string()),
            action: domain::common::entity::DomainMode::Alert,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            is_ipv6: false,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            message: "test".to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
        };
        let _route = AlertRoute {
            name: "test".to_string(),
            destination: AlertDestination::Log,
            min_severity: Severity::Low,
            event_types: None,
        };
    }
}
