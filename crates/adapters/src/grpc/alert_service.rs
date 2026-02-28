use domain::alert::entity::Alert;
use domain::common::entity::Severity;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};

use crate::grpc::proto;
use proto::alert_stream_service_server::AlertStreamService;

/// Converts a domain `Alert` to the protobuf `AlertEvent`.
fn alert_to_event(alert: &Alert) -> proto::AlertEvent {
    proto::AlertEvent {
        id: alert.id.clone(),
        timestamp_ns: alert.timestamp_ns,
        component: alert.component.clone(),
        severity: severity_label(alert.severity).to_string(),
        rule_id: alert.rule_id.0.clone(),
        action: alert.action.as_str().to_string(),
        src_addr: alert.src_addr.to_vec(),
        dst_addr: alert.dst_addr.to_vec(),
        src_port: u32::from(alert.src_port),
        dst_port: u32::from(alert.dst_port),
        protocol: u32::from(alert.protocol),
        message: alert.message.clone(),
        is_ipv6: alert.is_ipv6,
        false_positive: alert.false_positive,
        src_domain: alert.src_domain.clone().unwrap_or_default(),
        dst_domain: alert.dst_domain.clone().unwrap_or_default(),
        src_domain_score: alert.src_domain_score.unwrap_or(-1.0),
        dst_domain_score: alert.dst_domain_score.unwrap_or(-1.0),
        confidence: alert.confidence.map_or(-1, i32::from),
        threat_type: alert.threat_type.clone().unwrap_or_default(),
        data_type: alert.data_type.clone().unwrap_or_default(),
        pid: alert.pid.unwrap_or(0),
        tgid: alert.tgid.unwrap_or(0),
        direction: alert.direction.map_or(-1, i32::from),
        matched_domain: alert.matched_domain.clone().unwrap_or_default(),
        attack_type: alert.attack_type.clone().unwrap_or_default(),
        peak_pps: alert.peak_pps.unwrap_or(0),
        current_pps: alert.current_pps.unwrap_or(0),
        mitigation_status: alert.mitigation_status.clone().unwrap_or_default(),
        total_packets: alert.total_packets.unwrap_or(0),
    }
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Parse a severity string into a minimum severity u8 threshold.
/// Returns 0 (all) if empty or unrecognized.
fn parse_min_severity(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => 0, // "low" and unrecognized → show all
    }
}

/// gRPC implementation of the `AlertStreamService`.
///
/// Subscribes to a broadcast channel of domain `Alert`s and streams
/// them to connected clients with optional severity/component filtering.
pub struct AlertStreamServiceImpl {
    alert_tx: broadcast::Sender<Alert>,
}

impl AlertStreamServiceImpl {
    pub fn new(alert_tx: broadcast::Sender<Alert>) -> Self {
        Self { alert_tx }
    }
}

#[tonic::async_trait]
impl AlertStreamService for AlertStreamServiceImpl {
    type StreamAlertsStream = std::pin::Pin<
        Box<dyn tokio_stream::Stream<Item = Result<proto::AlertEvent, Status>> + Send>,
    >;

    async fn stream_alerts(
        &self,
        request: Request<proto::StreamAlertsRequest>,
    ) -> Result<Response<Self::StreamAlertsStream>, Status> {
        let req = request.into_inner();
        let min_severity = parse_min_severity(&req.min_severity);
        let component_filter = if req.component.is_empty() {
            None
        } else {
            Some(req.component.to_lowercase())
        };

        tracing::info!(
            min_severity = %req.min_severity,
            component = %req.component,
            "gRPC client subscribed to alert stream"
        );

        let rx = self.alert_tx.subscribe();
        let stream = BroadcastStream::new(rx);

        let output = tokio_stream::StreamExt::filter_map(stream, move |result| {
            match result {
                Ok(alert) => {
                    // Apply severity filter
                    if alert.severity.to_u8() < min_severity {
                        return None;
                    }
                    // Apply component filter
                    if let Some(ref comp) = component_filter
                        && alert.component.to_lowercase() != *comp
                    {
                        return None;
                    }
                    Some(Ok(alert_to_event(&alert)))
                }
                Err(_) => {
                    // Lagged — skip missed messages silently
                    None
                }
            }
        });

        Ok(Response::new(Box::pin(output)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, RuleId};

    fn make_alert(component: &str, severity: Severity, rule_id: &str) -> Alert {
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

    #[test]
    fn alert_to_event_maps_all_fields() {
        let alert = make_alert("ids", Severity::High, "ids-001");
        let event = alert_to_event(&alert);
        assert_eq!(event.id, "test-ids-001");
        assert_eq!(event.component, "ids");
        assert_eq!(event.severity, "high");
        assert_eq!(event.rule_id, "ids-001");
        assert_eq!(event.action, "alert");
        assert_eq!(event.src_addr, vec![0xC0A8_0001, 0, 0, 0]);
        assert_eq!(event.dst_addr, vec![0x0A00_0001, 0, 0, 0]);
        assert_eq!(event.src_port, 12345);
        assert_eq!(event.dst_port, 80);
        assert_eq!(event.protocol, 6);
        assert_eq!(event.message, "test alert");
        assert!(!event.is_ipv6);
        assert!(!event.false_positive);
        assert_eq!(event.src_domain, "");
        assert_eq!(event.dst_domain, "");
        assert_eq!(event.src_domain_score, -1.0);
        assert_eq!(event.dst_domain_score, -1.0);
    }

    #[test]
    fn parse_min_severity_values() {
        assert_eq!(parse_min_severity("low"), 0);
        assert_eq!(parse_min_severity("medium"), 1);
        assert_eq!(parse_min_severity("high"), 2);
        assert_eq!(parse_min_severity("critical"), 3);
        assert_eq!(parse_min_severity(""), 0);
        assert_eq!(parse_min_severity("unknown"), 0);
        assert_eq!(parse_min_severity("HIGH"), 2);
    }

    #[test]
    fn severity_label_mapping() {
        assert_eq!(severity_label(Severity::Low), "low");
        assert_eq!(severity_label(Severity::Medium), "medium");
        assert_eq!(severity_label(Severity::High), "high");
        assert_eq!(severity_label(Severity::Critical), "critical");
    }

    #[tokio::test]
    async fn stream_alerts_receives_broadcast() {
        let (tx, _rx) = broadcast::channel::<Alert>(16);
        let svc = AlertStreamServiceImpl::new(tx.clone());

        let request = Request::new(proto::StreamAlertsRequest {
            min_severity: String::new(),
            component: String::new(),
        });

        let response = svc.stream_alerts(request).await.unwrap();
        let mut stream = response.into_inner();

        // Send an alert after subscribing
        tx.send(make_alert("ids", Severity::High, "ids-001"))
            .unwrap();

        use tokio_stream::StreamExt;
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.rule_id, "ids-001");
        assert_eq!(event.severity, "high");
    }

    #[tokio::test]
    async fn stream_filters_by_severity() {
        let (tx, _rx) = broadcast::channel::<Alert>(16);
        let svc = AlertStreamServiceImpl::new(tx.clone());

        let request = Request::new(proto::StreamAlertsRequest {
            min_severity: "high".to_string(),
            component: String::new(),
        });

        let response = svc.stream_alerts(request).await.unwrap();
        let mut stream = response.into_inner();

        // Send a low-severity alert (should be filtered)
        tx.send(make_alert("ids", Severity::Low, "ids-low"))
            .unwrap();
        // Send a high-severity alert (should pass)
        tx.send(make_alert("ids", Severity::High, "ids-high"))
            .unwrap();

        use tokio_stream::StreamExt;
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.rule_id, "ids-high");
    }

    #[tokio::test]
    async fn stream_filters_by_component() {
        let (tx, _rx) = broadcast::channel::<Alert>(16);
        let svc = AlertStreamServiceImpl::new(tx.clone());

        let request = Request::new(proto::StreamAlertsRequest {
            min_severity: String::new(),
            component: "dlp".to_string(),
        });

        let response = svc.stream_alerts(request).await.unwrap();
        let mut stream = response.into_inner();

        // Send an IDS alert (should be filtered)
        tx.send(make_alert("ids", Severity::High, "ids-001"))
            .unwrap();
        // Send a DLP alert (should pass)
        tx.send(make_alert("dlp", Severity::High, "dlp-001"))
            .unwrap();

        use tokio_stream::StreamExt;
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.component, "dlp");
        assert_eq!(event.rule_id, "dlp-001");
    }
}
