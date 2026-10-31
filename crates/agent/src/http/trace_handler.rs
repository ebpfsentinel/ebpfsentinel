use std::net::IpAddr;
use std::sync::Arc;

use application::datapath_trace_service::{TraceNames, name_rules};
use axum::Json;
use axum::extract::State;
use domain::trace::{
    StageReport, StateDependence, TraceDirection, TraceError, TraceProtocol, TraceReport,
    TraceRequest,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::brokered::brokered;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Request / response DTOs ───────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct TraceRequestBody {
    /// Source address. Left out when `workload` names the source.
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Destination address, IPv4 or IPv6.
    pub dst_ip: String,
    /// Source port; zero or absent picks an ephemeral port. Ignored for ICMP.
    #[serde(default)]
    pub src_port: u16,
    /// Destination port, required for TCP and UDP.
    #[serde(default)]
    pub dst_port: u16,
    /// `tcp`, `udp` or `icmp`.
    pub protocol: String,
    /// `ingress` (default) or `egress`.
    #[serde(default)]
    pub direction: Option<String>,
    /// A pod as `namespace/name`, whose address becomes the source.
    #[serde(default)]
    pub workload: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct TraceStage {
    /// The stage, as `firewall`, `rate_limit`, `ids`, `nat_egress`...
    pub stage: String,
    /// `xdp`, `tc_ingress` or `tc_egress`.
    pub hook: String,
    /// `pass`, `log`, `drop`, `reject`, `bounce`, `redirect`, `abort` or `other`.
    pub verdict: String,
    /// Why the stage decided: `default`, `rule`, `established`, `rate`,
    /// `list`, `malformed`, `disabled`, `rewrite` or `unrecorded`.
    pub reason: String,
    /// The rule identifier as the stage numbers its rules.
    pub rule_id: Option<u32>,
    /// The rule's name, where the agent could name it.
    pub rule: Option<String>,
    /// What the stage adds in its own terms.
    pub detail: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct TraceStateDependence {
    pub stage: String,
    /// The state the verdict depends on, in a sentence.
    pub depends_on: String,
}

#[derive(Serialize, ToSchema)]
pub struct TraceResponse {
    /// The source address the packet was crafted from.
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub direction: String,
    /// Each stage the packet crossed, in the order it crossed them.
    pub stages: Vec<TraceStage>,
    /// The stage the packet stopped at, absent when it went through.
    pub stopped_at: Option<String>,
    /// The verdict at that stage, or `pass` when the packet went through.
    pub verdict: String,
    /// Verdicts that hold for this packet now and not for every packet of
    /// the five-tuple.
    pub state_dependent: Vec<TraceStateDependence>,
    /// Programs of this direction that are not loaded, so the trace could
    /// not ask them.
    pub not_loaded: Vec<String>,
}

/// The wire name serde gives a unit enum variant.
fn label<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => s,
        _ => String::new(),
    }
}

fn parse_request(body: TraceRequestBody) -> Result<TraceRequest, ApiError> {
    let bad = |message: String| ApiError::BadRequest {
        code: "INVALID_TRACE",
        message,
    };
    let ip = |field: &str, raw: &str| {
        raw.trim()
            .parse::<IpAddr>()
            .map_err(|_| bad(format!("{field} is not an IP address: {raw}")))
    };
    let src_ip = body
        .src_ip
        .as_deref()
        .map(|s| ip("src_ip", s))
        .transpose()?;
    let dst_ip = ip("dst_ip", &body.dst_ip)?;
    let protocol = match body.protocol.to_ascii_lowercase().as_str() {
        "tcp" => TraceProtocol::Tcp,
        "udp" => TraceProtocol::Udp,
        "icmp" | "icmpv6" => TraceProtocol::Icmp,
        other => return Err(bad(format!("unknown protocol {other}: tcp, udp or icmp"))),
    };
    let direction = match body.direction.as_deref().map(str::to_ascii_lowercase) {
        None => TraceDirection::Ingress,
        Some(d) if d == "ingress" => TraceDirection::Ingress,
        Some(d) if d == "egress" => TraceDirection::Egress,
        Some(other) => return Err(bad(format!("unknown direction {other}: ingress or egress"))),
    };
    Ok(TraceRequest {
        src_ip,
        dst_ip,
        src_port: body.src_port,
        dst_port: body.dst_port,
        protocol,
        direction,
        workload: body.workload.filter(|w| !w.trim().is_empty()),
    })
}

fn stage_dto(stage: &StageReport) -> TraceStage {
    TraceStage {
        stage: label(&stage.stage),
        hook: label(&stage.hook),
        verdict: label(&stage.verdict),
        reason: label(&stage.reason),
        rule_id: stage.rule_id,
        rule: stage.rule.clone(),
        detail: stage.detail.clone(),
    }
}

fn dependence_dto(dep: &StateDependence) -> TraceStateDependence {
    TraceStateDependence {
        stage: label(&dep.stage),
        depends_on: dep.depends_on.clone(),
    }
}

fn trace_response(report: &TraceReport) -> TraceResponse {
    let request = &report.request;
    TraceResponse {
        src_ip: report.src_ip.to_string(),
        dst_ip: request.dst_ip.to_string(),
        src_port: request.effective_src_port(),
        dst_port: request.effective_dst_port(),
        protocol: label(&request.protocol),
        direction: label(&request.direction),
        stages: report.stages.iter().map(stage_dto).collect(),
        stopped_at: report.stopped_at.as_ref().map(label),
        verdict: label(&report.verdict),
        state_dependent: report.state_dependent.iter().map(dependence_dto).collect(),
        not_loaded: report.not_loaded.clone(),
    }
}

fn trace_error(error: &TraceError) -> ApiError {
    match error {
        TraceError::Invalid(_) | TraceError::Workload { .. } => ApiError::BadRequest {
            code: "INVALID_TRACE",
            message: error.to_string(),
        },
        TraceError::Unavailable(_) => ApiError::ServiceUnavailable {
            message: error.to_string(),
        },
    }
}

// ── Handlers ──────────────────────────────────────────────────────

/// `POST /api/v1/trace` - what the loaded programs decide for one packet.
///
/// A packet is crafted from the five-tuple and run through the programs in
/// the order the hooks run them, with no interface and no traffic. Every
/// program reads its maps and skips its writes, so a trace changes no state.
/// A verdict that depends on state the crafted packet does not carry, an
/// established connection or a rate already spent, is reported as such.
#[utoipa::path(
    post, path = "/api/v1/trace",
    tag = "Trace",
    request_body = TraceRequestBody,
    responses((status = 200, description = "Each stage the packet crossed and where it stopped", body = TraceResponse),
        (status = 400, description = "The request does not describe one packet, or the workload has no address", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "No eBPF program is loaded on this node", body = ErrorBody),
        (status = 503, description = "The kernel refused to run the programs", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn trace_packet(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TraceRequestBody>,
) -> Result<Json<TraceResponse>, ApiError> {
    let tracer = state.datapath_trace.load_full().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "no eBPF program is loaded on this node, so there is nothing to trace".to_string(),
    })?;
    let request = parse_request(body)?;
    // The programs run in the kernel and the workload lookup may read the
    // cluster view: both block, so neither runs on the async worker.
    let mut report = brokered("packet trace", move || tracer.trace(request))
        .await
        .map_err(|message| ApiError::Internal { message })?
        .map_err(|e| trace_error(&e))?;

    let firewall = state.firewall_service.read().await;
    let ids = state.ids_service.as_ref().map(|s| s.load_full());
    let threatintel = state.threatintel_service.load_full();
    let feed = |ip: &IpAddr| threatintel.lookup(ip).map(|ioc| ioc.feed_id.clone());
    name_rules(
        &mut report,
        &TraceNames {
            firewall: Some(firewall.trace_index()),
            ids_rules: ids.as_ref().map_or(&[], |s| s.list_rules()),
            threat_feed: Some(&feed),
        },
    );
    Ok(Json(trace_response(&report)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::trace::{Reason, Stage, TraceHook, Verdict};

    fn body(protocol: &str) -> TraceRequestBody {
        TraceRequestBody {
            src_ip: Some("10.0.0.1".into()),
            dst_ip: "10.0.0.2".into(),
            src_port: 0,
            dst_port: 443,
            protocol: protocol.into(),
            direction: None,
            workload: None,
        }
    }

    #[test]
    fn a_request_reads_into_one_packet() {
        let request = parse_request(body("TCP")).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(request.protocol, TraceProtocol::Tcp);
        assert_eq!(request.direction, TraceDirection::Ingress);
        assert_eq!(request.dst_port, 443);
    }

    #[test]
    fn an_unknown_protocol_or_direction_is_refused() {
        assert!(parse_request(body("sctp")).is_err());
        let mut sideways = body("udp");
        sideways.direction = Some("sideways".into());
        assert!(parse_request(sideways).is_err());
        let mut bad_ip = body("udp");
        bad_ip.dst_ip = "not-an-ip".into();
        assert!(parse_request(bad_ip).is_err());
    }

    #[test]
    fn the_report_reads_as_the_cli_and_console_show_it() {
        let request = parse_request(body("tcp")).unwrap_or_else(|e| panic!("{e:?}"));
        let report = TraceReport {
            src_ip: "10.0.0.1"
                .parse()
                .unwrap_or(std::net::Ipv4Addr::LOCALHOST.into()),
            request,
            stages: vec![StageReport {
                stage: Stage::Firewall,
                hook: TraceHook::Xdp,
                verdict: Verdict::Drop,
                reason: Reason::Rule,
                rule_id: Some(3),
                rule: Some("deny-https".into()),
                detail: None,
            }],
            stopped_at: Some(Stage::Firewall),
            verdict: Verdict::Drop,
            state_dependent: vec![],
            not_loaded: vec!["tc_qos_ingress".into()],
        };
        let response = trace_response(&report);
        assert_eq!(response.stages[0].stage, "firewall");
        assert_eq!(response.stages[0].hook, "xdp");
        assert_eq!(response.verdict, "drop");
        assert_eq!(response.stopped_at.as_deref(), Some("firewall"));
        assert_eq!(response.src_port, 40_000);
        assert_eq!(response.protocol, "tcp");
    }
}
