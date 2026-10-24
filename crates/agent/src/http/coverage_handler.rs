use std::sync::Arc;

use application::pod_coverage_service::NodeCoverage;
use axum::Json;
use axum::extract::State;
use domain::coverage::{ClassCoverage, CoverageLevel, GapReason, InterfaceCoverage, PodCoverage};
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct CoverageInterface {
    /// Interface name in the host namespace.
    pub name: String,
    /// `veth`, `netkit`, `macvlan`, `ipvlan`, `bridge-member`, or the
    /// kernel's own word for a kind the agent does not attach to.
    pub kind: String,
    /// Every program of the chain is on the link.
    pub attached: bool,
    /// Why it is not, as a stable code. Absent when attached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// The same reason in a sentence. Absent when attached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CoverageClass {
    /// `north_south`, `east_west_across_nodes`, `east_west_on_node` or
    /// `loopback`.
    pub class: String,
    /// The agent's chain sees this traffic.
    pub observed: bool,
    /// Why it does not, as a stable code. Absent when observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gap: Option<String>,
    /// The same reason in a sentence. Absent when observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// An agent under the pod profile would see this traffic. Absent when
    /// observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_by_pod_profile: Option<bool>,
}

#[derive(Serialize, ToSchema)]
pub struct PodCoverageEntry {
    pub uid: String,
    pub name: String,
    pub namespace: String,
    /// The pod shares the node's network namespace.
    pub host_network: bool,
    /// `none`, `partial` or `full`, loopback aside: no node agent sees a
    /// pod's loopback.
    pub level: String,
    /// The links found leading into the pod; empty for a host-network pod,
    /// or when none was found.
    pub interfaces: Vec<CoverageInterface>,
    /// One entry per traffic class, in a fixed order.
    pub classes: Vec<CoverageClass>,
    /// A class other than loopback is missed for a reason the pod profile
    /// closes. Loopback alone never sets it.
    pub pod_profile_recommended: bool,
}

#[derive(Serialize, ToSchema)]
pub struct EbpfCoverageResponse {
    /// The chain is on the node's configured interfaces.
    pub uplinks_attached: bool,
    /// The node carries an encapsulating device, so traffic between nodes
    /// crosses the uplink inside an outer header.
    pub encapsulated: bool,
    /// Workload links whose owner names no pod the inventory holds.
    pub links_without_pod: usize,
    /// Pods with no class observed.
    pub uncovered: usize,
    /// Pods with some classes observed.
    pub partial: usize,
    /// Pods with every class but loopback observed.
    pub full: usize,
    /// Pods whose verdict argues for the pod profile.
    pub pod_profile_recommended: usize,
    /// One verdict per pod, uncovered first.
    pub pods: Vec<PodCoverageEntry>,
}

fn interface_entry(i: InterfaceCoverage) -> CoverageInterface {
    let gap = i.refusal.map(GapReason::LinkRefused);
    CoverageInterface {
        name: i.name,
        kind: i.kind,
        attached: i.attached,
        refusal: gap.as_ref().map(|g| g.code().to_owned()),
        reason: gap.as_ref().map(GapReason::describe),
    }
}

fn class_entry(c: ClassCoverage) -> CoverageClass {
    CoverageClass {
        class: c.class.as_str().to_owned(),
        observed: c.observed,
        reason: c.gap.as_ref().map(GapReason::describe),
        closed_by_pod_profile: c.gap.as_ref().map(GapReason::closed_by_pod_profile),
        gap: c.gap.map(|g| g.code().to_owned()),
    }
}

fn pod_entry(p: PodCoverage) -> PodCoverageEntry {
    let pod_profile_recommended = p.pod_profile_recommended();
    PodCoverageEntry {
        pod_profile_recommended,
        uid: p.uid,
        name: p.name,
        namespace: p.namespace,
        host_network: p.host_network,
        level: p.level.as_str().to_owned(),
        interfaces: p.interfaces.into_iter().map(interface_entry).collect(),
        classes: p.classes.into_iter().map(class_entry).collect(),
    }
}

fn coverage_body(report: NodeCoverage) -> EbpfCoverageResponse {
    let count = |level| report.pods.iter().filter(|p| p.level == level).count();
    EbpfCoverageResponse {
        uplinks_attached: report.node.uplinks_attached,
        encapsulated: report.node.encapsulated,
        links_without_pod: report.links_without_pod,
        uncovered: count(CoverageLevel::None),
        partial: count(CoverageLevel::Partial),
        full: count(CoverageLevel::Full),
        pod_profile_recommended: report
            .pods
            .iter()
            .filter(|p| p.pod_profile_recommended())
            .count(),
        pods: report.pods.into_iter().map(pod_entry).collect(),
    }
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/ebpf/coverage` - what the agent sees of each pod on this node.
///
/// Computed from the links the chain is actually on, so a pod whose link was
/// refused is reported with the reason rather than counted as watched.
#[utoipa::path(
    get, path = "/api/v1/ebpf/coverage",
    tag = "Operations",
    responses(
        (status = 200, description = "One verdict per pod on this node, uncovered first", body = EbpfCoverageResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "No pod inventory on this node: Kubernetes enrichment is off or the agent was built without it", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_ebpf_coverage(
    State(state): State<Arc<AppState>>,
) -> Result<Json<EbpfCoverageResponse>, ApiError> {
    let report = state
        .pod_coverage
        .verdicts()
        .await
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "no pod inventory on this node: Kubernetes enrichment is off, its client \
                      did not build, or the agent was built without Kubernetes support"
                .to_string(),
        })?;
    Ok(Json(coverage_body(report)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use domain::coverage::{
        LinkAttachment, LinkRefusal, NodeView, PodSubject, WorkloadLink, node_verdicts,
    };

    #[test]
    fn absent_reasons_are_absent_and_present_ones_carry_code_and_sentence() {
        let pods = vec![
            PodSubject {
                uid: "a".into(),
                name: "web".into(),
                namespace: "shop".into(),
                host_network: false,
                labels: std::collections::BTreeMap::new(),
            },
            PodSubject {
                uid: "b".into(),
                name: "db".into(),
                namespace: "shop".into(),
                host_network: false,
                labels: std::collections::BTreeMap::new(),
            },
        ];
        let links = vec![
            WorkloadLink {
                ifindex: 1,
                name: "veth1".into(),
                kind: "veth".into(),
                attachment: LinkAttachment::Attached,
                pod_uid: Some("a".into()),
            },
            WorkloadLink {
                ifindex: 2,
                name: "veth2".into(),
                kind: "veth".into(),
                attachment: LinkAttachment::Refused(LinkRefusal::AttachMode("netkit".into())),
                pod_uid: Some("b".into()),
            },
        ];
        let node = NodeView {
            uplinks_attached: true,
            encapsulated: false,
        };
        let body = coverage_body(NodeCoverage {
            node,
            links_without_pod: 0,
            pods: node_verdicts(&pods, &links, node),
        });
        assert_eq!((body.uncovered, body.partial, body.full), (0, 1, 1));
        let json = serde_json::to_value(&body).unwrap();
        let db = &json["pods"][0];
        assert_eq!(db["name"], "db");
        assert_eq!(db["interfaces"][0]["refusal"], "attach_mode_skips_kind");
        assert_eq!(db["classes"][2]["gap"], "attach_mode_skips_kind");
        assert!(db["classes"][0].get("gap").is_none());
        let web = &json["pods"][1];
        assert!(web["interfaces"][0].get("refusal").is_none());
        assert_eq!(web["level"], "full");
        assert_eq!(body.pod_profile_recommended, 1);
        assert_eq!(db["pod_profile_recommended"], true);
        assert_eq!(db["classes"][2]["closed_by_pod_profile"], true);
        assert!(db["classes"][0].get("closed_by_pod_profile").is_none());
        assert_eq!(web["pod_profile_recommended"], false);
    }
}
