use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::drops::describe;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// Packets the kernel dropped for one reason on one interface.
#[derive(Debug, Serialize, ToSchema)]
pub struct DropReasonBody {
    /// The reason as the running kernel names it, for instance `NO_SOCKET`.
    pub reason: String,
    /// The device name the packet was on, `if<index>` when the packet had no
    /// device left but remembered the index it arrived on, `none` when it had
    /// neither.
    pub interface: String,
    /// Drops counted since the counter was loaded.
    pub packets: u64,
    /// What the reason means, in plain language. Absent for a reason the
    /// agent does not describe, which is still counted under its own name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'static str>,
}

/// The kernel's drop counts on this node.
#[derive(Debug, Serialize, ToSchema)]
pub struct DropReasonsResponse {
    /// Whether the counter is attached.
    pub counting: bool,
    /// Why it is not, in one sentence. Absent when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Drops counted under a reason and an interface.
    pub total: u64,
    /// Drops seen but not counted under a pair, because the kernel-side map
    /// held as many pairs as it can.
    pub uncounted: u64,
    /// Why the last read of the counter failed. Absent when it succeeded;
    /// the counts are then the last ones read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Counts, busiest first.
    pub drops: Vec<DropReasonBody>,
}

/// `GET /api/v1/ebpf/drop-reasons` - why the kernel dropped packets.
#[utoipa::path(
    get, path = "/api/v1/ebpf/drop-reasons",
    tag = "Operations",
    responses((status = 200, description = "Kernel drop counts by reason and interface", body = DropReasonsResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_drop_reasons(State(state): State<Arc<AppState>>) -> Json<DropReasonsResponse> {
    let status = adapters::ebpf::drop_reason::status();
    let Some(service) = state.kernel_drops.load_full() else {
        return Json(DropReasonsResponse {
            counting: false,
            reason: Some(
                status
                    .reason
                    .unwrap_or_else(|| "the drop counter is not running".to_string()),
            ),
            total: 0,
            uncounted: 0,
            last_error: None,
            drops: Vec::new(),
        });
    };
    let snapshot = service.snapshot();
    Json(DropReasonsResponse {
        counting: status.attached,
        reason: status.reason,
        total: snapshot.reading.total(),
        uncounted: snapshot.reading.uncounted,
        last_error: snapshot.last_error,
        drops: snapshot
            .reading
            .counts
            .into_iter()
            .map(|c| DropReasonBody {
                description: describe(&c.reason),
                reason: c.reason,
                interface: c.interface,
                packets: c.packets,
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_described_reason_carries_its_description_and_another_does_not() {
        let described = DropReasonBody {
            reason: "NO_SOCKET".into(),
            interface: "eth0".into(),
            packets: 3,
            description: describe("NO_SOCKET"),
        };
        let json = serde_json::to_value(&described).unwrap_or_default();
        assert_eq!(json["interface"], "eth0");
        assert!(json["description"].is_string());
        let undescribed = DropReasonBody {
            description: describe("SUBSYS_OPENVSWITCH"),
            ..described
        };
        let json = serde_json::to_value(&undescribed).unwrap_or_default();
        assert!(json.get("description").is_none());
    }
}
