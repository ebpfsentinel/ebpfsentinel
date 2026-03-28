use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Path, State};
use domain::capture::entity::{CaptureSession, CaptureStatus};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;
use super::validation::validate_string_length;

/// Maximum BPF filter expression length.
const MAX_BPF_FILTER_LENGTH: usize = 2048;

// ── DTOs ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct StartCaptureRequest {
    /// BPF filter expression (e.g. "host 1.2.3.4 and port 443").
    pub filter: String,
    /// Capture duration in seconds (max configurable).
    pub duration_seconds: u64,
    /// Snap length: max bytes per packet (default 1500).
    #[serde(default = "default_snap_length")]
    pub snap_length: u32,
    /// Network interface (default: first configured interface).
    #[serde(default)]
    pub interface: Option<String>,
}

fn default_snap_length() -> u32 {
    1500
}

#[derive(Serialize, ToSchema)]
pub struct CaptureResponse {
    pub id: String,
    pub filter: String,
    pub duration_secs: u64,
    pub snap_length: u32,
    pub output_path: String,
    pub interface: String,
    pub status: String,
    pub file_size_bytes: u64,
    pub packets_captured: u64,
}

#[derive(Serialize, ToSchema)]
pub struct CaptureListResponse {
    pub captures: Vec<CaptureResponse>,
}

// ── Handlers ─────────────────────────────────────────────────────────

/// `POST /api/v1/captures/manual` — start a time-bounded packet capture.
#[utoipa::path(
    post, path = "/api/v1/captures/manual",
    tag = "Captures",
    request_body = StartCaptureRequest,
    responses(
        (status = 201, description = "Capture started", body = CaptureResponse),
        (status = 409, description = "Another capture is already running"),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn start_capture(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartCaptureRequest>,
) -> Result<Json<CaptureResponse>, ApiError> {
    let capture_engine = state
        .capture_engine
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "capture engine not configured".to_string(),
        })?;

    let now_ns: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX);

    let id = format!("cap-{}", now_ns / 1_000_000);
    // Defensive: ID is server-generated but verify it is path-safe (alphanumeric + hyphen)
    debug_assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    let interface = req.interface.unwrap_or_else(|| "any".to_string());

    // Validate BPF filter length
    validate_string_length("filter", &req.filter, MAX_BPF_FILTER_LENGTH)?;

    // Validate BPF filter: reject control characters (NUL, CR, LF, etc.)
    if req
        .filter
        .bytes()
        .any(|b| b.is_ascii_control() && b != b' ')
    {
        return Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: "BPF filter contains invalid control characters".to_string(),
        });
    }

    // Validate interface name (same rules as firewall scope validation)
    if interface != "any" {
        if interface.is_empty() || interface.len() > 15 {
            return Err(ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!("interface name must be 1-15 characters, got '{interface}'"),
            });
        }
        if !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':')
        {
            return Err(ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!("interface name contains invalid characters: '{interface}'"),
            });
        }
    }

    let output_path = format!("/var/lib/ebpfsentinel/captures/{id}.pcap");

    let session = CaptureSession {
        id: id.clone(),
        filter: req.filter,
        duration_secs: req.duration_seconds,
        snap_length: req.snap_length,
        output_path: output_path.clone(),
        interface: interface.clone(),
        status: CaptureStatus::Running,
        started_at_ns: now_ns,
        file_size_bytes: 0,
        packets_captured: 0,
    };

    {
        let mut engine = capture_engine.write().await;
        engine
            .start(session.clone())
            .map_err(|e| ApiError::Conflict {
                code: "CAPTURE_CONFLICT",
                message: e,
            })?;
    }

    // Build response before spawning (session is moved into the task)
    let resp = to_response(&session);

    // Spawn pcap capture in background (requires pcap-capture feature + libpcap-dev)
    #[cfg(feature = "pcap-capture")]
    {
        let cap_engine = Arc::clone(capture_engine);
        tokio::spawn(run_pcap_capture(
            session.id,
            session.interface,
            session.filter,
            session.duration_secs,
            session.snap_length,
            session.output_path,
            cap_engine,
        ));
    }
    #[cfg(not(feature = "pcap-capture"))]
    {
        let _ = capture_engine;
        tracing::warn!(capture_id = %session.id, "pcap capture requires the pcap-capture feature and libpcap-dev");
        // Session is registered but no actual capture runs without the feature
    }

    Ok(Json(resp))
}

/// `GET /api/v1/captures` — list all captures.
#[utoipa::path(
    get, path = "/api/v1/captures",
    tag = "Captures",
    responses(
        (status = 200, description = "Capture sessions", body = CaptureListResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_captures(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CaptureListResponse>, ApiError> {
    let capture_engine = state
        .capture_engine
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "capture engine not configured".to_string(),
        })?;

    let engine = capture_engine.read().await;
    let captures: Vec<CaptureResponse> = engine.list().iter().map(|s| to_response(s)).collect();

    Ok(Json(CaptureListResponse { captures }))
}

/// `DELETE /api/v1/captures/{id}` — stop a running capture.
#[utoipa::path(
    delete, path = "/api/v1/captures/{id}",
    tag = "Captures",
    params(("id" = String, Path, description = "Capture session ID")),
    responses(
        (status = 200, description = "Capture stopped", body = CaptureResponse),
        (status = 404, description = "Capture not found"),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn stop_capture(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<CaptureResponse>, ApiError> {
    let capture_engine = state
        .capture_engine
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "capture engine not configured".to_string(),
        })?;

    let mut engine = capture_engine.write().await;
    let session = engine.stop(&id).ok_or(ApiError::NotFound {
        code: "CAPTURE_NOT_FOUND",
        message: format!("capture '{id}' not found"),
    })?;

    Ok(Json(to_response(session)))
}

// ── libpcap capture ──────────────────────────────────────────────────

/// Run a packet capture using the `pcap` crate (libpcap).
#[cfg(feature = "pcap-capture")]
///
/// Spawned on a blocking thread via `tokio::task::spawn_blocking` because
/// libpcap's `next_packet()` blocks.
pub async fn run_pcap_capture(
    id: String,
    interface: String,
    filter: String,
    duration_secs: u64,
    snap_length: u32,
    output_path: String,
    engine: Arc<tokio::sync::RwLock<domain::capture::engine::CaptureEngine>>,
) {
    let result = tokio::task::spawn_blocking(move || {
        pcap_capture_blocking(
            &id,
            &interface,
            &filter,
            duration_secs,
            snap_length,
            &output_path,
        )
    })
    .await;

    let (cap_id, packets, file_size) = match result {
        Ok(Ok(stats)) => stats,
        Ok(Err((cap_id, err))) => {
            tracing::error!(capture_id = %cap_id, error = %err, "pcap capture failed");
            engine.write().await.fail(&cap_id);
            return;
        }
        Err(e) => {
            tracing::error!(error = %e, "pcap capture task panicked");
            return;
        }
    };

    let mut eng = engine.write().await;
    if eng.get(&cap_id).map(|s| s.status) == Some(CaptureStatus::Stopped) {
        tracing::info!(capture_id = %cap_id, "capture stopped by operator");
    } else {
        eng.complete(&cap_id, file_size, packets);
        tracing::info!(capture_id = %cap_id, packets, file_size, "capture completed");
    }
}

/// Blocking capture loop — runs on a dedicated thread.
#[cfg(feature = "pcap-capture")]
fn pcap_capture_blocking(
    id: &str,
    interface: &str,
    filter: &str,
    duration_secs: u64,
    snap_length: u32,
    output_path: &str,
) -> Result<(String, u64, u64), (String, String)> {
    let device = if interface == "any" {
        pcap::Device::lookup()
            .map_err(|e| (id.to_string(), format!("device lookup failed: {e}")))?
            .ok_or_else(|| (id.to_string(), "no capture device found".to_string()))?
    } else {
        pcap::Device::from(interface)
    };

    let mut cap = pcap::Capture::from_device(device)
        .map_err(|e| (id.to_string(), format!("capture init failed: {e}")))?
        .snaplen(snap_length.try_into().unwrap_or(i32::MAX))
        .timeout(1000) // 1s read timeout for periodic stop checks
        .open()
        .map_err(|e| (id.to_string(), format!("capture open failed: {e}")))?;

    if !filter.is_empty() {
        cap.filter(filter, true).map_err(|e| {
            tracing::debug!(error = %e, "BPF filter compilation failed");
            (
                id.to_string(),
                "BPF filter compilation failed — check filter syntax".to_string(),
            )
        })?;
    }

    let mut savefile = cap
        .savefile(output_path)
        .map_err(|e| (id.to_string(), format!("pcap file create failed: {e}")))?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(duration_secs);
    let mut packets: u64 = 0;

    while std::time::Instant::now() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                savefile.write(&packet);
                packets += 1;
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(_) => break,
        }
    }

    drop(savefile);
    let file_size = std::fs::metadata(output_path).map(|m| m.len()).unwrap_or(0);

    Ok((id.to_string(), packets, file_size))
}

// ── Helpers ──────────────────────────────────────────────────────────

fn to_response(session: &CaptureSession) -> CaptureResponse {
    CaptureResponse {
        id: session.id.clone(),
        filter: session.filter.clone(),
        duration_secs: session.duration_secs,
        snap_length: session.snap_length,
        output_path: session.output_path.clone(),
        interface: session.interface.clone(),
        status: format!("{:?}", session.status).to_lowercase(),
        file_size_bytes: session.file_size_bytes,
        packets_captured: session.packets_captured,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_response_serialization() {
        let resp = CaptureResponse {
            id: "cap-001".to_string(),
            filter: "host 1.2.3.4".to_string(),
            duration_secs: 60,
            snap_length: 1500,
            output_path: "/var/lib/ebpfsentinel/captures/cap.pcap".to_string(),
            interface: "eth0".to_string(),
            status: "running".to_string(),
            file_size_bytes: 0,
            packets_captured: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "cap-001");
        assert_eq!(json["status"], "running");
        assert_eq!(json["snap_length"], 1500);
    }

    #[test]
    fn default_snap_length_is_1500() {
        assert_eq!(default_snap_length(), 1500);
    }
}
