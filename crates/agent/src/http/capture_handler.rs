use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use domain::auth::entity::JwtClaims;
use domain::capture::entity::{CaptureSession, CaptureStatus};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
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

/// Reject a capture ID that is not safe to interpolate into a filesystem path.
///
/// The ID is server-generated and therefore always path-safe; this guard runs
/// at runtime (unlike a `debug_assert!`, which is compiled out of release
/// builds) so that any future change to the ID source cannot silently turn the
/// `{id}.pcap` path into a traversal sink.
fn ensure_path_safe_id(id: &str) -> Result<(), ApiError> {
    if id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        Ok(())
    } else {
        Err(ApiError::Internal {
            message: "generated capture id is not path-safe".to_string(),
        })
    }
}

/// `POST /api/v1/captures/manual` — start a time-bounded packet capture.
#[utoipa::path(
    post, path = "/api/v1/captures/manual",
    tag = "Captures",
    request_body = StartCaptureRequest,
    responses(
        (status = 201, description = "Capture started", body = CaptureResponse),
        (status = 409, description = "Another capture is already running", body = ErrorBody),
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
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<StartCaptureRequest>,
) -> Result<Json<CaptureResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
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
    ensure_path_safe_id(&id)?;
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

    // Spawn the capture in the background. Capture runs on an AF_PACKET socket
    // pre-opened by the privileged launcher (requires the pcap-capture feature).
    #[cfg(feature = "pcap-capture")]
    {
        if let Some(pool) = state.pcap_pool.clone() {
            let cap_engine = Arc::clone(capture_engine);
            tokio::spawn(run_pcap_capture(
                pool,
                session.id,
                session.interface,
                session.filter,
                session.duration_secs,
                session.snap_length,
                session.output_path,
                cap_engine,
            ));
        } else {
            tracing::warn!(
                capture_id = %session.id,
                "packet capture unavailable: the launcher provisioned no AF_PACKET socket (EBPFSENTINEL_PCAP_FDS unset)"
            );
        }
    }
    #[cfg(not(feature = "pcap-capture"))]
    {
        let _ = capture_engine;
        tracing::warn!(capture_id = %session.id, "pcap capture requires the pcap-capture feature");
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
        (status = 404, description = "Capture not found", body = ErrorBody),
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
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<Json<CaptureResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
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

// ── AF_PACKET capture (launcher-provisioned socket) ───────────────────

/// Run a packet capture on an `AF_PACKET` socket borrowed from the
/// launcher-provisioned pool.
///
/// Spawned on a blocking thread via `tokio::task::spawn_blocking` because the
/// capture loop performs blocking `recv` polling.
#[cfg(feature = "pcap-capture")]
#[allow(clippy::too_many_arguments)]
pub async fn run_pcap_capture(
    pool: Arc<adapters::net::pcap_capture::PcapSocketPool>,
    id: String,
    interface: String,
    filter: String,
    duration_secs: u64,
    snap_length: u32,
    output_path: String,
    engine: Arc<tokio::sync::RwLock<domain::capture::engine::CaptureEngine>>,
) {
    let result = tokio::task::spawn_blocking(move || {
        let Some(lease) = pool.borrow() else {
            return Err((
                id,
                "no AF_PACKET capture socket available (all sockets in use)".to_string(),
            ));
        };
        match adapters::net::pcap_capture::run_capture(
            lease.fd(),
            &interface,
            &filter,
            std::time::Duration::from_secs(duration_secs),
            snap_length,
            &output_path,
        ) {
            Ok(stats) => Ok((id, stats.packets, stats.file_size)),
            Err(e) => Err((id, e)),
        }
        // `lease` returns the socket to the pool on drop here.
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
