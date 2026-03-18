use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::state::AppState;

/// Response for `GET /api/v1/fingerprints/summary`.
#[derive(Serialize, ToSchema)]
pub struct FingerprintSummaryResponse {
    /// Number of cached fingerprints.
    pub cached_count: usize,
    /// Maximum cache size.
    pub max_size: usize,
    /// Cache TTL in seconds.
    pub ttl_seconds: u64,
}

/// `GET /api/v1/fingerprints/summary` — fingerprint cache status.
#[utoipa::path(
    get, path = "/api/v1/fingerprints/summary",
    tag = "Fingerprints",
    responses(
        (status = 200, description = "Fingerprint cache summary", body = FingerprintSummaryResponse),
    )
)]
pub async fn fingerprint_summary(
    State(_state): State<Arc<AppState>>,
) -> Json<FingerprintSummaryResponse> {
    // The fingerprint cache lives in EventDispatcher (application layer),
    // not directly accessible from AppState. Return static info for now —
    // will be wired when EventDispatcher exposes cache stats via a port.
    Json(FingerprintSummaryResponse {
        cached_count: 0,
        max_size: 10_000,
        ttl_seconds: 300,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_response_serialization() {
        let resp = FingerprintSummaryResponse {
            cached_count: 42,
            max_size: 10_000,
            ttl_seconds: 300,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["cached_count"], 42);
        assert_eq!(json["max_size"], 10_000);
        assert_eq!(json["ttl_seconds"], 300);
    }
}
