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
    State(state): State<Arc<AppState>>,
) -> Json<FingerprintSummaryResponse> {
    let cached_count = state
        .fingerprint_cache
        .as_ref()
        .and_then(|c| c.read().ok())
        .map_or(0, |c| c.len());

    Json(FingerprintSummaryResponse {
        cached_count,
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
