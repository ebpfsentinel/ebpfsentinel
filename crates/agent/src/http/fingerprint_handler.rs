use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// Response for `GET /api/v1/fingerprints/summary`, the JA4 client fingerprint cache.
#[derive(Serialize, ToSchema)]
pub struct FingerprintSummaryResponse {
    /// Number of cached fingerprints.
    pub cached_count: usize,
    /// Maximum cache size.
    pub max_size: usize,
    /// Cache TTL in seconds.
    pub ttl_seconds: u64,
    /// Whether the cache is backed by a persistent store that survives restarts.
    pub persistent: bool,
}

/// `GET /api/v1/fingerprints/summary` - fingerprint cache status.
#[utoipa::path(
    get, path = "/api/v1/fingerprints/summary",
    tag = "Fingerprints",
    responses(
        (status = 200, description = "Fingerprint cache summary", body = FingerprintSummaryResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn fingerprint_summary(
    State(state): State<Arc<AppState>>,
) -> Json<FingerprintSummaryResponse> {
    // The ceiling and the TTL are read off the cache rather than restated
    // here: a screen judges how full the cache is by comparing the count
    // against them, and a second copy of either number drifts the day the
    // cache is built with a different one.
    let cache = state.fingerprint_cache.as_ref();

    Json(FingerprintSummaryResponse {
        cached_count: cache.map_or(0, |c| c.len()),
        max_size: cache.map_or(0, |c| c.capacity()),
        ttl_seconds: cache.map_or(0, |c| c.ttl().as_secs()),
        persistent: cache.is_some_and(|c| c.is_persistent()),
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
            persistent: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["cached_count"], 42);
        assert_eq!(json["max_size"], 10_000);
        assert_eq!(json["ttl_seconds"], 300);
        assert_eq!(json["persistent"], false);
    }
}
