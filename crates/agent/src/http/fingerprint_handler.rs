use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
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
    /// Whether the cache is backed by a persistent store that survives restarts.
    pub persistent: bool,
}

/// Response for `GET /api/v1/fingerprints/ja4s`.
#[derive(Serialize, ToSchema)]
pub struct Ja4sSummaryResponse {
    /// Number of cached JA4S server fingerprints.
    pub cached_count: usize,
    /// Maximum cache size.
    pub max_size: usize,
    /// Cache TTL in seconds.
    pub ttl_seconds: u64,
    /// Whether the cache is backed by a persistent store that survives restarts.
    pub persistent: bool,
}

/// `GET /api/v1/fingerprints/summary` — fingerprint cache status.
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
    let cached_count = state.fingerprint_cache.as_ref().map_or(0, |c| c.len());
    let persistent = state
        .fingerprint_cache
        .as_ref()
        .is_some_and(|c| c.is_persistent());

    Json(FingerprintSummaryResponse {
        cached_count,
        max_size: 10_000,
        ttl_seconds: 300,
        persistent,
    })
}

/// `GET /api/v1/fingerprints/ja4s` — JA4S server-side fingerprint cache status.
#[utoipa::path(
    get, path = "/api/v1/fingerprints/ja4s",
    tag = "Fingerprints",
    responses(
        (status = 200, description = "JA4S server fingerprint cache summary", body = Ja4sSummaryResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn ja4s_summary(State(state): State<Arc<AppState>>) -> Json<Ja4sSummaryResponse> {
    let cached_count = state.ja4s_fingerprint_cache.as_ref().map_or(0, |c| c.len());
    let persistent = state
        .ja4s_fingerprint_cache
        .as_ref()
        .is_some_and(|c| c.is_persistent());

    Json(Ja4sSummaryResponse {
        cached_count,
        max_size: 10_000,
        ttl_seconds: 300,
        persistent,
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

    #[test]
    fn ja4s_summary_response_serialization() {
        let resp = Ja4sSummaryResponse {
            cached_count: 7,
            max_size: 10_000,
            ttl_seconds: 300,
            persistent: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["cached_count"], 7);
        assert_eq!(json["persistent"], true);
    }
}
