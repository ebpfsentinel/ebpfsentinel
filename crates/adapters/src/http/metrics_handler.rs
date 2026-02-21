use std::sync::Arc;

use axum::extract::State;
use axum::http::header;

use super::state::AppState;

/// Content-Type for `OpenMetrics` text exposition format.
const OPENMETRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Serves Prometheus metrics in `OpenMetrics` text format.
#[utoipa::path(
    get, path = "/metrics",
    tag = "Observability",
    responses(
        (status = 200, description = "OpenMetrics text exposition", content_type = "application/openmetrics-text"),
    )
)]
pub async fn metrics(
    State(state): State<Arc<AppState>>,
) -> ([(header::HeaderName, &'static str); 1], String) {
    let body = state.metrics.encode();
    ([(header::CONTENT_TYPE, OPENMETRICS_CONTENT_TYPE)], body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_is_valid() {
        assert!(OPENMETRICS_CONTENT_TYPE.starts_with("application/openmetrics-text"));
        assert!(OPENMETRICS_CONTENT_TYPE.contains("version=1.0.0"));
    }
}
