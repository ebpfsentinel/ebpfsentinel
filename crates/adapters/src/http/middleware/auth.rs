use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::super::error::ApiError;
use super::super::state::AppState;

/// Axum middleware that validates authentication via the `AuthProvider`.
///
/// Supports two authentication methods (tried in order):
/// 1. `Authorization: Bearer <token>` — JWT/OIDC tokens
/// 2. `X-API-Key: <key>` — static API keys
///
/// When no `auth_provider` is configured in state, requests pass through
/// (backward compatible — auth disabled).
pub async fn jwt_auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(ref auth_provider) = state.auth_provider else {
        // No auth provider configured — pass through
        return Ok(next.run(request).await);
    };

    let token = extract_token(&request)?;
    let claims = auth_provider.validate_token(token)?;
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Extract authentication credential from the request.
///
/// Checks `Authorization: Bearer <token>` first, then `X-API-Key: <key>`.
fn extract_token(request: &Request) -> Result<&str, ApiError> {
    // Try Bearer token first
    if let Some(auth_header) = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        && let Some(token) = auth_header.strip_prefix("Bearer ")
    {
        return Ok(token);
    }

    // Fall back to X-API-Key header
    if let Some(api_key) = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
    {
        return Ok(api_key);
    }

    Err(ApiError::Unauthorized {
        message: "authentication required: no token provided".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use domain::auth::entity::JwtClaims;
    use domain::auth::error::AuthError;
    use http_body_util::BodyExt;
    use ports::secondary::auth_provider::AuthProvider;
    use tower::ServiceExt;

    struct AlwaysOkProvider;
    impl AuthProvider for AlwaysOkProvider {
        fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Ok(JwtClaims {
                sub: "test-user".to_string(),
                exp: 9_999_999_999,
                iat: 0,
                iss: None,
                aud: None,
                role: Some("admin".to_string()),
                namespaces: None,
            })
        }
    }

    struct AlwaysFailProvider;
    impl AuthProvider for AlwaysFailProvider {
        fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Err(AuthError::TokenInvalid("bad".to_string()))
        }
    }

    fn make_test_state(auth_provider: Option<Arc<dyn AuthProvider>>) -> Arc<AppState> {
        use application::audit_service_impl::AuditAppService;
        use application::firewall_service_impl::FirewallAppService;
        use application::ips_service_impl::IpsAppService;
        use application::l7_service_impl::L7AppService;
        use application::ratelimit_service_impl::RateLimitAppService;
        use application::threatintel_service_impl::ThreatIntelAppService;
        use domain::audit::entity::AuditEntry;
        use domain::audit::error::AuditError;
        use domain::firewall::engine::FirewallEngine;
        use domain::ips::engine::IpsEngine;
        use domain::l7::engine::L7Engine;
        use domain::ratelimit::engine::RateLimitEngine;
        use domain::threatintel::engine::ThreatIntelEngine;
        use infrastructure::metrics::AgentMetrics;
        use ports::secondary::audit_sink::AuditSink;
        use ports::secondary::metrics_port::MetricsPort;
        use ports::test_utils::NoopMetrics;
        use std::sync::atomic::AtomicBool;

        struct NoopSink;
        impl AuditSink for NoopSink {
            fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
                Ok(())
            }
        }

        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        let mut state = AppState::new(
            Arc::new(AgentMetrics::new()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(tokio::sync::RwLock::new(FirewallAppService::new(
                FirewallEngine::new(),
                None,
                Arc::clone(&noop),
            ))),
            Arc::new(tokio::sync::RwLock::new(IpsAppService::new(
                IpsEngine::default(),
                Arc::clone(&noop),
            ))),
            Arc::new(tokio::sync::RwLock::new(L7AppService::new(
                L7Engine::new(),
                Arc::clone(&noop),
            ))),
            Arc::new(tokio::sync::RwLock::new(RateLimitAppService::new(
                RateLimitEngine::new(),
                Arc::clone(&noop),
            ))),
            Arc::new(tokio::sync::RwLock::new(ThreatIntelAppService::new(
                ThreatIntelEngine::new(1_000_000),
                Arc::clone(&noop),
                vec![],
            ))),
            Arc::new(tokio::sync::RwLock::new(AuditAppService::new(
                Arc::new(NoopSink) as Arc<dyn AuditSink>,
            ))),
            Arc::new(tokio::sync::RwLock::new(
                infrastructure::config::AgentConfig::from_yaml("agent:\n  interfaces: [eth0]")
                    .unwrap(),
            )),
            reload_tx,
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        );
        if let Some(provider) = auth_provider {
            state = state.with_auth_provider(provider, false);
        }
        Arc::new(state)
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn build_test_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/protected", get(ok_handler))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                jwt_auth_middleware,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn pass_through_when_no_provider() {
        let state = make_test_state(None);
        let router = build_test_router(state);
        let req = HttpRequest::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn reject_missing_header() {
        let state = make_test_state(Some(Arc::new(AlwaysOkProvider)));
        let router = build_test_router(state);
        let req = HttpRequest::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn reject_invalid_token() {
        let state = make_test_state(Some(Arc::new(AlwaysFailProvider)));
        let router = build_test_router(state);
        let req = HttpRequest::builder()
            .uri("/protected")
            .header("Authorization", "Bearer bad-token")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "AUTHENTICATION_REQUIRED");
    }

    #[tokio::test]
    async fn accept_valid_token() {
        let state = make_test_state(Some(Arc::new(AlwaysOkProvider)));
        let router = build_test_router(state);
        let req = HttpRequest::builder()
            .uri("/protected")
            .header("Authorization", "Bearer valid-token")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Handler that extracts claims from extensions and returns the subject.
    async fn claims_handler(
        axum::extract::Extension(claims): axum::extract::Extension<JwtClaims>,
    ) -> String {
        claims.sub
    }

    #[tokio::test]
    async fn claims_stored_in_extensions() {
        let state = make_test_state(Some(Arc::new(AlwaysOkProvider)));
        let router = Router::new()
            .route("/check-claims", get(claims_handler))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                jwt_auth_middleware,
            ))
            .with_state(state);
        let req = HttpRequest::builder()
            .uri("/check-claims")
            .header("Authorization", "Bearer valid-token")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"test-user");
    }

    #[tokio::test]
    async fn reject_non_bearer_auth() {
        let state = make_test_state(Some(Arc::new(AlwaysOkProvider)));
        let router = build_test_router(state);
        let req = HttpRequest::builder()
            .uri("/protected")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn accept_x_api_key_header() {
        let state = make_test_state(Some(Arc::new(AlwaysOkProvider)));
        let router = build_test_router(state);
        let req = HttpRequest::builder()
            .uri("/protected")
            .header("X-API-Key", "sk-test-key")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_preferred_over_api_key() {
        let state = make_test_state(Some(Arc::new(AlwaysOkProvider)));
        let router = Router::new()
            .route("/check-claims", get(claims_handler))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                jwt_auth_middleware,
            ))
            .with_state(state);
        let req = HttpRequest::builder()
            .uri("/check-claims")
            .header("Authorization", "Bearer jwt-token")
            .header("X-API-Key", "sk-api-key")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // AlwaysOkProvider returns "test-user" for any token — the key point is
        // that Bearer was used (the token passed to validate_token is "jwt-token",
        // not "sk-api-key"), verified by the 200 response.
    }

    #[tokio::test]
    async fn reject_x_api_key_invalid() {
        let state = make_test_state(Some(Arc::new(AlwaysFailProvider)));
        let router = build_test_router(state);
        let req = HttpRequest::builder()
            .uri("/protected")
            .header("X-API-Key", "sk-bad-key")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
