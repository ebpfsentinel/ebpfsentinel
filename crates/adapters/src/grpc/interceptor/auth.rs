use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{HeaderMap, Request, Response, header};
use ports::secondary::auth_provider::AuthProvider;
use tonic::Status;
use tonic::body::Body;
use tonic::server::NamedService;
use tower::{Layer, Service};

/// Tower layer that authenticates gRPC requests with an [`AuthProvider`].
///
/// Unlike a [`tonic`] sync interceptor, this validates the token **inside the
/// async call** rather than blocking a runtime worker thread with
/// `block_in_place` + `block_on`. That matters because token validation can do
/// network I/O (an OIDC/JWKS refresh on an unknown `kid`); blocking a worker
/// per request lets a flood of bogus-`kid` tokens starve the runtime.
///
/// Extraction order (HTTP-middleware parity):
/// 1. `authorization: Bearer <token>` — must look like a JWT (3 dot parts)
/// 2. `x-api-key: <key>`
///
/// Health and reflection services must NOT be wrapped with this layer.
#[derive(Clone)]
pub struct AuthLayer {
    provider: Arc<dyn AuthProvider>,
}

impl AuthLayer {
    #[must_use]
    pub fn new(provider: Arc<dyn AuthProvider>) -> Self {
        Self { provider }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            provider: Arc::clone(&self.provider),
        }
    }
}

/// Service produced by [`AuthLayer`].
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    provider: Arc<dyn AuthProvider>,
}

impl<S> Service<Request<Body>> for AuthService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let provider = Arc::clone(&self.provider);
        // Use the instance that was just `poll_ready`'d; leave a fresh clone in
        // its place (standard tower readiness-correctness pattern).
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        let token = extract_token(req.headers());

        Box::pin(async move {
            let Some(token) = token else {
                return Ok(Status::unauthenticated(
                    "authentication required: provide Bearer token or x-api-key",
                )
                .into_http());
            };
            match provider.validate_token(&token).await {
                Ok(_) => inner.call(req).await,
                Err(e) => Ok(Status::unauthenticated(e.to_string()).into_http()),
            }
        })
    }
}

impl<S: NamedService> NamedService for AuthService<S> {
    const NAME: &'static str = S::NAME;
}

/// Extract a credential from request headers: Bearer JWT first, then x-api-key.
///
/// Bearer tokens must look like a JWT (3 dot-separated parts); malformed
/// values are rejected early without hitting the provider.
fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(bearer) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        if !bearer.is_empty() && bearer.matches('.').count() == 2 {
            return Some(bearer.to_string());
        }
        // Malformed Bearer → no fallback (caller returns Unauthenticated).
        return None;
    }
    headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use domain::auth::entity::JwtClaims;
    use domain::auth::error::AuthError;
    use tower::util::BoxCloneService;
    use tower::{ServiceExt, service_fn};

    struct AlwaysOkProvider;
    #[async_trait]
    impl AuthProvider for AlwaysOkProvider {
        async fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Ok(JwtClaims {
                sub: "test".to_string(),
                exp: 9_999_999_999,
                iat: 0,
                iss: None,
                aud: None,
                role: None,
                namespaces: None,
                tenant_id: None,
                roles: None,
            })
        }
    }

    struct AlwaysFailProvider;
    #[async_trait]
    impl AuthProvider for AlwaysFailProvider {
        async fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Err(AuthError::TokenExpired)
        }
    }

    /// Build an `AuthService` whose inner service flips `called` to true and
    /// returns 200 OK, so tests can assert whether the request reached it.
    fn wrap(
        provider: Arc<dyn AuthProvider>,
        called: Arc<AtomicBool>,
    ) -> AuthService<BoxCloneService<Request<Body>, Response<Body>, Infallible>> {
        let inner = service_fn(move |_req: Request<Body>| {
            let called = Arc::clone(&called);
            async move {
                called.store(true, Ordering::SeqCst);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        })
        .boxed_clone();
        AuthLayer::new(provider).layer(inner)
    }

    fn grpc_status(resp: &Response<Body>) -> Option<i32> {
        resp.headers()
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
    }

    #[tokio::test]
    async fn valid_bearer_reaches_inner() {
        let called = Arc::new(AtomicBool::new(false));
        let svc = wrap(Arc::new(AlwaysOkProvider), Arc::clone(&called));
        let req = Request::builder()
            .header("authorization", "Bearer header.payload.signature")
            .body(Body::empty())
            .unwrap();
        let _ = svc.oneshot(req).await.unwrap();
        assert!(called.load(Ordering::SeqCst), "inner must be called");
    }

    #[tokio::test]
    async fn valid_api_key_reaches_inner() {
        let called = Arc::new(AtomicBool::new(false));
        let svc = wrap(Arc::new(AlwaysOkProvider), Arc::clone(&called));
        let req = Request::builder()
            .header("x-api-key", "sk-valid-key")
            .body(Body::empty())
            .unwrap();
        let _ = svc.oneshot(req).await.unwrap();
        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn missing_credential_rejected_before_inner() {
        let called = Arc::new(AtomicBool::new(false));
        let svc = wrap(Arc::new(AlwaysOkProvider), Arc::clone(&called));
        let req = Request::builder().body(Body::empty()).unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert!(!called.load(Ordering::SeqCst), "inner must NOT be called");
        // gRPC UNAUTHENTICATED = 16
        assert_eq!(grpc_status(&resp), Some(16));
    }

    #[tokio::test]
    async fn invalid_token_rejected_before_inner() {
        let called = Arc::new(AtomicBool::new(false));
        let svc = wrap(Arc::new(AlwaysFailProvider), Arc::clone(&called));
        let req = Request::builder()
            .header("authorization", "Bearer bad.token.here")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(grpc_status(&resp), Some(16));
    }

    #[tokio::test]
    async fn malformed_bearer_rejected() {
        let called = Arc::new(AtomicBool::new(false));
        let svc = wrap(Arc::new(AlwaysOkProvider), Arc::clone(&called));
        let req = Request::builder()
            .header("authorization", "Bearer not-a-jwt")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(grpc_status(&resp), Some(16));
    }

    #[tokio::test]
    async fn non_bearer_authorization_rejected() {
        let called = Arc::new(AtomicBool::new(false));
        let svc = wrap(Arc::new(AlwaysOkProvider), Arc::clone(&called));
        let req = Request::builder()
            .header("authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();
        let resp = svc.oneshot(req).await.unwrap();
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(grpc_status(&resp), Some(16));
    }
}
