use std::sync::Arc;

use ports::secondary::auth_provider::AuthProvider;
use tonic::{Request, Status};

/// Create a tonic interceptor that validates JWT Bearer tokens.
///
/// The returned function can be used with `ServiceServer::with_interceptor()`.
/// Health and reflection services should NOT use this interceptor.
pub fn make_jwt_interceptor(
    provider: Arc<dyn AuthProvider>,
) -> impl Fn(Request<()>) -> Result<Request<()>, Status> + Clone {
    move |request: Request<()>| {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                Status::unauthenticated("authentication required: no Bearer token provided")
            })?;

        provider
            .validate_token(token)
            .map_err(|e| Status::unauthenticated(e.to_string()))?;

        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::auth::entity::JwtClaims;
    use domain::auth::error::AuthError;
    use tonic::metadata::MetadataValue;

    struct AlwaysOkProvider;
    impl AuthProvider for AlwaysOkProvider {
        fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Ok(JwtClaims {
                sub: "test".to_string(),
                exp: 9_999_999_999,
                iat: 0,
                iss: None,
                aud: None,
                role: None,
                namespaces: None,
            })
        }
    }

    struct AlwaysFailProvider;
    impl AuthProvider for AlwaysFailProvider {
        fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Err(AuthError::TokenExpired)
        }
    }

    #[test]
    fn accept_valid_bearer() {
        let interceptor = make_jwt_interceptor(Arc::new(AlwaysOkProvider));
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer valid-token"),
        );
        assert!(interceptor(req).is_ok());
    }

    #[test]
    fn reject_missing_auth() {
        let interceptor = make_jwt_interceptor(Arc::new(AlwaysOkProvider));
        let req = Request::new(());
        let status = interceptor(req).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn reject_invalid_token() {
        let interceptor = make_jwt_interceptor(Arc::new(AlwaysFailProvider));
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Bearer bad-token"),
        );
        let status = interceptor(req).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn reject_non_bearer() {
        let interceptor = make_jwt_interceptor(Arc::new(AlwaysOkProvider));
        let mut req = Request::new(());
        req.metadata_mut().insert(
            "authorization",
            MetadataValue::from_static("Basic dXNlcjpwYXNz"),
        );
        let status = interceptor(req).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
    }
}
