use std::sync::Arc;

use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;
use ports::secondary::auth_provider::AuthProvider;

/// Composite authentication provider that tries multiple providers in order.
///
/// Used when both a token-based provider (JWT/OIDC) and API keys are configured.
/// The first provider to succeed wins; if all fail, a generic error is returned
/// to avoid leaking which provider was tried last.
pub struct CompositeAuthProvider {
    providers: Vec<Arc<dyn AuthProvider>>,
}

impl std::fmt::Debug for CompositeAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeAuthProvider")
            .field("provider_count", &self.providers.len())
            .finish_non_exhaustive()
    }
}

impl CompositeAuthProvider {
    pub fn new(providers: Vec<Arc<dyn AuthProvider>>) -> Self {
        Self { providers }
    }
}

impl AuthProvider for CompositeAuthProvider {
    fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError> {
        for provider in &self.providers {
            if let Ok(claims) = provider.validate_token(token) {
                return Ok(claims);
            }
        }
        // Return a generic error to avoid leaking provider-specific details.
        Err(AuthError::TokenInvalid("authentication failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OkProvider {
        sub: &'static str,
    }
    impl AuthProvider for OkProvider {
        fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Ok(JwtClaims {
                sub: self.sub.to_string(),
                exp: u64::MAX,
                iat: 0,
                iss: None,
                aud: None,
                role: Some("admin".to_string()),
                namespaces: None,
            })
        }
    }

    struct FailProvider;
    impl AuthProvider for FailProvider {
        fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Err(AuthError::TokenInvalid("nope".to_string()))
        }
    }

    #[test]
    fn first_provider_wins() {
        let composite = CompositeAuthProvider::new(vec![
            Arc::new(OkProvider { sub: "first" }),
            Arc::new(OkProvider { sub: "second" }),
        ]);
        let claims = composite.validate_token("any").unwrap();
        assert_eq!(claims.sub, "first");
    }

    #[test]
    fn falls_through_to_second_provider() {
        let composite = CompositeAuthProvider::new(vec![
            Arc::new(FailProvider) as Arc<dyn AuthProvider>,
            Arc::new(OkProvider { sub: "second" }),
        ]);
        let claims = composite.validate_token("any").unwrap();
        assert_eq!(claims.sub, "second");
    }

    #[test]
    fn all_fail_returns_generic_error() {
        let composite = CompositeAuthProvider::new(vec![
            Arc::new(FailProvider) as Arc<dyn AuthProvider>,
            Arc::new(FailProvider),
        ]);
        let err = composite.validate_token("any").unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)));
        assert_eq!(err.to_string(), "invalid token: authentication failed");
    }
}
