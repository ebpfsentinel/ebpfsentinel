use async_trait::async_trait;
use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;

/// Port for token-based authentication.
///
/// `async` because JWKS-backed providers may refresh their key set
/// inline when an unknown `kid` arrives — that refresh is an HTTPS
/// round-trip and must not block a Tokio worker. Static-PEM and API-key
/// providers do no I/O on the hot path; their implementations just
/// trampoline the synchronous decoder.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the trait is object-safe (can be used as `dyn AuthProvider`).
    #[test]
    fn trait_is_object_safe() {
        fn _accepts_dyn(_provider: &dyn AuthProvider) {}
    }
}
