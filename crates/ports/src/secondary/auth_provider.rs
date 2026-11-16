use async_trait::async_trait;
use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;

/// Port for token-based authentication.
///
/// `async` because JWKS-backed providers may refresh their key set
/// inline when an unknown `kid` arrives - that refresh is an HTTPS
/// round-trip and must not block a Tokio worker. Static-PEM and API-key
/// providers do no I/O on the hot path; their implementations just
/// trampoline the synchronous decoder.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError>;

    /// Validate a token presented with the post-quantum cosignature that may
    /// travel beside it (`X-Ebpfsentinel-Token-Cosignature`).
    ///
    /// A provider whose credentials are not signed tokens, such as static API
    /// keys, has no second signature to check and keeps this default. A
    /// provider that verifies signed tokens overrides it and applies
    /// [`domain::auth::cosignature::admit`].
    async fn validate_cosigned(
        &self,
        token: &str,
        cosignature: Option<&str>,
    ) -> Result<JwtClaims, AuthError> {
        let _ = cosignature;
        self.validate_token(token).await
    }
}

/// The request header carrying the ML-DSA-65 cosignature of a bearer token,
/// base64url without padding. gRPC carries it as metadata of the same name in
/// lower case.
pub const COSIGNATURE_HEADER: &str = "x-ebpfsentinel-token-cosignature";

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the trait is object-safe (can be used as `dyn AuthProvider`).
    #[test]
    fn trait_is_object_safe() {
        fn _accepts_dyn(_provider: &dyn AuthProvider) {}
    }
}
