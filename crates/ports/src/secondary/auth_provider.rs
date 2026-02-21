use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;

/// Port for token-based authentication.
///
/// Synchronous trait — JWT validation is CPU-bound and uses `std::sync::RwLock`
/// for the decoding key (non-blocking reads).
pub trait AuthProvider: Send + Sync {
    fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError>;
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
