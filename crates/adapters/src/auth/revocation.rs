use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;
use ports::secondary::auth_provider::AuthProvider;

/// Token revocation list that wraps an inner `AuthProvider`.
///
/// After the inner provider validates a token, the revocation list is checked
/// using `sub:iat` as the revocation key. This allows revoking all tokens
/// issued to a subject before a certain time.
pub struct RevocableAuthProvider {
    inner: Arc<dyn AuthProvider>,
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl std::fmt::Debug for RevocableAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.revoked.read().map(|r| r.len()).unwrap_or(0);
        f.debug_struct("RevocableAuthProvider")
            .field("revoked_count", &count)
            .finish_non_exhaustive()
    }
}

/// Build the revocation key from claims: `"sub:iat"`.
fn revocation_key(claims: &JwtClaims) -> String {
    format!("{}:{}", claims.sub, claims.iat)
}

impl RevocableAuthProvider {
    /// Create a new revocable provider wrapping an inner provider.
    pub fn new(inner: Arc<dyn AuthProvider>) -> Self {
        Self {
            inner,
            revoked: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Return a handle to the revocation set for external management.
    pub fn revocation_handle(&self) -> RevocationHandle {
        RevocationHandle {
            revoked: Arc::clone(&self.revoked),
        }
    }
}

impl AuthProvider for RevocableAuthProvider {
    fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let claims = self.inner.validate_token(token)?;

        let key = revocation_key(&claims);
        let revoked = self.revoked.read().map_err(|e| {
            tracing::error!("revocation list RwLock poisoned: {e}");
            AuthError::TokenInvalid("internal auth error".to_string())
        })?;
        if revoked.contains(&key) {
            return Err(AuthError::TokenInvalid(
                "token has been revoked".to_string(),
            ));
        }

        Ok(claims)
    }
}

/// Handle for managing the revocation list from outside the auth provider.
///
/// Obtained via [`RevocableAuthProvider::revocation_handle`].
#[derive(Clone)]
pub struct RevocationHandle {
    revoked: Arc<RwLock<HashSet<String>>>,
}

impl RevocationHandle {
    /// Revoke all tokens issued to `subject` at or before `issued_at`.
    pub fn revoke(&self, subject: &str, issued_at: u64) {
        let key = format!("{subject}:{issued_at}");
        let mut set = self.revoked.write().unwrap_or_else(|e| {
            tracing::error!("revocation list RwLock poisoned on revoke: {e}");
            e.into_inner()
        });
        set.insert(key);
    }

    /// Remove a revocation entry.
    pub fn unrevoke(&self, subject: &str, issued_at: u64) {
        let key = format!("{subject}:{issued_at}");
        let mut set = self.revoked.write().unwrap_or_else(|e| {
            tracing::error!("revocation list RwLock poisoned on unrevoke: {e}");
            e.into_inner()
        });
        set.remove(&key);
    }

    /// Number of revoked entries.
    pub fn len(&self) -> usize {
        self.revoked
            .read()
            .unwrap_or_else(|e| {
                tracing::error!("revocation list RwLock poisoned on len: {e}");
                e.into_inner()
            })
            .len()
    }

    /// Whether the revocation list is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all revocations.
    pub fn clear(&self) {
        let mut set = self.revoked.write().unwrap_or_else(|e| {
            tracing::error!("revocation list RwLock poisoned on clear: {e}");
            e.into_inner()
        });
        set.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OkProvider;
    impl AuthProvider for OkProvider {
        fn validate_token(&self, _token: &str) -> Result<JwtClaims, AuthError> {
            Ok(JwtClaims {
                sub: "user-1".to_string(),
                exp: u64::MAX,
                iat: 1000,
                iss: None,
                aud: None,
                role: Some("admin".to_string()),
                namespaces: None,
            })
        }
    }

    #[test]
    fn valid_token_passes_when_not_revoked() {
        let provider = RevocableAuthProvider::new(Arc::new(OkProvider));
        let claims = provider.validate_token("any").unwrap();
        assert_eq!(claims.sub, "user-1");
    }

    #[test]
    fn revoked_token_rejected() {
        let provider = RevocableAuthProvider::new(Arc::new(OkProvider));
        let handle = provider.revocation_handle();

        handle.revoke("user-1", 1000);
        let err = provider.validate_token("any").unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)));
        assert!(err.to_string().contains("revoked"));
    }

    #[test]
    fn unrevoke_restores_access() {
        let provider = RevocableAuthProvider::new(Arc::new(OkProvider));
        let handle = provider.revocation_handle();

        handle.revoke("user-1", 1000);
        assert!(provider.validate_token("any").is_err());

        handle.unrevoke("user-1", 1000);
        assert!(provider.validate_token("any").is_ok());
    }

    #[test]
    fn different_iat_not_revoked() {
        let provider = RevocableAuthProvider::new(Arc::new(OkProvider));
        let handle = provider.revocation_handle();

        // Revoke a different iat
        handle.revoke("user-1", 999);
        // Token with iat=1000 should still pass
        assert!(provider.validate_token("any").is_ok());
    }

    #[test]
    fn clear_removes_all_revocations() {
        let provider = RevocableAuthProvider::new(Arc::new(OkProvider));
        let handle = provider.revocation_handle();

        handle.revoke("user-1", 1000);
        assert_eq!(handle.len(), 1);

        handle.clear();
        assert!(handle.is_empty());
        assert!(provider.validate_token("any").is_ok());
    }

    #[test]
    fn handle_is_clone() {
        let provider = RevocableAuthProvider::new(Arc::new(OkProvider));
        let h1 = provider.revocation_handle();
        let h2 = h1.clone();

        h1.revoke("user-1", 1000);
        assert_eq!(h2.len(), 1); // shared state
    }
}
