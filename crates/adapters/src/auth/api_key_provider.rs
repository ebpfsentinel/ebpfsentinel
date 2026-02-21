use std::collections::HashMap;
use std::fmt::Write as _;

use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;
use ports::secondary::auth_provider::AuthProvider;
use sha2::{Digest, Sha256};

/// Metadata associated with a static API key.
#[derive(Debug, Clone)]
struct ApiKeyEntry {
    name: String,
    role: String,
    namespaces: Option<Vec<String>>,
}

/// Static API key authentication provider.
///
/// Keys are stored as SHA-256 hashes to prevent timing side-channel attacks
/// and to avoid keeping plaintext secrets in memory after construction.
pub struct ApiKeyAuthProvider {
    /// Map from hex-encoded SHA-256 hash of the key to its metadata.
    keys: HashMap<String, ApiKeyEntry>,
}

/// Compute the hex-encoded SHA-256 hash of a key.
fn hash_key(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

impl std::fmt::Debug for ApiKeyAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyAuthProvider")
            .field("key_count", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl ApiKeyAuthProvider {
    /// Create a provider from a list of `(name, key, role, namespaces)` tuples.
    ///
    /// Keys are immediately hashed with SHA-256; the plaintext is not retained.
    pub fn new(entries: Vec<(String, String, String, Vec<String>)>) -> Self {
        let mut keys = HashMap::with_capacity(entries.len());
        for (name, key, role, namespaces) in entries {
            let hashed = hash_key(&key);
            keys.insert(
                hashed,
                ApiKeyEntry {
                    name,
                    role,
                    namespaces: if namespaces.is_empty() {
                        None
                    } else {
                        Some(namespaces)
                    },
                },
            );
        }
        Self { keys }
    }
}

impl AuthProvider for ApiKeyAuthProvider {
    fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError> {
        if token.is_empty() {
            return Err(AuthError::TokenMissing);
        }

        // Hash the incoming token before lookup — constant-time w.r.t. key value
        let hashed = hash_key(token);
        let entry = self
            .keys
            .get(&hashed)
            .ok_or_else(|| AuthError::TokenInvalid("invalid API key".to_string()))?;

        Ok(JwtClaims {
            sub: entry.name.clone(),
            exp: u64::MAX, // API keys don't expire via token claims
            iat: 0,
            iss: None,
            aud: None,
            role: Some(entry.role.clone()),
            namespaces: entry.namespaces.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider() -> ApiKeyAuthProvider {
        ApiKeyAuthProvider::new(vec![
            (
                "admin-key".to_string(),
                "sk-admin-secret".to_string(),
                "admin".to_string(),
                vec![],
            ),
            (
                "viewer-key".to_string(),
                "sk-viewer-secret".to_string(),
                "viewer".to_string(),
                vec![],
            ),
            (
                "ops-prod".to_string(),
                "sk-ops-prod".to_string(),
                "operator".to_string(),
                vec!["prod".to_string(), "staging".to_string()],
            ),
        ])
    }

    #[test]
    fn valid_admin_key() {
        let provider = make_provider();
        let claims = provider.validate_token("sk-admin-secret").unwrap();
        assert_eq!(claims.sub, "admin-key");
        assert_eq!(claims.role.as_deref(), Some("admin"));
        assert!(claims.namespaces.is_none());
    }

    #[test]
    fn valid_viewer_key() {
        let provider = make_provider();
        let claims = provider.validate_token("sk-viewer-secret").unwrap();
        assert_eq!(claims.sub, "viewer-key");
        assert_eq!(claims.role.as_deref(), Some("viewer"));
    }

    #[test]
    fn valid_operator_key_with_namespaces() {
        let provider = make_provider();
        let claims = provider.validate_token("sk-ops-prod").unwrap();
        assert_eq!(claims.sub, "ops-prod");
        assert_eq!(claims.role.as_deref(), Some("operator"));
        let ns = claims.namespaces.unwrap();
        assert_eq!(ns, vec!["prod", "staging"]);
    }

    #[test]
    fn invalid_key_rejected() {
        let provider = make_provider();
        let err = provider.validate_token("sk-wrong-key").unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
    }

    #[test]
    fn empty_key_rejected() {
        let provider = make_provider();
        let err = provider.validate_token("").unwrap_err();
        assert!(matches!(err, AuthError::TokenMissing), "got: {err}");
    }

    #[test]
    fn debug_does_not_leak_keys() {
        let provider = make_provider();
        let debug = format!("{provider:?}");
        assert!(debug.contains("key_count: 3"));
        assert!(!debug.contains("sk-admin"));
    }

    #[test]
    fn plaintext_key_not_stored() {
        let provider = make_provider();
        // Keys should be stored as hashes, not plaintext
        assert!(!provider.keys.contains_key("sk-admin-secret"));
        // But the hash should be present
        let expected_hash = hash_key("sk-admin-secret");
        assert!(provider.keys.contains_key(&expected_hash));
    }

    #[test]
    fn hash_key_is_deterministic() {
        let h1 = hash_key("test-key");
        let h2 = hash_key("test-key");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn different_keys_produce_different_hashes() {
        let h1 = hash_key("key-a");
        let h2 = hash_key("key-b");
        assert_ne!(h1, h2);
    }
}
