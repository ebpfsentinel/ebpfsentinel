use std::sync::RwLock;

use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation};
use ports::secondary::auth_provider::AuthProvider;

/// JWT authentication provider using RSA (RS256) public key validation.
///
/// The decoding key is held behind a `std::sync::RwLock` for concurrent reads
/// and rare writes (key rotation via config reload).
pub struct JwtAuthProvider {
    decoding_key: RwLock<DecodingKey>,
    validation: Validation,
}

impl std::fmt::Debug for JwtAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuthProvider")
            .field("algorithm", &"RS256")
            .finish_non_exhaustive()
    }
}

impl JwtAuthProvider {
    /// Create a new provider from PEM-encoded RSA public key bytes.
    pub fn new(
        pem_bytes: &[u8],
        issuer: Option<&str>,
        audience: Option<&str>,
    ) -> Result<Self, AuthError> {
        let decoding_key = DecodingKey::from_rsa_pem(pem_bytes)
            .map_err(|e| AuthError::KeyLoadFailed(e.to_string()))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["sub", "exp"]);

        if let Some(iss) = issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(aud) = audience {
            validation.set_audience(&[aud]);
        }

        Ok(Self {
            decoding_key: RwLock::new(decoding_key),
            validation,
        })
    }

    /// Atomically replace the decoding key (for config-reload key rotation).
    pub fn rotate_key(&self, pem_bytes: &[u8]) -> Result<(), AuthError> {
        let new_key = DecodingKey::from_rsa_pem(pem_bytes)
            .map_err(|e| AuthError::KeyLoadFailed(e.to_string()))?;
        let mut key = self
            .decoding_key
            .write()
            .expect("decoding key lock poisoned");
        *key = new_key;
        Ok(())
    }
}

impl AuthProvider for JwtAuthProvider {
    fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError> {
        if token.is_empty() {
            return Err(AuthError::TokenMissing);
        }

        let key = self
            .decoding_key
            .read()
            .expect("decoding key lock poisoned");

        let token_data: TokenData<JwtClaims> = jsonwebtoken::decode(token, &key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::TokenInvalid(e.to_string()),
            })?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        exp: u64,
        iat: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
    }

    // Test RSA keypair (2048-bit, generated for tests only — NOT a real secret)
    const TEST_RSA_PRIVATE_KEY: &[u8] = include_bytes!("../../tests/fixtures/jwt_test_key.pem");
    const TEST_RSA_PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/jwt_test_key.pub.pem");

    fn sign_token(claims: &TestClaims, private_key: &[u8]) -> String {
        let key = EncodingKey::from_rsa_pem(private_key).unwrap();
        jsonwebtoken::encode(&Header::new(Algorithm::RS256), claims, &key).unwrap()
    }

    fn future_exp() -> u64 {
        // 1 hour from now (roughly)
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    fn past_exp() -> u64 {
        // 1 hour ago
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600
    }

    #[test]
    fn valid_token_accepted() {
        let provider = JwtAuthProvider::new(TEST_RSA_PUBLIC_KEY, None, None).unwrap();
        let claims = TestClaims {
            sub: "user-1".to_string(),
            exp: future_exp(),
            iat: 1_000_000,
            iss: None,
            aud: None,
        };
        let token = sign_token(&claims, TEST_RSA_PRIVATE_KEY);
        let result = provider.validate_token(&token).unwrap();
        assert_eq!(result.sub, "user-1");
    }

    #[test]
    fn expired_token_rejected() {
        let provider = JwtAuthProvider::new(TEST_RSA_PUBLIC_KEY, None, None).unwrap();
        let claims = TestClaims {
            sub: "user-1".to_string(),
            exp: past_exp(),
            iat: 1_000_000,
            iss: None,
            aud: None,
        };
        let token = sign_token(&claims, TEST_RSA_PRIVATE_KEY);
        let err = provider.validate_token(&token).unwrap_err();
        assert!(matches!(err, AuthError::TokenExpired), "got: {err}");
    }

    #[test]
    fn wrong_key_rejected() {
        // Use the private key as "public key" — will fail to parse or validate
        let provider = JwtAuthProvider::new(TEST_RSA_PUBLIC_KEY, None, None).unwrap();
        // Sign with a different key pair (we just use a tampered token)
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.invalid-signature";
        let err = provider.validate_token(token).unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
    }

    #[test]
    fn empty_token_rejected() {
        let provider = JwtAuthProvider::new(TEST_RSA_PUBLIC_KEY, None, None).unwrap();
        let err = provider.validate_token("").unwrap_err();
        assert!(matches!(err, AuthError::TokenMissing), "got: {err}");
    }

    #[test]
    fn issuer_validated() {
        let provider =
            JwtAuthProvider::new(TEST_RSA_PUBLIC_KEY, Some("https://idp.example.com"), None)
                .unwrap();
        let claims = TestClaims {
            sub: "user-1".to_string(),
            exp: future_exp(),
            iat: 0,
            iss: Some("https://wrong-idp.example.com".to_string()),
            aud: None,
        };
        let token = sign_token(&claims, TEST_RSA_PRIVATE_KEY);
        let err = provider.validate_token(&token).unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
    }

    #[test]
    fn audience_validated() {
        let provider =
            JwtAuthProvider::new(TEST_RSA_PUBLIC_KEY, None, Some("ebpfsentinel")).unwrap();
        let claims = TestClaims {
            sub: "user-1".to_string(),
            exp: future_exp(),
            iat: 0,
            iss: None,
            aud: Some("wrong-audience".to_string()),
        };
        let token = sign_token(&claims, TEST_RSA_PRIVATE_KEY);
        let err = provider.validate_token(&token).unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
    }

    #[test]
    fn key_rotation_works() {
        let provider = JwtAuthProvider::new(TEST_RSA_PUBLIC_KEY, None, None).unwrap();

        let claims = TestClaims {
            sub: "user-1".to_string(),
            exp: future_exp(),
            iat: 0,
            iss: None,
            aud: None,
        };
        let token = sign_token(&claims, TEST_RSA_PRIVATE_KEY);

        // Validate with original key
        provider.validate_token(&token).unwrap();

        // Rotate key to same key (simulates reload)
        provider.rotate_key(TEST_RSA_PUBLIC_KEY).unwrap();

        // Still validates
        let result = provider.validate_token(&token).unwrap();
        assert_eq!(result.sub, "user-1");
    }

    #[test]
    fn invalid_pem_fails_construction() {
        let err = JwtAuthProvider::new(b"not a PEM", None, None).unwrap_err();
        assert!(matches!(err, AuthError::KeyLoadFailed(_)), "got: {err}");
    }
}
