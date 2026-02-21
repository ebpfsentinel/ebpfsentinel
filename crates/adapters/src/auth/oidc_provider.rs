use std::sync::RwLock;

use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;
use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, decode, decode_header, jwk::JwkSet,
};
use ports::secondary::auth_provider::AuthProvider;

/// OIDC authentication provider using JWKS (JSON Web Key Set) for token validation.
///
/// Validates JWT tokens by matching the `kid` (Key ID) header field against
/// cached JWKS keys. Supports key rotation via `rotate_keys()`.
pub struct OidcAuthProvider {
    jwk_set: RwLock<JwkSet>,
    validation: Validation,
}

impl std::fmt::Debug for OidcAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAuthProvider")
            .field("algorithm", &"RS256")
            .finish_non_exhaustive()
    }
}

impl OidcAuthProvider {
    /// Create a new OIDC provider from a pre-fetched JWKS and optional issuer/audience.
    pub fn new(
        jwk_set: JwkSet,
        issuer: Option<&str>,
        audience: Option<&str>,
    ) -> Result<Self, AuthError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["sub", "exp"]);

        if let Some(iss) = issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(aud) = audience {
            validation.set_audience(&[aud]);
        }

        Ok(Self {
            jwk_set: RwLock::new(jwk_set),
            validation,
        })
    }

    /// Atomically replace the cached JWKS (for periodic key rotation).
    pub fn rotate_keys(&self, jwk_set: JwkSet) {
        let mut keys = self.jwk_set.write().expect("JWKS lock poisoned");
        *keys = jwk_set;
    }
}

impl AuthProvider for OidcAuthProvider {
    fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError> {
        if token.is_empty() {
            return Err(AuthError::TokenMissing);
        }

        // Decode the JWT header to extract the `kid`
        let header = decode_header(token)
            .map_err(|e| AuthError::TokenInvalid(format!("invalid JWT header: {e}")))?;

        let kid = header
            .kid
            .as_ref()
            .ok_or_else(|| AuthError::TokenInvalid("token missing 'kid' header".to_string()))?;

        // Find the matching JWK in the cached set
        let jwk_set = self.jwk_set.read().expect("JWKS lock poisoned");

        let jwk = jwk_set
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid.as_str()))
            .ok_or_else(|| AuthError::TokenInvalid(format!("no JWK found for kid '{kid}'")))?;

        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| AuthError::TokenInvalid(format!("invalid JWK: {e}")))?;

        let token_data: TokenData<JwtClaims> = decode(token, &decoding_key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::TokenInvalid(e.to_string()),
            })?;

        Ok(token_data.claims)
    }
}

/// Fetch a JWKS from a remote URL.
pub async fn fetch_jwks(url: &str) -> Result<JwkSet, AuthError> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| AuthError::KeyLoadFailed(format!("JWKS fetch failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(AuthError::KeyLoadFailed(format!(
            "JWKS fetch returned HTTP {}",
            resp.status()
        )));
    }

    resp.json::<JwkSet>()
        .await
        .map_err(|e| AuthError::KeyLoadFailed(format!("JWKS parse failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        exp: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        namespaces: Option<Vec<String>>,
    }

    const TEST_RSA_PRIVATE_KEY: &[u8] = include_bytes!("../../tests/fixtures/jwt_test_key.pem");
    const TEST_RSA_PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/jwt_test_key.pub.pem");

    fn future_exp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    fn past_exp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600
    }

    /// Build a minimal JwkSet from the test RSA public key with the given kid.
    fn build_test_jwk_set(kid: &str) -> JwkSet {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        // Parse the PEM to extract RSA components
        let pem_str = std::str::from_utf8(TEST_RSA_PUBLIC_KEY).unwrap();
        let pem_str = pem_str
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace('\n', "");

        use base64::engine::general_purpose::STANDARD;
        let der_bytes = STANDARD.decode(&pem_str).unwrap();

        // Parse the DER-encoded SubjectPublicKeyInfo
        // RSA public key in PKCS#8 format: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { n, e } } }
        // We need to extract n and e from the inner SEQUENCE.
        // For simplicity, use the jsonwebtoken crate's own mechanism.
        // We'll build the JWK manually using the raw key.
        let rsa_key = rsa_from_der(&der_bytes);

        let n_b64 = URL_SAFE_NO_PAD.encode(&rsa_key.n);
        let e_b64 = URL_SAFE_NO_PAD.encode(&rsa_key.e);

        let jwk_json = serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": n_b64,
                "e": e_b64
            }]
        });

        serde_json::from_value(jwk_json).unwrap()
    }

    struct RsaComponents {
        n: Vec<u8>,
        e: Vec<u8>,
    }

    /// Minimal ASN.1 DER parser for RSA SubjectPublicKeyInfo.
    fn rsa_from_der(der: &[u8]) -> RsaComponents {
        // parse_sequence returns (content_of_sequence, rest_after_sequence)
        let (inner, _) = parse_sequence(der);
        // inner = AlgorithmIdentifier SEQUENCE + BIT STRING
        let (_algo_id, rest) = parse_sequence(inner);
        // rest starts with BIT STRING
        let (bit_string_content, _) = parse_bit_string(rest);
        // bit_string_content = SEQUENCE { INTEGER(n), INTEGER(e) }
        let (rsa_seq, _) = parse_sequence(bit_string_content);
        let (rest_after_n, n) = parse_integer(rsa_seq);
        let (_, e) = parse_integer(rest_after_n);
        RsaComponents { n, e }
    }

    fn parse_tag_length(data: &[u8]) -> (u8, usize, &[u8]) {
        let tag = data[0];
        let (len, offset) = if data[1] & 0x80 == 0 {
            (data[1] as usize, 2)
        } else {
            let num_bytes = (data[1] & 0x7F) as usize;
            let mut len = 0usize;
            for i in 0..num_bytes {
                len = (len << 8) | data[2 + i] as usize;
            }
            (len, 2 + num_bytes)
        };
        (tag, len, &data[offset..])
    }

    fn parse_sequence(data: &[u8]) -> (&[u8], &[u8]) {
        let (tag, len, content) = parse_tag_length(data);
        assert_eq!(tag, 0x30, "expected SEQUENCE");
        let rest = &content[len..];
        (&content[..len], rest)
    }

    fn parse_bit_string(data: &[u8]) -> (&[u8], &[u8]) {
        let (tag, len, content) = parse_tag_length(data);
        assert_eq!(tag, 0x03, "expected BIT STRING");
        // First byte of BIT STRING content is unused-bits count (should be 0)
        let rest = &content[len..];
        (&content[1..len], rest)
    }

    fn parse_integer(data: &[u8]) -> (&[u8], Vec<u8>) {
        let (tag, len, content) = parse_tag_length(data);
        assert_eq!(tag, 0x02, "expected INTEGER");
        let int_bytes = &content[..len];
        let rest = &content[len..];
        // Strip leading zero byte (sign byte for positive integers)
        let stripped = if !int_bytes.is_empty() && int_bytes[0] == 0 {
            &int_bytes[1..]
        } else {
            int_bytes
        };
        (rest, stripped.to_vec())
    }

    fn sign_token_with_kid(claims: &TestClaims, kid: &str) -> String {
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY).unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &key).unwrap()
    }

    #[test]
    fn valid_token_with_matching_kid() {
        let jwk_set = build_test_jwk_set("test-key-1");
        let provider = OidcAuthProvider::new(jwk_set, None, None).unwrap();

        let claims = TestClaims {
            sub: "k8s-sa".to_string(),
            exp: future_exp(),
            iss: None,
            aud: None,
            role: Some("admin".to_string()),
            namespaces: Some(vec!["prod".to_string()]),
        };
        let token = sign_token_with_kid(&claims, "test-key-1");
        let result = provider.validate_token(&token).unwrap();
        assert_eq!(result.sub, "k8s-sa");
        assert_eq!(result.role.as_deref(), Some("admin"));
    }

    #[test]
    fn token_with_unknown_kid_rejected() {
        let jwk_set = build_test_jwk_set("test-key-1");
        let provider = OidcAuthProvider::new(jwk_set, None, None).unwrap();

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: future_exp(),
            iss: None,
            aud: None,
            role: None,
            namespaces: None,
        };
        let token = sign_token_with_kid(&claims, "unknown-kid");
        let err = provider.validate_token(&token).unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
        assert!(err.to_string().contains("unknown-kid"));
    }

    #[test]
    fn expired_token_rejected() {
        let jwk_set = build_test_jwk_set("test-key-1");
        let provider = OidcAuthProvider::new(jwk_set, None, None).unwrap();

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: past_exp(),
            iss: None,
            aud: None,
            role: None,
            namespaces: None,
        };
        let token = sign_token_with_kid(&claims, "test-key-1");
        let err = provider.validate_token(&token).unwrap_err();
        assert!(matches!(err, AuthError::TokenExpired), "got: {err}");
    }

    #[test]
    fn key_rotation() {
        let jwk_set = build_test_jwk_set("old-key");
        let provider = OidcAuthProvider::new(jwk_set, None, None).unwrap();

        let claims = TestClaims {
            sub: "user".to_string(),
            exp: future_exp(),
            iss: None,
            aud: None,
            role: None,
            namespaces: None,
        };

        // Token signed with kid "new-key" fails before rotation
        let token = sign_token_with_kid(&claims, "new-key");
        assert!(provider.validate_token(&token).is_err());

        // Rotate to include the new key
        let new_jwk_set = build_test_jwk_set("new-key");
        provider.rotate_keys(new_jwk_set);

        // Now it works
        let result = provider.validate_token(&token).unwrap();
        assert_eq!(result.sub, "user");
    }

    #[test]
    fn empty_token_rejected() {
        let jwk_set = build_test_jwk_set("k1");
        let provider = OidcAuthProvider::new(jwk_set, None, None).unwrap();
        let err = provider.validate_token("").unwrap_err();
        assert!(matches!(err, AuthError::TokenMissing), "got: {err}");
    }

    #[test]
    fn token_without_kid_rejected() {
        let jwk_set = build_test_jwk_set("k1");
        let provider = OidcAuthProvider::new(jwk_set, None, None).unwrap();

        // Sign without kid
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY).unwrap();
        let header = Header::new(Algorithm::RS256); // no kid
        let claims = TestClaims {
            sub: "user".to_string(),
            exp: future_exp(),
            iss: None,
            aud: None,
            role: None,
            namespaces: None,
        };
        let token = encode(&header, &claims, &key).unwrap();

        let err = provider.validate_token(&token).unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
        assert!(err.to_string().contains("kid"));
    }
}
