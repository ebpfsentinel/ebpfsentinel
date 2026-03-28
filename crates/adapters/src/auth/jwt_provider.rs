use std::sync::{PoisonError, RwLock};

use base64::Engine as _;
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

/// Minimum RSA key size in bits. Keys smaller than 2048 bits are
/// considered insecure and rejected at construction time.
const MIN_RSA_KEY_BITS: usize = 2048;

/// Validate that a PEM-encoded RSA public key is at least `MIN_RSA_KEY_BITS`.
///
/// Parses the PEM/DER `SubjectPublicKeyInfo` to extract the RSA modulus length.
fn validate_rsa_key_size(pem_bytes: &[u8]) -> Result<(), AuthError> {
    let pem_str = std::str::from_utf8(pem_bytes)
        .map_err(|_| AuthError::KeyLoadFailed("PEM is not valid UTF-8".to_string()))?;

    // Strip PEM header/footer and decode base64
    let b64: String = pem_str
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| AuthError::KeyLoadFailed(format!("PEM base64 decode failed: {e}")))?;

    // Parse SubjectPublicKeyInfo → BIT STRING → SEQUENCE { INTEGER(n), INTEGER(e) }
    let modulus_bytes = extract_rsa_modulus_len(&der).ok_or_else(|| {
        AuthError::KeyLoadFailed("failed to parse RSA public key DER".to_string())
    })?;
    let key_bits = modulus_bytes * 8;

    if key_bits < MIN_RSA_KEY_BITS {
        return Err(AuthError::KeyLoadFailed(format!(
            "RSA key too small: {key_bits} bits (minimum {MIN_RSA_KEY_BITS})"
        )));
    }
    Ok(())
}

/// Extract RSA modulus byte-length from a DER-encoded `SubjectPublicKeyInfo`.
fn extract_rsa_modulus_len(der: &[u8]) -> Option<usize> {
    // SEQUENCE (SubjectPublicKeyInfo)
    let (spki_content, _) = parse_der_seq(der)?;
    // Skip AlgorithmIdentifier SEQUENCE
    let (_, rest) = parse_der_seq(spki_content)?;
    // BIT STRING containing RSA public key
    let bs_content = parse_der_bitstring(rest)?;
    // SEQUENCE { INTEGER(n), INTEGER(e) }
    let (rsa_seq, _) = parse_der_seq(bs_content)?;
    // First INTEGER is the modulus
    let (_, n_len) = parse_der_integer(rsa_seq)?;
    Some(n_len)
}

/// Parse a DER SEQUENCE tag, return (content, rest).
fn parse_der_seq(data: &[u8]) -> Option<(&[u8], &[u8])> {
    if data.first()? != &0x30 {
        return None;
    }
    let (len, offset) = parse_der_len(&data[1..])?;
    let content = data.get(1 + offset..1 + offset + len)?;
    let rest = data.get(1 + offset + len..)?;
    Some((content, rest))
}

/// Parse a DER BIT STRING tag, return inner content (skip unused-bits byte).
fn parse_der_bitstring(data: &[u8]) -> Option<&[u8]> {
    if data.first()? != &0x03 {
        return None;
    }
    let (len, offset) = parse_der_len(&data[1..])?;
    // First byte of BIT STRING content is unused-bits count (should be 0)
    data.get(1 + offset + 1..1 + offset + len)
}

/// Parse a DER INTEGER tag, return (rest, byte length without leading zero).
fn parse_der_integer(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.first()? != &0x02 {
        return None;
    }
    let (len, offset) = parse_der_len(&data[1..])?;
    let int_bytes = data.get(1 + offset..1 + offset + len)?;
    let rest = data.get(1 + offset + len..)?;
    // Strip leading zero (sign byte for positive integers)
    let stripped_len = if !int_bytes.is_empty() && int_bytes[0] == 0 {
        len - 1
    } else {
        len
    };
    Some((rest, stripped_len))
}

/// Parse DER length encoding, return (length, bytes consumed).
fn parse_der_len(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | (*data.get(1 + i)?) as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

impl JwtAuthProvider {
    /// Create a new provider from PEM-encoded RSA public key bytes.
    ///
    /// Rejects keys smaller than 2048 bits.
    pub fn new(
        pem_bytes: &[u8],
        issuer: Option<&str>,
        audience: Option<&str>,
    ) -> Result<Self, AuthError> {
        validate_rsa_key_size(pem_bytes)?;

        let decoding_key = DecodingKey::from_rsa_pem(pem_bytes)
            .map_err(|e| AuthError::KeyLoadFailed(e.to_string()))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["sub", "exp"]);
        validation.leeway = 0; // Explicit: reject expired tokens with zero tolerance

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
    ///
    /// Rejects keys smaller than 2048 bits.
    pub fn rotate_key(&self, pem_bytes: &[u8]) -> Result<(), AuthError> {
        validate_rsa_key_size(pem_bytes)?;

        let new_key = DecodingKey::from_rsa_pem(pem_bytes)
            .map_err(|e| AuthError::KeyLoadFailed(e.to_string()))?;
        let mut key = self
            .decoding_key
            .write()
            .unwrap_or_else(PoisonError::into_inner);
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
            .unwrap_or_else(PoisonError::into_inner);

        let token_data: TokenData<JwtClaims> = jsonwebtoken::decode(token, &key, &self.validation)
            .map_err(|e| {
                if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                    AuthError::TokenExpired
                } else {
                    tracing::debug!(error = %e, "JWT token validation failed");
                    AuthError::TokenInvalid("invalid token".to_string())
                }
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

    #[test]
    fn rsa_key_size_validation_accepts_2048() {
        // The test fixture is a 2048-bit key
        assert!(validate_rsa_key_size(TEST_RSA_PUBLIC_KEY).is_ok());
    }

    #[test]
    fn rsa_key_size_validation_reports_bits() {
        let key_bits = {
            let pem_str = std::str::from_utf8(TEST_RSA_PUBLIC_KEY).unwrap();
            let b64: String = pem_str
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect();
            let der = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .unwrap();
            extract_rsa_modulus_len(&der).unwrap() * 8
        };
        assert_eq!(key_bits, 2048);
    }
}
