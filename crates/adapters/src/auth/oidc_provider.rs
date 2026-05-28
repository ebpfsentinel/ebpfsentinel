use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use domain::auth::entity::JwtClaims;
use domain::auth::error::AuthError;
use jsonwebtoken::{
    Algorithm, DecodingKey, TokenData, Validation, decode, decode_header, jwk::JwkSet,
};
use ports::secondary::auth_provider::AuthProvider;

/// Hook used by the OIDC / JWKS provider to refresh its key set when a
/// JWT arrives with a `kid` it does not know about.
///
/// The hook is constructed with the JWKS URL captured from the agent's
/// config so the provider can refetch + replace its cached `JwkSet`
/// without holding a `reqwest::Client` itself. Implementations must be
/// `Send + Sync` and idempotent — they can be called once per request
/// in the worst case.
#[async_trait]
pub trait JwksRefresher: Send + Sync {
    /// Fetch the latest JWKS from the upstream URL.
    async fn refresh(&self) -> Result<JwkSet, AuthError>;
}

/// OIDC authentication provider using JWKS (JSON Web Key Set) for token validation.
///
/// Validates JWT tokens by matching the `kid` (Key ID) header field against
/// cached JWKS keys. Supports key rotation via `rotate_keys()` and, when
/// configured, an inline refresh on unknown `kid`.
pub struct OidcAuthProvider {
    jwk_set: RwLock<JwkSet>,
    validation: Validation,
    /// Optional inline refresh handle used when a request arrives with
    /// a `kid` not present in the cached set.
    refresher: Option<std::sync::Arc<dyn JwksRefresher>>,
    /// Whether to attempt an inline refresh on unknown `kid`. Defaults
    /// to `true` so the dashboard can rotate keys without redeploying
    /// agents; set to `false` to keep the agent stricter / quieter.
    refresh_on_unknown_kid: bool,
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
        Ok(Self::new_with_algorithm(
            Algorithm::RS256,
            jwk_set,
            issuer,
            audience,
        ))
    }

    /// Create a new provider that validates `EdDSA` (Ed25519) tokens against
    /// a JWKS. Used by the dashboard's short-lived per-tenant JWT path.
    pub fn new_for_eddsa(
        jwk_set: JwkSet,
        issuer: Option<&str>,
        audience: Option<&str>,
    ) -> Result<Self, AuthError> {
        Ok(Self::new_with_algorithm(
            Algorithm::EdDSA,
            jwk_set,
            issuer,
            audience,
        ))
    }

    fn new_with_algorithm(
        algorithm: Algorithm,
        jwk_set: JwkSet,
        issuer: Option<&str>,
        audience: Option<&str>,
    ) -> Self {
        let mut validation = Validation::new(algorithm);
        validation.set_required_spec_claims(&["sub", "exp"]);
        validation.leeway = 0; // Explicit: reject expired tokens with zero tolerance

        if let Some(iss) = issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(aud) = audience {
            validation.set_audience(&[aud]);
        }

        Self {
            jwk_set: RwLock::new(jwk_set),
            validation,
            refresher: None,
            refresh_on_unknown_kid: true,
        }
    }

    /// Wire an inline JWKS refresher. The provider will call
    /// `refresher.refresh()` once per request that arrives with an
    /// unknown `kid`, replace its cached set with the result, and retry
    /// the verification before failing.
    #[must_use]
    pub fn with_refresher(
        mut self,
        refresher: std::sync::Arc<dyn JwksRefresher>,
        refresh_on_unknown_kid: bool,
    ) -> Self {
        self.refresher = Some(refresher);
        self.refresh_on_unknown_kid = refresh_on_unknown_kid;
        self
    }

    /// Atomically replace the cached JWKS (for periodic key rotation).
    pub fn rotate_keys(&self, jwk_set: JwkSet) {
        let mut keys = self.jwk_set.write().unwrap_or_else(|e| {
            tracing::error!("OIDC JWKS RwLock poisoned on write: {e}");
            e.into_inner()
        });
        *keys = jwk_set;
    }
}

impl OidcAuthProvider {
    /// True when the cached JWKS contains the given `kid`.
    fn cached_has_kid(&self, kid: &str) -> bool {
        self.jwk_set.read().is_ok_and(|guard| {
            guard
                .keys
                .iter()
                .any(|k| k.common.key_id.as_deref() == Some(kid))
        })
    }

    /// Look up `kid` in the cached set, build a `DecodingKey`, and
    /// run the verifier. Returns `AuthError::TokenInvalid("kid")` when
    /// the kid is missing from the cache so the outer call site can
    /// decide whether to refresh + retry.
    fn validate_with_cached(&self, token: &str, kid: &str) -> Result<JwtClaims, AuthError> {
        let jwk_set = self.jwk_set.read().map_err(|e| {
            tracing::error!("OIDC JWKS RwLock poisoned on read: {e}");
            AuthError::TokenInvalid("internal auth error".to_string())
        })?;

        let jwk = jwk_set
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .ok_or_else(|| {
                tracing::debug!(kid, "OIDC no JWK found for kid");
                AuthError::TokenInvalid("kid".to_string())
            })?;

        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|e| {
            tracing::debug!(error = %e, "OIDC JWK decode failed");
            AuthError::TokenInvalid("invalid token".to_string())
        })?;

        let token_data: TokenData<JwtClaims> = decode(token, &decoding_key, &self.validation)
            .map_err(|e| {
                if matches!(e.kind(), jsonwebtoken::errors::ErrorKind::ExpiredSignature) {
                    AuthError::TokenExpired
                } else {
                    tracing::debug!(error = %e, "OIDC token validation failed");
                    AuthError::TokenInvalid("invalid token".to_string())
                }
            })?;
        Ok(token_data.claims)
    }
}

#[async_trait]
impl AuthProvider for OidcAuthProvider {
    async fn validate_token(&self, token: &str) -> Result<JwtClaims, AuthError> {
        if token.is_empty() {
            return Err(AuthError::TokenMissing);
        }

        // Decode the JWT header to extract the `kid`.
        // Detailed errors are logged server-side; clients receive a generic message
        // to prevent authentication infrastructure enumeration.
        let header = decode_header(token).map_err(|e| {
            tracing::debug!(error = %e, "OIDC token header decode failed");
            AuthError::TokenInvalid("invalid token".to_string())
        })?;

        let kid = header.kid.clone().ok_or_else(|| {
            tracing::debug!("OIDC token missing kid header");
            AuthError::TokenInvalid("invalid token".to_string())
        })?;

        match self.validate_with_cached(token, &kid) {
            Ok(claims) => Ok(claims),
            Err(AuthError::TokenInvalid(ref msg)) if msg == "kid" => {
                if !self.refresh_on_unknown_kid {
                    return Err(AuthError::TokenInvalid("invalid token".to_string()));
                }
                let Some(refresher) = self.refresher.as_ref() else {
                    return Err(AuthError::TokenInvalid("invalid token".to_string()));
                };
                tracing::debug!(kid = %kid, "JWKS unknown kid — forcing refresh");
                let new_set = refresher.refresh().await.map_err(|e| {
                    tracing::warn!(error = %e, "JWKS inline refresh failed");
                    AuthError::TokenInvalid("invalid token".to_string())
                })?;
                self.rotate_keys(new_set);
                if !self.cached_has_kid(&kid) {
                    tracing::debug!(kid = %kid, "JWKS still missing kid after refresh");
                    return Err(AuthError::TokenInvalid("invalid token".to_string()));
                }
                self.validate_with_cached(token, &kid).map_err(|e| match e {
                    AuthError::TokenInvalid(msg) if msg == "kid" => {
                        AuthError::TokenInvalid("invalid token".to_string())
                    }
                    other => other,
                })
            }
            Err(other) => Err(other),
        }
    }
}

/// Concrete [`JwksRefresher`] implementation that calls [`fetch_jwks`]
/// with the configured URL on every refresh request.
///
/// Held by the OIDC provider behind an `Arc<dyn JwksRefresher>` so the
/// provider does not have to know about HTTP plumbing.
#[derive(Debug, Clone)]
pub struct HttpJwksRefresher {
    url: String,
}

impl HttpJwksRefresher {
    #[must_use]
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

#[async_trait]
impl JwksRefresher for HttpJwksRefresher {
    async fn refresh(&self) -> Result<JwkSet, AuthError> {
        fetch_jwks(&self.url).await
    }
}

/// Whether a JWKS URL may be fetched over plaintext HTTP.
///
/// Only loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) are exempt from
/// the HTTPS requirement — these never leave the host, so there is no MITM
/// surface. Every other host must use HTTPS. Mirrors the OAuth "localhost is
/// exempt" carve-out and lets dashboards/sidecars co-located with the agent
/// serve JWKS without provisioning TLS.
fn allows_plaintext(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "http" {
        return false;
    }
    match parsed.host_str() {
        Some(host) => {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        }
        None => false,
    }
}

/// Fetch a JWKS from a remote URL.
///
/// Enforces HTTPS (except for loopback hosts, see [`allows_plaintext`]) and a
/// 10-second timeout to prevent MITM attacks and hanging on unresponsive
/// identity providers.
pub async fn fetch_jwks(url: &str) -> Result<JwkSet, AuthError> {
    let client = reqwest::Client::builder()
        .https_only(!allows_plaintext(url))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| AuthError::KeyLoadFailed(format!("JWKS HTTP client error: {e}")))?;

    let resp = client
        .get(url)
        .send()
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

    /// Build a minimal `JwkSet` from the test RSA public key with the given kid.
    fn build_test_jwk_set(kid: &str) -> JwkSet {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        // Parse the PEM to extract RSA components
        let pem_str = std::str::from_utf8(TEST_RSA_PUBLIC_KEY).unwrap();
        let pem_str = pem_str
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace('\n', "");

        let der_bytes = base64::engine::general_purpose::STANDARD
            .decode(&pem_str)
            .unwrap();

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

    /// Minimal ASN.1 DER parser for RSA `SubjectPublicKeyInfo`.
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

    #[tokio::test]
    async fn valid_token_with_matching_kid() {
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
        let result = provider.validate_token(&token).await.unwrap();
        assert_eq!(result.sub, "k8s-sa");
        assert_eq!(result.role.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn token_with_unknown_kid_rejected() {
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
        let err = provider.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
        assert!(err.to_string().contains("invalid token"));
    }

    #[tokio::test]
    async fn expired_token_rejected() {
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
        let err = provider.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::TokenExpired), "got: {err}");
    }

    #[tokio::test]
    async fn key_rotation() {
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
        assert!(provider.validate_token(&token).await.is_err());

        // Rotate to include the new key
        let new_jwk_set = build_test_jwk_set("new-key");
        provider.rotate_keys(new_jwk_set);

        // Now it works
        let result = provider.validate_token(&token).await.unwrap();
        assert_eq!(result.sub, "user");
    }

    #[tokio::test]
    async fn empty_token_rejected() {
        let jwk_set = build_test_jwk_set("k1");
        let provider = OidcAuthProvider::new(jwk_set, None, None).unwrap();
        let err = provider.validate_token("").await.unwrap_err();
        assert!(matches!(err, AuthError::TokenMissing), "got: {err}");
    }

    #[tokio::test]
    async fn token_without_kid_rejected() {
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

        let err = provider.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
        assert!(err.to_string().contains("invalid token"));
    }

    // ── EdDSA-via-JWKS ─────────────────────────────────────────────

    const TEST_ED25519_PRIVATE_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/jwt_test_ed25519.pem");
    const TEST_ED25519_PUBLIC_KEY: &[u8] =
        include_bytes!("../../tests/fixtures/jwt_test_ed25519.pub.pem");

    /// Extract the raw 32-byte Ed25519 public key from a PEM-encoded
    /// `SubjectPublicKeyInfo`. Ed25519 has a fixed wire layout, so the
    /// public key is always the last 32 bytes of the DER body.
    fn ed25519_pubkey_raw() -> [u8; 32] {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        let pem = std::str::from_utf8(TEST_ED25519_PUBLIC_KEY).unwrap();
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = STANDARD.decode(body).unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(&der[der.len() - 32..]);
        out
    }

    fn build_eddsa_jwk_set(kid: &str) -> JwkSet {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let raw = ed25519_pubkey_raw();
        let x_b64 = URL_SAFE_NO_PAD.encode(raw);
        let jwk_json = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "use": "sig",
                "alg": "EdDSA",
                "x": x_b64,
            }]
        });
        serde_json::from_value(jwk_json).unwrap()
    }

    fn sign_eddsa_with_kid(claims: &TestClaims, kid: &str) -> String {
        let key = EncodingKey::from_ed_pem(TEST_ED25519_PRIVATE_KEY).unwrap();
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &key).unwrap()
    }

    #[tokio::test]
    async fn eddsa_jwks_valid_token_accepted() {
        let jwk_set = build_eddsa_jwk_set("dash-2026-04");
        let provider = OidcAuthProvider::new_for_eddsa(jwk_set, None, None).unwrap();

        let claims = TestClaims {
            sub: "tenant-admin".to_string(),
            exp: future_exp(),
            iss: None,
            aud: None,
            role: Some("admin".to_string()),
            namespaces: None,
        };
        let token = sign_eddsa_with_kid(&claims, "dash-2026-04");
        let result = provider.validate_token(&token).await.unwrap();
        assert_eq!(result.sub, "tenant-admin");
        assert_eq!(result.role.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn eddsa_jwks_unknown_kid_rejected() {
        let jwk_set = build_eddsa_jwk_set("dash-2026-04");
        let provider = OidcAuthProvider::new_for_eddsa(jwk_set, None, None).unwrap();

        let claims = TestClaims {
            sub: "x".to_string(),
            exp: future_exp(),
            iss: None,
            aud: None,
            role: None,
            namespaces: None,
        };
        let token = sign_eddsa_with_kid(&claims, "dash-2025-12");
        let err = provider.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
    }

    #[tokio::test]
    async fn eddsa_jwks_rejects_rs256_token() {
        let jwk_set = build_eddsa_jwk_set("dash-2026-04");
        let provider = OidcAuthProvider::new_for_eddsa(jwk_set, None, None).unwrap();

        let claims = TestClaims {
            sub: "x".to_string(),
            exp: future_exp(),
            iss: None,
            aud: None,
            role: None,
            namespaces: None,
        };
        let rsa_token = sign_token_with_kid(&claims, "dash-2026-04");
        let err = provider.validate_token(&rsa_token).await.unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
    }

    #[tokio::test]
    async fn eddsa_jwks_rotation_picks_up_new_kid() {
        let jwk_set = build_eddsa_jwk_set("old-kid");
        let provider = OidcAuthProvider::new_for_eddsa(jwk_set, None, None).unwrap();

        let claims = TestClaims {
            sub: "x".to_string(),
            exp: future_exp(),
            iss: None,
            aud: None,
            role: None,
            namespaces: None,
        };
        let token = sign_eddsa_with_kid(&claims, "new-kid");
        assert!(provider.validate_token(&token).await.is_err());

        provider.rotate_keys(build_eddsa_jwk_set("new-kid"));
        let result = provider.validate_token(&token).await.unwrap();
        assert_eq!(result.sub, "x");
    }

    // ── Inline force-refresh on unknown kid ────────────────────────

    /// In-memory `JwksRefresher` for tests — returns a pre-baked JWKS
    /// the next time `refresh()` is called and counts invocations.
    struct StubRefresher {
        next: std::sync::Mutex<Option<JwkSet>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl StubRefresher {
        fn new(next: JwkSet) -> Self {
            Self {
                next: std::sync::Mutex::new(Some(next)),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl JwksRefresher for StubRefresher {
        async fn refresh(&self) -> Result<JwkSet, AuthError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.next.lock().unwrap().take().ok_or_else(|| {
                AuthError::KeyLoadFailed("stub refresher already drained".to_string())
            })
        }
    }

    #[tokio::test]
    async fn unknown_kid_triggers_inline_refresh_and_retries() {
        let stale = build_eddsa_jwk_set("old-kid");
        let fresh = build_eddsa_jwk_set("new-kid");
        let refresher = std::sync::Arc::new(StubRefresher::new(fresh));
        let provider = OidcAuthProvider::new_for_eddsa(stale, None, None)
            .unwrap()
            .with_refresher(refresher.clone(), true);

        let token = sign_eddsa_with_kid(
            &TestClaims {
                sub: "rotated".to_string(),
                exp: future_exp(),
                iss: None,
                aud: None,
                role: None,
                namespaces: None,
            },
            "new-kid",
        );

        let claims = provider.validate_token(&token).await.unwrap();
        assert_eq!(claims.sub, "rotated");
        assert_eq!(refresher.calls(), 1);

        // Second call hits the cache — no extra refresh.
        let _ = provider.validate_token(&token).await.unwrap();
        assert_eq!(refresher.calls(), 1);
    }

    #[tokio::test]
    async fn unknown_kid_refused_when_refresh_disabled() {
        let stale = build_eddsa_jwk_set("old-kid");
        let fresh = build_eddsa_jwk_set("new-kid");
        let refresher = std::sync::Arc::new(StubRefresher::new(fresh));
        let provider = OidcAuthProvider::new_for_eddsa(stale, None, None)
            .unwrap()
            .with_refresher(refresher.clone(), false);

        let token = sign_eddsa_with_kid(
            &TestClaims {
                sub: "x".to_string(),
                exp: future_exp(),
                iss: None,
                aud: None,
                role: None,
                namespaces: None,
            },
            "new-kid",
        );
        assert!(provider.validate_token(&token).await.is_err());
        assert_eq!(refresher.calls(), 0);
    }

    #[tokio::test]
    async fn unknown_kid_still_missing_after_refresh_returns_invalid() {
        // Refresher returns a JWKS that still lacks the requested kid.
        let stale = build_eddsa_jwk_set("old-kid");
        let useless = build_eddsa_jwk_set("still-old-kid");
        let refresher = std::sync::Arc::new(StubRefresher::new(useless));
        let provider = OidcAuthProvider::new_for_eddsa(stale, None, None)
            .unwrap()
            .with_refresher(refresher.clone(), true);

        let token = sign_eddsa_with_kid(
            &TestClaims {
                sub: "x".to_string(),
                exp: future_exp(),
                iss: None,
                aud: None,
                role: None,
                namespaces: None,
            },
            "brand-new-kid",
        );
        let err = provider.validate_token(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::TokenInvalid(_)), "got: {err}");
        assert_eq!(refresher.calls(), 1);
    }

    #[test]
    fn allows_plaintext_only_for_loopback_http() {
        // Loopback over http is exempt.
        assert!(allows_plaintext("http://localhost:8765/jwks.json"));
        assert!(allows_plaintext("http://127.0.0.1:8765/jwks.json"));
        assert!(allows_plaintext("http://[::1]:8765/jwks.json"));
        assert!(allows_plaintext("http://127.0.0.2/jwks.json"));

        // Non-loopback http is not.
        assert!(!allows_plaintext("http://example.com/jwks.json"));
        assert!(!allows_plaintext("http://10.0.0.1/jwks.json"));

        // https never needs the carve-out (and is not "plaintext").
        assert!(!allows_plaintext("https://localhost/jwks.json"));
        assert!(!allows_plaintext("https://example.com/jwks.json"));

        // Garbage URLs are rejected.
        assert!(!allows_plaintext("not a url"));
    }
}
