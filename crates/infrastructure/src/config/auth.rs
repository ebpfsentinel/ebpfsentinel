//! Authentication domain configuration structs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub jwt: JwtConfig,

    /// OIDC provider configuration (JWKS-based token validation).
    #[serde(default)]
    pub oidc: Option<OidcConfig>,

    /// Static API keys for standalone authentication (no external identity provider required).
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,

    /// Salt for API key hashing. If omitted, a random 32-byte salt is generated
    /// at startup. Set this explicitly to ensure stable hashes across restarts.
    #[serde(default)]
    pub api_key_salt: Option<String>,

    /// Whether `/metrics` requires authentication (default: true).
    #[serde(default = "default_metrics_auth")]
    pub metrics_auth_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Human-readable name for the key (e.g. "admin-key", "monitoring").
    pub name: String,

    /// The secret key value (e.g. "sk-xxxxxxxxxxxx").
    pub key: String,

    /// RBAC role: "admin", "operator", or "viewer".
    #[serde(default = "default_api_key_role")]
    pub role: String,

    /// Optional namespace scoping (unrestricted when empty).
    #[serde(default)]
    pub namespaces: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            jwt: JwtConfig::default(),
            oidc: None,
            api_keys: Vec::new(),
            api_key_salt: None,
            metrics_auth_required: true,
        }
    }
}

fn default_metrics_auth() -> bool {
    true
}

fn default_api_key_role() -> String {
    "viewer".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// URL to fetch the JWKS key set from (e.g. K8s OIDC discovery endpoint).
    pub jwks_url: String,

    /// Expected token issuer (`iss` claim). Validated when set.
    #[serde(default)]
    pub issuer: Option<String>,

    /// Expected token audience (`aud` claim). Validated when set.
    #[serde(default)]
    pub audience: Option<String>,
}

/// Signing algorithm advertised by the JWT verifier.
///
/// `RS256` (legacy default) verifies with an RSA-2048+ public key.
/// `EdDSA` verifies with an Ed25519 public key — required for the
/// dashboard's short-lived per-tenant tokens with JWKS rotation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum JwtAlgorithm {
    /// RSA + SHA-256 (legacy). Requires `public_key_path` to point at
    /// an RSA-2048+ public key in PEM format.
    #[default]
    RS256,
    /// Ed25519. Pairs with either an Ed25519 PEM at `public_key_path`
    /// or a JWKS endpoint at `jwks_url` carrying `kty=OKP, crv=Ed25519`.
    EdDSA,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Signing algorithm. `RS256` keeps the existing static-PEM path;
    /// `EdDSA` enables the dashboard's rotating-key JWKS path.
    #[serde(default)]
    pub algorithm: JwtAlgorithm,

    /// Path to the public key in PEM format. Mutually exclusive with
    /// `jwks_url`. Empty string disables the static-PEM source.
    #[serde(default)]
    pub public_key_path: String,

    /// JWKS URL (`https://`). Mutually exclusive with
    /// `public_key_path`. The agent fetches once at startup, caches for
    /// `jwks_cache_ttl_seconds`, and refreshes in the background.
    #[serde(default)]
    pub jwks_url: Option<String>,

    /// JWKS cache TTL in seconds. Default: 3600 (1h).
    #[serde(default = "default_jwks_cache_ttl_seconds")]
    pub jwks_cache_ttl_seconds: u64,

    /// On unknown `kid`, request an immediate JWKS refresh from the
    /// background fetcher and retry once. Default: true.
    #[serde(default = "default_jwks_refresh_on_unknown_kid")]
    pub jwks_refresh_on_unknown_kid: bool,

    /// Expected token issuer (`iss` claim). Validated when set.
    #[serde(default)]
    pub issuer: Option<String>,

    /// Expected token audience (`aud` claim). Validated when set.
    #[serde(default)]
    pub audience: Option<String>,
}

fn default_jwks_cache_ttl_seconds() -> u64 {
    3600
}

fn default_jwks_refresh_on_unknown_kid() -> bool {
    true
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            algorithm: JwtAlgorithm::default(),
            public_key_path: String::new(),
            jwks_url: None,
            jwks_cache_ttl_seconds: default_jwks_cache_ttl_seconds(),
            jwks_refresh_on_unknown_kid: default_jwks_refresh_on_unknown_kid(),
            issuer: None,
            audience: None,
        }
    }
}

/// Source of the JWT verification key, derived from [`JwtConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtKeySource {
    /// Static PEM file on disk.
    Pem { path: String },
    /// JWKS HTTP endpoint with cached refresh.
    Jwks {
        url: String,
        cache_ttl_seconds: u64,
        refresh_on_unknown_kid: bool,
    },
    /// Auth disabled / no JWT source configured.
    None,
}

impl JwtConfig {
    /// Resolve the key source, rejecting ambiguous configurations.
    ///
    /// Returns [`JwtKeySource::None`] when both `public_key_path` and
    /// `jwks_url` are empty (auth turned off or pure-API-key mode).
    pub fn key_source(&self) -> Result<JwtKeySource, String> {
        let has_pem = !self.public_key_path.is_empty();
        let has_jwks = self.jwks_url.as_deref().is_some_and(|s| !s.is_empty());
        match (has_pem, has_jwks) {
            (true, true) => Err(
                "auth.jwt: exactly one of `public_key_path` or `jwks_url` may be set".to_string(),
            ),
            (true, false) => Ok(JwtKeySource::Pem {
                path: self.public_key_path.clone(),
            }),
            (false, true) => {
                let url = self.jwks_url.as_deref().unwrap_or_default().to_string();
                if !(url.starts_with("https://") || url.starts_with("http://")) {
                    return Err(format!(
                        "auth.jwt.jwks_url must be `http://` or `https://`, got {url:?}"
                    ));
                }
                Ok(JwtKeySource::Jwks {
                    url,
                    cache_ttl_seconds: self.jwks_cache_ttl_seconds,
                    refresh_on_unknown_kid: self.jwks_refresh_on_unknown_kid,
                })
            }
            (false, false) => Ok(JwtKeySource::None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = AuthConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.jwt.public_key_path, "");
        assert!(cfg.jwt.issuer.is_none());
        assert!(cfg.jwt.audience.is_none());
        assert!(cfg.oidc.is_none());
        assert!(cfg.api_keys.is_empty());
        assert!(cfg.metrics_auth_required);
    }

    #[test]
    fn yaml_with_api_keys() {
        let yaml = r"
enabled: true
api_keys:
  - name: admin-key
    key: sk-abc123
    role: admin
  - name: readonly
    key: sk-xyz789
";
        let cfg: AuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.api_keys.len(), 2);
        assert_eq!(cfg.api_keys[0].name, "admin-key");
        assert_eq!(cfg.api_keys[0].key, "sk-abc123");
        assert_eq!(cfg.api_keys[0].role, "admin");
    }

    #[test]
    fn default_api_key_role_is_viewer() {
        let yaml = r"
api_keys:
  - name: test
    key: sk-test
";
        let cfg: AuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.api_keys[0].role, "viewer");
    }

    #[test]
    fn yaml_with_oidc() {
        let yaml = r#"
oidc:
  jwks_url: "https://idp.example.com/.well-known/jwks.json"
  issuer: "https://idp.example.com"
  audience: "ebpfsentinel"
"#;
        let cfg: AuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let oidc = cfg.oidc.as_ref().unwrap();
        assert_eq!(
            oidc.jwks_url,
            "https://idp.example.com/.well-known/jwks.json"
        );
        assert_eq!(oidc.issuer.as_deref(), Some("https://idp.example.com"));
        assert_eq!(oidc.audience.as_deref(), Some("ebpfsentinel"));
    }

    #[test]
    fn yaml_with_jwt() {
        let yaml = r"
jwt:
  public_key_path: /etc/sentinel/pub.pem
  issuer: sentinel
  audience: api
";
        let cfg: AuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.jwt.public_key_path, "/etc/sentinel/pub.pem");
        assert_eq!(cfg.jwt.issuer.as_deref(), Some("sentinel"));
        assert_eq!(cfg.jwt.audience.as_deref(), Some("api"));
    }

    #[test]
    fn jwt_default_algorithm_is_rs256() {
        let cfg = JwtConfig::default();
        assert_eq!(cfg.algorithm, JwtAlgorithm::RS256);
        assert!(cfg.jwks_url.is_none());
        assert_eq!(cfg.jwks_cache_ttl_seconds, 3600);
        assert!(cfg.jwks_refresh_on_unknown_kid);
    }

    #[test]
    fn jwt_key_source_pem_when_only_path_set() {
        let cfg = JwtConfig {
            public_key_path: "/etc/keys/pub.pem".to_string(),
            ..JwtConfig::default()
        };
        assert_eq!(
            cfg.key_source().unwrap(),
            JwtKeySource::Pem {
                path: "/etc/keys/pub.pem".to_string()
            }
        );
    }

    #[test]
    fn jwt_key_source_jwks_when_only_url_set() {
        let cfg = JwtConfig {
            jwks_url: Some("https://dashboard/.well-known/jwks.json".to_string()),
            ..JwtConfig::default()
        };
        match cfg.key_source().unwrap() {
            JwtKeySource::Jwks {
                ref url,
                cache_ttl_seconds,
                refresh_on_unknown_kid,
            } => {
                assert_eq!(url, "https://dashboard/.well-known/jwks.json");
                assert_eq!(cache_ttl_seconds, 3600);
                assert!(refresh_on_unknown_kid);
            }
            other => panic!("unexpected source: {other:?}"),
        }
    }

    #[test]
    fn jwt_key_source_rejects_both_set() {
        let cfg = JwtConfig {
            public_key_path: "/p".to_string(),
            jwks_url: Some("https://x".to_string()),
            ..JwtConfig::default()
        };
        let err = cfg.key_source().unwrap_err();
        assert!(err.contains("exactly one"));
    }

    #[test]
    fn jwt_key_source_rejects_non_http_jwks() {
        let cfg = JwtConfig {
            jwks_url: Some("ftp://nope".to_string()),
            ..JwtConfig::default()
        };
        let err = cfg.key_source().unwrap_err();
        assert!(err.contains("must be"));
    }

    #[test]
    fn jwt_key_source_none_when_unset() {
        let cfg = JwtConfig::default();
        assert_eq!(cfg.key_source().unwrap(), JwtKeySource::None);
    }

    #[test]
    fn jwt_yaml_with_eddsa_and_jwks() {
        let yaml = r"
jwt:
  algorithm: EdDSA
  jwks_url: https://dashboard.example.com/.well-known/jwks.json
  jwks_cache_ttl_seconds: 600
  jwks_refresh_on_unknown_kid: false
  issuer: dashboard
  audience: agent
";
        let cfg: AuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.jwt.algorithm, JwtAlgorithm::EdDSA);
        assert_eq!(
            cfg.jwt.jwks_url.as_deref(),
            Some("https://dashboard.example.com/.well-known/jwks.json")
        );
        assert_eq!(cfg.jwt.jwks_cache_ttl_seconds, 600);
        assert!(!cfg.jwt.jwks_refresh_on_unknown_kid);
    }

    #[test]
    fn full_config_with_all_sections() {
        let yaml = r#"
enabled: true
jwt:
  public_key_path: /etc/ebpfsentinel/pub.pem
  issuer: myissuer
oidc:
  jwks_url: "https://auth.example.com/jwks"
api_keys:
  - name: ci
    key: sk-ci
    role: operator
    namespaces:
      - staging
metrics_auth_required: true
"#;
        let cfg: AuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.jwt.public_key_path, "/etc/ebpfsentinel/pub.pem");
        assert_eq!(cfg.jwt.issuer.as_deref(), Some("myissuer"));
        assert!(cfg.oidc.is_some());
        assert_eq!(cfg.api_keys.len(), 1);
        assert_eq!(cfg.api_keys[0].role, "operator");
        assert_eq!(cfg.api_keys[0].namespaces, vec!["staging".to_string()]);
        assert!(cfg.metrics_auth_required);
    }
}
