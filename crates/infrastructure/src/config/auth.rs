//! Authentication domain configuration structs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

    /// Whether `/metrics` requires authentication (default: false).
    #[serde(default)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Path to the RSA public key in PEM format.
    #[serde(default)]
    pub public_key_path: String,

    /// Expected token issuer (`iss` claim). Validated when set.
    #[serde(default)]
    pub issuer: Option<String>,

    /// Expected token audience (`aud` claim). Validated when set.
    #[serde(default)]
    pub audience: Option<String>,
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
        assert!(!cfg.metrics_auth_required);
    }

    #[test]
    fn yaml_with_api_keys() {
        let yaml = r#"
enabled: true
api_keys:
  - name: admin-key
    key: sk-abc123
    role: admin
  - name: readonly
    key: sk-xyz789
"#;
        let cfg: AuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.api_keys.len(), 2);
        assert_eq!(cfg.api_keys[0].name, "admin-key");
        assert_eq!(cfg.api_keys[0].key, "sk-abc123");
        assert_eq!(cfg.api_keys[0].role, "admin");
    }

    #[test]
    fn default_api_key_role_is_viewer() {
        let yaml = r#"
api_keys:
  - name: test
    key: sk-test
"#;
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
        let yaml = r#"
jwt:
  public_key_path: /etc/sentinel/pub.pem
  issuer: sentinel
  audience: api
"#;
        let cfg: AuthConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.jwt.public_key_path, "/etc/sentinel/pub.pem");
        assert_eq!(cfg.jwt.issuer.as_deref(), Some("sentinel"));
        assert_eq!(cfg.jwt.audience.as_deref(), Some("api"));
    }

    #[test]
    fn full_config_with_all_sections() {
        let yaml = r#"
enabled: true
jwt:
  public_key_path: /keys/pub.pem
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
        assert_eq!(cfg.jwt.public_key_path, "/keys/pub.pem");
        assert_eq!(cfg.jwt.issuer.as_deref(), Some("myissuer"));
        assert!(cfg.oidc.is_some());
        assert_eq!(cfg.api_keys.len(), 1);
        assert_eq!(cfg.api_keys[0].role, "operator");
        assert_eq!(cfg.api_keys[0].namespaces, vec!["staging".to_string()]);
        assert!(cfg.metrics_auth_required);
    }
}
