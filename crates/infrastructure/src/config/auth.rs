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
