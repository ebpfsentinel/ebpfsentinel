//! Construction of the agent's authentication stack.
//!
//! Both the OSS agent and the enterprise agent serve an HTTP API that has to
//! recognise the same principals, so the provider is built here once rather
//! than at each composition root.

use std::sync::Arc;

use adapters::auth::jwt_provider::JwtAuthProvider;
use adapters::auth::oidc_provider::{self, OidcAuthProvider};
use infrastructure::config::AuthConfig;
use ports::secondary::auth_provider::AuthProvider;
use tracing::{info, warn};

use crate::reload::AuthProviderHandle;

/// A token provider paired with the handle that can hot-reload its keys.
type TokenProvider = (Option<AuthProviderHandle>, Option<Arc<dyn AuthProvider>>);

/// Everything the HTTP layer needs to authenticate a request.
///
/// All three fields are `None` when authentication is disabled. Callers must
/// read that as "no principal can be established", not as "every caller is
/// authenticated": a request without a verified principal carries no identity
/// and no role.
pub struct AuthStack {
    /// Handle for hot-reloading keys, `None` when auth is disabled.
    pub handle: Option<AuthProviderHandle>,
    /// The provider used to validate credentials, `None` when auth is disabled.
    pub provider: Option<Arc<dyn AuthProvider>>,
    /// Handle for revoking issued tokens, `None` when auth is disabled.
    pub revocation: Option<adapters::auth::revocation::RevocationHandle>,
}

impl AuthStack {
    /// The stack of an agent running with authentication turned off.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            handle: None,
            provider: None,
            revocation: None,
        }
    }
}

/// Build the authentication stack described by `auth`.
///
/// Returns [`AuthStack::disabled`] when `auth.enabled` is false.
///
/// # Errors
///
/// Returns an error when a JWKS endpoint is unreachable, a PEM key is missing
/// or malformed, or authentication is enabled with no method configured.
pub async fn build_auth_stack(auth: &AuthConfig) -> anyhow::Result<AuthStack> {
    if !auth.enabled {
        return Ok(AuthStack::disabled());
    }

    let (token_handle, token_provider) = build_token_provider(auth).await?;
    let api_key_provider = build_api_key_provider(auth);

    let final_provider: Arc<dyn AuthProvider> = match (token_provider, api_key_provider) {
        (Some(tp), Some(akp)) => {
            info!("composite auth: token-based + API keys");
            Arc::new(adapters::auth::composite_provider::CompositeAuthProvider::new(vec![tp, akp]))
        }
        (Some(tp), None) => tp,
        (None, Some(akp)) => akp,
        (None, None) => {
            // Should not happen - config validation catches this
            return Err(anyhow::anyhow!(
                "auth is enabled but no auth method configured"
            ));
        }
    };

    // Wrap the final provider with token revocation support.
    let revocable = adapters::auth::revocation::RevocableAuthProvider::new(final_provider);
    let revocation_handle = revocable.revocation_handle();
    let final_provider = Arc::new(revocable) as Arc<dyn AuthProvider>;
    info!("token revocation enabled");

    let handle = token_handle.unwrap_or(AuthProviderHandle::ApiKeyOnly);
    Ok(AuthStack {
        handle: Some(handle),
        provider: Some(final_provider),
        revocation: Some(revocation_handle),
    })
}

/// Build the token half of the stack: OIDC, or JWT from a static PEM key or a
/// JWKS endpoint. Yields `(None, None)` when no token source is configured.
async fn build_token_provider(auth: &AuthConfig) -> anyhow::Result<TokenProvider> {
    if let Some(ref oidc) = auth.oidc {
        let jwk_set = oidc_provider::fetch_jwks(&oidc.jwks_url)
            .await
            .map_err(|e| anyhow::anyhow!("failed to fetch JWKS: {e}"))?;
        let provider =
            OidcAuthProvider::new(jwk_set, oidc.issuer.as_deref(), oidc.audience.as_deref())
                .map_err(|e| anyhow::anyhow!("failed to initialize OIDC auth provider: {e}"))?;
        info!(jwks_url = %oidc.jwks_url, "OIDC authentication enabled");
        let arc = Arc::new(provider);
        return Ok((
            Some(AuthProviderHandle::Oidc(Arc::clone(&arc))),
            Some(Arc::clone(&arc) as Arc<dyn AuthProvider>),
        ));
    }

    match auth
        .jwt
        .key_source()
        .map_err(|e| anyhow::anyhow!("auth.jwt config error: {e}"))?
    {
        infrastructure::config::JwtKeySource::Pem { path } => {
            let pem_bytes = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("failed to read JWT public key at '{path}': {e}"))?;
            let provider = match auth.jwt.algorithm {
                infrastructure::config::JwtAlgorithm::RS256 => JwtAuthProvider::new(
                    &pem_bytes,
                    auth.jwt.issuer.as_deref(),
                    auth.jwt.audience.as_deref(),
                ),
                infrastructure::config::JwtAlgorithm::EdDSA => JwtAuthProvider::new_eddsa(
                    &pem_bytes,
                    auth.jwt.issuer.as_deref(),
                    auth.jwt.audience.as_deref(),
                ),
            }
            .map_err(|e| anyhow::anyhow!("failed to initialize JWT auth provider: {e}"))?;
            info!(
                algorithm = ?auth.jwt.algorithm,
                "JWT authentication enabled (static PEM)"
            );
            let arc = Arc::new(provider);
            Ok((
                Some(AuthProviderHandle::Jwt(Arc::clone(&arc))),
                Some(Arc::clone(&arc) as Arc<dyn AuthProvider>),
            ))
        }
        infrastructure::config::JwtKeySource::Jwks {
            ref url,
            refresh_on_unknown_kid,
            ..
        } => {
            let jwk_set = oidc_provider::fetch_jwks(url)
                .await
                .map_err(|e| anyhow::anyhow!("failed to fetch JWT JWKS: {e}"))?;
            let provider = match auth.jwt.algorithm {
                infrastructure::config::JwtAlgorithm::RS256 => OidcAuthProvider::new(
                    jwk_set,
                    auth.jwt.issuer.as_deref(),
                    auth.jwt.audience.as_deref(),
                ),
                infrastructure::config::JwtAlgorithm::EdDSA => OidcAuthProvider::new_for_eddsa(
                    jwk_set,
                    auth.jwt.issuer.as_deref(),
                    auth.jwt.audience.as_deref(),
                ),
            }
            .map_err(|e| anyhow::anyhow!("failed to initialize JWT JWKS auth provider: {e}"))?;
            let refresher: Arc<dyn oidc_provider::JwksRefresher> =
                Arc::new(oidc_provider::HttpJwksRefresher::new(url.clone()));
            let provider = provider.with_refresher(refresher, refresh_on_unknown_kid);
            info!(
                algorithm = ?auth.jwt.algorithm,
                jwks_url = %url,
                refresh_on_unknown_kid,
                "JWT authentication enabled (JWKS)"
            );
            let arc = Arc::new(provider);
            Ok((
                Some(AuthProviderHandle::Oidc(Arc::clone(&arc))),
                Some(Arc::clone(&arc) as Arc<dyn AuthProvider>),
            ))
        }
        infrastructure::config::JwtKeySource::None => Ok((None, None)),
    }
}

/// Build the static API key half of the stack, `None` when no keys are listed.
fn build_api_key_provider(auth: &AuthConfig) -> Option<Arc<dyn AuthProvider>> {
    if auth.api_keys.is_empty() {
        return None;
    }
    let entries: Vec<_> = auth
        .api_keys
        .iter()
        .map(|k| {
            (
                k.name.clone(),
                k.key.clone(),
                k.role.clone(),
                k.namespaces.clone(),
            )
        })
        .collect();
    // Use configured salt or read 32 random bytes from /dev/urandom.
    let salt = auth.api_key_salt.as_deref().map_or_else(
        || {
            let mut buf = vec![0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
                .expect("/dev/urandom should be readable");
            warn!(
                "no api_key_salt configured - using ephemeral salt, API keys will invalidate on restart"
            );
            buf
        },
        |s| s.as_bytes().to_vec(),
    );
    info!(key_count = entries.len(), "API key authentication enabled");
    Some(
        Arc::new(adapters::auth::api_key_provider::ApiKeyAuthProvider::new(
            entries, &salt,
        )) as Arc<dyn AuthProvider>,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_disabled_config_yields_no_provider() {
        let auth = AuthConfig::default();
        assert!(!auth.enabled, "auth must be off by default");
        let stack = build_auth_stack(&auth).await.unwrap();
        assert!(stack.provider.is_none());
        assert!(stack.handle.is_none());
        assert!(stack.revocation.is_none());
    }

    #[tokio::test]
    async fn api_keys_alone_are_enough_to_authenticate() {
        let mut auth = AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        };
        auth.api_keys.push(infrastructure::config::ApiKeyConfig {
            name: "admin".into(),
            key: "secret-key".into(),
            role: "admin".into(),
            namespaces: vec![],
        });
        auth.api_key_salt = Some("fixed-salt".into());

        let stack = build_auth_stack(&auth).await.unwrap();
        let provider = stack.provider.expect("api keys must produce a provider");
        let claims = provider.validate_token("secret-key").await.unwrap();
        assert_eq!(claims.role.as_deref(), Some("admin"));
        assert!(provider.validate_token("wrong-key").await.is_err());
    }

    #[tokio::test]
    async fn enabling_auth_without_a_method_is_an_error() {
        let auth = AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        };
        assert!(build_auth_stack(&auth).await.is_err());
    }
}
