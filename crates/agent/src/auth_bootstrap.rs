//! Construction of the agent's authentication stack.
//!
//! Both the OSS agent and the enterprise agent serve an HTTP API that has to
//! recognise the same principals, so the provider is built here once rather
//! than at each composition root.

use std::sync::Arc;

use adapters::auth::bootstrap_key::{BOOTSTRAP_KEY_NAME, BootstrapKeyFile, KeyOrigin};
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
/// When authentication is on and the configuration names no method, the key
/// the agent drew for itself is the method. It is read here rather than merged
/// into the configuration the rest of the process holds, so the running config
/// an operator can read back carries no key at all.
///
/// # Errors
///
/// Returns an error when a JWKS endpoint is unreachable, a PEM key is missing
/// or malformed, the generated key cannot be read or written, or
/// authentication is enabled with no method configured and none generated.
pub async fn build_auth_stack(auth: &AuthConfig) -> anyhow::Result<AuthStack> {
    if !auth.enabled {
        return Ok(AuthStack::disabled());
    }

    let (token_handle, token_provider) = build_token_provider(auth).await?;
    let generated = generated_key(auth)?;
    let api_key_provider = build_api_key_provider(auth, generated.as_deref());

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

/// Read, or draw once, the key the agent keeps for itself.
///
/// Yields `None` when another method is configured or when the operator
/// emptied `auth.bootstrap_key_path` to refuse the generated key. The key is
/// printed exactly once, on the start that drew it: every later start says
/// only where it lives, because a credential repeated in a log is a
/// credential in every log shipper that reads it.
fn generated_key(auth: &AuthConfig) -> anyhow::Result<Option<String>> {
    if auth.bootstrap_key_path.is_empty() {
        return Ok(None);
    }
    let configured_method = auth.oidc.is_some()
        || !auth.api_keys.is_empty()
        || auth
            .jwt
            .key_source()
            .is_ok_and(|s| s != infrastructure::config::JwtKeySource::None);
    if configured_method {
        return Ok(None);
    }

    let file = BootstrapKeyFile::new(&auth.bootstrap_key_path);
    let drawn = file.load_or_create().map_err(|e| {
        anyhow::anyhow!(
            "could not read or create the API key at '{}': {e}",
            auth.bootstrap_key_path
        )
    })?;

    match drawn.origin {
        KeyOrigin::Generated => info!(
            path = %file.path().display(),
            api_key = %drawn.key,
            "no authentication method was configured, so an API key was generated: \
             send it as 'Authorization: Bearer <key>'. It is shown this once and kept \
             at the path above"
        ),
        KeyOrigin::Loaded => info!(
            path = %file.path().display(),
            "authenticating with the API key kept at this path"
        ),
    }

    Ok(Some(drawn.key))
}

/// Build the static API key half of the stack, `None` when no keys are listed
/// and none was generated.
fn build_api_key_provider(
    auth: &AuthConfig,
    generated: Option<&str>,
) -> Option<Arc<dyn AuthProvider>> {
    if auth.api_keys.is_empty() && generated.is_none() {
        return None;
    }
    let mut entries: Vec<_> = auth
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
    if let Some(key) = generated {
        entries.push((
            BOOTSTRAP_KEY_NAME.to_owned(),
            key.to_owned(),
            "admin".to_owned(),
            Vec::new(),
        ));
    }
    // Use configured salt or read 32 random bytes from /dev/urandom.
    let salt = auth.api_key_salt.as_deref().map_or_else(
        || {
            let mut buf = vec![0u8; 32];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf))
                .expect("/dev/urandom should be readable");
            if !auth.api_keys.is_empty() {
                warn!(
                    "no api_key_salt configured - using ephemeral salt, API keys will invalidate on restart"
                );
            }
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

    /// Points a config at a key file of this test's own, so a test never
    /// reads or writes the path a running agent uses.
    fn with_key_file(name: &str) -> (AuthConfig, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ebpfsentinel-auth-bootstrap-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        let auth = AuthConfig {
            bootstrap_key_path: dir.join("api-key").to_string_lossy().into_owned(),
            ..AuthConfig::default()
        };
        (auth, dir)
    }

    #[tokio::test]
    async fn a_config_turning_it_off_yields_no_provider() {
        let auth = AuthConfig {
            enabled: false,
            ..AuthConfig::default()
        };
        let stack = build_auth_stack(&auth).await.unwrap();
        assert!(stack.provider.is_none());
        assert!(stack.handle.is_none());
        assert!(stack.revocation.is_none());
    }

    #[tokio::test]
    async fn authentication_is_on_unless_somebody_turned_it_off() {
        // The API this guards reloads configuration, writes firewall rules and
        // arms the IPS. An agent answering every local caller is the posture
        // this default exists to refuse, so the pin is on the value itself.
        assert!(AuthConfig::default().enabled);
    }

    #[tokio::test]
    async fn a_config_naming_no_method_authenticates_off_a_generated_key() {
        let (auth, dir) = with_key_file("generated");

        let stack = build_auth_stack(&auth).await.unwrap();
        let provider = stack.provider.expect("a generated key is a method");
        let key = std::fs::read_to_string(&auth.bootstrap_key_path).expect("kept");

        let claims = provider.validate_token(&key).await.unwrap();
        assert_eq!(claims.role.as_deref(), Some("admin"));
        assert!(provider.validate_token("sk-nonsense").await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_restart_keeps_the_key_the_first_start_drew() {
        let (auth, dir) = with_key_file("restart");

        build_auth_stack(&auth).await.unwrap();
        let first = std::fs::read_to_string(&auth.bootstrap_key_path).expect("kept");
        let stack = build_auth_stack(&auth).await.unwrap();
        let second = std::fs::read_to_string(&auth.bootstrap_key_path).expect("kept");

        assert_eq!(first, second, "a restart must not lock an operator out");
        assert!(
            stack
                .provider
                .expect("provider")
                .validate_token(&first)
                .await
                .is_ok()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_configured_method_draws_no_key_of_its_own() {
        let (mut auth, dir) = with_key_file("configured");
        auth.api_keys.push(infrastructure::config::ApiKeyConfig {
            name: "admin".into(),
            key: "sk-configured".into(),
            role: "admin".into(),
            namespaces: vec![],
        });

        build_auth_stack(&auth).await.unwrap();

        assert!(
            !std::path::Path::new(&auth.bootstrap_key_path).exists(),
            "an operator who brought a key is not given a second one"
        );

        let _ = std::fs::remove_dir_all(&dir);
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
    async fn refusing_the_generated_key_without_naming_a_method_is_an_error() {
        let auth = AuthConfig {
            enabled: true,
            bootstrap_key_path: String::new(),
            ..AuthConfig::default()
        };
        assert!(build_auth_stack(&auth).await.is_err());
    }
}
