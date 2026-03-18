use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use infrastructure::config::PqMode;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::server::TlsStream;

/// Install the PQ-aware [`CryptoProvider`] as the process-wide default.
///
/// Call once at startup (before any rustls/reqwest client is created) so that
/// outbound TLS connections also use PQ hybrid key exchange.
pub fn install_pq_provider(pq_mode: PqMode) {
    let provider = build_crypto_provider(pq_mode);
    let _ = provider.install_default();
    tracing::info!(?pq_mode, "PQ CryptoProvider installed for outbound TLS");
}

/// Load a rustls [`ServerConfig`] with PQ-hybrid key exchange support.
///
/// Key exchange group preference depends on `pq_mode`:
/// - `Prefer`: `X25519MLKEM768` > `X25519` > `SECP256R1`
/// - `Require`: `X25519MLKEM768` only
/// - `Disable`: `X25519` > `SECP256R1`
pub fn load_rustls_config(
    cert_path: &Path,
    key_path: &Path,
    pq_mode: PqMode,
) -> anyhow::Result<Arc<ServerConfig>> {
    let provider = build_crypto_provider(pq_mode);

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| anyhow::anyhow!("failed to read TLS cert at '{}': {e}", cert_path.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse TLS certificates: {e}"))?;

    if certs.is_empty() {
        anyhow::bail!(
            "TLS cert file contains no certificates: {}",
            cert_path.display()
        );
    }

    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse TLS private key at '{}': {e}",
            key_path.display()
        )
    })?;

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid TLS certificate/key pair: {e}"))?;

    tracing::info!(pq_mode = ?pq_mode, "TLS server configured");

    Ok(Arc::new(config))
}

/// Build a [`CryptoProvider`] with key exchange groups ordered by PQ mode.
fn build_crypto_provider(pq_mode: PqMode) -> tokio_rustls::rustls::crypto::CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();

    provider.kx_groups = match pq_mode {
        PqMode::Prefer => vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
            aws_lc_rs::kx_group::SECP256R1,
        ],
        PqMode::Require => vec![aws_lc_rs::kx_group::X25519MLKEM768],
        PqMode::Disable => vec![aws_lc_rs::kx_group::X25519, aws_lc_rs::kx_group::SECP256R1],
    };

    provider
}

/// Build a [`reqwest::Client`] with PQ-hybrid TLS and sensible defaults.
///
/// Uses `reqwest`'s built-in root certificate handling; the custom
/// [`CryptoProvider`] overrides only key exchange groups.
pub fn build_pq_http_client() -> reqwest::Client {
    // Provider is already installed globally by `install_pq_provider()` at startup.
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("ebpfsentinel-agent/1.0")
        .build()
        .expect("failed to build PQ HTTP client")
}

/// A TCP listener that performs TLS handshakes on accepted connections.
///
/// Implements [`axum::serve::Listener`] so it can be used as a drop-in
/// replacement for [`TcpListener`] in `axum::serve`.
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> Self {
        Self {
            inner: listener,
            acceptor: TlsAcceptor::from(config),
        }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "TCP accept error");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            match self.acceptor.accept(stream).await {
                Ok(tls) => return (tls, addr),
                Err(e) => {
                    tracing::debug!(error = %e, %addr, "TLS handshake failed");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::rustls::NamedGroup;

    #[test]
    fn crypto_provider_prefer_has_pq_first() {
        let provider = build_crypto_provider(PqMode::Prefer);
        assert_eq!(provider.kx_groups.len(), 3);
        assert_eq!(provider.kx_groups[0].name(), NamedGroup::X25519MLKEM768);
        assert_eq!(provider.kx_groups[1].name(), NamedGroup::X25519);
        assert_eq!(provider.kx_groups[2].name(), NamedGroup::secp256r1);
    }

    #[test]
    fn build_pq_http_client_succeeds() {
        // Install a provider first (tests may run in any order)
        install_pq_provider(PqMode::Prefer);
        let client = build_pq_http_client();
        // Just verify the client is created without panic
        drop(client);
    }

    #[test]
    fn crypto_provider_require_only_pq() {
        let provider = build_crypto_provider(PqMode::Require);
        assert_eq!(provider.kx_groups.len(), 1);
        assert_eq!(provider.kx_groups[0].name(), NamedGroup::X25519MLKEM768);
    }

    #[test]
    fn crypto_provider_disable_no_pq() {
        let provider = build_crypto_provider(PqMode::Disable);
        assert_eq!(provider.kx_groups.len(), 2);
        assert!(
            provider
                .kx_groups
                .iter()
                .all(|g| g.name() != NamedGroup::X25519MLKEM768)
        );
    }
}
