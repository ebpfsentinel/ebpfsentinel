use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use infrastructure::config::PqMode;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::server::TlsStream;

pub use adapters::tls::{build_crypto_provider, install_pq_provider, outbound_mode};

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
    allow_tls12: bool,
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

    let versions: Vec<&'static tokio_rustls::rustls::SupportedProtocolVersion> = if allow_tls12 {
        tracing::warn!("TLS 1.2 enabled - consider upgrading clients to TLS 1.3");
        vec![
            &tokio_rustls::rustls::version::TLS13,
            &tokio_rustls::rustls::version::TLS12,
        ]
    } else {
        vec![&tokio_rustls::rustls::version::TLS13]
    };

    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid TLS certificate/key pair: {e}"))?;

    tracing::info!(pq_mode = ?pq_mode, "TLS server configured");

    Ok(Arc::new(config))
}

/// Newtype around [`SocketAddr`] that lets us implement
/// [`Connected`](axum::extract::connect_info::Connected) for [`TlsListener`]
/// without hitting the orphan rule.
///
/// A middleware in `server.rs` converts `ConnectInfo<TlsConnectInfo>` into
/// `ConnectInfo<SocketAddr>` before request processing so that
/// `tower_governor::PeerIpKeyExtractor` (which looks for
/// `ConnectInfo<SocketAddr>`) keeps working.
#[derive(Debug, Clone, Copy)]
pub struct TlsConnectInfo {
    pub addr: SocketAddr,
    /// Negotiated TLS 1.3 key-exchange named group for this connection,
    /// captured right after the handshake completes. `None` if the peer
    /// negotiated no key-exchange group (should not happen for TLS 1.3).
    pub kx_group: Option<tokio_rustls::rustls::NamedGroup>,
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for TlsConnectInfo
{
    fn connect_info(target: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        let addr = *target.remote_addr();
        // The handshake is already complete by the time the stream is yielded
        // from `TlsListener::accept`, so the negotiated group is observable.
        let kx_group = target
            .io()
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .map(tokio_rustls::rustls::crypto::SupportedKxGroup::name);
        Self { addr, kx_group }
    }
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
