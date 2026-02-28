use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::server::TlsStream;

/// Load a rustls [`ServerConfig`] from PEM-encoded certificate chain and private key files.
pub fn load_rustls_config(cert_path: &Path, key_path: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    // Ensure a CryptoProvider is installed (required by rustls 0.23+).
    // Ignore the error if already installed by another dependency.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

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

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid TLS certificate/key pair: {e}"))?;

    Ok(Arc::new(config))
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
