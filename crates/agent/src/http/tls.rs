use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use adapters::tls_accept::{HandshakeLimits, Handshaken, spawn_tls_acceptor};
use infrastructure::config::PqMode;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::server::TlsStream;

pub use adapters::tls::{build_crypto_provider, install_pq_provider};

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
    let provider = build_crypto_provider(adapters::tls::LINK_API, pq_mode);

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

/// A TCP listener that yields connections whose TLS handshake completed.
///
/// Handshakes run off the accept path, each under
/// [`HANDSHAKE_TIMEOUT`](adapters::tls_accept::HANDSHAKE_TIMEOUT) and a cap on
/// how many may be pending at once, so a client that connects and never sends
/// a `ClientHello` does not stop the REST API, the health probes or the
/// metrics scrape from answering anyone else.
///
/// Implements [`axum::serve::Listener`] so it can be used as a drop-in
/// replacement for [`TcpListener`] in `axum::serve`.
pub struct TlsListener {
    local: SocketAddr,
    ready: mpsc::Receiver<Handshaken>,
}

impl TlsListener {
    /// Start accepting on `listener`; must be called inside a Tokio runtime.
    ///
    /// # Errors
    ///
    /// The listener has no local address.
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> io::Result<Self> {
        let local = listener.local_addr()?;
        let ready = spawn_tls_acceptor(
            listener,
            TlsAcceptor::from(config),
            HandshakeLimits::default(),
            "api",
            |_| {},
        );
        Ok(Self { local, ready })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            // The accept loop only stops once this receiver is dropped, so
            // this is never reached while the listener is alive.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};

    use super::*;

    const HEALTHZ: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    /// A TCP client that never sends a `ClientHello` must not stop a second
    /// client from completing a request: the accept loop used to await each
    /// handshake inline, so the first one froze the whole API.
    #[tokio::test]
    async fn a_client_that_never_sends_a_client_hello_does_not_freeze_the_api() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate");
        let dir = tempfile::tempdir().expect("a temporary directory");
        let cert_path = dir.path().join("api.pem");
        let key_path = dir.path().join("api.key");
        std::fs::write(&cert_path, generated.cert.pem()).expect("the certificate is written");
        std::fs::write(&key_path, generated.signing_key.serialize_pem())
            .expect("the key is written");
        let config = load_rustls_config(&cert_path, &key_path, PqMode::Prefer, false)
            .expect("the listener configuration loads");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let tls = TlsListener::new(listener, config).expect("the listener starts");
        let addr = axum::serve::Listener::local_addr(&tls).expect("a bound address");
        let router = Router::new().route("/healthz", get(|| async { "ok" }));
        tokio::spawn(async move {
            let _ = axum::serve(
                tls,
                router.into_make_service_with_connect_info::<TlsConnectInfo>(),
            )
            .await;
        });

        let _stalled = TcpStream::connect(addr)
            .await
            .expect("the stalled client connects");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut roots = RootCertStore::empty();
        roots
            .add(generated.cert.der().clone())
            .expect("the test certificate is an authority");
        let client = ClientConfig::builder_with_provider(Arc::new(build_crypto_provider(
            adapters::tls::LINK_OUTBOUND,
            PqMode::Prefer,
        )))
        .with_safe_default_protocol_versions()
        .expect("TLS 1.3 is available")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client));
        let name = ServerName::try_from("localhost").expect("a valid server name");

        let response = tokio::time::timeout(Duration::from_secs(5), async move {
            let tcp = TcpStream::connect(addr).await?;
            let mut stream = connector.connect(name, tcp).await?;
            stream.write_all(HEALTHZ).await?;
            let mut response = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => response.extend_from_slice(&buf[..n]),
                }
            }
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&response).into_owned())
        })
        .await
        .expect("the second client is answered while the first stalls")
        .expect("the second request completes");

        assert!(
            response.starts_with("HTTP/1.1 200"),
            "unexpected response: {response}"
        );
        assert!(response.ends_with("ok"), "unexpected body: {response}");
    }
}
