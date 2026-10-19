use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use infrastructure::config::PqMode;

use domain::alert::entity::Alert;
use ports::secondary::auth_provider::AuthProvider;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tower::ServiceBuilder;

use super::alert_service::AlertStreamServiceImpl;
use super::interceptor::auth::AuthLayer;
use super::proto::alert_stream_service_server::AlertStreamServiceServer;

/// TLS material and policy for the gRPC server.
pub struct GrpcTlsConfig {
    /// PEM-encoded certificate chain.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key.
    pub key_pem: Vec<u8>,
    /// Which key-exchange groups the listener offers.
    pub pq_mode: PqMode,
    /// Whether TLS 1.2 is accepted alongside TLS 1.3.
    pub allow_tls12: bool,
}

/// Number of handshaken connections held between the accept loop and tonic.
const ACCEPT_BACKLOG: usize = 128;
/// Keepalive on an accepted gRPC connection. tonic sets this itself when it
/// owns the listener, and ignores its own setting when it is served a stream,
/// so it is applied here.
const GRPC_KEEPALIVE: Duration = Duration::from_secs(60);
/// How long the accept loop waits after an accept error, so a listener in a
/// bad state does not spin a core.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Build the rustls [`ServerConfig`] the gRPC listener terminates with.
///
/// The provider comes from [`crate::tls`], so this listener offers the same
/// key-exchange groups as the REST one rather than whatever provider happened
/// to be installed as the process default - which, for an agent that also
/// dials classical servers, is deliberately the permissive one.
fn grpc_server_config(tls: &GrpcTlsConfig) -> anyhow::Result<Arc<ServerConfig>> {
    let provider = crate::tls::build_crypto_provider(tls.pq_mode);

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&tls.cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("failed to parse gRPC TLS certificates: {e}"))?;
    if certs.is_empty() {
        anyhow::bail!("gRPC TLS cert contains no certificates");
    }

    let key = PrivateKeyDer::from_pem_slice(&tls.key_pem)
        .map_err(|e| anyhow::anyhow!("failed to parse gRPC TLS private key: {e}"))?;

    let versions: Vec<&'static tokio_rustls::rustls::SupportedProtocolVersion> = if tls.allow_tls12
    {
        vec![
            &tokio_rustls::rustls::version::TLS13,
            &tokio_rustls::rustls::version::TLS12,
        ]
    } else {
        vec![&tokio_rustls::rustls::version::TLS13]
    };

    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&versions)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("invalid gRPC TLS certificate/key pair: {e}"))?;

    // gRPC is HTTP/2 and nothing else, and a client that offers ALPN gets no
    // answer at all unless the listener names it.
    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(config))
}

/// Accepts connections and completes each TLS handshake off the accept loop,
/// handing tonic the streams that finished one. A peer that stalls mid
/// handshake therefore holds up nothing but itself, and a handshake that
/// fails is dropped rather than reported to the server, which has no
/// connection to answer on.
fn spawn_tls_acceptor(
    listener: TcpListener,
    acceptor: TlsAcceptor,
) -> ReceiverStream<Result<tokio_rustls::server::TlsStream<TcpStream>, std::io::Error>> {
    let (tx, rx) = tokio::sync::mpsc::channel(ACCEPT_BACKLOG);

    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "gRPC TCP accept error");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };
            apply_keepalive(&stream, GRPC_KEEPALIVE);
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls) => {
                        let _ = tx.send(Ok(tls)).await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, %peer, "gRPC TLS handshake failed");
                    }
                }
            });
        }
    });

    ReceiverStream::new(rx)
}

/// Keep the TCP keepalive the plain listener gets, which tonic applies itself
/// only when it owns the socket.
fn apply_keepalive(stream: &TcpStream, keepalive: Duration) {
    let sock = socket2::SockRef::from(stream);
    let params = socket2::TcpKeepalive::new().with_time(keepalive);
    if let Err(e) = sock.set_tcp_keepalive(&params) {
        tracing::debug!(error = %e, "failed to set TCP keepalive on gRPC connection");
    }
}

/// Run the gRPC server on the given port with health checks and optional reflection.
///
/// The server exposes:
/// - `AlertStreamService` for real-time alert streaming
/// - `grpc.health.v1.Health` for K8s liveness/readiness probes
/// - gRPC reflection for service discovery and debugging (NFR32) - only when
///   `enable_reflection` is `true`. Disabled by default in production to prevent
///   unauthenticated API schema enumeration.
///
/// When `tls_config` is `Some`, the server terminates TLS (NFR9).
/// When `auth_provider` is `Some`, the `AlertStreamService` is wrapped with
/// a JWT interceptor. Health service is always unauthenticated.
pub async fn run_grpc_server(
    alert_tx: broadcast::Sender<Alert>,
    bind_address: &str,
    port: u16,
    auth_provider: Option<Arc<dyn AuthProvider>>,
    tls_config: Option<GrpcTlsConfig>,
    enable_reflection: bool,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{bind_address}:{port}").parse()?;

    // Health service - mark AlertStreamService as serving
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<AlertStreamServiceServer<AlertStreamServiceImpl>>()
        .await;

    // Alert streaming service
    let alert_service = AlertStreamServiceImpl::new(alert_tx);

    let mut builder = Server::builder()
        .timeout(Duration::from_secs(30))
        .tcp_keepalive(Some(Duration::from_mins(1)))
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .concurrency_limit_per_connection(64);

    // TLS is terminated here rather than by tonic's own `ServerTlsConfig`,
    // which builds its `ServerConfig` from the process-wide default provider:
    // that provider is the one the agent's outbound clients need, so a
    // listener asked to require the hybrid group would quietly have accepted a
    // classical one.
    let server_config = match &tls_config {
        Some(tls) => Some(grpc_server_config(tls)?),
        None => None,
    };

    let mut router = builder.add_service(health_service);

    // Reflection service for service discovery (NFR32) - only when explicitly enabled
    if enable_reflection {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(super::proto::FILE_DESCRIPTOR_SET)
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .build_v1()?;
        router = router.add_service(reflection_service);
        tracing::info!("gRPC reflection enabled");
    }

    // Wrap AlertStreamService with the async auth layer when configured.
    // The layer validates tokens inside the async call (no worker-thread
    // blocking), unlike a sync tonic interceptor.
    router = if let Some(provider) = auth_provider {
        let svc = ServiceBuilder::new()
            .layer(AuthLayer::new(provider))
            .service(AlertStreamServiceServer::new(alert_service));
        router.add_service(svc)
    } else {
        router.add_service(AlertStreamServiceServer::new(alert_service))
    };

    if let Some(config) = server_config {
        let listener = TcpListener::bind(addr).await?;
        let incoming = spawn_tls_acceptor(listener, TlsAcceptor::from(config));
        tracing::info!(port, "gRPC server listening (TLS)");
        router
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await?;
    } else {
        tracing::info!(port, "gRPC server listening");
        router.serve_with_shutdown(addr, shutdown).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls(cert_pem: &str, key_pem: &str, pq_mode: PqMode) -> GrpcTlsConfig {
        GrpcTlsConfig {
            cert_pem: cert_pem.as_bytes().to_vec(),
            key_pem: key_pem.as_bytes().to_vec(),
            pq_mode,
            allow_tls12: false,
        }
    }

    #[test]
    fn a_pem_holding_no_certificate_is_refused_by_name() {
        let error = grpc_server_config(&tls("", "", PqMode::Prefer))
            .expect_err("an empty chain cannot serve TLS");
        assert!(
            error.to_string().contains("no certificates"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_chain_without_a_key_is_refused_before_the_listener_binds() {
        let chain = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let error = grpc_server_config(&tls(chain, "", PqMode::Require))
            .expect_err("a missing key cannot serve TLS");
        assert!(
            error.to_string().contains("private key"),
            "unexpected error: {error}"
        );
    }
}
