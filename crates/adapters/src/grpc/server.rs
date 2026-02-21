use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use domain::alert::entity::Alert;
use ports::secondary::auth_provider::AuthProvider;
use tokio::sync::broadcast;
use tonic::transport::Server;

use super::alert_service::AlertStreamServiceImpl;
use super::interceptor::auth::make_jwt_interceptor;
use super::proto::alert_stream_service_server::AlertStreamServiceServer;

/// TLS material for the gRPC server (PEM-encoded cert chain + private key).
pub struct GrpcTlsConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Run the gRPC server on the given port with health checks and reflection.
///
/// The server exposes:
/// - `AlertStreamService` for real-time alert streaming
/// - `grpc.health.v1.Health` for K8s liveness/readiness probes
/// - gRPC reflection for service discovery and debugging (NFR32)
///
/// When `tls_config` is `Some`, the server terminates TLS (NFR9).
/// When `auth_provider` is `Some`, the `AlertStreamService` is wrapped with
/// a JWT interceptor. Health and reflection services are always unauthenticated.
pub async fn run_grpc_server(
    alert_tx: broadcast::Sender<Alert>,
    bind_address: &str,
    port: u16,
    auth_provider: Option<Arc<dyn AuthProvider>>,
    tls_config: Option<GrpcTlsConfig>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{bind_address}:{port}").parse()?;

    // Health service — mark AlertStreamService as serving
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<AlertStreamServiceServer<AlertStreamServiceImpl>>()
        .await;

    // Reflection service for service discovery (NFR32)
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(super::proto::FILE_DESCRIPTOR_SET)
        .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
        .build_v1()?;

    // Alert streaming service
    let alert_service = AlertStreamServiceImpl::new(alert_tx);

    let mut builder = Server::builder();

    // Configure TLS when enabled
    if let Some(tls) = tls_config {
        let identity = tonic::transport::Identity::from_pem(tls.cert_pem, tls.key_pem);
        let tls_config = tonic::transport::ServerTlsConfig::new().identity(identity);
        builder = builder
            .tls_config(tls_config)
            .map_err(|e| anyhow::anyhow!("gRPC TLS configuration error: {e}"))?;
        tracing::info!(port, "gRPC server listening (TLS)");
    } else {
        tracing::info!(port, "gRPC server listening");
    }

    let mut router = builder
        .add_service(health_service)
        .add_service(reflection_service);

    // Wrap AlertStreamService with auth interceptor when configured
    router = if let Some(provider) = auth_provider {
        let interceptor = make_jwt_interceptor(provider);
        router.add_service(AlertStreamServiceServer::with_interceptor(
            alert_service,
            interceptor,
        ))
    } else {
        router.add_service(AlertStreamServiceServer::new(alert_service))
    };

    router.serve_with_shutdown(addr, shutdown).await?;

    Ok(())
}
