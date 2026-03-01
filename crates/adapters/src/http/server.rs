use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio_rustls::rustls::ServerConfig;

use super::router::build_router;
use super::state::AppState;
use super::tls::TlsListener;

/// Run the REST API HTTP server on the given bind address and port.
///
/// When `tls_config` is `Some`, the server terminates TLS (HTTPS).
/// The server shuts down gracefully when `shutdown` resolves, draining
/// in-flight connections before returning.
pub async fn run_http_server(
    state: Arc<AppState>,
    bind_address: &str,
    port: u16,
    swagger_ui: bool,
    tls_config: Option<Arc<ServerConfig>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let router = build_router(state, swagger_ui);
    let listener = tokio::net::TcpListener::bind(format!("{bind_address}:{port}")).await?;

    if let Some(tls) = tls_config {
        let tls_listener = TlsListener::new(listener, tls);
        tracing::info!(%bind_address, port, "HTTPS API server listening");
        axum::serve(tls_listener, router)
            .with_graceful_shutdown(shutdown)
            .await?;
    } else {
        tracing::info!(%bind_address, port, "HTTP API server listening");
        let app = router.into_make_service_with_connect_info::<SocketAddr>();
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await?;
    }

    Ok(())
}
