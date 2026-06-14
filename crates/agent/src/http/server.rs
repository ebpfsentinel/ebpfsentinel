use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use infrastructure::config::ApiRateLimitConfig;
use tokio_rustls::rustls::ServerConfig;

use axum::Router;

use super::router::{build_metrics_router, build_router};
use super::state::AppState;
use super::tls::{TlsConnectInfo, TlsListener};

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
    rate_limit: ApiRateLimitConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let router = build_router(state, swagger_ui, tls_config.is_some(), rate_limit);
    serve(router, bind_address, port, tls_config, "API", shutdown).await
}

/// Run the dedicated metrics server on `agent.metrics_port`.
///
/// Serves only `/metrics` so the metrics port can be exposed to a scraper while
/// the control-API port is firewalled. TLS mirrors the API server when enabled.
pub async fn run_metrics_server(
    state: Arc<AppState>,
    bind_address: &str,
    port: u16,
    tls_config: Option<Arc<ServerConfig>>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let router = build_metrics_router(state, tls_config.is_some());
    serve(router, bind_address, port, tls_config, "metrics", shutdown).await
}

/// Bind a `TcpListener` and serve `router`, terminating TLS when `tls_config`
/// is `Some`. `label` distinguishes the server in the startup log line.
async fn serve(
    router: Router,
    bind_address: &str,
    port: u16,
    tls_config: Option<Arc<ServerConfig>>,
    label: &str,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(format!("{bind_address}:{port}")).await?;

    if let Some(tls) = tls_config {
        // Axum only implements `Connected<IncomingStream<TcpListener>>` for
        // `SocketAddr`. The orphan rule prevents us from implementing it for
        // our custom `TlsListener`. We use `TlsConnectInfo` (newtype) for the
        // `Connected` impl and a middleware to convert it back to
        // `ConnectInfo<SocketAddr>` so `tower_governor::PeerIpKeyExtractor`
        // can extract the client IP.
        let tls_listener = TlsListener::new(listener, tls);
        let router = router.layer(axum::middleware::from_fn(tls_connect_info_to_socket_addr));
        tracing::info!(%bind_address, port, server = label, "HTTPS server listening");
        axum::serve(
            tls_listener,
            router.into_make_service_with_connect_info::<TlsConnectInfo>(),
        )
        .with_graceful_shutdown(shutdown)
        .await?;
    } else {
        tracing::info!(%bind_address, port, server = label, "HTTP server listening");
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await?;
    }

    Ok(())
}

/// Converts `ConnectInfo<TlsConnectInfo>` into `ConnectInfo<SocketAddr>`.
///
/// `tower_governor::PeerIpKeyExtractor` specifically looks for
/// `ConnectInfo<SocketAddr>` in request extensions. Without this conversion,
/// rate-limited endpoints return 500 when served over TLS.
async fn tls_connect_info_to_socket_addr(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(tls_info) = req
        .extensions()
        .get::<ConnectInfo<TlsConnectInfo>>()
        .copied()
    {
        req.extensions_mut().insert(ConnectInfo(tls_info.0.addr));
    }
    next.run(req).await
}
