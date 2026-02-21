use tokio::signal;
use tokio_util::sync::CancellationToken;

/// Create a `CancellationToken` and spawn a task that cancels it on
/// SIGINT or SIGTERM.  Returns the token so callers can pass clones
/// to every spawned task.
pub fn create_shutdown_token() -> CancellationToken {
    let token = CancellationToken::new();
    let token_clone = token.clone();

    tokio::spawn(async move {
        shutdown_signal().await;
        token_clone.cancel();
    });

    token
}

/// Wait for a shutdown signal (SIGINT or SIGTERM).
///
/// Returns when the first signal is received.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
