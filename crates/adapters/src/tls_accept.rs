//! Terminating TLS on a listener without letting one client hold up the next.
//!
//! Every handshake runs in a task of its own, bounded by a deadline and by a
//! cap on how many may be pending at once, and only the connections whose
//! handshake completed reach the server. A peer that opens a TCP connection
//! and never sends a `ClientHello` therefore costs one slot for at most the
//! deadline, and never stops the accept loop: the REST API, the health probes,
//! the metrics scrape and the gRPC stream keep answering everyone else.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// How long a client may take to complete its handshake before the
/// connection is dropped.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How many handshakes may be in progress at once. Past it, new connections
/// wait in the kernel's accept queue until a handshake ends.
pub const MAX_PENDING_HANDSHAKES: usize = 256;
/// How many completed handshakes may wait for the server to take them.
const ACCEPT_BACKLOG: usize = 128;
/// How long the accept loop waits after an accept error, so a listener in a
/// bad state does not spin a core.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// A connection whose TLS handshake completed, with the address it came from.
pub type Handshaken = (TlsStream<TcpStream>, SocketAddr);

/// The bounds every handshake runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeLimits {
    /// Deadline for one handshake, from the TCP accept.
    pub timeout: Duration,
    /// Handshakes in progress at once; at least one.
    pub max_pending: usize,
}

impl Default for HandshakeLimits {
    fn default() -> Self {
        Self {
            timeout: HANDSHAKE_TIMEOUT,
            max_pending: MAX_PENDING_HANDSHAKES,
        }
    }
}

/// Accept on `listener` and complete each TLS handshake off the accept loop.
///
/// The returned receiver yields the connections whose handshake completed; a
/// handshake that fails or outlives `limits.timeout` is dropped, since the
/// server has no connection to answer it on. `on_accept` runs on every TCP
/// connection before its handshake starts (socket options). The loop stops
/// and the listener closes once the receiver is dropped.
pub fn spawn_tls_acceptor(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    limits: HandshakeLimits,
    label: &'static str,
    on_accept: fn(&TcpStream),
) -> mpsc::Receiver<Handshaken> {
    let (tx, rx) = mpsc::channel(ACCEPT_BACKLOG);
    let slots = Arc::new(Semaphore::new(limits.max_pending.max(1)));

    tokio::spawn(async move {
        loop {
            let slot = tokio::select! {
                () = tx.closed() => return,
                slot = Arc::clone(&slots).acquire_owned() => match slot {
                    Ok(slot) => slot,
                    Err(_) => return,
                },
            };
            let accepted = tokio::select! {
                () = tx.closed() => return,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, listener = label, "TCP accept failed");
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };
            on_accept(&stream);
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let outcome = tokio::time::timeout(limits.timeout, acceptor.accept(stream)).await;
                drop(slot);
                match outcome {
                    Ok(Ok(tls)) => {
                        let _ = tx.send((tls, peer)).await;
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(error = %e, %peer, listener = label, "TLS handshake failed");
                    }
                    Err(_) => {
                        tracing::debug!(%peer, listener = label, "TLS handshake timed out");
                    }
                }
            });
        }
    });

    rx
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

    use super::*;
    use crate::tls::{LINK_API, LINK_OUTBOUND, build_crypto_provider};
    use infrastructure::config::PqMode;

    struct Server {
        addr: SocketAddr,
        cert: CertificateDer<'static>,
    }

    /// A loopback TLS server that answers `ok` on every connection the
    /// acceptor hands it.
    async fn server(limits: HandshakeLimits) -> Server {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate");
        let cert = generated.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
        let config = ServerConfig::builder_with_provider(Arc::new(build_crypto_provider(
            LINK_API,
            PqMode::Prefer,
        )))
        .with_safe_default_protocol_versions()
        .expect("TLS 1.3 is available")
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .expect("the certificate matches its key");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("a bound address");
        let mut ready = spawn_tls_acceptor(
            listener,
            TlsAcceptor::from(Arc::new(config)),
            limits,
            "test",
            |_| {},
        );
        tokio::spawn(async move {
            while let Some((mut tls, _)) = ready.recv().await {
                let _ = tls.write_all(b"ok").await;
                let _ = tls.shutdown().await;
            }
        });
        Server { addr, cert }
    }

    /// Complete a handshake with `server` and read its answer.
    async fn request(server: &Server) -> std::io::Result<Vec<u8>> {
        let mut roots = RootCertStore::empty();
        roots
            .add(server.cert.clone())
            .expect("the test certificate is an authority");
        let config = ClientConfig::builder_with_provider(Arc::new(build_crypto_provider(
            LINK_OUTBOUND,
            PqMode::Prefer,
        )))
        .with_safe_default_protocol_versions()
        .expect("TLS 1.3 is available")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let name = ServerName::try_from("localhost").expect("a valid server name");
        let tcp = TcpStream::connect(server.addr).await?;
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await?;
        let mut answer = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => answer.extend_from_slice(&buf[..n]),
            }
        }
        Ok(answer)
    }

    #[tokio::test]
    async fn a_client_that_never_sends_a_client_hello_does_not_hold_up_the_next() {
        let server = server(HandshakeLimits {
            timeout: Duration::from_secs(60),
            max_pending: 8,
        })
        .await;
        let _stalled = TcpStream::connect(server.addr)
            .await
            .expect("the stalled client connects");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let answer = tokio::time::timeout(Duration::from_secs(5), request(&server))
            .await
            .expect("the second client is served while the first stalls")
            .expect("the second handshake completes");
        assert_eq!(answer, b"ok");
    }

    #[tokio::test]
    async fn a_stalled_handshake_is_dropped_at_the_deadline() {
        let server = server(HandshakeLimits {
            timeout: Duration::from_millis(200),
            max_pending: 8,
        })
        .await;
        let mut stalled = TcpStream::connect(server.addr)
            .await
            .expect("the stalled client connects");
        let mut buf = [0u8; 16];
        let read = tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buf))
            .await
            .expect("the server closes a connection that never handshakes");
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "the stalled connection is closed, not answered: {read:?}"
        );
    }

    #[tokio::test]
    async fn a_full_handshake_cap_holds_the_next_client_until_a_slot_frees() {
        let deadline = Duration::from_millis(500);
        let server = server(HandshakeLimits {
            timeout: deadline,
            max_pending: 1,
        })
        .await;
        let _stalled = TcpStream::connect(server.addr)
            .await
            .expect("the stalled client connects");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = Instant::now();
        let answer = tokio::time::timeout(Duration::from_secs(5), request(&server))
            .await
            .expect("the slot frees at the deadline")
            .expect("the second handshake completes");
        assert_eq!(answer, b"ok");
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "the only slot was held by the stalled client, so the second waited for it"
        );
    }

    #[tokio::test]
    async fn dropping_the_receiver_closes_the_listener() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("a bound address");
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate");
        let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
        let config = ServerConfig::builder_with_provider(Arc::new(build_crypto_provider(
            LINK_API,
            PqMode::Prefer,
        )))
        .with_safe_default_protocol_versions()
        .expect("TLS 1.3 is available")
        .with_no_client_auth()
        .with_single_cert(vec![generated.cert.der().clone()], key)
        .expect("the certificate matches its key");
        let ready = spawn_tls_acceptor(
            listener,
            TlsAcceptor::from(Arc::new(config)),
            HandshakeLimits::default(),
            "test",
            |_| {},
        );
        drop(ready);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let refused = TcpStream::connect(addr).await;
        assert!(
            refused.is_err(),
            "the port is released once the server stops taking connections"
        );
    }
}
