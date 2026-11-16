//! `outbound_pq_mode: require` against a real syslog collector over TLS: a
//! collector that only speaks classical key exchange is refused before the
//! agent starts, and the refusal says why; one that answers the hybrid group
//! passes; and without `require` the classical collector is still reached.

use std::sync::Arc;

use adapters::flow::text_sink::{TextFormat, TextSink};
use adapters::tls::{build_crypto_provider, last_handshake};
use infrastructure::config::{FlowTargetConfig, PqMode, SyslogSinkConfig};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::{NamedGroup, ServerConfig};

struct Collector {
    address: String,
    ca: tempfile::NamedTempFile,
}

/// A syslog-over-TLS collector on loopback whose key exchange is `mode`.
async fn collector(link: &'static str, mode: PqMode) -> Collector {
    let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()])
        .expect("a self-signed certificate for the collector");
    let cert = generated.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
    let config = ServerConfig::builder_with_provider(Arc::new(build_crypto_provider(link, mode)))
        .with_safe_default_protocol_versions()
        .expect("TLS 1.3 is available")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("the certificate matches its key");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("a bound address").to_string();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let mut sink = Vec::new();
                    let _ = stream.read_to_end(&mut sink).await;
                }
            });
        }
    });
    let ca = tempfile::NamedTempFile::new().expect("a temporary file");
    std::fs::write(ca.path(), generated.cert.pem()).expect("the authority is written");
    Collector { address, ca }
}

fn sink(collector: &Collector, outbound: PqMode) -> Arc<TextSink> {
    let config = SyslogSinkConfig {
        enabled: true,
        targets: vec![FlowTargetConfig {
            address: collector.address.clone(),
            transport: "tls".to_string(),
        }],
        facility: 16,
        hostname: String::new(),
        ca_cert: Some(collector.ca.path().display().to_string()),
    };
    TextSink::from_config(
        &config,
        TextFormat::Syslog,
        "node-1",
        "0.0.0-dev",
        1,
        outbound,
    )
    .expect("the sink builds")
    .remove(0)
}

#[tokio::test]
async fn a_require_agent_refuses_a_classical_only_syslog_server_and_says_so() {
    let classical = collector("test-collector-classical", PqMode::Disable).await;
    let error = sink(&classical, PqMode::Require)
        .check_policy()
        .await
        .expect_err("a classical-only collector is refused at startup");
    let message = error.to_string();
    assert!(
        message.contains("no post-quantum key exchange"),
        "{message}"
    );
    assert!(message.contains("outbound_pq_mode: require"), "{message}");
    assert!(last_handshake("test-collector-classical").is_none());
}

#[tokio::test]
async fn a_require_agent_accepts_a_collector_that_answers_the_hybrid_group() {
    let hybrid = collector("test-collector-hybrid", PqMode::Prefer).await;
    sink(&hybrid, PqMode::Require)
        .check_policy()
        .await
        .expect("a hybrid collector passes");
    assert_eq!(
        last_handshake("test-collector-hybrid").map(|l| l.group),
        Some(NamedGroup::X25519MLKEM768)
    );
}

#[tokio::test]
async fn without_require_the_classical_collector_is_not_checked() {
    let classical = collector("test-collector-classical-prefer", PqMode::Disable).await;
    sink(&classical, PqMode::Prefer)
        .check_policy()
        .await
        .expect("prefer leaves the classical fallback on");
}

#[tokio::test]
async fn a_collector_that_is_down_does_not_hold_startup() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("a bound address").to_string();
    drop(listener);
    let classical = Collector {
        address,
        ca: collector("test-collector-down", PqMode::Disable).await.ca,
    };
    sink(&classical, PqMode::Require)
        .check_policy()
        .await
        .expect("an unreachable collector is retried later, not refused now");
}
