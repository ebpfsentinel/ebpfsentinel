//! The links the agent dials without a TLS configuration of its own - threat
//! intelligence feeds, `CrowdSec`, `GeoIP` downloads, webhooks, OIDC discovery
//! and JWKS, the anonymous heartbeat, alias resolution, OTLP and SMTP alerts -
//! all take the process-default provider the agent installs at start-up. These
//! tests complete a real handshake through the same two client stacks those
//! adapters use, `reqwest` and `lettre`, against a local server, and read the
//! group that was negotiated on both ends.
//!
//! The last test is what makes one wire test stand for every adapter: it
//! reads the sources and fails if any of them gives its client a TLS backend
//! of its own, which is the one thing that would take it off the default.

use std::path::Path;
use std::sync::Arc;

use adapters::tls::{
    LINK_OUTBOUND, build_crypto_provider, handshake_counts, install_pq_provider, last_handshake,
};
use infrastructure::config::PqMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{NamedGroup, ServerConfig};

struct Peer {
    cert: CertificateDer<'static>,
    port: u16,
}

/// A TLS server on loopback that answers each connection with `greeting`
/// after the handshake, counted under `link`.
async fn peer(link: &'static str, greeting: &'static [u8]) -> Peer {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("a self-signed certificate for the test peer");
    let cert = generated.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
    let config =
        ServerConfig::builder_with_provider(Arc::new(build_crypto_provider(link, PqMode::Prefer)))
            .with_safe_default_protocol_versions()
            .expect("TLS 1.3 is available")
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("the certificate matches its key");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("a bound address").port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let mut request = [0_u8; 1024];
                    let _ = stream.write_all(greeting).await;
                    let _ = stream.read(&mut request).await;
                    let _ = stream.write_all(greeting).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    Peer { cert, port }
}

fn outbound_count(group: NamedGroup) -> u64 {
    handshake_counts()
        .iter()
        .filter(|c| c.link == LINK_OUTBOUND && c.group == group)
        .map(|c| c.count)
        .sum()
}

#[tokio::test]
async fn the_default_clients_negotiate_the_hybrid_group() {
    install_pq_provider(PqMode::Prefer);

    // reqwest, as every HTTP adapter builds it.
    let before = outbound_count(NamedGroup::X25519MLKEM768);
    let web = peer(
        "test-http-peer",
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
    )
    .await;
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(&web.cert).expect("a DER certificate"))
        .build()
        .expect("a reqwest client");
    let body = client
        .get(format!("https://localhost:{}/", web.port))
        .send()
        .await
        .expect("the request reaches the peer")
        .text()
        .await
        .expect("a body");
    assert_eq!(body, "ok");
    assert_eq!(
        last_handshake("test-http-peer").map(|l| l.group),
        Some(NamedGroup::X25519MLKEM768),
        "the HTTP peer did not negotiate the hybrid group with a default client"
    );
    assert!(outbound_count(NamedGroup::X25519MLKEM768) > before);

    // lettre, as the SMTP alert sender builds it: implicit TLS on the relay.
    let before = outbound_count(NamedGroup::X25519MLKEM768);
    let mail = peer("test-smtp-peer", b"220 localhost ESMTP\r\n").await;
    let tls = lettre::transport::smtp::client::TlsParameters::builder("localhost".to_owned())
        .add_root_certificate(
            lettre::transport::smtp::client::Certificate::from_der(mail.cert.to_vec())
                .expect("a DER certificate"),
        )
        .build_rustls()
        .expect("TLS parameters");
    let transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor> =
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("localhost")
            .port(mail.port)
            .tls(lettre::transport::smtp::client::Tls::Wrapper(tls))
            .build();
    // The peer greets and hangs up, so the test connection fails after the
    // handshake; the handshake is what is under test.
    let _ = transport.test_connection().await;
    assert_eq!(
        last_handshake("test-smtp-peer").map(|l| l.group),
        Some(NamedGroup::X25519MLKEM768),
        "the SMTP peer did not negotiate the hybrid group with the alert sender's client"
    );
    assert!(outbound_count(NamedGroup::X25519MLKEM768) > before);
}

fn rust_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a readable source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_adapter_gives_its_client_a_tls_backend_of_its_own() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);
    rust_sources(&root.join("../agent/src"), &mut files);
    // A client that brings its own rustls configuration must build it from
    // `adapters::tls`, so it is counted under a link of its own rather than
    // escaping the policy. Turning certificate verification off, which the
    // OTLP exporter allows, changes who is trusted and not which groups go
    // on the wire, so it is not an escape here.
    let escapes = [
        "ServerConfig::builder()",
        "ClientConfig::builder()",
        "use_preconfigured_tls",
        "tls_backend_preconfigured",
        "aws_lc_rs::default_provider()",
        "ring::default_provider()",
    ];
    let mut found = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a readable source file");
        let production = text
            .split_once("#[cfg(test)]")
            .map_or(text.as_str(), |(before, _)| before);
        for escape in escapes {
            if production.contains(escape) && !file.ends_with("src/tls.rs") {
                found.push(format!("{} uses {escape}", file.display()));
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}
