//! RFC 5424 syslog and CEF, over UDP, TCP and TLS.
//!
//! One adapter carries both formats because only the payload differs: the
//! transports, the framing, the header and the backoff are the same
//! decisions, and a second copy of them is a second place for a bug in the
//! octet counting to live. What the payload is, is the one thing a caller
//! picks, and the mapping behind it lives in the domain layer so that the
//! CEF extension and the plain syslog message cannot drift apart.
//!
//! Framing follows the transport rather than the format. A datagram is its
//! own frame, so UDP sends one message per packet and a message longer than
//! the path's MTU is the operator's problem to route around. A stream has no
//! boundaries of its own, so TCP and TLS use RFC 6587's octet counting
//! rather than a newline: a flow record can carry a container image name or
//! a systemd unit, and a reader that splits on newlines splits a record in
//! half the day one of those arrives with a newline in it. The domain
//! mapping already strips newlines from values, which makes the two
//! defences independent rather than redundant.
//!
//! A destination that cannot be reached costs flow records and nothing else:
//! the sink counts the failure, arms its backoff, says so in its health and
//! returns, because the caller is draining a bounded queue that the
//! conntrack reader is filling.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use domain::common::error::DomainError;
use domain::flow::entity::FlowRecord;
use domain::flow::siem;
use infrastructure::config::{FlowTargetConfig, FlowTransport, PqMode, SyslogSinkConfig};
use ports::secondary::flow_sink_port::{FlowSink, FlowSinkHealth};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tracing::{info, warn};

/// The first wait before a refused destination is tried again.
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
/// The longest wait between two attempts, so a collector that comes back is
/// noticed in the same minute.
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// How long to wait before the next attempt, doubling with each failure.
fn backoff_for(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(6);
    let seconds = BACKOFF_FLOOR.as_secs().saturating_mul(1 << shift);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

/// Which payload the records are rendered as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFormat {
    /// The shared field list as the syslog message.
    Syslog,
    /// The same fields inside a CEF message.
    Cef,
}

impl TextFormat {
    /// The word in the sink's name, which is what the health endpoint shows.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Syslog => "syslog",
            Self::Cef => "cef",
        }
    }

    /// The message id the syslog header carries. A collector's CEF rule
    /// looks for `CEF` in that position, so the two formats are told apart
    /// without parsing the message.
    const fn msg_id(self) -> &'static str {
        match self {
            Self::Syslog => siem::SYSLOG_MSG_ID,
            Self::Cef => siem::SYSLOG_CEF_MSG_ID,
        }
    }
}

/// What a sink needs to know about the shape of its messages, settled once at
/// startup so a batch renders without touching configuration again.
#[derive(Debug, Clone)]
pub struct TextOptions {
    /// Which payload.
    pub format: TextFormat,
    /// The syslog facility.
    pub facility: u8,
    /// The host name in the header.
    pub hostname: String,
    /// The agent's version, which CEF's header carries and syslog does not.
    pub device_version: String,
    /// The exporter's sampling rate, written only where it is not one.
    pub sampling: u32,
}

/// The open socket, or nothing.
enum Connection {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Connection {
    /// True where a write failure means the session is gone, which is what
    /// decides whether the connection is thrown away on an error.
    const fn is_stream(&self) -> bool {
        matches!(self, Self::Tcp(_) | Self::Tls(_))
    }

    async fn write(&mut self, frame: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Udp(socket) => {
                socket.send(frame).await?;
                Ok(())
            }
            Self::Tcp(stream) => stream.write_all(frame).await,
            Self::Tls(stream) => stream.write_all(frame).await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Udp(_) => Ok(()),
            Self::Tcp(stream) => stream.shutdown().await,
            Self::Tls(stream) => stream.shutdown().await,
        }
    }
}

/// Everything one target's writer mutates.
struct SinkState {
    connection: Option<Connection>,
    retry_at: Option<Instant>,
    records_sent: u64,
    records_failed: u64,
    consecutive_failures: u32,
    detail: Option<String>,
}

/// One syslog or CEF target.
pub struct TextSink {
    name: String,
    address: String,
    transport: FlowTransport,
    options: TextOptions,
    tls: Option<Arc<ClientConfig>>,
    state: Mutex<SinkState>,
}

impl TextSink {
    /// A sink for one target. Nothing is opened here: the first batch opens
    /// the socket, so a collector that is not listening when the agent
    /// starts does not have to be, and startup never waits on a connect or a
    /// handshake.
    #[must_use]
    pub fn new(
        target: &FlowTargetConfig,
        options: TextOptions,
        tls: Option<Arc<ClientConfig>>,
    ) -> Self {
        let transport = target.transport();
        Self {
            name: format!(
                "{}-{}-{}",
                options.format.as_str(),
                transport.as_str(),
                target.address
            ),
            address: target.address.clone(),
            transport,
            options,
            tls,
            state: Mutex::new(SinkState {
                connection: None,
                retry_at: None,
                records_sent: 0,
                records_failed: 0,
                consecutive_failures: 0,
                detail: None,
            }),
        }
    }

    /// Every sink a configured section asks for.
    ///
    /// The authority is read once here rather than per connection, so a
    /// certificate file that does not parse is a startup failure naming the
    /// path instead of a sink that is permanently unhealthy for a reason an
    /// operator has to go and read. Returns the sinks, or the reason none
    /// could be built.
    pub fn from_config(
        config: &SyslogSinkConfig,
        format: TextFormat,
        hostname: &str,
        device_version: &str,
        sampling: u32,
        pq_mode: PqMode,
    ) -> Result<Vec<Arc<Self>>, DomainError> {
        if !config.enabled {
            return Ok(Vec::new());
        }
        let needs_tls = config
            .targets
            .iter()
            .any(|target| target.transport() == FlowTransport::Tls);
        let tls = if needs_tls {
            let authority = config.ca_cert.as_deref().unwrap_or_default();
            Some(Arc::new(client_config(Path::new(authority), pq_mode)?))
        } else {
            None
        };
        let hostname = if config.hostname.trim().is_empty() {
            hostname
        } else {
            config.hostname.trim()
        };
        let options = TextOptions {
            format,
            facility: config.facility,
            hostname: hostname.to_string(),
            device_version: device_version.to_string(),
            sampling,
        };
        Ok(config
            .targets
            .iter()
            .map(|target| Arc::new(Self::new(target, options.clone(), tls.clone())))
            .collect())
    }

    /// One record, rendered and framed for this sink's transport.
    fn frame(&self, record: &FlowRecord) -> Vec<u8> {
        let payload = match self.options.format {
            TextFormat::Syslog => siem::syslog_message(record, self.options.sampling),
            TextFormat::Cef => {
                siem::cef(record, &self.options.device_version, self.options.sampling)
            }
        };
        let message = siem::rfc5424(
            self.options.facility,
            &self.options.hostname,
            self.options.format.msg_id(),
            record.end_ms,
            &payload,
        );
        if self.transport.is_stream() {
            // RFC 6587 octet counting: the length in octets of the message
            // that follows, a space, then exactly that many octets.
            format!("{} {message}", message.len()).into_bytes()
        } else {
            message.into_bytes()
        }
    }

    /// The first address the target resolves to.
    async fn resolve(&self) -> Result<SocketAddr, DomainError> {
        lookup_host(self.address.as_str())
            .await
            .map_err(|error| DomainError::EngineError(format!("resolve failed: {error}")))?
            .next()
            .ok_or_else(|| DomainError::EngineError("resolved to no address".to_string()))
    }

    /// Open the socket, and for TLS complete the handshake before the first
    /// record: a session that cannot be verified must fail here rather than
    /// send anything.
    async fn connect(&self, state: &mut SinkState) -> Result<(), DomainError> {
        let destination = self.resolve().await?;
        let connection = match self.transport {
            FlowTransport::Udp => Connection::Udp(udp_socket(destination).await?),
            FlowTransport::Tcp => Connection::Tcp(tcp_stream(destination).await?),
            FlowTransport::Tls => {
                let config = self.tls.clone().ok_or_else(|| {
                    DomainError::EngineError("tls target with no authority".to_string())
                })?;
                let server_name = ServerName::try_from(host_of(&self.address).to_string())
                    .map_err(|_| {
                        DomainError::EngineError(format!(
                            "'{}' is not a name a certificate can be checked against",
                            host_of(&self.address)
                        ))
                    })?;
                let stream = tcp_stream(destination).await?;
                let stream = TlsConnector::from(config)
                    .connect(server_name, stream)
                    .await
                    .map_err(|error| {
                        DomainError::EngineError(format!("tls handshake failed: {error}"))
                    })?;
                Connection::Tls(Box::new(stream))
            }
        };
        state.connection = Some(connection);
        info!(sink = %self.name, "flow sink connected");
        Ok(())
    }

    /// Count a failure, drop a dead stream, and arm the backoff.
    fn note_failure(&self, state: &mut SinkState, records: u64, error: &DomainError) {
        state.records_failed = state.records_failed.saturating_add(records);
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.detail = Some(error.to_string());
        if state.connection.as_ref().is_some_and(Connection::is_stream) {
            state.connection = None;
        }
        state.retry_at = Some(Instant::now() + backoff_for(state.consecutive_failures));
        warn!(sink = %self.name, %error, "flow sink write failed");
    }

    /// One batch, in the order the exporter produced it.
    async fn deliver(
        &self,
        state: &mut SinkState,
        records: &[FlowRecord],
    ) -> Result<(), DomainError> {
        if state.connection.is_none() {
            self.connect(state).await?;
        }
        let frames: Vec<Vec<u8>> = records.iter().map(|record| self.frame(record)).collect();
        let Some(connection) = state.connection.as_mut() else {
            return Err(DomainError::EngineError("not connected".to_string()));
        };
        for frame in &frames {
            connection
                .write(frame)
                .await
                .map_err(|error| DomainError::EngineError(format!("write failed: {error}")))?;
        }
        Ok(())
    }
}

/// A connected datagram socket, bound on the family the destination is in.
async fn udp_socket(destination: SocketAddr) -> Result<UdpSocket, DomainError> {
    let bind = if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let bind: SocketAddr = bind
        .parse()
        .map_err(|_| DomainError::EngineError("local address unparseable".to_string()))?;
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|error| DomainError::EngineError(format!("bind failed: {error}")))?;
    socket
        .connect(destination)
        .await
        .map_err(|error| DomainError::EngineError(format!("connect failed: {error}")))?;
    Ok(socket)
}

/// A connected stream.
async fn tcp_stream(destination: SocketAddr) -> Result<TcpStream, DomainError> {
    TcpStream::connect(destination)
        .await
        .map_err(|error| DomainError::EngineError(format!("connect failed: {error}")))
}

/// The host half of `host:port`, with an IPv6 literal's brackets removed
/// because a certificate is checked against the name inside them.
fn host_of(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    address.rsplit_once(':').map_or(address, |(host, _)| host)
}

/// The client configuration for the `tls` transport.
///
/// The authority is the one the operator named and nothing else: there is no
/// public root list in this binary and no option to skip verification. A
/// syslog collector is an internal service, so naming its authority is the
/// configuration, and an agent that would accept any certificate is an agent
/// whose flow records go to whoever answers the port first.
fn client_config(authority: &Path, pq_mode: PqMode) -> Result<ClientConfig, DomainError> {
    let certificates: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(authority)
        .map_err(|error| {
            DomainError::EngineError(format!("failed to read '{}': {error}", authority.display()))
        })?
        .collect::<Result<_, _>>()
        .map_err(|error| {
            DomainError::EngineError(format!(
                "failed to parse the certificates in '{}': {error}",
                authority.display()
            ))
        })?;
    if certificates.is_empty() {
        return Err(DomainError::EngineError(format!(
            "'{}' holds no certificate",
            authority.display()
        )));
    }
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certificates);
    if added == 0 {
        return Err(DomainError::EngineError(format!(
            "none of the {ignored} certificates in '{}' can act as an authority",
            authority.display()
        )));
    }
    // The hybrid group is offered first here too, so a collector that knows
    // `X25519MLKEM768` gets it without the operator configuring anything. A
    // collector that does not falls back to a classical group, because
    // `require` is a statement about who may reach this agent rather than
    // about who this agent may reach.
    ClientConfig::builder_with_provider(crate::tls::client_provider(pq_mode))
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            DomainError::EngineError(format!("failed to build the TLS client policy: {error}"))
        })
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

impl FlowSink for TextSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn send<'a>(
        &'a self,
        records: &'a [FlowRecord],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DomainError>> + Send + 'a>>
    {
        Box::pin(async move {
            if records.is_empty() {
                return Ok(());
            }
            let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
            let mut state = self.state.lock().await;
            if let Some(retry_at) = state.retry_at {
                if Instant::now() < retry_at && state.connection.is_none() {
                    state.records_failed = state.records_failed.saturating_add(count);
                    return Err(DomainError::EngineError(
                        "destination unreachable, backing off".to_string(),
                    ));
                }
                state.retry_at = None;
            }
            match self.deliver(&mut state, records).await {
                Ok(()) => {
                    state.records_sent = state.records_sent.saturating_add(count);
                    state.consecutive_failures = 0;
                    state.detail = None;
                    Ok(())
                }
                Err(error) => {
                    self.note_failure(&mut state, count, &error);
                    Err(error)
                }
            }
        })
    }

    fn health<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = FlowSinkHealth> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            FlowSinkHealth {
                healthy: state.consecutive_failures == 0,
                detail: state.detail.clone(),
                records_sent: state.records_sent,
                records_failed: state.records_failed,
                consecutive_failures: state.consecutive_failures,
                ..FlowSinkHealth::new(self.name.clone())
            }
        })
    }

    fn close<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DomainError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if let Some(connection) = state.connection.as_mut() {
                let _ = connection.shutdown().await;
            }
            state.connection = None;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use domain::flow::entity::FlowEndReason;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    use super::*;

    fn record() -> FlowRecord {
        FlowRecord {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: 51_234,
            dst_port: 443,
            protocol: 6,
            packets: 12,
            bytes: 2_048,
            packets_rev: 10,
            bytes_rev: 16_384,
            start_ms: 1_760_000_000_000,
            end_ms: 1_760_000_012_500,
            reason: FlowEndReason::IdleTimeout,
            workload: None,
        }
    }

    fn target(address: &str, transport: &str) -> FlowTargetConfig {
        FlowTargetConfig {
            address: address.to_string(),
            transport: transport.to_string(),
        }
    }

    fn options(format: TextFormat) -> TextOptions {
        TextOptions {
            format,
            facility: 16,
            hostname: "node-1".to_string(),
            device_version: "0.0.0-dev".to_string(),
            sampling: 1,
        }
    }

    #[test]
    fn a_sink_is_named_for_its_format_its_transport_and_its_target() {
        let sink = TextSink::new(
            &target("siem.internal:6514", "tls"),
            options(TextFormat::Cef),
            None,
        );
        assert_eq!(sink.name(), "cef-tls-siem.internal:6514");
    }

    #[test]
    fn a_datagram_carries_the_message_and_no_frame() {
        let sink = TextSink::new(
            &target("127.0.0.1:514", "udp"),
            options(TextFormat::Syslog),
            None,
        );
        let frame = String::from_utf8(sink.frame(&record())).expect("the frame is text");
        assert!(frame.starts_with("<134>1 "), "{frame}");
        assert!(frame.contains(" node-1 ebpfsentinel - flow - "), "{frame}");
        assert!(frame.contains("src=10.0.0.7"), "{frame}");
        assert!(!frame.ends_with('\n'), "{frame}");
    }

    #[test]
    fn a_stream_counts_the_octets_that_follow() {
        let sink = TextSink::new(
            &target("127.0.0.1:601", "tcp"),
            options(TextFormat::Syslog),
            None,
        );
        let frame = String::from_utf8(sink.frame(&record())).expect("the frame is text");
        let (length, message) = frame.split_once(' ').expect("the count precedes a space");
        assert_eq!(
            length.parse::<usize>().expect("the count is a number"),
            message.len()
        );
        assert!(message.starts_with("<134>1 "), "{message}");
    }

    #[test]
    fn the_cef_payload_rides_the_same_envelope_under_its_own_message_id() {
        let sink = TextSink::new(
            &target("127.0.0.1:514", "udp"),
            options(TextFormat::Cef),
            None,
        );
        let frame = String::from_utf8(sink.frame(&record())).expect("the frame is text");
        assert!(frame.contains(" ebpfsentinel - CEF - CEF:0|"), "{frame}");
        assert!(frame.contains("|eBPFsentinel|Agent|0.0.0-dev|"), "{frame}");
    }

    #[test]
    fn the_facility_decides_the_priority() {
        let mut settings = options(TextFormat::Syslog);
        settings.facility = 1;
        let sink = TextSink::new(&target("127.0.0.1:514", "udp"), settings, None);
        let frame = String::from_utf8(sink.frame(&record())).expect("the frame is text");
        assert!(frame.starts_with("<14>1 "), "{frame}");
    }

    #[test]
    fn the_same_record_frames_identically_twice() {
        let sink = TextSink::new(
            &target("127.0.0.1:514", "udp"),
            options(TextFormat::Syslog),
            None,
        );
        assert_eq!(sink.frame(&record()), sink.frame(&record()));
    }

    #[test]
    fn a_disabled_section_builds_no_sink() {
        let config = SyslogSinkConfig::default();
        let sinks = TextSink::from_config(
            &config,
            TextFormat::Syslog,
            "node-1",
            "0.0.0-dev",
            1,
            PqMode::Prefer,
        )
        .expect("a disabled section is not an error");
        assert!(sinks.is_empty());
    }

    #[test]
    fn a_configured_section_builds_one_sink_per_target() {
        let config = SyslogSinkConfig {
            enabled: true,
            targets: vec![
                target("collector-a:514", "udp"),
                target("collector-b:601", "tcp"),
            ],
            facility: 16,
            hostname: String::new(),
            ca_cert: None,
        };
        let sinks = TextSink::from_config(
            &config,
            TextFormat::Cef,
            "node-7",
            "1.2.3",
            100,
            PqMode::Prefer,
        )
        .expect("neither target needs an authority");
        assert_eq!(sinks.len(), 2);
        assert_eq!(sinks[0].name(), "cef-udp-collector-a:514");
        assert_eq!(sinks[1].name(), "cef-tcp-collector-b:601");
        // An empty hostname takes the node's own, and the rate rides every
        // record because it is not one.
        let frame = String::from_utf8(sinks[0].frame(&record())).expect("the frame is text");
        assert!(frame.contains(" node-7 "), "{frame}");
        assert!(frame.contains("flowSampling=100"), "{frame}");
    }

    #[test]
    fn a_configured_hostname_wins_over_the_node_s_own() {
        let config = SyslogSinkConfig {
            enabled: true,
            targets: vec![target("collector:514", "udp")],
            facility: 16,
            hostname: "edge-3".to_string(),
            ca_cert: None,
        };
        let sinks = TextSink::from_config(
            &config,
            TextFormat::Syslog,
            "node-7",
            "1.2.3",
            1,
            PqMode::Prefer,
        )
        .expect("no authority is needed");
        let frame = String::from_utf8(sinks[0].frame(&record())).expect("the frame is text");
        assert!(frame.contains(" edge-3 "), "{frame}");
    }

    #[test]
    fn a_tls_target_whose_authority_cannot_be_read_refuses_at_startup() {
        let config = SyslogSinkConfig {
            enabled: true,
            targets: vec![target("collector:6514", "tls")],
            facility: 16,
            hostname: String::new(),
            ca_cert: Some("/nonexistent/ca.pem".to_string()),
        };
        let Err(error) = TextSink::from_config(
            &config,
            TextFormat::Syslog,
            "node-7",
            "1.2.3",
            1,
            PqMode::Prefer,
        ) else {
            panic!("an unreadable authority is a startup failure")
        };
        assert!(error.to_string().contains("/nonexistent/ca.pem"), "{error}");
    }

    #[test]
    fn a_file_that_is_not_a_certificate_names_itself_in_the_refusal() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("ca.pem");
        std::fs::write(&path, b"not a certificate").expect("the file is written");
        let error =
            client_config(&path, PqMode::Prefer).expect_err("a text file is not an authority");
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn the_host_is_what_a_certificate_is_checked_against() {
        assert_eq!(host_of("collector.internal:6514"), "collector.internal");
        assert_eq!(host_of("[2001:db8::1]:6514"), "2001:db8::1");
        assert_eq!(host_of("collector.internal"), "collector.internal");
    }

    #[test]
    fn the_wait_doubles_and_then_stops_doubling() {
        assert_eq!(backoff_for(0), Duration::from_secs(1));
        assert_eq!(backoff_for(1), Duration::from_secs(1));
        assert_eq!(backoff_for(3), Duration::from_secs(4));
        assert_eq!(backoff_for(7), Duration::from_secs(60));
        assert_eq!(backoff_for(u32::MAX), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn an_empty_batch_opens_nothing() {
        let sink = TextSink::new(
            &target("127.0.0.1:1", "tcp"),
            options(TextFormat::Syslog),
            None,
        );
        sink.send(&[])
            .await
            .expect("nothing to send is not a failure");
        let health = sink.health().await;
        assert!(health.healthy);
        assert_eq!(health.records_sent, 0);
    }

    #[tokio::test]
    async fn a_refused_destination_counts_the_records_and_backs_off() {
        // Port 1 on loopback is not listening, which is the cheapest refused
        // destination there is.
        let sink = TextSink::new(
            &target("127.0.0.1:1", "tcp"),
            options(TextFormat::Syslog),
            None,
        );
        let records = vec![record(), record()];
        sink.send(&records)
            .await
            .expect_err("nothing is listening there");
        let health = sink.health().await;
        assert!(!health.healthy);
        assert_eq!(health.records_failed, 2);
        assert_eq!(health.consecutive_failures, 1);
        assert!(health.detail.is_some());

        // The second attempt is refused by the backoff rather than by the
        // network, and still costs the records.
        sink.send(&records)
            .await
            .expect_err("the sink is backing off");
        let health = sink.health().await;
        assert_eq!(health.records_failed, 4);
        assert_eq!(
            health.consecutive_failures, 1,
            "a refusal that never touched the socket is not a new failure"
        );
    }

    #[tokio::test]
    async fn a_batch_arrives_framed_and_in_order_on_a_stream() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let address = listener
            .local_addr()
            .expect("the bound address")
            .to_string();
        let reader = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("the sink connects");
            let mut received = Vec::new();
            // Two frames, then the sink is dropped and the read ends.
            let _ = stream.read_to_end(&mut received).await;
            received
        });

        let sink = TextSink::new(&target(&address, "tcp"), options(TextFormat::Cef), None);
        let first = record();
        let second = FlowRecord {
            src_port: 51_235,
            ..record()
        };
        sink.send(&[first.clone(), second.clone()])
            .await
            .expect("the listener is up");
        sink.close().await.expect("the stream shuts down");

        let received =
            String::from_utf8(reader.await.expect("the reader joins")).expect("the stream is text");
        let expected_first = String::from_utf8(sink.frame(&first)).expect("a frame is text");
        let expected_second = String::from_utf8(sink.frame(&second)).expect("a frame is text");
        assert_eq!(received, format!("{expected_first}{expected_second}"));

        let health = sink.health().await;
        assert!(health.healthy);
        assert_eq!(health.records_sent, 2);
        assert_eq!(health.records_failed, 0);
    }

    #[tokio::test]
    async fn a_datagram_target_sends_one_message_per_record() {
        let collector = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback socket");
        let address = collector
            .local_addr()
            .expect("the bound address")
            .to_string();
        let sink = TextSink::new(&target(&address, "udp"), options(TextFormat::Syslog), None);
        sink.send(&[record(), record()])
            .await
            .expect("a datagram send cannot be refused");

        let mut buffer = vec![0_u8; 4_096];
        let expected = sink.frame(&record());
        for _ in 0..2 {
            let read = collector.recv(&mut buffer).await.expect("a datagram lands");
            assert_eq!(&buffer[..read], expected.as_slice());
        }
        assert_eq!(sink.health().await.records_sent, 2);
    }
}
