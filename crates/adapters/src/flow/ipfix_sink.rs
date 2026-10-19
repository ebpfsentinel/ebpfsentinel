//! IPFIX over UDP and TCP.
//!
//! One sink is one target. The encoder lives here with the connection
//! because the sequence number and the template state belong to the stream
//! the collector is reading: RFC 7011 counts data records per transport
//! session, so a reconnection restarts the count and re-sends the templates
//! before the first record, and a collector that was restarted underneath us
//! is not left decoding against a template it never received.
//!
//! The templates also go out on a timer, which is what RFC 7011 section
//! 10.3.6 asks of UDP: a collector has no way to request them, so a sender
//! that only ever announced them once makes every restart of the collector a
//! silent loss. The interval is configuration with a ten-minute default,
//! because ten minutes is the RFC's own figure.
//!
//! A destination that cannot be reached costs flow records and nothing else.
//! The sink counts the failure, backs off before trying the socket again, and
//! says so through its health; it never blocks, and it never retries inside
//! the call, because the caller is draining a bounded queue that the
//! conntrack reader is filling.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use domain::common::error::DomainError;
use domain::flow::entity::FlowRecord;
use domain::flow::ipfix::{IpfixEncoder, IpfixOptions};
use infrastructure::config::{FlowTargetConfig, FlowTransport, IpfixSinkConfig};
use ports::secondary::flow_sink_port::{FlowSink, FlowSinkHealth};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// The first wait before a refused destination is tried again.
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
/// The longest wait between two attempts. A collector that comes back must
/// be noticed in the same minute, not in the same hour.
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// How long to wait before the next attempt, doubling with each failure.
fn backoff_for(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(6);
    let seconds = BACKOFF_FLOOR.as_secs().saturating_mul(1 << shift);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

/// Unix seconds, the unit of the IPFIX message header's export time.
fn export_time_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u32::try_from(since.as_secs()).unwrap_or(u32::MAX)
        })
}

/// The open socket, or nothing.
enum Connection {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl Connection {
    /// True where a write failure means the session is gone. A UDP socket
    /// has no session to lose, so a transient send error does not throw the
    /// sequence number away.
    const fn is_stream(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    async fn write(&mut self, message: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Udp(socket) => {
                socket.send(message).await?;
                Ok(())
            }
            Self::Tcp(stream) => stream.write_all(message).await,
        }
    }
}

/// Everything one target's writer mutates.
struct SinkState {
    encoder: IpfixEncoder,
    connection: Option<Connection>,
    templates_at: Option<Instant>,
    retry_at: Option<Instant>,
    records_sent: u64,
    records_failed: u64,
    consecutive_failures: u32,
    detail: Option<String>,
}

/// One IPFIX target.
pub struct IpfixSink {
    name: String,
    address: String,
    transport: FlowTransport,
    template_interval: Duration,
    state: Mutex<SinkState>,
}

impl IpfixSink {
    /// A sink for one target. Nothing is opened here: the first batch opens
    /// the socket, so a collector that is not yet listening when the agent
    /// starts does not have to be, and startup never waits on a TCP connect.
    #[must_use]
    pub fn new(
        target: &FlowTargetConfig,
        options: IpfixOptions,
        template_interval: Duration,
    ) -> Self {
        let transport = target.transport();
        Self {
            name: format!("ipfix-{}-{}", transport.as_str(), target.address),
            address: target.address.clone(),
            transport,
            template_interval,
            state: Mutex::new(SinkState {
                encoder: IpfixEncoder::new(options),
                connection: None,
                templates_at: None,
                retry_at: None,
                records_sent: 0,
                records_failed: 0,
                consecutive_failures: 0,
                detail: None,
            }),
        }
    }

    /// Every sink a configured IPFIX section asks for.
    ///
    /// The address is not resolved here either, because a name that does not
    /// resolve at startup is a collector that is not up yet rather than a
    /// configuration error, and the configuration has already been checked
    /// for the shape of what it holds.
    #[must_use]
    pub fn from_config(config: &IpfixSinkConfig) -> Vec<Arc<Self>> {
        if !config.enabled {
            return Vec::new();
        }
        let options = IpfixOptions {
            observation_domain_id: config.observation_domain_id,
            enterprise_number: config.enterprise_number,
            max_message_bytes: config.max_message_bytes,
        };
        config
            .targets
            .iter()
            .map(|target| {
                Arc::new(Self::new(
                    target,
                    options,
                    Duration::from_secs(config.template_interval_secs),
                ))
            })
            .collect()
    }

    /// The first address the target resolves to.
    async fn resolve(&self) -> Result<SocketAddr, DomainError> {
        lookup_host(self.address.as_str())
            .await
            .map_err(|error| DomainError::EngineError(format!("resolve failed: {error}")))?
            .next()
            .ok_or_else(|| DomainError::EngineError("resolved to no address".to_string()))
    }

    /// Open the socket. For TCP this is a session, so the sequence number
    /// restarts and the templates are owed again before any record.
    async fn connect(&self, state: &mut SinkState) -> Result<(), DomainError> {
        let destination = self.resolve().await?;
        let connection = match self.transport {
            FlowTransport::Udp => {
                let bind: SocketAddr = if destination.is_ipv4() {
                    "0.0.0.0:0".parse().map_err(|_| {
                        DomainError::EngineError("local address unparseable".to_string())
                    })?
                } else {
                    "[::]:0".parse().map_err(|_| {
                        DomainError::EngineError("local address unparseable".to_string())
                    })?
                };
                let socket = UdpSocket::bind(bind)
                    .await
                    .map_err(|error| DomainError::EngineError(format!("bind failed: {error}")))?;
                socket.connect(destination).await.map_err(|error| {
                    DomainError::EngineError(format!("connect failed: {error}"))
                })?;
                Connection::Udp(socket)
            }
            FlowTransport::Tcp => {
                let stream = TcpStream::connect(destination).await.map_err(|error| {
                    DomainError::EngineError(format!("connect failed: {error}"))
                })?;
                Connection::Tcp(stream)
            }
            // Configuration refuses a tls target for this sink, because the
            // encoder writes to a plain socket. Saying so again here is what
            // keeps the two answers the same if that ever changes.
            FlowTransport::Tls => {
                return Err(DomainError::EngineError(
                    "ipfix does not speak tls".to_string(),
                ));
            }
        };
        state.encoder.reset_sequence();
        state.templates_at = None;
        state.connection = Some(connection);
        info!(sink = %self.name, "flow sink connected");
        Ok(())
    }

    /// Send the template set, and remember when.
    async fn send_templates(&self, state: &mut SinkState) -> Result<(), DomainError> {
        let message = state.encoder.template_message(export_time_secs());
        let Some(connection) = state.connection.as_mut() else {
            return Err(DomainError::EngineError("not connected".to_string()));
        };
        connection
            .write(&message)
            .await
            .map_err(|error| DomainError::EngineError(format!("template write failed: {error}")))?;
        state.templates_at = Some(Instant::now());
        debug!(
            sink = %self.name,
            templates = state.encoder.offered_templates().len(),
            "flow sink announced its templates"
        );
        Ok(())
    }

    /// True where the templates are owed: never sent on this session, or the
    /// interval has run out.
    fn templates_due(&self, state: &SinkState) -> bool {
        state
            .templates_at
            .is_none_or(|sent| sent.elapsed() >= self.template_interval)
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

    /// One batch, on an open session, templates first where they are owed.
    async fn deliver(
        &self,
        state: &mut SinkState,
        records: &[FlowRecord],
    ) -> Result<(), DomainError> {
        if state.connection.is_none() {
            self.connect(state).await?;
        }
        if self.templates_due(state) {
            self.send_templates(state).await?;
        }
        let messages = state.encoder.data_messages(records, export_time_secs());
        let Some(connection) = state.connection.as_mut() else {
            return Err(DomainError::EngineError("not connected".to_string()));
        };
        for message in &messages {
            connection
                .write(message)
                .await
                .map_err(|error| DomainError::EngineError(format!("write failed: {error}")))?;
        }
        Ok(())
    }
}

impl FlowSink for IpfixSink {
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
            if let Some(Connection::Tcp(stream)) = state.connection.as_mut() {
                let _ = stream.shutdown().await;
            }
            state.connection = None;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::flow::entity::FlowEndReason;
    use domain::flow::ipfix::{IPFIX_VERSION, SET_ID_TEMPLATE};
    use std::net::Ipv4Addr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn record(port: u16) -> FlowRecord {
        FlowRecord {
            src: Ipv4Addr::new(10, 0, 0, 1).into(),
            dst: Ipv4Addr::new(10, 0, 0, 2).into(),
            src_port: port,
            dst_port: 443,
            protocol: 6,
            packets: 4,
            bytes: 400,
            packets_rev: 2,
            bytes_rev: 200,
            start_ms: 1_000,
            end_ms: 2_000,
            reason: FlowEndReason::EndOfFlow,
            workload: None,
        }
    }

    fn target(address: &str, transport: &str) -> FlowTargetConfig {
        FlowTargetConfig {
            address: address.to_string(),
            transport: transport.to_string(),
        }
    }

    fn sink(address: &str, transport: &str) -> IpfixSink {
        IpfixSink::new(
            &target(address, transport),
            IpfixOptions::default(),
            Duration::from_secs(600),
        )
    }

    #[tokio::test]
    async fn a_sink_is_named_after_its_transport_and_its_target() {
        assert_eq!(
            sink("10.0.0.9:4739", "udp").name(),
            "ipfix-udp-10.0.0.9:4739"
        );
        assert_eq!(sink("[::1]:4739", "tcp").name(), "ipfix-tcp-[::1]:4739");
    }

    #[tokio::test]
    async fn nothing_is_opened_before_the_first_batch() {
        let sink = sink("127.0.0.1:1", "tcp");
        let health = sink.health().await;
        assert!(health.healthy, "a sink that has not written has not failed");
        assert_eq!(health.records_sent, 0);
        assert_eq!(health.records_failed, 0);
    }

    #[tokio::test]
    async fn an_empty_batch_opens_no_socket() {
        let sink = sink("127.0.0.1:1", "tcp");
        assert!(sink.send(&[]).await.is_ok());
        assert_eq!(sink.health().await.records_sent, 0);
    }

    #[tokio::test]
    async fn a_udp_collector_receives_templates_before_records() {
        let collector = UdpSocket::bind("127.0.0.1:0").await.expect("a free port");
        let address = collector.local_addr().expect("bound").to_string();
        let sink = sink(&address, "udp");
        sink.send(&[record(1000)]).await.expect("written");

        let mut buffer = [0_u8; 2048];
        let read = collector.recv(&mut buffer).await.expect("templates");
        assert_eq!(u16::from_be_bytes([buffer[0], buffer[1]]), IPFIX_VERSION);
        assert_eq!(
            u16::from_be_bytes([buffer[16], buffer[17]]),
            SET_ID_TEMPLATE,
            "the first message a collector sees is the template set"
        );
        assert!(read > 16);

        let read = collector.recv(&mut buffer).await.expect("a data set");
        assert_ne!(
            u16::from_be_bytes([buffer[16], buffer[17]]),
            SET_ID_TEMPLATE
        );
        assert!(read > 16);
        assert_eq!(sink.health().await.records_sent, 1);
    }

    #[tokio::test]
    async fn the_templates_go_out_again_when_the_interval_has_run_out() {
        let collector = UdpSocket::bind("127.0.0.1:0").await.expect("a free port");
        let address = collector.local_addr().expect("bound").to_string();
        let sink = IpfixSink::new(
            &target(&address, "udp"),
            IpfixOptions::default(),
            Duration::from_millis(0),
        );
        sink.send(&[record(1000)]).await.expect("written");
        sink.send(&[record(1001)]).await.expect("written");

        let mut buffer = [0_u8; 2048];
        let mut templates = 0;
        for _ in 0..4 {
            collector.recv(&mut buffer).await.expect("a message");
            if u16::from_be_bytes([buffer[16], buffer[17]]) == SET_ID_TEMPLATE {
                templates += 1;
            }
        }
        assert_eq!(
            templates, 2,
            "one announcement per batch at a zero interval"
        );
    }

    #[tokio::test]
    async fn a_tcp_collector_receives_one_stream_and_the_sequence_starts_at_zero() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a free port");
        let address = listener.local_addr().expect("bound").to_string();
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a connection");
            let mut buffer = vec![0_u8; 4096];
            let read = stream.read(&mut buffer).await.expect("bytes");
            buffer.truncate(read);
            buffer
        });
        let sink = sink(&address, "tcp");
        sink.send(&[record(1000)]).await.expect("written");
        let bytes = accepted.await.expect("the collector read");
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), IPFIX_VERSION);
        assert_eq!(
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            0,
            "a template message carries the sequence of the first record to come"
        );
        sink.close().await.expect("closed");
    }

    #[tokio::test]
    async fn a_refused_destination_is_counted_and_then_backed_off() {
        let sink = sink("127.0.0.1:1", "tcp");
        assert!(sink.send(&[record(1000)]).await.is_err());
        let health = sink.health().await;
        assert!(!health.healthy);
        assert_eq!(health.records_failed, 1);
        assert_eq!(health.consecutive_failures, 1);
        assert!(health.detail.is_some(), "the health endpoint says why");

        let error = sink.send(&[record(1001)]).await.expect_err("backing off");
        assert!(
            error.to_string().contains("backing off"),
            "the second attempt does not touch the socket: {error}"
        );
        assert_eq!(sink.health().await.records_failed, 2);
    }

    #[tokio::test]
    async fn an_address_that_does_not_resolve_is_a_failure_rather_than_a_panic() {
        let sink = sink("no-such-host.invalid:4739", "udp");
        assert!(sink.send(&[record(1000)]).await.is_err());
        assert!(!sink.health().await.healthy);
    }

    #[tokio::test]
    async fn closing_a_sink_that_never_opened_is_not_an_error() {
        assert!(sink("127.0.0.1:1", "udp").close().await.is_ok());
    }

    #[test]
    fn the_backoff_doubles_and_then_stops_doubling() {
        assert_eq!(backoff_for(0), Duration::from_secs(1));
        assert_eq!(backoff_for(1), Duration::from_secs(1));
        assert_eq!(backoff_for(2), Duration::from_secs(2));
        assert_eq!(backoff_for(3), Duration::from_secs(4));
        assert_eq!(backoff_for(7), BACKOFF_CEILING);
        assert_eq!(backoff_for(u32::MAX), BACKOFF_CEILING);
    }

    #[test]
    fn a_disabled_section_builds_no_sink_and_an_enabled_one_builds_one_per_target() {
        let mut config = IpfixSinkConfig {
            targets: vec![
                target("127.0.0.1:4739", "udp"),
                target("127.0.0.1:4740", "tcp"),
            ],
            ..IpfixSinkConfig::default()
        };
        assert!(IpfixSink::from_config(&config).is_empty());
        config.enabled = true;
        let sinks = IpfixSink::from_config(&config);
        assert_eq!(sinks.len(), 2);
        assert_eq!(sinks[0].name(), "ipfix-udp-127.0.0.1:4739");
        assert_eq!(sinks[1].name(), "ipfix-tcp-127.0.0.1:4740");
    }

    #[test]
    fn the_configured_pen_reaches_the_encoder() {
        let config = IpfixSinkConfig {
            enabled: true,
            enterprise_number: 12_345,
            targets: vec![target("127.0.0.1:4739", "udp")],
            ..IpfixSinkConfig::default()
        };
        let sinks = IpfixSink::from_config(&config);
        let sink = sinks.first().expect("one sink");
        let state = sink.state.try_lock().expect("uncontended");
        assert_eq!(state.encoder.offered_templates().len(), 4);
    }
}
