//! Flow export: the table's bounds, and one section per format.
//!
//! Every number here is a trade an operator makes about their own node, so
//! each one says what it costs rather than only what it is. The defaults are
//! the ones a collector expects: a sixty-second active timeout and a
//! fifteen-second idle timeout are what every `NetFlow` and IPFIX exporter
//! ships with, so a dashboard built for one of those reads these records
//! without being re-tuned.
//!
//! Export is off by default. A node that starts sending flow records to a
//! collector nobody configured is a node generating traffic its operator did
//! not ask for.

use serde::{Deserialize, Serialize};

use super::common::ConfigError;

/// A minute, which is what a collector's default aggregation window assumes.
fn default_active_timeout_secs() -> u64 {
    60
}

/// Fifteen seconds of silence ends a flow. Shorter splits an idle keep-alive
/// connection into many records; longer holds a finished flow in memory and
/// delays the record a responder is waiting for.
fn default_idle_timeout_secs() -> u64 {
    15
}

/// Sixty-five thousand flows, at a few hundred bytes each: a few tens of
/// megabytes, which is the right order for a node whose conntrack table is
/// itself bounded.
fn default_table_capacity() -> usize {
    65_536
}

/// Export every flow. Sampling is a decision about losing data and must be
/// typed on purpose.
fn default_sampling() -> u32 {
    1
}

/// The records held between the table and the sinks. Full means a dropped
/// record, which is a counter rather than a silence.
fn default_queue_depth() -> usize {
    4_096
}

/// How often the table is asked what the clock has made due. Finer than this
/// buys nothing: the timeouts are measured in seconds.
fn default_tick_interval_secs() -> u64 {
    5
}

/// How many records a sink is handed at once.
fn default_batch_size() -> usize {
    256
}

/// Ten minutes, which is the interval RFC 7011 section 10.3.6 suggests for
/// templates on an unreliable transport.
fn default_template_interval_secs() -> u64 {
    600
}

/// Room for IP and UDP headers inside a 1500-byte MTU, so a datagram reaches
/// the collector unfragmented.
fn default_max_message_bytes() -> usize {
    1_400
}

const MIN_TIMEOUT_SECS: u64 = 1;
const MAX_TIMEOUT_SECS: u64 = 3_600;
const MIN_TABLE_CAPACITY: usize = 1_024;
const MAX_TABLE_CAPACITY: usize = 4_194_304;
const MIN_QUEUE_DEPTH: usize = 64;
const MAX_QUEUE_DEPTH: usize = 1_048_576;
const MIN_BATCH_SIZE: usize = 1;
const MAX_BATCH_SIZE: usize = 8_192;
const MIN_TICK_INTERVAL_SECS: u64 = 1;
const MAX_TICK_INTERVAL_SECS: u64 = 300;
const MIN_MESSAGE_BYTES: usize = 512;
const MAX_MESSAGE_BYTES: usize = 65_535;

/// Which wire a sink uses.
///
/// `Tls` is TCP with the stream encrypted, which is what RFC 5425 asks of
/// syslog leaving a node: a flow record names every address a workload
/// talked to, so on anything but a trusted segment it is the transport to
/// pick. IPFIX refuses it, because this agent's IPFIX encoder writes to a
/// plain socket and a collector offered a TLS stream it cannot read is worse
/// than a refusal at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowTransport {
    Udp,
    Tcp,
    Tls,
}

impl FlowTransport {
    /// What an error message tells an operator to type.
    pub const ACCEPTED: &'static str = "udp, tcp, tls";

    /// What an error message tells an operator to type where the sink has no
    /// TLS of its own.
    pub const ACCEPTED_UNENCRYPTED: &'static str = "udp, tcp";

    /// Parse the configured word.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            "tls" => Some(Self::Tls),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }

    /// Whether the record travels over a stream, which is what decides
    /// framing: a datagram is its own frame, a stream needs one.
    #[must_use]
    pub fn is_stream(self) -> bool {
        matches!(self, Self::Tcp | Self::Tls)
    }
}

/// One collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowTargetConfig {
    /// `host:port`. A name is resolved at connection time rather than at
    /// startup, so a collector that moves does not need the agent restarted.
    pub address: String,

    /// `udp` or `tcp`.
    #[serde(default = "default_udp")]
    pub transport: String,
}

fn default_udp() -> String {
    "udp".to_string()
}

impl FlowTargetConfig {
    /// The parsed transport, `Udp` for an unparsable one, which `validate`
    /// has already refused.
    #[must_use]
    pub fn transport(&self) -> FlowTransport {
        FlowTransport::parse(&self.transport).unwrap_or(FlowTransport::Udp)
    }

    fn validate(&self, field: &str, accepted: &str) -> Result<(), ConfigError> {
        let refused = |message: String| ConfigError::Validation {
            field: format!("{field}.transport"),
            message,
        };
        let Some(transport) = FlowTransport::parse(&self.transport) else {
            return Err(refused(format!(
                "must be one of {accepted}, got '{}'",
                self.transport
            )));
        };
        if transport == FlowTransport::Tls && accepted == FlowTransport::ACCEPTED_UNENCRYPTED {
            return Err(refused(format!(
                "is tls, which this sink does not speak; it accepts {accepted}"
            )));
        }
        validate_address(&self.address, &format!("{field}.address"))
    }
}

/// `host:port`, with a port that is a port.
///
/// The host is not resolved here: a startup that fails because a collector's
/// DNS was briefly unavailable is a node that stops forwarding traffic over a
/// telemetry destination.
pub(super) fn validate_address(address: &str, field: &str) -> Result<(), ConfigError> {
    let invalid = |message: String| ConfigError::Validation {
        field: field.to_string(),
        message,
    };
    let Some((host, port)) = address.rsplit_once(':') else {
        return Err(invalid(format!("must be 'host:port', got '{address}'")));
    };
    // A bare IPv6 literal would split on its own last colon and read its
    // final group as a port, so a literal must be bracketed, which is what
    // every resolver expects to be handed back anyway.
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return Err(invalid(format!(
            "is an IPv6 literal and must be bracketed as '[host]:port', got '{address}'"
        )));
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(invalid(format!("names no host, got '{address}'")));
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(invalid(format!(
            "must end in a port between 1 and 65535, got '{address}'"
        ))),
        Ok(_) => Ok(()),
    }
}

/// IPFIX, over UDP or TCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfixSinkConfig {
    /// Off by default, like every sink.
    #[serde(default)]
    pub enabled: bool,

    /// The collectors. One sink per entry, each with its own sequence number
    /// and its own backoff.
    #[serde(default)]
    pub targets: Vec<FlowTargetConfig>,

    /// The observation domain a collector sees, which is how two exporters on
    /// one node are told apart.
    #[serde(default)]
    pub observation_domain_id: u32,

    /// The Private Enterprise Number the workload elements are written under.
    ///
    /// Zero, the default, means the workload block is not exported: a private
    /// element is only meaningful under a PEN its owner registered, and this
    /// project holds none. An operator who holds one sets it here and gets
    /// the block; the rest of the record is standard either way.
    #[serde(default)]
    pub enterprise_number: u32,

    /// How often the templates are re-sent. They are also sent on every
    /// reconnection, whatever this says.
    #[serde(default = "default_template_interval_secs")]
    pub template_interval_secs: u64,

    /// The size a message is kept under. A single record larger than this is
    /// still sent whole, because IPFIX cannot split a data record.
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
}

impl Default for IpfixSinkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            targets: Vec::new(),
            observation_domain_id: 0,
            enterprise_number: 0,
            template_interval_secs: default_template_interval_secs(),
            max_message_bytes: default_max_message_bytes(),
        }
    }
}

impl IpfixSinkConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.targets.is_empty() {
            return Err(ConfigError::Validation {
                field: "flow_export.ipfix.targets".to_string(),
                message: "is empty, so the sink has nowhere to send".to_string(),
            });
        }
        for (index, target) in self.targets.iter().enumerate() {
            target.validate(
                &format!("flow_export.ipfix.targets[{index}]"),
                FlowTransport::ACCEPTED_UNENCRYPTED,
            )?;
        }
        range(
            self.template_interval_secs,
            MIN_TIMEOUT_SECS,
            MAX_TIMEOUT_SECS,
            "flow_export.ipfix.template_interval_secs",
        )?;
        range_usize(
            self.max_message_bytes,
            MIN_MESSAGE_BYTES,
            MAX_MESSAGE_BYTES,
            "flow_export.ipfix.max_message_bytes",
        )
    }
}

/// A text sink over syslog's transports: RFC 5424 records, or the same
/// fields inside a CEF payload.
///
/// One struct serves both because they differ only in what the message
/// carries: the transports, the framing, the facility and the host name in
/// the header are the same decisions, and an operator who configured one has
/// nothing new to learn for the other.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyslogSinkConfig {
    /// Off by default, like every sink.
    #[serde(default)]
    pub enabled: bool,

    /// The collectors. One sink per entry, each with its own backoff.
    #[serde(default)]
    pub targets: Vec<FlowTargetConfig>,

    /// The syslog facility the records are sent under, 0 to 23.
    ///
    /// `local0` by default rather than `user`, which is where this agent's
    /// own alerts go: a flow record is volume, and an operator routing it to
    /// a file of its own should not have to write a message filter to keep it
    /// out of the alert stream.
    #[serde(default = "default_facility")]
    pub facility: u8,

    /// The host name written into the header. Empty means the node's own,
    /// read once at startup, which is what a collector expects to see.
    #[serde(default)]
    pub hostname: String,

    /// The certificate authority that signs the collector's certificate.
    ///
    /// Required for the `tls` transport and ignored for the other two. There
    /// is no public root list in this binary and no way to turn verification
    /// off: a syslog collector is an internal service, so naming its
    /// authority is the configuration, and an agent that would accept any
    /// certificate is an agent whose flow records can be read by whoever
    /// answers the port first.
    #[serde(default)]
    pub ca_cert: Option<String>,
}

/// `local0`, which is 16.
fn default_facility() -> u8 {
    16
}

const MAX_FACILITY: u8 = 23;

impl SyslogSinkConfig {
    fn validate(&self, section: &str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.targets.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("flow_export.{section}.targets"),
                message: "is empty, so the sink has nowhere to send".to_string(),
            });
        }
        for (index, target) in self.targets.iter().enumerate() {
            target.validate(
                &format!("flow_export.{section}.targets[{index}]"),
                FlowTransport::ACCEPTED,
            )?;
        }
        if self.facility > MAX_FACILITY {
            return Err(ConfigError::Validation {
                field: format!("flow_export.{section}.facility"),
                message: format!(
                    "must be between 0 and {MAX_FACILITY}, got {}",
                    self.facility
                ),
            });
        }
        let needs_authority = self
            .targets
            .iter()
            .any(|target| target.transport() == FlowTransport::Tls);
        if needs_authority && self.ca_cert.as_deref().unwrap_or_default().is_empty() {
            return Err(ConfigError::Validation {
                field: format!("flow_export.{section}.ca_cert"),
                message: "is empty and a target uses the tls transport; name the authority \
                          that signs the collector's certificate, because this sink will \
                          not skip verification"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// Flow records as JSON lines in a file.
///
/// Rotation is the system's job: an estate already runs logrotate or a
/// journald equivalent on every other file on the node, and a second
/// rotation policy inside the agent is one more place for a disk to fill in a
/// way nobody is watching. The sink reopens its path when the file it holds
/// is no longer the file at that path, so `create` and `copytruncate` both
/// work and no record is written into a rotated-away handle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonLinesSinkConfig {
    /// Off by default, like every sink.
    #[serde(default)]
    pub enabled: bool,

    /// The file the lines are appended to. Created with owner-only write
    /// where it does not exist, because a flow record names addresses.
    #[serde(default)]
    pub path: String,
}

impl JsonLinesSinkConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.path.trim().is_empty() {
            return Err(ConfigError::Validation {
                field: "flow_export.json_lines.path".to_string(),
                message: "is empty, so the sink has nowhere to write".to_string(),
            });
        }
        if !self.path.starts_with('/') {
            return Err(ConfigError::Validation {
                field: "flow_export.json_lines.path".to_string(),
                message: format!(
                    "must be an absolute path, got '{}'; the agent's working directory \
                     is not where an operator will look for it",
                    self.path
                ),
            });
        }
        Ok(())
    }
}

/// Flow records as OTLP logs.
///
/// There is one field here and deliberately no second one: the endpoint, the
/// protocol, the headers, the certificate authority and the timeout are the
/// ones under `alerting.otlp`, because an estate running one collector should
/// not have to write its address twice and then discover, at the worst
/// moment, that the two copies disagree. Turning flows on is one switch, and
/// turning that switch on without an `alerting.otlp` block to read is
/// refused rather than quietly inert.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OtlpFlowSinkConfig {
    /// Send flow records to the collector the alerting section already
    /// names. Off by default.
    #[serde(default)]
    pub enabled: bool,
}

/// The whole section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowExportConfig {
    /// Build flow records at all. Off by default.
    #[serde(default)]
    pub enabled: bool,

    /// How long a running flow goes before a record is written for it. The
    /// cost of a longer one is how late a responder learns about a transfer
    /// that is still going.
    #[serde(default = "default_active_timeout_secs")]
    pub active_timeout_secs: u64,

    /// How long a flow goes without a change before it is treated as over.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// How many flows are held at once. Past this the flow whose last reading
    /// is oldest is written out and dropped, which is counted.
    #[serde(default = "default_table_capacity")]
    pub table_capacity: usize,

    /// Export one flow in this many. `1` exports every flow.
    ///
    /// The decision is taken once per flow, from a hash of its five-tuple, so
    /// a sampled estate shows whole conversations rather than fragments of
    /// every conversation. The rate is not on the wire: no information element
    /// expresses flow-level selection cleanly, so a collector has to be told
    /// this number before it scales a count back up.
    #[serde(default = "default_sampling")]
    pub sampling: u32,

    /// Records held between the table and the sinks.
    #[serde(default = "default_queue_depth")]
    pub queue_depth: usize,

    /// How many records a sink is handed at once.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,

    /// How often the table is asked what is due.
    #[serde(default = "default_tick_interval_secs")]
    pub tick_interval_secs: u64,

    /// IPFIX.
    #[serde(default)]
    pub ipfix: IpfixSinkConfig,

    /// OTLP logs, on the collector `alerting.otlp` already names.
    #[serde(default)]
    pub otlp: OtlpFlowSinkConfig,

    /// RFC 5424 syslog.
    #[serde(default)]
    pub syslog: SyslogSinkConfig,

    /// CEF, inside the same syslog envelope.
    #[serde(default)]
    pub cef: SyslogSinkConfig,

    /// JSON lines in a file.
    #[serde(default)]
    pub json_lines: JsonLinesSinkConfig,
}

impl Default for FlowExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            active_timeout_secs: default_active_timeout_secs(),
            idle_timeout_secs: default_idle_timeout_secs(),
            table_capacity: default_table_capacity(),
            sampling: default_sampling(),
            queue_depth: default_queue_depth(),
            batch_size: default_batch_size(),
            tick_interval_secs: default_tick_interval_secs(),
            ipfix: IpfixSinkConfig::default(),
            otlp: OtlpFlowSinkConfig::default(),
            syslog: SyslogSinkConfig::default(),
            cef: SyslogSinkConfig::default(),
            json_lines: JsonLinesSinkConfig::default(),
        }
    }
}

impl FlowExportConfig {
    /// Whether any sink is configured to receive records.
    #[must_use]
    pub fn any_sink_enabled(&self) -> bool {
        self.ipfix.enabled
            || self.otlp.enabled
            || self.syslog.enabled
            || self.cef.enabled
            || self.json_lines.enabled
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.ipfix.validate()?;
        self.syslog.validate("syslog")?;
        self.cef.validate("cef")?;
        self.json_lines.validate()?;
        if !self.enabled {
            return Ok(());
        }
        range(
            self.active_timeout_secs,
            MIN_TIMEOUT_SECS,
            MAX_TIMEOUT_SECS,
            "flow_export.active_timeout_secs",
        )?;
        range(
            self.idle_timeout_secs,
            MIN_TIMEOUT_SECS,
            MAX_TIMEOUT_SECS,
            "flow_export.idle_timeout_secs",
        )?;
        if self.idle_timeout_secs > self.active_timeout_secs {
            return Err(ConfigError::Validation {
                field: "flow_export.idle_timeout_secs".to_string(),
                message: format!(
                    "is longer than active_timeout_secs ({}), so no flow would ever \
                     reach the active timeout",
                    self.active_timeout_secs
                ),
            });
        }
        range_usize(
            self.table_capacity,
            MIN_TABLE_CAPACITY,
            MAX_TABLE_CAPACITY,
            "flow_export.table_capacity",
        )?;
        if self.sampling == 0 {
            return Err(ConfigError::Validation {
                field: "flow_export.sampling".to_string(),
                message: "must be 1 or more; 1 exports every flow".to_string(),
            });
        }
        range_usize(
            self.queue_depth,
            MIN_QUEUE_DEPTH,
            MAX_QUEUE_DEPTH,
            "flow_export.queue_depth",
        )?;
        range_usize(
            self.batch_size,
            MIN_BATCH_SIZE,
            MAX_BATCH_SIZE,
            "flow_export.batch_size",
        )?;
        range(
            self.tick_interval_secs,
            MIN_TICK_INTERVAL_SECS,
            MAX_TICK_INTERVAL_SECS,
            "flow_export.tick_interval_secs",
        )?;
        if !self.any_sink_enabled() {
            return Err(ConfigError::Validation {
                field: "flow_export.enabled".to_string(),
                message: "is on with no sink enabled, so records would be built and \
                          thrown away"
                    .to_string(),
            });
        }
        Ok(())
    }
}

fn range(value: u64, min: u64, max: u64, field: &str) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::Validation {
            field: field.to_string(),
            message: format!("must be between {min} and {max}, got {value}"),
        });
    }
    Ok(())
}

fn range_usize(value: usize, min: usize, max: usize, field: &str) -> Result<(), ConfigError> {
    if value < min || value > max {
        return Err(ConfigError::Validation {
            field: field.to_string(),
            message: format!("must be between {min} and {max}, got {value}"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> FlowExportConfig {
        FlowExportConfig {
            enabled: true,
            ipfix: IpfixSinkConfig {
                enabled: true,
                targets: vec![FlowTargetConfig {
                    address: "collector.internal:4739".to_string(),
                    transport: "udp".to_string(),
                }],
                ..IpfixSinkConfig::default()
            },
            ..FlowExportConfig::default()
        }
    }

    #[test]
    fn export_is_off_until_somebody_turns_it_on() {
        let config = FlowExportConfig::default();
        assert!(!config.enabled);
        assert!(!config.any_sink_enabled());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_empty_section_is_the_default_section() {
        let config: FlowExportConfig = serde_norway::from_str("{}").expect("empty is valid");
        assert_eq!(config.active_timeout_secs, 60);
        assert_eq!(config.idle_timeout_secs, 15);
        assert_eq!(config.sampling, 1);
        assert_eq!(config.ipfix.enterprise_number, 0);
    }

    #[test]
    fn a_configured_section_round_trips() {
        let yaml = r"
enabled: true
active_timeout_secs: 120
idle_timeout_secs: 30
sampling: 10
ipfix:
  enabled: true
  enterprise_number: 55555
  targets:
    - address: '10.0.0.9:4739'
      transport: tcp
";
        let config: FlowExportConfig = serde_norway::from_str(yaml).expect("valid");
        assert!(config.enabled);
        assert_eq!(config.active_timeout_secs, 120);
        assert_eq!(config.sampling, 10);
        assert_eq!(config.ipfix.targets.len(), 1);
        assert_eq!(config.ipfix.targets[0].transport(), FlowTransport::Tcp);
        assert_eq!(config.ipfix.enterprise_number, 55_555);
        config.validate().expect("valid");
    }

    #[test]
    fn a_target_with_no_transport_is_udp() {
        let config: FlowExportConfig =
            serde_norway::from_str("ipfix:\n  targets:\n    - address: '10.0.0.9:4739'\n")
                .expect("valid");
        assert_eq!(config.ipfix.targets[0].transport(), FlowTransport::Udp);
    }

    #[test]
    fn an_unknown_transport_is_refused_by_name() {
        let mut config = enabled();
        config.ipfix.targets[0].transport = "sctp".to_string();
        let error = config.validate().expect_err("refused");
        assert!(error.to_string().contains("udp, tcp"), "{error}");
    }

    #[test]
    fn an_address_with_no_port_is_refused() {
        let mut config = enabled();
        config.ipfix.targets[0].address = "collector.internal".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_port_of_zero_is_refused() {
        let mut config = enabled();
        config.ipfix.targets[0].address = "10.0.0.9:0".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_and_is_accepted() {
        let mut config = enabled();
        config.ipfix.targets[0].address = "[2001:db8::9]:4739".to_string();
        config
            .validate()
            .expect("a bracketed literal is an address");
    }

    #[test]
    fn a_bare_ipv6_literal_is_refused_rather_than_read_as_a_port() {
        let mut config = enabled();
        config.ipfix.targets[0].address = "2001:db8::9".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_otlp_sink_alone_is_a_sink() {
        let mut config = FlowExportConfig {
            enabled: true,
            ..FlowExportConfig::default()
        };
        config.otlp.enabled = true;
        assert!(
            config.any_sink_enabled(),
            "flows on OTLP and nothing else is still an export"
        );
        config
            .validate()
            .expect("a section with one sink enabled is complete");
    }

    #[test]
    fn an_enabled_sink_with_no_target_is_refused() {
        let mut config = enabled();
        config.ipfix.targets.clear();
        let error = config.validate().expect_err("refused");
        assert!(error.to_string().contains("nowhere to send"), "{error}");
    }

    #[test]
    fn export_on_with_every_sink_off_is_refused() {
        let mut config = enabled();
        config.ipfix.enabled = false;
        let error = config.validate().expect_err("refused");
        assert!(error.to_string().contains("no sink enabled"), "{error}");
    }

    #[test]
    fn an_idle_timeout_longer_than_the_active_one_is_refused() {
        let mut config = enabled();
        config.idle_timeout_secs = 120;
        config.active_timeout_secs = 60;
        let error = config.validate().expect_err("refused");
        assert!(error.to_string().contains("active_timeout_secs"), "{error}");
    }

    #[test]
    fn sampling_of_zero_is_refused_rather_than_read_as_everything() {
        let mut config = enabled();
        config.sampling = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_table_too_small_to_be_worth_keeping_is_refused() {
        let mut config = enabled();
        config.table_capacity = 8;
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_message_bound_below_the_minimum_is_refused() {
        let mut config = enabled();
        config.ipfix.max_message_bytes = 64;
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_disabled_section_is_not_validated_for_its_bounds() {
        let config = FlowExportConfig {
            enabled: false,
            sampling: 0,
            table_capacity: 1,
            ..FlowExportConfig::default()
        };
        config
            .validate()
            .expect("an off section is not a misconfigured one");
    }

    #[test]
    fn a_sink_is_validated_even_when_export_is_off() {
        let config = FlowExportConfig {
            enabled: false,
            ipfix: IpfixSinkConfig {
                enabled: true,
                targets: vec![FlowTargetConfig {
                    address: "nope".to_string(),
                    transport: "udp".to_string(),
                }],
                ..IpfixSinkConfig::default()
            },
            ..FlowExportConfig::default()
        };
        assert!(
            config.validate().is_err(),
            "a sink nobody can reach is wrong whether or not it runs"
        );
    }

    #[test]
    fn the_transport_words_are_the_ones_the_error_offers() {
        assert_eq!(FlowTransport::parse("UDP"), Some(FlowTransport::Udp));
        assert_eq!(FlowTransport::parse(" tcp "), Some(FlowTransport::Tcp));
        assert_eq!(FlowTransport::parse("quic"), None);
        assert_eq!(FlowTransport::Udp.as_str(), "udp");
        assert_eq!(FlowTransport::Tcp.as_str(), "tcp");
    }

    fn syslog_target(address: &str, transport: &str) -> FlowTargetConfig {
        FlowTargetConfig {
            address: address.to_string(),
            transport: transport.to_string(),
        }
    }

    fn with_syslog(targets: Vec<FlowTargetConfig>, ca_cert: Option<&str>) -> FlowExportConfig {
        FlowExportConfig {
            enabled: true,
            syslog: SyslogSinkConfig {
                enabled: true,
                targets,
                facility: 16,
                hostname: String::new(),
                ca_cert: ca_cert.map(str::to_string),
            },
            ..FlowExportConfig::default()
        }
    }

    #[test]
    fn each_text_sink_alone_is_a_sink() {
        let syslog = with_syslog(vec![syslog_target("collector:514", "udp")], None);
        assert!(syslog.any_sink_enabled());
        syslog
            .validate()
            .expect("a syslog sink with a target is valid");

        let cef = FlowExportConfig {
            enabled: true,
            cef: syslog.syslog.clone(),
            ..FlowExportConfig::default()
        };
        assert!(cef.any_sink_enabled());
        cef.validate().expect("a cef sink with a target is valid");

        let lines = FlowExportConfig {
            enabled: true,
            json_lines: JsonLinesSinkConfig {
                enabled: true,
                path: "/var/log/ebpfsentinel/flows.jsonl".to_string(),
            },
            ..FlowExportConfig::default()
        };
        assert!(lines.any_sink_enabled());
        lines.validate().expect("a file sink with a path is valid");
    }

    #[test]
    fn a_text_sink_with_no_target_is_refused_and_names_its_own_section() {
        let config = with_syslog(Vec::new(), None);
        let error = config.validate().expect_err("nowhere to send");
        assert!(
            error.to_string().contains("flow_export.syslog.targets"),
            "{error}"
        );

        let config = FlowExportConfig {
            enabled: true,
            cef: SyslogSinkConfig {
                enabled: true,
                ..SyslogSinkConfig::default()
            },
            ..FlowExportConfig::default()
        };
        let error = config.validate().expect_err("nowhere to send");
        assert!(
            error.to_string().contains("flow_export.cef.targets"),
            "{error}"
        );
    }

    #[test]
    fn the_three_transport_words_are_the_ones_a_text_sink_offers() {
        let config = with_syslog(vec![syslog_target("collector:514", "sctp")], None);
        let error = config.validate().expect_err("sctp is not a transport here");
        let message = error.to_string();
        assert!(message.contains("udp, tcp, tls"), "{message}");
        assert!(message.contains("sctp"), "{message}");
    }

    #[test]
    fn a_tls_target_is_refused_on_a_sink_that_cannot_encrypt() {
        let config = FlowExportConfig {
            enabled: true,
            ipfix: IpfixSinkConfig {
                enabled: true,
                targets: vec![syslog_target("collector:4739", "tls")],
                ..IpfixSinkConfig::default()
            },
            ..FlowExportConfig::default()
        };
        let error = config
            .validate()
            .expect_err("the ipfix encoder writes to a plain socket");
        let message = error.to_string();
        assert!(message.contains("does not speak"), "{message}");
        assert!(message.contains("udp, tcp"), "{message}");
    }

    #[test]
    fn a_tls_target_with_no_authority_is_refused_rather_than_trusting_anything() {
        let config = with_syslog(vec![syslog_target("collector:6514", "tls")], None);
        let error = config.validate().expect_err("no authority was named");
        let message = error.to_string();
        assert!(message.contains("flow_export.syslog.ca_cert"), "{message}");
        assert!(
            message.contains("not skip verification"),
            "the refusal says why rather than only what: {message}"
        );

        let config = with_syslog(
            vec![syslog_target("collector:6514", "tls")],
            Some("/etc/ebpfsentinel/syslog-ca.pem"),
        );
        config
            .validate()
            .expect("a named authority is the whole requirement");
    }

    #[test]
    fn an_unencrypted_target_needs_no_authority() {
        with_syslog(vec![syslog_target("collector:514", "udp")], None)
            .validate()
            .expect("udp asks for no certificate");
    }

    #[test]
    fn a_facility_outside_the_rfc_s_range_is_refused() {
        let mut config = with_syslog(vec![syslog_target("collector:514", "udp")], None);
        config.syslog.facility = 24;
        let error = config.validate().expect_err("the range stops at 23");
        let message = error.to_string();
        assert!(message.contains("flow_export.syslog.facility"), "{message}");
        assert!(message.contains("0 and 23"), "{message}");

        config.syslog.facility = 23;
        config.validate().expect("23 is local7");
    }

    #[test]
    fn a_file_sink_needs_an_absolute_path() {
        let mut config = FlowExportConfig {
            enabled: true,
            json_lines: JsonLinesSinkConfig {
                enabled: true,
                path: "flows.jsonl".to_string(),
            },
            ..FlowExportConfig::default()
        };
        let error = config.validate().expect_err("a relative path is refused");
        assert!(error.to_string().contains("absolute path"), "{error}");

        config.json_lines.path = "   ".to_string();
        let error = config.validate().expect_err("an empty path is refused");
        assert!(error.to_string().contains("nowhere to write"), "{error}");
    }

    #[test]
    fn a_text_sink_is_validated_even_when_export_is_off() {
        let mut config = with_syslog(vec![syslog_target("collector", "udp")], None);
        config.enabled = false;
        let error = config
            .validate()
            .expect_err("a sink pointed at a port-less address is wrong either way");
        assert!(
            error
                .to_string()
                .contains("flow_export.syslog.targets[0].address"),
            "{error}"
        );
    }

    #[test]
    fn the_defaults_of_a_text_sink_are_off_local0_and_no_authority() {
        let config: SyslogSinkConfig = serde_norway::from_str("{}").expect("empty is valid");
        assert!(!config.enabled);
        assert_eq!(config.facility, 16);
        assert!(config.hostname.is_empty());
        assert!(config.ca_cert.is_none());
        assert!(config.targets.is_empty());
    }

    #[test]
    fn a_configured_text_section_round_trips() {
        let yaml = r"
enabled: true
syslog:
  enabled: true
  facility: 1
  hostname: edge-3
  ca_cert: /etc/ebpfsentinel/ca.pem
  targets:
    - address: 'syslog.internal:6514'
      transport: tls
cef:
  enabled: true
  targets:
    - address: '10.0.0.9:514'
      transport: udp
json_lines:
  enabled: true
  path: /var/log/ebpfsentinel/flows.jsonl
";
        let config: FlowExportConfig = serde_norway::from_str(yaml).expect("valid");
        assert_eq!(config.syslog.facility, 1);
        assert_eq!(config.syslog.hostname, "edge-3");
        assert_eq!(config.syslog.targets[0].transport(), FlowTransport::Tls);
        assert!(config.syslog.targets[0].transport().is_stream());
        assert_eq!(config.cef.targets[0].transport(), FlowTransport::Udp);
        assert!(!config.cef.targets[0].transport().is_stream());
        assert_eq!(config.json_lines.path, "/var/log/ebpfsentinel/flows.jsonl");
        config.validate().expect("valid");
    }
}
