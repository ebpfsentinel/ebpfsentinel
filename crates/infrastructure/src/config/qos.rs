//! `QoS` / Traffic Shaping domain configuration structs and conversion logic.

use std::collections::{HashMap, HashSet};

use domain::qos::entity::{QosClassifier, QosDirection, QosMatchRule, QosPipe, QosQueue};
use serde::{Deserialize, Serialize};

use domain::firewall::entity::IpNetwork;

use super::common::{ConfigError, default_true, parse_cidr};

// ── Security limits ────────────────────────────────────────────────

/// Maximum `QoS` pipes.
pub(super) const MAX_QOS_PIPES: usize = 64;
/// Maximum `QoS` queues.
pub(super) const MAX_QOS_QUEUES: usize = 256;
/// Maximum `QoS` classifiers.
pub(super) const MAX_QOS_CLASSIFIERS: usize = 1024;

// ── Serde defaults ──────────────────────────────────────────────────

fn default_burst() -> String {
    "64kb".to_string()
}

fn default_priority() -> u8 {
    0
}

fn default_direction() -> String {
    "egress".to_string()
}

// ── Section config ──────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QosSectionConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub pipes: Vec<QosPipeConfig>,

    #[serde(default)]
    pub queues: Vec<QosQueueConfig>,

    #[serde(default)]
    pub classifiers: Vec<QosClassifierConfig>,
}

// ── Pipe config ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosPipeConfig {
    pub id: String,

    /// Bandwidth string: "100mbps", "1gbps", "500kbps", "1000bps".
    pub bandwidth: String,

    /// Propagation delay in milliseconds.
    #[serde(default)]
    pub delay: u32,

    /// Random loss percentage (0.0-100.0).
    #[serde(default)]
    pub loss: f32,

    /// Maximum burst size: "64kb", "1mb", "4096b".
    #[serde(default = "default_burst")]
    pub burst: String,

    /// Direction: "egress" | "ingress" | "both".
    #[serde(default = "default_direction")]
    pub direction: String,

    /// Whether this pipe is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Interface groups this pipe applies to. Empty = all (floating).
    /// Prefix with "!" for inversion (e.g., `"!lan"` = all except lan).
    #[serde(default)]
    pub interfaces: Vec<String>,

    /// Tenant this pipe shapes for. 0 (the default) is global and applies to
    /// every tenant; a standalone agent resolves nothing else, so leaving it
    /// unset keeps single-tenant behaviour.
    #[serde(default)]
    pub tenant_id: u32,
}

// ── Queue config ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosQueueConfig {
    pub id: String,

    /// Pipe this queue is attached to.
    pub pipe_id: String,

    /// Whether this queue is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ── Classifier config ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosClassifierConfig {
    pub id: String,

    /// Queue this classifier assigns traffic to.
    pub queue_id: String,

    /// Classifier priority (lower = matched first).
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Match rule for classifying traffic. Spelled `match` in YAML (the
    /// shipped examples and docs use `match:`); `match_rule` accepted as alias.
    #[serde(rename = "match", alias = "match_rule", default)]
    pub match_rule: QosMatchConfig,

    /// Interface groups this classifier applies to. Empty = all (floating).
    /// Prefix with "!" for inversion (e.g., `"!lan"` = all except lan).
    #[serde(default)]
    pub interfaces: Vec<String>,

    /// Tenant this classifier applies to. 0 (the default) is global and
    /// applies to every tenant; a standalone agent resolves nothing else, so
    /// leaving it unset keeps single-tenant behaviour.
    #[serde(default)]
    pub tenant_id: u32,
}

// ── Match config ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QosMatchConfig {
    /// Source host, as a bare address or a `/32`. Shorter prefixes and IPv6
    /// are refused: the classifier map matches one exact address.
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Destination host, same shape as [`QosMatchConfig::src_ip`].
    #[serde(default)]
    pub dst_ip: Option<String>,
    /// Source port filter.
    #[serde(default)]
    pub src_port: Option<u16>,
    /// Destination port filter.
    #[serde(default)]
    pub dst_port: Option<u16>,
    /// IP protocol: "tcp", "udp", "icmp", or numeric.
    #[serde(default)]
    pub protocol: Option<String>,
    /// DSCP value (0-63).
    #[serde(default)]
    pub dscp: Option<u8>,
    /// 802.1Q VLAN ID (0-4094): omit to match any VLAN, 0 to match untagged
    /// traffic only.
    #[serde(default)]
    pub vlan_id: Option<u16>,
}

// ── Parsing helpers ─────────────────────────────────────────────────

/// Parse a bandwidth string like "100mbps", "1gbps", "500kbps", "1000bps"
/// into bits per second (the suffixes denote bits — "mbps" = megabits/sec).
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn parse_bandwidth(s: &str) -> Result<u64, String> {
    let lower = s.to_lowercase();
    let lower = lower.trim();

    let (num_str, multiplier) = if let Some(num) = lower.strip_suffix("gbps") {
        (num, 1_000_000_000.0_f64)
    } else if let Some(num) = lower.strip_suffix("mbps") {
        (num, 1_000_000.0_f64)
    } else if let Some(num) = lower.strip_suffix("kbps") {
        (num, 1_000.0_f64)
    } else if let Some(num) = lower.strip_suffix("bps") {
        (num, 1.0_f64)
    } else {
        return Err(format!(
            "invalid bandwidth format: '{s}' (expected e.g. '100mbps', '1gbps', '500kbps', '1000bps')"
        ));
    };

    let val: f64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid bandwidth number: '{num_str}'"))?;
    if val < 0.0 {
        return Err(format!("bandwidth cannot be negative: '{s}'"));
    }
    Ok((val * multiplier) as u64)
}

/// Parse a byte size string like "64kb", "1mb", "4096b" into bytes.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn parse_bytes(s: &str) -> Result<u64, String> {
    let lower = s.to_lowercase();
    let lower = lower.trim();

    if let Some(num) = lower.strip_suffix("gb") {
        let val: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid byte size number: '{num}'"))?;
        Ok((val * 1_073_741_824.0) as u64)
    } else if let Some(num) = lower.strip_suffix("mb") {
        let val: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid byte size number: '{num}'"))?;
        Ok((val * 1_048_576.0) as u64)
    } else if let Some(num) = lower.strip_suffix("kb") {
        let val: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid byte size number: '{num}'"))?;
        Ok((val * 1024.0) as u64)
    } else if let Some(num) = lower.strip_suffix('b') {
        let val: u64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid byte size number: '{num}'"))?;
        Ok(val)
    } else {
        Err(format!(
            "invalid byte size format: '{s}' (expected e.g. '64kb', '1mb', '4096b')"
        ))
    }
}

/// Parse a direction string to a domain `QosDirection`.
pub fn parse_direction(s: &str) -> Result<QosDirection, String> {
    match s.to_lowercase().as_str() {
        "egress" | "out" | "outbound" => Ok(QosDirection::Egress),
        "ingress" | "in" | "inbound" => Ok(QosDirection::Ingress),
        "both" | "all" | "bidirectional" => Ok(QosDirection::Both),
        _ => Err(format!(
            "invalid direction: '{s}' (expected egress, ingress, or both)"
        )),
    }
}

/// Validate a classifier match address.
///
/// The classifier map is keyed by an exact IPv4 address, so a prefix shorter
/// than `/32` has nothing to match against and an IPv6 address is reduced to a
/// flow hash userspace cannot reproduce. Either would be accepted at load and
/// then shape nothing, so both are refused here with the reason.
fn validate_classifier_host(field: String, value: &str) -> Result<(), ConfigError> {
    match parse_cidr(value).map_err(|e| ConfigError::Validation {
        field: field.clone(),
        message: e.to_string(),
    })? {
        IpNetwork::V4 { prefix_len: 32, .. } => Ok(()),
        IpNetwork::V4 { prefix_len, .. } => Err(ConfigError::Validation {
            field,
            message: format!(
                "prefix /{prefix_len} cannot be enforced: QoS classifiers match one exact address, \
                 so only a single host (or /32) is accepted"
            ),
        }),
        IpNetwork::V6 { .. } => Err(ConfigError::Validation {
            field,
            message: "IPv6 addresses cannot be enforced: QoS classifiers match one exact IPv4 \
                      address, so IPv6 flows are shaped by port, protocol or DSCP rules instead"
                .to_string(),
        }),
    }
}

/// Parse a protocol string to a protocol number.
fn parse_protocol_number(s: &str) -> Result<u8, String> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "icmpv6" => Ok(58),
        _ => s
            .parse::<u8>()
            .map_err(|_| format!("invalid protocol: '{s}' (expected tcp, udp, icmp, or number)")),
    }
}

// ── Validation ──────────────────────────────────────────────────────

impl QosSectionConfig {
    /// Validate all pipes, queues, classifiers, and referential integrity.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate pipe count
        super::common::check_limit("qos.pipes", self.pipes.len(), MAX_QOS_PIPES)?;
        super::common::check_limit("qos.queues", self.queues.len(), MAX_QOS_QUEUES)?;
        super::common::check_limit(
            "qos.classifiers",
            self.classifiers.len(),
            MAX_QOS_CLASSIFIERS,
        )?;

        // Validate individual pipes
        let mut pipe_ids = HashSet::new();
        for (idx, pipe) in self.pipes.iter().enumerate() {
            pipe.validate(idx)?;
            if !pipe_ids.insert(&pipe.id) {
                return Err(ConfigError::Validation {
                    field: format!("qos.pipes[{idx}].id"),
                    message: format!("duplicate pipe ID: '{}'", pipe.id),
                });
            }
        }

        // Validate individual queues
        let mut queue_ids = HashSet::new();
        for (idx, queue) in self.queues.iter().enumerate() {
            queue.validate(idx)?;
            if !queue_ids.insert(&queue.id) {
                return Err(ConfigError::Validation {
                    field: format!("qos.queues[{idx}].id"),
                    message: format!("duplicate queue ID: '{}'", queue.id),
                });
            }
        }

        // Validate individual classifiers
        let mut classifier_ids = HashSet::new();
        for (idx, classifier) in self.classifiers.iter().enumerate() {
            classifier.validate(idx)?;
            if !classifier_ids.insert(&classifier.id) {
                return Err(ConfigError::Validation {
                    field: format!("qos.classifiers[{idx}].id"),
                    message: format!("duplicate classifier ID: '{}'", classifier.id),
                });
            }
        }

        // Referential integrity: every queue must reference an existing pipe
        for (idx, queue) in self.queues.iter().enumerate() {
            if !pipe_ids.contains(&queue.pipe_id) {
                return Err(ConfigError::Validation {
                    field: format!("qos.queues[{idx}].pipe_id"),
                    message: format!(
                        "queue '{}' references non-existent pipe '{}'",
                        queue.id, queue.pipe_id
                    ),
                });
            }
        }

        // Referential integrity: every classifier must reference an existing queue
        for (idx, classifier) in self.classifiers.iter().enumerate() {
            if !queue_ids.contains(&classifier.queue_id) {
                return Err(ConfigError::Validation {
                    field: format!("qos.classifiers[{idx}].queue_id"),
                    message: format!(
                        "classifier '{}' references non-existent queue '{}'",
                        classifier.id, classifier.queue_id
                    ),
                });
            }
        }

        Ok(())
    }

    /// Convert all pipe configs to domain `QosPipe` entities.
    pub fn to_domain_pipes(
        &self,
        group_bits: &HashMap<String, u32>,
    ) -> Result<Vec<QosPipe>, ConfigError> {
        self.pipes
            .iter()
            .map(|p| p.to_domain_pipe(group_bits))
            .collect()
    }

    /// Convert all queue configs to domain `QosQueue` entities.
    pub fn to_domain_queues(&self) -> Result<Vec<QosQueue>, ConfigError> {
        self.queues
            .iter()
            .map(QosQueueConfig::to_domain_queue)
            .collect()
    }

    /// Convert all classifier configs to domain `QosClassifier` entities.
    pub fn to_domain_classifiers(
        &self,
        group_bits: &HashMap<String, u32>,
    ) -> Result<Vec<QosClassifier>, ConfigError> {
        self.classifiers
            .iter()
            .map(|c| c.to_domain_classifier(group_bits))
            .collect()
    }
}

// ── Pipe validation & conversion ────────────────────────────────────

impl QosPipeConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("qos.pipes[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "pipe ID must not be empty".to_string(),
            });
        }

        parse_bandwidth(&self.bandwidth).map_err(|msg| ConfigError::InvalidValue {
            field: format!("{prefix}.bandwidth"),
            value: self.bandwidth.clone(),
            expected: msg,
        })?;

        if !(0.0..=100.0).contains(&self.loss) {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.loss"),
                message: format!("loss must be 0.0-100.0, got {}", self.loss),
            });
        }

        parse_bytes(&self.burst).map_err(|msg| ConfigError::InvalidValue {
            field: format!("{prefix}.burst"),
            value: self.burst.clone(),
            expected: msg,
        })?;

        parse_direction(&self.direction).map_err(|msg| ConfigError::InvalidValue {
            field: format!("{prefix}.direction"),
            value: self.direction.clone(),
            expected: msg,
        })?;

        Ok(())
    }

    /// Convert to a domain `QosPipe`. `group_bits` maps every configured
    /// interface-group name to its bit, so `interfaces` can be resolved into
    /// the mask the shaper compares against the egress interface.
    pub fn to_domain_pipe(
        &self,
        group_bits: &HashMap<String, u32>,
    ) -> Result<QosPipe, ConfigError> {
        let bandwidth_bps =
            parse_bandwidth(&self.bandwidth).map_err(|msg| ConfigError::InvalidValue {
                field: "bandwidth".to_string(),
                value: self.bandwidth.clone(),
                expected: msg,
            })?;

        let burst_bytes = parse_bytes(&self.burst).map_err(|msg| ConfigError::InvalidValue {
            field: "burst".to_string(),
            value: self.burst.clone(),
            expected: msg,
        })?;

        let direction =
            parse_direction(&self.direction).map_err(|msg| ConfigError::InvalidValue {
                field: "direction".to_string(),
                value: self.direction.clone(),
                expected: msg,
            })?;

        Ok(QosPipe {
            id: self.id.clone(),
            rate_bps: bandwidth_bps,
            burst_bytes,
            delay_ms: self.delay,
            loss_pct: self.loss,
            direction,
            enabled: self.enabled,
            group_mask: super::parse_group_mask(&self.interfaces, group_bits).map_err(
                |message| ConfigError::Validation {
                    field: "qos.pipes.interfaces".to_string(),
                    message,
                },
            )?,
            tenant_id: self.tenant_id,
        })
    }
}

// ── Queue validation & conversion ───────────────────────────────────

impl QosQueueConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("qos.queues[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "queue ID must not be empty".to_string(),
            });
        }

        if self.pipe_id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.pipe_id"),
                message: "pipe_id must not be empty".to_string(),
            });
        }

        Ok(())
    }

    pub fn to_domain_queue(&self) -> Result<QosQueue, ConfigError> {
        Ok(QosQueue {
            id: self.id.clone(),
            pipe_id: self.pipe_id.clone(),
            enabled: self.enabled,
        })
    }
}

// ── Classifier validation & conversion ──────────────────────────────

impl QosClassifierConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("qos.classifiers[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "classifier ID must not be empty".to_string(),
            });
        }

        if self.queue_id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.queue_id"),
                message: "queue_id must not be empty".to_string(),
            });
        }

        // Validate match rule addresses
        if let Some(ref src) = self.match_rule.src_ip {
            validate_classifier_host(format!("{prefix}.match_rule.src_ip"), src)?;
        }
        if let Some(ref dst) = self.match_rule.dst_ip {
            validate_classifier_host(format!("{prefix}.match_rule.dst_ip"), dst)?;
        }

        // Validate protocol
        if let Some(ref proto) = self.match_rule.protocol {
            parse_protocol_number(proto).map_err(|msg| ConfigError::InvalidValue {
                field: format!("{prefix}.match_rule.protocol"),
                value: proto.clone(),
                expected: msg,
            })?;
        }

        // Validate DSCP
        if let Some(dscp) = self.match_rule.dscp
            && dscp > 63
        {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.match_rule.dscp"),
                message: format!("DSCP must be 0-63, got {dscp}"),
            });
        }

        // Validate VLAN ID (0 selects untagged traffic, 4095 is reserved)
        if let Some(vid) = self.match_rule.vlan_id
            && vid > 4094
        {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.match_rule.vlan_id"),
                message: format!("VLAN ID must be 0-4094, got {vid}"),
            });
        }

        Ok(())
    }

    /// Convert to a domain `QosClassifier`. `group_bits` maps every configured
    /// interface-group name to its bit, so `interfaces` can be resolved into
    /// the mask the shaper compares against the egress interface.
    pub fn to_domain_classifier(
        &self,
        group_bits: &HashMap<String, u32>,
    ) -> Result<QosClassifier, ConfigError> {
        // Validate addresses (but keep as strings in domain)
        if let Some(ref src) = self.match_rule.src_ip {
            validate_classifier_host("qos.classifiers.match_rule.src_ip".to_string(), src)?;
        }
        if let Some(ref dst) = self.match_rule.dst_ip {
            validate_classifier_host("qos.classifiers.match_rule.dst_ip".to_string(), dst)?;
        }

        let protocol = self
            .match_rule
            .protocol
            .as_deref()
            .map(parse_protocol_number)
            .transpose()
            .map_err(|msg| ConfigError::InvalidValue {
                field: "match_rule.protocol".to_string(),
                value: self.match_rule.protocol.clone().unwrap_or_default(),
                expected: msg,
            })?
            .unwrap_or(0);

        Ok(QosClassifier {
            id: self.id.clone(),
            queue_id: self.queue_id.clone(),
            priority: u32::from(self.priority),
            match_rule: QosMatchRule {
                src_ip: self.match_rule.src_ip.clone(),
                dst_ip: self.match_rule.dst_ip.clone(),
                src_port: self.match_rule.src_port.unwrap_or(0),
                dst_port: self.match_rule.dst_port.unwrap_or(0),
                protocol,
                dscp: self.match_rule.dscp.unwrap_or(0),
                vlan_id: self.match_rule.vlan_id,
            },
            group_mask: super::parse_group_mask(&self.interfaces, group_bits).map_err(
                |message| ConfigError::Validation {
                    field: "qos.classifiers.interfaces".to_string(),
                    message,
                },
            )?,
            tenant_id: self.tenant_id,
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Default config ──────────────────────────────────────────────

    #[test]
    fn default_config() {
        let cfg = QosSectionConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.pipes.is_empty());
        assert!(cfg.queues.is_empty());
        assert!(cfg.classifiers.is_empty());
    }

    // ── Bandwidth parsing ───────────────────────────────────────────

    #[test]
    fn parse_bandwidth_gbps() {
        assert_eq!(parse_bandwidth("1gbps").unwrap(), 1_000_000_000);
    }

    #[test]
    fn parse_bandwidth_mbps() {
        assert_eq!(parse_bandwidth("100mbps").unwrap(), 100_000_000);
    }

    #[test]
    fn parse_bandwidth_kbps() {
        assert_eq!(parse_bandwidth("500kbps").unwrap(), 500_000);
    }

    #[test]
    fn parse_bandwidth_bps() {
        assert_eq!(parse_bandwidth("8000bps").unwrap(), 8000);
    }

    #[test]
    fn parse_bandwidth_case_insensitive() {
        assert_eq!(parse_bandwidth("1Gbps").unwrap(), 1_000_000_000);
        assert_eq!(parse_bandwidth("100MBPS").unwrap(), 100_000_000);
    }

    #[test]
    fn parse_bandwidth_invalid_format() {
        assert!(parse_bandwidth("100").is_err());
        assert!(parse_bandwidth("fast").is_err());
        assert!(parse_bandwidth("").is_err());
    }

    #[test]
    fn parse_bandwidth_invalid_number() {
        assert!(parse_bandwidth("abcmbps").is_err());
    }

    #[test]
    fn parse_bandwidth_10gbps() {
        assert_eq!(parse_bandwidth("10gbps").unwrap(), 10_000_000_000);
    }

    // ── Byte size parsing ───────────────────────────────────────────

    #[test]
    fn parse_bytes_kb() {
        assert_eq!(parse_bytes("64kb").unwrap(), 65_536);
    }

    #[test]
    fn parse_bytes_mb() {
        assert_eq!(parse_bytes("1mb").unwrap(), 1_048_576);
    }

    #[test]
    fn parse_bytes_b() {
        assert_eq!(parse_bytes("4096b").unwrap(), 4096);
    }

    #[test]
    fn parse_bytes_gb() {
        assert_eq!(parse_bytes("1gb").unwrap(), 1_073_741_824);
    }

    #[test]
    fn parse_bytes_case_insensitive() {
        assert_eq!(parse_bytes("64KB").unwrap(), 65_536);
        assert_eq!(parse_bytes("1MB").unwrap(), 1_048_576);
    }

    #[test]
    fn parse_bytes_invalid_format() {
        assert!(parse_bytes("100").is_err());
        assert!(parse_bytes("big").is_err());
    }

    #[test]
    fn parse_bytes_invalid_number() {
        assert!(parse_bytes("abckb").is_err());
    }

    // ── Direction parsing ───────────────────────────────────────────

    #[test]
    fn parse_direction_valid() {
        assert_eq!(parse_direction("egress").unwrap(), QosDirection::Egress);
        assert_eq!(parse_direction("ingress").unwrap(), QosDirection::Ingress);
        assert_eq!(parse_direction("both").unwrap(), QosDirection::Both);
        assert_eq!(parse_direction("out").unwrap(), QosDirection::Egress);
        assert_eq!(parse_direction("in").unwrap(), QosDirection::Ingress);
        assert_eq!(parse_direction("all").unwrap(), QosDirection::Both);
    }

    #[test]
    fn parse_direction_case_insensitive() {
        assert_eq!(parse_direction("EGRESS").unwrap(), QosDirection::Egress);
    }

    #[test]
    fn parse_direction_invalid() {
        assert!(parse_direction("sideways").is_err());
    }

    // ── Scheduler parsing ───────────────────────────────────────────

    // ── Pipe validation ─────────────────────────────────────────────

    fn valid_pipe_yaml() -> QosPipeConfig {
        serde_yaml_ng::from_str(
            r"
id: pipe-1
bandwidth: 100mbps
delay: 10
loss: 0.5
burst: 64kb
priority: 0
direction: egress
",
        )
        .unwrap()
    }

    #[test]
    fn pipe_validate_ok() {
        valid_pipe_yaml().validate(0).unwrap();
    }

    #[test]
    fn pipe_validate_empty_id() {
        let mut pipe = valid_pipe_yaml();
        pipe.id = String::new();
        assert!(pipe.validate(0).is_err());
    }

    #[test]
    fn pipe_validate_invalid_bandwidth() {
        let mut pipe = valid_pipe_yaml();
        pipe.bandwidth = "fast".to_string();
        assert!(pipe.validate(0).is_err());
    }

    #[test]
    fn pipe_validate_loss_too_high() {
        let mut pipe = valid_pipe_yaml();
        pipe.loss = 101.0;
        assert!(pipe.validate(0).is_err());
    }

    #[test]
    fn pipe_validate_loss_negative() {
        let mut pipe = valid_pipe_yaml();
        pipe.loss = -1.0;
        assert!(pipe.validate(0).is_err());
    }

    #[test]
    fn pipe_validate_invalid_burst() {
        let mut pipe = valid_pipe_yaml();
        pipe.burst = "lots".to_string();
        assert!(pipe.validate(0).is_err());
    }

    #[test]
    fn pipe_validate_invalid_direction() {
        let mut pipe = valid_pipe_yaml();
        pipe.direction = "sideways".to_string();
        assert!(pipe.validate(0).is_err());
    }

    // ── Queue validation ────────────────────────────────────────────

    fn valid_queue_yaml() -> QosQueueConfig {
        serde_yaml_ng::from_str(
            r"
id: q-1
pipe_id: pipe-1
",
        )
        .unwrap()
    }

    #[test]
    fn queue_validate_ok() {
        valid_queue_yaml().validate(0).unwrap();
    }

    #[test]
    fn queue_validate_empty_id() {
        let mut q = valid_queue_yaml();
        q.id = String::new();
        assert!(q.validate(0).is_err());
    }

    #[test]
    fn queue_validate_empty_pipe_id() {
        let mut q = valid_queue_yaml();
        q.pipe_id = String::new();
        assert!(q.validate(0).is_err());
    }

    // ── Classifier validation ───────────────────────────────────────

    fn valid_classifier_yaml() -> QosClassifierConfig {
        serde_yaml_ng::from_str(
            r"
id: cls-1
queue_id: q-1
priority: 0
match_rule:
  dst_port: 443
  protocol: tcp
",
        )
        .unwrap()
    }

    #[test]
    fn classifier_validate_ok() {
        valid_classifier_yaml().validate(0).unwrap();
    }

    #[test]
    fn classifier_validate_empty_id() {
        let mut c = valid_classifier_yaml();
        c.id = String::new();
        assert!(c.validate(0).is_err());
    }

    #[test]
    fn classifier_validate_empty_queue_id() {
        let mut c = valid_classifier_yaml();
        c.queue_id = String::new();
        assert!(c.validate(0).is_err());
    }

    #[test]
    fn classifier_validate_invalid_src_ip() {
        let mut c = valid_classifier_yaml();
        c.match_rule.src_ip = Some("not-a-cidr".to_string());
        assert!(c.validate(0).is_err());
    }

    #[test]
    fn classifier_accepts_a_single_host() {
        let mut c = valid_classifier_yaml();
        c.match_rule.src_ip = Some("10.0.0.7".to_string());
        c.validate(0).unwrap();

        c.match_rule.src_ip = Some("10.0.0.7/32".to_string());
        c.validate(0).unwrap();
    }

    #[test]
    fn classifier_refuses_a_prefix_it_cannot_enforce() {
        let mut c = valid_classifier_yaml();
        c.match_rule.src_ip = Some("10.0.0.0/8".to_string());
        assert!(c.validate(0).is_err());

        let mut c = valid_classifier_yaml();
        c.match_rule.dst_ip = Some("192.168.1.0/24".to_string());
        assert!(c.validate(0).is_err());
    }

    #[test]
    fn classifier_refuses_an_ipv6_host() {
        let mut c = valid_classifier_yaml();
        c.match_rule.dst_ip = Some("2001:db8::1".to_string());
        assert!(c.validate(0).is_err());
    }

    #[test]
    fn classifier_validate_invalid_protocol() {
        let mut c = valid_classifier_yaml();
        c.match_rule.protocol = Some("magic".to_string());
        assert!(c.validate(0).is_err());
    }

    #[test]
    fn classifier_validate_dscp_too_high() {
        let mut c = valid_classifier_yaml();
        c.match_rule.dscp = Some(64);
        assert!(c.validate(0).is_err());
    }

    #[test]
    fn classifier_validate_valid_dscp() {
        let mut c = valid_classifier_yaml();
        c.match_rule.dscp = Some(46);
        c.validate(0).unwrap();
    }

    // ── Section validation (referential integrity) ──────────────────

    fn valid_section_yaml() -> QosSectionConfig {
        serde_yaml_ng::from_str(
            r"
enabled: true
pipes:
  - id: pipe-1
    bandwidth: 100mbps
    burst: 64kb
queues:
  - id: q-1
    pipe_id: pipe-1
classifiers:
  - id: cls-1
    queue_id: q-1
    match_rule:
      dst_port: 443
      protocol: tcp
",
        )
        .unwrap()
    }

    #[test]
    fn section_validate_ok() {
        valid_section_yaml().validate().unwrap();
    }

    #[test]
    fn section_validate_duplicate_pipe_id() {
        let mut cfg = valid_section_yaml();
        cfg.pipes.push(cfg.pipes[0].clone());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn section_validate_duplicate_queue_id() {
        let mut cfg = valid_section_yaml();
        cfg.queues.push(cfg.queues[0].clone());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn section_validate_duplicate_classifier_id() {
        let mut cfg = valid_section_yaml();
        cfg.classifiers.push(cfg.classifiers[0].clone());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn section_validate_orphaned_queue() {
        let mut cfg = valid_section_yaml();
        cfg.queues[0].pipe_id = "nonexistent".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn section_validate_orphaned_classifier() {
        let mut cfg = valid_section_yaml();
        cfg.classifiers[0].queue_id = "nonexistent".to_string();
        assert!(cfg.validate().is_err());
    }

    // ── to_domain conversions ───────────────────────────────────────

    #[test]
    fn to_domain_pipe_correct_conversion() {
        let pipe: QosPipeConfig = serde_yaml_ng::from_str(
            r"
id: pipe-test
bandwidth: 1gbps
delay: 20
loss: 1.5
burst: 1mb
priority: 5
direction: both
",
        )
        .unwrap();

        let domain = pipe.to_domain_pipe(&HashMap::new()).unwrap();
        assert_eq!(domain.id, "pipe-test");
        assert_eq!(domain.rate_bps, 1_000_000_000);
        assert_eq!(domain.delay_ms, 20);
        assert!((domain.loss_pct - 1.5).abs() < f32::EPSILON);
        assert_eq!(domain.burst_bytes, 1_048_576);
        assert_eq!(domain.direction, QosDirection::Both);
        assert!(domain.enabled);
    }

    #[test]
    fn to_domain_pipe_and_classifier_carry_the_configured_tenant() {
        let pipe: QosPipeConfig = serde_yaml_ng::from_str(
            r"
id: pipe-tenant
bandwidth: 1gbps
tenant_id: 6
",
        )
        .unwrap();
        assert_eq!(pipe.to_domain_pipe(&HashMap::new()).unwrap().tenant_id, 6);

        let cls: QosClassifierConfig = serde_yaml_ng::from_str(
            r"
id: cls-tenant
queue_id: q-1
tenant_id: 6
",
        )
        .unwrap();
        assert_eq!(
            cls.to_domain_classifier(&HashMap::new()).unwrap().tenant_id,
            6
        );
    }

    #[test]
    fn to_domain_queue_correct_conversion() {
        let q: QosQueueConfig = serde_yaml_ng::from_str(
            r"
id: q-test
pipe_id: pipe-1
",
        )
        .unwrap();

        let domain = q.to_domain_queue().unwrap();
        assert_eq!(domain.id, "q-test");
        assert_eq!(domain.pipe_id, "pipe-1");
        assert!(domain.enabled);
    }

    #[test]
    fn to_domain_classifier_correct_conversion() {
        let c: QosClassifierConfig = serde_yaml_ng::from_str(
            r#"
id: cls-test
queue_id: q-1
priority: 3
match_rule:
  src_ip: "10.0.0.7"
  dst_port: 443
  protocol: tcp
  dscp: 46
"#,
        )
        .unwrap();

        let domain = c.to_domain_classifier(&HashMap::new()).unwrap();
        assert_eq!(domain.id, "cls-test");
        assert_eq!(domain.queue_id, "q-1");
        assert_eq!(domain.priority, 3);
        assert!(domain.match_rule.src_ip.is_some());
        assert_eq!(domain.match_rule.dst_port, 443);
        assert_eq!(domain.match_rule.protocol, 6); // TCP
        assert_eq!(domain.match_rule.dscp, 46);
    }

    #[test]
    fn to_domain_classifier_all_wildcards() {
        let c: QosClassifierConfig = serde_yaml_ng::from_str(
            r"
id: cls-wild
queue_id: q-1
",
        )
        .unwrap();

        let domain = c.to_domain_classifier(&HashMap::new()).unwrap();
        assert!(domain.match_rule.src_ip.is_none());
        assert!(domain.match_rule.dst_ip.is_none());
        assert_eq!(domain.match_rule.src_port, 0);
        assert_eq!(domain.match_rule.dst_port, 0);
        assert_eq!(domain.match_rule.protocol, 0);
        assert_eq!(domain.match_rule.dscp, 0);
        assert_eq!(domain.match_rule.vlan_id, None);
    }

    #[test]
    fn to_domain_pipes_from_section() {
        let cfg = valid_section_yaml();
        let pipes = cfg.to_domain_pipes(&HashMap::new()).unwrap();
        assert_eq!(pipes.len(), 1);
        assert_eq!(pipes[0].id, "pipe-1");
    }

    #[test]
    fn to_domain_queues_from_section() {
        let cfg = valid_section_yaml();
        let queues = cfg.to_domain_queues().unwrap();
        assert_eq!(queues.len(), 1);
        assert_eq!(queues[0].id, "q-1");
    }

    #[test]
    fn to_domain_classifiers_from_section() {
        let cfg = valid_section_yaml();
        let classifiers = cfg.to_domain_classifiers(&HashMap::new()).unwrap();
        assert_eq!(classifiers.len(), 1);
        assert_eq!(classifiers[0].id, "cls-1");
    }

    // ── Protocol number parsing ─────────────────────────────────────

    #[test]
    fn protocol_number_named() {
        assert_eq!(parse_protocol_number("tcp").unwrap(), 6);
        assert_eq!(parse_protocol_number("udp").unwrap(), 17);
        assert_eq!(parse_protocol_number("icmp").unwrap(), 1);
        assert_eq!(parse_protocol_number("icmpv6").unwrap(), 58);
    }

    #[test]
    fn protocol_number_numeric() {
        assert_eq!(parse_protocol_number("6").unwrap(), 6);
        assert_eq!(parse_protocol_number("17").unwrap(), 17);
    }

    #[test]
    fn protocol_number_invalid() {
        assert!(parse_protocol_number("magic").is_err());
    }

    // ── Pipe defaults from serde ────────────────────────────────────

    #[test]
    fn pipe_serde_defaults() {
        let pipe: QosPipeConfig = serde_yaml_ng::from_str(
            r"
id: pipe-1
bandwidth: 100mbps
",
        )
        .unwrap();
        assert_eq!(pipe.delay, 0);
        assert!(pipe.loss.abs() < f32::EPSILON);
        assert_eq!(pipe.burst, "64kb");
        assert_eq!(pipe.direction, "egress");
        assert!(pipe.enabled);
    }

    // ── Queue defaults from serde ───────────────────────────────────

    #[test]
    fn queue_serde_defaults() {
        let q: QosQueueConfig = serde_yaml_ng::from_str(
            r"
id: q-1
pipe_id: pipe-1
",
        )
        .unwrap();
        assert!(q.enabled);
    }
}
