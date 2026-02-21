use serde::{Deserialize, Serialize};

use crate::common::entity::{DomainMode, Protocol, RuleId, Severity};
use ebpf_common::event::PacketEvent;
use ebpf_common::ids::{IDS_ACTION_ALERT, IDS_ACTION_DROP, IdsPatternKey, IdsPatternValue};

// ── Domain matching ─────────────────────────────────────────────

/// How to match the `domain_pattern` field of an IDS rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainMatchMode {
    /// Case-insensitive exact match.
    Exact,
    /// Wildcard prefix match via `DomainPattern` (e.g. `*.evil.com`).
    Wildcard,
    /// Full regex match (compiled with `DoS` limits).
    Regex,
}

// ── Sampling ─────────────────────────────────────────────────────

/// Configurable event sampling to reduce processing load.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum SamplingMode {
    /// Process all events (default).
    #[default]
    None,
    /// Probabilistic sampling: each event has `rate` chance (0.0-1.0) of being processed.
    Random { rate: f64 },
    /// Deterministic per-flow sampling: hash of `src_ip` ^ `dst_ip` determines selection.
    Hash { rate: f64 },
}

impl SamplingMode {
    /// Returns `true` if this event should be processed (not sampled out).
    pub fn should_process(&self, src_ip: u32, dst_ip: u32) -> bool {
        match self {
            Self::None => true,
            Self::Random { rate } => {
                let hash = (src_ip ^ dst_ip)
                    .wrapping_mul(2_654_435_761)
                    .wrapping_add(src_ip.wrapping_mul(17));
                let normalized = f64::from(hash) / f64::from(u32::MAX);
                normalized < *rate
            }
            Self::Hash { rate } => {
                let hash = (src_ip ^ dst_ip).wrapping_mul(2_654_435_761);
                let normalized = f64::from(hash) / f64::from(u32::MAX);
                normalized < *rate
            }
        }
    }

    /// Validate the sampling configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::None => Ok(()),
            Self::Random { rate } | Self::Hash { rate } => {
                if (0.0..=1.0).contains(rate) {
                    Ok(())
                } else {
                    Err("sampling rate must be between 0.0 and 1.0")
                }
            }
        }
    }
}

// ── Threshold detection ──────────────────────────────────────────

/// How alert suppression/aggregation works for threshold detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdType {
    /// Alert the first `count` times per window, then suppress.
    Limit,
    /// Alert every `count`-th occurrence.
    Threshold,
    /// After `count` occurrences, alert once per window.
    Both,
}

/// Which IP address to use as the tracking key for threshold state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackBy {
    SrcIp,
    DstIp,
    Both,
}

/// Per-rule threshold configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdConfig {
    pub threshold_type: ThresholdType,
    pub count: u32,
    pub window_secs: u64,
    pub track_by: TrackBy,
}

impl TrackBy {
    /// Compute a tracking key from source and destination IPs.
    pub fn track_key(&self, src_ip: u32, dst_ip: u32) -> u64 {
        match self {
            Self::SrcIp => u64::from(src_ip),
            Self::DstIp => u64::from(dst_ip),
            Self::Both => (u64::from(src_ip) << 32) | u64::from(dst_ip),
        }
    }
}

/// An IDS rule defining what traffic to detect and how to respond.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    pub id: RuleId,
    pub description: String,
    pub severity: Severity,
    pub mode: DomainMode,
    pub protocol: Protocol,
    pub dst_port: Option<u16>,
    pub pattern: String,
    pub enabled: bool,
    /// Optional per-rule threshold/rate detection.
    #[serde(skip)]
    pub threshold: Option<ThresholdConfig>,
    /// Optional domain pattern for userspace domain-aware matching.
    /// When set, the engine matches resolved domains for the destination IP.
    #[serde(default)]
    pub domain_pattern: Option<String>,
    /// How to interpret `domain_pattern`. Required when `domain_pattern` is set.
    #[serde(default)]
    pub domain_match_mode: Option<DomainMatchMode>,
}

impl IdsRule {
    /// Validate the rule fields.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.id.validate()?;
        if let Some(port) = self.dst_port
            && port == 0
        {
            return Err("dst_port must be > 0");
        }
        // domain_pattern and domain_match_mode must be set together
        match (&self.domain_pattern, &self.domain_match_mode) {
            (Some(_), None) => {
                return Err("domain_match_mode is required when domain_pattern is set");
            }
            (None, Some(_)) => {
                return Err("domain_pattern is required when domain_match_mode is set");
            }
            (Some(pat), Some(_)) if pat.is_empty() => {
                return Err("domain_pattern must not be empty");
            }
            _ => {}
        }
        Ok(())
    }

    /// Convert to an eBPF map key for the `IDS_PATTERNS` `HashMap`.
    /// Returns `None` if `dst_port` is not set (wildcard rules cannot be
    /// represented in the exact-match eBPF `HashMap`).
    pub fn to_ebpf_key(&self) -> Option<IdsPatternKey> {
        let dst_port = self.dst_port?;
        Some(IdsPatternKey {
            dst_port,
            protocol: self.protocol.to_u8(),
            _padding: 0,
        })
    }

    /// Convert to an eBPF map value for the `IDS_PATTERNS` `HashMap`.
    /// `rule_index` is the position in the engine's rule list, used as
    /// the `rule_id` in the eBPF value for event correlation.
    pub fn to_ebpf_value(&self, rule_index: u32) -> IdsPatternValue {
        IdsPatternValue {
            action: match self.mode {
                DomainMode::Alert => IDS_ACTION_ALERT,
                DomainMode::Block => IDS_ACTION_DROP,
            },
            severity: self.severity.to_u8(),
            _padding: [0; 2],
            rule_id: rule_index,
        }
    }
}

/// Domain-level IDS alert produced when an event matches a loaded rule.
/// Captures the full packet context from the `PacketEvent` plus the
/// matched rule's metadata for downstream alert routing.
#[derive(Debug, Clone)]
pub struct IdsAlert {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub mode: DomainMode,
    /// Source address: `[v4, 0, 0, 0]` for IPv4, full 128-bit for IPv6.
    pub src_addr: [u32; 4],
    /// Destination address: same encoding as `src_addr`.
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// `true` if the addresses are IPv6.
    pub is_ipv6: bool,
    pub rule_index: u32,
    pub timestamp_ns: u64,
    /// Domain that matched a domain-aware rule (if any).
    pub matched_domain: Option<String>,
}

impl IdsAlert {
    /// Create an alert from a kernel event and the matched IDS rule.
    pub fn from_event(event: &PacketEvent, rule: &IdsRule) -> Self {
        Self {
            rule_id: rule.id.clone(),
            severity: rule.severity,
            mode: rule.mode,
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            is_ipv6: event.is_ipv6(),
            rule_index: event.rule_id,
            timestamp_ns: event.timestamp_ns,
            matched_domain: None,
        }
    }

    /// Returns the source IPv4 address (first element of `src_addr`).
    pub fn src_ip(&self) -> u32 {
        self.src_addr[0]
    }

    /// Returns the destination IPv4 address (first element of `dst_addr`).
    pub fn dst_ip(&self) -> u32 {
        self.dst_addr[0]
    }
}

/// Result of evaluating a packet against an IDS rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub matched_pattern: String,
    pub action: DomainMode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::event::EVENT_TYPE_IDS;

    fn sample_event() -> PacketEvent {
        PacketEvent {
            timestamp_ns: 1_000_000_000,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            event_type: EVENT_TYPE_IDS,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
        }
    }

    fn sample_rule() -> IdsRule {
        IdsRule {
            id: RuleId("ids-001".to_string()),
            description: "Detect SSH bruteforce".to_string(),
            severity: Severity::High,
            mode: DomainMode::Alert,
            protocol: Protocol::Tcp,
            dst_port: Some(22),
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
        }
    }

    #[test]
    fn ids_rule_validate_ok() {
        assert!(sample_rule().validate().is_ok());
    }

    #[test]
    fn ids_rule_validate_empty_id() {
        let mut rule = sample_rule();
        rule.id = RuleId(String::new());
        assert!(rule.validate().is_err());
    }

    #[test]
    fn ids_rule_validate_zero_port() {
        let mut rule = sample_rule();
        rule.dst_port = Some(0);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn ids_rule_validate_no_port() {
        let mut rule = sample_rule();
        rule.dst_port = None;
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn ids_rule_validate_domain_pattern_without_mode() {
        let mut rule = sample_rule();
        rule.domain_pattern = Some("evil.com".to_string());
        rule.domain_match_mode = None;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn ids_rule_validate_domain_mode_without_pattern() {
        let mut rule = sample_rule();
        rule.domain_pattern = None;
        rule.domain_match_mode = Some(DomainMatchMode::Exact);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn ids_rule_validate_empty_domain_pattern() {
        let mut rule = sample_rule();
        rule.domain_pattern = Some(String::new());
        rule.domain_match_mode = Some(DomainMatchMode::Exact);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn ids_rule_validate_domain_both_set_ok() {
        let mut rule = sample_rule();
        rule.domain_pattern = Some("evil.com".to_string());
        rule.domain_match_mode = Some(DomainMatchMode::Exact);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn ids_rule_to_ebpf_key_with_port() {
        let rule = sample_rule();
        let key = rule.to_ebpf_key().unwrap();
        assert_eq!(key.dst_port, 22);
        assert_eq!(key.protocol, 6); // TCP
    }

    #[test]
    fn ids_rule_to_ebpf_key_no_port_returns_none() {
        let mut rule = sample_rule();
        rule.dst_port = None;
        assert!(rule.to_ebpf_key().is_none());
    }

    #[test]
    fn ids_rule_to_ebpf_value_alert() {
        let rule = sample_rule();
        let val = rule.to_ebpf_value(42);
        assert_eq!(val.action, IDS_ACTION_ALERT);
        assert_eq!(val.severity, Severity::High.to_u8());
        assert_eq!(val.rule_id, 42);
    }

    #[test]
    fn ids_rule_to_ebpf_value_block() {
        let mut rule = sample_rule();
        rule.mode = DomainMode::Block;
        let val = rule.to_ebpf_value(0);
        assert_eq!(val.action, IDS_ACTION_DROP);
    }

    // ── IdsAlert tests ──────────────────────────────────────────

    #[test]
    fn ids_alert_from_event_maps_fields() {
        let event = sample_event();
        let rule = sample_rule();
        let alert = IdsAlert::from_event(&event, &rule);

        assert_eq!(alert.rule_id, rule.id);
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.mode, DomainMode::Alert);
        assert_eq!(alert.src_ip(), 0xC0A8_0001);
        assert_eq!(alert.dst_ip(), 0x0A00_0001);
        assert_eq!(alert.src_port, 12345);
        assert_eq!(alert.dst_port, 22);
        assert_eq!(alert.protocol, 6);
        assert!(!alert.is_ipv6);
        assert_eq!(alert.rule_index, 0);
        assert_eq!(alert.timestamp_ns, 1_000_000_000);
    }

    #[test]
    fn ids_alert_from_event_uses_rule_metadata() {
        let mut event = sample_event();
        event.rule_id = 5;
        let mut rule = sample_rule();
        rule.severity = Severity::Critical;
        rule.mode = DomainMode::Block;
        let alert = IdsAlert::from_event(&event, &rule);

        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.mode, DomainMode::Block);
        assert_eq!(alert.rule_index, 5);
    }

    #[test]
    fn match_result_fields() {
        let result = MatchResult {
            rule_id: RuleId("ids-001".to_string()),
            severity: Severity::Critical,
            matched_pattern: "port 4444".to_string(),
            action: DomainMode::Block,
        };
        assert_eq!(result.rule_id.0, "ids-001");
        assert_eq!(result.severity, Severity::Critical);
        assert_eq!(result.action, DomainMode::Block);
    }

    // ── SamplingMode tests ──────────────────────────────────────

    #[test]
    fn sampling_none_always_processes() {
        let mode = SamplingMode::None;
        for i in 0..100u32 {
            assert!(mode.should_process(i, i + 1));
        }
    }

    #[test]
    fn sampling_random_rate_zero_never_processes() {
        let mode = SamplingMode::Random { rate: 0.0 };
        for i in 0..100u32 {
            assert!(!mode.should_process(i, i + 1));
        }
    }

    #[test]
    fn sampling_random_rate_one_always_processes() {
        let mode = SamplingMode::Random { rate: 1.0 };
        for i in 0..100u32 {
            assert!(mode.should_process(i, i + 1));
        }
    }

    #[test]
    fn sampling_hash_deterministic_for_same_ips() {
        let mode = SamplingMode::Hash { rate: 0.5 };
        let result1 = mode.should_process(0xC0A8_0001, 0x0A00_0001);
        let result2 = mode.should_process(0xC0A8_0001, 0x0A00_0001);
        assert_eq!(result1, result2);
    }

    #[test]
    fn sampling_hash_rate_zero_never_processes() {
        let mode = SamplingMode::Hash { rate: 0.0 };
        for i in 0..100u32 {
            assert!(!mode.should_process(i, i + 1));
        }
    }

    #[test]
    fn sampling_hash_rate_one_always_processes() {
        let mode = SamplingMode::Hash { rate: 1.0 };
        for i in 0..100u32 {
            assert!(mode.should_process(i, i + 1));
        }
    }

    #[test]
    fn sampling_validate_none_ok() {
        assert!(SamplingMode::None.validate().is_ok());
    }

    #[test]
    fn sampling_validate_valid_rate() {
        assert!(SamplingMode::Random { rate: 0.5 }.validate().is_ok());
        assert!(SamplingMode::Hash { rate: 0.0 }.validate().is_ok());
        assert!(SamplingMode::Hash { rate: 1.0 }.validate().is_ok());
    }

    #[test]
    fn sampling_validate_invalid_rate() {
        assert!(SamplingMode::Random { rate: -0.1 }.validate().is_err());
        assert!(SamplingMode::Random { rate: 1.1 }.validate().is_err());
        assert!(SamplingMode::Hash { rate: 2.0 }.validate().is_err());
    }

    #[test]
    fn sampling_default_is_none() {
        assert_eq!(SamplingMode::default(), SamplingMode::None);
    }

    // ── TrackBy tests ──────────────────────────────────────────

    #[test]
    fn track_by_src_ip() {
        assert_eq!(TrackBy::SrcIp.track_key(100, 200), 100);
    }

    #[test]
    fn track_by_dst_ip() {
        assert_eq!(TrackBy::DstIp.track_key(100, 200), 200);
    }

    #[test]
    fn track_by_both() {
        let key = TrackBy::Both.track_key(1, 2);
        assert_eq!(key, (1u64 << 32) | 2);
    }
}
