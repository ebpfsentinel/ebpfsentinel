//! `DDoS` detection and mitigation configuration.

use domain::common::entity::RuleId;
use domain::ddos::entity::{DdosAttackType, DdosMitigationAction, DdosPolicy};
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};

/// Maximum number of `DDoS` policies.
pub(super) const MAX_DDOS_POLICIES: usize = 100;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DdosConfig {
    #[serde(default)]
    pub enabled: bool,

    /// SYN flood protection settings (eBPF-side).
    #[serde(default)]
    pub syn_protection: SynProtectionConfig,

    /// ICMP flood protection settings (eBPF-side).
    #[serde(default)]
    pub icmp_protection: IcmpProtectionConfig,

    /// UDP amplification protection settings (eBPF-side).
    #[serde(default)]
    pub amplification_protection: AmpProtectionConfig,

    /// TCP connection tracking settings (eBPF-side).
    #[serde(default)]
    pub connection_tracking: ConnTrackSectionConfig,

    /// Detection policies (userspace domain engine).
    #[serde(default)]
    pub policies: Vec<DdosPolicyConfig>,
}

// ── SYN Protection ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynProtectionConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Use threshold mode (only activate when SYN rate exceeds threshold).
    #[serde(default = "default_true")]
    pub threshold_mode: bool,

    /// SYN packets per second threshold (only in threshold mode).
    #[serde(default = "default_syn_threshold")]
    pub threshold_pps: u64,
}

fn default_syn_threshold() -> u64 {
    10_000
}

impl Default for SynProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold_mode: true,
            threshold_pps: default_syn_threshold(),
        }
    }
}

// ── ICMP Protection ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpProtectionConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Maximum ICMP echo requests per second per source IP.
    #[serde(default = "default_icmp_max_pps")]
    pub max_pps: u32,

    /// Maximum ICMP payload size in bytes.
    #[serde(default = "default_icmp_max_payload")]
    pub max_payload_size: u16,
}

fn default_icmp_max_pps() -> u32 {
    10
}

fn default_icmp_max_payload() -> u16 {
    64
}

impl Default for IcmpProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_pps: default_icmp_max_pps(),
            max_payload_size: default_icmp_max_payload(),
        }
    }
}

// ── Amplification Protection ────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AmpProtectionConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub ports: Vec<AmpPortConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmpPortConfig {
    pub port: u16,

    #[serde(default = "default_amp_protocol")]
    pub protocol: String,

    /// Maximum packets per second from this source port per destination.
    pub max_pps: u32,
}

fn default_amp_protocol() -> String {
    "udp".to_string()
}

// ── Connection Tracking ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnTrackSectionConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Max half-open connections per source before dropping new SYNs.
    #[serde(default = "default_half_open_threshold")]
    pub half_open_threshold: u32,

    /// Max RST packets per source per second.
    #[serde(default = "default_flood_threshold")]
    pub rst_threshold: u32,

    /// Max FIN packets per source per second.
    #[serde(default = "default_flood_threshold")]
    pub fin_threshold: u32,

    /// Max ACK packets (to non-existent connections) per source per second.
    #[serde(default = "default_ack_threshold")]
    pub ack_threshold: u32,
}

fn default_half_open_threshold() -> u32 {
    100
}

fn default_flood_threshold() -> u32 {
    50
}

fn default_ack_threshold() -> u32 {
    200
}

impl Default for ConnTrackSectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            half_open_threshold: default_half_open_threshold(),
            rst_threshold: default_flood_threshold(),
            fin_threshold: default_flood_threshold(),
            ack_threshold: default_ack_threshold(),
        }
    }
}

// ── DDoS Policy Config ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosPolicyConfig {
    pub id: String,

    /// Attack type: `syn_flood`, `udp_amplification`, `icmp_flood`, etc.
    pub attack_type: String,

    /// Packets per second threshold to trigger detection.
    pub detection_threshold_pps: u64,

    /// Action when attack is detected: alert, throttle, block.
    #[serde(default = "default_mitigation_action")]
    pub mitigation_action: String,

    /// Duration in seconds to auto-block sources (0 = indefinite).
    #[serde(default = "default_auto_block_duration")]
    pub auto_block_duration_secs: u64,

    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_mitigation_action() -> String {
    "alert".to_string()
}

fn default_auto_block_duration() -> u64 {
    300
}

impl DdosPolicyConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("ddos.policies[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "policy ID must not be empty".to_string(),
            });
        }

        if self.detection_threshold_pps == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.detection_threshold_pps"),
                message: "threshold must be > 0".to_string(),
            });
        }

        parse_attack_type(&self.attack_type).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.attack_type"),
            value: self.attack_type.clone(),
            expected: "syn_flood, udp_amplification, icmp_flood, rst_flood, fin_flood, ack_flood, volumetric".to_string(),
        })?;

        parse_mitigation_action(&self.mitigation_action).map_err(|()| {
            ConfigError::InvalidValue {
                field: format!("{prefix}.mitigation_action"),
                value: self.mitigation_action.clone(),
                expected: "alert, throttle, block".to_string(),
            }
        })?;

        Ok(())
    }

    pub fn to_domain_policy(&self) -> Result<DdosPolicy, ConfigError> {
        let attack_type =
            parse_attack_type(&self.attack_type).map_err(|()| ConfigError::InvalidValue {
                field: "attack_type".to_string(),
                value: self.attack_type.clone(),
                expected: "syn_flood, udp_amplification, icmp_flood, rst_flood, fin_flood, ack_flood, volumetric".to_string(),
            })?;

        let mitigation_action = parse_mitigation_action(&self.mitigation_action).map_err(|()| {
            ConfigError::InvalidValue {
                field: "mitigation_action".to_string(),
                value: self.mitigation_action.clone(),
                expected: "alert, throttle, block".to_string(),
            }
        })?;

        Ok(DdosPolicy {
            id: RuleId(self.id.clone()),
            attack_type,
            detection_threshold_pps: self.detection_threshold_pps,
            mitigation_action,
            auto_block_duration_secs: self.auto_block_duration_secs,
            enabled: self.enabled,
        })
    }
}

fn parse_attack_type(s: &str) -> Result<DdosAttackType, ()> {
    match s.to_lowercase().as_str() {
        "syn_flood" | "synflood" => Ok(DdosAttackType::SynFlood),
        "udp_amplification" | "udpamplification" => Ok(DdosAttackType::UdpAmplification),
        "icmp_flood" | "icmpflood" => Ok(DdosAttackType::IcmpFlood),
        "rst_flood" | "rstflood" => Ok(DdosAttackType::RstFlood),
        "fin_flood" | "finflood" => Ok(DdosAttackType::FinFlood),
        "ack_flood" | "ackflood" => Ok(DdosAttackType::AckFlood),
        "volumetric" => Ok(DdosAttackType::Volumetric),
        _ => Err(()),
    }
}

fn parse_mitigation_action(s: &str) -> Result<DdosMitigationAction, ()> {
    match s.to_lowercase().as_str() {
        "alert" | "log" => Ok(DdosMitigationAction::Alert),
        "throttle" | "ratelimit" => Ok(DdosMitigationAction::Throttle),
        "block" | "drop" | "deny" => Ok(DdosMitigationAction::Block),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_policy_config() -> DdosPolicyConfig {
        DdosPolicyConfig {
            id: "syn-flood-1".to_string(),
            attack_type: "syn_flood".to_string(),
            detection_threshold_pps: 5000,
            mitigation_action: "block".to_string(),
            auto_block_duration_secs: 300,
            enabled: true,
        }
    }

    #[test]
    fn valid_policy_passes_validation() {
        assert!(valid_policy_config().validate(0).is_ok());
    }

    #[test]
    fn empty_id_fails_validation() {
        let mut cfg = valid_policy_config();
        cfg.id = String::new();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn zero_threshold_fails_validation() {
        let mut cfg = valid_policy_config();
        cfg.detection_threshold_pps = 0;
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn invalid_attack_type_fails_validation() {
        let mut cfg = valid_policy_config();
        cfg.attack_type = "invalid".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn invalid_action_fails_validation() {
        let mut cfg = valid_policy_config();
        cfg.mitigation_action = "invalid".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn to_domain_policy_succeeds() {
        let policy = valid_policy_config().to_domain_policy().unwrap();
        assert_eq!(policy.id.0, "syn-flood-1");
        assert_eq!(policy.attack_type, DdosAttackType::SynFlood);
        assert_eq!(policy.detection_threshold_pps, 5000);
        assert_eq!(policy.mitigation_action, DdosMitigationAction::Block);
    }

    #[test]
    fn parse_all_attack_types() {
        assert!(parse_attack_type("syn_flood").is_ok());
        assert!(parse_attack_type("udp_amplification").is_ok());
        assert!(parse_attack_type("icmp_flood").is_ok());
        assert!(parse_attack_type("rst_flood").is_ok());
        assert!(parse_attack_type("fin_flood").is_ok());
        assert!(parse_attack_type("ack_flood").is_ok());
        assert!(parse_attack_type("volumetric").is_ok());
        assert!(parse_attack_type("unknown").is_err());
    }

    #[test]
    fn parse_all_mitigation_actions() {
        assert!(parse_mitigation_action("alert").is_ok());
        assert!(parse_mitigation_action("throttle").is_ok());
        assert!(parse_mitigation_action("block").is_ok());
        assert!(parse_mitigation_action("unknown").is_err());
    }

    #[test]
    fn default_config_is_disabled() {
        let cfg = DdosConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.syn_protection.enabled);
        assert!(!cfg.icmp_protection.enabled);
        assert!(!cfg.amplification_protection.enabled);
        assert!(!cfg.connection_tracking.enabled);
        assert!(cfg.policies.is_empty());
    }
}
