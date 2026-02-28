use serde::{Deserialize, Serialize};

use crate::common::entity::RuleId;

use super::error::DdosError;

/// Types of `DDoS` attacks detected by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdosAttackType {
    SynFlood,
    UdpAmplification,
    IcmpFlood,
    RstFlood,
    FinFlood,
    AckFlood,
    Volumetric,
}

impl DdosAttackType {
    /// Map eBPF `event_type` to attack type.
    pub fn from_event_type(event_type: u8) -> Option<Self> {
        match event_type {
            10 => Some(Self::SynFlood),         // EVENT_TYPE_DDOS_SYN
            11 => Some(Self::IcmpFlood),        // EVENT_TYPE_DDOS_ICMP
            12 => Some(Self::UdpAmplification), // EVENT_TYPE_DDOS_AMP
            13 => Some(Self::Volumetric),       // EVENT_TYPE_DDOS_CONNTRACK
            _ => None,
        }
    }
}

/// Mitigation status of a detected attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdosMitigationStatus {
    /// Attack detected, monitoring rate.
    Detecting,
    /// Attack confirmed active (rate above threshold for 3+ seconds).
    Active,
    /// Attack mitigated (rate below threshold for 30+ seconds).
    Mitigated,
    /// Attack expired (mitigated for 5+ minutes, removed from active list).
    Expired,
}

/// Action to take when a `DDoS` attack is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DdosMitigationAction {
    /// Only alert, do not change traffic handling.
    #[default]
    Alert,
    /// Throttle traffic from attack sources.
    Throttle,
    /// Block traffic from attack sources.
    Block,
}

/// A tracked `DDoS` attack.
#[derive(Debug, Clone, Serialize)]
pub struct DdosAttack {
    pub id: String,
    pub attack_type: DdosAttackType,
    pub start_time_ns: u64,
    pub last_seen_ns: u64,
    /// Number of distinct source IPs observed.
    pub source_count: u64,
    /// Peak packets per second observed.
    pub peak_pps: u64,
    /// Current smoothed packets per second (`EWMA`).
    pub current_pps: u64,
    /// Total packets in this attack.
    pub total_packets: u64,
    pub mitigation_status: DdosMitigationStatus,
    /// Number of consecutive seconds above threshold.
    pub consecutive_above: u32,
    /// Number of consecutive seconds below threshold.
    pub consecutive_below: u32,
    /// Count for the current 1-second window.
    window_count: u64,
    /// Timestamp of the current window start.
    window_start_ns: u64,
}

/// EWMA smoothing factor for rate calculation.
const EWMA_ALPHA_NUM: u64 = 3;
const EWMA_ALPHA_DEN: u64 = 10;

/// Seconds above threshold to declare Active.
const ACTIVE_THRESHOLD_SECS: u32 = 3;
/// Seconds below threshold to declare Mitigated.
const MITIGATED_THRESHOLD_SECS: u32 = 30;
/// Seconds mitigated before expiring.
const EXPIRY_SECS: u32 = 300;

/// 1 second in nanoseconds.
const NS_PER_SEC: u64 = 1_000_000_000;

impl DdosAttack {
    /// Create a new attack tracker.
    pub fn new(id: String, attack_type: DdosAttackType, now_ns: u64) -> Self {
        Self {
            id,
            attack_type,
            start_time_ns: now_ns,
            last_seen_ns: now_ns,
            source_count: 1,
            peak_pps: 0,
            current_pps: 0,
            total_packets: 1,
            mitigation_status: DdosMitigationStatus::Detecting,
            consecutive_above: 0,
            consecutive_below: 0,
            window_count: 1,
            window_start_ns: now_ns,
        }
    }

    /// Record a new packet event for this attack.
    pub fn record_event(&mut self, now_ns: u64) {
        self.total_packets += 1;
        self.last_seen_ns = now_ns;

        // Check if we're in a new 1-second window
        let elapsed = now_ns.saturating_sub(self.window_start_ns);
        if elapsed >= NS_PER_SEC {
            // Compute EWMA of pps
            let instant_pps = self.window_count;
            self.current_pps = (EWMA_ALPHA_NUM * instant_pps
                + (EWMA_ALPHA_DEN - EWMA_ALPHA_NUM) * self.current_pps)
                / EWMA_ALPHA_DEN;
            self.peak_pps = self.peak_pps.max(self.current_pps);

            // Reset window
            self.window_count = 1;
            self.window_start_ns = now_ns;
        } else {
            self.window_count += 1;
        }
    }

    /// Update mitigation status based on a detection threshold.
    /// Call this once per second from the engine's tick.
    pub fn update_status(&mut self, threshold_pps: u64) {
        if self.current_pps >= threshold_pps {
            self.consecutive_above += 1;
            self.consecutive_below = 0;
        } else {
            self.consecutive_below += 1;
            self.consecutive_above = 0;
        }

        match self.mitigation_status {
            DdosMitigationStatus::Detecting => {
                if self.consecutive_above >= ACTIVE_THRESHOLD_SECS {
                    self.mitigation_status = DdosMitigationStatus::Active;
                }
            }
            DdosMitigationStatus::Active => {
                if self.consecutive_below >= MITIGATED_THRESHOLD_SECS {
                    self.mitigation_status = DdosMitigationStatus::Mitigated;
                }
            }
            DdosMitigationStatus::Mitigated => {
                if self.consecutive_above >= ACTIVE_THRESHOLD_SECS {
                    self.mitigation_status = DdosMitigationStatus::Active;
                } else if self.consecutive_below >= EXPIRY_SECS {
                    self.mitigation_status = DdosMitigationStatus::Expired;
                }
            }
            DdosMitigationStatus::Expired => {}
        }
    }

    /// Duration in seconds since the attack started.
    pub fn duration_secs(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.start_time_ns) / NS_PER_SEC
    }

    /// Returns `true` if the attack is active.
    pub fn is_active(&self) -> bool {
        self.mitigation_status == DdosMitigationStatus::Active
    }

    /// Returns `true` if the attack has expired.
    pub fn is_expired(&self) -> bool {
        self.mitigation_status == DdosMitigationStatus::Expired
    }
}

/// A `DDoS` detection/mitigation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosPolicy {
    pub id: RuleId,
    pub attack_type: DdosAttackType,
    /// Packets per second threshold to trigger detection.
    pub detection_threshold_pps: u64,
    /// Action when attack is detected.
    pub mitigation_action: DdosMitigationAction,
    /// Duration in seconds to auto-block sources (0 = indefinite).
    pub auto_block_duration_secs: u64,
    pub enabled: bool,
}

impl DdosPolicy {
    /// Validate the policy.
    pub fn validate(&self) -> Result<(), DdosError> {
        self.id
            .validate()
            .map_err(|msg| DdosError::InvalidPolicy(msg.to_string()))?;

        if self.detection_threshold_pps == 0 {
            return Err(DdosError::InvalidThreshold);
        }

        Ok(())
    }
}

/// A `DDoS` event received from the eBPF pipeline.
#[derive(Debug, Clone)]
pub struct DdosEvent {
    pub timestamp_ns: u64,
    pub attack_type: DdosAttackType,
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub is_ipv6: bool,
}

/// Severity levels for `DDoS` alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DdosSeverity {
    Medium,
    High,
    Critical,
}

impl DdosAttackType {
    /// Map attack type to severity.
    pub fn severity(&self) -> DdosSeverity {
        match self {
            Self::SynFlood | Self::Volumetric => DdosSeverity::Critical,
            Self::UdpAmplification | Self::AckFlood => DdosSeverity::High,
            Self::IcmpFlood | Self::RstFlood | Self::FinFlood => DdosSeverity::Medium,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_type_from_event_type() {
        assert_eq!(
            DdosAttackType::from_event_type(10),
            Some(DdosAttackType::SynFlood)
        );
        assert_eq!(
            DdosAttackType::from_event_type(11),
            Some(DdosAttackType::IcmpFlood)
        );
        assert_eq!(
            DdosAttackType::from_event_type(12),
            Some(DdosAttackType::UdpAmplification)
        );
        assert_eq!(
            DdosAttackType::from_event_type(13),
            Some(DdosAttackType::Volumetric)
        );
        assert_eq!(DdosAttackType::from_event_type(99), None);
    }

    #[test]
    fn attack_type_severity() {
        assert_eq!(DdosAttackType::SynFlood.severity(), DdosSeverity::Critical);
        assert_eq!(
            DdosAttackType::UdpAmplification.severity(),
            DdosSeverity::High
        );
        assert_eq!(DdosAttackType::IcmpFlood.severity(), DdosSeverity::Medium);
    }

    #[test]
    fn ddos_attack_lifecycle() {
        let mut attack = DdosAttack::new("atk-1".to_string(), DdosAttackType::SynFlood, 0);
        assert_eq!(attack.mitigation_status, DdosMitigationStatus::Detecting);

        // Simulate high rate for 3 seconds
        for i in 1..=3 {
            attack.current_pps = 10_000;
            attack.update_status(5000);
            if i >= ACTIVE_THRESHOLD_SECS {
                assert!(attack.is_active(), "should be active after {i} secs");
            }
        }

        // Simulate low rate for 30 seconds
        for _ in 0..MITIGATED_THRESHOLD_SECS {
            attack.current_pps = 100;
            attack.update_status(5000);
        }
        assert_eq!(attack.mitigation_status, DdosMitigationStatus::Mitigated);

        // Simulate expiry
        for _ in 0..EXPIRY_SECS {
            attack.current_pps = 0;
            attack.update_status(5000);
        }
        assert!(attack.is_expired());
    }

    #[test]
    fn ddos_attack_rate_tracking() {
        let mut attack = DdosAttack::new("atk-2".to_string(), DdosAttackType::IcmpFlood, 0);

        // Record 1000 events in the first second
        for i in 1..=1000 {
            attack.record_event(i * 500_000); // 0.5ms intervals
        }
        assert_eq!(attack.total_packets, 1001); // 1 from new + 1000 recorded

        // Cross into new window to trigger EWMA
        attack.record_event(NS_PER_SEC + 1);
        assert!(attack.current_pps > 0);
    }

    #[test]
    fn ddos_attack_reactivation() {
        let mut attack = DdosAttack::new("atk-3".to_string(), DdosAttackType::SynFlood, 0);

        // Become active
        for _ in 0..ACTIVE_THRESHOLD_SECS {
            attack.current_pps = 10_000;
            attack.update_status(5000);
        }
        assert!(attack.is_active());

        // Mitigate
        for _ in 0..MITIGATED_THRESHOLD_SECS {
            attack.current_pps = 100;
            attack.update_status(5000);
        }
        assert_eq!(attack.mitigation_status, DdosMitigationStatus::Mitigated);

        // Re-activate
        for _ in 0..ACTIVE_THRESHOLD_SECS {
            attack.current_pps = 10_000;
            attack.update_status(5000);
        }
        assert!(attack.is_active());
    }

    #[test]
    fn ddos_policy_validation() {
        let valid = DdosPolicy {
            id: RuleId("syn-flood-1".to_string()),
            attack_type: DdosAttackType::SynFlood,
            detection_threshold_pps: 5000,
            mitigation_action: DdosMitigationAction::Block,
            auto_block_duration_secs: 300,
            enabled: true,
        };
        assert!(valid.validate().is_ok());

        let zero_threshold = DdosPolicy {
            detection_threshold_pps: 0,
            ..valid.clone()
        };
        assert!(zero_threshold.validate().is_err());

        let empty_id = DdosPolicy {
            id: RuleId(String::new()),
            ..valid
        };
        assert!(empty_id.validate().is_err());
    }

    #[test]
    fn ddos_attack_duration() {
        let attack = DdosAttack::new("atk-4".to_string(), DdosAttackType::SynFlood, 1_000_000_000);
        assert_eq!(attack.duration_secs(6_000_000_000), 5);
    }
}
