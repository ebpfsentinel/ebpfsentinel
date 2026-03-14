use serde::{Deserialize, Serialize};

/// Direction for `QoS` shaping: ingress, egress, or both.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QosDirection {
    Ingress,
    #[default]
    Egress,
    Both,
}

impl QosDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
            Self::Both => "both",
        }
    }
}

impl std::fmt::Display for QosDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Scheduler type for `QoS` queues:
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QosScheduler {
    /// Dummynet-style FIFO with bandwidth/delay shaping.
    #[default]
    Fifo,
    /// Weighted Fair Queuing (WF2Q+).
    Wf2q,
    /// Flow Queue Controlled Delay.
    FqCodel,
}

impl QosScheduler {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Wf2q => "wf2q",
            Self::FqCodel => "fq_codel",
        }
    }
}

impl std::fmt::Display for QosScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `QoS` pipe — bandwidth limiter with optional delay and loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosPipe {
    /// Unique pipe identifier.
    pub id: String,
    /// Bandwidth limit in bits per second.
    pub rate_bps: u64,
    /// Maximum burst size in bytes.
    pub burst_bytes: u64,
    /// Added latency in milliseconds.
    pub delay_ms: u32,
    /// Packet loss percentage (0.0-100.0).
    pub loss_pct: f32,
    /// Pipe priority (lower = higher priority).
    pub priority: u8,
    /// Direction: ingress, egress, or both.
    pub direction: QosDirection,
    /// Whether this pipe is enabled.
    pub enabled: bool,
}

/// A `QoS` queue — scheduling unit attached to a pipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosQueue {
    /// Unique queue identifier.
    pub id: String,
    /// Pipe this queue is attached to.
    pub pipe_id: String,
    /// Scheduling weight (1-100).
    pub weight: u16,
    /// Whether this queue is enabled.
    pub enabled: bool,
}

/// Match criteria for a `QoS` classifier:
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QosMatchRule {
    /// Source IP (CIDR string, None = wildcard).
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Destination IP (CIDR string, None = wildcard).
    #[serde(default)]
    pub dst_ip: Option<String>,
    /// Source port (None or 0 = wildcard).
    #[serde(default)]
    pub src_port: u16,
    /// Destination port (None or 0 = wildcard).
    #[serde(default)]
    pub dst_port: u16,
    /// IP protocol (0 = wildcard).
    #[serde(default)]
    pub protocol: u8,
    /// DSCP value (0 = wildcard).
    #[serde(default)]
    pub dscp: u8,
    /// VLAN ID (0 = wildcard).
    #[serde(default)]
    pub vlan_id: u16,
}

/// A `QoS` classifier — maps traffic to a queue based on match rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosClassifier {
    /// Unique classifier identifier.
    pub id: String,
    /// Queue this classifier maps to.
    pub queue_id: String,
    /// Direction (ingress/egress/both).
    pub direction: QosDirection,
    /// Match criteria.
    pub match_rule: QosMatchRule,
    /// Priority (lower = matched first).
    pub priority: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_as_str() {
        assert_eq!(QosDirection::Ingress.as_str(), "ingress");
        assert_eq!(QosDirection::Egress.as_str(), "egress");
        assert_eq!(QosDirection::Both.as_str(), "both");
    }

    #[test]
    fn direction_default_is_egress() {
        assert_eq!(QosDirection::default(), QosDirection::Egress);
    }

    #[test]
    fn scheduler_as_str() {
        assert_eq!(QosScheduler::Fifo.as_str(), "fifo");
        assert_eq!(QosScheduler::Wf2q.as_str(), "wf2q");
        assert_eq!(QosScheduler::FqCodel.as_str(), "fq_codel");
    }

    #[test]
    fn scheduler_default_is_fifo() {
        assert_eq!(QosScheduler::default(), QosScheduler::Fifo);
    }

    #[test]
    fn match_rule_default_is_wildcard() {
        let rule = QosMatchRule::default();
        assert!(rule.src_ip.is_none());
        assert!(rule.dst_ip.is_none());
        assert_eq!(rule.src_port, 0);
        assert_eq!(rule.dst_port, 0);
        assert_eq!(rule.protocol, 0);
        assert_eq!(rule.dscp, 0);
        assert_eq!(rule.vlan_id, 0);
    }
}
