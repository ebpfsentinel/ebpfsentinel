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
    /// Direction: ingress, egress, or both.
    pub direction: QosDirection,
    /// Whether this pipe is enabled.
    pub enabled: bool,
    /// Interface group bitmask for multi-interface rule scoping.
    /// 0 = floating (applies to all interfaces). Bit 31 = invert.
    pub group_mask: u32,
}

/// A `QoS` queue — the indirection classifiers point at to reach a pipe.
///
/// Traffic is shaped by the pipe, not by the queue: disabling a queue detaches
/// every classifier that names it in one move, without editing them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosQueue {
    /// Unique queue identifier.
    pub id: String,
    /// Pipe this queue is attached to.
    pub pipe_id: String,
    /// Whether this queue is enabled.
    pub enabled: bool,
}

/// Match criteria for a `QoS` classifier:
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QosMatchRule {
    /// Source host address, `None` = wildcard.
    ///
    /// The classifier map is keyed by an exact address, so this is a single
    /// IPv4 host: a prefix would have nothing to match against.
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Destination host address, `None` = wildcard. Single IPv4 host, as
    /// for [`QosMatchRule::src_ip`].
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
    /// 802.1Q VLAN ID: `None` = any VLAN, `Some(0)` = untagged traffic only,
    /// `Some(vid)` = that tag only.
    #[serde(default)]
    pub vlan_id: Option<u16>,
}

/// A `QoS` classifier — maps traffic to a queue based on match rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosClassifier {
    /// Unique classifier identifier.
    pub id: String,
    /// Queue this classifier maps to.
    pub queue_id: String,
    /// Match criteria.
    pub match_rule: QosMatchRule,
    /// Priority (lower = matched first).
    pub priority: u32,
    /// Interface group bitmask for multi-interface rule scoping.
    /// 0 = floating (applies to all interfaces). Bit 31 = invert.
    pub group_mask: u32,
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
    fn match_rule_default_is_wildcard() {
        let rule = QosMatchRule::default();
        assert!(rule.src_ip.is_none());
        assert!(rule.dst_ip.is_none());
        assert_eq!(rule.src_port, 0);
        assert_eq!(rule.dst_port, 0);
        assert_eq!(rule.protocol, 0);
        assert_eq!(rule.dscp, 0);
        assert_eq!(rule.vlan_id, None);
    }
}
