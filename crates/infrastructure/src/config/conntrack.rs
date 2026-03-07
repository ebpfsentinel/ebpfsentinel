//! Connection tracking configuration.

use serde::{Deserialize, Serialize};

/// TCP connection tracking settings (eBPF-side).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        let cfg = ConnTrackSectionConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.half_open_threshold, 100);
        assert_eq!(cfg.rst_threshold, 50);
        assert_eq!(cfg.fin_threshold, 50);
        assert_eq!(cfg.ack_threshold, 200);
    }
}
