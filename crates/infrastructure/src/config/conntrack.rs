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

    /// Max concurrent connections a single source may hold (0 = unlimited).
    #[serde(default)]
    pub max_src_states: u32,

    /// Max new connections a single source may open within
    /// `conn_rate_window_secs` (0 = unlimited).
    #[serde(default)]
    pub max_src_conn_rate: u32,

    /// Width of the window `max_src_conn_rate` is measured over, in seconds.
    #[serde(default = "default_conn_rate_window_secs")]
    pub conn_rate_window_secs: u32,

    /// How long a source that exceeded `max_src_conn_rate` stays refused, in
    /// seconds (0 = until the agent restarts).
    #[serde(default = "default_overload_ttl_secs")]
    pub overload_ttl_secs: u32,
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

fn default_conn_rate_window_secs() -> u32 {
    5
}

fn default_overload_ttl_secs() -> u32 {
    3600
}

impl Default for ConnTrackSectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            half_open_threshold: default_half_open_threshold(),
            rst_threshold: default_flood_threshold(),
            fin_threshold: default_flood_threshold(),
            ack_threshold: default_ack_threshold(),
            max_src_states: 0,
            max_src_conn_rate: 0,
            conn_rate_window_secs: default_conn_rate_window_secs(),
            overload_ttl_secs: default_overload_ttl_secs(),
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
        assert_eq!(cfg.max_src_states, 0);
        assert_eq!(cfg.max_src_conn_rate, 0);
        assert_eq!(cfg.conn_rate_window_secs, 5);
        assert_eq!(cfg.overload_ttl_secs, 3600);
    }

    #[test]
    fn the_per_source_guard_is_reachable_from_yaml() {
        let cfg: ConnTrackSectionConfig = serde_yaml_ng::from_str(
            "enabled: true\nmax_src_states: 512\nmax_src_conn_rate: 64\nconn_rate_window_secs: 10\noverload_ttl_secs: 300\n",
        )
        .expect("conntrack section parses");
        assert_eq!(cfg.max_src_states, 512);
        assert_eq!(cfg.max_src_conn_rate, 64);
        assert_eq!(cfg.conn_rate_window_secs, 10);
        assert_eq!(cfg.overload_ttl_secs, 300);
    }
}
