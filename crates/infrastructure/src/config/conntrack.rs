use serde::{Deserialize, Serialize};

use super::common::ConfigError;

/// The top-level `conntrack` section: the per-source connection ceilings the
/// connection tracker enforces on the XDP fast path.
///
/// The flood thresholds and the kernel connection table belong to the `DDoS`
/// guard and are written under `ddos.connection_tracking`
/// ([`DdosConnTrackConfig`]); either key here is refused at load.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnTrackConfig {
    #[serde(default)]
    pub enabled: bool,

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

impl Default for ConnTrackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_src_states: 0,
            max_src_conn_rate: 0,
            conn_rate_window_secs: default_conn_rate_window_secs(),
            overload_ttl_secs: default_overload_ttl_secs(),
        }
    }
}

/// The `ddos.connection_tracking` section: the `DDoS` guard's per-source
/// flood thresholds and the kernel connection table it keeps.
///
/// The per-source connection ceilings belong to the top-level `conntrack`
/// section ([`ConnTrackConfig`]); any of them here is refused at load.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DdosConnTrackConfig {
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

    /// Capacity of the kernel connection table the `DDoS` guard keeps, in
    /// connections tracked at once. Per CPU, least recently seen connection
    /// evicted when full. Applies at the next agent start.
    #[serde(default)]
    pub max_entries: Option<u32>,
}

/// Smallest and largest `ddos.connection_tracking.max_entries`.
pub const DDOS_CONNTRACK_MIN_ENTRIES: u32 = 1_024;
pub const DDOS_CONNTRACK_MAX_ENTRIES: u32 = 4_194_304;
/// The connection table's capacity when the configuration names none.
pub const DDOS_CONNTRACK_DEFAULT_ENTRIES: u32 = 65_536;

impl DdosConnTrackConfig {
    /// The capacity the `DDoS` connection table is created with.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.max_entries.unwrap_or(DDOS_CONNTRACK_DEFAULT_ENTRIES)
    }

    /// Bounds on an explicit connection table capacity.
    pub(super) fn validate_capacity(&self) -> Result<(), ConfigError> {
        if let Some(n) = self.max_entries
            && !(DDOS_CONNTRACK_MIN_ENTRIES..=DDOS_CONNTRACK_MAX_ENTRIES).contains(&n)
        {
            return Err(ConfigError::Validation {
                field: "ddos.connection_tracking.max_entries".to_string(),
                message: format!(
                    "must be between {DDOS_CONNTRACK_MIN_ENTRIES} and {DDOS_CONNTRACK_MAX_ENTRIES}"
                ),
            });
        }
        Ok(())
    }
}

impl Default for DdosConnTrackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            half_open_threshold: default_half_open_threshold(),
            rst_threshold: default_flood_threshold(),
            fin_threshold: default_flood_threshold(),
            ack_threshold: default_ack_threshold(),
            max_entries: None,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_default_is_disabled() {
        let cfg = ConnTrackConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_src_states, 0);
        assert_eq!(cfg.max_src_conn_rate, 0);
        assert_eq!(cfg.conn_rate_window_secs, 5);
        assert_eq!(cfg.overload_ttl_secs, 3600);
    }

    #[test]
    fn ddos_conntrack_default_is_disabled() {
        let cfg = DdosConnTrackConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.half_open_threshold, 100);
        assert_eq!(cfg.rst_threshold, 50);
        assert_eq!(cfg.fin_threshold, 50);
        assert_eq!(cfg.ack_threshold, 200);
        assert_eq!(cfg.capacity(), DDOS_CONNTRACK_DEFAULT_ENTRIES);
    }

    #[test]
    fn the_per_source_guard_is_reachable_from_yaml() {
        let cfg: ConnTrackConfig = serde_norway::from_str(
            "enabled: true\nmax_src_states: 512\nmax_src_conn_rate: 64\nconn_rate_window_secs: 10\noverload_ttl_secs: 300\n",
        )
        .expect("conntrack section parses");
        assert_eq!(cfg.max_src_states, 512);
        assert_eq!(cfg.max_src_conn_rate, 64);
        assert_eq!(cfg.conn_rate_window_secs, 10);
        assert_eq!(cfg.overload_ttl_secs, 300);
    }

    #[test]
    fn the_flood_thresholds_are_reachable_from_yaml() {
        let cfg: DdosConnTrackConfig = serde_norway::from_str(
            "enabled: true\nhalf_open_threshold: 5\nrst_threshold: 10\nfin_threshold: 20\nack_threshold: 30\nmax_entries: 8192\n",
        )
        .expect("ddos connection tracking section parses");
        assert_eq!(cfg.half_open_threshold, 5);
        assert_eq!(cfg.rst_threshold, 10);
        assert_eq!(cfg.fin_threshold, 20);
        assert_eq!(cfg.ack_threshold, 30);
        assert_eq!(cfg.capacity(), 8_192);
    }

    #[test]
    fn a_flood_threshold_under_conntrack_is_refused() {
        for key in [
            "half_open_threshold",
            "rst_threshold",
            "fin_threshold",
            "ack_threshold",
            "max_entries",
        ] {
            let err = serde_norway::from_str::<ConnTrackConfig>(&format!("{key}: 100\n"))
                .expect_err(key)
                .to_string();
            assert!(err.contains("unknown field"), "{key}: {err}");
        }
    }

    #[test]
    fn a_per_source_ceiling_under_ddos_connection_tracking_is_refused() {
        for key in [
            "max_src_states",
            "max_src_conn_rate",
            "conn_rate_window_secs",
            "overload_ttl_secs",
        ] {
            let err = serde_norway::from_str::<DdosConnTrackConfig>(&format!("{key}: 100\n"))
                .expect_err(key)
                .to_string();
            assert!(err.contains("unknown field"), "{key}: {err}");
        }
    }
}
