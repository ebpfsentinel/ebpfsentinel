//! Socket attribution: naming the workload behind a flow.
//!
//! The datapath knows addresses. The task that opened the socket is known one
//! layer up, at `connect()` or `sendmsg()` time, and the cgroup socket hooks
//! are what record it. This block decides whether those hooks are attached,
//! where, and how many sockets the agent is willing to remember.
//!
//! Nothing here enforces anything. Turning the block off costs the workload
//! name on an alert and on a flow; it changes no verdict and drops no packet.

use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};

/// Default ceiling on the socket table, matching the eBPF map's own default.
fn default_max_sockets() -> u32 {
    ebpf_common::attribution::ATTRIBUTION_MAX_SOCKETS
}

/// cgroup v2 hierarchy root, where the hooks are attached.
fn default_cgroup_root() -> String {
    "/sys/fs/cgroup".to_string()
}

/// The smallest table worth attaching the hooks for. Below this the eviction
/// rate makes the attribution so partial that an operator reading a flow with
/// no workload cannot tell a transited packet from a lost entry.
const MIN_MAX_SOCKETS: u32 = 1_024;

/// The largest table the agent will create. At 40 bytes an entry plus the
/// LRU's own overhead, a million sockets is tens of megabytes of locked
/// memory, which is a decision an operator should have to write down rather
/// than reach by typing a large number.
const MAX_MAX_SOCKETS: u32 = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionConfig {
    /// Attach the socket hooks. On by default: the whole point of the agent
    /// is to say what is happening on the node, and an alert naming only an
    /// address is half an answer.
    ///
    /// A kernel or a host that refuses the attach is not a failure to start:
    /// the agent runs on with no workload block and says so once, with the
    /// reason, which the kernel-features endpoint then reports.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// The cgroup the hooks are attached to. The root of the v2 hierarchy
    /// covers every task on the node, which is what a node agent wants; a
    /// sub-path narrows attribution to the tasks under it.
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: String,

    /// How many sockets the kernel table holds before it evicts the coldest.
    #[serde(default = "default_max_sockets")]
    pub max_sockets: u32,
}

impl Default for AttributionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cgroup_root: default_cgroup_root(),
            max_sockets: default_max_sockets(),
        }
    }
}

impl AttributionConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.cgroup_root.trim().is_empty() {
            return Err(ConfigError::Validation {
                field: "attribution.cgroup_root".to_string(),
                message: "cgroup root must not be empty".to_string(),
            });
        }
        if !self.cgroup_root.starts_with('/') {
            return Err(ConfigError::Validation {
                field: "attribution.cgroup_root".to_string(),
                message: format!("cgroup root must be an absolute path: {}", self.cgroup_root),
            });
        }
        if self.max_sockets < MIN_MAX_SOCKETS || self.max_sockets > MAX_MAX_SOCKETS {
            return Err(ConfigError::Validation {
                field: "attribution.max_sockets".to_string(),
                message: format!(
                    "must be between {MIN_MAX_SOCKETS} and {MAX_MAX_SOCKETS}, got {}",
                    self.max_sockets
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_on_and_valid() {
        let cfg = AttributionConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn the_default_table_matches_the_map_the_kernel_side_declares() {
        assert_eq!(
            AttributionConfig::default().max_sockets,
            ebpf_common::attribution::ATTRIBUTION_MAX_SOCKETS
        );
    }

    #[test]
    fn a_relative_cgroup_root_is_refused() {
        let cfg = AttributionConfig {
            cgroup_root: "sys/fs/cgroup".to_string(),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_table_too_small_to_be_honest_is_refused() {
        let cfg = AttributionConfig {
            max_sockets: 16,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_table_large_enough_to_be_a_memory_decision_is_refused() {
        let cfg = AttributionConfig {
            max_sockets: MAX_MAX_SOCKETS + 1,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
