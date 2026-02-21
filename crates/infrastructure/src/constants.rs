use std::time::Duration;

// ── Network defaults ───────────────────────────────────────────────

pub const DEFAULT_CONFIG_PATH: &str = "/etc/ebpfsentinel/config.yaml";
pub const DEFAULT_HTTP_PORT: u16 = 8080;
pub const DEFAULT_GRPC_PORT: u16 = 50051;
pub const DEFAULT_METRICS_PORT: u16 = 9090;

// ── Channel capacities ─────────────────────────────────────────────

pub const EVENT_CHANNEL_CAPACITY: usize = 10_000;
pub const ALERT_CHANNEL_CAPACITY: usize = 1_000;
pub const CONFIG_BROADCAST_CAPACITY: usize = 16;
pub const MAP_UPDATE_CHANNEL_CAPACITY: usize = 256;

// ── Timeouts ───────────────────────────────────────────────────────

pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

// ── eBPF ──────────────────────────────────────────────────────────

/// Default directory containing compiled eBPF program binaries.
pub const DEFAULT_EBPF_PROGRAM_DIR: &str = "/usr/local/lib/ebpfsentinel";

/// Fall-back for local development (relative to the workspace root).
pub const DEFAULT_EBPF_PROGRAM_DIR_DEV: &str = "target/bpfel-unknown-none/release";

// ── Thresholds ─────────────────────────────────────────────────────

pub const EBPF_MAP_CAPACITY_WARN_THRESHOLD: f32 = 0.80;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_are_distinct() {
        assert_ne!(DEFAULT_HTTP_PORT, DEFAULT_GRPC_PORT);
        assert_ne!(DEFAULT_HTTP_PORT, DEFAULT_METRICS_PORT);
        assert_ne!(DEFAULT_GRPC_PORT, DEFAULT_METRICS_PORT);
    }

    #[test]
    fn channel_capacities_are_positive() {
        assert!(EVENT_CHANNEL_CAPACITY > 0);
        assert!(ALERT_CHANNEL_CAPACITY > 0);
        assert!(CONFIG_BROADCAST_CAPACITY > 0);
        assert!(MAP_UPDATE_CHANNEL_CAPACITY > 0);
    }

    #[test]
    fn shutdown_timeout_is_reasonable() {
        assert!(GRACEFUL_SHUTDOWN_TIMEOUT.as_secs() >= 1);
        assert!(GRACEFUL_SHUTDOWN_TIMEOUT.as_secs() <= 30);
    }

    #[test]
    fn map_threshold_is_valid() {
        assert!(EBPF_MAP_CAPACITY_WARN_THRESHOLD > 0.0);
        assert!(EBPF_MAP_CAPACITY_WARN_THRESHOLD <= 1.0);
    }
}
