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

/// How long the stop sequence waits for running packet captures to close their
/// files after being asked to stop.
///
/// A capture polls its stop flag every 50 ms, so this is two orders of
/// magnitude more than one reader needs; it is a window rather than a sleep
/// because the alternative is exiting while a savefile is half flushed, and
/// the cost of being wrong in the other direction is a stop that hangs.
pub const CAPTURE_STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a caller waits for a warden-brokered operation that it has moved
/// onto a blocking thread.
///
/// The client's own socket timeout is what normally ends such a call, and it is
/// shorter than this, so an answer that never comes is reported by the call
/// itself and names the operation. This is the outer bound: a blocking thread
/// wedged before or after the socket call - a poisoned lock, a child the warden
/// is still killing - would otherwise hold the request that is awaiting it for
/// as long as the agent runs. Reaching this bound frees the caller and leaves
/// the thread to the blocking pool, which is the right way round: a thread is
/// cheap and a request that never answers is not.
pub const WARDEN_BROKER_CALL_TIMEOUT: Duration = Duration::from_secs(10);

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
    #[allow(clippy::assertions_on_constants)]
    fn channel_capacities_are_positive() {
        assert!(EVENT_CHANNEL_CAPACITY > 0);
        assert!(ALERT_CHANNEL_CAPACITY > 0);
        assert!(CONFIG_BROADCAST_CAPACITY > 0);
        assert!(MAP_UPDATE_CHANNEL_CAPACITY > 0);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn shutdown_timeout_is_reasonable() {
        assert!(GRACEFUL_SHUTDOWN_TIMEOUT.as_secs() >= 1);
        assert!(GRACEFUL_SHUTDOWN_TIMEOUT.as_secs() <= 30);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn capture_stop_fits_inside_the_graceful_window() {
        assert!(CAPTURE_STOP_TIMEOUT.as_millis() >= 500);
        assert!(
            CAPTURE_STOP_TIMEOUT <= GRACEFUL_SHUTDOWN_TIMEOUT,
            "a capture must not hold a stop longer than draining the servers does"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn the_broker_bound_is_the_outer_one() {
        // The warden client gives up first, so the error a caller sees names the
        // operation that timed out rather than this generic bound.
        assert!(
            WARDEN_BROKER_CALL_TIMEOUT > ebpfsentinel_warden_client::CALL_TIMEOUT,
            "the brokered-call bound must outlast the client's own socket timeout"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn map_threshold_is_valid() {
        assert!(EBPF_MAP_CAPACITY_WARN_THRESHOLD > 0.0);
        assert!(EBPF_MAP_CAPACITY_WARN_THRESHOLD <= 1.0);
    }
}
