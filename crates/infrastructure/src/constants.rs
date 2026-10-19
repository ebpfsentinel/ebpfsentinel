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

/// How many workload firewall refusals wait between the ring buffer and the
/// alert they become.
///
/// Smaller than the alert channel on purpose: a refusal is one socket
/// operation rather than a packet, and a backlog deep enough to outlive the
/// policy that named its slots would turn into alerts about the wrong rule.
pub const WORKLOAD_DENIAL_CHANNEL_CAPACITY: usize = 256;

// ── Timeouts ───────────────────────────────────────────────────────

pub const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the per-rule refusal counters are read out of the kernel.
///
/// The counters are exact and cumulative, so the interval decides how fresh a
/// scrape is and nothing else: a reading missed is a reading folded into the
/// next one. Ten seconds is shorter than any sensible scrape interval and long
/// enough that a policy at its ceiling costs one map walk a tick.
pub const WORKLOAD_DENIAL_READ_INTERVAL: Duration = Duration::from_secs(10);

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

/// How long the agent's stop sequence is given before the service manager
/// kills it, which is `TimeoutStopSec` in both units.
///
/// It has to outlast the whole ordered stop and not only the server drain: a
/// capture closes its file inside [`GRACEFUL_SHUTDOWN_TIMEOUT`], and a stop
/// that is waiting on the warden can be holding a brokered call for up to
/// [`WARDEN_BROKER_CALL_TIMEOUT`]. The sum of those two is the worst case, and
/// this is it plus room, so a `SIGKILL` means something is wrong rather than
/// that the budget was tight.
pub const AGENT_STOP_BUDGET: Duration = Duration::from_secs(20);

/// How long the pod's `preStop` hook holds the container before the agent is
/// signalled, so the endpoint is out of every Service's backend list first.
///
/// Kubernetes sends `SIGTERM` and removes the endpoint concurrently, so without
/// this the agent can be draining while traffic is still being routed to it.
pub const PRESTOP_DRAIN: Duration = Duration::from_secs(5);

/// What the chart's `terminationGracePeriodSeconds` must be at least, and is.
///
/// Kubernetes counts the `preStop` hook inside the grace period, so the budget
/// is the hook plus the agent's own stop: a grace period shorter than the sum
/// turns an ordered stop into a `SIGKILL`.
pub const POD_TERMINATION_GRACE: Duration = Duration::from_secs(30);

/// `WatchdogSec` in both units: how long the service manager waits for a
/// keep-alive before it concludes the process is wedged and restarts it.
///
/// systemd asks for a ping every half of this, so the agent has two chances
/// inside every window.
pub const WATCHDOG_INTERVAL: Duration = Duration::from_secs(90);

/// How long the datapath may go without a ring-buffer pass before the agent
/// stops telling the service manager it is healthy.
///
/// A reader makes a pass every 10 ms even with no traffic, so a minute of
/// silence is six thousand missed ticks: this is a wedged or dead reader task
/// rather than a quiet network. It is shorter than
/// [`WATCHDOG_INTERVAL`] so a stall is noticed, and withheld from a ping,
/// within one watchdog window.
pub const DATAPATH_STALL_AFTER: Duration = Duration::from_secs(60);

/// `StartLimitBurst`: how many starts inside [`RESTART_LIMIT_WINDOW`] the
/// service manager allows before it stops trying.
///
/// With `RestartSec=5s` a permanent failure - an eBPF program the kernel
/// refuses, a config that does not parse - exhausts this in about half a
/// minute and leaves the unit failed, where an operator finds it. Without it,
/// the loader is re-entered every five seconds for as long as nobody looks.
pub const RESTART_LIMIT_BURST: u32 = 5;

/// `StartLimitIntervalSec`: the window [`RESTART_LIMIT_BURST`] is counted in.
pub const RESTART_LIMIT_WINDOW: Duration = Duration::from_secs(300);

// ── eBPF ──────────────────────────────────────────────────────────

/// Default directory containing compiled eBPF program binaries.
///
/// Where the tarball's `install.sh` puts them: `/usr/local` is the prefix for
/// software installed outside the package manager.
pub const DEFAULT_EBPF_PROGRAM_DIR: &str = "/usr/local/lib/ebpfsentinel";

/// Where a distribution package puts the same objects.
///
/// A `.deb` or an `.rpm` may not write under `/usr/local` - that prefix
/// belongs to the administrator, not to the package manager - so the native
/// packages install the objects here and the agent looks in both places.
pub const DEFAULT_EBPF_PROGRAM_DIR_PACKAGE: &str = "/usr/lib/ebpfsentinel";

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
        assert!(WORKLOAD_DENIAL_CHANNEL_CAPACITY > 0);
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
    fn the_stop_budget_outlasts_the_stop_it_bounds() {
        // TimeoutStopSec has to cover the ordered stop's worst case: the server
        // drain, inside which a capture closes its file, plus a brokered warden
        // call the stop can be waiting on.
        assert!(
            AGENT_STOP_BUDGET > GRACEFUL_SHUTDOWN_TIMEOUT + WARDEN_BROKER_CALL_TIMEOUT,
            "a stop killed by its own budget looks like a hang and is not one"
        );
        assert!(CAPTURE_STOP_TIMEOUT < AGENT_STOP_BUDGET);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn the_pod_grace_period_covers_the_hook_and_the_stop() {
        // Kubernetes counts preStop inside terminationGracePeriodSeconds, so
        // the chart's value and these two have to add up or the agent is
        // SIGKILLed mid-stop.
        assert!(
            POD_TERMINATION_GRACE >= PRESTOP_DRAIN + AGENT_STOP_BUDGET,
            "the grace period must cover the hook and the agent's own stop"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn a_datapath_stall_is_noticed_inside_one_watchdog_window() {
        // systemd pings at half the interval, so the stall bound plus one ping
        // gap has to fit inside the window, or a stalled agent could be killed
        // for a stall nobody had measured yet.
        assert!(
            DATAPATH_STALL_AFTER < WATCHDOG_INTERVAL,
            "a stall must be measurable before the watchdog fires"
        );
        assert!(
            DATAPATH_STALL_AFTER >= WATCHDOG_INTERVAL / 2,
            "a bound shorter than the ping gap would withhold on a single slow tick"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn the_restart_limit_bites_before_an_operator_would() {
        // Five starts at RestartSec=5s is about half a minute of trying.
        assert!(
            RESTART_LIMIT_BURST >= 3,
            "a transient failure must be retried"
        );
        assert!(
            RESTART_LIMIT_WINDOW.as_secs()
                > u64::from(RESTART_LIMIT_BURST) * GRACEFUL_SHUTDOWN_TIMEOUT.as_secs(),
            "the window must be wider than the burst takes, or the limit never trips"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn map_threshold_is_valid() {
        assert!(EBPF_MAP_CAPACITY_WARN_THRESHOLD > 0.0);
        assert!(EBPF_MAP_CAPACITY_WARN_THRESHOLD <= 1.0);
    }
}
