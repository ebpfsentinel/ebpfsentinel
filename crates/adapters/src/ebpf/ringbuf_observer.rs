#![allow(unsafe_code)] // clock_gettime(CLOCK_BOOTTIME) has no safe wrapper in libc

use std::sync::Arc;

use domain::common::agent_event::AgentEvent;
use ports::secondary::metrics_port::MetricsPort;

/// Kernel-side `CLOCK_BOOTTIME` stamp carried by a decoded event.
///
/// Every emit path stamps its record with `bpf_ktime_get_boot_ns()`, whichever
/// program produced it, so one accessor serves all three readers.
#[must_use]
pub fn event_timestamp_ns(event: &AgentEvent) -> u64 {
    match event {
        AgentEvent::L4(e) => e.timestamp_ns,
        AgentEvent::L7 { header, .. } => header.timestamp_ns,
        AgentEvent::Dns { header, .. } => header.timestamp_ns,
        AgentEvent::Dlp(e) => e.timestamp_ns,
    }
}

/// Accounting for one datapath ring buffer, shared by every reader.
///
/// The kernel already counts what it refused to emit, in the `events_dropped`
/// slot of each program's metrics map. Userspace counted nothing, so a record
/// that was committed and then thrown away at the channel was indistinguishable
/// from a record the kernel never emitted at all. This makes drained, dropped
/// and refused three separate numbers.
///
/// `source` is the producing program (`xdp-firewall`, `tc-dns`, ...), so a
/// backlog can be attributed to the datapath that caused it.
#[derive(Clone)]
pub struct RingBufObserver {
    source: &'static str,
    metrics: Option<Arc<dyn MetricsPort>>,
}

impl RingBufObserver {
    /// Observe the ring buffer fed by `source`, reporting to `metrics`.
    #[must_use]
    pub fn new(source: &'static str, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            source,
            metrics: Some(metrics),
        }
    }

    /// An observer that records nothing.
    ///
    /// Used by call sites that drain a ring buffer outside the agent's
    /// metrics registry (tools, tests), so they are not forced to build one.
    #[must_use]
    pub fn disabled(source: &'static str) -> Self {
        Self {
            source,
            metrics: None,
        }
    }

    /// Current `CLOCK_BOOTTIME` in nanoseconds, or `0` when this observer
    /// records nothing.
    ///
    /// Read once per batch drain rather than once per record: a batch is
    /// drained in a tight loop, so one clock read for the whole batch keeps
    /// the measurement honest without putting a syscall on every event.
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        if self.metrics.is_none() {
            return 0;
        }
        boottime_now_ns()
    }

    /// Record one record drained from the ring buffer.
    ///
    /// `event_ts_ns` is the kernel-side timestamp carried by the record. Every
    /// emit path stamps it with `bpf_ktime_get_boot_ns()`, the same clock
    /// [`now_ns`](Self::now_ns) reads, so the difference is a real queueing
    /// delay. A record stamped in the future (clock read before the record was
    /// committed, or a zero timestamp) contributes no observation rather than
    /// a bogus one.
    pub fn drained(&self, now_ns: u64, event_ts_ns: u64) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        metrics.record_ringbuf_event(self.source);
        if event_ts_ns > 0 && now_ns >= event_ts_ns {
            #[allow(clippy::cast_precision_loss)]
            let seconds = (now_ns - event_ts_ns) as f64 / 1_000_000_000.0;
            metrics.observe_ringbuf_latency(self.source, seconds);
        }
    }

    /// Record a drained record that userspace threw away before the pipeline
    /// saw it.
    pub fn dropped(&self, reason: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.record_ringbuf_event_dropped(self.source, reason);
        }
    }
}

/// `CLOCK_BOOTTIME` in nanoseconds; `0` if the clock cannot be read.
///
/// `CLOCK_BOOTTIME` and not `CLOCK_MONOTONIC`: the kernel stamps events with
/// `bpf_ktime_get_boot_ns()`, which includes suspend time. Comparing against
/// `CLOCK_MONOTONIC` would report every event as arriving early by however
/// long the host had been suspended.
fn boottime_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a live, fully initialised `timespec` owned by this
    // frame; `clock_gettime` only writes through the pointer we pass.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) };
    if rc != 0 {
        return 0;
    }
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics, CtMetrics,
        DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics,
        FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
        ThreatIntelMetrics, ZoneMetrics,
    };
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        drained: Mutex<Vec<String>>,
        dropped: Mutex<Vec<(String, String)>>,
        latencies: Mutex<Vec<(String, f64)>>,
    }

    impl PacketMetrics for Recorder {}
    impl FirewallMetrics for Recorder {}
    impl AlertMetrics for Recorder {}
    impl IpsMetrics for Recorder {}
    impl DnsMetrics for Recorder {}
    impl DomainMetrics for Recorder {}
    impl SystemMetrics for Recorder {}
    impl ConfigMetrics for Recorder {}
    impl DlpMetrics for Recorder {}
    impl DdosMetrics for Recorder {}
    impl ConntrackMetrics for Recorder {}
    impl RoutingMetrics for Recorder {}
    impl AuditMetrics for Recorder {}
    impl LbMetrics for Recorder {}
    impl FingerprintMetrics for Recorder {}
    impl ContainerMetrics for Recorder {}
    impl CtMetrics for Recorder {}
    impl ThreatIntelMetrics for Recorder {}
    impl ZoneMetrics for Recorder {}
    impl EventMetrics for Recorder {
        fn record_ringbuf_event(&self, source: &str) {
            self.drained.lock().unwrap().push(source.to_string());
        }
        fn record_ringbuf_event_dropped(&self, source: &str, reason: &str) {
            self.dropped
                .lock()
                .unwrap()
                .push((source.to_string(), reason.to_string()));
        }
        fn observe_ringbuf_latency(&self, source: &str, seconds: f64) {
            self.latencies
                .lock()
                .unwrap()
                .push((source.to_string(), seconds));
        }
    }

    #[test]
    fn drained_records_source_and_latency() {
        let rec = Arc::new(Recorder::default());
        let obs = RingBufObserver::new("tc-ids", Arc::clone(&rec) as Arc<dyn MetricsPort>);

        obs.drained(2_000_000_000, 1_500_000_000);

        assert_eq!(rec.drained.lock().unwrap().as_slice(), ["tc-ids"]);
        let lat = rec.latencies.lock().unwrap();
        assert_eq!(lat.len(), 1);
        assert!((lat[0].1 - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn unusable_timestamp_counts_the_event_but_not_the_latency() {
        let rec = Arc::new(Recorder::default());
        let obs = RingBufObserver::new("tc-dns", Arc::clone(&rec) as Arc<dyn MetricsPort>);

        // Zero timestamp (never stamped) and a timestamp ahead of the clock
        // read must not turn into a latency observation.
        obs.drained(2_000_000_000, 0);
        obs.drained(2_000_000_000, 3_000_000_000);

        assert_eq!(rec.drained.lock().unwrap().len(), 2);
        assert!(rec.latencies.lock().unwrap().is_empty());
    }

    #[test]
    fn dropped_carries_source_and_reason() {
        let rec = Arc::new(Recorder::default());
        let obs = RingBufObserver::new("uprobe-dlp", Arc::clone(&rec) as Arc<dyn MetricsPort>);

        obs.dropped("channel_full");

        assert_eq!(
            rec.dropped.lock().unwrap().as_slice(),
            [("uprobe-dlp".to_string(), "channel_full".to_string())]
        );
    }

    #[test]
    fn disabled_observer_records_nothing_and_skips_the_clock() {
        let obs = RingBufObserver::disabled("xdp-firewall");
        assert_eq!(obs.now_ns(), 0);
        // Must not panic without a metrics sink behind it.
        obs.drained(1, 1);
        obs.dropped("channel_full");
    }

    #[test]
    fn boottime_is_monotonic_and_nonzero() {
        let first = boottime_now_ns();
        let second = boottime_now_ns();
        assert!(first > 0, "CLOCK_BOOTTIME must be readable");
        assert!(second >= first, "CLOCK_BOOTTIME must not go backwards");
    }
}
