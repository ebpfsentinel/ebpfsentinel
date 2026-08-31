#![allow(unsafe_code)] // clock_gettime(CLOCK_BOOTTIME) has no safe wrapper in libc

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// Replace the stamp a decoded event carries.
///
/// The match is exhaustive on purpose: a variant added to [`AgentEvent`] has to
/// say which clock its stamp is on before it will compile.
fn set_event_timestamp_ns(event: &mut AgentEvent, timestamp_ns: u64) {
    match event {
        AgentEvent::L4(e) => e.timestamp_ns = timestamp_ns,
        AgentEvent::L7 { header, .. } => header.timestamp_ns = timestamp_ns,
        AgentEvent::Dns { header, .. } => header.timestamp_ns = timestamp_ns,
        AgentEvent::Dlp(e) => e.timestamp_ns = timestamp_ns,
    }
}

/// What separates a kernel `CLOCK_BOOTTIME` stamp from a Unix epoch one.
///
/// Read once and cached. Both clocks advance at the same rate, so the offset is
/// a constant for the life of the process; reading it per event would put a
/// second syscall on the drain loop for a number that cannot have changed.
/// Suspend needs no correction either, because `CLOCK_BOOTTIME` counts it,
/// which is why the kernel stamps with `bpf_ktime_get_boot_ns()` rather than
/// `bpf_ktime_get_ns()`.
fn boot_epoch_offset_ns() -> u64 {
    static OFFSET: OnceLock<u64> = OnceLock::new();
    *OFFSET.get_or_init(|| {
        let epoch_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_nanos()).ok())
            .unwrap_or(0);
        epoch_ns.saturating_sub(boottime_now_ns())
    })
}

/// Convert a kernel stamp into nanoseconds since the Unix epoch.
///
/// The kernel stamps every record with `bpf_ktime_get_boot_ns()`, which counts
/// from boot rather than from 1970. Carried through unconverted it reaches an
/// exporter as a date in January 1970, and an alert raised in userspace, which
/// is stamped from the wall clock, ends up decades away from a kernel alert
/// raised on the same host a second earlier. Converting here rather than in
/// each exporter is what keeps the two comparable.
///
/// `0` is left alone: several call sites pass a zero stamp deliberately to mean
/// "no time", and turning that into the boot instant would be a date rather
/// than the absence of one.
#[must_use]
pub fn boottime_to_epoch_ns(boot_ns: u64) -> u64 {
    if boot_ns == 0 {
        return 0;
    }
    boot_ns.saturating_add(boot_epoch_offset_ns())
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

    /// Account for one drained record and put its stamp on the wall clock.
    ///
    /// Both halves belong together and in this order. The latency observation
    /// compares the record against [`now_ns`](Self::now_ns), which reads the
    /// same `CLOCK_BOOTTIME` the kernel stamped it with, so it has to be taken
    /// before the conversion; everything downstream of the ring buffer wants an
    /// epoch stamp, so the conversion has to happen before the event is handed
    /// on. A reader that accounts for a record is therefore also a reader that
    /// normalises it, rather than two things a new reader has to remember.
    pub fn accept(&self, now_ns: u64, event: &mut AgentEvent) {
        let event_ts_ns = event_timestamp_ns(event);
        self.drained(now_ns, event_ts_ns);
        set_event_timestamp_ns(event, boottime_to_epoch_ns(event_ts_ns));
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
    use ebpf_common::dlp::DlpEvent;
    use ebpf_common::dns::DnsEvent;
    use ebpf_common::event::PacketEvent;
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

    fn wall_clock_now_ns() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("wall clock is after 1970")
                .as_nanos(),
        )
        .expect("nanoseconds since 1970 fit in u64")
    }

    #[test]
    fn a_kernel_stamp_lands_on_the_wall_clock() {
        // What the kernel would have stamped a moment ago: a boot-relative
        // value, small on any host that has not been up for decades.
        let boot_ns = boottime_now_ns();
        let converted = boottime_to_epoch_ns(boot_ns);
        let now = wall_clock_now_ns();

        // Within a second of now, in either direction: the offset is read from
        // two clocks a few instructions apart, and the test itself takes time.
        let delta = converted.abs_diff(now);
        assert!(
            delta < 1_000_000_000,
            "converted stamp {converted} is {delta}ns from the wall clock {now}"
        );
    }

    #[test]
    fn a_stamp_of_zero_stays_a_stamp_of_zero() {
        // Zero means "no time", not "the instant the host booted". Several
        // call sites pass it deliberately.
        assert_eq!(boottime_to_epoch_ns(0), 0);
    }

    #[test]
    fn conversion_preserves_the_distance_between_two_stamps() {
        let earlier = boottime_to_epoch_ns(1_000_000_000);
        let later = boottime_to_epoch_ns(1_500_000_000);
        assert!(later > earlier);
        assert_eq!(later - earlier, 500_000_000);
    }

    fn packet_event_stamped(timestamp_ns: u64) -> PacketEvent {
        let mut event: PacketEvent = unsafe { std::mem::zeroed() };
        event.timestamp_ns = timestamp_ns;
        event
    }

    fn dns_event_stamped(timestamp_ns: u64) -> DnsEvent {
        let mut event: DnsEvent = unsafe { std::mem::zeroed() };
        event.timestamp_ns = timestamp_ns;
        event
    }

    fn dlp_event_stamped(timestamp_ns: u64) -> DlpEvent {
        let mut event: DlpEvent = unsafe { std::mem::zeroed() };
        event.timestamp_ns = timestamp_ns;
        event
    }

    #[test]
    fn every_variant_leaves_the_ring_buffer_on_the_wall_clock() {
        let obs = RingBufObserver::disabled("xdp-firewall");
        let boot_ns = boottime_now_ns();
        let now = wall_clock_now_ns();

        let mut events = vec![
            AgentEvent::L4(packet_event_stamped(boot_ns)),
            AgentEvent::L7 {
                header: packet_event_stamped(boot_ns),
                payload: Vec::new(),
            },
            AgentEvent::Dns {
                header: dns_event_stamped(boot_ns),
                payload: Vec::new(),
            },
            AgentEvent::Dlp(Box::new(dlp_event_stamped(boot_ns))),
        ];

        for event in &mut events {
            obs.accept(0, event);
            let stamped = event_timestamp_ns(event);
            assert!(
                stamped.abs_diff(now) < 1_000_000_000,
                "a record left the ring buffer stamped {stamped}, not near {now}"
            );
        }
    }

    #[test]
    fn accepting_a_record_still_counts_it_against_the_kernel_clock() {
        let rec = Arc::new(Recorder::default());
        let obs = RingBufObserver::new("tc-ids", Arc::clone(&rec) as Arc<dyn MetricsPort>);

        // The latency observation compares two boot-relative values, so it has
        // to be taken before the stamp is moved onto the wall clock.
        let mut event = AgentEvent::L4(packet_event_stamped(1_500_000_000));
        obs.accept(2_000_000_000, &mut event);

        assert_eq!(rec.drained.lock().unwrap().as_slice(), ["tc-ids"]);
        let lat = rec.latencies.lock().unwrap();
        assert_eq!(lat.len(), 1);
        assert!((lat[0].1 - 0.5).abs() < f64::EPSILON);
    }
}
