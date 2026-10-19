//! Flow export: the two tasks between the kernel's readings and a collector.
//!
//! The split is deliberate. [`FlowCollector`] holds the table and never
//! blocks: it takes conntrack events and the tick of a clock, and pushes
//! finished records into a bounded queue. [`FlowDispatcher`] drains that
//! queue and hands batches to the sinks, where a write can take as long as a
//! TCP connect to a collector that is not listening.
//!
//! A queue between them rather than a direct call is the whole point. A SIEM
//! that stops answering must cost flow records and nothing else: it must not
//! slow the conntrack reader, and it must never make the agent stop
//! forwarding traffic. So the queue is bounded, a full queue drops the
//! newest record, and the drop is a counter under its own reason - never a
//! silence, and never backpressure that climbs into the datapath.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use domain::common::error::DomainError;
use domain::conntrack::entity::{Connection, ConntrackEvent, ConntrackEventType};
use domain::flow::entity::{FlowRecord, FlowTable, FlowTableLimits, FlowTableStats};
use ports::secondary::flow_sink_port::{FlowSink, FlowSinkHealth};
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::socket_identity_port::FlowEndpoints;
use tokio::sync::{broadcast, mpsc};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::workload_resolver::WorkloadResolver;

/// The reason label on a record that was built and never written.
pub const DROP_QUEUE_FULL: &str = "queue_full";
/// Records lost because the conntrack broadcast moved on while the collector
/// was busy: the reading itself never arrived, so the flow is short of bytes
/// rather than missing, and an operator is owed the difference.
pub const DROP_CONNTRACK_LAG: &str = "conntrack_lag";
/// Records a sink refused.
pub const DROP_SINK_ERROR: &str = "sink_error";

/// Unix milliseconds. The one place the clock is read, so the table itself
/// stays pure and every test of it names its own instants.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The flow endpoints of a conntrack row, for the workload lookup.
fn flow_of(connection: &Connection) -> Option<FlowEndpoints> {
    Some(FlowEndpoints {
        local_addr: connection.src_ip.parse().ok()?,
        remote_addr: connection.dst_ip.parse().ok()?,
        local_port: connection.src_port,
        remote_port: connection.dst_port,
        protocol: connection.protocol,
    })
}

/// One word for a failed write, so the metric's cardinality is the number of
/// ways a sink can fail rather than the number of messages it can produce.
fn failure_reason(error: &DomainError) -> &'static str {
    match error {
        DomainError::InvalidConfig(_) => "config",
        DomainError::PermissionDenied(_) => "permission",
        DomainError::EngineError(_) => "transport",
        _ => "error",
    }
}

/// What the collector and the dispatcher were configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowExportSettings {
    pub limits: FlowTableLimits,
    /// Records held between the two tasks.
    pub queue_depth: usize,
    /// Records handed to a sink at once.
    pub batch_size: usize,
    /// How often the table is asked what the clock has made due.
    pub tick_interval: Duration,
}

impl Default for FlowExportSettings {
    fn default() -> Self {
        Self {
            limits: FlowTableLimits::default(),
            queue_depth: 4_096,
            batch_size: 256,
            tick_interval: Duration::from_secs(5),
        }
    }
}

/// The queue the two halves share.
#[must_use]
pub fn flow_queue(depth: usize) -> (mpsc::Sender<FlowRecord>, mpsc::Receiver<FlowRecord>) {
    mpsc::channel(depth.max(1))
}

/// Readings in, records into the queue.
pub struct FlowCollector {
    table: FlowTable,
    workloads: WorkloadResolver,
    queue: mpsc::Sender<FlowRecord>,
    metrics: Arc<dyn MetricsPort>,
    tick_interval: Duration,
    /// Published rather than returned, because the table lives inside the
    /// task and the status route reads it from outside.
    published: Arc<Mutex<FlowTableStats>>,
    dropped: Arc<AtomicU64>,
}

impl FlowCollector {
    #[must_use]
    pub fn new(
        settings: FlowExportSettings,
        workloads: WorkloadResolver,
        queue: mpsc::Sender<FlowRecord>,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        Self {
            table: FlowTable::new(settings.limits),
            workloads,
            queue,
            metrics,
            tick_interval: settings.tick_interval,
            published: Arc::new(Mutex::new(FlowTableStats::default())),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The counters the status route reads while the task owns the table.
    #[must_use]
    pub fn published_stats(&self) -> Arc<Mutex<FlowTableStats>> {
        Arc::clone(&self.published)
    }

    /// The records this collector could not hand on, shared the same way.
    #[must_use]
    pub fn queue_drops(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.dropped)
    }

    /// What the table has done, for the status route.
    #[must_use]
    pub fn stats(&self) -> FlowTableStats {
        self.table.stats()
    }

    /// Records this collector could not hand on.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Copy the table's counters where a reader outside the task can see them.
    fn publish(&self) {
        if let Ok(mut published) = self.published.lock() {
            *published = self.table.stats();
        }
    }

    /// Run until cancelled, then flush what the table still holds.
    ///
    /// The flush is not optional: a flow whose record was never written is
    /// traffic the node saw and nobody can ask about afterwards, and an agent
    /// restarting on a new configuration would lose a minute of every open
    /// connection on the host.
    pub async fn run(
        mut self,
        mut events: broadcast::Receiver<ConntrackEvent>,
        cancel: CancellationToken,
    ) {
        info!(
            active_timeout_ms = self.table.limits().active_timeout_ms,
            idle_timeout_ms = self.table.limits().idle_timeout_ms,
            sampling = self.table.limits().sampling,
            "flow export collecting"
        );
        let mut ticker = tokio::time::interval(self.tick_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = ticker.tick() => {
                    let due = self.table.due(now_ms());
                    self.push_all(due);
                }
                received = events.recv() => match received {
                    Ok(event) => self.observe(&event),
                    Err(broadcast::error::RecvError::Lagged(missed)) => {
                        self.metrics.record_flows_dropped(DROP_CONNTRACK_LAG, missed);
                        warn!(missed, "conntrack readings missed, flow counters undercount");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
        }
        let remaining = self.table.flush(now_ms());
        let count = remaining.len();
        self.push_all(remaining);
        self.publish();
        debug!(count, "flow export flushed on shutdown");
    }

    /// Take one reading.
    fn observe(&mut self, event: &ConntrackEvent) {
        let now = now_ms();
        let record = match event.event_type {
            ConntrackEventType::Destroy => self.table.close(&event.connection, now),
            ConntrackEventType::New | ConntrackEventType::Update => {
                let workload = self.resolve(&event.connection);
                self.table.observe(&event.connection, now, workload)
            }
        };
        if let Some(record) = record {
            self.push(record);
        }
    }

    /// The workload behind a row: the one the reading already carried, else
    /// the socket index's answer. A row this node only forwarded resolves to
    /// nothing, and nothing is what the record then carries.
    fn resolve(&self, connection: &Connection) -> Option<domain::workload::entity::Workload> {
        if connection.workload.is_some() {
            return connection.workload.clone();
        }
        if !self.workloads.is_wired() {
            return None;
        }
        flow_of(connection).and_then(|flow| self.workloads.by_flow(&flow))
    }

    fn push_all(&mut self, records: Vec<FlowRecord>) {
        for record in records {
            self.push(record);
        }
    }

    /// Hand a record on, or count it as dropped. Never waits: the caller is
    /// the task reading the kernel's events.
    fn push(&mut self, record: FlowRecord) {
        if self.queue.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_flows_dropped(DROP_QUEUE_FULL, 1);
        }
        self.publish();
    }
}

/// Queue out, sinks in.
pub struct FlowDispatcher {
    sinks: Vec<Arc<dyn FlowSink>>,
    metrics: Arc<dyn MetricsPort>,
    batch_size: usize,
}

impl FlowDispatcher {
    #[must_use]
    pub fn new(
        sinks: Vec<Arc<dyn FlowSink>>,
        metrics: Arc<dyn MetricsPort>,
        settings: FlowExportSettings,
    ) -> Self {
        Self {
            sinks,
            metrics,
            batch_size: settings.batch_size.max(1),
        }
    }

    /// What every sink says about itself.
    pub async fn health(&self) -> Vec<FlowSinkHealth> {
        let mut health = Vec::with_capacity(self.sinks.len());
        for sink in &self.sinks {
            health.push(sink.health().await);
        }
        health
    }

    /// The names of the sinks that cannot currently reach their destination.
    pub async fn unhealthy(&self) -> Vec<String> {
        self.health()
            .await
            .into_iter()
            .filter(|health| !health.healthy)
            .map(|health| health.name)
            .collect()
    }

    /// Drain the queue until it closes or the agent is cancelled, then write
    /// what the collector's own flush put there and close the sinks.
    pub async fn run(&self, mut queue: mpsc::Receiver<FlowRecord>, cancel: CancellationToken) {
        let mut batch = Vec::with_capacity(self.batch_size);
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                count = queue.recv_many(&mut batch, self.batch_size) => {
                    if count == 0 {
                        break;
                    }
                    self.deliver(&batch).await;
                    batch.clear();
                }
            }
        }
        // The collector flushes its table when it is cancelled, so the last
        // records arrive after the cancellation the loop above just left on.
        loop {
            let count = queue.recv_many(&mut batch, self.batch_size).await;
            if count == 0 {
                break;
            }
            self.deliver(&batch).await;
            batch.clear();
        }
        for sink in &self.sinks {
            if let Err(error) = sink.close().await {
                warn!(sink = sink.name(), %error, "flow sink did not close cleanly");
            }
        }
    }

    /// Hand one batch to every sink. A sink that refuses costs its own
    /// records and not another sink's: the batch is offered to each in turn.
    async fn deliver(&self, records: &[FlowRecord]) {
        if records.is_empty() {
            return;
        }
        let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
        for sink in &self.sinks {
            match sink.send(records).await {
                Ok(()) => self.metrics.record_flows_exported(sink.name(), count),
                Err(error) => {
                    self.metrics
                        .record_flow_export_failure(sink.name(), failure_reason(&error));
                    self.metrics.record_flows_dropped(DROP_SINK_ERROR, count);
                    debug!(sink = sink.name(), %error, "flow sink refused a batch");
                }
            }
        }
    }
}

/// What the status route reads, and what the agent holds on to once both
/// tasks are running.
#[derive(Clone)]
pub struct FlowExportHandle {
    published: Arc<Mutex<FlowTableStats>>,
    queue_drops: Arc<AtomicU64>,
    dispatcher: Arc<FlowDispatcher>,
    settings: FlowExportSettings,
}

impl FlowExportHandle {
    /// What the flow table has observed, sampled out, exported and evicted.
    #[must_use]
    pub fn table_stats(&self) -> FlowTableStats {
        self.published
            .lock()
            .map(|published| *published)
            .unwrap_or_default()
    }

    /// Records built and never handed to a sink because the queue was full.
    #[must_use]
    pub fn queue_drops(&self) -> u64 {
        self.queue_drops.load(Ordering::Relaxed)
    }

    /// What this exporter was configured with.
    #[must_use]
    pub const fn settings(&self) -> FlowExportSettings {
        self.settings
    }

    /// What every sink says about itself.
    pub async fn sinks(&self) -> Vec<FlowSinkHealth> {
        self.dispatcher.health().await
    }

    /// The sinks that cannot currently reach their destination.
    pub async fn unhealthy(&self) -> Vec<String> {
        self.dispatcher.unhealthy().await
    }
}

/// Start the two tasks and hand back what reads them.
///
/// Returns `None` where there is no sink to write to: an exporter with
/// nowhere to send is a table that fills and empties for nothing, and it must
/// not cost the conntrack reader a single broadcast receiver.
#[must_use]
pub fn spawn_flow_export(
    settings: FlowExportSettings,
    workloads: WorkloadResolver,
    sinks: Vec<Arc<dyn FlowSink>>,
    metrics: Arc<dyn MetricsPort>,
    events: broadcast::Receiver<ConntrackEvent>,
    cancel: CancellationToken,
) -> Option<FlowExportHandle> {
    if sinks.is_empty() {
        return None;
    }
    let names: Vec<&str> = sinks.iter().map(|sink| sink.name()).collect();
    info!(sinks = ?names, "flow export starting");
    let (queue_tx, queue_rx) = flow_queue(settings.queue_depth);
    let collector = FlowCollector::new(settings, workloads, queue_tx, Arc::clone(&metrics));
    let handle = FlowExportHandle {
        published: collector.published_stats(),
        queue_drops: collector.queue_drops(),
        dispatcher: Arc::new(FlowDispatcher::new(sinks, metrics, settings)),
        settings,
    };
    let dispatcher = Arc::clone(&handle.dispatcher);
    let dispatcher_cancel = cancel.clone();
    tokio::spawn(async move {
        dispatcher.run(queue_rx, dispatcher_cancel).await;
    });
    tokio::spawn(collector.run(events, cancel));
    Some(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::conntrack::entity::ConnectionState;
    use domain::flow::entity::FlowEndReason;
    use ports::test_utils::NoopMetrics;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn connection(sport: u16, packets: u32) -> Connection {
        Connection {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: sport,
            dst_port: 443,
            protocol: 6,
            state: ConnectionState::Established,
            packets_fwd: packets,
            packets_rev: packets,
            bytes_fwd: packets * 100,
            bytes_rev: packets * 100,
            workload: None,
        }
    }

    fn event(event_type: ConntrackEventType, connection: Connection) -> ConntrackEvent {
        ConntrackEvent {
            event_type,
            connection,
        }
    }

    fn record() -> FlowRecord {
        FlowRecord {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            src_port: 1000,
            dst_port: 443,
            protocol: 6,
            packets: 1,
            bytes: 100,
            packets_rev: 1,
            bytes_rev: 100,
            start_ms: 0,
            end_ms: 1,
            reason: FlowEndReason::EndOfFlow,
            workload: None,
        }
    }

    /// A sink that remembers what it was handed, and refuses on demand.
    struct RecordingSink {
        name: String,
        written: Mutex<Vec<FlowRecord>>,
        refuse: bool,
        closed: AtomicU64,
    }

    impl RecordingSink {
        fn new(name: &str, refuse: bool) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                written: Mutex::new(Vec::new()),
                refuse,
                closed: AtomicU64::new(0),
            })
        }

        fn written(&self) -> Vec<FlowRecord> {
            self.written.lock().expect("not poisoned").clone()
        }
    }

    impl FlowSink for RecordingSink {
        fn name(&self) -> &str {
            &self.name
        }

        fn send<'a>(
            &'a self,
            records: &'a [FlowRecord],
        ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
            Box::pin(async move {
                if self.refuse {
                    return Err(DomainError::EngineError("no route".to_string()));
                }
                self.written
                    .lock()
                    .expect("not poisoned")
                    .extend_from_slice(records);
                Ok(())
            })
        }

        fn health<'a>(&'a self) -> Pin<Box<dyn Future<Output = FlowSinkHealth> + Send + 'a>> {
            Box::pin(async move {
                FlowSinkHealth {
                    healthy: !self.refuse,
                    detail: self.refuse.then(|| "no route".to_string()),
                    ..FlowSinkHealth::new(self.name.clone())
                }
            })
        }

        fn close<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
            self.closed.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    fn settings() -> FlowExportSettings {
        FlowExportSettings {
            limits: FlowTableLimits {
                idle_timeout_ms: 1,
                active_timeout_ms: 1,
                ..FlowTableLimits::default()
            },
            queue_depth: 64,
            batch_size: 8,
            tick_interval: Duration::from_millis(10),
        }
    }

    #[tokio::test]
    async fn a_destroyed_flow_reaches_the_queue() {
        let (tx, mut rx) = flow_queue(8);
        let mut collector = FlowCollector::new(
            settings(),
            WorkloadResolver::new(),
            tx,
            Arc::new(NoopMetrics),
        );
        collector.observe(&event(ConntrackEventType::New, connection(1000, 1)));
        collector.observe(&event(ConntrackEventType::Destroy, connection(1000, 4)));
        let record = rx.try_recv().expect("one record");
        assert_eq!(record.packets, 4);
        assert_eq!(record.reason, FlowEndReason::EndOfFlow);
    }

    #[tokio::test]
    async fn a_full_queue_drops_rather_than_blocks() {
        let (tx, _rx) = flow_queue(1);
        let mut collector = FlowCollector::new(
            settings(),
            WorkloadResolver::new(),
            tx,
            Arc::new(NoopMetrics),
        );
        for port in 0..8u16 {
            collector.observe(&event(ConntrackEventType::New, connection(1000 + port, 1)));
            collector.observe(&event(
                ConntrackEventType::Destroy,
                connection(1000 + port, 2),
            ));
        }
        assert!(
            collector.dropped() > 0,
            "a bounded queue costs records, and the count says so"
        );
    }

    #[tokio::test]
    async fn the_collector_flushes_its_table_when_it_is_cancelled() {
        let (tx, mut rx) = flow_queue(16);
        let mut collector = FlowCollector::new(
            settings(),
            WorkloadResolver::new(),
            tx,
            Arc::new(NoopMetrics),
        );
        collector.observe(&event(ConntrackEventType::New, connection(1000, 7)));
        let (events_tx, events_rx) = broadcast::channel(4);
        let cancel = CancellationToken::new();
        cancel.cancel();
        collector.run(events_rx, cancel).await;
        drop(events_tx);
        let record = rx.try_recv().expect("the open flow was written out");
        assert_eq!(record.reason, FlowEndReason::Forced);
        assert_eq!(record.packets, 7);
    }

    #[tokio::test]
    async fn the_collector_closes_when_the_conntrack_channel_does() {
        let (tx, _rx) = flow_queue(16);
        let collector = FlowCollector::new(
            settings(),
            WorkloadResolver::new(),
            tx,
            Arc::new(NoopMetrics),
        );
        let (events_tx, events_rx) = broadcast::channel(4);
        drop(events_tx);
        collector.run(events_rx, CancellationToken::new()).await;
    }

    #[tokio::test]
    async fn a_reading_from_the_channel_is_taken_and_a_tick_writes_it() {
        let (tx, mut rx) = flow_queue(16);
        let collector = FlowCollector::new(
            settings(),
            WorkloadResolver::new(),
            tx,
            Arc::new(NoopMetrics),
        );
        let (events_tx, events_rx) = broadcast::channel(4);
        events_tx
            .send(event(ConntrackEventType::New, connection(1000, 3)))
            .expect("a receiver is listening");
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(collector.run(events_rx, cancel.clone()));
        let record = loop {
            if let Ok(record) = rx.try_recv() {
                break record;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(record.packets, 3);
        cancel.cancel();
        drop(events_tx);
        handle.await.expect("the task ends");
    }

    #[tokio::test]
    async fn every_sink_is_handed_every_batch() {
        let first = RecordingSink::new("ipfix-0", false);
        let second = RecordingSink::new("ipfix-1", false);
        let dispatcher = FlowDispatcher::new(
            vec![first.clone(), second.clone()],
            Arc::new(NoopMetrics),
            settings(),
        );
        dispatcher.deliver(&[record(), record()]).await;
        assert_eq!(first.written().len(), 2);
        assert_eq!(second.written().len(), 2);
    }

    #[tokio::test]
    async fn a_sink_that_refuses_does_not_cost_another_sink_its_batch() {
        let broken = RecordingSink::new("ipfix-0", true);
        let working = RecordingSink::new("ipfix-1", false);
        let dispatcher = FlowDispatcher::new(
            vec![broken.clone(), working.clone()],
            Arc::new(NoopMetrics),
            settings(),
        );
        dispatcher.deliver(&[record()]).await;
        assert!(broken.written().is_empty());
        assert_eq!(working.written().len(), 1);
    }

    #[tokio::test]
    async fn an_empty_batch_is_not_offered_to_a_sink() {
        let sink = RecordingSink::new("ipfix-0", false);
        let dispatcher = FlowDispatcher::new(vec![sink.clone()], Arc::new(NoopMetrics), settings());
        dispatcher.deliver(&[]).await;
        assert!(sink.written().is_empty());
    }

    #[tokio::test]
    async fn the_unhealthy_sinks_are_named_and_the_healthy_ones_are_not() {
        let broken = RecordingSink::new("ipfix-0", true);
        let working = RecordingSink::new("ipfix-1", false);
        let dispatcher =
            FlowDispatcher::new(vec![broken, working], Arc::new(NoopMetrics), settings());
        assert_eq!(dispatcher.unhealthy().await, vec!["ipfix-0".to_string()]);
        let health = dispatcher.health().await;
        assert_eq!(health.len(), 2);
        assert_eq!(health[0].detail.as_deref(), Some("no route"));
        assert!(health[1].detail.is_none());
    }

    #[tokio::test]
    async fn the_dispatcher_drains_the_queue_and_closes_its_sinks() {
        let sink = RecordingSink::new("ipfix-0", false);
        let dispatcher = FlowDispatcher::new(vec![sink.clone()], Arc::new(NoopMetrics), settings());
        let (tx, rx) = flow_queue(16);
        for _ in 0..3 {
            tx.try_send(record()).expect("room");
        }
        drop(tx);
        dispatcher.run(rx, CancellationToken::new()).await;
        assert_eq!(sink.written().len(), 3);
        assert_eq!(sink.closed.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_cancelled_dispatcher_still_writes_what_the_flush_left() {
        let sink = RecordingSink::new("ipfix-0", false);
        let dispatcher = FlowDispatcher::new(vec![sink.clone()], Arc::new(NoopMetrics), settings());
        let (tx, rx) = flow_queue(16);
        let cancel = CancellationToken::new();
        cancel.cancel();
        tx.try_send(record()).expect("room");
        drop(tx);
        dispatcher.run(rx, cancel).await;
        assert_eq!(
            sink.written().len(),
            1,
            "the record the collector flushed is not thrown away"
        );
    }

    #[tokio::test]
    async fn an_exporter_with_no_sink_is_not_started() {
        let (_tx, rx) = broadcast::channel(4);
        assert!(
            spawn_flow_export(
                settings(),
                WorkloadResolver::new(),
                Vec::new(),
                Arc::new(NoopMetrics),
                rx,
                CancellationToken::new(),
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn the_handle_reads_the_table_and_the_sinks_from_outside_the_tasks() {
        let sink = RecordingSink::new("ipfix-0", false);
        let (events_tx, events_rx) = broadcast::channel(8);
        let cancel = CancellationToken::new();
        let handle = spawn_flow_export(
            settings(),
            WorkloadResolver::new(),
            vec![sink.clone()],
            Arc::new(NoopMetrics),
            events_rx,
            cancel.clone(),
        )
        .expect("one sink is enough");
        assert_eq!(handle.queue_drops(), 0);
        assert!(handle.unhealthy().await.is_empty());
        assert_eq!(handle.settings().batch_size, 8);

        events_tx
            .send(event(ConntrackEventType::New, connection(1000, 3)))
            .expect("a receiver is listening");
        events_tx
            .send(event(ConntrackEventType::Destroy, connection(1000, 6)))
            .expect("a receiver is listening");
        let written = loop {
            let written = sink.written();
            if !written.is_empty() {
                break written;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(written[0].packets, 6);
        assert_eq!(handle.table_stats().observed, 1);
        assert_eq!(handle.table_stats().exported, 1);
        cancel.cancel();
        drop(events_tx);
    }

    #[test]
    fn a_failure_is_labelled_by_kind_rather_than_by_message() {
        assert_eq!(
            failure_reason(&DomainError::EngineError("connection refused".to_string())),
            "transport"
        );
        assert_eq!(
            failure_reason(&DomainError::InvalidConfig("bad address".to_string())),
            "config"
        );
        assert_eq!(
            failure_reason(&DomainError::PermissionDenied("no".to_string())),
            "permission"
        );
        assert_eq!(
            failure_reason(&DomainError::RuleNotFound("x".to_string())),
            "error"
        );
    }

    #[test]
    fn a_row_whose_address_does_not_parse_has_no_endpoints_to_look_up() {
        let mut broken = connection(1000, 1);
        broken.src_ip = "nonsense".to_string();
        assert!(flow_of(&broken).is_none());
    }

    #[test]
    fn the_clock_is_read_in_milliseconds_since_the_epoch() {
        assert!(now_ms() > 1_700_000_000_000, "a plausible wall clock");
    }
}
