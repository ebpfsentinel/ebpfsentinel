//! Following the writes this host pushes to file shares, off the flow
//! records, and raising an alert for a process that reaches several servers
//! it never wrote to before.
//!
//! It takes the flow records the way an export sink does, from a collector
//! of its own: the export's sampling, which a SIEM may want, would make a
//! volume here undercount, so this one reads every flow.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use domain::alert::entity::Alert;
use domain::common::error::DomainError;
use domain::flow::entity::FlowRecord;
use domain::share_writes::{ShareWrite, ShareWritesEngine, ShareWritesSettings};
use ports::secondary::flow_sink_port::{FlowSink, FlowSinkHealth};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::alert_event::AlertEvent;

/// The name the collector and the logs know this reader by.
pub const SHARE_WRITES_SINK: &str = "share_writes";

/// Reads flow records for writes to file shares.
pub struct ShareWritesService {
    engine: Mutex<ShareWritesEngine>,
    alerts: mpsc::Sender<AlertEvent>,
    writes: AtomicU64,
    raised: AtomicU64,
}

impl ShareWritesService {
    #[must_use]
    pub fn new(settings: ShareWritesSettings, alerts: mpsc::Sender<AlertEvent>) -> Self {
        Self {
            engine: Mutex::new(ShareWritesEngine::new(settings)),
            alerts,
            writes: AtomicU64::new(0),
            raised: AtomicU64::new(0),
        }
    }

    /// Writes to file shares taken since the agent started.
    #[must_use]
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    /// Alerts raised since the agent started.
    #[must_use]
    pub fn raised(&self) -> u64 {
        self.raised.load(Ordering::Relaxed)
    }

    /// The alerts one batch of records makes, in the order of the records.
    fn read(&self, records: &[FlowRecord]) -> Vec<AlertEvent> {
        let mut engine = self.engine.lock().unwrap_or_else(PoisonError::into_inner);
        let mut events = Vec::new();
        for write in records.iter().filter_map(ShareWrite::from_flow) {
            self.writes.fetch_add(1, Ordering::Relaxed);
            if let Some(verdict) = engine.observe(write) {
                warn!(
                    peers = verdict.peers.len(),
                    bytes = verdict.bytes(),
                    pid = verdict.workload.as_ref().map(|w| w.pid),
                    "writes to file servers this host never wrote to"
                );
                events.push(AlertEvent::System(Box::new(Alert::from_share_writes(
                    &verdict,
                ))));
            }
        }
        events
    }
}

impl FlowSink for ShareWritesService {
    fn name(&self) -> &str {
        SHARE_WRITES_SINK
    }

    fn send<'a>(
        &'a self,
        records: &'a [FlowRecord],
    ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
        Box::pin(async move {
            for event in self.read(records) {
                self.raised.fetch_add(1, Ordering::Relaxed);
                if self.alerts.send(event).await.is_err() {
                    debug!("alert pipeline closed, share writes stop raising");
                    break;
                }
            }
            Ok(())
        })
    }

    fn health<'a>(&'a self) -> Pin<Box<dyn Future<Output = FlowSinkHealth> + Send + 'a>> {
        Box::pin(async move {
            FlowSinkHealth {
                records_sent: self.writes(),
                ..FlowSinkHealth::new(SHARE_WRITES_SINK)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::flow::entity::FlowEndReason;
    use domain::share_writes::SHARE_WRITES_COMPONENT;
    use domain::workload::entity::{Workload, WorkloadSource};
    use std::net::IpAddr;

    const MIB: u64 = 1_048_576;

    fn settings() -> ShareWritesSettings {
        ShareWritesSettings {
            learning_ns: 3_600 * 1_000_000_000,
            window_ns: 300 * 1_000_000_000,
            min_new_peers: 3,
            min_bytes_per_peer: MIB,
        }
    }

    fn record(server: u8, port: u16, bytes: u64, end_ms: u64) -> FlowRecord {
        FlowRecord {
            src: IpAddr::from([10, 0, 0, 5]),
            dst: IpAddr::from([10, 0, 1, server]),
            src_port: 50_000,
            dst_port: port,
            protocol: 6,
            packets: 100,
            bytes,
            packets_rev: 100,
            bytes_rev: 512,
            start_ms: end_ms.saturating_sub(1_000),
            end_ms,
            reason: FlowEndReason::ActiveTimeout,
            workload: Workload::new(4_410, WorkloadSource::Socket).map(|mut w| {
                w.exe = Some("/tmp/.x".to_string());
                w
            }),
        }
    }

    #[tokio::test]
    async fn writes_to_new_servers_after_learning_raise_one_alert() {
        let (tx, mut rx) = mpsc::channel(8);
        let service = ShareWritesService::new(settings(), tx);
        let learned = 1_000;
        let later = 2 * 3_600 * 1_000;
        service
            .send(&[record(1, 445, 8 * MIB, learned)])
            .await
            .expect("taken");
        service
            .send(&[
                record(1, 445, 8 * MIB, later),
                record(50, 445, 4 * MIB, later),
                record(51, 443, 4 * MIB, later),
                record(52, 139, 4 * MIB, later),
                record(53, 445, 4 * MIB, later + 1_000),
                record(54, 445, 4 * MIB, later + 2_000),
            ])
            .await
            .expect("taken");

        let AlertEvent::System(alert) = rx.try_recv().expect("one alert") else {
            panic!("a system alert");
        };
        assert_eq!(alert.component, SHARE_WRITES_COMPONENT);
        assert_eq!(alert.tgid, Some(4_410));
        assert_eq!(alert.dst_port, 445);
        assert!(alert.message.contains("3 file servers"));
        assert!(rx.try_recv().is_err(), "one alert per window");
        assert_eq!(service.writes(), 6, "the flow to 443 is not a write");
        assert_eq!(service.raised(), 1);
        assert_eq!(service.health().await.records_sent, 6);
    }

    #[tokio::test]
    async fn the_servers_it_learned_raise_nothing() {
        let (tx, mut rx) = mpsc::channel(8);
        let service = ShareWritesService::new(settings(), tx);
        let learning: Vec<FlowRecord> = (1..=10).map(|n| record(n, 445, MIB, 1_000)).collect();
        service.send(&learning).await.expect("taken");
        let nightly: Vec<FlowRecord> = (1..=10)
            .map(|n| record(n, 445, 500 * MIB, 86_400_000))
            .collect();
        service.send(&nightly).await.expect("taken");
        assert!(rx.try_recv().is_err());
    }
}
