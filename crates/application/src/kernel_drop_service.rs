//! The packets the kernel dropped, read on a cadence and kept for the API.
//!
//! Each poll reads the kernel-side counter whole, folds it into a reading,
//! adds what moved since the last poll to the Prometheus counter, and keeps
//! the reading for whoever asks. A read that fails leaves the last reading
//! in place and says so, rather than answering that nothing was dropped.

use std::sync::{Arc, Mutex, PoisonError};

use domain::drops::{DropDeltas, DropReading};
use ports::secondary::drop_counter_port::DropCounterPort;
use ports::secondary::metrics_port::PacketMetrics;
use tracing::warn;

/// What the service answers: the latest reading and how it was obtained.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelDropsSnapshot {
    pub reading: DropReading,
    /// Polls that have read the counter since the agent started.
    pub polls: u64,
    /// Why the last poll could not read the counter, `None` when it could.
    pub last_error: Option<String>,
}

pub struct KernelDropService {
    source: Box<dyn DropCounterPort>,
    metrics: Arc<dyn PacketMetrics>,
    state: Mutex<(DropDeltas, KernelDropsSnapshot)>,
}

impl KernelDropService {
    #[must_use]
    pub fn new(source: Box<dyn DropCounterPort>, metrics: Arc<dyn PacketMetrics>) -> Self {
        Self {
            source,
            metrics,
            state: Mutex::new((DropDeltas::default(), KernelDropsSnapshot::default())),
        }
    }

    /// Read the counter once and publish what moved.
    pub fn poll(&self) {
        let read = self.source.read();
        // The deltas and the snapshot change together, so a reader never sees
        // a reading whose increments were not published.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (deltas, snapshot) = &mut *state;
        match read {
            Ok((raw, uncounted)) => {
                let reading = DropReading::from_raw(&raw, uncounted);
                let increments = deltas.advance(&reading);
                for (reason, interface, added) in &increments.counts {
                    self.metrics.record_kernel_drops(reason, interface, *added);
                }
                if increments.uncounted > 0 {
                    self.metrics
                        .record_kernel_drops_uncounted(increments.uncounted);
                }
                snapshot.reading = reading;
                snapshot.polls = snapshot.polls.saturating_add(1);
                snapshot.last_error = None;
            }
            Err(e) => {
                warn!(error = %e, "kernel drop counter read failed");
                snapshot.last_error = Some(e.to_string());
            }
        }
    }

    /// The latest reading.
    #[must_use]
    pub fn snapshot(&self) -> KernelDropsSnapshot {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .1
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::error::DomainError;
    use domain::drops::RawDrop;

    type Recorded = Vec<(String, String, u64)>;

    #[derive(Default)]
    struct Recorder(Mutex<Recorded>, Mutex<u64>);

    impl PacketMetrics for Recorder {
        fn record_kernel_drops(&self, reason: &str, interface: &str, count: u64) {
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
                reason.into(),
                interface.into(),
                count,
            ));
        }
        fn record_kernel_drops_uncounted(&self, count: u64) {
            *self.1.lock().unwrap_or_else(PoisonError::into_inner) += count;
        }
    }

    type Poll = Result<(Vec<RawDrop>, u64), DomainError>;

    /// Answers each poll from a script, one entry per poll.
    struct Scripted(Mutex<Vec<Poll>>);

    impl DropCounterPort for Scripted {
        fn read(&self) -> Result<(Vec<RawDrop>, u64), DomainError> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(0)
        }
    }

    fn raw_drop(packets: u64) -> RawDrop {
        RawDrop {
            reason: "NO_SOCKET".into(),
            ifindex: 1,
            name: "lo".into(),
            packets,
        }
    }

    #[test]
    fn polls_publish_increments_and_keep_the_last_reading_on_failure() {
        let recorder = Arc::new(Recorder::default());
        let service = KernelDropService::new(
            Box::new(Scripted(Mutex::new(vec![
                Ok((vec![raw_drop(4)], 0)),
                Ok((vec![raw_drop(9)], 3)),
                Err(DomainError::EngineError("map gone".into())),
            ]))),
            recorder.clone(),
        );
        service.poll();
        service.poll();
        service.poll();
        assert_eq!(
            *recorder.0.lock().unwrap_or_else(PoisonError::into_inner),
            vec![
                ("NO_SOCKET".into(), "lo".into(), 4),
                ("NO_SOCKET".into(), "lo".into(), 5)
            ]
        );
        assert_eq!(
            *recorder.1.lock().unwrap_or_else(PoisonError::into_inner),
            3
        );
        let snapshot = service.snapshot();
        assert_eq!(snapshot.polls, 2);
        assert_eq!(snapshot.reading.total(), 9);
        assert!(snapshot.last_error.is_some_and(|e| e.contains("map gone")));
    }
}
