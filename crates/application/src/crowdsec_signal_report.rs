//! Writes the agent's own blocks back to a CrowdSec local API.
//!
//! Alerts are read from the same broadcast the alert stream serves, folded
//! into one signal per blocked source and component, and sent once per
//! window. A window that fails to send is dropped rather than held: a local
//! API that is down must not grow the agent's memory, and the next window
//! reports whatever is still being blocked.

use std::sync::Arc;
use std::time::Duration;

use domain::alert::entity::Alert;
use domain::threatintel::crowdsec::SignalBatch;
use ports::secondary::signal_report_port::SignalReportPort;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

/// Send whatever `batch` holds, logging the outcome. Returns how many signals
/// were sent.
async fn flush(batch: &mut SignalBatch, reporter: &dyn SignalReportPort) -> usize {
    let (signals, dropped) = batch.drain();
    if dropped > 0 {
        tracing::warn!(
            dropped,
            "CrowdSec report window full: blocked sources beyond the limit were not reported"
        );
    }
    if signals.is_empty() {
        return 0;
    }
    match reporter.report(&signals).await {
        Ok(()) => {
            tracing::debug!(signals = signals.len(), "CrowdSec signals reported");
            signals.len()
        }
        Err(e) => {
            tracing::warn!(
                signals = signals.len(),
                error = %e,
                "CrowdSec signal report failed, window dropped"
            );
            0
        }
    }
}

/// Run the reporter until `cancel` fires or the alert broadcast closes. The
/// window still held at that moment is sent before returning.
pub async fn run_signal_reporter(
    mut alerts: broadcast::Receiver<Alert>,
    reporter: Arc<dyn SignalReportPort>,
    window: Duration,
    cancel: CancellationToken,
) {
    let mut batch = SignalBatch::new();
    let mut tick = tokio::time::interval(window);
    tick.tick().await;
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = tick.tick() => {
                flush(&mut batch, reporter.as_ref()).await;
            }
            received = alerts.recv() => match received {
                Ok(alert) => {
                    batch.observe(&alert);
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!(missed, "CrowdSec reporter fell behind the alert stream");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        }
    }
    flush(&mut batch, reporter.as_ref()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::DomainMode;
    use domain::common::error::DomainError;
    use domain::threatintel::crowdsec::Signal;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        windows: Mutex<Vec<Vec<Signal>>>,
        fail: bool,
    }

    impl SignalReportPort for Recorder {
        fn report<'a>(
            &'a self,
            signals: &'a [Signal],
        ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
            Box::pin(async move {
                self.windows
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(signals.to_vec());
                if self.fail {
                    Err(DomainError::EngineError("down".to_string()))
                } else {
                    Ok(())
                }
            })
        }
    }

    fn alert(action: DomainMode) -> Alert {
        let mut alert: Alert = serde_json::from_value(serde_json::json!({
            "id": "a", "timestamp_ns": 7, "component": "ids", "severity": "High",
            "rule_id": "r", "action": "Alert", "src_addr": [0xcb00_7101_u32, 0, 0, 0],
            "dst_addr": [0x0a00_0001_u32, 0, 0, 0], "src_port": 1, "dst_port": 22,
            "protocol": 6, "is_ipv6": false, "message": "m"
        }))
        .unwrap();
        alert.action = action;
        alert
    }

    #[tokio::test]
    async fn blocks_are_sent_once_per_window_and_on_shutdown() {
        let (tx, rx) = broadcast::channel(16);
        let recorder = Arc::new(Recorder::default());
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_signal_reporter(
            rx,
            Arc::clone(&recorder) as Arc<dyn SignalReportPort>,
            Duration::from_secs(3600),
            cancel.clone(),
        ));
        tx.send(alert(DomainMode::Block)).unwrap();
        tx.send(alert(DomainMode::Block)).unwrap();
        tx.send(alert(DomainMode::Alert)).unwrap();
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        task.await.unwrap();
        let windows = recorder.windows.lock().unwrap();
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].len(), 1);
        assert_eq!(windows[0][0].count, 2);
        assert_eq!(windows[0][0].scenario, "ebpfsentinel/ids");
    }

    #[tokio::test]
    async fn nothing_blocked_sends_nothing_and_a_failure_is_survived() {
        let recorder = Arc::new(Recorder {
            fail: true,
            ..Recorder::default()
        });
        let mut batch = SignalBatch::new();
        assert_eq!(flush(&mut batch, recorder.as_ref()).await, 0);
        assert!(recorder.windows.lock().unwrap().is_empty());
        batch.observe(&alert(DomainMode::Block));
        assert_eq!(flush(&mut batch, recorder.as_ref()).await, 0);
        assert!(batch.is_empty());
    }
}
