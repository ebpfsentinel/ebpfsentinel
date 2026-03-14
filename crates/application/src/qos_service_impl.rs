use std::sync::Arc;

use domain::common::error::DomainError;
use domain::qos::engine::QosEngine;
use domain::qos::entity::{QosClassifier, QosPipe, QosQueue, QosScheduler};
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::qos_map_port::QosMapPort;

/// Application-level `QoS` / traffic shaping service.
///
/// Orchestrates the `QoS` domain engine, optional eBPF map sync, and metrics
/// updates. Designed to be wrapped in `RwLock` for shared access.
pub struct QosAppService {
    engine: QosEngine,
    map_port: Option<Box<dyn QosMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
    scheduler: QosScheduler,
}

impl QosAppService {
    pub fn new(metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine: QosEngine::new(),
            map_port: None,
            metrics,
            enabled: false,
            scheduler: QosScheduler::default(),
        }
    }

    /// Set the eBPF map port and perform an initial sync.
    pub fn set_map_port(&mut self, port: Box<dyn QosMapPort + Send>) {
        self.map_port = Some(port);
        self.sync_maps();
    }

    /// Return whether the `QoS` service is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        tracing::info!(enabled, "qos service toggled");
    }

    /// Return the current scheduler type.
    pub fn scheduler(&self) -> &QosScheduler {
        &self.scheduler
    }

    /// Set the scheduler type.
    pub fn set_scheduler(&mut self, scheduler: QosScheduler) {
        self.scheduler = scheduler;
        tracing::info!(?scheduler, "qos scheduler updated");
    }

    // ── Pipe operations ──────────────────────────────────────────────

    /// Reload all pipes atomically.
    pub fn reload_pipes(&mut self, pipes: Vec<QosPipe>) -> Result<(), DomainError> {
        let count = pipes.len();
        self.engine.reload_pipes(pipes)?;
        self.sync_maps();
        self.update_metrics();
        tracing::info!(count, "qos pipes reloaded");
        Ok(())
    }

    /// Add a pipe.
    pub fn add_pipe(&mut self, pipe: QosPipe) -> Result<(), DomainError> {
        self.engine.add_pipe(pipe)?;
        self.sync_maps();
        self.update_metrics();
        Ok(())
    }

    /// Remove a pipe by ID.
    pub fn remove_pipe(&mut self, id: &str) -> Result<(), DomainError> {
        self.engine.remove_pipe(id)?;
        self.sync_maps();
        self.update_metrics();
        Ok(())
    }

    /// Return a slice of all loaded pipes.
    pub fn pipes(&self) -> &[QosPipe] {
        self.engine.pipes()
    }

    // ── Queue operations ─────────────────────────────────────────────

    /// Reload all queues atomically.
    pub fn reload_queues(&mut self, queues: Vec<QosQueue>) -> Result<(), DomainError> {
        let count = queues.len();
        self.engine.reload_queues(queues)?;
        self.sync_maps();
        self.update_metrics();
        tracing::info!(count, "qos queues reloaded");
        Ok(())
    }

    /// Add a queue.
    pub fn add_queue(&mut self, queue: QosQueue) -> Result<(), DomainError> {
        self.engine.add_queue(queue)?;
        self.sync_maps();
        self.update_metrics();
        Ok(())
    }

    /// Remove a queue by ID.
    pub fn remove_queue(&mut self, id: &str) -> Result<(), DomainError> {
        self.engine.remove_queue(id)?;
        self.sync_maps();
        self.update_metrics();
        Ok(())
    }

    /// Return a slice of all loaded queues.
    pub fn queues(&self) -> &[QosQueue] {
        self.engine.queues()
    }

    // ── Classifier operations ────────────────────────────────────────

    /// Reload all classifiers atomically.
    pub fn reload_classifiers(
        &mut self,
        classifiers: Vec<QosClassifier>,
    ) -> Result<(), DomainError> {
        let count = classifiers.len();
        self.engine.reload_classifiers(classifiers)?;
        self.sync_maps();
        self.update_metrics();
        tracing::info!(count, "qos classifiers reloaded");
        Ok(())
    }

    /// Add a classifier.
    pub fn add_classifier(&mut self, classifier: QosClassifier) -> Result<(), DomainError> {
        self.engine.add_classifier(classifier)?;
        self.sync_maps();
        self.update_metrics();
        Ok(())
    }

    /// Remove a classifier by ID.
    pub fn remove_classifier(&mut self, id: &str) -> Result<(), DomainError> {
        self.engine.remove_classifier(id)?;
        self.sync_maps();
        self.update_metrics();
        Ok(())
    }

    /// Return a slice of all loaded classifiers.
    pub fn classifiers(&self) -> &[QosClassifier] {
        self.engine.classifiers()
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// Full-reload sync: push all engine state to eBPF maps.
    fn sync_maps(&mut self) {
        let Some(ref mut port) = self.map_port else {
            return;
        };

        if let Err(e) = port.clear_all() {
            tracing::warn!("failed to clear QoS eBPF maps: {e}");
            return;
        }

        if let Err(e) = port.load_pipes(self.engine.pipes()) {
            tracing::warn!("failed to sync QoS pipes to eBPF map: {e}");
            return;
        }

        if let Err(e) = port.load_queues(self.engine.queues()) {
            tracing::warn!("failed to sync QoS queues to eBPF map: {e}");
            return;
        }

        if let Err(e) = port.load_classifiers(self.engine.classifiers()) {
            tracing::warn!("failed to sync QoS classifiers to eBPF map: {e}");
        }
    }

    fn update_metrics(&self) {
        let total = self.engine.pipes().len()
            + self.engine.queues().len()
            + self.engine.classifiers().len();
        self.metrics.set_rules_loaded("qos", total as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::qos::entity::{QosDirection, QosMatchRule};
    use ports::test_utils::NoopMetrics;

    fn make_service() -> QosAppService {
        QosAppService::new(Arc::new(NoopMetrics))
    }

    fn make_pipe(id: &str, rate_bps: u64) -> QosPipe {
        QosPipe {
            id: id.to_string(),
            rate_bps,
            burst_bytes: rate_bps / 8,
            delay_ms: 0,
            loss_pct: 0.0,
            priority: 0,
            direction: QosDirection::Egress,
            enabled: true,
        }
    }

    fn make_queue(id: &str, pipe_id: &str, weight: u16) -> QosQueue {
        QosQueue {
            id: id.to_string(),
            pipe_id: pipe_id.to_string(),
            weight,
            enabled: true,
        }
    }

    fn make_classifier(id: &str, queue_id: &str) -> QosClassifier {
        QosClassifier {
            id: id.to_string(),
            queue_id: queue_id.to_string(),
            direction: QosDirection::Egress,
            match_rule: QosMatchRule::default(),
            priority: 100,
        }
    }

    // ── Pipe tests ───────────────────────────────────────────────────

    #[test]
    fn add_pipe_succeeds() {
        let mut svc = make_service();
        assert!(svc.add_pipe(make_pipe("pipe-1", 1_000_000)).is_ok());
        assert_eq!(svc.pipes().len(), 1);
    }

    #[test]
    fn add_duplicate_pipe_fails() {
        let mut svc = make_service();
        svc.add_pipe(make_pipe("pipe-1", 1_000_000)).unwrap();
        assert!(svc.add_pipe(make_pipe("pipe-1", 2_000_000)).is_err());
    }

    #[test]
    fn remove_pipe_succeeds() {
        let mut svc = make_service();
        svc.add_pipe(make_pipe("pipe-1", 1_000_000)).unwrap();
        assert!(svc.remove_pipe("pipe-1").is_ok());
        assert_eq!(svc.pipes().len(), 0);
    }

    #[test]
    fn remove_nonexistent_pipe_fails() {
        let mut svc = make_service();
        assert!(svc.remove_pipe("nope").is_err());
    }

    #[test]
    fn reload_pipes_replaces_all() {
        let mut svc = make_service();
        svc.add_pipe(make_pipe("old", 1_000_000)).unwrap();
        svc.reload_pipes(vec![
            make_pipe("new-1", 1_000_000),
            make_pipe("new-2", 2_000_000),
        ])
        .unwrap();
        assert_eq!(svc.pipes().len(), 2);
    }

    #[test]
    fn reload_pipes_empty_clears() {
        let mut svc = make_service();
        svc.add_pipe(make_pipe("pipe-1", 1_000_000)).unwrap();
        svc.reload_pipes(vec![]).unwrap();
        assert_eq!(svc.pipes().len(), 0);
    }

    // ── Queue tests ──────────────────────────────────────────────────

    #[test]
    fn add_queue_succeeds() {
        let mut svc = make_service();
        assert!(svc.add_queue(make_queue("q-1", "pipe-1", 50)).is_ok());
        assert_eq!(svc.queues().len(), 1);
    }

    #[test]
    fn add_duplicate_queue_fails() {
        let mut svc = make_service();
        svc.add_queue(make_queue("q-1", "pipe-1", 50)).unwrap();
        assert!(svc.add_queue(make_queue("q-1", "pipe-2", 100)).is_err());
    }

    #[test]
    fn remove_queue_succeeds() {
        let mut svc = make_service();
        svc.add_queue(make_queue("q-1", "pipe-1", 50)).unwrap();
        assert!(svc.remove_queue("q-1").is_ok());
        assert_eq!(svc.queues().len(), 0);
    }

    #[test]
    fn remove_nonexistent_queue_fails() {
        let mut svc = make_service();
        assert!(svc.remove_queue("nope").is_err());
    }

    #[test]
    fn reload_queues_replaces_all() {
        let mut svc = make_service();
        svc.add_queue(make_queue("old", "pipe-1", 50)).unwrap();
        svc.reload_queues(vec![
            make_queue("new-1", "pipe-1", 50),
            make_queue("new-2", "pipe-1", 100),
        ])
        .unwrap();
        assert_eq!(svc.queues().len(), 2);
    }

    #[test]
    fn reload_queues_empty_clears() {
        let mut svc = make_service();
        svc.add_queue(make_queue("q-1", "pipe-1", 50)).unwrap();
        svc.reload_queues(vec![]).unwrap();
        assert_eq!(svc.queues().len(), 0);
    }

    // ── Classifier tests ─────────────────────────────────────────────

    #[test]
    fn add_classifier_succeeds() {
        let mut svc = make_service();
        assert!(svc.add_classifier(make_classifier("cls-1", "q-1")).is_ok());
        assert_eq!(svc.classifiers().len(), 1);
    }

    #[test]
    fn add_duplicate_classifier_fails() {
        let mut svc = make_service();
        svc.add_classifier(make_classifier("cls-1", "q-1")).unwrap();
        assert!(svc.add_classifier(make_classifier("cls-1", "q-2")).is_err());
    }

    #[test]
    fn remove_classifier_succeeds() {
        let mut svc = make_service();
        svc.add_classifier(make_classifier("cls-1", "q-1")).unwrap();
        assert!(svc.remove_classifier("cls-1").is_ok());
        assert_eq!(svc.classifiers().len(), 0);
    }

    #[test]
    fn remove_nonexistent_classifier_fails() {
        let mut svc = make_service();
        assert!(svc.remove_classifier("nope").is_err());
    }

    #[test]
    fn reload_classifiers_replaces_all() {
        let mut svc = make_service();
        svc.add_classifier(make_classifier("old", "q-1")).unwrap();
        svc.reload_classifiers(vec![
            make_classifier("new-1", "q-1"),
            make_classifier("new-2", "q-2"),
        ])
        .unwrap();
        assert_eq!(svc.classifiers().len(), 2);
    }

    #[test]
    fn reload_classifiers_empty_clears() {
        let mut svc = make_service();
        svc.add_classifier(make_classifier("cls-1", "q-1")).unwrap();
        svc.reload_classifiers(vec![]).unwrap();
        assert_eq!(svc.classifiers().len(), 0);
    }

    // ── Service-level tests ──────────────────────────────────────────

    #[test]
    fn new_service_defaults() {
        let svc = make_service();
        assert!(!svc.enabled());
        assert_eq!(svc.pipes().len(), 0);
        assert_eq!(svc.queues().len(), 0);
        assert_eq!(svc.classifiers().len(), 0);
    }

    #[test]
    fn enabled_toggle() {
        let mut svc = make_service();
        assert!(!svc.enabled());
        svc.set_enabled(true);
        assert!(svc.enabled());
        svc.set_enabled(false);
        assert!(!svc.enabled());
    }

    #[test]
    fn scheduler_set_and_get() {
        let mut svc = make_service();
        let default = *svc.scheduler();
        assert_eq!(default, QosScheduler::default());

        svc.set_scheduler(QosScheduler::Wf2q);
        assert_eq!(*svc.scheduler(), QosScheduler::Wf2q);
    }
}
