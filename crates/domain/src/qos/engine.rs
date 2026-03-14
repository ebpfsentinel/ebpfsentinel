use crate::common::error::DomainError;

use super::entity::{QosClassifier, QosPipe, QosQueue};
use super::error::QosError;

/// Maximum number of pipes.
const MAX_PIPES: usize = 64;
/// Maximum number of queues.
const MAX_QUEUES: usize = 256;
/// Maximum number of classifiers.
const MAX_CLASSIFIERS: usize = 1024;

/// `QoS` / traffic-shaping domain engine.
///
/// Manages pipes, queues, and classifiers. Validates constraints
/// (uniqueness, limits) and provides CRUD + bulk-reload operations.
#[derive(Debug, Default)]
pub struct QosEngine {
    pipes: Vec<QosPipe>,
    queues: Vec<QosQueue>,
    classifiers: Vec<QosClassifier>,
}

impl QosEngine {
    pub fn new() -> Self {
        Self {
            pipes: Vec::new(),
            queues: Vec::new(),
            classifiers: Vec::new(),
        }
    }

    // ── Pipe operations ──────────────────────────────────────────────

    /// Return a slice of all pipes.
    pub fn pipes(&self) -> &[QosPipe] {
        &self.pipes
    }

    /// Add a pipe. Rejects duplicates and enforces the max limit.
    pub fn add_pipe(&mut self, pipe: QosPipe) -> Result<(), DomainError> {
        if self.pipes.iter().any(|p| p.id == pipe.id) {
            return Err(QosError::DuplicatePipe { id: pipe.id }.into());
        }
        if self.pipes.len() >= MAX_PIPES {
            return Err(QosError::InvalidPipe("maximum pipe count reached".to_string()).into());
        }
        self.pipes.push(pipe);
        Ok(())
    }

    /// Remove a pipe by ID.
    pub fn remove_pipe(&mut self, id: &str) -> Result<(), DomainError> {
        let idx = self
            .pipes
            .iter()
            .position(|p| p.id == id)
            .ok_or_else(|| QosError::PipeNotFound { id: id.to_string() })?;
        self.pipes.remove(idx);
        Ok(())
    }

    /// Replace all pipes atomically.
    pub fn reload_pipes(&mut self, pipes: Vec<QosPipe>) -> Result<(), DomainError> {
        if pipes.len() > MAX_PIPES {
            return Err(QosError::InvalidPipe("maximum pipe count exceeded".to_string()).into());
        }
        // Check for duplicates
        for (i, pipe) in pipes.iter().enumerate() {
            if pipes[i + 1..].iter().any(|p| p.id == pipe.id) {
                return Err(QosError::DuplicatePipe {
                    id: pipe.id.clone(),
                }
                .into());
            }
        }
        self.pipes = pipes;
        Ok(())
    }

    // ── Queue operations ─────────────────────────────────────────────

    /// Return a slice of all queues.
    pub fn queues(&self) -> &[QosQueue] {
        &self.queues
    }

    /// Add a queue. Rejects duplicates and enforces the max limit.
    pub fn add_queue(&mut self, queue: QosQueue) -> Result<(), DomainError> {
        if self.queues.iter().any(|q| q.id == queue.id) {
            return Err(QosError::DuplicateQueue { id: queue.id }.into());
        }
        if self.queues.len() >= MAX_QUEUES {
            return Err(QosError::InvalidQueue("maximum queue count reached".to_string()).into());
        }
        self.queues.push(queue);
        Ok(())
    }

    /// Remove a queue by ID.
    pub fn remove_queue(&mut self, id: &str) -> Result<(), DomainError> {
        let idx = self
            .queues
            .iter()
            .position(|q| q.id == id)
            .ok_or_else(|| QosError::QueueNotFound { id: id.to_string() })?;
        self.queues.remove(idx);
        Ok(())
    }

    /// Replace all queues atomically.
    pub fn reload_queues(&mut self, queues: Vec<QosQueue>) -> Result<(), DomainError> {
        if queues.len() > MAX_QUEUES {
            return Err(QosError::InvalidQueue("maximum queue count exceeded".to_string()).into());
        }
        for (i, queue) in queues.iter().enumerate() {
            if queues[i + 1..].iter().any(|q| q.id == queue.id) {
                return Err(QosError::DuplicateQueue {
                    id: queue.id.clone(),
                }
                .into());
            }
        }
        self.queues = queues;
        Ok(())
    }

    // ── Classifier operations ────────────────────────────────────────

    /// Return a slice of all classifiers.
    pub fn classifiers(&self) -> &[QosClassifier] {
        &self.classifiers
    }

    /// Add a classifier. Rejects duplicates and enforces the max limit.
    pub fn add_classifier(&mut self, classifier: QosClassifier) -> Result<(), DomainError> {
        if self.classifiers.iter().any(|c| c.id == classifier.id) {
            return Err(QosError::DuplicateClassifier { id: classifier.id }.into());
        }
        if self.classifiers.len() >= MAX_CLASSIFIERS {
            return Err(QosError::InvalidClassifier(
                "maximum classifier count reached".to_string(),
            )
            .into());
        }
        self.classifiers.push(classifier);
        Ok(())
    }

    /// Remove a classifier by ID.
    pub fn remove_classifier(&mut self, id: &str) -> Result<(), DomainError> {
        let idx = self
            .classifiers
            .iter()
            .position(|c| c.id == id)
            .ok_or_else(|| QosError::ClassifierNotFound { id: id.to_string() })?;
        self.classifiers.remove(idx);
        Ok(())
    }

    /// Replace all classifiers atomically.
    pub fn reload_classifiers(
        &mut self,
        classifiers: Vec<QosClassifier>,
    ) -> Result<(), DomainError> {
        if classifiers.len() > MAX_CLASSIFIERS {
            return Err(QosError::InvalidClassifier(
                "maximum classifier count exceeded".to_string(),
            )
            .into());
        }
        for (i, cls) in classifiers.iter().enumerate() {
            if classifiers[i + 1..].iter().any(|c| c.id == cls.id) {
                return Err(QosError::DuplicateClassifier { id: cls.id.clone() }.into());
            }
        }
        self.classifiers = classifiers;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qos::entity::{QosDirection, QosMatchRule};

    fn make_pipe(id: &str) -> QosPipe {
        QosPipe {
            id: id.to_string(),
            rate_bps: 1_000_000,
            burst_bytes: 125_000,
            delay_ms: 0,
            loss_pct: 0.0,
            priority: 0,
            direction: QosDirection::Egress,
            enabled: true,
            group_mask: 0,
        }
    }

    fn make_queue(id: &str, pipe_id: &str) -> QosQueue {
        QosQueue {
            id: id.to_string(),
            pipe_id: pipe_id.to_string(),
            weight: 50,
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
            group_mask: 0,
        }
    }

    #[test]
    fn new_engine_is_empty() {
        let engine = QosEngine::new();
        assert_eq!(engine.pipes().len(), 0);
        assert_eq!(engine.queues().len(), 0);
        assert_eq!(engine.classifiers().len(), 0);
    }

    #[test]
    fn add_pipe_succeeds() {
        let mut engine = QosEngine::new();
        assert!(engine.add_pipe(make_pipe("p-1")).is_ok());
        assert_eq!(engine.pipes().len(), 1);
    }

    #[test]
    fn add_duplicate_pipe_fails() {
        let mut engine = QosEngine::new();
        engine.add_pipe(make_pipe("p-1")).unwrap();
        assert!(engine.add_pipe(make_pipe("p-1")).is_err());
    }

    #[test]
    fn remove_pipe_succeeds() {
        let mut engine = QosEngine::new();
        engine.add_pipe(make_pipe("p-1")).unwrap();
        assert!(engine.remove_pipe("p-1").is_ok());
        assert_eq!(engine.pipes().len(), 0);
    }

    #[test]
    fn remove_pipe_not_found() {
        let mut engine = QosEngine::new();
        assert!(engine.remove_pipe("nope").is_err());
    }

    #[test]
    fn reload_pipes() {
        let mut engine = QosEngine::new();
        engine.add_pipe(make_pipe("old")).unwrap();
        engine
            .reload_pipes(vec![make_pipe("new-1"), make_pipe("new-2")])
            .unwrap();
        assert_eq!(engine.pipes().len(), 2);
    }

    #[test]
    fn add_queue_succeeds() {
        let mut engine = QosEngine::new();
        assert!(engine.add_queue(make_queue("q-1", "p-1")).is_ok());
    }

    #[test]
    fn add_duplicate_queue_fails() {
        let mut engine = QosEngine::new();
        engine.add_queue(make_queue("q-1", "p-1")).unwrap();
        assert!(engine.add_queue(make_queue("q-1", "p-2")).is_err());
    }

    #[test]
    fn remove_queue_succeeds() {
        let mut engine = QosEngine::new();
        engine.add_queue(make_queue("q-1", "p-1")).unwrap();
        assert!(engine.remove_queue("q-1").is_ok());
    }

    #[test]
    fn add_classifier_succeeds() {
        let mut engine = QosEngine::new();
        assert!(engine.add_classifier(make_classifier("c-1", "q-1")).is_ok());
    }

    #[test]
    fn add_duplicate_classifier_fails() {
        let mut engine = QosEngine::new();
        engine
            .add_classifier(make_classifier("c-1", "q-1"))
            .unwrap();
        assert!(
            engine
                .add_classifier(make_classifier("c-1", "q-2"))
                .is_err()
        );
    }

    #[test]
    fn remove_classifier_succeeds() {
        let mut engine = QosEngine::new();
        engine
            .add_classifier(make_classifier("c-1", "q-1"))
            .unwrap();
        assert!(engine.remove_classifier("c-1").is_ok());
    }

    #[test]
    fn reload_classifiers() {
        let mut engine = QosEngine::new();
        engine
            .add_classifier(make_classifier("old", "q-1"))
            .unwrap();
        engine
            .reload_classifiers(vec![
                make_classifier("new-1", "q-1"),
                make_classifier("new-2", "q-2"),
            ])
            .unwrap();
        assert_eq!(engine.classifiers().len(), 2);
    }
}
