use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum QosError {
    #[error("invalid pipe: {0}")]
    InvalidPipe(String),

    #[error("invalid queue: {0}")]
    InvalidQueue(String),

    #[error("invalid classifier: {0}")]
    InvalidClassifier(String),

    #[error("duplicate pipe: {id}")]
    DuplicatePipe { id: String },

    #[error("duplicate queue: {id}")]
    DuplicateQueue { id: String },

    #[error("duplicate classifier: {id}")]
    DuplicateClassifier { id: String },

    #[error("pipe not found: {id}")]
    PipeNotFound { id: String },

    #[error("queue not found: {id}")]
    QueueNotFound { id: String },

    #[error("classifier not found: {id}")]
    ClassifierNotFound { id: String },

    #[error("orphaned queue {queue_id}: references non-existent pipe {pipe_id}")]
    OrphanedQueue { queue_id: String, pipe_id: String },

    #[error("orphaned classifier {classifier_id}: references non-existent queue {queue_id}")]
    OrphanedClassifier {
        classifier_id: String,
        queue_id: String,
    },

    #[error("invalid bandwidth: must be > 0")]
    InvalidBandwidth,

    #[error("invalid loss percentage: must be 0.0..=100.0, got {0}")]
    InvalidLossPct(f32),

    #[error("invalid weight: must be 1..=100, got {0}")]
    InvalidWeight(u16),
}

impl From<QosError> for DomainError {
    fn from(e: QosError) -> Self {
        match e {
            QosError::PipeNotFound { id }
            | QosError::QueueNotFound { id }
            | QosError::ClassifierNotFound { id } => Self::RuleNotFound(id),
            QosError::DuplicatePipe { id }
            | QosError::DuplicateQueue { id }
            | QosError::DuplicateClassifier { id } => Self::DuplicateRule(id),
            QosError::InvalidPipe(msg)
            | QosError::InvalidQueue(msg)
            | QosError::InvalidClassifier(msg) => Self::InvalidRule(msg),
            QosError::OrphanedQueue { .. }
            | QosError::OrphanedClassifier { .. }
            | QosError::InvalidBandwidth
            | QosError::InvalidLossPct(_)
            | QosError::InvalidWeight(_) => Self::InvalidRule(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_pipe_to_domain_error() {
        let e: DomainError = QosError::InvalidPipe("bad".to_string()).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn invalid_queue_to_domain_error() {
        let e: DomainError = QosError::InvalidQueue("bad".to_string()).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn invalid_classifier_to_domain_error() {
        let e: DomainError = QosError::InvalidClassifier("bad".to_string()).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn duplicate_pipe_to_domain_error() {
        let e: DomainError = QosError::DuplicatePipe {
            id: "p-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::DuplicateRule(_)));
    }

    #[test]
    fn duplicate_queue_to_domain_error() {
        let e: DomainError = QosError::DuplicateQueue {
            id: "q-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::DuplicateRule(_)));
    }

    #[test]
    fn duplicate_classifier_to_domain_error() {
        let e: DomainError = QosError::DuplicateClassifier {
            id: "c-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::DuplicateRule(_)));
    }

    #[test]
    fn pipe_not_found_to_domain_error() {
        let e: DomainError = QosError::PipeNotFound {
            id: "p-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::RuleNotFound(_)));
    }

    #[test]
    fn queue_not_found_to_domain_error() {
        let e: DomainError = QosError::QueueNotFound {
            id: "q-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::RuleNotFound(_)));
    }

    #[test]
    fn classifier_not_found_to_domain_error() {
        let e: DomainError = QosError::ClassifierNotFound {
            id: "c-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::RuleNotFound(_)));
    }

    #[test]
    fn orphaned_queue_to_domain_error() {
        let e: DomainError = QosError::OrphanedQueue {
            queue_id: "q-1".to_string(),
            pipe_id: "p-99".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn orphaned_classifier_to_domain_error() {
        let e: DomainError = QosError::OrphanedClassifier {
            classifier_id: "c-1".to_string(),
            queue_id: "q-99".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn invalid_bandwidth_to_domain_error() {
        let e: DomainError = QosError::InvalidBandwidth.into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn invalid_loss_pct_to_domain_error() {
        let e: DomainError = QosError::InvalidLossPct(101.0).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn invalid_weight_to_domain_error() {
        let e: DomainError = QosError::InvalidWeight(0).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }
}
