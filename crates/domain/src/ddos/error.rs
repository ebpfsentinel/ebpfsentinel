use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum DdosError {
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("duplicate policy: {id}")]
    DuplicatePolicy { id: String },

    #[error("policy not found: {id}")]
    PolicyNotFound { id: String },

    #[error("invalid threshold: must be > 0")]
    InvalidThreshold,
}

impl From<DdosError> for DomainError {
    fn from(e: DdosError) -> Self {
        match e {
            DdosError::PolicyNotFound { id } => Self::RuleNotFound(id),
            DdosError::DuplicatePolicy { id } => Self::DuplicateRule(id),
            DdosError::InvalidPolicy(msg) => Self::InvalidRule(msg),
            DdosError::InvalidThreshold => Self::InvalidRule(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_policy_to_domain_error() {
        let e: DomainError = DdosError::InvalidPolicy("bad".to_string()).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn duplicate_to_domain_error() {
        let e: DomainError = DdosError::DuplicatePolicy {
            id: "ddos-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::DuplicateRule(_)));
    }

    #[test]
    fn not_found_to_domain_error() {
        let e: DomainError = DdosError::PolicyNotFound {
            id: "ddos-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::RuleNotFound(_)));
    }

    #[test]
    fn invalid_threshold_to_domain_error() {
        let e: DomainError = DdosError::InvalidThreshold.into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }
}
