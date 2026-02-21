use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("duplicate policy: {id}")]
    DuplicatePolicy { id: String },

    #[error("policy not found: {id}")]
    PolicyNotFound { id: String },

    #[error("invalid rate: must be > 0")]
    InvalidRate,

    #[error("invalid burst: must be > 0")]
    InvalidBurst,
}

impl From<RateLimitError> for DomainError {
    fn from(e: RateLimitError) -> Self {
        match e {
            RateLimitError::PolicyNotFound { id } => Self::RuleNotFound(id),
            RateLimitError::DuplicatePolicy { id } => Self::DuplicateRule(id),
            RateLimitError::InvalidPolicy(msg) => Self::InvalidRule(msg),
            RateLimitError::InvalidRate | RateLimitError::InvalidBurst => {
                Self::InvalidRule(e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_policy_to_domain_error() {
        let e: DomainError = RateLimitError::InvalidPolicy("bad".to_string()).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn duplicate_to_domain_error() {
        let e: DomainError = RateLimitError::DuplicatePolicy {
            id: "rl-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::DuplicateRule(_)));
    }

    #[test]
    fn not_found_to_domain_error() {
        let e: DomainError = RateLimitError::PolicyNotFound {
            id: "rl-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::RuleNotFound(_)));
    }

    #[test]
    fn invalid_rate_to_domain_error() {
        let e: DomainError = RateLimitError::InvalidRate.into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn invalid_burst_to_domain_error() {
        let e: DomainError = RateLimitError::InvalidBurst.into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }
}
