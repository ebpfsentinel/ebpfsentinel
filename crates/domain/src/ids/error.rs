use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum IdsError {
    #[error("invalid rule pattern: {0}")]
    InvalidPattern(String),

    #[error("invalid rule ID: {reason}")]
    InvalidRuleId { reason: &'static str },

    #[error("duplicate rule: {id}")]
    DuplicateRule { id: String },

    #[error("rule not found: {id}")]
    RuleNotFound { id: String },
}

impl From<IdsError> for DomainError {
    fn from(e: IdsError) -> Self {
        match e {
            IdsError::DuplicateRule { ref id } => DomainError::DuplicateRule(id.clone()),
            IdsError::RuleNotFound { ref id } => DomainError::RuleNotFound(id.clone()),
            other => DomainError::InvalidRule(other.to_string()),
        }
    }
}
