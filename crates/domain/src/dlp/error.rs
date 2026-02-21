use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum DlpError {
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),

    #[error("duplicate pattern: {id}")]
    DuplicatePattern { id: String },

    #[error("pattern not found: {id}")]
    PatternNotFound { id: String },

    #[error("invalid regex in pattern '{pattern}': {reason}")]
    InvalidRegex { pattern: String, reason: String },
}

impl From<DlpError> for DomainError {
    fn from(e: DlpError) -> Self {
        match e {
            DlpError::DuplicatePattern { ref id } => DomainError::DuplicateRule(id.clone()),
            DlpError::PatternNotFound { ref id } => DomainError::RuleNotFound(id.clone()),
            other => DomainError::InvalidRule(other.to_string()),
        }
    }
}
