use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum AliasError {
    #[error("alias not found: {id}")]
    NotFound { id: String },

    #[error("duplicate alias: {id}")]
    Duplicate { id: String },

    #[error("circular alias reference detected: {path}")]
    CircularReference { path: String },

    #[error("invalid alias: {reason}")]
    Invalid { reason: String },

    #[error("type mismatch: alias '{id}' is not an IP set")]
    NotIpSet { id: String },

    #[error("type mismatch: alias '{id}' is not a port set")]
    NotPortSet { id: String },

    #[error("resolution failed: {reason}")]
    ResolutionFailed { reason: String },
}

impl From<AliasError> for DomainError {
    fn from(e: AliasError) -> Self {
        match e {
            AliasError::NotFound { ref id } => DomainError::RuleNotFound(id.clone()),
            AliasError::Duplicate { ref id } => DomainError::DuplicateRule(id.clone()),
            other => DomainError::InvalidRule(other.to_string()),
        }
    }
}
