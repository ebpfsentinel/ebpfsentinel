use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum ZoneError {
    #[error("zone not found: {id}")]
    NotFound { id: String },

    #[error("duplicate zone: {id}")]
    Duplicate { id: String },

    #[error("invalid zone: {reason}")]
    Invalid { reason: String },

    #[error("zone pair not found: {from} -> {to}")]
    PairNotFound { from: String, to: String },
}

impl From<ZoneError> for DomainError {
    fn from(e: ZoneError) -> Self {
        DomainError::InvalidConfig(e.to_string())
    }
}
