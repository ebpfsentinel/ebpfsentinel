use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum ConnTrackError {
    #[error("invalid timeout: {field} must be > 0")]
    InvalidTimeout { field: &'static str },

    #[error("conntrack table full")]
    TableFull,

    #[error("connection not found")]
    NotFound,

    #[error("invalid configuration: {reason}")]
    InvalidConfig { reason: String },
}

impl From<ConnTrackError> for DomainError {
    fn from(e: ConnTrackError) -> Self {
        DomainError::InvalidConfig(e.to_string())
    }
}
