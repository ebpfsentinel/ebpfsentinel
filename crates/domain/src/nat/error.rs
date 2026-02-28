use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum NatError {
    #[error("invalid NAT rule: {reason}")]
    InvalidRule { reason: String },

    #[error("duplicate NAT rule: {id}")]
    DuplicateRule { id: String },

    #[error("NAT rule not found: {id}")]
    RuleNotFound { id: String },

    #[error("port allocation exhausted")]
    PortExhausted,

    #[error("invalid port range: {start}..{end}")]
    InvalidPortRange { start: u16, end: u16 },
}

impl From<NatError> for DomainError {
    fn from(e: NatError) -> Self {
        match e {
            NatError::DuplicateRule { ref id } => DomainError::DuplicateRule(id.clone()),
            NatError::RuleNotFound { ref id } => DomainError::RuleNotFound(id.clone()),
            other => DomainError::InvalidRule(other.to_string()),
        }
    }
}
