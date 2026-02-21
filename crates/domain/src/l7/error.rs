use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum L7Error {
    #[error("insufficient data: need at least {needed} bytes, got {got}")]
    InsufficientData { needed: usize, got: usize },

    #[error("{protocol}: {detail}")]
    InvalidFormat {
        protocol: &'static str,
        detail: String,
    },

    #[error("unsupported protocol version")]
    UnsupportedVersion,

    #[error("invalid priority: must be > 0")]
    InvalidPriority,

    #[error("invalid rule ID: {reason}")]
    InvalidRuleId { reason: &'static str },

    #[error("duplicate L7 rule: {id}")]
    DuplicateRule { id: String },

    #[error("L7 rule not found: {id}")]
    RuleNotFound { id: String },

    #[error("invalid port range: {start}..{end}")]
    InvalidPortRange { start: u16, end: u16 },

    #[error("invalid CIDR prefix length: {prefix_len} (must be 0-32)")]
    InvalidCidr { prefix_len: u8 },

    #[error("invalid domain pattern `{pattern}`: {reason}")]
    InvalidDomainPattern { pattern: String, reason: String },

    #[error("domain pattern too long: {length} chars (max {max})")]
    DomainPatternTooLong { length: usize, max: usize },
}

impl From<L7Error> for DomainError {
    fn from(e: L7Error) -> Self {
        match e {
            L7Error::DuplicateRule { ref id } => DomainError::DuplicateRule(id.clone()),
            L7Error::RuleNotFound { ref id } => DomainError::RuleNotFound(id.clone()),
            other => DomainError::InvalidRule(other.to_string()),
        }
    }
}
