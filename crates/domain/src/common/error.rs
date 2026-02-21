use thiserror::Error;

use crate::audit::error::AuditError;
use crate::dns::error::DnsError;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("rule not found: {0}")]
    RuleNotFound(String),

    #[error("duplicate rule: {0}")]
    DuplicateRule(String),

    #[error("invalid rule: {0}")]
    InvalidRule(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("engine error: {0}")]
    EngineError(String),
}

impl From<DnsError> for DomainError {
    fn from(err: DnsError) -> Self {
        Self::EngineError(err.to_string())
    }
}

impl From<AuditError> for DomainError {
    fn from(err: AuditError) -> Self {
        Self::EngineError(err.to_string())
    }
}
