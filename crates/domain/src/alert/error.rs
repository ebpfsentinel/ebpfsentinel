use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum AlertError {
    #[error("routing error: {0}")]
    RoutingError(String),

    #[error("send failed: {0}")]
    SendFailed(String),

    #[error("duplicate alert suppressed")]
    DuplicateAlert,

    #[error("alert throttled")]
    ThrottledAlert,

    #[error("no matching route for alert")]
    NoMatchingRoute,

    #[error("alert store write failed: {0}")]
    StoreFailed(String),

    #[error("alert store query failed: {0}")]
    QueryFailed(String),

    #[error("alert store unavailable: {0}")]
    StoreUnavailable(String),

    #[error("alert not found: {0}")]
    NotFound(String),
}

impl From<AlertError> for DomainError {
    fn from(e: AlertError) -> Self {
        DomainError::EngineError(e.to_string())
    }
}
