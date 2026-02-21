use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit write failed: {0}")]
    WriteFailed(String),

    #[error("audit query failed: {0}")]
    QueryFailed(String),

    #[error("audit store unavailable: {0}")]
    StoreUnavailable(String),
}
