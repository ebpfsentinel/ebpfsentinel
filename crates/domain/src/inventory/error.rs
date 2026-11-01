use thiserror::Error;

/// Why a package database was not read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InventoryError {
    /// The file is not in the format its location says it holds.
    #[error("not in the expected format: {0}")]
    NotThisFormat(String),
    /// The file is in the format and breaks it.
    #[error("corrupt: {0}")]
    Corrupt(String),
}
