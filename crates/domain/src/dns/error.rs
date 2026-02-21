use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("malformed DNS packet: {0}")]
    MalformedPacket(String),

    #[error("truncated payload: need at least {need} bytes, got {got}")]
    TruncatedPayload { need: usize, got: usize },

    #[error("label too long: {length} bytes (max 63)")]
    LabelTooLong { length: usize },

    #[error("domain name too long: {length} bytes (max 253)")]
    DomainTooLong { length: usize },

    #[error("too many answer records: {count} (max {max})")]
    TooManyRecords { count: u16, max: u16 },

    #[error("compression pointer loop detected")]
    CompressionLoop,

    #[error("invalid blocklist pattern: {0}")]
    InvalidBlocklistPattern(String),

    #[error("invalid blocklist feed: {0}")]
    InvalidBlocklistFeed(String),

    #[error("duplicate blocklist pattern: {0}")]
    DuplicatePattern(String),

    #[error("blocklist pattern not found: {0}")]
    PatternNotFound(String),
}
