use crate::common::error::DomainError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThreatIntelError {
    #[error("feed error: {0}")]
    FeedError(String),

    #[error("invalid IOC '{ip}': {reason}")]
    InvalidIoc { ip: String, reason: String },

    #[error("feed not found: {id}")]
    FeedNotFound { id: String },

    #[error("IOC map full: capacity {capacity}")]
    MapFull { capacity: usize },
}

impl From<ThreatIntelError> for DomainError {
    fn from(e: ThreatIntelError) -> Self {
        match e {
            ThreatIntelError::FeedError(msg) => DomainError::EngineError(msg),
            ThreatIntelError::InvalidIoc { ip, reason } => {
                DomainError::InvalidRule(format!("invalid IOC '{ip}': {reason}"))
            }
            ThreatIntelError::FeedNotFound { id } => {
                DomainError::RuleNotFound(format!("feed '{id}'"))
            }
            ThreatIntelError::MapFull { capacity } => {
                DomainError::EngineError(format!("IOC map full: capacity {capacity}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_error_to_domain() {
        let e: DomainError = ThreatIntelError::FeedError("timeout".to_string()).into();
        assert!(matches!(e, DomainError::EngineError(_)));
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn invalid_ioc_to_domain() {
        let e: DomainError = ThreatIntelError::InvalidIoc {
            ip: "1.2.3.4".to_string(),
            reason: "bad confidence".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
        assert!(e.to_string().contains("1.2.3.4"));
    }

    #[test]
    fn feed_not_found_to_domain() {
        let e: DomainError = ThreatIntelError::FeedNotFound {
            id: "my-feed".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::RuleNotFound(_)));
    }

    #[test]
    fn map_full_to_domain() {
        let e: DomainError = ThreatIntelError::MapFull { capacity: 1000 }.into();
        assert!(matches!(e, DomainError::EngineError(_)));
        assert!(e.to_string().contains("1000"));
    }
}
