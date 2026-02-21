use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum IpsError {
    #[error("blacklist error: {0}")]
    BlacklistError(String),

    #[error("blacklist is full (max capacity reached)")]
    BlacklistFull,

    #[error("IP already blacklisted: {ip}")]
    AlreadyBlacklisted { ip: String },

    #[error("IP not blacklisted: {ip}")]
    NotBlacklisted { ip: String },

    #[error("invalid IPS policy: {0}")]
    InvalidPolicy(String),

    #[error("enforcement action failed: {0}")]
    EnforcementFailed(String),

    #[error("IP is whitelisted: {ip}")]
    Whitelisted { ip: String },
}

impl From<IpsError> for DomainError {
    fn from(e: IpsError) -> Self {
        match e {
            IpsError::InvalidPolicy(_) => DomainError::InvalidConfig(e.to_string()),
            IpsError::BlacklistFull
            | IpsError::AlreadyBlacklisted { .. }
            | IpsError::NotBlacklisted { .. }
            | IpsError::Whitelisted { .. }
            | IpsError::EnforcementFailed(_)
            | IpsError::BlacklistError(_) => DomainError::EngineError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blacklist_full_message() {
        let err = IpsError::BlacklistFull;
        assert!(err.to_string().contains("full"));
    }

    #[test]
    fn already_blacklisted_message() {
        let err = IpsError::AlreadyBlacklisted {
            ip: "10.0.0.1".to_string(),
        };
        assert!(err.to_string().contains("10.0.0.1"));
    }

    #[test]
    fn not_blacklisted_message() {
        let err = IpsError::NotBlacklisted {
            ip: "10.0.0.2".to_string(),
        };
        assert!(err.to_string().contains("10.0.0.2"));
    }

    #[test]
    fn invalid_policy_message() {
        let err = IpsError::InvalidPolicy("bad threshold".to_string());
        assert!(err.to_string().contains("bad threshold"));
    }

    #[test]
    fn enforcement_failed_message() {
        let err = IpsError::EnforcementFailed("map write failed".to_string());
        assert!(err.to_string().contains("map write failed"));
    }

    #[test]
    fn from_ips_error_to_domain_error() {
        let domain: DomainError = IpsError::BlacklistFull.into();
        assert!(matches!(domain, DomainError::EngineError(_)));

        let domain: DomainError = IpsError::InvalidPolicy("x".to_string()).into();
        assert!(matches!(domain, DomainError::InvalidConfig(_)));

        let domain: DomainError = IpsError::NotBlacklisted {
            ip: "1.2.3.4".to_string(),
        }
        .into();
        assert!(matches!(domain, DomainError::EngineError(_)));
    }
}
