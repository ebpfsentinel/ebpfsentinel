use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum LbError {
    #[error("invalid service: {0}")]
    InvalidService(String),

    #[error("duplicate service: {id}")]
    DuplicateService { id: String },

    #[error("service not found: {id}")]
    ServiceNotFound { id: String },

    #[error("backend not found: {id}")]
    BackendNotFound { id: String },

    #[error("no healthy backend available for service: {service_id}")]
    NoHealthyBackend { service_id: String },

    #[error("invalid backend: {0}")]
    InvalidBackend(String),
}

impl From<LbError> for DomainError {
    fn from(e: LbError) -> Self {
        match e {
            LbError::ServiceNotFound { id } | LbError::BackendNotFound { id } => {
                Self::RuleNotFound(id)
            }
            LbError::DuplicateService { id } => Self::DuplicateRule(id),
            LbError::InvalidService(msg) | LbError::InvalidBackend(msg) => Self::InvalidRule(msg),
            LbError::NoHealthyBackend { .. } => Self::EngineError(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_not_found_to_domain_error() {
        let e: DomainError = LbError::ServiceNotFound {
            id: "svc-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::RuleNotFound(_)));
    }

    #[test]
    fn duplicate_to_domain_error() {
        let e: DomainError = LbError::DuplicateService {
            id: "svc-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::DuplicateRule(_)));
    }

    #[test]
    fn invalid_service_to_domain_error() {
        let e: DomainError = LbError::InvalidService("bad".to_string()).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }

    #[test]
    fn backend_not_found_to_domain_error() {
        let e: DomainError = LbError::BackendNotFound {
            id: "be-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::RuleNotFound(_)));
    }

    #[test]
    fn no_healthy_backend_to_domain_error() {
        let e: DomainError = LbError::NoHealthyBackend {
            service_id: "svc-1".to_string(),
        }
        .into();
        assert!(matches!(e, DomainError::EngineError(_)));
    }

    #[test]
    fn invalid_backend_to_domain_error() {
        let e: DomainError = LbError::InvalidBackend("bad port".to_string()).into();
        assert!(matches!(e, DomainError::InvalidRule(_)));
    }
}
