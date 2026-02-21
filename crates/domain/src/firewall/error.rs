use thiserror::Error;

use crate::common::error::DomainError;

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("invalid port range: {start}..{end}")]
    InvalidPortRange { start: u16, end: u16 },

    #[error("invalid CIDR prefix length: {prefix_len}")]
    InvalidCidr { prefix_len: u8 },

    #[error("invalid priority: must be > 0")]
    InvalidPriority,

    #[error("invalid rule ID: {reason}")]
    InvalidRuleId { reason: &'static str },

    #[error("duplicate rule: {id}")]
    DuplicateRule { id: String },

    #[error("rule not found: {id}")]
    RuleNotFound { id: String },

    #[error("mixed address families: src and dst must both be IPv4 or both IPv6")]
    MixedAddressFamilies,

    #[error("invalid VLAN ID: {vlan_id} (must be 0-4094)")]
    InvalidVlanId { vlan_id: u16 },
}

impl From<FirewallError> for DomainError {
    fn from(e: FirewallError) -> Self {
        match e {
            FirewallError::DuplicateRule { ref id } => DomainError::DuplicateRule(id.clone()),
            FirewallError::RuleNotFound { ref id } => DomainError::RuleNotFound(id.clone()),
            other => DomainError::InvalidRule(other.to_string()),
        }
    }
}
