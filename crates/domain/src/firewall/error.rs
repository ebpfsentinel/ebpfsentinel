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

    #[error("TCP flags can only be used with TCP protocol")]
    TcpFlagsWithNonTcp,

    #[error("ICMP type/code can only be used with ICMP protocol")]
    IcmpFieldsWithNonIcmp,

    #[error("ICMP rules cannot specify port ranges")]
    IcmpWithPorts,

    #[error("invalid TCP flags specification: {value}")]
    InvalidTcpFlags { value: String },

    #[error("invalid MAC address: {value}")]
    InvalidMacAddress { value: String },

    #[error("invalid DSCP value: {value} (must be 0-63)")]
    InvalidDscp { value: u8 },

    #[error("cannot delete system rule: {id}")]
    SystemRuleProtected { id: String },

    #[error("invalid scope: {reason}")]
    InvalidScope { reason: String },

    #[error("invalid workload selector: {reason}")]
    InvalidWorkloadSelector { reason: String },

    /// A matcher the socket hooks cannot decide was written on a rule naming a
    /// workload. The hook runs inside the task's own `connect()` or `bind()`,
    /// where there is no frame, no source address and no connection yet, so a
    /// rule carrying one of those would never match anything and saying so at
    /// load time is the only way an operator finds out.
    #[error("{matcher} has no meaning on a rule naming a workload: {reason}")]
    WorkloadMatcherUnsupported {
        matcher: &'static str,
        reason: &'static str,
    },

    #[error("too many workload rules: {count}, more than the {maximum} the kernel holds")]
    WorkloadPolicyTooLarge { count: usize, maximum: usize },
}

impl From<FirewallError> for DomainError {
    fn from(e: FirewallError) -> Self {
        match e {
            FirewallError::DuplicateRule { ref id } => DomainError::DuplicateRule(id.clone()),
            FirewallError::RuleNotFound { ref id } => DomainError::RuleNotFound(id.clone()),
            FirewallError::SystemRuleProtected { ref id } => {
                DomainError::PermissionDenied(format!("cannot delete system rule: {id}"))
            }
            other => DomainError::InvalidRule(other.to_string()),
        }
    }
}
