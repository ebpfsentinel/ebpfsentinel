use std::net::IpAddr;
use std::time::Duration;

use domain::common::error::DomainError;

/// Secondary port for IPS blacklist operations.
///
/// Used by the DNS blocklist service to inject/remove IPs from the IPS
/// blacklist when `inject_target: ips` is configured. The implementation
/// wraps `IpsAppService` with interior mutability.
pub trait IpsBlacklistPort: Send + Sync {
    /// Add an IP to the IPS blacklist with the given reason and TTL.
    fn add_to_blacklist(
        &self,
        ip: IpAddr,
        reason: String,
        ttl: Duration,
    ) -> Result<(), DomainError>;

    /// Remove an IP from the IPS blacklist.
    fn remove_from_blacklist(&self, ip: &IpAddr) -> Result<(), DomainError>;
}
