use std::net::IpAddr;

use domain::common::error::DomainError;

/// Metadata for an IOC injected via DNS blocklist resolution.
#[derive(Debug, Clone)]
pub struct IocMetadata {
    /// Source identifier (e.g. `"dns-blocklist"`).
    pub source: String,
    /// The domain that resolved to the injected IP.
    pub domain: Option<String>,
    /// Threat classification (e.g. `"blocklisted-domain"`).
    pub threat_type: String,
    /// Confidence score (0-100).
    pub confidence: u8,
}

/// Secondary port for dynamic eBPF map writes from DNS blocklist.
///
/// Allows the domain/application layer to inject or remove IPs from
/// kernel-space eBPF maps without depending on aya directly.
pub trait EbpfMapWritePort: Send + Sync {
    /// Insert an IP into the threat intelligence IOC map.
    fn inject_threatintel_ip(&self, ip: IpAddr, metadata: &IocMetadata) -> Result<(), DomainError>;

    /// Remove an IP from the threat intelligence IOC map.
    fn remove_threatintel_ip(&self, ip: IpAddr) -> Result<(), DomainError>;

    /// Insert an IP as a firewall drop rule.
    fn inject_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError>;

    /// Remove an IP from the firewall drop rules.
    fn remove_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError>;
}
