use domain::alias::entity::GeoIpInfo;
use std::net::IpAddr;

/// Port for `GeoIP` lookups.
pub trait GeoIpPort: Send + Sync {
    /// Look up `GeoIP` info for an IP address.
    fn lookup(&self, ip: &IpAddr) -> Option<GeoIpInfo>;

    /// Return true if the database is loaded and ready.
    fn is_ready(&self) -> bool;
}
