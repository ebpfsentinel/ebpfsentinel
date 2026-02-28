use domain::common::error::DomainError;
use domain::firewall::entity::IpNetwork;

/// Secondary port for resolving dynamic alias sources.
///
/// Handles external lookups required by aliases that cannot be resolved
/// purely from configuration data: URL tables (HTTP fetch), DNS dynamic
/// hostnames, and `GeoIP` country-code resolution.
///
/// Implemented by an adapter that wraps HTTP clients, DNS resolvers,
/// and `GeoIP` databases.
pub trait AliasResolutionPort: Send + Sync {
    /// Fetch an IP list from a remote URL (e.g. Spamhaus DROP list).
    fn fetch_url_table(&self, url: &str) -> Result<Vec<IpNetwork>, DomainError>;

    /// Resolve a hostname to its current IP addresses.
    fn resolve_dns(&self, hostname: &str) -> Result<Vec<IpNetwork>, DomainError>;

    /// Look up all IP networks for the given country codes (ISO 3166-1 alpha-2).
    fn lookup_geoip(&self, country_codes: &[String]) -> Result<Vec<IpNetwork>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_resolution_port_is_object_safe() {
        fn _check(_port: &dyn AliasResolutionPort) {}
    }
}
