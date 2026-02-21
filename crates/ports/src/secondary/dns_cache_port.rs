use std::net::IpAddr;

use domain::dns::entity::{DnsCacheEntry, DnsCacheStats};

/// Secondary port for DNS resolution cache operations.
///
/// Implemented by the application-layer service that wraps the domain engine.
/// Consumed by adapters (HTTP handlers, alert enrichment) that need DNS data.
pub trait DnsCachePort: Send + Sync {
    /// Look up a domain and return its cached entry (updates access metadata).
    fn lookup_domain(&self, domain: &str) -> Option<DnsCacheEntry>;

    /// Reverse lookup: find all domains that resolved to the given IP.
    fn lookup_ip(&self, ip: &IpAddr) -> Vec<String>;

    /// Paginated listing of all cache entries.
    fn lookup_all(&self, page: usize, page_size: usize) -> Vec<(String, DnsCacheEntry)>;

    /// Insert or update a DNS cache entry.
    fn insert(&self, domain: String, ips: Vec<IpAddr>, ttl_secs: u64, timestamp_ns: u64);

    /// Return current cache statistics.
    fn stats(&self) -> DnsCacheStats;

    /// Remove all entries and reset statistics.
    fn flush(&self);
}
