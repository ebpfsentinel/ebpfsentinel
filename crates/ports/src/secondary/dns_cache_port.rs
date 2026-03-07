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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct InMemoryDnsCache {
        entries: Mutex<HashMap<String, DnsCacheEntry>>,
    }

    impl InMemoryDnsCache {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }
    }

    impl DnsCachePort for InMemoryDnsCache {
        fn lookup_domain(&self, domain: &str) -> Option<DnsCacheEntry> {
            self.entries.lock().unwrap().get(domain).cloned()
        }

        fn lookup_ip(&self, ip: &IpAddr) -> Vec<String> {
            self.entries
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, entry)| entry.ips.contains(ip))
                .map(|(domain, _)| domain.clone())
                .collect()
        }

        fn lookup_all(&self, page: usize, page_size: usize) -> Vec<(String, DnsCacheEntry)> {
            let entries = self.entries.lock().unwrap();
            let mut all: Vec<(String, DnsCacheEntry)> = entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            all.sort_by(|a, b| a.0.cmp(&b.0));
            all.into_iter()
                .skip(page * page_size)
                .take(page_size)
                .collect()
        }

        fn insert(&self, domain: String, ips: Vec<IpAddr>, ttl_secs: u64, timestamp_ns: u64) {
            self.entries.lock().unwrap().insert(
                domain,
                DnsCacheEntry {
                    ips,
                    ttl_secs,
                    inserted_at_ns: timestamp_ns,
                    last_queried_ns: timestamp_ns,
                    query_count: 0,
                },
            );
        }

        fn stats(&self) -> DnsCacheStats {
            let entries = self.entries.lock().unwrap();
            DnsCacheStats {
                total_entries: entries.len(),
                ..Default::default()
            }
        }

        fn flush(&self) {
            self.entries.lock().unwrap().clear();
        }
    }

    #[test]
    fn insert_and_lookup_domain() {
        let cache = InMemoryDnsCache::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        cache.insert("example.com".to_string(), vec![ip], 300, 1000);

        let entry = cache.lookup_domain("example.com").unwrap();
        assert_eq!(entry.ips, vec![ip]);
        assert_eq!(entry.ttl_secs, 300);
        assert_eq!(entry.inserted_at_ns, 1000);
    }

    #[test]
    fn lookup_ip_reverse() {
        let cache = InMemoryDnsCache::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        cache.insert("myhost.local".to_string(), vec![ip], 60, 500);

        let domains = cache.lookup_ip(&ip);
        assert_eq!(domains, vec!["myhost.local".to_string()]);
    }

    #[test]
    fn lookup_all_pagination() {
        let cache = InMemoryDnsCache::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        cache.insert("a.com".to_string(), vec![ip], 60, 1);
        cache.insert("b.com".to_string(), vec![ip], 60, 2);
        cache.insert("c.com".to_string(), vec![ip], 60, 3);

        let page0 = cache.lookup_all(0, 2);
        assert_eq!(page0.len(), 2);

        let page1 = cache.lookup_all(1, 2);
        assert_eq!(page1.len(), 1);
    }

    #[test]
    fn flush_clears_all() {
        let cache = InMemoryDnsCache::new();
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        cache.insert("test.com".to_string(), vec![ip], 60, 0);
        assert!(cache.lookup_domain("test.com").is_some());

        cache.flush();
        assert!(cache.lookup_domain("test.com").is_none());
    }

    #[test]
    fn stats_reflect_state() {
        let cache = InMemoryDnsCache::new();
        assert_eq!(cache.stats().total_entries, 0);

        let ip: IpAddr = "2.2.2.2".parse().unwrap();
        cache.insert("one.com".to_string(), vec![ip], 60, 0);
        cache.insert("two.com".to_string(), vec![ip], 60, 0);
        assert_eq!(cache.stats().total_entries, 2);
    }
}
