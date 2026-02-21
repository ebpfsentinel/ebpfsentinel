use std::collections::HashMap;
use std::net::IpAddr;

use super::entity::{DnsCacheConfig, DnsCacheEntry, DnsCacheStats};

/// In-memory DNS resolution cache with forward and reverse indices.
///
/// Thread safety: callers wrap this in `RwLock` at the application layer.
/// The engine itself is single-threaded — all mutation goes through `&mut self`.
pub struct DnsCacheEngine {
    /// Forward index: domain → cache entry.
    forward: HashMap<String, DnsCacheEntry>,
    /// Reverse index: IP → list of domains that resolved to it.
    reverse: HashMap<IpAddr, Vec<String>>,
    config: DnsCacheConfig,
    stats: DnsCacheStats,
}

impl DnsCacheEngine {
    pub fn new(config: DnsCacheConfig) -> Self {
        Self {
            forward: HashMap::new(),
            reverse: HashMap::new(),
            config,
            stats: DnsCacheStats::default(),
        }
    }

    /// Insert or update a DNS cache entry.
    ///
    /// If the domain already exists, its IPs are replaced and the reverse
    /// index is updated. TTL is floored to `min_ttl_secs`. When the cache
    /// is full, the least-recently-queried entry is evicted.
    pub fn insert(&mut self, domain: String, ips: Vec<IpAddr>, ttl_secs: u64, timestamp_ns: u64) {
        let effective_ttl = ttl_secs.max(self.config.min_ttl_secs);

        // If domain already exists, remove old reverse index entries first.
        if let Some(old) = self.forward.get(&domain) {
            self.remove_reverse_entries(&domain, &old.ips.clone());
        }

        // Evict LRU if at capacity and this is a new domain.
        if !self.forward.contains_key(&domain) && self.forward.len() >= self.config.max_entries {
            self.evict_lru();
        }

        // Add reverse index entries for new IPs.
        for ip in &ips {
            self.reverse.entry(*ip).or_default().push(domain.clone());
        }

        let entry = DnsCacheEntry {
            ips,
            ttl_secs: effective_ttl,
            inserted_at_ns: timestamp_ns,
            last_queried_ns: timestamp_ns,
            query_count: 1,
        };
        self.forward.insert(domain, entry);
    }

    /// Look up a domain in the cache, updating access metadata on hit.
    pub fn lookup_domain(&mut self, domain: &str, now_ns: u64) -> Option<&DnsCacheEntry> {
        if let Some(entry) = self.forward.get_mut(domain) {
            entry.last_queried_ns = now_ns;
            entry.query_count += 1;
            self.stats.hit_count += 1;
            Some(entry)
        } else {
            self.stats.miss_count += 1;
            None
        }
    }

    /// Reverse lookup: find all domains that resolved to the given IP.
    pub fn lookup_ip(&self, ip: &IpAddr) -> Vec<String> {
        self.reverse.get(ip).cloned().unwrap_or_default()
    }

    /// Paginated listing of all cache entries.
    pub fn lookup_all(&self, page: usize, page_size: usize) -> Vec<(String, DnsCacheEntry)> {
        self.forward
            .iter()
            .skip(page * page_size)
            .take(page_size)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Return current cache statistics.
    pub fn stats(&self) -> DnsCacheStats {
        DnsCacheStats {
            total_entries: self.forward.len(),
            ..self.stats.clone()
        }
    }

    /// Remove all entries and reset statistics.
    pub fn flush(&mut self) {
        self.forward.clear();
        self.reverse.clear();
        self.stats = DnsCacheStats::default();
    }

    /// Purge entries whose TTL has expired. Returns the number of purged entries.
    pub fn purge_expired(&mut self, now_ns: u64) -> usize {
        let expired_domains: Vec<String> = self
            .forward
            .iter()
            .filter(|(_, entry)| {
                let expiry_ns = entry.inserted_at_ns + entry.ttl_secs * 1_000_000_000;
                now_ns >= expiry_ns
            })
            .map(|(domain, _)| domain.clone())
            .collect();

        let count = expired_domains.len();
        for domain in &expired_domains {
            if let Some(entry) = self.forward.remove(domain) {
                self.remove_reverse_entries(domain, &entry.ips);
            }
        }
        self.stats.expired_count += count as u64;
        count
    }

    /// Return the top N most-queried domains.
    pub fn top_queried(&self, n: usize) -> Vec<(String, u64)> {
        let mut entries: Vec<(String, u64)> = self
            .forward
            .iter()
            .map(|(domain, entry)| (domain.clone(), entry.query_count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(n);
        entries
    }

    /// Search entries whose domain contains the given substring (case-insensitive).
    pub fn search_by_domain(
        &self,
        substring: &str,
        page: usize,
        page_size: usize,
    ) -> Vec<(String, DnsCacheEntry)> {
        let needle = substring.to_lowercase();
        self.forward
            .iter()
            .filter(|(domain, _)| domain.contains(&needle))
            .skip(page * page_size)
            .take(page_size)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Total number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.forward.len()
    }

    /// Evict the least-recently-queried entry.
    fn evict_lru(&mut self) {
        let lru_domain = self
            .forward
            .iter()
            .min_by_key(|(_, entry)| entry.last_queried_ns)
            .map(|(domain, _)| domain.clone());

        if let Some(domain) = lru_domain {
            if let Some(entry) = self.forward.remove(&domain) {
                self.remove_reverse_entries(&domain, &entry.ips);
            }
            self.stats.eviction_count += 1;
        }
    }

    /// Remove a domain from the reverse index for the given IPs.
    fn remove_reverse_entries(&mut self, domain: &str, ips: &[IpAddr]) {
        for ip in ips {
            if let Some(domains) = self.reverse.get_mut(ip) {
                domains.retain(|d| d != domain);
                if domains.is_empty() {
                    self.reverse.remove(ip);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_config(max_entries: usize) -> DnsCacheConfig {
        DnsCacheConfig {
            max_entries,
            min_ttl_secs: 60,
            purge_interval_secs: 30,
        }
    }

    fn ts(secs: u64) -> u64 {
        secs * 1_000_000_000
    }

    #[test]
    fn insert_and_lookup_domain() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];
        engine.insert("example.com".to_string(), ips.clone(), 300, ts(0));

        let entry = engine.lookup_domain("example.com", ts(1)).unwrap();
        assert_eq!(entry.ips, ips);
        assert_eq!(entry.ttl_secs, 300);
        assert_eq!(entry.query_count, 2); // 1 from insert + 1 from lookup
    }

    #[test]
    fn lookup_miss_increments_counter() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        assert!(engine.lookup_domain("nope.com", ts(0)).is_none());
        assert_eq!(engine.stats().miss_count, 1);
    }

    #[test]
    fn reverse_index_lookup() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        engine.insert("a.com".to_string(), vec![ip], 300, ts(0));
        engine.insert("b.com".to_string(), vec![ip], 300, ts(0));

        let mut domains = engine.lookup_ip(&ip);
        domains.sort();
        assert_eq!(domains, vec!["a.com", "b.com"]);
    }

    #[test]
    fn reverse_index_empty_for_unknown_ip() {
        let engine = DnsCacheEngine::new(test_config(100));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(engine.lookup_ip(&ip).is_empty());
    }

    #[test]
    fn min_ttl_floor_applied() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        engine.insert("short-ttl.com".to_string(), ips, 5, ts(0)); // TTL=5 < min_ttl=60

        let entry = engine.lookup_domain("short-ttl.com", ts(1)).unwrap();
        assert_eq!(entry.ttl_secs, 60); // Floored to min_ttl
    }

    #[test]
    fn ttl_expiry_purge() {
        let mut engine = DnsCacheEngine::new(DnsCacheConfig {
            max_entries: 100,
            min_ttl_secs: 10,
            purge_interval_secs: 30,
        });
        let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        engine.insert("expire-me.com".to_string(), ips.clone(), 10, ts(0));
        engine.insert("keep-me.com".to_string(), ips, 3600, ts(0));

        // At t=11s, first entry should be expired
        let purged = engine.purge_expired(ts(11));
        assert_eq!(purged, 1);
        assert!(engine.lookup_domain("expire-me.com", ts(11)).is_none());
        assert!(engine.lookup_domain("keep-me.com", ts(11)).is_some());
        assert_eq!(engine.stats().expired_count, 1);
    }

    #[test]
    fn lru_eviction_when_full() {
        let mut engine = DnsCacheEngine::new(test_config(3));
        let ip = |n: u8| vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))];

        engine.insert("a.com".to_string(), ip(1), 300, ts(0));
        engine.insert("b.com".to_string(), ip(2), 300, ts(1));
        engine.insert("c.com".to_string(), ip(3), 300, ts(2));

        // Access a.com so it's not LRU
        engine.lookup_domain("a.com", ts(3));

        // Insert d.com — should evict b.com (oldest last_queried_ns)
        engine.insert("d.com".to_string(), ip(4), 300, ts(4));

        assert_eq!(engine.entry_count(), 3);
        assert!(engine.lookup_domain("a.com", ts(5)).is_some());
        // b.com was evicted (LRU)
        assert!(engine.lookup_domain("b.com", ts(5)).is_none());
        assert!(engine.lookup_domain("c.com", ts(5)).is_some());
        assert!(engine.lookup_domain("d.com", ts(5)).is_some());
        assert_eq!(engine.stats().eviction_count, 1);
    }

    #[test]
    fn reverse_index_cleaned_on_eviction() {
        let mut engine = DnsCacheEngine::new(test_config(2));
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        engine.insert("a.com".to_string(), vec![ip1], 300, ts(0));
        engine.insert("b.com".to_string(), vec![ip2], 300, ts(1));

        // Evict a.com by inserting c.com
        engine.insert("c.com".to_string(), vec![ip1], 300, ts(2));

        // ip1 should now only point to c.com (a.com was evicted)
        let domains = engine.lookup_ip(&ip1);
        assert_eq!(domains, vec!["c.com"]);
    }

    #[test]
    fn reverse_index_cleaned_on_expiry() {
        let mut engine = DnsCacheEngine::new(DnsCacheConfig {
            max_entries: 100,
            min_ttl_secs: 10,
            purge_interval_secs: 30,
        });
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        engine.insert("expire.com".to_string(), vec![ip], 10, ts(0));

        engine.purge_expired(ts(11));
        assert!(engine.lookup_ip(&ip).is_empty());
    }

    #[test]
    fn duplicate_insert_updates_entry() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        engine.insert("example.com".to_string(), vec![ip1], 300, ts(0));
        engine.insert("example.com".to_string(), vec![ip2], 600, ts(1));

        let entry = engine.lookup_domain("example.com", ts(2)).unwrap();
        assert_eq!(entry.ips, vec![ip2]);
        assert_eq!(entry.ttl_secs, 600);

        // Old IP should be cleaned from reverse index
        assert!(engine.lookup_ip(&ip1).is_empty());
        assert_eq!(engine.lookup_ip(&ip2), vec!["example.com"]);
    }

    #[test]
    fn stats_tracking() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        engine.insert("a.com".to_string(), ips, 300, ts(0));

        engine.lookup_domain("a.com", ts(1)); // hit
        engine.lookup_domain("a.com", ts(2)); // hit
        engine.lookup_domain("nope.com", ts(3)); // miss

        let stats = engine.stats();
        assert_eq!(stats.total_entries, 1);
        assert_eq!(stats.hit_count, 2);
        assert_eq!(stats.miss_count, 1);
    }

    #[test]
    fn flush_clears_everything() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        engine.insert("a.com".to_string(), vec![ip], 300, ts(0));
        engine.lookup_domain("a.com", ts(1));

        engine.flush();

        assert_eq!(engine.entry_count(), 0);
        assert!(engine.lookup_ip(&ip).is_empty());
        let stats = engine.stats();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.hit_count, 0);
        assert_eq!(stats.miss_count, 0);
    }

    #[test]
    fn lookup_all_pagination() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        for i in 0..5 {
            engine.insert(
                format!("{i}.com"),
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, i))],
                300,
                ts(i.into()),
            );
        }

        let page0 = engine.lookup_all(0, 3);
        assert_eq!(page0.len(), 3);
        let page1 = engine.lookup_all(1, 3);
        assert_eq!(page1.len(), 2);
        let page2 = engine.lookup_all(2, 3);
        assert!(page2.is_empty());
    }

    #[test]
    fn ipv6_support() {
        let mut engine = DnsCacheEngine::new(test_config(100));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        engine.insert("v6.example.com".to_string(), vec![ipv6], 300, ts(0));

        let entry = engine.lookup_domain("v6.example.com", ts(1)).unwrap();
        assert_eq!(entry.ips, vec![ipv6]);
        assert_eq!(engine.lookup_ip(&ipv6), vec!["v6.example.com"]);
    }
}
