use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use domain::dns::engine::DnsCacheEngine;
use domain::dns::entity::{DnsCacheConfig, DnsCacheEntry, DnsCacheStats};
use ports::secondary::dns_cache_port::DnsCachePort;
use ports::secondary::metrics_port::MetricsPort;

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        * 1_000_000_000
}

/// Application-level DNS cache service.
///
/// Wraps the domain `DnsCacheEngine` with thread-safe access (`RwLock`)
/// and metrics updates. Implements `DnsCachePort` for use by adapters.
///
/// Expired entries are purged by the service itself, at most once per
/// `purge_interval_secs`, by the first insert or domain lookup past the
/// deadline: no task has to be spawned beside it, so every binary that
/// builds the service gets the purge.
pub struct DnsCacheAppService {
    engine: RwLock<DnsCacheEngine>,
    metrics: Arc<dyn MetricsPort>,
    purge_interval_ns: u64,
    next_purge_ns: AtomicU64,
}

impl DnsCacheAppService {
    pub fn new(config: DnsCacheConfig, metrics: Arc<dyn MetricsPort>) -> Self {
        let purge_interval_ns = config
            .purge_interval_secs
            .max(1)
            .saturating_mul(1_000_000_000);
        Self {
            engine: RwLock::new(DnsCacheEngine::new(config)),
            metrics,
            purge_interval_ns,
            next_purge_ns: AtomicU64::new(now_ns().saturating_add(purge_interval_ns)),
        }
    }

    /// Purge expired entries when the interval has elapsed, under the write
    /// lock the caller already holds.
    fn purge_if_due(&self, engine: &mut DnsCacheEngine, now_ns: u64) {
        if now_ns < self.next_purge_ns.load(Ordering::Relaxed) {
            return;
        }
        self.next_purge_ns.store(
            now_ns.saturating_add(self.purge_interval_ns),
            Ordering::Relaxed,
        );
        let evicted = engine.purge_expired(now_ns);
        let entry_count = engine.entry_count();
        if evicted > 0 {
            for _ in 0..evicted {
                self.metrics.increment_dns_cache_evictions();
            }
            tracing::debug!(evicted, remaining = entry_count, "dns cache purge complete");
        }
        self.metrics.set_dns_cache_entries(entry_count as u64);
    }

    /// Search entries whose domain contains the given substring.
    pub fn search_by_domain(
        &self,
        substring: &str,
        page: usize,
        page_size: usize,
    ) -> Vec<(String, DnsCacheEntry)> {
        let engine = self
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.search_by_domain(substring, page, page_size)
    }

    /// Return the top N most-queried domains.
    pub fn top_queried(&self, n: usize) -> Vec<(String, u64)> {
        let engine = self
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.top_queried(n)
    }

    /// Flush the cache and return the number of entries removed.
    pub fn flush_and_count(&self) -> usize {
        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = engine.entry_count();
        engine.flush();
        self.update_metrics(&engine);
        count
    }

    fn update_metrics(&self, engine: &DnsCacheEngine) {
        self.metrics
            .set_dns_cache_entries(engine.entry_count() as u64);
    }
}

impl DnsCachePort for DnsCacheAppService {
    fn lookup_domain(&self, domain: &str) -> Option<DnsCacheEntry> {
        let now_ns = now_ns();

        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.purge_if_due(&mut engine, now_ns);
        let result = engine.lookup_domain(domain, now_ns).cloned();

        if result.is_some() {
            self.metrics.increment_dns_cache_hits();
        }
        result
    }

    fn lookup_ip(&self, ip: &IpAddr) -> Vec<String> {
        let engine = self
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.lookup_ip(ip)
    }

    fn lookup_all(&self, page: usize, page_size: usize) -> Vec<(String, DnsCacheEntry)> {
        let engine = self
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.lookup_all(page, page_size)
    }

    fn insert(&self, domain: String, ips: Vec<IpAddr>, ttl_secs: u64, timestamp_ns: u64) {
        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.purge_if_due(&mut engine, now_ns());
        engine.insert(domain, ips, ttl_secs, timestamp_ns);
        self.update_metrics(&engine);
    }

    fn stats(&self) -> DnsCacheStats {
        let engine = self
            .engine
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.stats()
    }

    fn flush(&self) {
        let mut engine = self
            .engine
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        engine.flush();
        self.update_metrics(&engine);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ports::test_utils::NoopMetrics;

    fn make_service() -> DnsCacheAppService {
        DnsCacheAppService::new(
            DnsCacheConfig {
                max_entries: 100,
                min_ttl_secs: 60,
                purge_interval_secs: 30,
            },
            Arc::new(NoopMetrics),
        )
    }

    #[test]
    fn insert_and_lookup() {
        let svc = make_service();
        let ip = "1.2.3.4".parse().unwrap();
        svc.insert("example.com".to_string(), vec![ip], 300, 0);

        let entry = svc.lookup_domain("example.com").unwrap();
        assert_eq!(entry.ips, vec![ip]);
    }

    #[test]
    fn reverse_lookup() {
        let svc = make_service();
        let ip = "10.0.0.1".parse().unwrap();
        svc.insert("a.com".to_string(), vec![ip], 300, 0);
        svc.insert("b.com".to_string(), vec![ip], 300, 0);

        let mut domains = svc.lookup_ip(&ip);
        domains.sort();
        assert_eq!(domains, vec!["a.com", "b.com"]);
    }

    #[test]
    fn stats_and_flush() {
        let svc = make_service();
        let ip = "1.1.1.1".parse().unwrap();
        svc.insert("x.com".to_string(), vec![ip], 300, 0);

        let stats = svc.stats();
        assert_eq!(stats.total_entries, 1);

        svc.flush();
        assert_eq!(svc.stats().total_entries, 0);
    }

    #[test]
    fn lookup_all_pagination() {
        let svc = make_service();
        for i in 0..5u8 {
            let ip = format!("10.0.0.{i}").parse().unwrap();
            svc.insert(format!("{i}.com"), vec![ip], 300, u64::from(i));
        }

        let page = svc.lookup_all(0, 3);
        assert_eq!(page.len(), 3);
    }

    #[test]
    fn an_expired_entry_is_purged_once_the_interval_has_passed() {
        let svc = make_service();
        let ip = "10.0.0.9".parse().unwrap();
        svc.insert("stale.com".to_string(), vec![ip], 60, 0);

        // Before the interval, an expired entry stays until something purges.
        assert!(svc.lookup_domain("stale.com").is_some());

        svc.next_purge_ns.store(0, Ordering::Relaxed);
        svc.insert("fresh.com".to_string(), vec![ip], 60, now_ns());

        assert!(svc.lookup_domain("stale.com").is_none());
        assert!(svc.lookup_domain("fresh.com").is_some());
        assert!(svc.next_purge_ns.load(Ordering::Relaxed) > now_ns());
    }
}
