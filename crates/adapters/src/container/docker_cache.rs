//! LRU + TTL cache for Docker metadata lookups.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;

use domain::container::entity::DockerMetadata;

/// Default cache capacity.
pub const DEFAULT_CAPACITY: usize = 1024;
/// Default entry TTL.
pub const DEFAULT_TTL_SECS: u64 = 300;

struct Entry {
    metadata: DockerMetadata,
    inserted_at: Instant,
}

/// Thread-safe LRU cache with a uniform time-to-live per entry.
pub struct DockerCache {
    inner: Mutex<LruCache<String, Entry>>,
    ttl: Duration,
}

impl DockerCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("max(1) > 0");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            ttl,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_CAPACITY, Duration::from_secs(DEFAULT_TTL_SECS))
    }

    /// Returns `Some(metadata)` on cache hit within TTL, `None` otherwise.
    pub fn get(&self, container_id: &str) -> Option<DockerMetadata> {
        let mut lock = self.inner.lock().ok()?;
        let entry = lock.get(container_id)?;
        if entry.inserted_at.elapsed() > self.ttl {
            lock.pop(container_id);
            return None;
        }
        Some(entry.metadata.clone())
    }

    pub fn insert(&self, container_id: String, metadata: DockerMetadata) {
        if let Ok(mut lock) = self.inner.lock() {
            lock.put(
                container_id,
                Entry {
                    metadata,
                    inserted_at: Instant::now(),
                },
            );
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |l| l.len())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> DockerMetadata {
        DockerMetadata {
            name: name.to_string(),
            image: "img".into(),
            labels: vec![],
            created_at: "t".into(),
            status: "running".into(),
        }
    }

    #[test]
    fn hit_miss() {
        let cache = DockerCache::new(4, Duration::from_mins(1));
        assert!(cache.get("abc").is_none());
        cache.insert("abc".into(), sample("c1"));
        assert_eq!(cache.get("abc").unwrap().name, "c1");
    }

    #[test]
    fn ttl_expiry() {
        let cache = DockerCache::new(4, Duration::from_millis(1));
        cache.insert("abc".into(), sample("c1"));
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get("abc").is_none());
    }

    #[test]
    fn capacity_eviction() {
        let cache = DockerCache::new(2, Duration::from_mins(1));
        cache.insert("a".into(), sample("1"));
        cache.insert("b".into(), sample("2"));
        cache.insert("c".into(), sample("3"));
        assert!(cache.get("a").is_none());
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn zero_capacity_coerces_to_one() {
        let cache = DockerCache::new(0, Duration::from_mins(1));
        cache.insert("a".into(), sample("1"));
        assert!(cache.get("a").is_some());
    }

    #[test]
    fn len_reflects_inserts() {
        let cache = DockerCache::new(4, Duration::from_mins(1));
        assert!(cache.is_empty());
        cache.insert("a".into(), sample("1"));
        cache.insert("b".into(), sample("2"));
        assert_eq!(cache.len(), 2);
    }
}
