use std::collections::HashMap;
use std::net::IpAddr;

use crate::common::error::DomainError;
use crate::threatintel::entity::Ioc;
use crate::threatintel::error::ThreatIntelError;

/// Userspace threat intelligence engine.
///
/// Stores IOCs in a `HashMap` keyed by IP address. Provides CRUD operations,
/// deduplication (highest confidence wins), and capacity enforcement.
///
/// This engine is source-agnostic — it doesn't know about feed providers,
/// only about validated IOC entries.
pub struct ThreatIntelEngine {
    iocs: HashMap<IpAddr, Ioc>,
    max_capacity: usize,
}

impl ThreatIntelEngine {
    /// Create a new engine with the specified maximum IOC capacity.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            iocs: HashMap::new(),
            max_capacity,
        }
    }

    /// Add an IOC. If the same IP already exists, keep the entry with
    /// the highest confidence score (deduplication across feeds).
    pub fn add_ioc(&mut self, ioc: Ioc) -> Result<(), DomainError> {
        ioc.validate()
            .map_err(|reason| ThreatIntelError::InvalidIoc {
                ip: ioc.ip.to_string(),
                reason: reason.to_string(),
            })?;

        // Dedup: if IP exists with lower confidence, replace it
        if let Some(existing) = self.iocs.get(&ioc.ip) {
            if ioc.confidence > existing.confidence {
                self.iocs.insert(ioc.ip, ioc);
            }
            // If same or lower confidence, silently keep existing
            return Ok(());
        }

        // Check capacity before inserting
        if self.iocs.len() >= self.max_capacity {
            return Err(ThreatIntelError::MapFull {
                capacity: self.max_capacity,
            }
            .into());
        }

        self.iocs.insert(ioc.ip, ioc);
        Ok(())
    }

    /// Remove an IOC by IP address.
    pub fn remove_ioc(&mut self, ip: &IpAddr) -> Result<(), DomainError> {
        if self.iocs.remove(ip).is_none() {
            return Err(DomainError::RuleNotFound(format!("IOC {ip}")));
        }
        Ok(())
    }

    /// Remove all IOCs.
    pub fn clear(&mut self) {
        self.iocs.clear();
    }

    /// Atomically replace all IOCs. Validates all entries first;
    /// if any validation fails, the existing set is preserved (rollback).
    pub fn reload(&mut self, iocs: Vec<Ioc>) -> Result<(), DomainError> {
        // Phase 1: validate all IOCs
        for ioc in &iocs {
            ioc.validate()
                .map_err(|reason| ThreatIntelError::InvalidIoc {
                    ip: ioc.ip.to_string(),
                    reason: reason.to_string(),
                })?;
        }

        // Phase 2: build new map with dedup
        let mut new_map: HashMap<IpAddr, Ioc> = HashMap::with_capacity(iocs.len());
        for ioc in iocs {
            match new_map.get(&ioc.ip) {
                Some(existing) if existing.confidence >= ioc.confidence => {
                    // Keep existing (higher or equal confidence)
                }
                _ => {
                    new_map.insert(ioc.ip, ioc);
                }
            }
        }

        // Check capacity
        if new_map.len() > self.max_capacity {
            return Err(ThreatIntelError::MapFull {
                capacity: self.max_capacity,
            }
            .into());
        }

        // Atomic swap
        self.iocs = new_map;
        Ok(())
    }

    /// Lookup an IOC by IP address.
    pub fn lookup(&self, ip: &IpAddr) -> Option<&Ioc> {
        self.iocs.get(ip)
    }

    /// Total number of loaded IOCs.
    pub fn ioc_count(&self) -> usize {
        self.iocs.len()
    }

    /// Filter IOCs by feed ID.
    pub fn iocs_by_feed(&self, feed_id: &str) -> Vec<&Ioc> {
        self.iocs
            .values()
            .filter(|ioc| ioc.feed_id == feed_id)
            .collect()
    }

    /// Iterate over all IOCs.
    pub fn all_iocs(&self) -> impl Iterator<Item = &Ioc> {
        self.iocs.values()
    }

    /// Maximum capacity of the engine.
    pub fn max_capacity(&self) -> usize {
        self.max_capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threatintel::entity::ThreatType;
    use std::net::Ipv4Addr;

    fn ioc(ip: &str, feed: &str, confidence: u8) -> Ioc {
        Ioc {
            ip: ip.parse().unwrap(),
            feed_id: feed.to_string(),
            confidence,
            threat_type: ThreatType::Malware,
            last_seen: 0,
            source_feed: feed.to_string(),
        }
    }

    #[test]
    fn empty_engine() {
        let engine = ThreatIntelEngine::new(100);
        assert_eq!(engine.ioc_count(), 0);
        assert!(
            engine
                .lookup(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
                .is_none()
        );
    }

    #[test]
    fn add_and_lookup() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "feed-a", 80)).unwrap();
        let found = engine.lookup(&"10.0.0.1".parse().unwrap());
        assert!(found.is_some());
        assert_eq!(found.unwrap().confidence, 80);
        assert_eq!(engine.ioc_count(), 1);
    }

    #[test]
    fn add_duplicate_keeps_highest_confidence() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "feed-a", 60)).unwrap();
        engine.add_ioc(ioc("10.0.0.1", "feed-b", 90)).unwrap();
        // Higher confidence replaced
        let found = engine.lookup(&"10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(found.confidence, 90);
        assert_eq!(found.feed_id, "feed-b");
        // Still only one entry
        assert_eq!(engine.ioc_count(), 1);
    }

    #[test]
    fn add_duplicate_lower_confidence_no_replace() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "feed-a", 90)).unwrap();
        engine.add_ioc(ioc("10.0.0.1", "feed-b", 50)).unwrap();
        let found = engine.lookup(&"10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(found.confidence, 90);
        assert_eq!(found.feed_id, "feed-a");
    }

    #[test]
    fn capacity_limit() {
        let mut engine = ThreatIntelEngine::new(2);
        engine.add_ioc(ioc("10.0.0.1", "f", 80)).unwrap();
        engine.add_ioc(ioc("10.0.0.2", "f", 80)).unwrap();
        let result = engine.add_ioc(ioc("10.0.0.3", "f", 80));
        assert!(result.is_err());
        assert_eq!(engine.ioc_count(), 2);
    }

    #[test]
    fn capacity_dedup_does_not_count_twice() {
        let mut engine = ThreatIntelEngine::new(2);
        engine.add_ioc(ioc("10.0.0.1", "f", 80)).unwrap();
        engine.add_ioc(ioc("10.0.0.2", "f", 80)).unwrap();
        // Same IP, different feed — dedup replaces, doesn't add
        engine.add_ioc(ioc("10.0.0.1", "g", 95)).unwrap();
        assert_eq!(engine.ioc_count(), 2);
    }

    #[test]
    fn remove_existing() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "f", 80)).unwrap();
        engine.remove_ioc(&"10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(engine.ioc_count(), 0);
    }

    #[test]
    fn remove_nonexistent_fails() {
        let mut engine = ThreatIntelEngine::new(100);
        assert!(engine.remove_ioc(&"10.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn clear_empties_engine() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "f", 80)).unwrap();
        engine.add_ioc(ioc("10.0.0.2", "f", 80)).unwrap();
        engine.clear();
        assert_eq!(engine.ioc_count(), 0);
    }

    #[test]
    fn reload_replaces_all() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "old", 80)).unwrap();

        engine
            .reload(vec![
                ioc("192.168.1.1", "new-a", 70),
                ioc("192.168.1.2", "new-b", 60),
            ])
            .unwrap();

        assert_eq!(engine.ioc_count(), 2);
        assert!(engine.lookup(&"10.0.0.1".parse().unwrap()).is_none());
        assert!(engine.lookup(&"192.168.1.1".parse().unwrap()).is_some());
    }

    #[test]
    fn reload_deduplicates() {
        let mut engine = ThreatIntelEngine::new(100);
        engine
            .reload(vec![
                ioc("10.0.0.1", "feed-a", 60),
                ioc("10.0.0.1", "feed-b", 90),
            ])
            .unwrap();

        assert_eq!(engine.ioc_count(), 1);
        let found = engine.lookup(&"10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(found.confidence, 90);
    }

    #[test]
    fn reload_rollback_on_invalid() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "keep", 80)).unwrap();

        let invalid = Ioc {
            ip: "10.0.0.2".parse().unwrap(),
            feed_id: String::new(), // invalid: empty feed_id
            confidence: 80,
            threat_type: ThreatType::C2,
            last_seen: 0,
            source_feed: String::new(),
        };

        let result = engine.reload(vec![ioc("10.0.0.3", "new", 70), invalid]);
        assert!(result.is_err());
        // Original data preserved
        assert_eq!(engine.ioc_count(), 1);
        assert!(engine.lookup(&"10.0.0.1".parse().unwrap()).is_some());
    }

    #[test]
    fn reload_exceeds_capacity_fails() {
        let mut engine = ThreatIntelEngine::new(1);
        let result = engine.reload(vec![ioc("10.0.0.1", "f", 80), ioc("10.0.0.2", "f", 80)]);
        assert!(result.is_err());
        // Engine untouched (was empty, still empty)
        assert_eq!(engine.ioc_count(), 0);
    }

    #[test]
    fn iocs_by_feed() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "alpha", 80)).unwrap();
        engine.add_ioc(ioc("10.0.0.2", "beta", 70)).unwrap();
        engine.add_ioc(ioc("10.0.0.3", "alpha", 60)).unwrap();

        let alpha = engine.iocs_by_feed("alpha");
        assert_eq!(alpha.len(), 2);
        let beta = engine.iocs_by_feed("beta");
        assert_eq!(beta.len(), 1);
        let gamma = engine.iocs_by_feed("gamma");
        assert!(gamma.is_empty());
    }

    #[test]
    fn all_iocs_iterates() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(ioc("10.0.0.1", "f", 80)).unwrap();
        engine.add_ioc(ioc("10.0.0.2", "f", 70)).unwrap();
        assert_eq!(engine.all_iocs().count(), 2);
    }

    #[test]
    fn add_invalid_ioc_fails() {
        let mut engine = ThreatIntelEngine::new(100);
        let bad = Ioc {
            ip: "10.0.0.1".parse().unwrap(),
            feed_id: String::new(),
            confidence: 80,
            threat_type: ThreatType::Other,
            last_seen: 0,
            source_feed: String::new(),
        };
        assert!(engine.add_ioc(bad).is_err());
        assert_eq!(engine.ioc_count(), 0);
    }

    #[test]
    fn add_ioc_confidence_over_100_fails() {
        let mut engine = ThreatIntelEngine::new(100);
        let bad = Ioc {
            ip: "10.0.0.1".parse().unwrap(),
            feed_id: "f".to_string(),
            confidence: 150,
            threat_type: ThreatType::Other,
            last_seen: 0,
            source_feed: "f".to_string(),
        };
        assert!(engine.add_ioc(bad).is_err());
    }

    #[test]
    fn max_capacity_getter() {
        let engine = ThreatIntelEngine::new(42);
        assert_eq!(engine.max_capacity(), 42);
    }
}
