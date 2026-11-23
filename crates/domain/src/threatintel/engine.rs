use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use crate::common::error::DomainError;
use crate::threatintel::entity::{Ioc, address_bits, network_of};
use crate::threatintel::error::ThreatIntelError;

/// An indicator's identity: its first address and its prefix length, the
/// full address length for one address.
type IocKey = (IpAddr, u8);

/// Userspace threat intelligence engine.
///
/// Stores IOCs in a `HashMap` keyed by address and prefix length, so one
/// address and the range around it are two entries. Provides CRUD
/// operations, deduplication (highest confidence wins), capacity
/// enforcement, and the lookup the datapath performs: the address itself
/// first, then the longest range holding it.
///
/// This engine is source-agnostic - it doesn't know about feed providers,
/// only about validated IOC entries.
#[derive(Clone)]
pub struct ThreatIntelEngine {
    iocs: HashMap<IocKey, Ioc>,
    /// How many ranges of each prefix length are loaded, per family
    /// (`false` for IPv4). A lookup probes only the lengths present.
    range_lengths: BTreeMap<(bool, u8), usize>,
    max_capacity: usize,
    /// Per-country confidence adjustment (e.g. `{"RU": 10, "CN": 5}`).
    /// Positive values boost, negative values reduce. Clamped to 0-100.
    country_confidence_boost: HashMap<String, i8>,
}

fn key_of(ioc: &Ioc) -> IocKey {
    (ioc.ip, ioc.prefix())
}

fn invalid(ioc: &Ioc, reason: &str) -> DomainError {
    ThreatIntelError::InvalidIoc {
        ip: ioc.target(),
        reason: reason.to_string(),
    }
    .into()
}

fn count_ranges(iocs: &HashMap<IocKey, Ioc>) -> BTreeMap<(bool, u8), usize> {
    let mut lengths = BTreeMap::new();
    for ioc in iocs.values().filter(|i| i.is_range()) {
        *lengths.entry((ioc.ip.is_ipv6(), ioc.prefix())).or_insert(0) += 1;
    }
    lengths
}

impl ThreatIntelEngine {
    /// Create a new engine with the specified maximum IOC capacity.
    pub fn new(max_capacity: usize) -> Self {
        Self {
            iocs: HashMap::new(),
            range_lengths: BTreeMap::new(),
            max_capacity,
            country_confidence_boost: HashMap::new(),
        }
    }

    /// Add an IOC. If the same address or range already exists, keep the
    /// entry with the highest confidence score (deduplication across feeds).
    pub fn add_ioc(&mut self, ioc: Ioc) -> Result<(), DomainError> {
        ioc.validate().map_err(|reason| invalid(&ioc, reason))?;
        let key = key_of(&ioc);

        // Dedup: if the entry exists with lower confidence, replace it
        if let Some(existing) = self.iocs.get(&key) {
            if ioc.confidence > existing.confidence {
                self.iocs.insert(key, ioc);
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

        if ioc.is_range() {
            *self
                .range_lengths
                .entry((ioc.ip.is_ipv6(), ioc.prefix()))
                .or_insert(0) += 1;
        }
        self.iocs.insert(key, ioc);
        Ok(())
    }

    /// Remove the IOC naming exactly this address (not a range holding it).
    pub fn remove_ioc(&mut self, ip: &IpAddr) -> Result<(), DomainError> {
        if self.iocs.remove(&(*ip, address_bits(*ip))).is_none() {
            return Err(DomainError::RuleNotFound(format!("IOC {ip}")));
        }
        Ok(())
    }

    /// Remove all IOCs.
    pub fn clear(&mut self) {
        self.iocs.clear();
        self.range_lengths.clear();
    }

    /// Atomically replace all IOCs. Validates all entries first;
    /// if any validation fails, the existing set is preserved (rollback).
    pub fn reload(&mut self, iocs: Vec<Ioc>) -> Result<(), DomainError> {
        // Phase 1: validate all IOCs
        for ioc in &iocs {
            ioc.validate().map_err(|reason| invalid(ioc, reason))?;
        }

        // Phase 2: build new map with dedup
        let mut new_map: HashMap<IocKey, Ioc> = HashMap::with_capacity(iocs.len());
        for ioc in iocs {
            let key = key_of(&ioc);
            match new_map.get(&key) {
                Some(existing) if existing.confidence >= ioc.confidence => {
                    // Keep existing (higher or equal confidence)
                }
                _ => {
                    new_map.insert(key, ioc);
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
        self.range_lengths = count_ranges(&new_map);
        self.iocs = new_map;
        Ok(())
    }

    /// The indicator deciding for `ip`, as the datapath decides it: the
    /// address itself when it is listed, otherwise the longest range
    /// holding it.
    pub fn lookup(&self, ip: &IpAddr) -> Option<&Ioc> {
        if let Some(ioc) = self.iocs.get(&(*ip, address_bits(*ip))) {
            return Some(ioc);
        }
        let v6 = ip.is_ipv6();
        self.range_lengths
            .range((v6, 0)..=(v6, u8::MAX))
            .rev()
            .find_map(|(&(_, len), _)| self.iocs.get(&(network_of(*ip, len), len)))
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

    /// Set per-country confidence boost values.
    ///
    /// Keys are ISO 3166-1 alpha-2 country codes (e.g. "RU", "CN").
    /// Values are signed adjustments applied to IOC confidence scores.
    pub fn set_country_confidence_boost(&mut self, boost: HashMap<String, i8>) {
        self.country_confidence_boost = boost;
    }

    /// Apply country-based confidence adjustment to an IOC.
    ///
    /// If the IOC's IP resolves to a country with a configured boost,
    /// the confidence is adjusted and clamped to 0-100.
    /// No-op if `country_code` is `None` or no boost is configured for that country.
    pub fn apply_country_boost(&self, ioc: &mut Ioc, country_code: Option<&str>) {
        let Some(cc) = country_code else { return };
        let Some(&boost) = self.country_confidence_boost.iter().find_map(|(k, v)| {
            if k.eq_ignore_ascii_case(cc) {
                Some(v)
            } else {
                None
            }
        }) else {
            return;
        };
        let adjusted = i16::from(ioc.confidence) + i16::from(boost);
        // Safety: clamp(0, 100) guarantees the value is non-negative and fits in u8.
        #[allow(clippy::cast_sign_loss)]
        let clamped = adjusted.clamp(0, 100) as u8;
        ioc.confidence = clamped;
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
            prefix_len: None,
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
        // Same IP, different feed - dedup replaces, doesn't add
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
            prefix_len: None,
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
            prefix_len: None,
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
            prefix_len: None,
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

    // ── Country confidence boost ───────────────────────────────────

    #[test]
    fn country_boost_increases_confidence() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.set_country_confidence_boost(HashMap::from([("RU".to_string(), 10)]));

        let mut entry = ioc("10.0.0.1", "feed-a", 50);
        engine.apply_country_boost(&mut entry, Some("RU"));
        assert_eq!(entry.confidence, 60);
    }

    #[test]
    fn country_boost_clamps_to_100() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.set_country_confidence_boost(HashMap::from([("CN".to_string(), 15)]));

        let mut entry = ioc("10.0.0.1", "feed-a", 95);
        engine.apply_country_boost(&mut entry, Some("CN"));
        assert_eq!(entry.confidence, 100);
    }

    #[test]
    fn country_boost_clamps_to_0() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.set_country_confidence_boost(HashMap::from([("US".to_string(), -20)]));

        let mut entry = ioc("10.0.0.1", "feed-a", 10);
        engine.apply_country_boost(&mut entry, Some("US"));
        assert_eq!(entry.confidence, 0);
    }

    #[test]
    fn no_boost_without_country() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.set_country_confidence_boost(HashMap::from([("RU".to_string(), 10)]));

        let mut entry = ioc("10.0.0.1", "feed-a", 50);
        engine.apply_country_boost(&mut entry, None);
        assert_eq!(entry.confidence, 50);
    }

    #[test]
    fn no_boost_for_unconfigured_country() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.set_country_confidence_boost(HashMap::from([("RU".to_string(), 10)]));

        let mut entry = ioc("10.0.0.1", "feed-a", 50);
        engine.apply_country_boost(&mut entry, Some("FR"));
        assert_eq!(entry.confidence, 50);
    }

    #[test]
    fn country_boost_case_insensitive() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.set_country_confidence_boost(HashMap::from([("RU".to_string(), 10)]));

        let mut entry = ioc("10.0.0.1", "feed-a", 50);
        engine.apply_country_boost(&mut entry, Some("ru"));
        assert_eq!(entry.confidence, 60);
    }

    fn range(net: &str, feed: &str, confidence: u8) -> Ioc {
        let (ip, prefix_len) = crate::threatintel::entity::parse_target(net).unwrap();
        Ioc {
            ip,
            prefix_len,
            ..ioc("0.0.0.0", feed, confidence)
        }
    }

    #[test]
    fn a_range_matches_every_address_it_holds() {
        let mut engine = ThreatIntelEngine::new(100);
        engine
            .add_ioc(range("198.51.100.0/24", "drop", 90))
            .unwrap();
        for ip in ["198.51.100.0", "198.51.100.77", "198.51.100.255"] {
            let found = engine.lookup(&ip.parse().unwrap()).unwrap();
            assert_eq!(found.target(), "198.51.100.0/24", "{ip}");
        }
        assert!(engine.lookup(&"198.51.101.1".parse().unwrap()).is_none());
        assert!(engine.lookup(&"2001:db8::1".parse().unwrap()).is_none());
    }

    #[test]
    fn the_address_wins_over_a_range_then_the_longest_range() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(range("10.0.0.0/8", "wide", 10)).unwrap();
        engine.add_ioc(range("10.1.0.0/16", "narrow", 20)).unwrap();
        engine.add_ioc(ioc("10.1.2.3", "host", 30)).unwrap();

        let at = |ip: &str| engine.lookup(&ip.parse().unwrap()).unwrap().feed_id.clone();
        assert_eq!(at("10.1.2.3"), "host");
        assert_eq!(at("10.1.2.4"), "narrow");
        assert_eq!(at("10.2.0.1"), "wide");
    }

    #[test]
    fn an_ipv6_range_matches_by_prefix() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(range("2001:db8::/32", "v6", 70)).unwrap();
        assert!(
            engine
                .lookup(&"2001:db8:ffff::1".parse().unwrap())
                .is_some()
        );
        assert!(engine.lookup(&"2001:db9::1".parse().unwrap()).is_none());
        // An IPv4 range length never applies to an IPv6 address.
        engine.add_ioc(range("32.0.0.0/8", "v4", 70)).unwrap();
        assert!(engine.lookup(&"2001:db9::1".parse().unwrap()).is_none());
    }

    #[test]
    fn a_range_and_its_first_address_are_two_entries() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(range("192.0.2.0/24", "net", 50)).unwrap();
        engine.add_ioc(ioc("192.0.2.0", "host", 50)).unwrap();
        assert_eq!(engine.ioc_count(), 2);
        engine.remove_ioc(&"192.0.2.0".parse().unwrap()).unwrap();
        assert_eq!(engine.ioc_count(), 1);
        assert_eq!(
            engine
                .lookup(&"192.0.2.0".parse().unwrap())
                .unwrap()
                .feed_id,
            "net"
        );
    }

    #[test]
    fn reload_replaces_ranges_too() {
        let mut engine = ThreatIntelEngine::new(100);
        engine.add_ioc(range("192.0.2.0/24", "old", 50)).unwrap();
        engine
            .reload(vec![range("203.0.113.0/25", "new", 50)])
            .unwrap();
        assert!(engine.lookup(&"192.0.2.1".parse().unwrap()).is_none());
        assert!(engine.lookup(&"203.0.113.1".parse().unwrap()).is_some());
        assert!(engine.lookup(&"203.0.113.200".parse().unwrap()).is_none());
    }

    #[test]
    fn a_range_off_its_first_address_is_refused() {
        let mut engine = ThreatIntelEngine::new(100);
        let mut bad = range("192.0.2.0/24", "f", 50);
        bad.ip = "192.0.2.9".parse().unwrap();
        assert!(engine.add_ioc(bad.clone()).is_err());
        assert!(engine.reload(vec![bad]).is_err());
    }
}
