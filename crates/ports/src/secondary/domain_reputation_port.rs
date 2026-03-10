use domain::dns::entity::{DomainReputation, ReputationFactor, ReputationStats};

/// Secondary port for querying and updating domain reputation data.
pub trait DomainReputationPort: Send + Sync {
    /// Get the reputation entry for a specific domain.
    fn get_reputation(&self, domain: &str) -> Option<DomainReputation>;

    /// Get the effective score for a domain (with time decay).
    fn get_score(&self, domain: &str) -> Option<f64>;

    /// Update reputation by adding a factor.
    fn update_reputation(&self, domain: &str, factor: ReputationFactor);

    /// List domains above a minimum score threshold.
    fn list_high_risk(&self, min_score: f64) -> Vec<(DomainReputation, f64)>;

    /// Get all reputations paginated.
    fn list_all(&self, page: usize, page_size: usize) -> Vec<(DomainReputation, f64)>;

    /// Aggregated statistics.
    fn stats(&self) -> ReputationStats;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct InMemoryDomainReputation {
        entries: Mutex<HashMap<String, DomainReputation>>,
    }

    impl InMemoryDomainReputation {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }
    }

    impl DomainReputationPort for InMemoryDomainReputation {
        fn get_reputation(&self, domain: &str) -> Option<DomainReputation> {
            self.entries.lock().unwrap().get(domain).cloned()
        }

        fn get_score(&self, domain: &str) -> Option<f64> {
            self.entries
                .lock()
                .unwrap()
                .get(domain)
                .map(DomainReputation::compute_score)
        }

        fn update_reputation(&self, domain: &str, factor: ReputationFactor) {
            let mut entries = self.entries.lock().unwrap();
            let entry = entries
                .entry(domain.to_string())
                .or_insert_with(|| DomainReputation {
                    domain: domain.to_string(),
                    factors: Vec::new(),
                    first_seen: 0,
                    last_seen: 0,
                    total_connections: 0,
                });
            entry.factors.push(factor);
        }

        fn list_high_risk(&self, min_score: f64) -> Vec<(DomainReputation, f64)> {
            self.entries
                .lock()
                .unwrap()
                .values()
                .filter_map(|r| {
                    let score = r.compute_score();
                    if score >= min_score {
                        Some((r.clone(), score))
                    } else {
                        None
                    }
                })
                .collect()
        }

        fn list_all(&self, page: usize, page_size: usize) -> Vec<(DomainReputation, f64)> {
            let entries = self.entries.lock().unwrap();
            let mut all: Vec<(DomainReputation, f64)> = entries
                .values()
                .map(|r| (r.clone(), r.compute_score()))
                .collect();
            all.sort_by(|a, b| a.0.domain.cmp(&b.0.domain));
            all.into_iter()
                .skip(page * page_size)
                .take(page_size)
                .collect()
        }

        fn stats(&self) -> ReputationStats {
            let entries = self.entries.lock().unwrap();
            let high_risk = entries
                .values()
                .filter(|r| r.compute_score() >= 0.8)
                .count();
            ReputationStats {
                tracked_domains: entries.len(),
                high_risk_count: high_risk,
                auto_blocked_count: 0,
            }
        }
    }

    #[test]
    fn update_and_get_reputation() {
        let store = InMemoryDomainReputation::new();
        store.update_reputation(
            "evil.com",
            ReputationFactor::BlocklistHit {
                list_name: "test-list".to_string(),
            },
        );

        let rep = store.get_reputation("evil.com").unwrap();
        assert_eq!(rep.domain, "evil.com");
        assert_eq!(rep.factors.len(), 1);
    }

    #[test]
    fn get_score_returns_value() {
        let store = InMemoryDomainReputation::new();
        assert!(store.get_score("unknown.com").is_none());

        store.update_reputation("bad.com", ReputationFactor::HighEntropy { entropy: 4.5 });
        let rep_score = store.get_score("bad.com").unwrap();
        assert!(rep_score > 0.0);
    }

    #[test]
    fn list_high_risk_filters() {
        let store = InMemoryDomainReputation::new();
        // BlocklistHit has weight 0.9 → score 0.9
        store.update_reputation(
            "dangerous.com",
            ReputationFactor::BlocklistHit {
                list_name: "blocklist".to_string(),
            },
        );
        // HighEntropy has weight 0.3 → score 0.3
        store.update_reputation("benign.com", ReputationFactor::HighEntropy { entropy: 3.0 });

        let high_risk = store.list_high_risk(0.5);
        assert_eq!(high_risk.len(), 1);
        assert_eq!(high_risk[0].0.domain, "dangerous.com");
    }

    #[test]
    fn stats_reflect_state() {
        let store = InMemoryDomainReputation::new();
        let stats = store.stats();
        assert_eq!(stats.tracked_domains, 0);
        assert_eq!(stats.high_risk_count, 0);

        store.update_reputation(
            "tracked.com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
        );
        let stats = store.stats();
        assert_eq!(stats.tracked_domains, 1);
        assert_eq!(stats.high_risk_count, 1);
    }
}
