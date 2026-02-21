use std::collections::HashMap;

use super::entity::{DomainReputation, ReputationConfig, ReputationFactor, ReputationStats};

/// Domain reputation engine: tracks per-domain risk factors, computes
/// scores with time decay, and provides LRU eviction at capacity.
pub struct DomainReputationEngine {
    entries: HashMap<String, DomainReputation>,
    config: ReputationConfig,
    auto_blocked_count: u64,
}

impl DomainReputationEngine {
    pub fn new(config: ReputationConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
            auto_blocked_count: 0,
        }
    }

    /// Update reputation for a domain by adding/replacing a factor.
    ///
    /// If a factor with the same `kind_key()` already exists, it is replaced.
    /// Returns the new effective score.
    pub fn update(&mut self, domain: &str, factor: ReputationFactor, now_ns: u64) -> f64 {
        let entry = self
            .entries
            .entry(domain.to_lowercase())
            .or_insert_with(|| DomainReputation {
                domain: domain.to_lowercase(),
                factors: Vec::new(),
                first_seen: now_ns,
                last_seen: now_ns,
                total_connections: 0,
            });

        entry.last_seen = now_ns;
        entry.total_connections += 1;

        // Dedup: replace factor with same kind_key
        let key = factor.kind_key();
        entry.factors.retain(|f| f.kind_key() != key);
        entry.factors.push(factor);

        let score = entry.effective_score(now_ns, self.config.half_life_ns());

        // LRU eviction if at capacity
        if self.entries.len() > self.config.max_tracked_domains {
            self.evict_lowest(now_ns);
        }

        score
    }

    /// Record a connection without adding a new factor.
    pub fn record_connection(&mut self, domain: &str, now_ns: u64) {
        if let Some(entry) = self.entries.get_mut(&domain.to_lowercase()) {
            entry.last_seen = now_ns;
            entry.total_connections += 1;
        }
    }

    /// Get reputation for a specific domain.
    pub fn get(&self, domain: &str) -> Option<&DomainReputation> {
        self.entries.get(&domain.to_lowercase())
    }

    /// List domains with effective score above `min_score`, sorted by score descending.
    pub fn list_high_risk(&self, min_score: f64, now_ns: u64) -> Vec<(&DomainReputation, f64)> {
        let half_life = self.config.half_life_ns();
        let mut results: Vec<(&DomainReputation, f64)> = self
            .entries
            .values()
            .filter_map(|rep| {
                let score = rep.effective_score(now_ns, half_life);
                if score >= min_score {
                    Some((rep, score))
                } else {
                    None
                }
            })
            .collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Get all entries paginated with effective scores.
    pub fn list_all(
        &self,
        page: usize,
        page_size: usize,
        now_ns: u64,
    ) -> Vec<(&DomainReputation, f64)> {
        let half_life = self.config.half_life_ns();
        let mut entries: Vec<(&DomainReputation, f64)> = self
            .entries
            .values()
            .map(|rep| (rep, rep.effective_score(now_ns, half_life)))
            .collect();
        entries.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        entries
            .into_iter()
            .skip(page * page_size)
            .take(page_size)
            .collect()
    }

    /// Get domains that exceed the auto-block threshold.
    pub fn get_auto_block_candidates(&self, now_ns: u64) -> Vec<&str> {
        if !self.config.auto_block_enabled {
            return Vec::new();
        }
        let half_life = self.config.half_life_ns();
        self.entries
            .values()
            .filter(|rep| {
                rep.effective_score(now_ns, half_life) >= self.config.auto_block_threshold
            })
            .map(|rep| rep.domain.as_str())
            .collect()
    }

    /// Increment the auto-blocked counter.
    pub fn record_auto_block(&mut self) {
        self.auto_blocked_count += 1;
    }

    /// Current statistics.
    pub fn stats(&self, now_ns: u64) -> ReputationStats {
        let half_life = self.config.half_life_ns();
        let high_risk_count = self
            .entries
            .values()
            .filter(|rep| {
                rep.effective_score(now_ns, half_life) >= self.config.auto_block_threshold
            })
            .count();
        ReputationStats {
            tracked_domains: self.entries.len(),
            high_risk_count,
            auto_blocked_count: self.auto_blocked_count,
        }
    }

    /// Number of tracked domains.
    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }

    /// Auto-block threshold from config.
    pub fn auto_block_threshold(&self) -> f64 {
        self.config.auto_block_threshold
    }

    /// Evict the entry with the lowest effective score.
    fn evict_lowest(&mut self, now_ns: u64) {
        let half_life = self.config.half_life_ns();
        if let Some(worst_domain) = self
            .entries
            .iter()
            .min_by(|(_, a), (_, b)| {
                let sa = a.effective_score(now_ns, half_life);
                let sb = b.effective_score(now_ns, half_life);
                sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&worst_domain);
        }
    }
}

// ── Entropy calculation ─────────────────────────────────────────────

/// Compute Shannon entropy of the second-level domain label.
///
/// For `sub.example.com`, computes entropy of `example`.
/// High entropy (>3.5) is a DGA indicator.
pub fn domain_entropy(domain: &str) -> f64 {
    let label = extract_second_level_label(domain);
    if label.is_empty() {
        return 0.0;
    }
    shannon_entropy(label)
}

/// Shannon entropy of a string (bits per character).
fn shannon_entropy(s: &str) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }

    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// Extract the second-level domain label.
///
/// `sub.example.com` → `example`
/// `example.com` → `example`
/// `com` → `com`
fn extract_second_level_label(domain: &str) -> &str {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2]
    } else if parts.len() == 1 {
        parts[0]
    } else {
        ""
    }
}

/// Entropy threshold above which a domain is considered DGA-like.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 3.5;

/// Short TTL threshold in seconds (fast-flux indicator).
pub const SHORT_TTL_THRESHOLD: u64 = 60;

/// Minimum resolutions before short-TTL factor is added.
pub const SHORT_TTL_MIN_RESOLUTIONS: u64 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u64) -> u64 {
        secs * 1_000_000_000
    }

    fn test_config() -> ReputationConfig {
        ReputationConfig {
            enabled: true,
            max_tracked_domains: 100,
            auto_block_threshold: 0.8,
            auto_block_enabled: true,
            auto_block_ttl_secs: 3600,
            decay_half_life_hours: 24,
        }
    }

    // ── Score computation ───────────────────────────────────────────

    #[test]
    fn single_factor_score() {
        let rep = DomainReputation {
            domain: "bad.com".to_string(),
            factors: vec![ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            }],
            first_seen: 0,
            last_seen: 0,
            total_connections: 1,
        };
        assert!((rep.compute_score() - 0.9).abs() < 0.001);
    }

    #[test]
    fn multiple_factors_probabilistic_or() {
        let rep = DomainReputation {
            domain: "dga.com".to_string(),
            factors: vec![
                ReputationFactor::HighEntropy { entropy: 4.0 },
                ReputationFactor::ShortTtl { avg_ttl: 30 },
            ],
            first_seen: 0,
            last_seen: 0,
            total_connections: 1,
        };
        // 1 - (1-0.3)*(1-0.2) = 1 - 0.56 = 0.44
        assert!((rep.compute_score() - 0.44).abs() < 0.001);
    }

    #[test]
    fn empty_factors_score_zero() {
        let rep = DomainReputation {
            domain: "clean.com".to_string(),
            factors: vec![],
            first_seen: 0,
            last_seen: 0,
            total_connections: 1,
        };
        assert_eq!(rep.compute_score(), 0.0);
    }

    // ── Score decay ─────────────────────────────────────────────────

    #[test]
    fn score_decays_after_half_life() {
        let rep = DomainReputation {
            domain: "old.com".to_string(),
            factors: vec![ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            }],
            first_seen: 0,
            last_seen: 0,
            total_connections: 1,
        };
        let half_life = 24 * 3600 * 1_000_000_000u64; // 24h in ns
        let base = rep.compute_score();

        // After exactly one half-life: score should be ~half
        let decayed = rep.effective_score(half_life, half_life);
        assert!((decayed - base / 2.0).abs() < 0.01);

        // At t=0: no decay
        let no_decay = rep.effective_score(0, half_life);
        assert!((no_decay - base).abs() < 0.001);
    }

    // ── Engine update + dedup ───────────────────────────────────────

    #[test]
    fn update_adds_factor() {
        let mut engine = DomainReputationEngine::new(test_config());
        engine.update(
            "bad.com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
            ts(0),
        );
        let rep = engine.get("bad.com").unwrap();
        assert_eq!(rep.factors.len(), 1);
        assert_eq!(rep.total_connections, 1);
    }

    #[test]
    fn update_deduplicates_same_factor_kind() {
        let mut engine = DomainReputationEngine::new(test_config());
        engine.update(
            "bad.com",
            ReputationFactor::BlocklistHit {
                list_name: "list-a".to_string(),
            },
            ts(0),
        );
        engine.update(
            "bad.com",
            ReputationFactor::BlocklistHit {
                list_name: "list-b".to_string(),
            },
            ts(10),
        );
        let rep = engine.get("bad.com").unwrap();
        assert_eq!(rep.factors.len(), 1);
        assert_eq!(rep.total_connections, 2);
        // Should have the latest value
        if let ReputationFactor::BlocklistHit { list_name } = &rep.factors[0] {
            assert_eq!(list_name, "list-b");
        } else {
            panic!("expected BlocklistHit");
        }
    }

    #[test]
    fn update_keeps_different_factor_kinds() {
        let mut engine = DomainReputationEngine::new(test_config());
        engine.update(
            "bad.com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
            ts(0),
        );
        engine.update(
            "bad.com",
            ReputationFactor::HighEntropy { entropy: 4.0 },
            ts(10),
        );
        let rep = engine.get("bad.com").unwrap();
        assert_eq!(rep.factors.len(), 2);
    }

    // ── LRU eviction ────────────────────────────────────────────────

    #[test]
    fn lru_eviction_at_capacity() {
        let config = ReputationConfig {
            max_tracked_domains: 3,
            ..test_config()
        };
        let mut engine = DomainReputationEngine::new(config);

        // Add 3 entries, one with high score
        engine.update(
            "high.com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
            ts(0),
        );
        engine.update(
            "low1.com",
            ReputationFactor::FrequentQueries { rate_per_min: 5.0 },
            ts(0),
        );
        engine.update(
            "low2.com",
            ReputationFactor::FrequentQueries { rate_per_min: 5.0 },
            ts(0),
        );
        assert_eq!(engine.tracked_count(), 3);

        // Adding a 4th triggers eviction of lowest score
        engine.update(
            "new.com",
            ReputationFactor::CtiMatch {
                feed_name: "test".to_string(),
                threat_type: "c2".to_string(),
            },
            ts(0),
        );
        // Should still be 3 (one evicted)
        assert_eq!(engine.tracked_count(), 3);
        // high.com should survive (0.9 score)
        assert!(engine.get("high.com").is_some());
    }

    // ── High-risk listing ───────────────────────────────────────────

    #[test]
    fn list_high_risk_filters_by_score() {
        let mut engine = DomainReputationEngine::new(test_config());
        engine.update(
            "high.com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
            ts(0),
        );
        engine.update(
            "low.com",
            ReputationFactor::FrequentQueries { rate_per_min: 5.0 },
            ts(0),
        );

        let high = engine.list_high_risk(0.5, ts(0));
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].0.domain, "high.com");
    }

    // ── Auto-block ──────────────────────────────────────────────────

    #[test]
    fn auto_block_candidates() {
        let mut engine = DomainReputationEngine::new(test_config());
        engine.update(
            "bad.com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
            ts(0),
        );
        engine.update(
            "ok.com",
            ReputationFactor::FrequentQueries { rate_per_min: 5.0 },
            ts(0),
        );

        let candidates = engine.get_auto_block_candidates(ts(0));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0], "bad.com");
    }

    #[test]
    fn auto_block_disabled_returns_empty() {
        let config = ReputationConfig {
            auto_block_enabled: false,
            ..test_config()
        };
        let mut engine = DomainReputationEngine::new(config);
        engine.update(
            "bad.com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
            ts(0),
        );
        assert!(engine.get_auto_block_candidates(ts(0)).is_empty());
    }

    // ── Entropy ─────────────────────────────────────────────────────

    #[test]
    fn entropy_legitimate_domain() {
        // "google" has relatively low entropy
        let e = domain_entropy("www.google.com");
        assert!(e < HIGH_ENTROPY_THRESHOLD);
    }

    #[test]
    fn entropy_dga_like_domain() {
        // Random-looking string has high entropy
        let e = domain_entropy("sub.asdkj3nf8qwn2lksd.com");
        assert!(e > HIGH_ENTROPY_THRESHOLD);
    }

    #[test]
    fn entropy_empty_domain() {
        assert_eq!(domain_entropy(""), 0.0);
    }

    #[test]
    fn entropy_single_label() {
        let e = domain_entropy("localhost");
        assert!(e > 0.0);
    }

    // ── Stats ───────────────────────────────────────────────────────

    #[test]
    fn stats_tracking() {
        let mut engine = DomainReputationEngine::new(test_config());
        engine.update(
            "bad.com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
            ts(0),
        );
        engine.record_auto_block();

        let stats = engine.stats(ts(0));
        assert_eq!(stats.tracked_domains, 1);
        assert_eq!(stats.high_risk_count, 1);
        assert_eq!(stats.auto_blocked_count, 1);
    }

    // ── Case insensitive lookup ─────────────────────────────────────

    #[test]
    fn case_insensitive_lookup() {
        let mut engine = DomainReputationEngine::new(test_config());
        engine.update(
            "Bad.Com",
            ReputationFactor::BlocklistHit {
                list_name: "test".to_string(),
            },
            ts(0),
        );
        assert!(engine.get("bad.com").is_some());
        assert!(engine.get("BAD.COM").is_some());
    }
}
