use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::ids::entity::SamplingMode;

use super::entity::{BlacklistEntry, EnforcementAction, IpsPolicy, WhitelistEntry};
use super::error::IpsError;

/// Mask an IPv4 address to a /24 network base.
fn mask_v4_to_24(ip: std::net::Ipv4Addr) -> std::net::Ipv4Addr {
    let bits = u32::from(ip) & 0xFFFF_FF00;
    std::net::Ipv4Addr::from(bits)
}

/// Mask an IPv6 address to a /48 network base.
fn mask_v6_to_48(ip: std::net::Ipv6Addr) -> std::net::Ipv6Addr {
    let bits = u128::from(ip) & (u128::MAX << 80);
    std::net::Ipv6Addr::from(bits)
}

/// IPS engine: manages an in-memory IP blacklist with detection counting,
/// threshold-based auto-blacklisting, and TTL-based expiration.
///
/// The blacklist is ephemeral (lost on restart) by design.
#[derive(Debug, Clone)]
pub struct IpsEngine {
    blacklist: Arc<Mutex<HashMap<IpAddr, BlacklistEntry>>>,
    detection_counts: Arc<Mutex<HashMap<IpAddr, (u32, Instant)>>>,
    whitelist: Vec<WhitelistEntry>,
    policy: IpsPolicy,
    sampling: SamplingMode,
    /// Active /24 (v4) or /48 (v6) subnet blocks with expiry tracking.
    subnet_blocks: Arc<Mutex<HashMap<(IpAddr, u8), Instant>>>,
}

impl IpsEngine {
    pub fn new(policy: IpsPolicy) -> Self {
        Self {
            blacklist: Arc::new(Mutex::new(HashMap::new())),
            detection_counts: Arc::new(Mutex::new(HashMap::new())),
            whitelist: Vec::new(),
            policy,
            sampling: SamplingMode::default(),
            subnet_blocks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if an IP is currently blacklisted. Whitelisted IPs always
    /// return `false`. Expired entries are auto-removed and return `false`.
    pub fn is_blacklisted(&self, ip: IpAddr) -> bool {
        if self.is_whitelisted(ip) {
            return false;
        }
        let mut blacklist = self
            .blacklist
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = blacklist.get(&ip) {
            if entry.is_expired() {
                blacklist.remove(&ip);
                return false;
            }
            return true;
        }
        false
    }

    /// Record a detection event for the given IP.
    ///
    /// Delegates to [`record_detection_with_country`] with `None`.
    pub fn record_detection(&self, ip: IpAddr) -> Vec<EnforcementAction> {
        self.record_detection_with_country(ip, None)
    }

    /// Record a detection event for the given IP with an optional country code.
    ///
    /// Whitelisted IPs are skipped entirely (returns `None`).
    /// Increments the detection counter and returns a `BlacklistIp`
    /// enforcement action if the threshold is reached.
    ///
    /// When `src_country` matches a key in `policy.country_thresholds`,
    /// that per-country value is used instead of `auto_blacklist_threshold`.
    ///
    /// Detection counts reset if the time since the first detection in
    /// the current window exceeds `max_blacklist_duration`.
    pub fn record_detection_with_country(
        &self,
        ip: IpAddr,
        src_country: Option<&str>,
    ) -> Vec<EnforcementAction> {
        if self.is_whitelisted(ip) {
            return Vec::new();
        }
        let now = Instant::now();

        let mut detection_counts = self
            .detection_counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        let (count, first_seen) = detection_counts.entry(ip).or_insert((0, now));

        // Reset window if expired
        if now.duration_since(*first_seen) >= self.policy.max_blacklist_duration {
            *count = 0;
            *first_seen = now;
        }

        *count += 1;

        let threshold = src_country
            .and_then(|cc| {
                self.policy
                    .country_thresholds
                    .as_ref()
                    .and_then(|ct| ct.get(cc).copied())
            })
            .unwrap_or(self.policy.auto_blacklist_threshold);

        if *count >= threshold {
            // Remove from detection counts since we're blacklisting
            detection_counts.remove(&ip);
            // Drop the detection_counts lock before calling add_to_blacklist
            drop(detection_counts);

            // Auto-blacklist (ignore error if already blacklisted or full)
            let _ = self.add_to_blacklist(
                ip,
                "auto-blacklisted: detection threshold reached".to_string(),
                true,
                self.policy.max_blacklist_duration,
            );

            let ttl = self.policy.max_blacklist_duration;
            let mut actions = vec![EnforcementAction::BlacklistIp { ip, ttl }];

            // Also emit BlockSubnet if this IP's country is in country_thresholds
            let is_country_hit = src_country.is_some_and(|cc| {
                self.policy
                    .country_thresholds
                    .as_ref()
                    .is_some_and(|ct| ct.contains_key(cc))
            });
            if is_country_hit {
                let (subnet_addr, prefix_len) = match ip {
                    IpAddr::V4(v4) => (IpAddr::V4(mask_v4_to_24(v4)), 24),
                    IpAddr::V6(v6) => (IpAddr::V6(mask_v6_to_48(v6)), 48),
                };
                let key = (subnet_addr, prefix_len);
                let mut subnet_blocks = self
                    .subnet_blocks
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if let std::collections::hash_map::Entry::Vacant(e) = subnet_blocks.entry(key) {
                    e.insert(now);
                    actions.push(EnforcementAction::BlockSubnet {
                        addr: subnet_addr,
                        prefix_len,
                        ttl,
                    });
                }
            }

            actions
        } else {
            Vec::new()
        }
    }

    /// Add an IP to the blacklist with the given reason and TTL.
    /// Returns an error if the IP is whitelisted, already blacklisted, or
    /// the blacklist is full.
    pub fn add_to_blacklist(
        &self,
        ip: IpAddr,
        reason: String,
        auto_generated: bool,
        ttl: Duration,
    ) -> Result<(), IpsError> {
        if self.is_whitelisted(ip) {
            return Err(IpsError::Whitelisted { ip: ip.to_string() });
        }
        let mut blacklist = self
            .blacklist
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if blacklist.contains_key(&ip) {
            return Err(IpsError::AlreadyBlacklisted { ip: ip.to_string() });
        }
        if blacklist.len() >= self.policy.max_blacklist_size {
            return Err(IpsError::BlacklistFull);
        }

        let now = Instant::now();
        blacklist.insert(
            ip,
            BlacklistEntry {
                ip,
                reason,
                auto_generated,
                added_at: now,
                ttl,
                detection_count: 1,
                last_detected_at: now,
            },
        );
        Ok(())
    }

    /// Remove an IP from the blacklist.
    pub fn remove_from_blacklist(&self, ip: &IpAddr) -> Result<(), IpsError> {
        let mut blacklist = self
            .blacklist
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if blacklist.remove(ip).is_none() {
            return Err(IpsError::NotBlacklisted { ip: ip.to_string() });
        }
        Ok(())
    }

    /// Read-only snapshot of the blacklist entries.
    pub fn blacklist_entries(&self) -> HashMap<IpAddr, BlacklistEntry> {
        self.blacklist
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Current number of blacklisted IPs.
    pub fn blacklist_size(&self) -> usize {
        self.blacklist
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Remove all blacklist entries.
    pub fn clear_blacklist(&self) {
        self.blacklist
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.detection_counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// Scan for and remove expired entries. Returns `UnblacklistIp` and
    /// `UnblockSubnet` actions for each removed entry.
    pub fn cleanup_expired(&self) -> Vec<EnforcementAction> {
        let mut blacklist = self
            .blacklist
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let expired_ips: Vec<IpAddr> = blacklist
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(ip, _)| *ip)
            .collect();

        let mut actions = Vec::with_capacity(expired_ips.len());
        for ip in expired_ips {
            blacklist.remove(&ip);
            actions.push(EnforcementAction::UnblacklistIp { ip });
        }
        drop(blacklist);

        // Expire subnet blocks (same TTL as max_blacklist_duration)
        let mut subnet_blocks = self
            .subnet_blocks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let expired_subnets: Vec<(IpAddr, u8)> = subnet_blocks
            .iter()
            .filter(|(_, added_at)| added_at.elapsed() >= self.policy.max_blacklist_duration)
            .map(|(&(addr, prefix), _)| (addr, prefix))
            .collect();

        for (addr, prefix_len) in expired_subnets {
            subnet_blocks.remove(&(addr, prefix_len));
            actions.push(EnforcementAction::UnblockSubnet { addr, prefix_len });
        }

        actions
    }

    /// Check if an IP matches any whitelist entry.
    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.iter().any(|entry| entry.matches(ip))
    }

    /// Replace the whitelist (used during hot-reload).
    pub fn set_whitelist(&mut self, entries: Vec<WhitelistEntry>) {
        self.whitelist = entries;
    }

    /// Read-only access to the whitelist entries.
    pub fn whitelist_entries(&self) -> &[WhitelistEntry] {
        &self.whitelist
    }

    /// Update the policy at runtime (e.g., during hot-reload).
    pub fn set_policy(&mut self, policy: IpsPolicy) {
        self.policy = policy;
    }

    /// Read-only access to the current policy.
    pub fn policy(&self) -> &IpsPolicy {
        &self.policy
    }

    /// Set the sampling mode for detection processing.
    pub fn set_sampling(&mut self, mode: SamplingMode) {
        self.sampling = mode;
    }

    /// Read-only access to the current sampling mode.
    pub fn sampling(&self) -> &SamplingMode {
        &self.sampling
    }

    /// Check whether a packet should be processed based on the sampling mode.
    /// Call this before `record_detection` to apply sampling.
    pub fn should_process(&self, src_ip: u32, dst_ip: u32) -> bool {
        self.sampling.should_process(src_ip, dst_ip)
    }
}

impl Default for IpsEngine {
    fn default() -> Self {
        Self::new(IpsPolicy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn test_policy() -> IpsPolicy {
        IpsPolicy {
            max_blacklist_duration: Duration::from_secs(60),
            auto_blacklist_threshold: 3,
            max_blacklist_size: 100,
            country_thresholds: None,
        }
    }

    // ── new / default ────────────────────────────────────────────

    #[test]
    fn new_engine_is_empty() {
        let engine = IpsEngine::new(test_policy());
        assert_eq!(engine.blacklist_size(), 0);
        assert!(engine.blacklist_entries().is_empty());
    }

    #[test]
    fn default_uses_default_policy() {
        let engine = IpsEngine::default();
        assert_eq!(
            engine.policy().max_blacklist_duration,
            Duration::from_secs(3600)
        );
        assert_eq!(engine.policy().auto_blacklist_threshold, 3);
    }

    // ── is_blacklisted ───────────────────────────────────────────

    #[test]
    fn is_blacklisted_false_when_empty() {
        let mut engine = IpsEngine::new(test_policy());
        assert!(!engine.is_blacklisted(ip(10, 0, 0, 1)));
    }

    #[test]
    fn is_blacklisted_true_after_add() {
        let mut engine = IpsEngine::new(test_policy());
        engine
            .add_to_blacklist(
                ip(10, 0, 0, 1),
                "test".into(),
                false,
                Duration::from_secs(60),
            )
            .unwrap();
        assert!(engine.is_blacklisted(ip(10, 0, 0, 1)));
    }

    #[test]
    fn is_blacklisted_removes_expired() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        // Insert with a very short TTL
        engine
            .add_to_blacklist(addr, "test".into(), false, Duration::from_millis(1))
            .unwrap();
        assert_eq!(engine.blacklist_size(), 1);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(5));

        assert!(!engine.is_blacklisted(addr));
        assert_eq!(engine.blacklist_size(), 0);
    }

    // ── add_to_blacklist ──────────────────────────────────────────

    #[test]
    fn add_to_blacklist_succeeds() {
        let mut engine = IpsEngine::new(test_policy());
        let result = engine.add_to_blacklist(
            ip(10, 0, 0, 1),
            "attack".into(),
            true,
            Duration::from_secs(60),
        );
        assert!(result.is_ok());
        assert_eq!(engine.blacklist_size(), 1);
    }

    #[test]
    fn add_duplicate_fails() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        engine
            .add_to_blacklist(addr, "first".into(), true, Duration::from_secs(60))
            .unwrap();
        let result = engine.add_to_blacklist(addr, "second".into(), true, Duration::from_secs(60));
        assert!(matches!(result, Err(IpsError::AlreadyBlacklisted { .. })));
    }

    #[test]
    fn add_when_full_fails() {
        let policy = IpsPolicy {
            max_blacklist_size: 2,
            ..test_policy()
        };
        let mut engine = IpsEngine::new(policy);
        engine
            .add_to_blacklist(ip(10, 0, 0, 1), "a".into(), true, Duration::from_secs(60))
            .unwrap();
        engine
            .add_to_blacklist(ip(10, 0, 0, 2), "b".into(), true, Duration::from_secs(60))
            .unwrap();
        let result =
            engine.add_to_blacklist(ip(10, 0, 0, 3), "c".into(), true, Duration::from_secs(60));
        assert!(matches!(result, Err(IpsError::BlacklistFull)));
    }

    // ── remove_from_blacklist ─────────────────────────────────────

    #[test]
    fn remove_succeeds() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        engine
            .add_to_blacklist(addr, "test".into(), true, Duration::from_secs(60))
            .unwrap();
        engine.remove_from_blacklist(&addr).unwrap();
        assert_eq!(engine.blacklist_size(), 0);
    }

    #[test]
    fn remove_nonexistent_fails() {
        let mut engine = IpsEngine::new(test_policy());
        let result = engine.remove_from_blacklist(&ip(10, 0, 0, 1));
        assert!(matches!(result, Err(IpsError::NotBlacklisted { .. })));
    }

    // ── clear_blacklist ──────────────────────────────────────────

    #[test]
    fn clear_removes_all() {
        let mut engine = IpsEngine::new(test_policy());
        engine
            .add_to_blacklist(ip(10, 0, 0, 1), "a".into(), true, Duration::from_secs(60))
            .unwrap();
        engine
            .add_to_blacklist(ip(10, 0, 0, 2), "b".into(), true, Duration::from_secs(60))
            .unwrap();
        engine.clear_blacklist();
        assert_eq!(engine.blacklist_size(), 0);
    }

    // ── record_detection ─────────────────────────────────────────

    #[test]
    fn record_detection_under_threshold() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        assert!(engine.record_detection(addr).is_empty());
        assert!(engine.record_detection(addr).is_empty());
        assert_eq!(engine.blacklist_size(), 0);
    }

    #[test]
    fn record_detection_at_threshold_triggers_blacklist() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        assert!(engine.record_detection(addr).is_empty()); // 1
        assert!(engine.record_detection(addr).is_empty()); // 2
        let actions = engine.record_detection(addr); // 3 = threshold
        assert_eq!(actions.len(), 1);
        assert_eq!(
            actions[0],
            EnforcementAction::BlacklistIp {
                ip: addr,
                ttl: Duration::from_secs(60),
            }
        );
        assert!(engine.is_blacklisted(addr));
    }

    #[test]
    fn record_detection_resets_after_window() {
        let policy = IpsPolicy {
            max_blacklist_duration: Duration::from_millis(1),
            auto_blacklist_threshold: 3,
            max_blacklist_size: 100,
            country_thresholds: None,
        };
        let mut engine = IpsEngine::new(policy);
        let addr = ip(10, 0, 0, 1);

        // Record 2 detections
        engine.record_detection(addr);
        engine.record_detection(addr);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(5));

        // Counter should reset, so 1 detection after reset
        assert!(engine.record_detection(addr).is_empty());
    }

    // ── cleanup_expired ──────────────────────────────────────────

    #[test]
    fn cleanup_expired_removes_and_returns_actions() {
        let mut engine = IpsEngine::new(test_policy());
        let addr1 = ip(10, 0, 0, 1);
        let addr2 = ip(10, 0, 0, 2);

        engine
            .add_to_blacklist(addr1, "old".into(), true, Duration::from_millis(1))
            .unwrap();
        engine
            .add_to_blacklist(addr2, "fresh".into(), true, Duration::from_secs(3600))
            .unwrap();

        std::thread::sleep(Duration::from_millis(5));

        let actions = engine.cleanup_expired();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], EnforcementAction::UnblacklistIp { ip: addr1 });
        assert_eq!(engine.blacklist_size(), 1);
        assert!(engine.blacklist_entries().contains_key(&addr2));
    }

    #[test]
    fn cleanup_no_expired_returns_empty() {
        let mut engine = IpsEngine::new(test_policy());
        engine
            .add_to_blacklist(ip(10, 0, 0, 1), "x".into(), true, Duration::from_secs(3600))
            .unwrap();
        let actions = engine.cleanup_expired();
        assert!(actions.is_empty());
    }

    // ── policy ───────────────────────────────────────────────────

    #[test]
    fn record_detection_country_threshold_lower() {
        let mut ct = std::collections::HashMap::new();
        ct.insert("RU".to_string(), 1_u32);
        let policy = IpsPolicy {
            auto_blacklist_threshold: 3,
            country_thresholds: Some(ct),
            ..test_policy()
        };
        let mut engine = IpsEngine::new(policy);
        let addr = ip(10, 0, 0, 1);
        // RU threshold is 1 -> blacklist after first detection + subnet block
        let actions = engine.record_detection_with_country(addr, Some("RU"));
        assert_eq!(actions.len(), 2);
        assert!(matches!(actions[0], EnforcementAction::BlacklistIp { .. }));
        assert!(matches!(actions[1], EnforcementAction::BlockSubnet { .. }));
        assert!(engine.is_blacklisted(addr));
    }

    #[test]
    fn record_detection_unknown_country_uses_global() {
        let mut ct = std::collections::HashMap::new();
        ct.insert("RU".to_string(), 1_u32);
        let policy = IpsPolicy {
            auto_blacklist_threshold: 3,
            country_thresholds: Some(ct),
            ..test_policy()
        };
        let mut engine = IpsEngine::new(policy);
        let addr = ip(10, 0, 0, 2);
        // FR not in map -> uses global threshold of 3
        assert!(
            engine
                .record_detection_with_country(addr, Some("FR"))
                .is_empty()
        );
        assert!(
            engine
                .record_detection_with_country(addr, Some("FR"))
                .is_empty()
        );
        let actions = engine.record_detection_with_country(addr, Some("FR"));
        assert!(!actions.is_empty());
    }

    #[test]
    fn set_policy_updates() {
        let mut engine = IpsEngine::new(test_policy());
        let new_policy = IpsPolicy {
            max_blacklist_duration: Duration::from_secs(120),
            auto_blacklist_threshold: 5,
            max_blacklist_size: 500,
            country_thresholds: None,
        };
        engine.set_policy(new_policy.clone());
        assert_eq!(engine.policy().auto_blacklist_threshold, 5);
        assert_eq!(engine.policy().max_blacklist_size, 500);
    }

    #[test]
    fn blacklist_entries_accessor() {
        let mut engine = IpsEngine::new(test_policy());
        engine
            .add_to_blacklist(
                ip(10, 0, 0, 1),
                "test".into(),
                false,
                Duration::from_secs(60),
            )
            .unwrap();
        let entries = engine.blacklist_entries();
        assert_eq!(entries.len(), 1);
        assert!(entries.contains_key(&ip(10, 0, 0, 1)));
        assert!(!entries[&ip(10, 0, 0, 1)].auto_generated);
    }

    // ── whitelist ─────────────────────────────────────────────────

    fn wl_exact(a: u8, b: u8, c: u8, d: u8) -> WhitelistEntry {
        WhitelistEntry::new(ip(a, b, c, d), None).unwrap()
    }

    fn wl_cidr(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> WhitelistEntry {
        WhitelistEntry::new(ip(a, b, c, d), Some(prefix)).unwrap()
    }

    #[test]
    fn whitelisted_ip_rejected_by_blacklist() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        engine.set_whitelist(vec![wl_exact(10, 0, 0, 1)]);
        let result = engine.add_to_blacklist(addr, "test".into(), false, Duration::from_secs(60));
        assert!(matches!(result, Err(IpsError::Whitelisted { .. })));
    }

    #[test]
    fn whitelisted_ip_skips_detection() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        engine.set_whitelist(vec![wl_exact(10, 0, 0, 1)]);
        // Record 3+ detections — should never trigger blacklist
        assert!(engine.record_detection(addr).is_empty());
        assert!(engine.record_detection(addr).is_empty());
        assert!(engine.record_detection(addr).is_empty());
        assert!(engine.record_detection(addr).is_empty());
        assert_eq!(engine.blacklist_size(), 0);
    }

    #[test]
    fn cidr_whitelist_match() {
        let mut engine = IpsEngine::new(test_policy());
        engine.set_whitelist(vec![wl_cidr(192, 168, 1, 0, 24)]);
        // IP in the /24 range — whitelisted
        assert!(engine.is_whitelisted(ip(192, 168, 1, 50)));
        // IP outside the range — not whitelisted
        assert!(!engine.is_whitelisted(ip(192, 168, 2, 1)));
    }

    #[test]
    fn non_whitelisted_ip_still_blocked() {
        let mut engine = IpsEngine::new(test_policy());
        engine.set_whitelist(vec![wl_exact(10, 0, 0, 1)]);
        let other = ip(10, 0, 0, 2);
        engine
            .add_to_blacklist(other, "test".into(), false, Duration::from_secs(60))
            .unwrap();
        assert!(engine.is_blacklisted(other));
    }

    #[test]
    fn set_whitelist_replaces() {
        let mut engine = IpsEngine::new(test_policy());
        engine.set_whitelist(vec![wl_exact(10, 0, 0, 1)]);
        assert_eq!(engine.whitelist_entries().len(), 1);

        engine.set_whitelist(vec![wl_exact(10, 0, 0, 2), wl_exact(10, 0, 0, 3)]);
        assert_eq!(engine.whitelist_entries().len(), 2);
        assert!(!engine.is_whitelisted(ip(10, 0, 0, 1)));
        assert!(engine.is_whitelisted(ip(10, 0, 0, 2)));
    }

    #[test]
    fn empty_whitelist_no_effect() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        engine
            .add_to_blacklist(addr, "test".into(), false, Duration::from_secs(60))
            .unwrap();
        assert!(engine.is_blacklisted(addr));
    }

    // ── sampling ─────────────────────────────────────────────────

    use crate::ids::entity::SamplingMode;

    #[test]
    fn sampling_default_is_none() {
        let engine = IpsEngine::new(test_policy());
        assert_eq!(*engine.sampling(), SamplingMode::None);
    }

    #[test]
    fn set_sampling_updates() {
        let mut engine = IpsEngine::new(test_policy());
        engine.set_sampling(SamplingMode::Hash { rate: 0.3 });
        assert_eq!(*engine.sampling(), SamplingMode::Hash { rate: 0.3 });
    }

    #[test]
    fn should_process_with_none_always_true() {
        let engine = IpsEngine::new(test_policy());
        assert!(engine.should_process(0xC0A8_0001, 0x0A00_0001));
    }

    #[test]
    fn should_process_with_zero_rate_always_false() {
        let mut engine = IpsEngine::new(test_policy());
        engine.set_sampling(SamplingMode::Hash { rate: 0.0 });
        assert!(!engine.should_process(0xC0A8_0001, 0x0A00_0001));
    }

    #[test]
    fn should_process_with_full_rate_always_true() {
        let mut engine = IpsEngine::new(test_policy());
        engine.set_sampling(SamplingMode::Hash { rate: 1.0 });
        assert!(engine.should_process(0xC0A8_0001, 0x0A00_0001));
    }

    #[test]
    fn whitelist_entries_accessor() {
        let mut engine = IpsEngine::new(test_policy());
        assert!(engine.whitelist_entries().is_empty());
        engine.set_whitelist(vec![wl_exact(10, 0, 0, 1)]);
        assert_eq!(engine.whitelist_entries().len(), 1);
    }

    #[test]
    fn whitelist_priority_over_active_blacklist() {
        let mut engine = IpsEngine::new(test_policy());
        let addr = ip(10, 0, 0, 1);
        // First blacklist
        engine
            .add_to_blacklist(addr, "test".into(), false, Duration::from_secs(3600))
            .unwrap();
        assert!(engine.is_blacklisted(addr));
        // Then add to whitelist
        engine.set_whitelist(vec![wl_exact(10, 0, 0, 1)]);
        assert!(!engine.is_blacklisted(addr));
    }

    // Property-based tests
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn blacklisted_ip_is_always_detected(
                a in 1u8..=254u8,
                b in 0u8..=255u8,
                c in 0u8..=255u8,
                d in 1u8..=254u8,
            ) {
                let mut engine = IpsEngine::new(test_policy());
                let addr = IpAddr::V4(Ipv4Addr::new(a, b, c, d));

                engine.add_to_blacklist(
                    addr,
                    "proptest".to_string(),
                    false,
                    Duration::from_secs(60),
                ).unwrap();
                prop_assert!(engine.is_blacklisted(addr));
            }

            #[test]
            fn whitelisted_ip_is_never_blacklisted(
                a in 1u8..=254u8,
                b in 0u8..=255u8,
            ) {
                let mut engine = IpsEngine::new(test_policy());
                let addr = IpAddr::V4(Ipv4Addr::new(a, b, 0, 1));

                engine.set_whitelist(vec![
                    WhitelistEntry::new(
                        IpAddr::V4(Ipv4Addr::new(a, b, 0, 0)),
                        Some(16),
                    ).unwrap(),
                ]);

                // Even after detection attempts, whitelisted IPs should not get blacklisted
                let actions = engine.record_detection(addr);
                prop_assert!(actions.is_empty());
                prop_assert!(engine.is_whitelisted(addr));
                prop_assert!(!engine.is_blacklisted(addr));
            }
        }
    }

    // ── Subnet blocking tests ────────────────────────────────────

    #[test]
    fn ips_engine_emits_block_subnet_for_high_risk_country() {
        let mut ct = std::collections::HashMap::new();
        ct.insert("RU".to_string(), 1_u32);
        let policy = IpsPolicy {
            auto_blacklist_threshold: 3,
            country_thresholds: Some(ct),
            ..test_policy()
        };
        let mut engine = IpsEngine::new(policy);
        let addr = ip(1, 2, 3, 4);
        let actions = engine.record_detection_with_country(addr, Some("RU"));
        assert_eq!(actions.len(), 2);
        assert!(matches!(actions[0], EnforcementAction::BlacklistIp { .. }));
        assert!(matches!(
            actions[1],
            EnforcementAction::BlockSubnet { prefix_len: 24, .. }
        ));
    }

    #[test]
    fn ips_engine_subnet_is_correct_24() {
        let mut ct = std::collections::HashMap::new();
        ct.insert("RU".to_string(), 1_u32);
        let policy = IpsPolicy {
            auto_blacklist_threshold: 3,
            country_thresholds: Some(ct),
            ..test_policy()
        };
        let mut engine = IpsEngine::new(policy);
        let addr = ip(1, 2, 3, 4);
        let actions = engine.record_detection_with_country(addr, Some("RU"));
        if let EnforcementAction::BlockSubnet {
            addr: subnet_addr,
            prefix_len,
            ..
        } = &actions[1]
        {
            assert_eq!(*subnet_addr, ip(1, 2, 3, 0));
            assert_eq!(*prefix_len, 24);
        } else {
            panic!("expected BlockSubnet");
        }
    }

    #[test]
    fn ips_engine_no_subnet_for_non_country_threshold_ip() {
        let mut ct = std::collections::HashMap::new();
        ct.insert("RU".to_string(), 1_u32);
        let policy = IpsPolicy {
            auto_blacklist_threshold: 3,
            country_thresholds: Some(ct),
            ..test_policy()
        };
        let mut engine = IpsEngine::new(policy);
        let addr = ip(10, 0, 0, 1);
        // 3 detections with FR (not in thresholds) -> no subnet block
        engine.record_detection_with_country(addr, Some("FR"));
        engine.record_detection_with_country(addr, Some("FR"));
        let actions = engine.record_detection_with_country(addr, Some("FR"));
        // Should only have BlacklistIp, no BlockSubnet
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], EnforcementAction::BlacklistIp { .. }));
    }

    #[test]
    fn ips_engine_unblock_subnet_on_expiry() {
        let mut ct = std::collections::HashMap::new();
        ct.insert("RU".to_string(), 1_u32);
        let policy = IpsPolicy {
            max_blacklist_duration: Duration::from_millis(1),
            auto_blacklist_threshold: 3,
            max_blacklist_size: 100,
            country_thresholds: Some(ct),
        };
        let mut engine = IpsEngine::new(policy);
        let addr = ip(1, 2, 3, 4);
        engine.record_detection_with_country(addr, Some("RU"));

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(5));

        let actions = engine.cleanup_expired();
        // Should have UnblacklistIp + UnblockSubnet
        let has_unblock_subnet = actions
            .iter()
            .any(|a| matches!(a, EnforcementAction::UnblockSubnet { .. }));
        assert!(has_unblock_subnet);
    }
}
