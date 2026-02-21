use std::collections::HashMap;
use std::net::IpAddr;

use super::entity::{
    BlocklistAction, BlocklistMatch, DomainBlocklistConfig, DomainBlocklistStats, DomainPattern,
    InjectTarget, InjectedIpEntry,
};
use super::error::DnsError;

/// Domain blocklist engine: evaluates domains against patterns and tracks
/// injected IPs for lifecycle management (TTL expiry + grace period).
pub struct DomainBlocklistEngine {
    patterns: Vec<DomainPattern>,
    action: BlocklistAction,
    inject_target: InjectTarget,
    grace_period_secs: u64,
    /// Tracks IPs currently injected into eBPF maps.
    injected_ips: HashMap<IpAddr, InjectedIpEntry>,
    /// Count of total domains matched since startup.
    domains_blocked_count: u64,
    /// Per-pattern match counts (parallel to `patterns`).
    pattern_match_counts: Vec<u64>,
}

impl DomainBlocklistEngine {
    pub fn new(config: DomainBlocklistConfig) -> Self {
        let pattern_count = config.patterns.len();
        Self {
            patterns: config.patterns,
            action: config.action,
            inject_target: config.inject_target,
            grace_period_secs: config.grace_period_secs,
            injected_ips: HashMap::new(),
            domains_blocked_count: 0,
            pattern_match_counts: vec![0; pattern_count],
        }
    }

    /// Check a domain against the blocklist patterns.
    /// Returns the matching pattern info if blocked, or `None`.
    pub fn evaluate(&mut self, domain: &str) -> Option<BlocklistMatch> {
        for (i, pattern) in self.patterns.iter().enumerate() {
            if pattern.matches(domain) {
                self.pattern_match_counts[i] += 1;
                return Some(BlocklistMatch {
                    domain: domain.to_string(),
                    pattern: pattern.clone(),
                    action: self.action,
                    inject_target: self.inject_target,
                });
            }
        }
        None
    }

    /// Process a DNS response for a blocked domain: record resolved IPs for injection.
    ///
    /// Returns the list of new IPs to inject (caller performs the actual eBPF write).
    /// Also returns IPs that should be removed (domain re-resolution with new IPs).
    pub fn on_blocked_resolution(
        &mut self,
        domain: &str,
        resolved_ips: &[IpAddr],
        ttl_secs: u32,
        now_ns: u64,
    ) -> InjectionDelta {
        self.domains_blocked_count += 1;

        let dns_ttl_expires_ns = now_ns + u64::from(ttl_secs) * 1_000_000_000;

        // Find old IPs for this domain that should be removed
        let old_ips: Vec<IpAddr> = self
            .injected_ips
            .iter()
            .filter(|(_, entry)| entry.domain == domain)
            .map(|(ip, _)| *ip)
            .collect();

        let mut to_remove = Vec::new();
        for ip in &old_ips {
            if !resolved_ips.contains(ip) {
                self.injected_ips.remove(ip);
                to_remove.push(*ip);
            }
        }

        // Insert new IPs
        let mut to_inject = Vec::new();
        for ip in resolved_ips {
            if !self.injected_ips.contains_key(ip) {
                to_inject.push(*ip);
            }
            // Always update the entry (refresh TTL)
            self.injected_ips.insert(
                *ip,
                InjectedIpEntry {
                    domain: domain.to_string(),
                    injected_at_ns: now_ns,
                    dns_ttl_expires_ns,
                    grace_period_secs: self.grace_period_secs,
                },
            );
        }

        InjectionDelta {
            to_inject,
            to_remove,
        }
    }

    /// Collect expired injected IPs (past TTL + grace period) for removal.
    /// Returns the list of IPs to remove from the eBPF map.
    pub fn collect_expired(&mut self, now_ns: u64) -> Vec<IpAddr> {
        let expired: Vec<IpAddr> = self
            .injected_ips
            .iter()
            .filter(|(_, entry)| entry.is_expired(now_ns))
            .map(|(ip, _)| *ip)
            .collect();

        for ip in &expired {
            self.injected_ips.remove(ip);
        }
        expired
    }

    /// Reload patterns from a new config. Returns the set of currently
    /// injected IPs that are no longer blocked (should be removed from eBPF maps).
    pub fn reload(&mut self, config: DomainBlocklistConfig) -> Vec<IpAddr> {
        self.patterns = config.patterns;
        self.action = config.action;
        self.inject_target = config.inject_target;
        self.grace_period_secs = config.grace_period_secs;
        self.pattern_match_counts = vec![0; self.patterns.len()];

        // Find injected IPs whose domains are no longer blocked
        let patterns = &self.patterns;
        let to_remove: Vec<IpAddr> = self
            .injected_ips
            .iter()
            .filter(|(_, entry)| !patterns.iter().any(|p| p.matches(&entry.domain)))
            .map(|(ip, _)| *ip)
            .collect();

        for ip in &to_remove {
            self.injected_ips.remove(ip);
        }
        to_remove
    }

    /// Current blocklist action.
    pub fn action(&self) -> BlocklistAction {
        self.action
    }

    /// Current injection target.
    pub fn inject_target(&self) -> InjectTarget {
        self.inject_target
    }

    /// Grace period in seconds for IP expiration.
    pub fn grace_period_secs(&self) -> u64 {
        self.grace_period_secs
    }

    /// Current statistics.
    pub fn stats(&self) -> DomainBlocklistStats {
        DomainBlocklistStats {
            pattern_count: self.patterns.len(),
            domains_blocked: self.domains_blocked_count,
            ips_injected: self.injected_ips.len(),
        }
    }

    /// Number of patterns loaded.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Number of IPs currently injected.
    pub fn injected_ip_count(&self) -> usize {
        self.injected_ips.len()
    }

    /// List all patterns with their per-pattern match counts.
    pub fn list_patterns_with_counts(&self) -> Vec<(&DomainPattern, u64)> {
        self.patterns
            .iter()
            .zip(self.pattern_match_counts.iter().copied())
            .collect()
    }

    /// Add a domain pattern to the runtime blocklist.
    /// Returns an error if the pattern is already present or invalid.
    pub fn add_pattern(&mut self, raw: &str) -> Result<(), DnsError> {
        let pattern = DomainPattern::parse(raw)?;
        if self
            .patterns
            .iter()
            .any(|p| p.to_string() == pattern.to_string())
        {
            return Err(DnsError::DuplicatePattern(raw.to_string()));
        }
        self.patterns.push(pattern);
        self.pattern_match_counts.push(0);
        Ok(())
    }

    /// Remove a domain pattern from the runtime blocklist.
    /// Returns an error if the pattern is not found.
    pub fn remove_pattern(&mut self, raw: &str) -> Result<(), DnsError> {
        let pos = self
            .patterns
            .iter()
            .position(|p| p.to_string() == raw)
            .ok_or_else(|| DnsError::PatternNotFound(raw.to_string()))?;
        self.patterns.remove(pos);
        self.pattern_match_counts.remove(pos);
        Ok(())
    }
}

/// Delta of IPs to inject/remove after processing a blocked DNS resolution.
#[derive(Debug)]
pub struct InjectionDelta {
    /// IPs to add to the eBPF map.
    pub to_inject: Vec<IpAddr>,
    /// IPs to remove from the eBPF map (stale from previous resolution).
    pub to_remove: Vec<IpAddr>,
}

// ── Feed parsing ──────────────────────────────────────────────────

/// Feed format for domain blocklist files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistFeedFormat {
    /// One domain per line, `#` comments.
    Plaintext,
    /// Hosts-file format: `0.0.0.0 domain.com` or `127.0.0.1 domain.com`.
    Hosts,
}

/// Parse a blocklist feed into a list of domain strings.
pub fn parse_blocklist_feed(
    content: &str,
    format: BlocklistFeedFormat,
) -> Result<Vec<String>, DnsError> {
    let mut domains = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        match format {
            BlocklistFeedFormat::Plaintext => {
                domains.push(line.to_lowercase());
            }
            BlocklistFeedFormat::Hosts => {
                // Format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let host = parts[1].to_lowercase();
                    // Skip localhost entries
                    if host != "localhost"
                        && host != "localhost.localdomain"
                        && host != "broadcasthost"
                        && host != "local"
                    {
                        domains.push(host);
                    }
                }
            }
        }
    }

    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ts(secs: u64) -> u64 {
        secs * 1_000_000_000
    }

    fn test_config(patterns: Vec<&str>) -> DomainBlocklistConfig {
        DomainBlocklistConfig {
            patterns: patterns
                .into_iter()
                .map(|p| DomainPattern::parse(p).unwrap())
                .collect(),
            action: BlocklistAction::Block,
            inject_target: InjectTarget::ThreatIntel,
            grace_period_secs: 300,
        }
    }

    #[test]
    fn evaluate_exact_match() {
        let mut engine = DomainBlocklistEngine::new(test_config(vec!["bad.com", "evil.org"]));
        let m = engine.evaluate("bad.com").unwrap();
        assert_eq!(m.domain, "bad.com");
        assert_eq!(m.action, BlocklistAction::Block);
        assert!(engine.evaluate("good.com").is_none());
    }

    #[test]
    fn evaluate_wildcard_match() {
        let mut engine = DomainBlocklistEngine::new(test_config(vec!["*.malware.com"]));
        assert!(engine.evaluate("tracker.malware.com").is_some());
        assert!(engine.evaluate("sub.tracker.malware.com").is_some());
        assert!(engine.evaluate("malware.com").is_none()); // not a subdomain
    }

    #[test]
    fn evaluate_case_insensitive() {
        let mut engine = DomainBlocklistEngine::new(test_config(vec!["BAD.COM"]));
        assert!(engine.evaluate("bad.com").is_some());
        assert!(engine.evaluate("Bad.Com").is_some());
    }

    #[test]
    fn on_blocked_resolution_injects_ips() {
        let mut engine = DomainBlocklistEngine::new(test_config(vec!["bad.com"]));
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        let delta = engine.on_blocked_resolution("bad.com", &[ip1, ip2], 300, ts(0));
        assert_eq!(delta.to_inject.len(), 2);
        assert!(delta.to_remove.is_empty());
        assert_eq!(engine.injected_ip_count(), 2);
    }

    #[test]
    fn on_blocked_resolution_updates_on_reresolution() {
        let mut engine = DomainBlocklistEngine::new(test_config(vec!["bad.com"]));
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));

        engine.on_blocked_resolution("bad.com", &[ip1, ip2], 300, ts(0));

        // Re-resolution: ip1 stays, ip2 removed, ip3 added
        let delta = engine.on_blocked_resolution("bad.com", &[ip1, ip3], 300, ts(10));
        assert_eq!(delta.to_inject, vec![ip3]);
        assert_eq!(delta.to_remove, vec![ip2]);
        assert_eq!(engine.injected_ip_count(), 2);
    }

    #[test]
    fn collect_expired_removes_past_grace_period() {
        let mut engine = DomainBlocklistEngine::new(DomainBlocklistConfig {
            grace_period_secs: 60,
            ..test_config(vec!["bad.com"])
        });
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        engine.on_blocked_resolution("bad.com", &[ip], 10, ts(0)); // TTL=10s

        // At t=50s: TTL expired at 10s, grace period ends at 10+60=70s → not expired
        assert!(engine.collect_expired(ts(50)).is_empty());

        // At t=70s: grace period expired
        let expired = engine.collect_expired(ts(70));
        assert_eq!(expired, vec![ip]);
        assert_eq!(engine.injected_ip_count(), 0);
    }

    #[test]
    fn reload_removes_unblocked_ips() {
        let mut engine = DomainBlocklistEngine::new(test_config(vec!["bad.com", "evil.org"]));
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));

        engine.on_blocked_resolution("bad.com", &[ip1], 300, ts(0));
        engine.on_blocked_resolution("evil.org", &[ip2], 300, ts(0));

        // Reload: remove evil.org from blocklist
        let removed = engine.reload(test_config(vec!["bad.com"]));
        assert_eq!(removed, vec![ip2]);
        assert_eq!(engine.injected_ip_count(), 1);
    }

    #[test]
    fn stats_tracking() {
        let mut engine = DomainBlocklistEngine::new(test_config(vec!["bad.com"]));
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        engine.on_blocked_resolution("bad.com", &[ip], 300, ts(0));

        let stats = engine.stats();
        assert_eq!(stats.pattern_count, 1);
        assert_eq!(stats.domains_blocked, 1);
        assert_eq!(stats.ips_injected, 1);
    }

    // ── Feed parsing tests ────────────────────────────────────────

    #[test]
    fn parse_plaintext_feed() {
        let content = "# Comment\nbad.com\nevil.org\n\n# Another comment\nmalware.net\n";
        let domains = parse_blocklist_feed(content, BlocklistFeedFormat::Plaintext).unwrap();
        assert_eq!(domains, vec!["bad.com", "evil.org", "malware.net"]);
    }

    #[test]
    fn parse_hosts_feed() {
        let content = "# Hosts blocklist\n0.0.0.0 bad.com\n127.0.0.1 evil.org\n0.0.0.0 localhost\n";
        let domains = parse_blocklist_feed(content, BlocklistFeedFormat::Hosts).unwrap();
        assert_eq!(domains, vec!["bad.com", "evil.org"]);
    }

    #[test]
    fn parse_hosts_skips_localhost_variants() {
        let content = "0.0.0.0 localhost\n0.0.0.0 localhost.localdomain\n0.0.0.0 broadcasthost\n0.0.0.0 local\n0.0.0.0 real.domain\n";
        let domains = parse_blocklist_feed(content, BlocklistFeedFormat::Hosts).unwrap();
        assert_eq!(domains, vec!["real.domain"]);
    }

    #[test]
    fn parse_plaintext_case_normalized() {
        let content = "BAD.COM\nEvil.Org\n";
        let domains = parse_blocklist_feed(content, BlocklistFeedFormat::Plaintext).unwrap();
        assert_eq!(domains, vec!["bad.com", "evil.org"]);
    }

    #[test]
    fn parse_empty_feed() {
        let domains = parse_blocklist_feed("", BlocklistFeedFormat::Plaintext).unwrap();
        assert!(domains.is_empty());
    }

    // ── Runtime add/remove tests ──────────────────────────────────

    fn make_engine() -> DomainBlocklistEngine {
        DomainBlocklistEngine::new(DomainBlocklistConfig {
            patterns: vec![DomainPattern::parse("evil.com").unwrap()],
            action: BlocklistAction::Block,
            inject_target: InjectTarget::ThreatIntel,
            grace_period_secs: 300,
        })
    }

    #[test]
    fn add_pattern_succeeds() {
        let mut engine = make_engine();
        assert_eq!(engine.pattern_count(), 1);
        engine.add_pattern("*.malware.com").unwrap();
        assert_eq!(engine.pattern_count(), 2);
    }

    #[test]
    fn add_pattern_duplicate_fails() {
        let mut engine = make_engine();
        let err = engine.add_pattern("evil.com").unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn add_pattern_invalid_fails() {
        let mut engine = make_engine();
        let err = engine.add_pattern("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn remove_pattern_succeeds() {
        let mut engine = make_engine();
        engine.remove_pattern("evil.com").unwrap();
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn remove_pattern_not_found_fails() {
        let mut engine = make_engine();
        let err = engine.remove_pattern("nonexistent.com").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn add_then_remove_pattern() {
        let mut engine = make_engine();
        engine.add_pattern("*.phishing.com").unwrap();
        assert_eq!(engine.pattern_count(), 2);
        engine.remove_pattern("*.phishing.com").unwrap();
        assert_eq!(engine.pattern_count(), 1);
    }
}
