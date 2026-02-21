use std::fmt;
use std::net::IpAddr;

/// DNS record type codes (RFC 1035 + extensions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    TXT,
    MX,
    NS,
    SOA,
    PTR,
    SRV,
    Other(u16),
}

impl DnsRecordType {
    /// Parse from the wire format u16 type code.
    pub fn from_wire(value: u16) -> Self {
        match value {
            1 => Self::A,
            28 => Self::AAAA,
            5 => Self::CNAME,
            16 => Self::TXT,
            15 => Self::MX,
            2 => Self::NS,
            6 => Self::SOA,
            12 => Self::PTR,
            33 => Self::SRV,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::AAAA => write!(f, "AAAA"),
            Self::CNAME => write!(f, "CNAME"),
            Self::TXT => write!(f, "TXT"),
            Self::MX => write!(f, "MX"),
            Self::NS => write!(f, "NS"),
            Self::SOA => write!(f, "SOA"),
            Self::PTR => write!(f, "PTR"),
            Self::SRV => write!(f, "SRV"),
            Self::Other(n) => write!(f, "TYPE{n}"),
        }
    }
}

/// DNS response code (RCODE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl DnsResponseCode {
    pub fn from_wire(value: u8) -> Self {
        match value & 0x0F {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            other => Self::Other(other),
        }
    }
}

/// A parsed DNS query (question section entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub domain: String,
    pub query_type: DnsRecordType,
    pub src_addr: IpAddr,
    pub timestamp_ns: u64,
}

/// A parsed DNS answer record with resolved addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub domain: String,
    pub record_type: DnsRecordType,
    pub resolved_ips: Vec<IpAddr>,
    pub cname_target: Option<String>,
    pub ttl: u32,
    pub timestamp_ns: u64,
}

/// A complete DNS response with all parsed sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub transaction_id: u16,
    pub rcode: DnsResponseCode,
    pub queries: Vec<DnsQuery>,
    pub answers: Vec<DnsRecord>,
    pub authority_count: u16,
    pub additional_count: u16,
}

/// Top-level parsed DNS packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPacket {
    Query(DnsQuery),
    Response(DnsResponse),
}

// ── Domain blocklist entities ──────────────────────────────────────

/// A domain pattern for blocklist matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainPattern {
    /// Exact domain match (case-insensitive).
    Exact(String),
    /// Wildcard prefix match: `*.example.com` matches any subdomain.
    Wildcard {
        /// The suffix to match against (lowercase, without the `*.` prefix).
        suffix: String,
        /// Maximum subdomain depth to match (default 5).
        max_depth: u8,
    },
}

impl DomainPattern {
    /// Parse a pattern string into a `DomainPattern`.
    ///
    /// - `"example.com"` → `Exact("example.com")`
    /// - `"*.example.com"` → `Wildcard { suffix: "example.com", max_depth: 5 }`
    pub fn parse(pattern: &str) -> Result<Self, super::error::DnsError> {
        let pattern = pattern.trim().to_lowercase();
        if pattern.is_empty() {
            return Err(super::error::DnsError::InvalidBlocklistPattern(
                "empty pattern".to_string(),
            ));
        }

        if let Some(suffix) = pattern.strip_prefix("*.") {
            if suffix.is_empty() {
                return Err(super::error::DnsError::InvalidBlocklistPattern(
                    "wildcard pattern requires a suffix after *.".to_string(),
                ));
            }
            Ok(Self::Wildcard {
                suffix: suffix.to_string(),
                max_depth: 5,
            })
        } else {
            Ok(Self::Exact(pattern))
        }
    }

    /// Check if a domain matches this pattern (case-insensitive).
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        match self {
            Self::Exact(exact) => domain == *exact,
            Self::Wildcard { suffix, max_depth } => {
                // Must be a subdomain, not the suffix itself
                if let Some(prefix) = domain.strip_suffix(suffix) {
                    if let Some(prefix) = prefix.strip_suffix('.') {
                        // Count depth: number of labels in the prefix
                        let depth = prefix.chars().filter(|&c| c == '.').count() + 1;
                        depth <= *max_depth as usize
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(d) => write!(f, "{d}"),
            Self::Wildcard { suffix, .. } => write!(f, "*.{suffix}"),
        }
    }
}

/// Action to take when a domain matches the blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistAction {
    /// Drop traffic to resolved IPs at kernel level.
    Block,
    /// Generate alert but allow traffic.
    Alert,
    /// Log the match only.
    Log,
}

impl fmt::Display for BlocklistAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block => write!(f, "block"),
            Self::Alert => write!(f, "alert"),
            Self::Log => write!(f, "log"),
        }
    }
}

/// Target eBPF map for IP injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectTarget {
    /// Inject into the threat intelligence IOC map.
    ThreatIntel,
    /// Inject as a firewall drop rule.
    Firewall,
    /// Inject into the IPS blacklist (auto-expiry via IPS lifecycle).
    Ips,
}

/// Result of a domain blocklist evaluation.
#[derive(Debug, Clone)]
pub struct BlocklistMatch {
    pub domain: String,
    pub pattern: DomainPattern,
    pub action: BlocklistAction,
    pub inject_target: InjectTarget,
}

/// Metadata attached to an IP injected from DNS blocklist resolution.
#[derive(Debug, Clone)]
pub struct InjectedIpEntry {
    /// The domain that resolved to this IP.
    pub domain: String,
    /// When the IP was injected into the eBPF map (nanoseconds).
    pub injected_at_ns: u64,
    /// When the DNS TTL expires (nanoseconds).
    pub dns_ttl_expires_ns: u64,
    /// Grace period in seconds after TTL expiry before removal.
    pub grace_period_secs: u64,
}

impl InjectedIpEntry {
    /// Check whether this injected IP should be removed.
    pub fn is_expired(&self, now_ns: u64) -> bool {
        let removal_ns = self.dns_ttl_expires_ns + self.grace_period_secs * 1_000_000_000;
        now_ns >= removal_ns
    }
}

/// Configuration for domain blocklist enforcement.
#[derive(Debug, Clone)]
pub struct DomainBlocklistConfig {
    pub patterns: Vec<DomainPattern>,
    pub action: BlocklistAction,
    pub inject_target: InjectTarget,
    pub grace_period_secs: u64,
}

impl Default for DomainBlocklistConfig {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            action: BlocklistAction::Block,
            inject_target: InjectTarget::ThreatIntel,
            grace_period_secs: 300,
        }
    }
}

/// Statistics for the domain blocklist engine.
#[derive(Debug, Clone, Default)]
pub struct DomainBlocklistStats {
    pub pattern_count: usize,
    pub domains_blocked: u64,
    pub ips_injected: usize,
}

// ── Domain reputation entities ────────────────────────────────────

/// A factor contributing to a domain's reputation score.
#[derive(Debug, Clone, PartialEq)]
pub enum ReputationFactor {
    /// Domain is in a blocklist.
    BlocklistHit { list_name: String },
    /// Domain matched a CTI feed IOC.
    CtiMatch {
        feed_name: String,
        threat_type: String,
    },
    /// Domain has high Shannon entropy (DGA indicator).
    HighEntropy { entropy: f64 },
    /// Domain has unusually short DNS TTL (fast-flux indicator).
    ShortTtl { avg_ttl: u64 },
    /// Domain triggered an L7 firewall rule.
    L7RuleMatch { rule_id: String },
    /// Domain is queried at an unusually high rate.
    FrequentQueries { rate_per_min: f64 },
}

impl ReputationFactor {
    /// Base weight for this factor type (0.0–1.0).
    pub fn weight(&self) -> f64 {
        match self {
            Self::BlocklistHit { .. } => 0.9,
            Self::CtiMatch { .. } => 0.8,
            Self::HighEntropy { .. } => 0.3,
            Self::ShortTtl { .. } => 0.2,
            Self::L7RuleMatch { .. } => 0.5,
            Self::FrequentQueries { .. } => 0.1,
        }
    }

    /// Discriminant key for deduplication (same type → same key).
    pub fn kind_key(&self) -> &'static str {
        match self {
            Self::BlocklistHit { .. } => "blocklist",
            Self::CtiMatch { .. } => "cti",
            Self::HighEntropy { .. } => "entropy",
            Self::ShortTtl { .. } => "ttl",
            Self::L7RuleMatch { .. } => "l7",
            Self::FrequentQueries { .. } => "freq",
        }
    }
}

/// Aggregated reputation state for a single domain.
#[derive(Debug, Clone)]
pub struct DomainReputation {
    pub domain: String,
    pub factors: Vec<ReputationFactor>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub total_connections: u64,
}

impl DomainReputation {
    /// Compute the reputation score using probabilistic OR of factor weights.
    ///
    /// `score = 1 - product(1 - weight_i)`, capped at 1.0.
    pub fn compute_score(&self) -> f64 {
        if self.factors.is_empty() {
            return 0.0;
        }
        let product: f64 = self.factors.iter().map(|f| 1.0 - f.weight()).product();
        (1.0 - product).min(1.0)
    }

    /// Compute effective score with time decay.
    ///
    /// `effective = base_score * 2^(-(now - last_seen) / half_life)`
    pub fn effective_score(&self, now_ns: u64, half_life_ns: u64) -> f64 {
        let base = self.compute_score();
        if base == 0.0 || half_life_ns == 0 {
            return base;
        }
        let elapsed = now_ns.saturating_sub(self.last_seen);
        #[allow(clippy::cast_precision_loss)]
        let ratio = elapsed as f64 / half_life_ns as f64;
        let decay = (-ratio).exp2();
        (base * decay).min(1.0)
    }
}

/// Configuration for the domain reputation engine.
#[derive(Debug, Clone)]
pub struct ReputationConfig {
    pub enabled: bool,
    pub max_tracked_domains: usize,
    pub auto_block_threshold: f64,
    pub auto_block_enabled: bool,
    /// TTL for reputation-based IPS blocks (seconds).
    pub auto_block_ttl_secs: u64,
    /// Decay half-life in hours.
    pub decay_half_life_hours: u64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_tracked_domains: 50_000,
            auto_block_threshold: 0.8,
            auto_block_enabled: false,
            auto_block_ttl_secs: 3600,
            decay_half_life_hours: 24,
        }
    }
}

impl ReputationConfig {
    /// Half-life in nanoseconds.
    pub fn half_life_ns(&self) -> u64 {
        self.decay_half_life_hours * 3600 * 1_000_000_000
    }
}

/// Aggregated statistics for the reputation engine.
#[derive(Debug, Clone, Default)]
pub struct ReputationStats {
    pub tracked_domains: usize,
    pub high_risk_count: usize,
    pub auto_blocked_count: u64,
}

// ── DNS Cache entities ──────────────────────────────────────────────

/// Configuration for the DNS resolution cache.
#[derive(Debug, Clone)]
pub struct DnsCacheConfig {
    pub max_entries: usize,
    pub min_ttl_secs: u64,
    pub purge_interval_secs: u64,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            min_ttl_secs: 60,
            purge_interval_secs: 30,
        }
    }
}

/// A single entry in the DNS resolution cache.
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub ips: Vec<IpAddr>,
    pub ttl_secs: u64,
    pub inserted_at_ns: u64,
    pub last_queried_ns: u64,
    pub query_count: u64,
}

/// Aggregated statistics for the DNS cache.
#[derive(Debug, Clone, Default)]
pub struct DnsCacheStats {
    pub total_entries: usize,
    pub hit_count: u64,
    pub miss_count: u64,
    pub eviction_count: u64,
    pub expired_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_from_wire() {
        assert_eq!(DnsRecordType::from_wire(1), DnsRecordType::A);
        assert_eq!(DnsRecordType::from_wire(28), DnsRecordType::AAAA);
        assert_eq!(DnsRecordType::from_wire(5), DnsRecordType::CNAME);
        assert_eq!(DnsRecordType::from_wire(16), DnsRecordType::TXT);
        assert_eq!(DnsRecordType::from_wire(15), DnsRecordType::MX);
        assert_eq!(DnsRecordType::from_wire(2), DnsRecordType::NS);
        assert_eq!(DnsRecordType::from_wire(6), DnsRecordType::SOA);
        assert_eq!(DnsRecordType::from_wire(12), DnsRecordType::PTR);
        assert_eq!(DnsRecordType::from_wire(33), DnsRecordType::SRV);
        assert_eq!(DnsRecordType::from_wire(99), DnsRecordType::Other(99));
    }

    #[test]
    fn test_record_type_display() {
        assert_eq!(DnsRecordType::A.to_string(), "A");
        assert_eq!(DnsRecordType::AAAA.to_string(), "AAAA");
        assert_eq!(DnsRecordType::Other(99).to_string(), "TYPE99");
    }

    #[test]
    fn test_response_code_from_wire() {
        assert_eq!(DnsResponseCode::from_wire(0), DnsResponseCode::NoError);
        assert_eq!(DnsResponseCode::from_wire(3), DnsResponseCode::NXDomain);
        assert_eq!(DnsResponseCode::from_wire(5), DnsResponseCode::Refused);
        assert_eq!(DnsResponseCode::from_wire(9), DnsResponseCode::Other(9));
    }

    // ── Domain pattern tests ──────────────────────────────────────

    #[test]
    fn pattern_exact_match() {
        let p = DomainPattern::parse("example.com").unwrap();
        assert!(p.matches("example.com"));
        assert!(p.matches("EXAMPLE.COM")); // case-insensitive
        assert!(!p.matches("sub.example.com"));
        assert!(!p.matches("notexample.com"));
    }

    #[test]
    fn pattern_wildcard_match() {
        let p = DomainPattern::parse("*.example.com").unwrap();
        assert!(p.matches("foo.example.com"));
        assert!(p.matches("bar.baz.example.com"));
        assert!(p.matches("A.B.C.example.com")); // case-insensitive
        assert!(!p.matches("example.com")); // NOT the suffix itself
        assert!(!p.matches("notexample.com"));
    }

    #[test]
    fn pattern_wildcard_depth_limit() {
        let p = DomainPattern::Wildcard {
            suffix: "example.com".to_string(),
            max_depth: 2,
        };
        assert!(p.matches("a.example.com")); // depth 1
        assert!(p.matches("a.b.example.com")); // depth 2
        assert!(!p.matches("a.b.c.example.com")); // depth 3 > max 2
    }

    #[test]
    fn pattern_parse_empty_errors() {
        assert!(DomainPattern::parse("").is_err());
        assert!(DomainPattern::parse("*.").is_err());
    }

    #[test]
    fn pattern_display() {
        assert_eq!(
            DomainPattern::parse("example.com").unwrap().to_string(),
            "example.com"
        );
        assert_eq!(
            DomainPattern::parse("*.evil.com").unwrap().to_string(),
            "*.evil.com"
        );
    }

    #[test]
    fn injected_ip_expiry() {
        let entry = InjectedIpEntry {
            domain: "test.com".to_string(),
            injected_at_ns: 0,
            dns_ttl_expires_ns: 60_000_000_000, // 60s
            grace_period_secs: 300,             // 5min
        };
        // Not expired at 60s (TTL expired but grace period active)
        assert!(!entry.is_expired(60_000_000_000));
        // Not expired at 300s
        assert!(!entry.is_expired(300_000_000_000));
        // Expired at 360s (TTL 60s + grace 300s)
        assert!(entry.is_expired(360_000_000_000));
    }
}
