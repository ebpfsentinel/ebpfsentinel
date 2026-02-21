use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use super::error::IpsError;

/// An entry in the IPS blacklist. Tracks when the IP was blacklisted,
/// how long it should remain, and detection metadata.
#[derive(Debug, Clone)]
pub struct BlacklistEntry {
    pub ip: IpAddr,
    pub reason: String,
    pub auto_generated: bool,
    pub added_at: Instant,
    pub ttl: Duration,
    pub detection_count: u32,
    pub last_detected_at: Instant,
}

impl BlacklistEntry {
    /// Returns `true` if this entry has exceeded its TTL.
    pub fn is_expired(&self) -> bool {
        self.added_at.elapsed() >= self.ttl
    }
}

/// Policy governing IPS blacklist behavior.
#[derive(Debug, Clone)]
pub struct IpsPolicy {
    /// Maximum time an IP can remain blacklisted.
    pub max_blacklist_duration: Duration,
    /// Number of detections before an IP is auto-blacklisted.
    pub auto_blacklist_threshold: u32,
    /// Maximum number of entries in the blacklist.
    pub max_blacklist_size: usize,
}

impl Default for IpsPolicy {
    fn default() -> Self {
        Self {
            max_blacklist_duration: Duration::from_secs(3600),
            auto_blacklist_threshold: 3,
            max_blacklist_size: 10_000,
        }
    }
}

/// An enforcement action produced by the IPS engine to be sent to the
/// single-writer eBPF map updater task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementAction {
    /// Add an IP to the eBPF blacklist map.
    BlacklistIp { ip: IpAddr, ttl: Duration },
    /// Remove an IP from the eBPF blacklist map.
    UnblacklistIp { ip: IpAddr },
}

/// A whitelist entry that can match a single IP or a CIDR range.
///
/// Whitelisted IPs bypass IPS blacklisting and detection counting.
/// Fields are private to enforce validation invariants; use [`WhitelistEntry::new`]
/// or [`FromStr`] to construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistEntry {
    ip: IpAddr,
    cidr_prefix: Option<u8>,
}

impl WhitelistEntry {
    /// Create a new whitelist entry with validated CIDR prefix.
    ///
    /// Returns an error if `cidr_prefix` exceeds 32 for IPv4 or 128 for IPv6.
    pub fn new(ip: IpAddr, cidr_prefix: Option<u8>) -> Result<Self, IpsError> {
        if let Some(prefix) = cidr_prefix {
            match ip {
                IpAddr::V4(_) if prefix > 32 => {
                    return Err(IpsError::InvalidPolicy(format!(
                        "IPv4 CIDR prefix must be 0-32, got {prefix}"
                    )));
                }
                IpAddr::V6(_) if prefix > 128 => {
                    return Err(IpsError::InvalidPolicy(format!(
                        "IPv6 CIDR prefix must be 0-128, got {prefix}"
                    )));
                }
                _ => {}
            }
        }
        Ok(Self { ip, cidr_prefix })
    }

    /// The network address (for CIDR) or exact IP.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// `None` means exact match. `Some(n)` means CIDR /n.
    pub fn cidr_prefix(&self) -> Option<u8> {
        self.cidr_prefix
    }

    /// Check if the given address matches this whitelist entry.
    pub fn matches(&self, addr: IpAddr) -> bool {
        match (self.ip, addr) {
            (IpAddr::V4(wl), IpAddr::V4(target)) => match self.cidr_prefix {
                None => wl == target,
                Some(0) => true,
                Some(prefix) => {
                    let mask = u32::MAX << (32 - prefix);
                    (u32::from(wl) & mask) == (u32::from(target) & mask)
                }
            },
            (IpAddr::V6(wl), IpAddr::V6(target)) => match self.cidr_prefix {
                None => wl == target,
                Some(0) => true,
                Some(prefix) => {
                    let mask = u128::MAX << (128 - prefix);
                    (u128::from(wl) & mask) == (u128::from(target) & mask)
                }
            },
            // Cross-family never matches
            _ => false,
        }
    }
}

impl FromStr for WhitelistEntry {
    type Err = IpsError;

    /// Parse a string like `"10.0.0.1"` or `"192.168.1.0/24"` into a
    /// `WhitelistEntry`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| IpsError::InvalidPolicy(format!("invalid IP in whitelist: '{s}'")))?;
            let prefix: u8 = prefix_str.parse().map_err(|_| {
                IpsError::InvalidPolicy(format!("invalid CIDR prefix in whitelist: '{s}'"))
            })?;
            Self::new(ip, Some(prefix))
        } else {
            let ip: IpAddr = s
                .parse()
                .map_err(|_| IpsError::InvalidPolicy(format!("invalid IP in whitelist: '{s}'")))?;
            Self::new(ip, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ttl: Duration) -> BlacklistEntry {
        let now = Instant::now();
        BlacklistEntry {
            ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            reason: "test".to_string(),
            auto_generated: true,
            added_at: now,
            ttl,
            detection_count: 1,
            last_detected_at: now,
        }
    }

    #[test]
    fn entry_not_expired() {
        let entry = make_entry(Duration::from_secs(3600));
        assert!(!entry.is_expired());
    }

    #[test]
    fn entry_expired() {
        let entry = BlacklistEntry {
            added_at: Instant::now().checked_sub(Duration::from_secs(10)).unwrap(),
            ttl: Duration::from_millis(1),
            ..make_entry(Duration::from_millis(1))
        };
        assert!(entry.is_expired());
    }

    #[test]
    fn default_policy_values() {
        let policy = IpsPolicy::default();
        assert_eq!(policy.max_blacklist_duration, Duration::from_secs(3600));
        assert_eq!(policy.auto_blacklist_threshold, 3);
        assert_eq!(policy.max_blacklist_size, 10_000);
    }

    #[test]
    fn enforcement_action_blacklist() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let action = EnforcementAction::BlacklistIp {
            ip,
            ttl: Duration::from_secs(60),
        };
        assert!(matches!(action, EnforcementAction::BlacklistIp { .. }));
    }

    #[test]
    fn enforcement_action_unblacklist() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let action = EnforcementAction::UnblacklistIp { ip };
        assert!(matches!(action, EnforcementAction::UnblacklistIp { .. }));
    }

    #[test]
    fn enforcement_action_equality() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let a = EnforcementAction::BlacklistIp {
            ip,
            ttl: Duration::from_secs(60),
        };
        let b = EnforcementAction::BlacklistIp {
            ip,
            ttl: Duration::from_secs(60),
        };
        assert_eq!(a, b);
    }

    // ── WhitelistEntry ─────────────────────────────────────────────

    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn whitelist_new_valid_ipv4() {
        let entry = WhitelistEntry::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), Some(24)).unwrap();
        assert_eq!(entry.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(entry.cidr_prefix(), Some(24));
    }

    #[test]
    fn whitelist_new_invalid_ipv4_prefix() {
        let result = WhitelistEntry::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), Some(33));
        assert!(result.is_err());
    }

    #[test]
    fn whitelist_new_valid_ipv6() {
        let entry = WhitelistEntry::new(IpAddr::V6(Ipv6Addr::LOCALHOST), Some(64)).unwrap();
        assert_eq!(entry.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(entry.cidr_prefix(), Some(64));
    }

    #[test]
    fn whitelist_new_invalid_ipv6_prefix() {
        let result = WhitelistEntry::new(IpAddr::V6(Ipv6Addr::LOCALHOST), Some(129));
        assert!(result.is_err());
    }

    #[test]
    fn whitelist_exact_match() {
        let entry = WhitelistEntry::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None).unwrap();
        assert!(entry.matches(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!entry.matches(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    }

    #[test]
    fn whitelist_cidr_match() {
        let entry =
            WhitelistEntry::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), Some(24)).unwrap();
        assert!(entry.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
        assert!(entry.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))));
    }

    #[test]
    fn whitelist_cidr_no_match() {
        let entry =
            WhitelistEntry::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), Some(24)).unwrap();
        assert!(!entry.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(!entry.matches(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn whitelist_cidr_zero_matches_all() {
        let entry = WhitelistEntry::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), Some(0)).unwrap();
        assert!(entry.matches(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(entry.matches(IpAddr::V4(Ipv4Addr::BROADCAST)));
    }

    // ── IPv6 matching ─────────────────────────────────────────────

    #[test]
    fn whitelist_ipv6_exact_match() {
        let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let entry = WhitelistEntry::new(IpAddr::V6(addr), None).unwrap();
        assert!(entry.matches(IpAddr::V6(addr)));
        let other = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        assert!(!entry.matches(IpAddr::V6(other)));
    }

    #[test]
    fn whitelist_ipv6_cidr_match() {
        let net = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0);
        let entry = WhitelistEntry::new(IpAddr::V6(net), Some(64)).unwrap();
        // Same /64 prefix
        let target = Ipv6Addr::new(0xfd00, 0, 0, 0, 0xab, 0xcd, 0xef, 0x12);
        assert!(entry.matches(IpAddr::V6(target)));
        // Different /64 prefix
        let outside = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0);
        assert!(!entry.matches(IpAddr::V6(outside)));
    }

    #[test]
    fn whitelist_ipv6_cidr_zero_matches_all() {
        let entry = WhitelistEntry::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), Some(0)).unwrap();
        assert!(entry.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let any = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert!(entry.matches(IpAddr::V6(any)));
    }

    // ── Cross-family ──────────────────────────────────────────────

    #[test]
    fn whitelist_cross_family_never_matches() {
        let v4 = WhitelistEntry::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None).unwrap();
        assert!(!v4.matches(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        let v6 = WhitelistEntry::new(IpAddr::V6(Ipv6Addr::LOCALHOST), None).unwrap();
        assert!(!v6.matches(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    // ── FromStr ───────────────────────────────────────────────────

    #[test]
    fn whitelist_parse_single_ip() {
        let entry: WhitelistEntry = "10.0.0.1".parse().unwrap();
        assert_eq!(entry.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(entry.cidr_prefix(), None);
    }

    #[test]
    fn whitelist_parse_cidr() {
        let entry: WhitelistEntry = "192.168.1.0/24".parse().unwrap();
        assert_eq!(entry.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(entry.cidr_prefix(), Some(24));
    }

    #[test]
    fn whitelist_parse_ipv6() {
        let entry: WhitelistEntry = "fd00::1".parse().unwrap();
        assert_eq!(
            entry.ip(),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(entry.cidr_prefix(), None);
    }

    #[test]
    fn whitelist_parse_ipv6_cidr() {
        let entry: WhitelistEntry = "fd00::/64".parse().unwrap();
        assert_eq!(
            entry.ip(),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0))
        );
        assert_eq!(entry.cidr_prefix(), Some(64));
    }

    #[test]
    fn whitelist_parse_invalid_ip() {
        assert!("not-an-ip".parse::<WhitelistEntry>().is_err());
    }

    #[test]
    fn whitelist_parse_invalid_prefix() {
        assert!("10.0.0.0/33".parse::<WhitelistEntry>().is_err());
    }

    #[test]
    fn whitelist_parse_invalid_ipv6_prefix() {
        assert!("::1/129".parse::<WhitelistEntry>().is_err());
    }
}
