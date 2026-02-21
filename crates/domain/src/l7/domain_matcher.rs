use std::fmt;

use regex::Regex;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::error::L7Error;

/// Maximum domain pattern length (per RFC 1035: 253 chars for a FQDN).
const MAX_PATTERN_LENGTH: usize = 253;

/// Regex NFA size limit (same as IDS/DLP).
const REGEX_SIZE_LIMIT: usize = 10 * (1 << 20);

/// Regex nesting depth limit (same as IDS/DLP).
const REGEX_NEST_LIMIT: u32 = 200;

/// Pre-compiled domain matcher for L7 firewall rules.
///
/// Supports five matching modes:
/// - **Exact**: `example.com` matches only `example.com`
/// - **`WildcardPrefix`**: `*.example.com` matches `foo.example.com` but not `example.com`
/// - **`WildcardSuffix`**: `example.*` matches `example.com`, `example.org`
/// - **Regex**: `~^(ads|tracker)\.` matches via compiled regex
/// - **Substring**: `example` matches any domain containing `example` (backward compat)
#[derive(Clone)]
pub struct DomainMatcher {
    /// Original pattern string (used for serialization and equality).
    pattern: String,
    kind: DomainMatcherKind,
}

#[derive(Clone)]
enum DomainMatcherKind {
    /// Exact match (lowercased).
    Exact(String),
    /// `*.suffix` — matches subdomains of suffix.
    WildcardPrefix {
        /// The suffix after `*.`, lowercased (e.g., `example.com`).
        suffix: String,
    },
    /// `prefix.*` — matches domains starting with prefix.
    WildcardSuffix {
        /// The prefix before `.*`, lowercased (e.g., `example`).
        prefix: String,
    },
    /// `~regex` — compiled case-insensitive regex.
    Regex(Regex),
    /// Legacy substring match (backward compat), lowercased.
    Substring(String),
}

impl DomainMatcher {
    /// Parse a pattern string and pre-compile the matcher.
    ///
    /// Pattern detection:
    /// - `*.suffix` → `WildcardPrefix`
    /// - `prefix.*` → `WildcardSuffix`
    /// - `~regex` → `Regex` (compiled with case-insensitive flag)
    /// - anything else → `Substring` (backward-compatible)
    pub fn new(pattern: &str) -> Result<Self, L7Error> {
        if pattern.is_empty() {
            return Err(L7Error::InvalidDomainPattern {
                pattern: pattern.to_string(),
                reason: "pattern must not be empty".to_string(),
            });
        }

        if pattern.len() > MAX_PATTERN_LENGTH {
            return Err(L7Error::DomainPatternTooLong {
                length: pattern.len(),
                max: MAX_PATTERN_LENGTH,
            });
        }

        // Reject patterns with both prefix and suffix wildcards: *.example.*
        if pattern.starts_with("*.") && pattern.ends_with(".*") {
            return Err(L7Error::InvalidDomainPattern {
                pattern: pattern.to_string(),
                reason: "cannot have both prefix and suffix wildcards".to_string(),
            });
        }

        let kind = if let Some(rest) = pattern.strip_prefix("*.") {
            let suffix = rest.to_ascii_lowercase();
            DomainMatcherKind::WildcardPrefix { suffix }
        } else if let Some(rest) = pattern.strip_suffix(".*") {
            let prefix = rest.to_ascii_lowercase();
            DomainMatcherKind::WildcardSuffix { prefix }
        } else if let Some(regex_str) = pattern.strip_prefix('~') {
            let regex = compile_domain_regex(regex_str).map_err(|reason| {
                L7Error::InvalidDomainPattern {
                    pattern: pattern.to_string(),
                    reason,
                }
            })?;
            DomainMatcherKind::Regex(regex)
        } else {
            DomainMatcherKind::Substring(pattern.to_ascii_lowercase())
        };

        Ok(Self {
            pattern: pattern.to_string(),
            kind,
        })
    }

    /// Create an exact-match `DomainMatcher`.
    pub fn exact(domain: &str) -> Result<Self, L7Error> {
        if domain.is_empty() {
            return Err(L7Error::InvalidDomainPattern {
                pattern: domain.to_string(),
                reason: "domain must not be empty".to_string(),
            });
        }
        if domain.len() > MAX_PATTERN_LENGTH {
            return Err(L7Error::DomainPatternTooLong {
                length: domain.len(),
                max: MAX_PATTERN_LENGTH,
            });
        }
        Ok(Self {
            pattern: domain.to_string(),
            kind: DomainMatcherKind::Exact(domain.to_ascii_lowercase()),
        })
    }

    /// Test whether a domain matches this pattern.
    ///
    /// The domain is normalized to lowercase before comparison.
    pub fn matches(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }
        let lower = domain.to_ascii_lowercase();
        match &self.kind {
            DomainMatcherKind::Exact(expected) => lower == *expected,
            DomainMatcherKind::WildcardPrefix { suffix } => {
                // `*.example.com` matches `foo.example.com` but not `example.com`.
                // The domain must end with `.suffix` and have at least one more label.
                if let Some(stripped) = lower.strip_suffix(suffix.as_str()) {
                    stripped.ends_with('.')
                } else {
                    false
                }
            }
            DomainMatcherKind::WildcardSuffix { prefix } => {
                // `example.*` matches `example.com`, `example.org`.
                // The domain must start with `prefix.`.
                if let Some(stripped) = lower.strip_prefix(prefix.as_str()) {
                    stripped.starts_with('.')
                } else {
                    false
                }
            }
            DomainMatcherKind::Regex(re) => re.is_match(&lower),
            DomainMatcherKind::Substring(needle) => lower.contains(needle.as_str()),
        }
    }

    /// The original pattern string.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

fn compile_domain_regex(pattern: &str) -> Result<Regex, String> {
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|e| format!("invalid regex: {e}"))
}

// ── Trait impls ─────────────────────────────────────────────────────

impl fmt::Debug for DomainMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainMatcher")
            .field("pattern", &self.pattern)
            .finish_non_exhaustive()
    }
}

impl PartialEq for DomainMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for DomainMatcher {}

impl Serialize for DomainMatcher {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.pattern)
    }
}

impl<'de> Deserialize<'de> for DomainMatcher {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DomainMatcherVisitor;

        impl Visitor<'_> for DomainMatcherVisitor {
            type Value = DomainMatcher;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a domain pattern string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<DomainMatcher, E> {
                DomainMatcher::new(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(DomainMatcherVisitor)
    }
}

impl fmt::Display for DomainMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.pattern)
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction ────────────────────────────────────────────────

    #[test]
    fn new_wildcard_prefix() {
        let m = DomainMatcher::new("*.example.com").unwrap();
        assert_eq!(m.pattern(), "*.example.com");
    }

    #[test]
    fn new_wildcard_suffix() {
        let m = DomainMatcher::new("example.*").unwrap();
        assert_eq!(m.pattern(), "example.*");
    }

    #[test]
    fn new_regex() {
        let m = DomainMatcher::new("~^(ads|tracker)\\.").unwrap();
        assert_eq!(m.pattern(), "~^(ads|tracker)\\.");
    }

    #[test]
    fn new_substring_default() {
        let m = DomainMatcher::new("example.com").unwrap();
        assert_eq!(m.pattern(), "example.com");
    }

    #[test]
    fn new_exact() {
        let m = DomainMatcher::exact("example.com").unwrap();
        assert_eq!(m.pattern(), "example.com");
    }

    #[test]
    fn empty_pattern_rejected() {
        assert!(DomainMatcher::new("").is_err());
    }

    #[test]
    fn pattern_too_long_rejected() {
        let long = "a".repeat(254);
        assert!(DomainMatcher::new(&long).is_err());
    }

    #[test]
    fn both_wildcards_rejected() {
        assert!(DomainMatcher::new("*.example.*").is_err());
    }

    #[test]
    fn invalid_regex_rejected() {
        assert!(DomainMatcher::new("~[invalid").is_err());
    }

    // ── Exact matching ──────────────────────────────────────────────

    #[test]
    fn exact_matches_same_domain() {
        let m = DomainMatcher::exact("example.com").unwrap();
        assert!(m.matches("example.com"));
    }

    #[test]
    fn exact_does_not_match_subdomain() {
        let m = DomainMatcher::exact("example.com").unwrap();
        assert!(!m.matches("sub.example.com"));
    }

    #[test]
    fn exact_case_insensitive() {
        let m = DomainMatcher::exact("Example.COM").unwrap();
        assert!(m.matches("example.com"));
        assert!(m.matches("EXAMPLE.COM"));
    }

    // ── Wildcard prefix matching ────────────────────────────────────

    #[test]
    fn wildcard_prefix_matches_subdomain() {
        let m = DomainMatcher::new("*.example.com").unwrap();
        assert!(m.matches("foo.example.com"));
    }

    #[test]
    fn wildcard_prefix_matches_deep_subdomain() {
        let m = DomainMatcher::new("*.example.com").unwrap();
        assert!(m.matches("a.b.example.com"));
    }

    #[test]
    fn wildcard_prefix_does_not_match_base_domain() {
        let m = DomainMatcher::new("*.example.com").unwrap();
        assert!(!m.matches("example.com"));
    }

    #[test]
    fn wildcard_prefix_does_not_match_unrelated() {
        let m = DomainMatcher::new("*.example.com").unwrap();
        assert!(!m.matches("notexample.com"));
    }

    #[test]
    fn wildcard_prefix_case_insensitive() {
        let m = DomainMatcher::new("*.Example.COM").unwrap();
        assert!(m.matches("foo.example.com"));
    }

    // ── Wildcard suffix matching ────────────────────────────────────

    #[test]
    fn wildcard_suffix_matches_different_tld() {
        let m = DomainMatcher::new("example.*").unwrap();
        assert!(m.matches("example.com"));
        assert!(m.matches("example.org"));
    }

    #[test]
    fn wildcard_suffix_does_not_match_partial() {
        let m = DomainMatcher::new("example.*").unwrap();
        assert!(!m.matches("myexample.com"));
    }

    #[test]
    fn wildcard_suffix_case_insensitive() {
        let m = DomainMatcher::new("Example.*").unwrap();
        assert!(m.matches("example.com"));
    }

    // ── Regex matching ──────────────────────────────────────────────

    #[test]
    fn regex_matches_ads_tracker() {
        let m = DomainMatcher::new("~^(ads|tracker)\\.").unwrap();
        assert!(m.matches("ads.example.com"));
        assert!(m.matches("tracker.foo.net"));
        assert!(!m.matches("safe.example.com"));
    }

    #[test]
    fn regex_case_insensitive() {
        let m = DomainMatcher::new("~^ads\\.").unwrap();
        assert!(m.matches("ADS.example.com"));
    }

    // ── Substring matching (backward compat) ────────────────────────

    #[test]
    fn substring_matches_contained() {
        let m = DomainMatcher::new("evil.com").unwrap();
        assert!(m.matches("www.evil.com"));
        assert!(m.matches("evil.com"));
        assert!(m.matches("sub.evil.com.extra"));
    }

    #[test]
    fn substring_does_not_match_absent() {
        let m = DomainMatcher::new("evil.com").unwrap();
        assert!(!m.matches("good.com"));
    }

    #[test]
    fn substring_case_insensitive() {
        let m = DomainMatcher::new("Evil.COM").unwrap();
        assert!(m.matches("www.evil.com"));
    }

    // ── Empty domain input ──────────────────────────────────────────

    #[test]
    fn empty_domain_never_matches() {
        let m = DomainMatcher::new("example.com").unwrap();
        assert!(!m.matches(""));

        let m2 = DomainMatcher::new("*.example.com").unwrap();
        assert!(!m2.matches(""));

        let m3 = DomainMatcher::new("~.").unwrap();
        assert!(!m3.matches(""));

        let m4 = DomainMatcher::exact("example.com").unwrap();
        assert!(!m4.matches(""));
    }

    // ── IDN / punycode ──────────────────────────────────────────────

    #[test]
    fn idn_punycode_wildcard() {
        let m = DomainMatcher::new("*.example.com").unwrap();
        assert!(m.matches("xn--nxasmq6b.example.com"));
    }

    // ── Serde roundtrip ─────────────────────────────────────────────

    #[test]
    fn serde_roundtrip() {
        let m = DomainMatcher::new("*.example.com").unwrap();
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"*.example.com\"");
        let m2: DomainMatcher = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn serde_roundtrip_regex() {
        let m = DomainMatcher::new("~^ads\\.").unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let m2: DomainMatcher = serde_json::from_str(&json).unwrap();
        assert_eq!(m.pattern(), m2.pattern());
    }

    // ── Equality ────────────────────────────────────────────────────

    #[test]
    fn equality_by_pattern() {
        let a = DomainMatcher::new("*.example.com").unwrap();
        let b = DomainMatcher::new("*.example.com").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_patterns() {
        let a = DomainMatcher::new("*.example.com").unwrap();
        let b = DomainMatcher::new("*.other.com").unwrap();
        assert_ne!(a, b);
    }

    // ── Display ─────────────────────────────────────────────────────

    #[test]
    fn display_shows_pattern() {
        let m = DomainMatcher::new("*.example.com").unwrap();
        assert_eq!(format!("{m}"), "*.example.com");
    }
}
