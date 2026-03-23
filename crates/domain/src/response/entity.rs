use serde::{Deserialize, Serialize};

/// Type of manual response action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    /// Block an IP or CIDR via a temporary firewall deny rule.
    BlockIp,
    /// Apply a temporary rate limit to an IP.
    ThrottleIp,
}

/// A time-bounded manual response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    /// Unique action identifier.
    pub id: String,
    /// Action type (block or throttle).
    pub action_type: ResponseActionType,
    /// Target IP or CIDR (e.g. "1.2.3.4" or "10.0.0.0/24").
    pub target: String,
    /// TTL in seconds.
    pub ttl_secs: u64,
    /// Creation timestamp (nanoseconds since epoch).
    pub created_at_ns: u64,
    /// Expiration timestamp (nanoseconds since epoch).
    pub expires_at_ns: u64,
    /// Underlying rule ID created in the firewall or rate-limiter.
    pub rule_id: String,
    /// Rate limit in packets per second (only for `ThrottleIp`).
    pub rate_pps: Option<u64>,
    /// Whether the action has been revoked early.
    #[serde(default)]
    pub revoked: bool,
}

impl ResponseAction {
    /// Remaining seconds before expiration (0 if expired).
    pub fn remaining_secs(&self, now_ns: u64) -> u64 {
        self.expires_at_ns.saturating_sub(now_ns) / 1_000_000_000
    }

    /// Whether this action has expired or been revoked.
    pub fn is_expired(&self, now_ns: u64) -> bool {
        self.revoked || now_ns >= self.expires_at_ns
    }
}

// ── Simple auto-response (OSS) ──────────────────────────────────────

/// A simple severity-based auto-response policy.
#[derive(Debug, Clone)]
pub struct SimpleResponsePolicy {
    pub name: String,
    pub min_severity: crate::common::entity::Severity,
    pub components: Vec<String>,
    pub action: ResponseActionType,
    pub ttl_secs: u64,
    pub rate_pps: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_action(ttl_secs: u64) -> ResponseAction {
        let now = 1_000_000_000_000u64;
        ResponseAction {
            id: "resp-001".to_string(),
            action_type: ResponseActionType::BlockIp,
            target: "1.2.3.4".to_string(),
            ttl_secs,
            created_at_ns: now,
            expires_at_ns: now + ttl_secs * 1_000_000_000,
            rule_id: "response-resp-001".to_string(),
            rate_pps: None,
            revoked: false,
        }
    }

    #[test]
    fn remaining_secs_before_expiry() {
        let action = make_action(3600);
        let half = action.created_at_ns + 1800 * 1_000_000_000;
        assert_eq!(action.remaining_secs(half), 1800);
    }

    #[test]
    fn remaining_secs_after_expiry() {
        let action = make_action(60);
        let after = action.expires_at_ns + 1_000_000_000;
        assert_eq!(action.remaining_secs(after), 0);
    }

    #[test]
    fn is_expired_before() {
        let action = make_action(3600);
        assert!(!action.is_expired(action.created_at_ns + 1));
    }

    #[test]
    fn is_expired_after() {
        let action = make_action(60);
        assert!(action.is_expired(action.expires_at_ns));
    }

    #[test]
    fn is_expired_when_revoked() {
        let mut action = make_action(3600);
        action.revoked = true;
        assert!(action.is_expired(action.created_at_ns));
    }
}
