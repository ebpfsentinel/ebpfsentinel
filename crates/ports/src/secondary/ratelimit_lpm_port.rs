use domain::common::error::DomainError;
use ebpf_common::ratelimit::RateLimitConfig;

/// Secondary port for loading country-tier CIDR → rate limit config
/// into the eBPF LPM Trie maps used by xdp-ratelimit.
pub trait RateLimitLpmPort: Send + Sync {
    /// Load IPv4 tier CIDRs. Each tuple: `(prefix_len, addr_bytes, tier_id)`.
    fn load_tier_cidrs_v4(&mut self, entries: &[(u32, [u8; 4], u8)]) -> Result<(), DomainError>;

    /// Load IPv6 tier CIDRs. Each tuple: `(prefix_len, addr_bytes, tier_id)`.
    fn load_tier_cidrs_v6(&mut self, entries: &[(u32, [u8; 16], u8)]) -> Result<(), DomainError>;

    /// Load tier configurations into the `RL_TIER_CONFIG` array map.
    fn load_tier_configs(&mut self, configs: &[(u8, RateLimitConfig)]) -> Result<(), DomainError>;

    /// Clear all entries from the tier CIDR LPM maps.
    fn clear_tier_cidrs(&mut self) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: `RateLimitLpmPort` must be object-safe.
    #[test]
    fn ratelimit_lpm_port_is_object_safe() {
        fn _check(_port: &dyn RateLimitLpmPort) {}
    }
}
