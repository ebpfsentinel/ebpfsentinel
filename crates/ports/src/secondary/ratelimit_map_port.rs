use domain::common::error::DomainError;
use domain::ratelimit::entity::RateLimitPolicy;

/// Secondary port for rate limit eBPF map operations.
///
/// Provides a typed interface to the kernel `RATELIMIT_CONFIG` `HashMap`.
/// Implemented by `RateLimitMapManager` in the adapter layer.
pub trait RateLimitMapPort: Send + Sync {
    /// Load rate limit policies into the eBPF config map.
    ///
    /// Clears existing entries, then inserts per-IP configs and a default
    /// config at key `{src_ip: 0}`.
    fn load_policies(
        &mut self,
        policies: &[RateLimitPolicy],
        default_rate: u64,
        default_burst: u64,
        default_algorithm: u8,
    ) -> Result<(), DomainError>;

    /// Remove all entries from the config map.
    fn clear_config(&mut self) -> Result<(), DomainError>;

    /// Return the number of config entries in the map.
    fn config_count(&self) -> Result<usize, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratelimit_map_port_is_object_safe() {
        fn _check(port: &dyn RateLimitMapPort) {
            let _ = port.config_count();
        }
    }
}
