use aya::Ebpf;
use aya::maps::{HashMap, MapData};
use domain::common::error::DomainError;
use domain::ratelimit::entity::RateLimitPolicy;
use ebpf_common::ratelimit::{ALGO_TOKEN_BUCKET, RateLimitConfig, RateLimitKey};
use ports::secondary::ratelimit_map_port::RateLimitMapPort;
use tracing::info;

/// Manages the `RATELIMIT_CONFIG` eBPF `HashMap`.
///
/// Provides typed wrappers around the raw eBPF map for loading and
/// clearing rate limit configurations. The `RATELIMIT_BUCKETS` map
/// (`LruHashMap`) is managed by the kernel; userspace only pushes config.
pub struct RateLimitMapManager {
    config_map: HashMap<MapData, RateLimitKey, RateLimitConfig>,
}

impl RateLimitMapManager {
    /// Create a new `RateLimitMapManager` by taking ownership of the
    /// `RATELIMIT_CONFIG` map from the loaded eBPF program.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("RATELIMIT_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'RATELIMIT_CONFIG' not found in eBPF object"))?;
        let config_map = HashMap::try_from(map)?;
        info!("RATELIMIT_CONFIG map acquired");
        Ok(Self { config_map })
    }

    /// Load rate limit policies into the eBPF config map.
    ///
    /// Clears any existing entries, then inserts per-IP configs and
    /// a default config at key `{src_ip: 0}` using the provided defaults.
    pub fn load_policies(
        &mut self,
        policies: &[RateLimitPolicy],
        default_rate: u64,
        default_burst: u64,
        default_algorithm: u8,
    ) -> Result<(), anyhow::Error> {
        self.clear_config()?;

        // Insert per-policy entries
        for policy in policies {
            if !policy.enabled {
                continue;
            }
            let key = policy.to_ebpf_key();
            let config = policy.to_ebpf_config();
            self.config_map
                .insert(key, config, 0)
                .map_err(|e| anyhow::anyhow!("RATELIMIT_CONFIG insert failed: {e}"))?;
        }

        // Insert default config at key 0 (applies to unmatched source IPs)
        if default_rate > 0 {
            let default_key = RateLimitKey { src_ip: 0 };
            let default_config =
                build_default_config(default_rate, default_burst, default_algorithm);
            self.config_map
                .insert(default_key, default_config, 0)
                .map_err(|e| anyhow::anyhow!("RATELIMIT_CONFIG default insert failed: {e}"))?;
        }

        info!(
            policy_count = policies.len(),
            default_rate = default_rate,
            default_burst = default_burst,
            default_algorithm = default_algorithm,
            "ratelimit policies loaded into eBPF map"
        );
        Ok(())
    }

    /// Remove all entries from the config map.
    pub fn clear_config(&mut self) -> Result<(), anyhow::Error> {
        let keys: Vec<RateLimitKey> = self.config_map.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.config_map
                .remove(key)
                .map_err(|e| anyhow::anyhow!("RATELIMIT_CONFIG clear failed: {e}"))?;
        }
        Ok(())
    }

    /// Return the number of config entries in the map.
    pub fn config_count(&self) -> usize {
        self.config_map.keys().filter_map(Result::ok).count()
    }
}

impl RateLimitMapPort for RateLimitMapManager {
    fn load_policies(
        &mut self,
        policies: &[RateLimitPolicy],
        default_rate: u64,
        default_burst: u64,
        default_algorithm: u8,
    ) -> Result<(), DomainError> {
        self.load_policies(policies, default_rate, default_burst, default_algorithm)
            .map_err(|e| DomainError::EngineError(format!("ratelimit map load failed: {e}")))
    }

    fn clear_config(&mut self) -> Result<(), DomainError> {
        self.clear_config()
            .map_err(|e| DomainError::EngineError(format!("ratelimit map clear failed: {e}")))
    }

    fn config_count(&self) -> Result<usize, DomainError> {
        Ok(self.config_count())
    }
}

/// Build a default `RateLimitConfig` based on algorithm type.
fn build_default_config(rate: u64, burst: u64, algorithm: u8) -> RateLimitConfig {
    match algorithm {
        ebpf_common::ratelimit::ALGO_FIXED_WINDOW | ebpf_common::ratelimit::ALGO_SLIDING_WINDOW => {
            RateLimitConfig {
                ns_per_token: rate,
                burst: 0,
                action: ebpf_common::ratelimit::RATELIMIT_ACTION_DROP,
                algorithm,
                _padding: [0; 6],
            }
        }
        ebpf_common::ratelimit::ALGO_LEAKY_BUCKET => RateLimitConfig {
            ns_per_token: rate,
            burst,
            action: ebpf_common::ratelimit::RATELIMIT_ACTION_DROP,
            algorithm,
            _padding: [0; 6],
        },
        _ => {
            // ALGO_TOKEN_BUCKET or unknown → token bucket
            RateLimitConfig {
                ns_per_token: 1_000_000_000 / rate,
                burst,
                action: ebpf_common::ratelimit::RATELIMIT_ACTION_DROP,
                algorithm: ALGO_TOKEN_BUCKET,
                _padding: [0; 6],
            }
        }
    }
}
