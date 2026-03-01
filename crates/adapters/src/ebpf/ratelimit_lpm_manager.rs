use aya::Ebpf;
use aya::maps::Array;
use aya::maps::MapData;
use aya::maps::lpm_trie::{Key, LpmTrie};
use domain::common::error::DomainError;
use ebpf_common::ratelimit::{RateLimitConfig, RateLimitTierValue};
use ports::secondary::ratelimit_lpm_port::RateLimitLpmPort;
use tracing::info;

/// Manages the 3 eBPF maps for country-tier rate limiting:
/// `RL_LPM_SRC_V4`, `RL_LPM_SRC_V6`, and `RL_TIER_CONFIG`.
pub struct RateLimitLpmManager {
    lpm_src_v4: LpmTrie<MapData, [u8; 4], RateLimitTierValue>,
    lpm_src_v6: LpmTrie<MapData, [u8; 16], RateLimitTierValue>,
    tier_config: Array<MapData, RateLimitConfig>,
}

impl RateLimitLpmManager {
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let lpm_src_v4 = LpmTrie::try_from(
            ebpf.take_map("RL_LPM_SRC_V4")
                .ok_or_else(|| anyhow::anyhow!("map 'RL_LPM_SRC_V4' not found"))?,
        )?;
        let lpm_src_v6 = LpmTrie::try_from(
            ebpf.take_map("RL_LPM_SRC_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'RL_LPM_SRC_V6' not found"))?,
        )?;
        let tier_config = Array::try_from(
            ebpf.take_map("RL_TIER_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("map 'RL_TIER_CONFIG' not found"))?,
        )?;

        info!("Rate limit LPM maps acquired from xdp-ratelimit");
        Ok(Self {
            lpm_src_v4,
            lpm_src_v6,
            tier_config,
        })
    }
}

impl RateLimitLpmPort for RateLimitLpmManager {
    fn load_tier_cidrs_v4(&mut self, entries: &[(u32, [u8; 4], u8)]) -> Result<(), DomainError> {
        for &(prefix_len, addr, tier_id) in entries {
            let key = Key::new(prefix_len, addr);
            let value = RateLimitTierValue {
                tier_id,
                _padding: [0; 3],
            };
            self.lpm_src_v4
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("RL LPM V4 insert failed: {e}")))?;
        }
        info!(count = entries.len(), "rate limit LPM V4 CIDRs loaded");
        Ok(())
    }

    fn load_tier_cidrs_v6(&mut self, entries: &[(u32, [u8; 16], u8)]) -> Result<(), DomainError> {
        for &(prefix_len, addr, tier_id) in entries {
            let key = Key::new(prefix_len, addr);
            let value = RateLimitTierValue {
                tier_id,
                _padding: [0; 3],
            };
            self.lpm_src_v6
                .insert(&key, value, 0)
                .map_err(|e| DomainError::EngineError(format!("RL LPM V6 insert failed: {e}")))?;
        }
        info!(count = entries.len(), "rate limit LPM V6 CIDRs loaded");
        Ok(())
    }

    fn load_tier_configs(&mut self, configs: &[(u8, RateLimitConfig)]) -> Result<(), DomainError> {
        for &(tier_id, ref config) in configs {
            self.tier_config
                .set(u32::from(tier_id), *config, 0)
                .map_err(|e| {
                    DomainError::EngineError(format!(
                        "RL tier config set failed for tier {tier_id}: {e}"
                    ))
                })?;
        }
        info!(count = configs.len(), "rate limit tier configs loaded");
        Ok(())
    }

    fn clear_tier_cidrs(&mut self) -> Result<(), DomainError> {
        // Clear V4
        let keys: Vec<Key<[u8; 4]>> = self.lpm_src_v4.keys().filter_map(Result::ok).collect();
        for key in &keys {
            let _ = self.lpm_src_v4.remove(key);
        }
        // Clear V6
        let keys: Vec<Key<[u8; 16]>> = self.lpm_src_v6.keys().filter_map(Result::ok).collect();
        for key in &keys {
            let _ = self.lpm_src_v6.remove(key);
        }
        info!("rate limit LPM tier CIDRs cleared");
        Ok(())
    }
}
