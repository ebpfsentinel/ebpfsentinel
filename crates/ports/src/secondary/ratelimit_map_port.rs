use domain::common::error::DomainError;
use domain::ratelimit::entity::RateLimitPolicy;
use ebpf_common::ratelimit::{RateLimitConfig, RateLimitKey};

/// Secondary port for rate limit eBPF map operations.
///
/// Provides a typed interface to the kernel `RATELIMIT_CONFIG` `HashMap`.
/// Implemented by `RateLimitMapManager` in the adapter layer.
pub trait RateLimitMapPort: Send + Sync {
    /// Load rate limit policies into the eBPF config map.
    ///
    /// Clears existing entries, then inserts per-IP configs and a default
    /// config at key `{tenant_id: 0, src_ip: 0}`.
    fn load_policies(
        &mut self,
        policies: &[RateLimitPolicy],
        default_rate: u64,
        default_burst: u64,
        default_algorithm: u8,
    ) -> Result<(), DomainError>;

    /// Insert or replace a single tenant-scoped config entry.
    ///
    /// The `key` carries the `tenant_id`; a non-zero tenant scopes the config
    /// to that tenant, while `tenant_id == 0` is the global/floating entry. The
    /// kernel resolves the packet's tenant and falls back to the global entry
    /// when no tenant-specific one exists. Unlike [`load_policies`], this is an
    /// incremental upsert that does not clear the map — it is the write path the
    /// enterprise control plane uses to push per-tenant rules without disturbing
    /// the global (tenant-0) configuration.
    ///
    /// [`load_policies`]: RateLimitMapPort::load_policies
    fn upsert_tenant_config(
        &mut self,
        key: RateLimitKey,
        config: RateLimitConfig,
    ) -> Result<(), DomainError>;

    /// Remove a single tenant-scoped config entry. No-op if absent.
    fn remove_tenant_config(&mut self, key: RateLimitKey) -> Result<(), DomainError>;

    /// Remove all entries from the config map.
    fn clear_config(&mut self) -> Result<(), DomainError>;

    /// Return the number of config entries in the map.
    fn config_count(&self) -> Result<usize, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn ratelimit_map_port_is_object_safe() {
        fn _check(port: &dyn RateLimitMapPort) {
            let _ = port.config_count();
        }
    }

    /// In-memory implementation used to exercise the per-tenant write contract.
    #[derive(Default)]
    struct InMemoryRateLimitMap {
        configs: Mutex<HashMap<(u32, u32), RateLimitConfig>>,
    }

    impl RateLimitMapPort for InMemoryRateLimitMap {
        fn load_policies(
            &mut self,
            _policies: &[RateLimitPolicy],
            _default_rate: u64,
            _default_burst: u64,
            _default_algorithm: u8,
        ) -> Result<(), DomainError> {
            Ok(())
        }

        fn upsert_tenant_config(
            &mut self,
            key: RateLimitKey,
            config: RateLimitConfig,
        ) -> Result<(), DomainError> {
            self.configs
                .lock()
                .unwrap()
                .insert((key.tenant_id, key.src_ip), config);
            Ok(())
        }

        fn remove_tenant_config(&mut self, key: RateLimitKey) -> Result<(), DomainError> {
            self.configs
                .lock()
                .unwrap()
                .remove(&(key.tenant_id, key.src_ip));
            Ok(())
        }

        fn clear_config(&mut self) -> Result<(), DomainError> {
            self.configs.lock().unwrap().clear();
            Ok(())
        }

        fn config_count(&self) -> Result<usize, DomainError> {
            Ok(self.configs.lock().unwrap().len())
        }
    }

    fn sample_config() -> RateLimitConfig {
        RateLimitConfig {
            ns_per_token: 1_000,
            burst: 10,
            action: ebpf_common::ratelimit::RATELIMIT_ACTION_DROP,
            algorithm: ebpf_common::ratelimit::ALGO_TOKEN_BUCKET,
            _padding: [0; 2],
            group_mask: 0,
            tenant_id: 0,
            _pad2: [0; 4],
        }
    }

    #[test]
    fn upsert_then_remove_tenant_config() {
        let mut map = InMemoryRateLimitMap::default();
        let tenant_key = RateLimitKey {
            tenant_id: 7,
            src_ip: 0x0A00_0001,
        };
        let global_key = RateLimitKey {
            tenant_id: 0,
            src_ip: 0x0A00_0001,
        };

        map.upsert_tenant_config(tenant_key, sample_config())
            .unwrap();
        map.upsert_tenant_config(global_key, sample_config())
            .unwrap();
        assert_eq!(map.config_count().unwrap(), 2);

        // Removing the tenant entry leaves the global (tenant-0) entry intact.
        map.remove_tenant_config(tenant_key).unwrap();
        assert_eq!(map.config_count().unwrap(), 1);
        assert!(map.configs.lock().unwrap().contains_key(&(0, 0x0A00_0001)));
    }
}
