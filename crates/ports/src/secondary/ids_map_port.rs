use domain::common::error::DomainError;
use ebpf_common::ids::{IdsPatternKey, IdsPatternValue, IdsSamplingConfig};

/// Secondary port for IDS eBPF map operations.
///
/// Provides a typed interface to the kernel `IDS_PATTERNS` `HashMap`.
/// Implemented by `IdsMapManager` in the adapter layer.
pub trait IdsMapPort: Send + Sync {
    /// Insert or update a pattern in the eBPF map.
    fn insert_pattern(
        &mut self,
        key: &IdsPatternKey,
        value: &IdsPatternValue,
    ) -> Result<(), DomainError>;

    /// Remove a pattern from the eBPF map.
    fn remove_pattern(&mut self, key: &IdsPatternKey) -> Result<(), DomainError>;

    /// Remove all patterns from the eBPF map.
    fn clear_patterns(&mut self) -> Result<(), DomainError>;

    /// Insert or update a pattern in the source-port `IDS_SRC_PATTERNS`
    /// map (rules that match on the reply leg). The key's `dst_port` field
    /// carries the source port. Default no-op for backends without the map.
    fn insert_src_pattern(
        &mut self,
        _key: &IdsPatternKey,
        _value: &IdsPatternValue,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    /// Remove all patterns from the source-port map. Default no-op.
    fn clear_src_patterns(&mut self) -> Result<(), DomainError> {
        Ok(())
    }

    /// Return the number of patterns currently in the eBPF map.
    fn pattern_count(&self) -> Result<usize, DomainError>;

    /// Write the kernel-side IDS sampling configuration to the
    /// `IDS_SAMPLING_CONFIG` Array map.
    fn set_sampling_config(&mut self, config: &IdsSamplingConfig) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_map_port_is_object_safe() {
        fn _check(port: &dyn IdsMapPort) {
            let _ = port.pattern_count();
        }
    }
}
