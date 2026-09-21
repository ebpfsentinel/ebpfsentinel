use crate::ebpf::feature_gates::{self, Feature};
use crate::ebpf::map_store::MapStore;
use aya::maps::{Array, HashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::ids::{IdsPatternKey, IdsPatternValue, IdsSamplingConfig};
use ports::secondary::ids_map_port::IdsMapPort;
use tracing::info;

/// Manages the `IDS_PATTERNS` eBPF `HashMap`.
///
/// Provides typed wrappers around the raw eBPF map for inserting,
/// removing, and clearing IDS patterns. All writes are serialized
/// through `&mut self` (single writer pattern).
pub struct IdsMapManager {
    patterns: HashMap<MapData, IdsPatternKey, IdsPatternValue>,
    src_patterns: HashMap<MapData, IdsPatternKey, IdsPatternValue>,
    sampling_config: Array<MapData, IdsSamplingConfig>,
}

impl IdsMapManager {
    /// Create a new `IdsMapManager` by taking ownership of the
    /// `IDS_PATTERNS` map from the loaded eBPF program.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("IDS_PATTERNS")
            .ok_or_else(|| anyhow::anyhow!("map 'IDS_PATTERNS' not found in eBPF object"))?;
        let patterns = HashMap::try_from(map)?;

        let src_map = ebpf
            .take_map("IDS_SRC_PATTERNS")
            .ok_or_else(|| anyhow::anyhow!("map 'IDS_SRC_PATTERNS' not found in eBPF object"))?;
        let src_patterns = HashMap::try_from(src_map)?;

        let sampling_map = ebpf
            .take_map("IDS_SAMPLING_CONFIG")
            .ok_or_else(|| anyhow::anyhow!("map 'IDS_SAMPLING_CONFIG' not found in eBPF object"))?;
        let sampling_config = Array::try_from(sampling_map)?;

        // The two pattern maps are shared by pin, so a previous run's rules
        // can still be in them. Count what is actually there rather than
        // assuming a fresh map, because a gate published against an
        // assumption would skip a lookup that would have hit.
        feature_gates::publish(Feature::IdsPatterns, patterns.keys().next().is_none());
        feature_gates::publish(
            Feature::IdsSrcPatterns,
            src_patterns.keys().next().is_none(),
        );

        info!("IDS_PATTERNS, IDS_SRC_PATTERNS and IDS_SAMPLING_CONFIG maps acquired");
        Ok(Self {
            patterns,
            src_patterns,
            sampling_config,
        })
    }
}

impl IdsMapPort for IdsMapManager {
    fn insert_pattern(
        &mut self,
        key: &IdsPatternKey,
        value: &IdsPatternValue,
    ) -> Result<(), DomainError> {
        // Open the lookup before the insert, so a rule is never written
        // behind a gate that is still saying the map is empty.
        feature_gates::publish(Feature::IdsPatterns, false);
        self.patterns
            .insert(key, value, 0)
            .map_err(|e| DomainError::EngineError(format!("IDS_PATTERNS insert failed: {e}")))?;
        Ok(())
    }

    fn remove_pattern(&mut self, key: &IdsPatternKey) -> Result<(), DomainError> {
        self.patterns
            .remove(key)
            .map_err(|e| DomainError::EngineError(format!("IDS_PATTERNS remove failed: {e}")))?;
        Ok(())
    }

    fn clear_patterns(&mut self) -> Result<(), DomainError> {
        let keys: Vec<IdsPatternKey> = self.patterns.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.patterns
                .remove(key)
                .map_err(|e| DomainError::EngineError(format!("IDS_PATTERNS clear failed: {e}")))?;
        }
        // Every key is gone, so the lookup can be closed. A removal one key at
        // a time leaves it open until the next load, which is the slower half
        // of the trade and the only one safe to get wrong.
        feature_gates::publish(Feature::IdsPatterns, true);
        Ok(())
    }

    fn insert_src_pattern(
        &mut self,
        key: &IdsPatternKey,
        value: &IdsPatternValue,
    ) -> Result<(), DomainError> {
        feature_gates::publish(Feature::IdsSrcPatterns, false);
        self.src_patterns.insert(key, value, 0).map_err(|e| {
            DomainError::EngineError(format!("IDS_SRC_PATTERNS insert failed: {e}"))
        })?;
        Ok(())
    }

    fn clear_src_patterns(&mut self) -> Result<(), DomainError> {
        let keys: Vec<IdsPatternKey> = self.src_patterns.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.src_patterns.remove(key).map_err(|e| {
                DomainError::EngineError(format!("IDS_SRC_PATTERNS clear failed: {e}"))
            })?;
        }
        feature_gates::publish(Feature::IdsSrcPatterns, true);
        Ok(())
    }

    fn pattern_count(&self) -> Result<usize, DomainError> {
        let count = self.patterns.keys().filter_map(Result::ok).count();
        Ok(count)
    }

    fn set_sampling_config(&mut self, config: &IdsSamplingConfig) -> Result<(), DomainError> {
        self.sampling_config.set(0, config, 0).map_err(|e| {
            DomainError::EngineError(format!("IDS_SAMPLING_CONFIG set failed: {e}"))
        })?;
        Ok(())
    }
}
