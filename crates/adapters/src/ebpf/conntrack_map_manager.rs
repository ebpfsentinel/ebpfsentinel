use crate::ebpf::feature_gates::{self, Feature};
use crate::ebpf::map_store::MapStore;
use aya::maps::{Array, MapData};
use domain::common::error::DomainError;
use domain::conntrack::entity::{ConnTrackSettings, Connection};
use ports::secondary::conntrack_map_port::ConnTrackMapPort;
use tracing::info;

/// Manages the eBPF conntrack configuration map.
///
/// The `CT_TABLE_V4`/`V6` shadow maps have been deleted - kernel
/// netfilter is the sole connection tracking engine. This manager now
/// only handles `CT_CONFIG` (timeouts, enable flag) pushed to BPF.
///
/// Connection reads are served by `ProcNetfilterConntrackPort` (e30-2)
/// which reads from `/proc/net/nf_conntrack`.
pub struct ConnTrackMapManager {
    config: Array<MapData, ebpf_common::conntrack::ConnTrackConfig>,
}

impl ConnTrackMapManager {
    /// Create a new `ConnTrackMapManager` by taking ownership of the
    /// `CT_CONFIG` map from the loaded eBPF program.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let config = Array::try_from(
            ebpf.take_map("CT_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("map 'CT_CONFIG' not found"))?,
        )?;

        // Only `check_connection_limits` writes the overload set the firewall
        // probes, and it only runs when one of the two per-source ceilings is
        // configured. Nothing has configured one yet.
        feature_gates::publish(Feature::SourceLimits, true);

        info!("conntrack config map acquired (CT_CONFIG)");
        Ok(Self { config })
    }
}

impl ConnTrackMapPort for ConnTrackMapManager {
    fn get_connections(&self, _limit: usize) -> Result<Vec<Connection>, DomainError> {
        // Shadow tables deleted - connection reads served by
        // ProcNetfilterConntrackPort via /proc/net/nf_conntrack.
        Ok(Vec::new())
    }

    fn flush_all(&mut self) -> Result<u64, DomainError> {
        // Shadow tables deleted - flush via ProcNetfilterConntrackPort
        // (conntrack -F).
        Ok(0)
    }

    fn set_config(&mut self, settings: &ConnTrackSettings) -> Result<(), DomainError> {
        let cfg = settings.to_ebpf_config();
        let limits_off = source_limits_off(&cfg);
        if !limits_off {
            feature_gates::publish(Feature::SourceLimits, false);
        }
        self.config
            .set(0, cfg, 0)
            .map_err(|e| DomainError::EngineError(format!("set CT_CONFIG failed: {e}")))?;
        if limits_off {
            feature_gates::publish(Feature::SourceLimits, true);
        }
        info!(
            enabled = settings.enabled,
            "conntrack config synced to eBPF"
        );
        Ok(())
    }

    fn connection_count(&self) -> Result<u64, DomainError> {
        // Shadow tables deleted - count via ProcNetfilterConntrackPort.
        Ok(0)
    }
}

/// Whether neither per-source ceiling is configured.
///
/// `check_connection_limits` is the only thing that ever writes the overload
/// set the firewall probes on every packet, and it only runs when one of the
/// two is set, so with both at zero the probe can only miss.
fn source_limits_off(cfg: &ebpf_common::conntrack::ConnTrackConfig) -> bool {
    cfg.max_src_states == 0 && cfg.max_src_conn_rate == 0
}

/// Push runtime-resolved `nf_conn` BTF offsets into the
/// `CT_NF_CONN_OFFSETS` BPF array map.
pub fn push_nf_conn_offsets(
    ebpf: &mut dyn MapStore,
    offsets: ebpf_common::conntrack::NfConnOffsets,
) -> Result<(), anyhow::Error> {
    let map = ebpf
        .map_mut("CT_NF_CONN_OFFSETS")
        .ok_or_else(|| anyhow::anyhow!("CT_NF_CONN_OFFSETS map not found"))?;
    let mut arr = aya::maps::Array::<_, ebpf_common::conntrack::NfConnOffsets>::try_from(map)?;
    arr.set(0, offsets, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(max_src_states: u32, max_src_conn_rate: u32) -> ConnTrackSettings {
        ConnTrackSettings {
            max_src_states,
            max_src_conn_rate,
            ..Default::default()
        }
    }

    #[test]
    fn no_ceiling_means_nothing_writes_the_overload_set() {
        assert!(source_limits_off(&config_with(0, 0).to_ebpf_config()));
    }

    #[test]
    fn either_ceiling_on_its_own_reopens_the_probe() {
        assert!(!source_limits_off(&config_with(100, 0).to_ebpf_config()));
        assert!(!source_limits_off(&config_with(0, 50).to_ebpf_config()));
    }
}
