use aya::Ebpf;
use aya::maps::{MapData, PerCpuArray, PerCpuValues};
use tracing::info;

/// Reads eBPF per-CPU metric counters from a `PerCpuArray` map.
///
/// Reusable for any `*_METRICS` map (`FIREWALL_METRICS`, `IDS_METRICS`,
/// `RATELIMIT_METRICS`, `THREATINTEL_METRICS`, `DNS_METRICS`, `DLP_METRICS`).
/// Each index stores a u64 counter across all CPUs; `read_metric` sums them.
pub struct MetricsReader {
    metrics_map: PerCpuArray<MapData, u64>,
    map_name: String,
}

impl MetricsReader {
    /// Create a new `MetricsReader` by taking ownership of a named
    /// `PerCpuArray<u64>` map from the loaded eBPF program.
    pub fn new(ebpf: &mut Ebpf, map_name: &str) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map(map_name)
            .ok_or_else(|| anyhow::anyhow!("map '{map_name}' not found in eBPF object"))?;
        let metrics_map = PerCpuArray::try_from(map)?;
        info!(map_name, "PerCpuArray metrics map acquired");
        Ok(Self {
            metrics_map,
            map_name: map_name.to_string(),
        })
    }

    /// Read the metric at `index`, summing values across all CPUs.
    pub fn read_metric(&self, index: u32) -> Result<u64, anyhow::Error> {
        let values: PerCpuValues<u64> = self
            .metrics_map
            .get(&index, 0)
            .map_err(|e| anyhow::anyhow!("{} get index={index} failed: {e}", self.map_name))?;
        let sum: u64 = values.iter().sum();
        Ok(sum)
    }

    /// Return the map name this reader was created for.
    pub fn map_name(&self) -> &str {
        &self.map_name
    }
}
