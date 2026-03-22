use aya::Ebpf;
use aya::maps::CpuMap;
use tracing::{debug, info};

/// Populate a CpuMap with all online CPUs for packet steering.
/// Each entry gets a default queue size of 192 packets.
/// If the map is not found or cannot be converted, this is a no-op
/// (graceful degradation — eBPF programs fall back to XDP_DROP).
pub fn populate_cpumap(ebpf: &mut Ebpf, map_name: &str) {
    let map = match ebpf.map_mut(map_name) {
        Some(m) => m,
        None => {
            debug!(map_name, "CpuMap not found (non-fatal)");
            return;
        }
    };
    let mut cpumap: CpuMap<_> = match CpuMap::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            debug!(map_name, error = %e, "CpuMap conversion failed (non-fatal)");
            return;
        }
    };

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4);
    let queue_size = 192u32;
    let mut populated = 0u32;
    for cpu in 0..num_cpus.min(128) {
        if cpumap.set(cpu, queue_size, None, 0).is_ok() {
            populated += 1;
        }
    }
    info!(
        map_name,
        cpus = populated,
        "CpuMap populated for CPU steering"
    );
}
