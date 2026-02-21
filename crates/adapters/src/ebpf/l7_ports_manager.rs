use aya::Ebpf;
use aya::maps::{HashMap, MapData};
use tracing::info;

/// Manages the `L7_PORTS` eBPF `HashMap`.
///
/// Used by tc-ids to determine which destination ports should trigger
/// L7 payload capture. Each port maps to a `1u8` marker value.
pub struct L7PortsManager {
    ports_map: HashMap<MapData, u16, u8>,
}

impl L7PortsManager {
    /// Create a new `L7PortsManager` by taking ownership of the
    /// `L7_PORTS` map from the loaded eBPF program.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("L7_PORTS")
            .ok_or_else(|| anyhow::anyhow!("map 'L7_PORTS' not found in eBPF object"))?;
        let ports_map = HashMap::try_from(map)?;
        info!("L7_PORTS map acquired");
        Ok(Self { ports_map })
    }

    /// Replace all L7 capture ports: clear existing, then insert each port.
    pub fn set_ports(&mut self, ports: &[u16]) -> Result<(), anyhow::Error> {
        // Clear existing entries
        let keys: Vec<u16> = self.ports_map.keys().filter_map(Result::ok).collect();
        for key in &keys {
            self.ports_map
                .remove(key)
                .map_err(|e| anyhow::anyhow!("L7_PORTS clear failed: {e}"))?;
        }

        // Insert new ports
        for &port in ports {
            self.ports_map
                .insert(port, 1u8, 0)
                .map_err(|e| anyhow::anyhow!("L7_PORTS insert port={port} failed: {e}"))?;
        }

        info!(port_count = ports.len(), "L7_PORTS updated");
        Ok(())
    }

    /// Return the number of ports currently configured.
    pub fn port_count(&self) -> usize {
        self.ports_map.keys().filter_map(Result::ok).count()
    }
}
