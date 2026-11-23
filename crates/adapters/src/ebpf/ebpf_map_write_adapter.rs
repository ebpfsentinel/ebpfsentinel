use std::net::IpAddr;

use crate::ebpf::threatintel_map_manager::SharedThreatIntelTables;
use domain::common::error::DomainError;
use ebpf_common::threatintel::{THREATINTEL_ACTION_DROP, ThreatIntelValue};
use ports::secondary::ebpf_map_write_port::{EbpfMapWritePort, IocMetadata};
use tracing::info;

/// Adapter implementing `EbpfMapWritePort` for dynamic eBPF map writes.
///
/// Used by the DNS blocklist service to inject and withdraw addresses in the
/// threat intelligence tables at runtime. The tables are shared with
/// `ThreatIntelMapManager`, which keeps the injected addresses apart from the
/// feed set so a feed reload carries them over.
pub struct EbpfMapWriteAdapter {
    tables: SharedThreatIntelTables,
}

impl EbpfMapWriteAdapter {
    /// Create a new adapter with shared access to the threat intel tables.
    pub fn new(tables: SharedThreatIntelTables) -> Self {
        info!("EbpfMapWriteAdapter initialized");
        Self { tables }
    }
}

impl EbpfMapWritePort for EbpfMapWriteAdapter {
    fn inject_threatintel_ip(&self, ip: IpAddr, metadata: &IocMetadata) -> Result<(), DomainError> {
        let value = ThreatIntelValue {
            action: THREATINTEL_ACTION_DROP,
            feed_id: 0, // DNS blocklist feed
            confidence: metadata.confidence,
            threat_type: 0, // THREAT_TYPE_OTHER
        };
        self.tables
            .lock()
            .map_err(|e| {
                DomainError::EngineError(format!("threat intel tables lock poisoned: {e}"))
            })?
            .inject(ip, value)
    }

    fn remove_threatintel_ip(&self, ip: IpAddr) -> Result<(), DomainError> {
        self.tables
            .lock()
            .map_err(|e| {
                DomainError::EngineError(format!("threat intel tables lock poisoned: {e}"))
            })?
            .withdraw(ip)
    }
}
