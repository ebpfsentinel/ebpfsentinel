use domain::common::error::DomainError;
use domain::conntrack::entity::{ConnTrackSettings, Connection};

/// Secondary port for conntrack eBPF map operations.
///
/// Provides read and control access to the kernel conntrack table
/// (`CT_TABLE_V4`/`CT_TABLE_V6`) and configuration map (`CT_CONFIG`).
///
/// Implemented by a conntrack adapter in the adapter layer.
pub trait ConnTrackMapPort: Send + Sync {
    /// Retrieve active connections from the conntrack table, up to `limit`.
    fn get_connections(&self, limit: usize) -> Result<Vec<Connection>, DomainError>;

    /// Flush all entries from the conntrack table. Returns the number removed.
    fn flush_all(&mut self) -> Result<u64, DomainError>;

    /// Push conntrack configuration (timeouts, enabled flag) to the kernel.
    fn set_config(&mut self, settings: &ConnTrackSettings) -> Result<(), DomainError>;

    /// Return the current number of tracked connections.
    fn connection_count(&self) -> Result<u64, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_map_port_is_object_safe() {
        fn _check(port: &dyn ConnTrackMapPort) {
            let _ = port.connection_count();
        }
    }
}
