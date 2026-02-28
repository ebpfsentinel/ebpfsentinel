use std::sync::Arc;

use domain::common::error::DomainError;
use domain::conntrack::entity::{ConnTrackSettings, Connection};
use ports::secondary::conntrack_map_port::ConnTrackMapPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level conntrack service.
///
/// Orchestrates conntrack configuration and eBPF map access.
/// Designed to be wrapped in `RwLock` for shared access from HTTP handlers.
pub struct ConnTrackAppService {
    settings: ConnTrackSettings,
    map_port: Option<Box<dyn ConnTrackMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
}

impl ConnTrackAppService {
    pub fn new(metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            settings: ConnTrackSettings::default(),
            map_port: None,
            metrics,
            enabled: false,
        }
    }

    /// Return whether conntrack is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.settings.enabled = enabled;
    }

    /// Set the eBPF map port for kernel map access.
    pub fn set_map_port(&mut self, port: Box<dyn ConnTrackMapPort + Send>) {
        self.map_port = Some(port);
    }

    /// Reload conntrack settings and sync to eBPF.
    pub fn reload_settings(&mut self, settings: ConnTrackSettings) -> Result<(), DomainError> {
        self.settings = settings;
        self.sync_ebpf_config();
        Ok(())
    }

    /// Get active connections, up to `limit`.
    pub fn get_connections(&self, limit: usize) -> Result<Vec<Connection>, DomainError> {
        match self.map_port {
            Some(ref port) => port.get_connections(limit),
            None => Ok(Vec::new()),
        }
    }

    /// Flush all connections. Returns the count removed.
    pub fn flush_all(&mut self) -> Result<u64, DomainError> {
        match self.map_port {
            Some(ref mut port) => {
                let count = port.flush_all()?;
                self.metrics.set_rules_loaded("conntrack", 0);
                Ok(count)
            }
            None => Ok(0),
        }
    }

    /// Return the current connection count.
    pub fn connection_count(&self) -> Result<u64, DomainError> {
        match self.map_port {
            Some(ref port) => port.connection_count(),
            None => Ok(0),
        }
    }

    /// Sync current settings to the eBPF `CT_CONFIG` map.
    fn sync_ebpf_config(&mut self) {
        let Some(ref mut port) = self.map_port else {
            return;
        };

        if let Err(e) = port.set_config(&self.settings) {
            tracing::warn!("failed to sync conntrack config to eBPF: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ports::test_utils::NoopMetrics;

    fn make_service() -> ConnTrackAppService {
        ConnTrackAppService::new(Arc::new(NoopMetrics))
    }

    #[test]
    fn default_disabled() {
        let svc = make_service();
        assert!(!svc.enabled());
    }

    #[test]
    fn enable_disable() {
        let mut svc = make_service();
        svc.set_enabled(true);
        assert!(svc.enabled());
        svc.set_enabled(false);
        assert!(!svc.enabled());
    }

    #[test]
    fn connections_without_map() {
        let svc = make_service();
        let conns = svc.get_connections(100).unwrap();
        assert!(conns.is_empty());
    }

    #[test]
    fn connection_count_without_map() {
        let svc = make_service();
        assert_eq!(svc.connection_count().unwrap(), 0);
    }

    #[test]
    fn flush_without_map() {
        let mut svc = make_service();
        assert_eq!(svc.flush_all().unwrap(), 0);
    }

    #[test]
    fn reload_settings() {
        let mut svc = make_service();
        let settings = ConnTrackSettings {
            enabled: true,
            tcp_established_timeout_secs: 1000,
            ..ConnTrackSettings::default()
        };
        assert!(svc.reload_settings(settings).is_ok());
    }
}
