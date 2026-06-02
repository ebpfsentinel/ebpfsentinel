use std::sync::Arc;

use domain::common::error::DomainError;
use domain::conntrack::entity::{ConnTrackSettings, Connection};
use ports::secondary::conntrack_map_port::ConnTrackMapPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level conntrack service.
///
/// Orchestrates conntrack configuration and eBPF map access.
/// Designed to be wrapped in `RwLock` for shared access from HTTP handlers.
///
/// When a `netfilter_port` is injected (reading kernel netfilter via
/// `/proc/net/nf_conntrack`), `get_connections` and `connection_count`
/// prefer it as the authoritative source of truth — coherent with
/// `conntrack -L` and any firewall tooling on the host. The BPF
/// `map_port` remains for shadow-table config sync and as a fallback
/// when the netfilter port is unavailable.
pub struct ConnTrackAppService {
    settings: ConnTrackSettings,
    map_port: Option<Box<dyn ConnTrackMapPort + Send>>,
    /// Kernel netfilter reader (via `/proc/net/nf_conntrack`). When
    /// present, takes priority over `map_port` for read operations.
    netfilter_port: Option<Box<dyn ConnTrackMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
}

impl ConnTrackAppService {
    pub fn new(metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            settings: ConnTrackSettings::default(),
            map_port: None,
            netfilter_port: None,
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
        tracing::info!(enabled, "conntrack service toggled");
    }

    /// Set the eBPF map port for kernel map access.
    pub fn set_map_port(&mut self, port: Box<dyn ConnTrackMapPort + Send>) {
        self.map_port = Some(port);
    }

    /// Clear the eBPF map port (program unloaded).
    pub fn clear_map_port(&mut self) {
        self.map_port = None;
    }

    /// Inject a kernel netfilter port that reads the authoritative
    /// conntrack table via `/proc/net/nf_conntrack`. When set, read
    /// operations (`get_connections`, `connection_count`) prefer this
    /// port over the BPF shadow.
    pub fn set_netfilter_port(&mut self, port: Box<dyn ConnTrackMapPort + Send>) {
        self.netfilter_port = Some(port);
    }

    /// Reload conntrack settings and sync to eBPF.
    pub fn reload_settings(&mut self, settings: ConnTrackSettings) -> Result<(), DomainError> {
        self.settings = settings;
        self.sync_ebpf_config();
        tracing::info!("conntrack settings reloaded");
        Ok(())
    }

    /// Get active connections, up to `limit`. Prefers the kernel
    /// netfilter port when available (authoritative), falls back to
    /// the BPF shadow.
    pub fn get_connections(&self, limit: usize) -> Result<Vec<Connection>, DomainError> {
        // Prefer the kernel netfilter reader, but fall back to the BPF shadow
        // when it cannot be read — e.g. a kernel built without
        // CONFIG_NF_CONNTRACK_PROCFS, where the sysctl knobs are still present
        // (so the port is wired for writes) but /proc/net/nf_conntrack is not.
        if let Some(ref nf) = self.netfilter_port
            && let Ok(conns) = nf.get_connections(limit)
        {
            return Ok(conns);
        }
        match self.map_port {
            Some(ref port) => port.get_connections(limit),
            None => Ok(Vec::new()),
        }
    }

    /// Flush all connections. Flushes both kernel netfilter (via
    /// `conntrack -F`) and BPF shadow when both ports are present.
    pub fn flush_all(&mut self) -> Result<u64, DomainError> {
        // Prefer netfilter flush (kernel ground truth).
        let count = if let Some(ref mut nf) = self.netfilter_port {
            nf.flush_all()?
        } else if let Some(ref mut port) = self.map_port {
            port.flush_all()?
        } else {
            return Ok(0);
        };
        // Also flush BPF shadow if netfilter port did the primary flush.
        if self.netfilter_port.is_some()
            && let Some(ref mut port) = self.map_port
        {
            let _ = port.flush_all();
        }
        self.metrics.set_rules_loaded("conntrack", 0);
        self.metrics.set_conntrack_active(0);
        tracing::info!(flushed = count, "conntrack table flushed");
        Ok(count)
    }

    /// Return the current connection count. Prefers kernel netfilter
    /// when available.
    pub fn connection_count(&self) -> Result<u64, DomainError> {
        if let Some(ref nf) = self.netfilter_port
            && let Ok(count) = nf.connection_count()
        {
            return Ok(count);
        }
        match self.map_port {
            Some(ref port) => port.connection_count(),
            None => Ok(0),
        }
    }

    /// Sync current settings to both the eBPF `CT_CONFIG` map and
    /// kernel netfilter sysctl timeouts.
    fn sync_ebpf_config(&mut self) {
        if let Some(ref mut port) = self.map_port
            && let Err(e) = port.set_config(&self.settings)
        {
            tracing::warn!("failed to sync conntrack config to eBPF: {e}");
        }
        if let Some(ref mut nf) = self.netfilter_port
            && let Err(e) = nf.set_config(&self.settings)
        {
            tracing::warn!("failed to sync conntrack config to kernel sysctl: {e}");
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
