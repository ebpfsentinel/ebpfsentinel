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
/// Reads and writes are served by different ports, deliberately. The
/// `netfilter_port` is the only source of connections, and is coherent with
/// `conntrack -L` and any firewall tooling on the host; the BPF `map_port`
/// carries the shadow-table config sync and the write path (add, remove,
/// flush) and holds no connections to read back.
pub struct ConnTrackAppService {
    settings: ConnTrackSettings,
    map_port: Option<Box<dyn ConnTrackMapPort + Send>>,
    /// Kernel netfilter reader, from the proc file or a conntrack-tools dump.
    /// Sole source for `get_connections` and `connection_count`.
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
    ///
    /// The port is handed the settings the service is already holding. It is
    /// wired once the programs are loaded, which is after the configuration
    /// was read and pushed, so a port that waited for the next reload would
    /// wait for one that never comes: `CT_CONFIG` would stay at the zeroes
    /// the map was created with and the per-source guard in `xdp-firewall`
    /// reads that as no limit to enforce.
    pub fn set_map_port(&mut self, port: Box<dyn ConnTrackMapPort + Send>) {
        self.map_port = Some(port);
        self.sync_map_port();
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

    /// Get active connections, up to `limit`, from the kernel netfilter port.
    /// Empty when no port is wired, an error when the table cannot be read.
    pub fn get_connections(&self, limit: usize) -> Result<Vec<Connection>, DomainError> {
        // The netfilter port is the only source of connections: the BPF shadow
        // tables were deleted, so ConnTrackMapManager::get_connections answers
        // Ok(empty) by construction. Falling back to it therefore reported "no
        // connections" for "could not read the connections" - the same answer a
        // genuinely idle host gives, on an endpoint an operator uses to decide
        // whether traffic is flowing. Surface the read failure instead.
        match self.netfilter_port {
            Some(ref nf) => nf.get_connections(limit),
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

    /// Return the current connection count, from the kernel netfilter port.
    /// `None` when no port is wired, an error when the table cannot be read.
    ///
    /// Nothing counted is not a count of nothing: a host with no netfilter
    /// port reports no figure at all, because answering zero there is the
    /// same answer an idle host gives and an operator acts on the second.
    pub fn connection_count(&self) -> Result<Option<u64>, DomainError> {
        // Same reasoning as `get_connections`: the shadow counts nothing, so
        // masking a read failure with it reports an idle host.
        match self.netfilter_port {
            Some(ref nf) => nf.connection_count().map(Some),
            None => Ok(None),
        }
    }

    /// Sync current settings to both the eBPF `CT_CONFIG` map and
    /// kernel netfilter sysctl timeouts.
    fn sync_ebpf_config(&mut self) {
        self.sync_map_port();
        if let Some(ref mut nf) = self.netfilter_port
            && let Err(e) = nf.set_config(&self.settings)
        {
            tracing::warn!("failed to sync conntrack config to kernel sysctl: {e}");
        }
    }

    /// Push the current settings to the eBPF `CT_CONFIG` map, where one is
    /// wired. A failure is reported and never fatal: the map is a mirror of
    /// settings the service holds either way.
    fn sync_map_port(&mut self) {
        if let Some(ref mut port) = self.map_port
            && let Err(e) = port.set_config(&self.settings)
        {
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
        assert_eq!(svc.connection_count().unwrap(), None);
    }

    #[test]
    fn flush_without_map() {
        let mut svc = make_service();
        assert_eq!(svc.flush_all().unwrap(), 0);
    }

    /// Records what the last `set_config` carried, so a test can assert a
    /// port wired after the settings were read still received them.
    struct RecordingMapPort {
        last: Arc<std::sync::Mutex<Option<ConnTrackSettings>>>,
    }

    impl ConnTrackMapPort for RecordingMapPort {
        fn get_connections(&self, _limit: usize) -> Result<Vec<Connection>, DomainError> {
            Ok(Vec::new())
        }

        fn flush_all(&mut self) -> Result<u64, DomainError> {
            Ok(0)
        }

        fn set_config(&mut self, settings: &ConnTrackSettings) -> Result<(), DomainError> {
            *self.last.lock().expect("recording port lock") = Some(settings.clone());
            Ok(())
        }

        fn connection_count(&self) -> Result<u64, DomainError> {
            Ok(0)
        }
    }

    #[test]
    fn map_port_wired_after_reload_receives_the_settings() {
        let mut svc = make_service();
        svc.reload_settings(ConnTrackSettings {
            enabled: true,
            max_src_conn_rate: 3,
            conn_rate_window_secs: 60,
            overload_ttl_secs: 3600,
            ..ConnTrackSettings::default()
        })
        .expect("reload");

        let last = Arc::new(std::sync::Mutex::new(None));
        svc.set_map_port(Box::new(RecordingMapPort {
            last: Arc::clone(&last),
        }));

        let seen = last.lock().expect("recording port lock").clone();
        let seen = seen.expect("wiring the map port pushed no settings");
        assert_eq!(seen.max_src_conn_rate, 3);
        assert_eq!(seen.conn_rate_window_secs, 60);
        assert_eq!(seen.overload_ttl_secs, 3600);
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
