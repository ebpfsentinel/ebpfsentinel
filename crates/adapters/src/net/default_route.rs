//! Default-route programming for multi-WAN failover.
//!
//! Writing the main routing table is a `CAP_NET_ADMIN` operation. The rootless
//! agent has no such capability, so it asks the warden over its typed protocol
//! (selected by `EBPFSENTINEL_WARDEN_SOCK`); a privileged agent runs `ip route
//! replace` itself.

use std::path::PathBuf;
use std::sync::Mutex;

use domain::common::error::DomainError;
use ebpfsentinel_warden_client::{ReconnectingClient, RouteSpec};
use ports::secondary::default_route_port::DefaultRoutePort;

/// Env var carrying the warden control-plane socket path.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// Main routing table, the one the kernel consults for unpolicied traffic.
const MAIN_TABLE: u32 = 254;

/// Destination of a default route.
const DEFAULT_DST: &str = "0.0.0.0/0";

/// Installs the elected gateway as the host default route.
pub struct IpDefaultRoute {
    /// Warden control-plane client. Present for the rootless agent, in which
    /// case the route write is proxied instead of executed locally. Held behind
    /// a `Mutex` because the port method takes `&self`.
    warden: Option<Mutex<ReconnectingClient>>,
}

impl IpDefaultRoute {
    /// Build the adapter, proxying through the warden when one is configured.
    #[must_use]
    pub fn new() -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| Mutex::new(ReconnectingClient::new(p)));
        Self { warden }
    }
}

impl Default for IpDefaultRoute {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultRoutePort for IpDefaultRoute {
    fn replace_default_route(&self, gateway_ip: &str, interface: &str) -> Result<(), DomainError> {
        let spec = RouteSpec {
            dst_cidr: DEFAULT_DST.to_owned(),
            gateway: gateway_ip.to_owned(),
            iface: interface.to_owned(),
            table: MAIN_TABLE,
        };
        if let Some(warden) = &self.warden {
            warden
                .lock()
                .map_err(|_| DomainError::EngineError("warden client lock poisoned".into()))?
                .route_add(&spec)
                .map_err(|e| {
                    DomainError::EngineError(format!("warden default route replace failed: {e}"))
                })?;
            tracing::info!(
                gateway = gateway_ip,
                interface,
                "default route programmed via warden"
            );
            return Ok(());
        }
        let status = std::process::Command::new("ip")
            .args([
                "route",
                "replace",
                DEFAULT_DST,
                "via",
                gateway_ip,
                "dev",
                interface,
                "table",
                "main",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| {
                DomainError::EngineError(format!(
                    "failed to run `ip route replace`: {e} (iproute2 installed?)"
                ))
            })?;
        if !status.success() {
            return Err(DomainError::EngineError(format!(
                "`ip route replace {DEFAULT_DST} via {gateway_ip} dev {interface}` exited with status {status} (CAP_NET_ADMIN?)"
            )));
        }
        tracing::info!(gateway = gateway_ip, interface, "default route programmed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_warden_socket_the_adapter_execs_locally() {
        // The env var drives the choice; an unset var must leave no client behind.
        let port = IpDefaultRoute::new();
        assert_eq!(
            port.warden.is_some(),
            std::env::var_os(WARDEN_SOCK_ENV).is_some()
        );
    }
}
