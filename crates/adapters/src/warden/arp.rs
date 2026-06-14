//! `GratuitousArpPort` backed by the warden (rootless deployment).
//!
//! On VIP-speaker takeover the agent broadcasts a gratuitous ARP so upstream
//! switches relearn the MAC. That needs an `AF_PACKET`/`SOCK_RAW` socket, which
//! the capability-dropped agent cannot create (`CAP_NET_RAW`). The rootless agent
//! therefore asks the warden — which holds the capability and resolves the
//! interface MAC itself — to emit the gratuitous ARP over its typed protocol.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::loadbalancer::vip::Vip;
use ebpfsentinel_warden_client::ReconnectingClient;
use ports::secondary::vip_announcer_port::GratuitousArpPort;
use tracing::debug;

/// `GratuitousArpPort` that proxies the broadcast to the warden.
pub struct WardenGratuitousArp {
    client: Mutex<ReconnectingClient>,
}

impl WardenGratuitousArp {
    /// Build an adapter talking to the warden at `sock`.
    #[must_use]
    pub fn new(sock: PathBuf) -> Self {
        Self {
            client: Mutex::new(ReconnectingClient::new(sock)),
        }
    }
}

impl GratuitousArpPort for WardenGratuitousArp {
    fn send_gratuitous_arp(
        &self,
        interface: &str,
        _src_mac: [u8; 6],
        vip: &Vip,
    ) -> Result<(), DomainError> {
        // The warden resolves the NIC MAC itself, so `src_mac` is unused here.
        // IPv6 VIPs use unsolicited neighbour advertisement, out of scope (mirrors
        // the raw-socket adapter).
        let v4 = match vip.addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                debug!(vip = %vip.name, "warden gratuitous ARP skipped for IPv6 VIP (ND is out of scope)");
                return Ok(());
            }
        };
        let mut client = self
            .client
            .lock()
            .map_err(|_| DomainError::EngineError("warden client lock poisoned".into()))?;
        client
            .arp_announce(interface, &v4.to_string())
            .map_err(|e| DomainError::EngineError(format!("warden arp_announce failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::WardenGratuitousArp;
    use domain::loadbalancer::vip::Vip;
    use ports::secondary::vip_announcer_port::GratuitousArpPort;

    #[test]
    fn ipv6_vip_is_a_noop_without_contacting_the_warden() {
        // A v6 VIP returns Ok without ever locking/dialing the (absent) warden.
        let arp = WardenGratuitousArp::new("/nonexistent/warden.sock".into());
        let vip = Vip {
            name: "v6".into(),
            addr: "2001:db8::1".parse().unwrap(),
        };
        assert!(arp.send_gratuitous_arp("lo", [0; 6], &vip).is_ok());
    }
}
