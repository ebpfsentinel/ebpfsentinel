use std::net::IpAddr;

use domain::common::error::DomainError;
use domain::loadbalancer::bgp::{BgpConfig, BgpSession};

/// Secondary port for the routing daemon that announces the VIPs over BGP.
///
/// The agent implements no BGP itself: an adapter renders the policy into
/// the daemon's configuration, asks the daemon to load it, and reads the
/// sessions back. `routes` is the set of VIPs to export, empty while this
/// node does not speak, so a standby keeps its sessions and announces
/// nothing.
pub trait BgpDaemonPort: Send + Sync {
    /// Push the policy and the exported routes, and have the daemon load it.
    fn apply(&self, config: &BgpConfig, routes: &[IpAddr]) -> Result<(), DomainError>;

    /// The daemon's sessions for the peers this agent configured. A peer
    /// missing from the answer is one the daemon does not currently hold,
    /// which is how a daemon restarted on its base configuration shows.
    fn sessions(&self) -> Result<Vec<BgpSession>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Noop;
    impl BgpDaemonPort for Noop {
        fn apply(&self, _config: &BgpConfig, _routes: &[IpAddr]) -> Result<(), DomainError> {
            Ok(())
        }
        fn sessions(&self) -> Result<Vec<BgpSession>, DomainError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn object_safe() {
        let p: Box<dyn BgpDaemonPort> = Box::new(Noop);
        assert!(p.sessions().unwrap().is_empty());
    }
}
