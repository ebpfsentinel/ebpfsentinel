//! BGP announcement of the VIPs.
//!
//! The agent speaks no BGP itself. It configures and supervises BIRD, a
//! routing daemon that runs beside it, and reads the sessions back. What
//! this model holds is what the agent asks of that daemon: the local
//! autonomous system, the peers, and the rule that only the node holding
//! the speaker role exports a route for its VIPs. Sessions stay up on
//! every node, so a takeover is a route appearing on an established
//! session rather than a session being brought up.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::error::LbError;

/// Most peers one node may hold a session with.
pub const MAX_BGP_PEERS: usize = 16;

/// Default BGP port.
pub const DEFAULT_BGP_PORT: u16 = 179;

/// Default hold time in seconds, the RFC 4271 suggestion.
pub const DEFAULT_HOLD_TIME_SECS: u16 = 90;

/// One BGP neighbour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpPeer {
    /// Stable label: the daemon's protocol name and the `{peer}` metric
    /// dimension. Lowercase letters, digits and underscores.
    pub name: String,
    pub address: IpAddr,
    pub asn: u32,
    pub port: u16,
    /// Seconds; zero or 3 to 65535 as RFC 4271 allows.
    pub hold_time: u16,
    /// The TCP MD5 secret, already read from its file.
    pub password: Option<String>,
}

/// BGP announcement policy for one node.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpConfig {
    pub enabled: bool,
    pub local_asn: u32,
    /// Router ID; the daemon picks one from the interfaces when unset.
    pub router_id: Option<std::net::Ipv4Addr>,
    pub peers: Vec<BgpPeer>,
}

impl BgpConfig {
    /// Validate the policy; a disabled one is always valid.
    pub fn validate(&self) -> Result<(), LbError> {
        if !self.enabled {
            return Ok(());
        }
        if self.local_asn == 0 {
            return Err(LbError::InvalidService(
                "bgp local_asn must be set".to_string(),
            ));
        }
        if self.peers.is_empty() {
            return Err(LbError::InvalidService(
                "bgp needs at least one peer".to_string(),
            ));
        }
        if self.peers.len() > MAX_BGP_PEERS {
            return Err(LbError::InvalidService(format!(
                "bgp supports at most {MAX_BGP_PEERS} peers"
            )));
        }
        let mut names = HashSet::new();
        let mut addrs = HashSet::new();
        for p in &self.peers {
            if p.name.is_empty()
                || p.name.len() > 32
                || !p
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(LbError::InvalidService(format!(
                    "bgp peer name {:?} must be 1 to 32 lowercase letters, digits or underscores",
                    p.name
                )));
            }
            if !names.insert(p.name.as_str()) {
                return Err(LbError::InvalidService(format!(
                    "bgp peer name {} is used twice",
                    p.name
                )));
            }
            if !addrs.insert(p.address) {
                return Err(LbError::InvalidService(format!(
                    "bgp peer address {} is used twice",
                    p.address
                )));
            }
            if p.asn == 0 {
                return Err(LbError::InvalidService(format!(
                    "bgp peer {} needs an asn",
                    p.name
                )));
            }
            if p.port == 0 {
                return Err(LbError::InvalidService(format!(
                    "bgp peer {} port must not be zero",
                    p.name
                )));
            }
            if (1..3).contains(&p.hold_time) {
                return Err(LbError::InvalidService(format!(
                    "bgp peer {} hold time must be 0 or at least 3 seconds",
                    p.name
                )));
            }
            if let Some(pw) = &p.password
                && (pw.is_empty()
                    || pw.len() > 80
                    || pw.chars().any(|c| c == '"' || c == '\\' || c.is_control()))
            {
                return Err(LbError::InvalidService(format!(
                    "bgp peer {} password must be 1 to 80 printable characters without quotes or backslashes",
                    p.name
                )));
            }
        }
        Ok(())
    }
}

/// State of one BGP session as the daemon reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpSession {
    pub peer: String,
    /// RFC 4271 state: `Idle`, `Connect`, `Active`, `OpenSent`,
    /// `OpenConfirm` or `Established`; `Down` when the protocol is
    /// administratively off.
    pub state: String,
    /// When the session entered that state, as the daemon prints it.
    pub since: String,
    /// The daemon's last error for this session, when it has one.
    pub last_error: Option<String>,
}

impl BgpSession {
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == "Established"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, addr: &str) -> BgpPeer {
        BgpPeer {
            name: name.to_string(),
            address: addr.parse().unwrap(),
            asn: 64512,
            port: DEFAULT_BGP_PORT,
            hold_time: DEFAULT_HOLD_TIME_SECS,
            password: None,
        }
    }

    fn cfg(peers: Vec<BgpPeer>) -> BgpConfig {
        BgpConfig {
            enabled: true,
            local_asn: 64513,
            router_id: None,
            peers,
        }
    }

    #[test]
    fn disabled_is_valid() {
        assert!(BgpConfig::default().validate().is_ok());
    }

    #[test]
    fn valid_policy() {
        assert!(
            cfg(vec![peer("tor1", "10.0.0.1"), peer("tor2", "fd00::1")])
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn refuses_missing_asn_and_peers() {
        let mut c = cfg(vec![peer("tor1", "10.0.0.1")]);
        c.local_asn = 0;
        assert!(c.validate().is_err());
        assert!(cfg(vec![]).validate().is_err());
    }

    #[test]
    fn refuses_duplicate_and_bad_names() {
        assert!(
            cfg(vec![peer("tor1", "10.0.0.1"), peer("tor1", "10.0.0.2")])
                .validate()
                .is_err()
        );
        assert!(
            cfg(vec![peer("a", "10.0.0.1"), peer("b", "10.0.0.1")])
                .validate()
                .is_err()
        );
        assert!(cfg(vec![peer("Tor-1", "10.0.0.1")]).validate().is_err());
        assert!(
            cfg(vec![peer("x\"; protocol", "10.0.0.1")])
                .validate()
                .is_err()
        );
    }

    #[test]
    fn refuses_bad_hold_time_and_password() {
        let mut p = peer("tor1", "10.0.0.1");
        p.hold_time = 2;
        assert!(cfg(vec![p.clone()]).validate().is_err());
        p.hold_time = 0;
        assert!(cfg(vec![p.clone()]).validate().is_ok());
        p.password = Some("a\"b".to_string());
        assert!(cfg(vec![p]).validate().is_err());
    }
}
