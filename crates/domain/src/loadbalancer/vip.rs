//! Virtual IP (VIP) announcer domain model.
//!
//! Owns the L2 VIP-announce policy: which IPs this node may claim via ARP,
//! and whether this node is the elected speaker. Election is config-driven
//! (explicit `primary`/`standby`); there is no gossip or leader-lease layer
//! in the domain — the Kubernetes Lease seam is documented in the operator
//! but deliberately not implemented here.
//!
//! Split-brain safety is a property of the wiring, not just this model: the
//! userspace agent pushes the VIP set into the kernel map **only** while
//! [`AnnounceRole::Primary`]. A standby node's map is empty, so its bounded
//! XDP responder never answers and it never emits gratuitous ARP.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::error::LbError;

/// Single-speaker election role for this node.
///
/// Election is explicit and config-driven. Exactly one node in an L2
/// failover pair should be [`Primary`](AnnounceRole::Primary) at a time;
/// operator tooling (or a future k8s Lease) is responsible for not
/// configuring two primaries simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnounceRole {
    /// VIP announcing is turned off entirely on this node.
    #[default]
    Disabled,
    /// This node is the elected speaker: it claims every owned VIP via
    /// ARP and emits gratuitous ARP on takeover.
    Primary,
    /// This node is a hot standby: it owns the same VIP set on paper but
    /// stays silent until promoted to [`Primary`](AnnounceRole::Primary).
    Standby,
}

impl AnnounceRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Primary => "primary",
            Self::Standby => "standby",
        }
    }

    /// Whether this node should actively answer ARP and emit gratuitous
    /// ARP for owned VIPs.
    pub fn is_speaker(self) -> bool {
        matches!(self, Self::Primary)
    }
}

impl std::fmt::Display for AnnounceRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single owned virtual IP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vip {
    /// Stable label used as the Prometheus `{vip}` dimension and in logs.
    pub name: String,
    /// The virtual IP address this node may claim on the L2 segment.
    pub addr: IpAddr,
}

impl Vip {
    /// Validate a single VIP entry.
    ///
    /// Rejects empty names and addresses that can never be the target of
    /// a meaningful ARP request (unspecified, loopback, multicast).
    pub fn validate(&self) -> Result<(), LbError> {
        if self.name.trim().is_empty() {
            return Err(LbError::InvalidService("vip name must not be empty".into()));
        }
        if self.addr.is_unspecified() || self.addr.is_loopback() || self.addr.is_multicast() {
            return Err(LbError::InvalidService(format!(
                "vip '{}' has a non-announceable address {}",
                self.name, self.addr
            )));
        }
        Ok(())
    }
}

/// Node-level VIP announce policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VipAnnounceConfig {
    /// Single-speaker role for this node.
    #[serde(default)]
    pub role: AnnounceRole,
    /// L2 interface the VIPs live on (the ARP responder egresses here on
    /// `XDP_TX`; gratuitous ARP is sent from its NIC MAC).
    #[serde(default)]
    pub interface: String,
    /// The set of VIPs this node owns.
    #[serde(default)]
    pub vips: Vec<Vip>,
}

impl VipAnnounceConfig {
    /// Whether this node is the elected speaker (drives whether the agent
    /// pushes the VIP set into the kernel map).
    pub fn is_speaker(&self) -> bool {
        self.role.is_speaker()
    }

    /// Validate the announce policy.
    ///
    /// A `disabled` node is always valid regardless of the rest of the
    /// block. Primary/standby nodes need an interface and a non-empty,
    /// duplicate-free VIP set.
    pub fn validate(&self) -> Result<(), LbError> {
        if self.role == AnnounceRole::Disabled {
            return Ok(());
        }

        if self.interface.trim().is_empty() {
            return Err(LbError::InvalidService(
                "vip announce interface must not be empty when role is primary/standby".into(),
            ));
        }

        if self.vips.is_empty() {
            return Err(LbError::InvalidService(
                "vip announce role primary/standby requires at least one vip".into(),
            ));
        }

        let mut seen_names = HashSet::new();
        let mut seen_addrs = HashSet::new();
        for vip in &self.vips {
            vip.validate()?;
            if !seen_names.insert(vip.name.as_str()) {
                return Err(LbError::InvalidService(format!(
                    "duplicate vip name: {}",
                    vip.name
                )));
            }
            if !seen_addrs.insert(vip.addr) {
                return Err(LbError::InvalidService(format!(
                    "duplicate vip address: {}",
                    vip.addr
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn vip(name: &str, addr: IpAddr) -> Vip {
        Vip {
            name: name.to_string(),
            addr,
        }
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn role_display_and_default() {
        assert_eq!(format!("{}", AnnounceRole::Disabled), "disabled");
        assert_eq!(format!("{}", AnnounceRole::Primary), "primary");
        assert_eq!(format!("{}", AnnounceRole::Standby), "standby");
        assert_eq!(AnnounceRole::default(), AnnounceRole::Disabled);
    }

    #[test]
    fn only_primary_is_speaker() {
        assert!(AnnounceRole::Primary.is_speaker());
        assert!(!AnnounceRole::Standby.is_speaker());
        assert!(!AnnounceRole::Disabled.is_speaker());
    }

    #[test]
    fn role_serde_lowercase() {
        let json = serde_json::to_string(&AnnounceRole::Primary).unwrap();
        assert_eq!(json, "\"primary\"");
        let parsed: AnnounceRole = serde_json::from_str("\"standby\"").unwrap();
        assert_eq!(parsed, AnnounceRole::Standby);
    }

    #[test]
    fn vip_validate_ok() {
        assert!(vip("web", v4(192, 0, 2, 10)).validate().is_ok());
        assert!(
            vip(
                "web6",
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            )
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn vip_rejects_empty_name() {
        assert!(vip("  ", v4(192, 0, 2, 10)).validate().is_err());
    }

    #[test]
    fn vip_rejects_non_announceable_addrs() {
        assert!(vip("z", v4(0, 0, 0, 0)).validate().is_err());
        assert!(vip("lo", v4(127, 0, 0, 1)).validate().is_err());
        assert!(vip("mc", v4(224, 0, 0, 1)).validate().is_err());
    }

    #[test]
    fn disabled_config_always_valid() {
        let cfg = VipAnnounceConfig::default();
        assert_eq!(cfg.role, AnnounceRole::Disabled);
        assert!(!cfg.is_speaker());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn primary_requires_interface() {
        let cfg = VipAnnounceConfig {
            role: AnnounceRole::Primary,
            interface: String::new(),
            vips: vec![vip("web", v4(192, 0, 2, 10))],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn primary_requires_non_empty_vips() {
        let cfg = VipAnnounceConfig {
            role: AnnounceRole::Primary,
            interface: "eth0".into(),
            vips: vec![],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn standby_validates_like_primary_but_is_silent() {
        let cfg = VipAnnounceConfig {
            role: AnnounceRole::Standby,
            interface: "eth0".into(),
            vips: vec![vip("web", v4(192, 0, 2, 10))],
        };
        assert!(cfg.validate().is_ok());
        assert!(!cfg.is_speaker());
    }

    #[test]
    fn rejects_duplicate_vip_name() {
        let cfg = VipAnnounceConfig {
            role: AnnounceRole::Primary,
            interface: "eth0".into(),
            vips: vec![vip("web", v4(192, 0, 2, 10)), vip("web", v4(192, 0, 2, 11))],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_vip_addr() {
        let cfg = VipAnnounceConfig {
            role: AnnounceRole::Primary,
            interface: "eth0".into(),
            vips: vec![vip("a", v4(192, 0, 2, 10)), vip("b", v4(192, 0, 2, 10))],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn valid_primary_config() {
        let cfg = VipAnnounceConfig {
            role: AnnounceRole::Primary,
            interface: "eth0".into(),
            vips: vec![vip("web", v4(192, 0, 2, 10)), vip("api", v4(192, 0, 2, 11))],
        };
        assert!(cfg.validate().is_ok());
        assert!(cfg.is_speaker());
    }
}
