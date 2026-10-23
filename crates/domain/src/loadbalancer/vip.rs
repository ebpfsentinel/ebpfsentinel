//! Virtual IP (VIP) announcer domain model.
//!
//! Owns the L2 VIP-announce policy: which IPs this node may claim via ARP,
//! and whether this node is the speaker. Two ways to decide that:
//!
//! - fixed in the configuration, `primary` on one node and `standby` on the
//!   others, promoted by editing the file, and
//! - `elected`, where every node stays silent until something outside it -
//!   the Kubernetes operator, or any orchestrator holding its own lease -
//!   grants it the speaker role for a bounded number of seconds. A grant that
//!   is not renewed lapses on the node itself, so a speaker cut off from its
//!   elector stops answering on its own clock rather than on anybody else's.
//!
//! Split-brain safety is a property of the wiring, not just this model: the
//! userspace agent pushes the VIP set into the kernel map **only** while the
//! node speaks. A silent node's map is empty, so its bounded XDP responder
//! never answers and it never emits gratuitous ARP.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::error::LbError;

/// Longest speaker grant an elector may hand out in one call. A grant is a
/// fence, so it is meant to be short and renewed; five minutes is far past
/// any renewal cadence and still bounds how long a forgotten speaker answers.
pub const MAX_SPEAKER_GRANT_SECS: u32 = 300;

/// Single-speaker role for this node.
///
/// With [`Primary`](AnnounceRole::Primary) and
/// [`Standby`](AnnounceRole::Standby) the configuration decides, and whoever
/// writes it is responsible for never naming two primaries. With
/// [`Elected`](AnnounceRole::Elected) an elector decides, one bounded grant
/// at a time.
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
    /// The node owns the VIP set on paper and stays silent until an elector
    /// grants it the speaker role, and falls silent again when the grant
    /// lapses without being renewed.
    Elected,
}

impl AnnounceRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Primary => "primary",
            Self::Standby => "standby",
            Self::Elected => "elected",
        }
    }

    /// Whether the configuration alone makes this node answer ARP and emit
    /// gratuitous ARP for owned VIPs. An elected node speaks only under a
    /// live grant, which the configuration does not carry.
    pub fn is_speaker(self) -> bool {
        matches!(self, Self::Primary)
    }
}

/// Check the length of a speaker grant before it is honoured. Zero is a
/// release, anything above [`MAX_SPEAKER_GRANT_SECS`] is refused.
pub fn validate_grant_seconds(seconds: u32) -> Result<(), LbError> {
    if seconds > MAX_SPEAKER_GRANT_SECS {
        return Err(LbError::InvalidService(format!(
            "speaker grant of {seconds}s exceeds the {MAX_SPEAKER_GRANT_SECS}s ceiling"
        )));
    }
    Ok(())
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
    /// block. Primary, standby and elected nodes need an interface and a
    /// non-empty, duplicate-free VIP set.
    pub fn validate(&self) -> Result<(), LbError> {
        if self.role == AnnounceRole::Disabled {
            return Ok(());
        }

        if self.interface.trim().is_empty() {
            return Err(LbError::InvalidService(
                "vip announce interface must not be empty when role is primary, standby or elected"
                    .into(),
            ));
        }

        if self.vips.is_empty() {
            return Err(LbError::InvalidService(
                "vip announce role primary, standby or elected requires at least one vip".into(),
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
        assert_eq!(format!("{}", AnnounceRole::Elected), "elected");
        assert_eq!(AnnounceRole::default(), AnnounceRole::Disabled);
    }

    #[test]
    fn only_primary_is_speaker() {
        assert!(AnnounceRole::Primary.is_speaker());
        assert!(!AnnounceRole::Standby.is_speaker());
        assert!(!AnnounceRole::Disabled.is_speaker());
        assert!(!AnnounceRole::Elected.is_speaker());
    }

    #[test]
    fn grant_seconds_bounded() {
        assert!(validate_grant_seconds(0).is_ok());
        assert!(validate_grant_seconds(MAX_SPEAKER_GRANT_SECS).is_ok());
        assert!(validate_grant_seconds(MAX_SPEAKER_GRANT_SECS + 1).is_err());
    }

    #[test]
    fn elected_validates_like_primary_but_is_silent() {
        let cfg = VipAnnounceConfig {
            role: AnnounceRole::Elected,
            interface: "eth0".into(),
            vips: vec![vip("web", v4(192, 0, 2, 10))],
        };
        assert!(cfg.validate().is_ok());
        assert!(!cfg.is_speaker());
        let empty = VipAnnounceConfig {
            role: AnnounceRole::Elected,
            interface: "eth0".into(),
            vips: vec![],
        };
        assert!(empty.validate().is_err());
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
