use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::common::entity::RuleId;
use crate::firewall::entity::PortRange;

use super::error::NatError;

/// NAT rule type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NatType {
    /// Source NAT: rewrite source address/port.
    Snat {
        addr: IpAddr,
        port_range: Option<PortRange>,
    },
    /// Destination NAT: rewrite destination address/port.
    Dnat { addr: IpAddr, port: Option<u16> },
    /// Masquerade: SNAT using the outgoing interface's IP.
    Masquerade {
        interface: String,
        port_range: Option<PortRange>,
    },
    /// 1:1 NAT: bidirectional address mapping.
    OneToOne { external: IpAddr, internal: IpAddr },
    /// Redirect: DNAT to localhost on specified port.
    Redirect { port: u16 },
    /// Port forwarding: map external port range to internal addr:port range.
    PortForward {
        ext_port: PortRange,
        int_addr: IpAddr,
        int_port: PortRange,
    },
}

/// NAT rule with matching criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRule {
    pub id: RuleId,
    pub priority: u32,
    pub nat_type: NatType,
    /// Source CIDR to match (None = any).
    pub match_src: Option<String>,
    /// Destination CIDR to match (None = any).
    pub match_dst: Option<String>,
    /// Destination port to match (None = any).
    pub match_dst_port: Option<PortRange>,
    /// Protocol to match (None = any).
    pub match_protocol: Option<String>,
    pub enabled: bool,
}

impl NatRule {
    pub fn validate(&self) -> Result<(), NatError> {
        self.id.validate().map_err(|reason| NatError::InvalidRule {
            reason: reason.to_string(),
        })?;

        if self.priority == 0 {
            return Err(NatError::InvalidRule {
                reason: "priority must be > 0".to_string(),
            });
        }

        match &self.nat_type {
            NatType::Snat { port_range, .. } | NatType::Masquerade { port_range, .. } => {
                if let Some(range) = port_range
                    && range.start > range.end
                {
                    return Err(NatError::InvalidPortRange {
                        start: range.start,
                        end: range.end,
                    });
                }
            }
            NatType::PortForward {
                ext_port, int_port, ..
            } => {
                if ext_port.start > ext_port.end {
                    return Err(NatError::InvalidPortRange {
                        start: ext_port.start,
                        end: ext_port.end,
                    });
                }
                if int_port.start > int_port.end {
                    return Err(NatError::InvalidPortRange {
                        start: int_port.start,
                        end: int_port.end,
                    });
                }
                let ext_size = ext_port.end - ext_port.start;
                let int_size = int_port.end - int_port.start;
                if ext_size != int_size {
                    return Err(NatError::InvalidRule {
                        reason: "external and internal port ranges must have the same size"
                            .to_string(),
                    });
                }
            }
            NatType::Redirect { port } => {
                if *port == 0 {
                    return Err(NatError::InvalidRule {
                        reason: "redirect port must be > 0".to_string(),
                    });
                }
            }
            NatType::Dnat { .. } | NatType::OneToOne { .. } => {}
        }

        if let Some(ref range) = self.match_dst_port
            && range.start > range.end
        {
            return Err(NatError::InvalidPortRange {
                start: range.start,
                end: range.end,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snat_rule(id: &str) -> NatRule {
        NatRule {
            id: RuleId(id.to_string()),
            priority: 10,
            nat_type: NatType::Snat {
                addr: "10.0.0.1".parse().unwrap(),
                port_range: None,
            },
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            enabled: true,
        }
    }

    #[test]
    fn validate_snat_ok() {
        assert!(make_snat_rule("nat-1").validate().is_ok());
    }

    #[test]
    fn validate_empty_id() {
        let rule = make_snat_rule("");
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_zero_priority() {
        let mut rule = make_snat_rule("nat-1");
        rule.priority = 0;
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_dnat_ok() {
        let rule = NatRule {
            id: RuleId("dnat-1".to_string()),
            priority: 10,
            nat_type: NatType::Dnat {
                addr: "10.0.1.10".parse().unwrap(),
                port: Some(80),
            },
            match_src: None,
            match_dst: None,
            match_dst_port: Some(PortRange {
                start: 8080,
                end: 8080,
            }),
            match_protocol: Some("tcp".to_string()),
            enabled: true,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_masquerade_ok() {
        let rule = NatRule {
            id: RuleId("masq-1".to_string()),
            priority: 10,
            nat_type: NatType::Masquerade {
                interface: "eth0".to_string(),
                port_range: Some(PortRange {
                    start: 10000,
                    end: 60000,
                }),
            },
            match_src: Some("192.168.0.0/16".to_string()),
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            enabled: true,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_one_to_one_ok() {
        let rule = NatRule {
            id: RuleId("1to1".to_string()),
            priority: 10,
            nat_type: NatType::OneToOne {
                external: "203.0.113.50".parse().unwrap(),
                internal: "10.0.2.50".parse().unwrap(),
            },
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            enabled: true,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_redirect_zero_port() {
        let rule = NatRule {
            id: RuleId("redir-1".to_string()),
            priority: 10,
            nat_type: NatType::Redirect { port: 0 },
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            enabled: true,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_port_forward_mismatched_ranges() {
        let rule = NatRule {
            id: RuleId("pf-1".to_string()),
            priority: 10,
            nat_type: NatType::PortForward {
                ext_port: PortRange {
                    start: 8080,
                    end: 8090,
                },
                int_addr: "10.0.1.10".parse().unwrap(),
                int_port: PortRange { start: 80, end: 85 },
            },
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            enabled: true,
        };
        assert!(rule.validate().is_err());
    }

    #[test]
    fn validate_port_forward_ok() {
        let rule = NatRule {
            id: RuleId("pf-1".to_string()),
            priority: 10,
            nat_type: NatType::PortForward {
                ext_port: PortRange {
                    start: 8080,
                    end: 8085,
                },
                int_addr: "10.0.1.10".parse().unwrap(),
                int_port: PortRange { start: 80, end: 85 },
            },
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            enabled: true,
        };
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn validate_invalid_match_port_range() {
        let mut rule = make_snat_rule("nat-1");
        rule.match_dst_port = Some(PortRange {
            start: 500,
            end: 100,
        });
        assert!(rule.validate().is_err());
    }
}
