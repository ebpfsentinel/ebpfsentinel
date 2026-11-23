//! Which packets the kernel hands over whole, read off the loaded rules.
//!
//! A rule decided on the packet needs every packet its header can match: the
//! protocols it names, and the ports when it lists them. A rule on `ip`
//! needs every protocol. What no rule asks for is not captured, so a ruleset
//! with none costs the datapath one table read per packet.

use std::collections::BTreeSet;

use super::entity::{IdsRule, PacketProto};

/// Ports a rule may list before it is captured on every port of its
/// protocol instead.
pub const CAPTURE_PORTS_PER_RULE: usize = 64;

/// The `(protocol, port)` pairs the kernel's port table holds at most. Past
/// it the protocols involved are captured whole.
pub const CAPTURE_PORT_ENTRIES: usize = 4096;

/// Protocol numbers whose ports a packet carries where the kernel reads them.
const PORTED: [u8; 2] = [6, 17];

/// What the kernel captures whole.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureSet {
    /// Protocols captured on every port, and with no port at all.
    pub protos: BTreeSet<u8>,
    /// Protocol and port pairs captured when either end of a packet holds the
    /// port.
    pub ports: BTreeSet<(u8, u16)>,
}

impl CaptureSet {
    /// The capture the enabled rules decided on the packet need.
    #[must_use]
    pub fn of(rules: &[IdsRule]) -> Self {
        let mut set = Self::default();
        for rule in rules.iter().filter(|r| r.enabled) {
            let Some(scope) = rule
                .imported
                .as_ref()
                .and_then(|i| i.scope.as_ref())
                .filter(|s| s.on_packet)
            else {
                continue;
            };
            let protos: &[u8] = match scope.proto {
                PacketProto::Ip => &[],
                PacketProto::Tcp | PacketProto::TcpPkt => &[6],
                PacketProto::Udp => &[17],
                PacketProto::Icmp => &[1, 58],
                PacketProto::Icmpv6 => &[58],
            };
            let ports = scope.index_ports(CAPTURE_PORTS_PER_RULE);
            match (scope.proto, ports) {
                // A rule on `ip` naming ports holds only for packets carrying
                // one, so it needs those ports on the protocols that do.
                (PacketProto::Ip, Some(ports)) => {
                    for proto in PORTED {
                        set.ports.extend(ports.iter().map(|&port| (proto, port)));
                    }
                }
                (PacketProto::Ip, None) => set.protos.extend(0..=u8::MAX),
                (PacketProto::Tcp | PacketProto::TcpPkt | PacketProto::Udp, Some(ports)) => {
                    for &proto in protos {
                        set.ports.extend(ports.iter().map(|&port| (proto, port)));
                    }
                }
                _ => set.protos.extend(protos.iter().copied()),
            }
        }
        set.settle()
    }

    /// Drop the ports of a protocol captured whole, and capture whole the
    /// protocols whose ports overflow the kernel table.
    fn settle(mut self) -> Self {
        if self.ports.len() > CAPTURE_PORT_ENTRIES {
            let crowded: BTreeSet<u8> = self.ports.iter().map(|&(proto, _)| proto).collect();
            self.protos.extend(crowded);
        }
        let protos = &self.protos;
        self.ports.retain(|(proto, _)| !protos.contains(proto));
        self
    }

    /// Whether nothing is captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.protos.is_empty() && self.ports.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::suricata::{SuricataVars, compile_rule_admitting};

    fn rules(texts: &[&str]) -> Vec<IdsRule> {
        texts
            .iter()
            .enumerate()
            .flat_map(|(n, text)| {
                let text = text.replace(')', &format!(" sid:{};)", n + 1));
                compile_rule_admitting(&text, &SuricataVars::default(), true).expect("compiles")
            })
            .collect()
    }

    #[test]
    fn a_tcp_content_rule_on_listed_ports_is_left_to_the_payload_capture() {
        let set = CaptureSet::of(&rules(&[
            r#"alert tcp any any -> any 80 (msg:"x"; content:"GET";)"#,
        ]));
        assert!(set.is_empty());
    }

    #[test]
    fn listed_ports_are_captured_on_their_protocol() {
        let set = CaptureSet::of(&rules(&[
            r#"alert udp any any -> any [53,5353] (msg:"x"; content:"a";)"#,
            r#"alert tcp-pkt any 25 -> any any (msg:"x"; content:"a";)"#,
        ]));
        assert!(set.protos.is_empty());
        assert_eq!(
            set.ports.into_iter().collect::<Vec<_>>(),
            vec![(6, 25), (17, 53), (17, 5353)]
        );
    }

    #[test]
    fn a_rule_on_every_port_takes_its_protocol_whole() {
        let set = CaptureSet::of(&rules(&[
            r#"alert tcp any any -> any 80 (msg:"x"; flags:S;)"#,
            r#"alert tcp any any -> any !80 (msg:"x"; content:"a";)"#,
            r#"alert icmp any any -> any any (msg:"x"; itype:8;)"#,
        ]));
        assert_eq!(set.protos.into_iter().collect::<Vec<_>>(), vec![1, 6, 58]);
        assert!(set.ports.is_empty(), "port 80 rides on TCP captured whole");
    }

    #[test]
    fn a_rule_on_ip_takes_every_protocol_or_its_ports_on_tcp_and_udp() {
        let ported = CaptureSet::of(&rules(&[
            r#"alert ip any any -> any 53 (msg:"x"; ttl:>0;)"#,
        ]));
        assert_eq!(
            ported.ports.into_iter().collect::<Vec<_>>(),
            vec![(6, 53), (17, 53)]
        );
        let every = CaptureSet::of(&rules(&[
            r#"alert ip any any -> any any (msg:"x"; ttl:1;)"#,
        ]));
        assert_eq!(every.protos.len(), 256);
    }

    #[test]
    fn ports_past_the_kernel_table_take_their_protocol_whole() {
        let lists: Vec<String> = (0..70u16)
            .map(|block| {
                let ports: Vec<String> = (0..60u16)
                    .map(|n| (1000 + block * 60 + n).to_string())
                    .collect();
                format!(
                    r#"alert udp any any -> any [{}] (msg:"x"; content:"a";)"#,
                    ports.join(",")
                )
            })
            .collect();
        let texts: Vec<&str> = lists.iter().map(String::as_str).collect();
        let set = CaptureSet::of(&rules(&texts));
        assert_eq!(set.protos.into_iter().collect::<Vec<_>>(), vec![17]);
        assert!(set.ports.is_empty());
    }

    #[test]
    fn a_disabled_rule_captures_nothing() {
        let mut compiled = rules(&[r#"alert icmp any any -> any any (msg:"x"; itype:8;)"#]);
        compiled[0].enabled = false;
        assert!(CaptureSet::of(&compiled).is_empty());
    }
}
