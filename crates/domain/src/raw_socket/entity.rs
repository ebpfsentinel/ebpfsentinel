use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;

/// The component an alert about a packet socket carries.
pub const RAW_SOCKET_COMPONENT: &str = "raw_socket";

/// The rule id of the alert raised for a socket that appeared.
pub const RAW_SOCKET_RULE_ID: &str = "raw-socket-opened";

/// How the socket hands frames over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawSocketKind {
    /// `SOCK_RAW`: whole frames, link-layer header included.
    Raw,
    /// `SOCK_DGRAM`: frames with the link-layer header removed.
    Dgram,
    /// A type the kernel reported and this agent does not name.
    Other,
}

impl RawSocketKind {
    /// The kind behind a socket type number.
    #[must_use]
    pub fn from_type(socket_type: u16) -> Self {
        match socket_type {
            3 => Self::Raw,
            2 => Self::Dgram,
            _ => Self::Other,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Dgram => "dgram",
            Self::Other => "other",
        }
    }
}

/// What is known of the classic BPF filter attached to a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum FilterState {
    /// The kernel was not asked or would not answer: the reader lacked the
    /// privilege over the socket's namespace.
    Unknown,
    /// No classic filter: the socket receives every frame its protocol and
    /// interface let through.
    Absent,
    /// A classic BPF filter of this many instructions.
    Classic { instructions: u32 },
}

impl FilterState {
    /// The state behind an instruction count, `None` being "not known".
    #[must_use]
    pub fn from_count(count: Option<u32>) -> Self {
        match count {
            None => Self::Unknown,
            Some(0) => Self::Absent,
            Some(instructions) => Self::Classic { instructions },
        }
    }

    #[must_use]
    pub fn is_attached(self) -> bool {
        matches!(self, Self::Classic { .. })
    }
}

/// One packet socket open on the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawSocket {
    /// The socket's inode, unique within its network namespace.
    pub inode: u64,
    pub kind: RawSocketKind,
    /// The ethertype it receives, in host order: `0x0003` for every
    /// protocol, `0` for none until it is bound.
    pub protocol: u16,
    /// The interface it is bound to, `0` for every interface.
    pub ifindex: u32,
    /// The interface's name, where the reader could resolve it.
    pub interface: Option<String>,
    /// The uid that opened it.
    pub uid: u32,
    /// The inode of its network namespace.
    pub netns: u64,
    /// Whether that namespace is the host's.
    pub host_netns: bool,
    /// The process holding it, where a descriptor names it.
    pub pid: Option<u32>,
    pub filter: FilterState,
}

impl RawSocket {
    /// The ethertype as a word a person reads, or its hex value.
    #[must_use]
    pub fn protocol_name(&self) -> String {
        match self.protocol {
            0x0000 => "none".to_string(),
            0x0003 => "all".to_string(),
            0x0800 => "ipv4".to_string(),
            0x0806 => "arp".to_string(),
            0x86dd => "ipv6".to_string(),
            0x8100 => "vlan".to_string(),
            0x8035 => "rarp".to_string(),
            0x888e => "eapol".to_string(),
            0x88cc => "lldp".to_string(),
            0x8863 | 0x8864 => "pppoe".to_string(),
            other => format!("0x{other:04x}"),
        }
    }

    /// The interface as a person reads it: its name, its index, or `any`.
    #[must_use]
    pub fn interface_label(&self) -> String {
        match (&self.interface, self.ifindex) {
            (Some(name), _) => name.clone(),
            (None, 0) => "any".to_string(),
            (None, index) => format!("#{index}"),
        }
    }

    /// The key a socket keeps between two readings.
    #[must_use]
    pub fn key(&self) -> (u64, u64) {
        (self.netns, self.inode)
    }

    /// The rule id of the alert raised when it appears.
    #[must_use]
    pub fn rule_id() -> RuleId {
        RuleId(RAW_SOCKET_RULE_ID.to_string())
    }

    /// A socket filter is how a frame reaches a process without the stack
    /// seeing it, which is the shape of a backdoor waiting for a magic
    /// packet.
    #[must_use]
    pub fn mitre() -> MitreAttackInfo {
        MitreAttackInfo {
            technique_id: "T1205.002".to_string(),
            technique_name: "Traffic Signaling: Socket Filters".to_string(),
            tactic: "defense-evasion".to_string(),
        }
    }

    /// The alert's sentence.
    #[must_use]
    pub fn message(&self) -> String {
        let holder = self
            .pid
            .map_or_else(|| "no process".to_string(), |pid| format!("pid {pid}"));
        let filter = match self.filter {
            FilterState::Classic { instructions } => {
                format!(", classic BPF filter of {instructions} instructions attached")
            }
            FilterState::Absent => ", no filter".to_string(),
            FilterState::Unknown => ", filter unknown".to_string(),
        };
        let namespace = if self.host_netns {
            "host network namespace"
        } else {
            "a pod or container network namespace"
        };
        format!(
            "packet socket opened by {holder} (uid {}): {} protocol {} on {} in the {namespace}{filter}",
            self.uid,
            self.kind.as_str(),
            self.protocol_name(),
            self.interface_label(),
        )
    }
}

/// The sockets of `current` that `previous` did not hold.
#[must_use]
pub fn new_sockets<'a>(previous: &[RawSocket], current: &'a [RawSocket]) -> Vec<&'a RawSocket> {
    let known: HashSet<(u64, u64)> = previous.iter().map(RawSocket::key).collect();
    current
        .iter()
        .filter(|s| !known.contains(&s.key()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(inode: u64, filter: Option<u32>) -> RawSocket {
        RawSocket {
            inode,
            kind: RawSocketKind::from_type(3),
            protocol: 0x0003,
            ifindex: 0,
            interface: None,
            uid: 0,
            netns: 4_026_531_840,
            host_netns: true,
            pid: Some(812),
            filter: FilterState::from_count(filter),
        }
    }

    #[test]
    fn an_instruction_count_reads_into_a_filter_state() {
        assert_eq!(FilterState::from_count(None), FilterState::Unknown);
        assert_eq!(FilterState::from_count(Some(0)), FilterState::Absent);
        assert_eq!(
            FilterState::from_count(Some(30)),
            FilterState::Classic { instructions: 30 }
        );
        assert!(FilterState::from_count(Some(1)).is_attached());
        assert!(!FilterState::Unknown.is_attached());
    }

    #[test]
    fn only_a_socket_the_previous_reading_lacked_is_new() {
        let before = vec![socket(1, Some(0))];
        let mut other_ns = socket(1, Some(0));
        other_ns.netns = 4_026_532_000;
        let now = vec![socket(1, Some(0)), socket(2, Some(4)), other_ns];
        let fresh: Vec<_> = new_sockets(&before, &now)
            .into_iter()
            .map(RawSocket::key)
            .collect();
        assert_eq!(fresh, vec![(4_026_531_840, 2), (4_026_532_000, 1)]);
    }

    #[test]
    fn the_message_names_holder_protocol_interface_and_filter() {
        let message = socket(7, Some(30)).message();
        assert!(message.contains("pid 812"));
        assert!(message.contains("raw protocol all on any"));
        assert!(message.contains("classic BPF filter of 30 instructions"));
        let mut eth = socket(8, None);
        eth.protocol = 0x88cc;
        eth.ifindex = 3;
        eth.pid = None;
        let message = eth.message();
        assert!(message.contains("no process"));
        assert!(message.contains("lldp on #3"));
        assert!(message.contains("filter unknown"));
    }

    #[test]
    fn a_filtered_socket_raises_a_high_alert_and_a_bare_one_a_medium() {
        use crate::alert::entity::Alert;
        use crate::common::entity::Severity;
        let filtered = Alert::from_raw_socket(&socket(1, Some(30)), None, 7);
        assert_eq!(filtered.severity, Severity::High);
        assert_eq!(filtered.component, RAW_SOCKET_COMPONENT);
        assert_eq!(filtered.tgid, Some(812));
        assert_eq!(
            filtered.mitre_attack.map(|m| m.technique_id).as_deref(),
            Some("T1205.002")
        );
        let bare = Alert::from_raw_socket(&socket(2, Some(0)), None, 7);
        assert_eq!(bare.severity, Severity::Medium);
    }

    #[test]
    fn an_unnamed_ethertype_reads_as_hex() {
        let mut s = socket(1, None);
        s.protocol = 0x1234;
        assert_eq!(s.protocol_name(), "0x1234");
        assert_eq!(RawSocketKind::from_type(10), RawSocketKind::Other);
    }
}
