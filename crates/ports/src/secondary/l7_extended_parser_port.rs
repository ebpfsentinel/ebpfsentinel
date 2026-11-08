use domain::common::entity::RuleId;
use domain::firewall::entity::FirewallAction;
use ebpf_common::event::PacketEvent;

/// What an extended parser read from one payload: the protocol label it
/// recognised and, when one of its own rules matched the parsed fields,
/// the verdict that rule carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedL7Reading {
    /// Stable lowercase label of the protocol (`"mqtt"`, `"amqp"`, ...).
    pub label: &'static str,
    /// Action and rule identifier of the first matching rule, if any.
    pub verdict: Option<(FirewallAction, RuleId)>,
}

impl ExtendedL7Reading {
    /// A reading that names the protocol and carries no verdict.
    pub fn label_only(label: &'static str) -> Self {
        Self {
            label,
            verdict: None,
        }
    }
}

/// Optional secondary port consulted by the L7 dispatcher when the
/// built-in detector returns [`Unknown`](DetectedProtocol::Unknown).
///
/// Implementations can run on the hot path. They are expected to
/// short-circuit on the first byte mismatch and never allocate on a miss.
///
/// [`Unknown`]: domain::l7::entity::DetectedProtocol::Unknown
pub trait L7ExtendedParser: Send + Sync {
    /// Return a stable lowercase label (`"mqtt"`, `"amqp"`, ...) when the
    /// payload matches one of the parser's protocols, or `None` when
    /// nothing recognises the bytes.
    fn detect_label(&self, payload: &[u8]) -> Option<&'static str>;

    /// Read the payload of one packet: the protocol it carries and the
    /// verdict of the parser's own rules on its parsed fields. The default
    /// names the protocol and decides nothing, so an implementation that
    /// only labels traffic needs no override.
    fn inspect(&self, _header: &PacketEvent, payload: &[u8]) -> Option<ExtendedL7Reading> {
        self.detect_label(payload)
            .map(ExtendedL7Reading::label_only)
    }

    /// Stable name of the parser, used in metrics / logs. Defaults to
    /// `"extended"` so existing implementations need no override.
    fn name(&self) -> &'static str {
        "extended"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LabelOnly;

    impl L7ExtendedParser for LabelOnly {
        fn detect_label(&self, payload: &[u8]) -> Option<&'static str> {
            payload.starts_with(b"PING").then_some("nats")
        }
    }

    #[test]
    fn the_default_inspection_names_the_protocol_and_decides_nothing() {
        let header = PacketEvent {
            timestamp_ns: 0,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 40_000,
            dst_port: 4222,
            protocol: 6,
            event_type: 0,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            cgroup1_id: 0,
            rss_hash: 0,
            rss_hash_type: 0,
            rx_hw_timestamp_ns: 0,
        };
        assert_eq!(
            LabelOnly.inspect(&header, b"PING\r\n"),
            Some(ExtendedL7Reading::label_only("nats"))
        );
        assert_eq!(LabelOnly.inspect(&header, b"\x00\x01"), None);
    }
}
