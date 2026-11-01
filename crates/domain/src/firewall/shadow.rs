//! What a rule in shadow mode would have done.
//!
//! A shadow rule is read by the datapath after the verdict is taken and never
//! changes it. What it leaves behind is a reading: how much traffic it matched,
//! how much of that it would have decided otherwise, and a bounded sample of
//! the flows it would have changed. The reading is what an operator weighs
//! before trusting the rule with any traffic.

use std::net::IpAddr;

use serde::Serialize;

use super::entity::FirewallAction;
use crate::common::entity::RuleId;

/// What a packet got, or what a shadow rule would have given it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ShadowVerdict {
    Allow,
    Deny,
}

impl ShadowVerdict {
    /// What a rule carrying `action` gives the packets it matches. A log rule
    /// lets them through.
    pub fn of(action: FirewallAction) -> Self {
        match action {
            FirewallAction::Allow | FirewallAction::Log => Self::Allow,
            FirewallAction::Deny | FirewallAction::Reject => Self::Deny,
        }
    }

    /// The other verdict.
    #[must_use]
    pub fn opposite(self) -> Self {
        match self {
            Self::Allow => Self::Deny,
            Self::Deny => Self::Allow,
        }
    }
}

/// What a shadow rule matched since it was loaded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ShadowCounters {
    /// Packets the rule matched.
    pub packets: u64,
    /// Flows the rule matched, each counted on first sight. A flow the
    /// datapath forgot under load and saw again counts twice.
    pub flows: u64,
    /// Matched packets the rule would have decided otherwise.
    pub changed_packets: u64,
    /// Flows the rule would have decided otherwise that entered the sample.
    pub changed_flows: u64,
}

impl ShadowCounters {
    /// Add another set of counters, for a rule the kernel holds as several
    /// entries.
    pub fn add(&mut self, other: &Self) {
        self.packets += other.packets;
        self.flows += other.flows;
        self.changed_packets += other.changed_packets;
        self.changed_flows += other.changed_flows;
    }
}

/// One flow a shadow rule would have decided otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShadowFlow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// IP protocol number.
    pub protocol: u8,
    /// What the flow actually got.
    pub verdict: ShadowVerdict,
    /// Packets of the flow seen since it entered the sample.
    pub packets: u64,
    /// Nanoseconds since the Unix epoch.
    pub first_seen_ns: u64,
    /// Nanoseconds since the Unix epoch.
    pub last_seen_ns: u64,
}

/// What one shadow rule has counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShadowReading {
    pub rule_id: RuleId,
    pub action: FirewallAction,
    /// What the rule would give the packets it matches.
    pub would: ShadowVerdict,
    /// Whether the datapath holds the rule. One it does not hold counts
    /// nothing: its interface scope or an alias could not be placed, or the
    /// datapath's shadow capacity was full.
    pub installed: bool,
    pub counters: ShadowCounters,
    /// The flows it would have changed, most recent first, from a sample the
    /// datapath bounds across every shadow rule.
    pub sample: Vec<ShadowFlow>,
}

/// Every shadow rule's reading.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ShadowReport {
    /// When the counters last started afresh, in nanoseconds since the Unix
    /// epoch; `0` before any shadow rule was loaded. They start afresh
    /// whenever the set of shadow rules changes, since a counter then
    /// belongs to another rule.
    pub counting_since_ns: u64,
    pub rules: Vec<ShadowReading>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_rule_lets_its_packets_through() {
        assert_eq!(ShadowVerdict::of(FirewallAction::Log), ShadowVerdict::Allow);
        assert_eq!(
            ShadowVerdict::of(FirewallAction::Reject),
            ShadowVerdict::Deny
        );
        assert_eq!(ShadowVerdict::Allow.opposite(), ShadowVerdict::Deny);
    }

    #[test]
    fn counters_of_several_entries_add_up() {
        let mut sum = ShadowCounters::default();
        let one = ShadowCounters {
            packets: 3,
            flows: 1,
            changed_packets: 2,
            changed_flows: 1,
        };
        sum.add(&one);
        sum.add(&one);
        assert_eq!(sum.packets, 6);
        assert_eq!(sum.changed_flows, 2);
    }
}
