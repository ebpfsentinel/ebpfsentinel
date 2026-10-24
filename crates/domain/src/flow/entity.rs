//! A flow record, and the table that turns observed connections into them.
//!
//! A conntrack row is a live reading: it says what a connection looks like
//! now, and the next reading replaces it. A flow record is the opposite - it
//! says what happened between two instants and is never revised, which is
//! what an NDR, a forensic question asked a week later and an IPFIX collector
//! all need and none of them can build from a snapshot.
//!
//! The table here is the whole of that translation and it is pure: it is
//! handed readings and the current time, and it answers with the records that
//! are due. Nothing in it reaches a socket, a clock or a file, so the
//! timeouts, the delta arithmetic, the capacity bound and the sampling
//! decision are all asserted without a network.
//!
//! Three rules hold everywhere below:
//!
//! - **Counters are deltas.** A conntrack row counts from the start of the
//!   connection, so a flow re-exported on the active timeout would report the
//!   same bytes twice. Every record carries what happened since the previous
//!   record of that flow, which is what `octetDeltaCount` means on the wire.
//! - **A number that went backwards is a new flow, not a negative.** The
//!   kernel reuses a five-tuple, and a row whose counters dropped is a second
//!   connection wearing the first one's address pair.
//! - **Absence is absence.** A flow this node only forwarded has no local
//!   process, so its record carries no workload block rather than a zeroed
//!   one, exactly as the conntrack row does.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::conntrack::entity::Connection;
use crate::workload::entity::Workload;

/// Why a record was written, in the spelling and the numbering RFC 7012 gives
/// `flowEndReason`.
///
/// The number is on the wire, so it is fixed here rather than derived from the
/// declaration order: a variant inserted in the middle must not renumber the
/// others under a collector that has already been configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowEndReason {
    /// Nothing changed on the flow for the idle timeout.
    IdleTimeout,
    /// The flow is still running, and the active timeout came round.
    ActiveTimeout,
    /// The kernel's table no longer holds the flow.
    EndOfFlow,
    /// The exporter was asked to flush, which is what shutdown does.
    Forced,
    /// The table was full and this flow was the oldest in it.
    LackOfResources,
}

impl FlowEndReason {
    /// The IANA code point, which is what the IPFIX field carries.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::IdleTimeout => 1,
            Self::ActiveTimeout => 2,
            Self::EndOfFlow => 3,
            Self::Forced => 4,
            Self::LackOfResources => 5,
        }
    }

    /// The word every text format writes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdleTimeout => "idle_timeout",
            Self::ActiveTimeout => "active_timeout",
            Self::EndOfFlow => "end_of_flow",
            Self::Forced => "forced",
            Self::LackOfResources => "lack_of_resources",
        }
    }
}

impl std::fmt::Display for FlowEndReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The five-tuple a flow is keyed on, in the orientation the kernel printed.
///
/// `BTreeMap` rather than `HashMap` holds these, and that is a requirement
/// rather than a preference: two runs over the same readings must produce the
/// same bytes, and a hash map's iteration order is neither stable across runs
/// nor across builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// The key of a conntrack row, or `None` when an address the kernel
    /// printed does not parse: there is no flow to export without two
    /// addresses.
    #[must_use]
    pub fn of(connection: &Connection) -> Option<Self> {
        Some(Self {
            src: connection.src_ip.parse().ok()?,
            dst: connection.dst_ip.parse().ok()?,
            src_port: connection.src_port,
            dst_port: connection.dst_port,
            protocol: connection.protocol,
        })
    }

    /// A stable hash of the key, used for the sampling decision.
    ///
    /// FNV-1a over the key's own bytes: the point is that the same flow
    /// decides the same way on every node and in every run, so a sampled
    /// estate is a readable subset of its traffic rather than a different
    /// subset every restart.
    #[must_use]
    pub fn stable_hash(&self) -> u64 {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut hash = OFFSET;
        let mut feed = |byte: u8| {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(PRIME);
        };
        for byte in ip_bytes(self.src) {
            feed(byte);
        }
        for byte in ip_bytes(self.dst) {
            feed(byte);
        }
        for byte in self.src_port.to_be_bytes() {
            feed(byte);
        }
        for byte in self.dst_port.to_be_bytes() {
            feed(byte);
        }
        feed(self.protocol);
        hash
    }
}

/// The address as the wire carries it: four bytes or sixteen, never a text
/// rendering, so a v4 address written in a v6 form hashes as what it is.
fn ip_bytes(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// One flow record: what happened on one five-tuple between two instants.
///
/// Every format the agent writes - IPFIX, OTLP logs, syslog, CEF and JSON
/// lines - renders this one structure, so a field means the same thing in all
/// of them and the mapping is asserted once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// Packets seen in the direction the key names, since the previous record
    /// of this flow.
    pub packets: u64,
    /// Bytes in the same direction, same window.
    pub bytes: u64,
    /// Packets in the reverse direction, same window.
    pub packets_rev: u64,
    /// Bytes in the reverse direction, same window.
    pub bytes_rev: u64,
    /// When the flow was first observed, in Unix milliseconds.
    pub start_ms: u64,
    /// The end of the window this record covers, in Unix milliseconds.
    pub end_ms: u64,
    /// Why the record was written.
    pub reason: FlowEndReason,
    /// The local workload at one end, where the node could name it. Absent on
    /// a transited flow, and never a zero.
    #[serde(default, skip_serializing_if = "crate::workload::entity::is_absent")]
    pub workload: Option<Workload>,
}

impl FlowRecord {
    /// Whether this record names an IPv6 flow. A record never mixes families:
    /// the key comes from one conntrack row, which has one.
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.src.is_ipv6() || self.dst.is_ipv6()
    }

    /// The protocol's usual name, `proto-<n>` for one with no usual name.
    #[must_use]
    pub fn protocol_name(&self) -> String {
        match self.protocol {
            1 => "icmp".to_string(),
            6 => "tcp".to_string(),
            17 => "udp".to_string(),
            47 => "gre".to_string(),
            50 => "esp".to_string(),
            58 => "icmpv6".to_string(),
            132 => "sctp".to_string(),
            other => format!("proto-{other}"),
        }
    }
}

/// The bounds and the clocks the table runs on.
///
/// Every one of them is configuration with a documented default, and every
/// one of them has a cost stated where it is written down: a long active
/// timeout is a forensic gap, a short one is volume, a small capacity is
/// evicted flows and a sampling rate above one is a count a collector cannot
/// scale back up without being told the rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTableLimits {
    /// How many flows the table holds before the oldest is evicted.
    pub capacity: usize,
    /// How long a running flow goes before a record is written for it.
    pub active_timeout_ms: u64,
    /// How long a flow goes without a change before it is considered over.
    pub idle_timeout_ms: u64,
    /// One flow in this many is exported. `1` exports every flow.
    pub sampling: u32,
}

impl Default for FlowTableLimits {
    fn default() -> Self {
        Self {
            capacity: 65_536,
            active_timeout_ms: 60_000,
            idle_timeout_ms: 15_000,
            sampling: 1,
        }
    }
}

/// What the table did, so the cost of every bound above is readable rather
/// than inferred.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FlowTableStats {
    /// Readings handed to the table.
    pub observed: u64,
    /// Records the table produced.
    pub exported: u64,
    /// Flows the sampling decision left out.
    pub sampled_out: u64,
    /// Flows dropped because the table was at capacity.
    pub evicted: u64,
    /// Flows whose counters went backwards, counted as a new flow on a reused
    /// tuple rather than reported as a negative delta.
    pub restarted: u64,
}

/// What the table remembers about one flow between readings.
#[derive(Debug, Clone)]
struct FlowState {
    start_ms: u64,
    /// When the last reading changed anything, which is what the idle timeout
    /// measures.
    last_change_ms: u64,
    /// When a record was last written for this flow, which is what the active
    /// timeout measures.
    last_export_ms: u64,
    /// The counters the kernel last reported.
    packets: u64,
    bytes: u64,
    packets_rev: u64,
    bytes_rev: u64,
    /// The counters the last record already accounted for.
    sent_packets: u64,
    sent_bytes: u64,
    sent_packets_rev: u64,
    sent_bytes_rev: u64,
    workload: Option<Workload>,
    /// Decided once, when the flow was first seen.
    sampled: bool,
}

impl FlowState {
    fn pending(&self) -> bool {
        self.packets > self.sent_packets
            || self.bytes > self.sent_bytes
            || self.packets_rev > self.sent_packets_rev
            || self.bytes_rev > self.sent_bytes_rev
    }
}

/// The flow table: readings in, records out.
#[derive(Debug)]
pub struct FlowTable {
    flows: BTreeMap<FlowKey, FlowState>,
    limits: FlowTableLimits,
    stats: FlowTableStats,
}

impl FlowTable {
    #[must_use]
    pub fn new(limits: FlowTableLimits) -> Self {
        Self {
            flows: BTreeMap::new(),
            limits,
            stats: FlowTableStats::default(),
        }
    }

    #[must_use]
    pub fn stats(&self) -> FlowTableStats {
        self.stats
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    #[must_use]
    pub fn limits(&self) -> FlowTableLimits {
        self.limits
    }

    /// Replace the bounds, keeping the flows already held.
    ///
    /// A capacity lowered below what is held is honoured on the next
    /// observation rather than by throwing records away here: a reload must
    /// not lose traffic that was already counted.
    pub fn set_limits(&mut self, limits: FlowTableLimits) {
        self.limits = limits;
    }

    /// Take a reading of a live flow.
    ///
    /// Returns a record when this reading had to close a flow to make room
    /// for itself, or when the counters said the tuple was reused: in both
    /// cases what came before is over and owes a record.
    pub fn observe(
        &mut self,
        connection: &Connection,
        now_ms: u64,
        workload: Option<Workload>,
    ) -> Option<FlowRecord> {
        let key = FlowKey::of(connection)?;
        self.stats.observed += 1;

        let packets = u64::from(connection.packets_fwd);
        let bytes = u64::from(connection.bytes_fwd);
        let packets_rev = u64::from(connection.packets_rev);
        let bytes_rev = u64::from(connection.bytes_rev);

        if let Some(state) = self.flows.get_mut(&key) {
            let went_backwards = packets < state.packets
                || bytes < state.bytes
                || packets_rev < state.packets_rev
                || bytes_rev < state.bytes_rev;
            if went_backwards {
                self.stats.restarted += 1;
                let closing = state.clone();
                let sampled = closing.sampled;
                let record = Self::record_of(&key, &closing, now_ms, FlowEndReason::EndOfFlow);
                if record.is_some() {
                    self.stats.exported += 1;
                }
                self.flows.insert(
                    key,
                    FlowState {
                        start_ms: now_ms,
                        last_change_ms: now_ms,
                        last_export_ms: now_ms,
                        packets,
                        bytes,
                        packets_rev,
                        bytes_rev,
                        sent_packets: 0,
                        sent_bytes: 0,
                        sent_packets_rev: 0,
                        sent_bytes_rev: 0,
                        workload,
                        sampled,
                    },
                );
                return record;
            }

            let changed = packets != state.packets
                || bytes != state.bytes
                || packets_rev != state.packets_rev
                || bytes_rev != state.bytes_rev;
            state.packets = packets;
            state.bytes = bytes;
            state.packets_rev = packets_rev;
            state.bytes_rev = bytes_rev;
            if changed {
                state.last_change_ms = now_ms;
            }
            // A block that resolved once is kept: the socket closes long
            // before the conntrack row does, so re-reading it would turn a
            // named flow into an anonymous one halfway through its life.
            if state.workload.is_none() && workload.is_some() {
                state.workload = workload;
            }
            return None;
        }

        let evicted = self.make_room(now_ms);
        let sampled =
            self.limits.sampling <= 1 || key.stable_hash() % u64::from(self.limits.sampling) == 0;
        if !sampled {
            self.stats.sampled_out += 1;
        }
        self.flows.insert(
            key,
            FlowState {
                start_ms: now_ms,
                last_change_ms: now_ms,
                last_export_ms: now_ms,
                packets,
                bytes,
                packets_rev,
                bytes_rev,
                sent_packets: 0,
                sent_bytes: 0,
                sent_packets_rev: 0,
                sent_bytes_rev: 0,
                workload,
                sampled,
            },
        );
        evicted
    }

    /// The kernel no longer holds this flow. Returns its final record.
    ///
    /// The closing reading is the flow's last one and usually its highest, so
    /// its counters are taken: a destroy event that arrives between two polls
    /// carries bytes no reading ever showed, and dropping them would lose the
    /// tail of every short connection. Counters that went backwards are left
    /// alone, being a tuple that was reused and then freed.
    pub fn close(&mut self, connection: &Connection, now_ms: u64) -> Option<FlowRecord> {
        let key = FlowKey::of(connection)?;
        let mut state = self.flows.remove(&key)?;
        state.packets = state.packets.max(u64::from(connection.packets_fwd));
        state.bytes = state.bytes.max(u64::from(connection.bytes_fwd));
        state.packets_rev = state.packets_rev.max(u64::from(connection.packets_rev));
        state.bytes_rev = state.bytes_rev.max(u64::from(connection.bytes_rev));
        let record = Self::record_of(&key, &state, now_ms, FlowEndReason::EndOfFlow);
        if record.is_some() {
            self.stats.exported += 1;
        }
        record
    }

    /// The records the clock has made due: one per flow past its active
    /// timeout with traffic to report, and one per flow past its idle timeout,
    /// which is also removed.
    ///
    /// Idle is decided before active, because a flow that has been silent long
    /// enough to be over must not be reported as still running.
    pub fn due(&mut self, now_ms: u64) -> Vec<FlowRecord> {
        let mut records = Vec::new();
        let mut expired = Vec::new();

        for (key, state) in &mut self.flows {
            if now_ms.saturating_sub(state.last_change_ms) >= self.limits.idle_timeout_ms {
                expired.push(*key);
                continue;
            }
            if now_ms.saturating_sub(state.last_export_ms) >= self.limits.active_timeout_ms
                && let Some(record) =
                    Self::record_of(key, state, now_ms, FlowEndReason::ActiveTimeout)
            {
                Self::mark_sent(state, now_ms);
                records.push(record);
            }
        }

        for key in expired {
            if let Some(state) = self.flows.remove(&key)
                && let Some(record) =
                    Self::record_of(&key, &state, now_ms, FlowEndReason::IdleTimeout)
            {
                records.push(record);
            }
        }

        self.stats.exported += u64::try_from(records.len()).unwrap_or(u64::MAX);
        records
    }

    /// Everything the table still holds, written out and forgotten.
    ///
    /// This is what shutdown calls: a flow whose record was never written is
    /// traffic the estate observed and nobody can ask about later.
    pub fn flush(&mut self, now_ms: u64) -> Vec<FlowRecord> {
        let flows = std::mem::take(&mut self.flows);
        let records: Vec<FlowRecord> = flows
            .iter()
            .filter_map(|(key, state)| Self::record_of(key, state, now_ms, FlowEndReason::Forced))
            .collect();
        self.stats.exported += u64::try_from(records.len()).unwrap_or(u64::MAX);
        records
    }

    /// Evict the flow whose last reading is oldest, when the table is full.
    fn make_room(&mut self, now_ms: u64) -> Option<FlowRecord> {
        if self.flows.len() < self.limits.capacity {
            return None;
        }
        let oldest = self
            .flows
            .iter()
            .min_by_key(|(key, state)| (state.last_change_ms, **key))
            .map(|(key, _)| *key)?;
        let state = self.flows.remove(&oldest)?;
        self.stats.evicted += 1;
        let record = Self::record_of(&oldest, &state, now_ms, FlowEndReason::LackOfResources);
        if record.is_some() {
            self.stats.exported += 1;
        }
        record
    }

    /// The record a flow owes, or `None` when it owes none: a flow the
    /// sampling decision left out, and a flow whose every byte is already on
    /// a previous record, both have nothing to say.
    fn record_of(
        key: &FlowKey,
        state: &FlowState,
        now_ms: u64,
        reason: FlowEndReason,
    ) -> Option<FlowRecord> {
        if !state.sampled || !state.pending() {
            return None;
        }
        Some(FlowRecord {
            src: key.src,
            dst: key.dst,
            src_port: key.src_port,
            dst_port: key.dst_port,
            protocol: key.protocol,
            packets: state.packets - state.sent_packets,
            bytes: state.bytes - state.sent_bytes,
            packets_rev: state.packets_rev - state.sent_packets_rev,
            bytes_rev: state.bytes_rev - state.sent_bytes_rev,
            start_ms: state.start_ms,
            end_ms: now_ms.max(state.start_ms),
            reason,
            workload: state.workload.clone(),
        })
    }

    fn mark_sent(state: &mut FlowState, now_ms: u64) {
        state.sent_packets = state.packets;
        state.sent_bytes = state.bytes;
        state.sent_packets_rev = state.packets_rev;
        state.sent_bytes_rev = state.bytes_rev;
        state.last_export_ms = now_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::entity::ConnectionState;
    use crate::workload::entity::WorkloadSource;

    fn connection(sport: u16, packets: u32, bytes: u32) -> Connection {
        Connection {
            src_ip: "10.0.0.1".to_string(),
            dst_ip: "10.0.0.2".to_string(),
            src_port: sport,
            dst_port: 443,
            protocol: 6,
            state: ConnectionState::Established,
            packets_fwd: packets,
            packets_rev: packets,
            bytes_fwd: bytes,
            bytes_rev: bytes,
            workload: None,
            reply: None,
        }
    }

    fn table() -> FlowTable {
        FlowTable::new(FlowTableLimits::default())
    }

    #[test]
    fn a_first_reading_writes_nothing() {
        let mut table = table();
        assert!(
            table
                .observe(&connection(1000, 10, 1_000), 0, None)
                .is_none()
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.stats().exported, 0);
    }

    #[test]
    fn the_record_of_a_closed_flow_carries_the_whole_flow() {
        let mut table = table();
        table.observe(&connection(1000, 10, 1_000), 0, None);
        let record = table
            .close(&connection(1000, 10, 1_000), 5_000)
            .expect("a closed flow owes a record");
        assert_eq!(record.packets, 10);
        assert_eq!(record.bytes, 1_000);
        assert_eq!(record.packets_rev, 10);
        assert_eq!(record.reason, FlowEndReason::EndOfFlow);
        assert_eq!(record.start_ms, 0);
        assert_eq!(record.end_ms, 5_000);
        assert!(table.is_empty());
    }

    #[test]
    fn the_closing_reading_is_the_flows_last_word_on_its_counters() {
        let mut table = table();
        table.observe(&connection(1000, 10, 1_000), 0, None);
        let record = table
            .close(&connection(1000, 40, 4_000), 1_000)
            .expect("a record");
        assert_eq!(record.packets, 40, "the bytes between the last two polls");
        assert_eq!(record.bytes, 4_000);
    }

    #[test]
    fn a_closing_reading_that_went_backwards_does_not_lower_the_counters() {
        let mut table = table();
        table.observe(&connection(1000, 40, 4_000), 0, None);
        let record = table
            .close(&connection(1000, 1, 100), 1_000)
            .expect("a record");
        assert_eq!(record.packets, 40);
    }

    #[test]
    fn a_destroy_for_a_flow_never_seen_is_not_a_record() {
        let mut table = table();
        assert!(table.close(&connection(1000, 5, 500), 1_000).is_none());
    }

    #[test]
    fn a_second_record_carries_only_what_the_first_did_not() {
        let mut table = FlowTable::new(FlowTableLimits {
            active_timeout_ms: 1_000,
            idle_timeout_ms: 10_000,
            ..FlowTableLimits::default()
        });
        table.observe(&connection(1000, 10, 1_000), 0, None);
        let first = table.due(1_000);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].bytes, 1_000);
        assert_eq!(first[0].reason, FlowEndReason::ActiveTimeout);

        table.observe(&connection(1000, 25, 3_000), 1_500, None);
        let second = table.due(2_500);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].packets, 15, "the delta, not the total");
        assert_eq!(second[0].bytes, 2_000);
    }

    #[test]
    fn a_flow_with_nothing_new_to_say_writes_no_second_record() {
        let mut table = FlowTable::new(FlowTableLimits {
            active_timeout_ms: 1_000,
            idle_timeout_ms: 10_000,
            ..FlowTableLimits::default()
        });
        table.observe(&connection(1000, 10, 1_000), 0, None);
        assert_eq!(table.due(1_000).len(), 1);
        assert!(
            table.due(2_000).is_empty(),
            "the same bytes must not be reported twice"
        );
    }

    #[test]
    fn a_silent_flow_is_closed_on_the_idle_timeout() {
        let mut table = FlowTable::new(FlowTableLimits {
            active_timeout_ms: 60_000,
            idle_timeout_ms: 1_000,
            ..FlowTableLimits::default()
        });
        table.observe(&connection(1000, 10, 1_000), 0, None);
        let records = table.due(1_000);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, FlowEndReason::IdleTimeout);
        assert!(table.is_empty(), "an idle flow leaves the table");
    }

    #[test]
    fn counters_that_went_backwards_are_a_reused_tuple() {
        let mut table = table();
        table.observe(&connection(1000, 100, 10_000), 0, None);
        let record = table
            .observe(&connection(1000, 2, 200), 1_000, None)
            .expect("the flow that ended owes a record");
        assert_eq!(record.packets, 100, "the old flow's own counters");
        assert_eq!(table.stats().restarted, 1);
        assert_eq!(table.len(), 1, "the new flow took its place");
    }

    #[test]
    fn a_full_table_evicts_its_oldest_flow_with_a_record() {
        let mut table = FlowTable::new(FlowTableLimits {
            capacity: 2,
            ..FlowTableLimits::default()
        });
        table.observe(&connection(1000, 1, 100), 0, None);
        table.observe(&connection(1001, 1, 100), 1_000, None);
        let record = table
            .observe(&connection(1002, 1, 100), 2_000, None)
            .expect("the evicted flow owes a record");
        assert_eq!(record.src_port, 1000, "the oldest reading went");
        assert_eq!(record.reason, FlowEndReason::LackOfResources);
        assert_eq!(table.stats().evicted, 1);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn sampling_leaves_flows_out_and_counts_them() {
        let mut table = FlowTable::new(FlowTableLimits {
            sampling: 4,
            ..FlowTableLimits::default()
        });
        for port in 0..200u16 {
            table.observe(&connection(10_000 + port, 1, 100), 0, None);
        }
        let stats = table.stats();
        assert!(stats.sampled_out > 0, "one in four leaves three out");
        assert!(stats.sampled_out < 200);
    }

    #[test]
    fn the_sampling_decision_is_the_same_on_every_run() {
        let key = FlowKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            src_port: 1000,
            dst_port: 443,
            protocol: 6,
        };
        assert_eq!(key.stable_hash(), key.stable_hash());
        let other = FlowKey {
            src_port: 1001,
            ..key
        };
        assert_ne!(key.stable_hash(), other.stable_hash());
    }

    #[test]
    fn a_sampled_out_flow_writes_no_record_at_all() {
        let mut table = FlowTable::new(FlowTableLimits {
            sampling: u32::MAX,
            ..FlowTableLimits::default()
        });
        table.observe(&connection(1000, 10, 1_000), 0, None);
        assert!(table.close(&connection(1000, 10, 1_000), 1_000).is_none());
    }

    #[test]
    fn a_flush_writes_every_flow_once_and_empties_the_table() {
        let mut table = table();
        table.observe(&connection(1000, 1, 100), 0, None);
        table.observe(&connection(1001, 1, 100), 0, None);
        let records = table.flush(1_000);
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.reason == FlowEndReason::Forced));
        assert!(table.is_empty());
        assert!(table.flush(2_000).is_empty());
    }

    #[test]
    fn a_transited_flow_carries_no_workload_block() {
        let mut table = table();
        table.observe(&connection(1000, 1, 100), 0, None);
        let record = table.close(&connection(1000, 1, 100), 1_000).unwrap();
        assert!(record.workload.is_none());
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("workload"), "absence is absence: {json}");
    }

    #[test]
    fn a_block_that_resolved_once_is_kept_for_the_life_of_the_flow() {
        let mut table = table();
        let workload = Workload::new(4_242, WorkloadSource::Flow);
        table.observe(&connection(1000, 1, 100), 0, workload);
        table.observe(&connection(1000, 2, 200), 1_000, None);
        let record = table.close(&connection(1000, 2, 200), 2_000).unwrap();
        assert_eq!(record.workload.as_ref().map(|w| w.pid), Some(4_242));
    }

    #[test]
    fn an_address_the_kernel_printed_that_does_not_parse_is_not_a_flow() {
        let mut table = table();
        let mut broken = connection(1000, 1, 100);
        broken.src_ip = "not-an-address".to_string();
        assert!(table.observe(&broken, 0, None).is_none());
        assert!(table.is_empty());
        assert_eq!(table.stats().observed, 0);
    }

    #[test]
    fn the_reason_codes_are_the_numbers_the_rfc_gives() {
        assert_eq!(FlowEndReason::IdleTimeout.code(), 1);
        assert_eq!(FlowEndReason::ActiveTimeout.code(), 2);
        assert_eq!(FlowEndReason::EndOfFlow.code(), 3);
        assert_eq!(FlowEndReason::Forced.code(), 4);
        assert_eq!(FlowEndReason::LackOfResources.code(), 5);
    }

    #[test]
    fn a_protocol_with_no_usual_name_is_numbered_rather_than_guessed() {
        let mut table = table();
        let mut other = connection(1000, 1, 100);
        other.protocol = 200;
        table.observe(&other, 0, None);
        let record = table.close(&other, 1_000).unwrap();
        assert_eq!(record.protocol_name(), "proto-200");
    }

    #[test]
    fn the_usual_protocols_are_named() {
        for (number, name) in [(1u8, "icmp"), (6, "tcp"), (17, "udp"), (58, "icmpv6")] {
            let mut table = table();
            let mut conn = connection(1000, 1, 100);
            conn.protocol = number;
            table.observe(&conn, 0, None);
            let record = table.close(&conn, 1_000).unwrap();
            assert_eq!(record.protocol_name(), name);
        }
    }

    #[test]
    fn an_ipv6_flow_says_so() {
        let mut table = table();
        let mut conn = connection(1000, 1, 100);
        conn.src_ip = "2001:db8::1".to_string();
        conn.dst_ip = "2001:db8::2".to_string();
        table.observe(&conn, 0, None);
        let record = table.close(&conn, 1_000).unwrap();
        assert!(record.is_ipv6());
    }

    #[test]
    fn the_records_of_one_pass_come_out_in_the_same_order_every_time() {
        let order = |()| {
            let mut table = FlowTable::new(FlowTableLimits {
                idle_timeout_ms: 1_000,
                ..FlowTableLimits::default()
            });
            for port in 0..50u16 {
                table.observe(&connection(2_000 + port, 1, 100), 0, None);
            }
            table
                .due(1_000)
                .into_iter()
                .map(|r| r.src_port)
                .collect::<Vec<u16>>()
        };
        assert_eq!(order(()), order(()), "a hash map's order would differ here");
    }

    #[test]
    fn lowering_the_capacity_does_not_throw_away_what_was_counted() {
        let mut table = table();
        table.observe(&connection(1000, 1, 100), 0, None);
        table.set_limits(FlowTableLimits {
            capacity: 1,
            ..FlowTableLimits::default()
        });
        assert_eq!(table.len(), 1);
        assert_eq!(table.limits().capacity, 1);
    }
}
