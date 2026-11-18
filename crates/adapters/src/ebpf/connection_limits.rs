//! Keeps the connection ceilings counting connections that are open.
//!
//! `conntrack.max_src_states` and a rule's `max_states` are ceilings on open
//! connections. The datapath counts a connection when it admits one, and it
//! never sees one end: the end of a connection is a state the kernel conntrack
//! table reaches, not a packet the firewall judges. Left alone the counters
//! only ever rise, and a source that opened its ceiling's worth of
//! connections once, over any length of time, is refused for as long as the
//! agent runs.
//!
//! So the datapath records each flow it counted in `CT_LIMIT_HOLDS`, and this
//! module, on an interval, reads the kernel conntrack table, drops the holds
//! whose connection is no longer open there and writes the counters back from
//! the holds that remain. A hold younger than [`ADMISSION_GRACE`] is kept
//! whatever the table says, because the firewall admits a flow before
//! netfilter has created the entry for it.
//!
//! The counters are rewritten while the datapath may be incrementing them, so
//! an admission landing between the read of the holds and the write of the
//! counters is missing from that one write and present in the next: the
//! ceiling can be exceeded by what is admitted within one pass, never by more.

use std::collections::{HashMap as StdHashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use aya::maps::{Array, HashMap, MapData};
use domain::conntrack::entity::{Connection, ConnectionState};
use ebpf_common::conntrack::{
    LIMIT_HOLD_NO_RULE, LimitHold, LimitHoldKey, SRC_COUNTER_FLAG_OVERLOADED, SrcCounterKey,
    SrcStateCounter,
};
use ebpf_common::firewall::{
    FIREWALL_RULE_BANKS, MAX_FIREWALL_RULES, RULE_STATE_SLOTS, bank_base, rule_state_slot_in_bank,
};
use ports::secondary::conntrack_map_port::ConnTrackMapPort;
use tracing::{debug, warn};

use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::boottime_now_ns;

/// How often the counters are brought back to what is open.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

/// How long a flow is held after admission whatever the conntrack table says:
/// the firewall runs before netfilter has created the entry.
pub const ADMISSION_GRACE: Duration = Duration::from_secs(10);

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

/// The banks the datapath reads, published by the firewall map manager each
/// time it flips one: bit 0 the IPv4 bank, bit 1 the IPv6 bank.
static LIVE_BANKS: AtomicU32 = AtomicU32::new(0);

/// Record which bank of each family the datapath now reads.
pub fn publish_live_banks(bank_v4: u32, bank_v6: u32) {
    LIVE_BANKS.store((bank_v4 & 1) | ((bank_v6 & 1) << 1), Ordering::Release);
}

/// The banks the datapath reads.
#[must_use]
pub fn live_banks() -> LiveBanks {
    let word = LIVE_BANKS.load(Ordering::Acquire);
    LiveBanks {
        v4: word & 1,
        v6: (word >> 1) & 1,
    }
}

/// The bank of each family the datapath reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LiveBanks {
    pub v4: u32,
    pub v6: u32,
}

impl LiveBanks {
    /// Whether a per-rule counter slot belongs to a rule the datapath still
    /// reads. A slot of the other bank names a rule a reload replaced.
    #[must_use]
    pub fn holds_slot(self, slot: u32) -> bool {
        let family_span = FIREWALL_RULE_BANKS * MAX_FIREWALL_RULES;
        if slot >= RULE_STATE_SLOTS {
            return false;
        }
        let bank = if slot < family_span { self.v4 } else { self.v6 };
        rule_state_slot_in_bank(slot, bank_base(bank))
    }
}

/// One flow by its original tuple, the shape both the hold table and the
/// kernel conntrack table can be read into.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl FlowTuple {
    fn new(protocol: u8, src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> Self {
        // The datapath holds an ICMP flow without ports, the conntrack table
        // with the echo identifier: compare them on addresses alone.
        let (src_port, dst_port) = if protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6 {
            (0, 0)
        } else {
            (src_port, dst_port)
        };
        Self {
            protocol,
            src,
            dst,
            src_port,
            dst_port,
        }
    }

    /// The flow a hold was recorded for.
    #[must_use]
    pub fn of_hold(key: &LimitHoldKey) -> Self {
        let (src, dst) = if key.family == 6 {
            (
                IpAddr::V6(words_to_v6(key.src)),
                IpAddr::V6(words_to_v6(key.dst)),
            )
        } else {
            (
                IpAddr::V4(Ipv4Addr::from(key.src[0])),
                IpAddr::V4(Ipv4Addr::from(key.dst[0])),
            )
        };
        Self::new(key.protocol, src, dst, key.src_port, key.dst_port)
    }

    /// The flow a conntrack entry stands for, or `None` when the entry is
    /// closed or its addresses do not parse.
    #[must_use]
    pub fn of_open_connection(conn: &Connection) -> Option<Self> {
        if conn.state == ConnectionState::TimeWait {
            return None;
        }
        let src = conn.src_ip.parse::<IpAddr>().ok()?;
        let dst = conn.dst_ip.parse::<IpAddr>().ok()?;
        Some(Self::new(
            conn.protocol,
            unmap(src),
            unmap(dst),
            conn.src_port,
            conn.dst_port,
        ))
    }
}

fn unmap(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn words_to_v6(words: [u32; 4]) -> Ipv6Addr {
    let bits = (u128::from(words[0]) << 96)
        | (u128::from(words[1]) << 64)
        | (u128::from(words[2]) << 32)
        | u128::from(words[3]);
    Ipv6Addr::from(bits)
}

/// The per-source counter key a hold was counted against.
fn source_key(key: &LimitHoldKey) -> SrcCounterKey {
    if key.family == 6 {
        SrcCounterKey::from_v6(key.src)
    } else {
        SrcCounterKey::from_v4(key.src[0])
    }
}

/// What one pass decides from the holds and the open connections.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Holds whose connection is over.
    pub release: Vec<LimitHoldKey>,
    /// Holds that stay, with their rule detached because a reload replaced it.
    pub detach: Vec<(LimitHoldKey, LimitHold)>,
    /// Open connections per source, by source address words.
    pub per_source: StdHashMap<[u32; 4], u32>,
    /// Open connections per live rule counter slot.
    pub per_rule: StdHashMap<u32, u32>,
}

/// Decide what one pass writes.
#[must_use]
pub fn reconcile<S: std::hash::BuildHasher>(
    holds: &[(LimitHoldKey, LimitHold)],
    open: &HashSet<FlowTuple, S>,
    now_ns: u64,
    live: LiveBanks,
) -> Reconciliation {
    let grace_ns = u64::try_from(ADMISSION_GRACE.as_nanos()).unwrap_or(u64::MAX);
    let mut out = Reconciliation::default();
    for (key, hold) in holds {
        let young = now_ns.saturating_sub(hold.admitted_ns) < grace_ns;
        if !young && !open.contains(&FlowTuple::of_hold(key)) {
            out.release.push(*key);
            continue;
        }
        if hold.counted_src != 0 {
            *out.per_source.entry(source_key(key).addr).or_insert(0) += 1;
        }
        if hold.rule_idx != LIMIT_HOLD_NO_RULE {
            let slot = u32::try_from(hold.rule_idx).ok();
            match slot.filter(|s| live.holds_slot(*s)) {
                Some(s) => *out.per_rule.entry(s).or_insert(0) += 1,
                None => out.detach.push((
                    *key,
                    LimitHold {
                        rule_idx: LIMIT_HOLD_NO_RULE,
                        ..*hold
                    },
                )),
            }
        }
    }
    out
}

/// The counter a source should carry once its open connections are known, or
/// `None` when the entry can go: nothing open, no overload mark standing and
/// its rate window over.
#[must_use]
pub fn next_source_counter(
    current: SrcStateCounter,
    open: u32,
    now_ns: u64,
    rate_window_ns: u64,
) -> Option<SrcStateCounter> {
    let marked = current.flags & SRC_COUNTER_FLAG_OVERLOADED != 0;
    let window_over = now_ns.saturating_sub(current.window_start_ns) >= rate_window_ns;
    if open == 0 && !marked && window_over {
        return None;
    }
    Some(SrcStateCounter {
        conn_count: open,
        ..current
    })
}

/// The three tables a pass reads and writes, taken from the xdp-firewall
/// object.
pub struct ConnectionLimitMaps {
    holds: HashMap<MapData, LimitHoldKey, LimitHold>,
    sources: HashMap<MapData, SrcCounterKey, SrcStateCounter>,
    rules: Array<MapData, u32>,
}

impl ConnectionLimitMaps {
    /// Take the tables from a loaded xdp-firewall object, or `None` when the
    /// object predates them.
    pub fn take(ebpf: &mut dyn MapStore) -> Option<Self> {
        let holds = HashMap::try_from(ebpf.take_map("CT_LIMIT_HOLDS")?).ok()?;
        let sources = HashMap::try_from(ebpf.take_map("CT_SRC_COUNTERS")?).ok()?;
        let rules = Array::try_from(ebpf.take_map("FW_RULE_STATE_COUNT")?).ok()?;
        Some(Self {
            holds,
            sources,
            rules,
        })
    }

    /// Run one pass against a snapshot of the open connections.
    pub fn apply<S: std::hash::BuildHasher>(
        &mut self,
        open: &HashSet<FlowTuple, S>,
        rate_window: Duration,
    ) -> PassReport {
        let now_ns = boottime_now_ns();
        let holds: Vec<(LimitHoldKey, LimitHold)> =
            self.holds.iter().filter_map(Result::ok).collect();
        let plan = reconcile(&holds, open, now_ns, live_banks());

        for key in &plan.release {
            let _ = self.holds.remove(key);
        }
        for (key, hold) in &plan.detach {
            let _ = self.holds.insert(key, hold, 0);
        }

        let rate_window_ns = u64::try_from(rate_window.as_nanos()).unwrap_or(u64::MAX);
        let sources: Vec<(SrcCounterKey, SrcStateCounter)> =
            self.sources.iter().filter_map(Result::ok).collect();
        let mut sources_written = 0usize;
        for (key, current) in sources {
            let open_now = plan.per_source.get(&key.addr).copied().unwrap_or(0);
            match next_source_counter(current, open_now, now_ns, rate_window_ns) {
                None => {
                    let _ = self.sources.remove(&key);
                    sources_written += 1;
                }
                Some(next) if next != current => {
                    let _ = self.sources.insert(&key, &next, 0);
                    sources_written += 1;
                }
                Some(_) => {}
            }
        }

        let mut rules_written = 0usize;
        for slot in 0..RULE_STATE_SLOTS {
            let current = self.rules.get(&slot, 0).unwrap_or(0);
            let want = plan.per_rule.get(&slot).copied().unwrap_or(0);
            if current != want && self.rules.set(slot, &want, 0).is_ok() {
                rules_written += 1;
            }
        }

        PassReport {
            held: holds.len() - plan.release.len(),
            released: plan.release.len(),
            sources_written,
            rules_written,
        }
    }
}

/// What one pass changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassReport {
    pub held: usize,
    pub released: usize,
    pub sources_written: usize,
    pub rules_written: usize,
}

/// Bring the ceilings back to what is open on every interval, for as long as
/// the agent runs. A pass whose conntrack read fails changes nothing: a hold
/// is only released on the table's word that its connection is gone.
pub async fn run_connection_limit_reconciler(
    mut maps: ConnectionLimitMaps,
    conntrack: Box<dyn ConnTrackMapPort>,
    rate_window: Duration,
) {
    let conntrack: std::sync::Arc<dyn ConnTrackMapPort> = std::sync::Arc::from(conntrack);
    let mut ticker = tokio::time::interval(RECONCILE_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing = false;
    loop {
        ticker.tick().await;
        let port = std::sync::Arc::clone(&conntrack);
        let snapshot = tokio::task::spawn_blocking(move || port.get_connections(usize::MAX)).await;
        let connections = match snapshot {
            Ok(Ok(c)) => {
                failing = false;
                c
            }
            Ok(Err(e)) => {
                if !failing {
                    warn!(error = %e, "conntrack unreadable, connection ceilings keep their counts until it answers");
                }
                failing = true;
                continue;
            }
            Err(e) => {
                warn!(error = %e, "conntrack read task failed");
                continue;
            }
        };
        let open: HashSet<FlowTuple> = connections
            .iter()
            .filter_map(FlowTuple::of_open_connection)
            .collect();
        let report = maps.apply(&open, rate_window);
        debug!(
            held = report.held,
            released = report.released,
            sources = report.sources_written,
            rules = report.rules_written,
            "connection ceilings reconciled"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: u64 = 1_000_000_000;

    fn v4_hold(
        src: [u8; 4],
        sport: u16,
        rule_idx: i32,
        admitted_ns: u64,
    ) -> (LimitHoldKey, LimitHold) {
        (
            LimitHoldKey {
                src: [u32::from(Ipv4Addr::from(src)), 0, 0, 0],
                dst: [u32::from(Ipv4Addr::new(10, 0, 0, 1)), 0, 0, 0],
                src_port: sport,
                dst_port: 80,
                protocol: 6,
                family: 4,
                _pad: [0; 2],
            },
            LimitHold {
                rule_idx,
                counted_src: 1,
                _pad: [0; 3],
                admitted_ns,
            },
        )
    }

    fn open_conn(src: &str, sport: u16, state: ConnectionState) -> Connection {
        Connection {
            src_ip: src.to_string(),
            dst_ip: "10.0.0.1".to_string(),
            src_port: sport,
            dst_port: 80,
            protocol: 6,
            state,
            packets_fwd: 0,
            packets_rev: 0,
            bytes_fwd: 0,
            bytes_rev: 0,
            workload: None,
            reply: None,
        }
    }

    fn open_set(conns: &[Connection]) -> HashSet<FlowTuple> {
        conns
            .iter()
            .filter_map(FlowTuple::of_open_connection)
            .collect()
    }

    #[test]
    fn a_closed_connection_stops_counting_against_its_source() {
        let holds = vec![
            v4_hold([192, 0, 2, 1], 40000, LIMIT_HOLD_NO_RULE, 0),
            v4_hold([192, 0, 2, 1], 40001, LIMIT_HOLD_NO_RULE, 0),
        ];
        let open = open_set(&[open_conn("192.0.2.1", 40000, ConnectionState::Established)]);
        let plan = reconcile(&holds, &open, 60 * SEC, LiveBanks::default());
        assert_eq!(plan.release, vec![holds[1].0]);
        let key = SrcCounterKey::from_v4(u32::from(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(plan.per_source.get(&key.addr), Some(&1));
    }

    #[test]
    fn time_wait_is_not_open() {
        let holds = vec![v4_hold([192, 0, 2, 1], 40000, LIMIT_HOLD_NO_RULE, 0)];
        let open = open_set(&[open_conn("192.0.2.1", 40000, ConnectionState::TimeWait)]);
        let plan = reconcile(&holds, &open, 60 * SEC, LiveBanks::default());
        assert_eq!(plan.release.len(), 1);
        assert!(plan.per_source.is_empty());
    }

    #[test]
    fn a_flow_admitted_moments_ago_is_kept_before_conntrack_has_it() {
        let holds = vec![v4_hold([192, 0, 2, 1], 40000, LIMIT_HOLD_NO_RULE, 55 * SEC)];
        let plan = reconcile(&holds, &HashSet::new(), 60 * SEC, LiveBanks::default());
        assert!(plan.release.is_empty());
        assert_eq!(plan.per_source.len(), 1);
    }

    #[test]
    fn a_rule_counts_only_its_open_flows_in_the_live_bank() {
        let holds = vec![
            v4_hold([192, 0, 2, 1], 40000, 3, 0),
            v4_hold([192, 0, 2, 2], 40000, 3, 0),
        ];
        let open = open_set(&[
            open_conn("192.0.2.1", 40000, ConnectionState::Established),
            open_conn("192.0.2.2", 40000, ConnectionState::Established),
        ]);
        let plan = reconcile(&holds, &open, 60 * SEC, LiveBanks::default());
        assert_eq!(plan.per_rule.get(&3), Some(&2));
        assert!(plan.detach.is_empty());
    }

    #[test]
    fn a_reload_detaches_the_rule_its_flows_were_counted_against() {
        let holds = vec![v4_hold([192, 0, 2, 1], 40000, 3, 0)];
        let open = open_set(&[open_conn("192.0.2.1", 40000, ConnectionState::Established)]);
        let live = LiveBanks { v4: 1, v6: 0 };
        let plan = reconcile(&holds, &open, 60 * SEC, live);
        assert!(plan.per_rule.is_empty());
        assert_eq!(plan.detach.len(), 1);
        assert_eq!(plan.detach[0].1.rule_idx, LIMIT_HOLD_NO_RULE);
        // The source still counts it: the connection is open.
        assert_eq!(plan.per_source.len(), 1);
    }

    #[test]
    fn live_bank_slots_are_told_apart_by_family_and_bank() {
        let live = LiveBanks { v4: 0, v6: 1 };
        assert!(live.holds_slot(0));
        assert!(!live.holds_slot(MAX_FIREWALL_RULES));
        let v6_base = FIREWALL_RULE_BANKS * MAX_FIREWALL_RULES;
        assert!(!live.holds_slot(v6_base));
        assert!(live.holds_slot(v6_base + MAX_FIREWALL_RULES + 5));
        assert!(!live.holds_slot(RULE_STATE_SLOTS));
    }

    #[test]
    fn an_ipv6_hold_matches_its_conntrack_entry() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let words = |a: Ipv6Addr| {
            let b = a.octets();
            [
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
                u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
                u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            ]
        };
        let key = LimitHoldKey {
            src: words(src),
            dst: words(dst),
            src_port: 5000,
            dst_port: 443,
            protocol: 6,
            family: 6,
            _pad: [0; 2],
        };
        let conn = Connection {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: 5000,
            dst_port: 443,
            protocol: 6,
            state: ConnectionState::Established,
            packets_fwd: 0,
            packets_rev: 0,
            bytes_fwd: 0,
            bytes_rev: 0,
            workload: None,
            reply: None,
        };
        assert_eq!(
            FlowTuple::of_open_connection(&conn),
            Some(FlowTuple::of_hold(&key))
        );
    }

    #[test]
    fn icmp_is_matched_on_addresses_alone() {
        let (mut key, _) = v4_hold([192, 0, 2, 1], 0, LIMIT_HOLD_NO_RULE, 0);
        key.protocol = 1;
        key.dst_port = 0;
        let mut conn = open_conn("192.0.2.1", 1234, ConnectionState::New);
        conn.protocol = 1;
        conn.dst_port = 0;
        assert_eq!(
            FlowTuple::of_open_connection(&conn),
            Some(FlowTuple::of_hold(&key))
        );
    }

    #[test]
    fn an_idle_source_leaves_the_table_and_a_marked_one_stays() {
        let idle = SrcStateCounter {
            conn_count: 4,
            conn_rate: 4,
            window_start_ns: 0,
            flags: 0,
            _pad: [0; 7],
            overloaded_at_ns: 0,
        };
        assert_eq!(next_source_counter(idle, 0, 120 * SEC, 60 * SEC), None);
        let in_window = next_source_counter(idle, 0, 30 * SEC, 60 * SEC);
        assert_eq!(in_window.map(|c| (c.conn_count, c.conn_rate)), Some((0, 4)));
        let marked = SrcStateCounter {
            flags: SRC_COUNTER_FLAG_OVERLOADED,
            ..idle
        };
        assert!(next_source_counter(marked, 0, 120 * SEC, 60 * SEC).is_some());
        assert_eq!(
            next_source_counter(idle, 2, 120 * SEC, 60 * SEC).map(|c| c.conn_count),
            Some(2)
        );
    }
}
