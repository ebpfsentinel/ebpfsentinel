//! What a flow, a host and a pair of hosts remember between packets, for the
//! imported rules that read or write it: `flowbits`, `xbits`, `hostbits`,
//! `flowint`, `noalert` and `detection_filter`.
//!
//! Each behaviour is held to a real Suricata by
//! `tests/fixtures/suricata/flow-verdicts.txt`: a bit set on one packet is
//! seen by the packets of either direction after it, a rule that writes state
//! runs before a rule that only reads it on the same packet, `a|b` tests any
//! of the names and nothing else is split, a host or pair bit expires
//! `expire` seconds after it was first set (30 when unnamed) and setting it
//! again does not push that back, a rule writes its bits and its `flowint`s
//! only once every test of it held, so `flowint:n,+,1; flowint:n,>,2` never
//! counts, and a `detection_filter` alerts on every match past its count
//! until its window, opened by the first match, has run past its seconds.
//!
//! Time is the packet's timestamp, so a replayed capture ages as it did on
//! the wire.

use std::collections::{HashMap, HashSet};

use ebpf_common::event::PacketEvent;

use super::sig::model::{
    BitOp, BitScope, Bits, Check, Flowint, FlowintOp, Signature, Threshold, ThresholdKind, Track,
    Value,
};
use super::suricata::{Compiled, Refused};

const NS: u64 = 1_000_000_000;
/// Suricata's default idle timeout of an established TCP flow.
const TCP_TIMEOUT_NS: u64 = 600 * NS;
/// Suricata's default idle timeout of an established flow of another
/// protocol.
const OTHER_TIMEOUT_NS: u64 = 300 * NS;
/// Seconds a host or pair bit lives when its rule names no `expire`, as in
/// Suricata.
const DEFAULT_EXPIRE_SECS: u64 = 30;
/// Entries each table keeps before it drops the idle ones, then the oldest.
const MAX_ENTRIES: usize = 65_536;

/// An address, and whether it is IPv6.
type Addr = ([u32; 4], bool);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    low: (Addr, u16),
    high: (Addr, u16),
}

/// Where a host or pair bit lives. A pair is the same pair whichever
/// address sent the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum HostKey {
    Host(Addr),
    Pair(Addr, Addr),
}

/// What a `detection_filter` counts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Tracked {
    Rule,
    Host(HostKey),
    Flow(FlowKey),
}

/// The packet as the state tables see it.
#[derive(Debug, Clone, Copy)]
pub struct Packet {
    flow: FlowKey,
    src: Addr,
    dst: Addr,
    now: u64,
    timeout: u64,
}

impl Packet {
    #[must_use]
    pub fn of(event: &PacketEvent) -> Self {
        let v6 = event.is_ipv6();
        let src = (event.src_addr, v6);
        let dst = (event.dst_addr, v6);
        let (low, high) = order((src, event.src_port), (dst, event.dst_port));
        Self {
            flow: FlowKey {
                proto: event.protocol,
                low,
                high,
            },
            src,
            dst,
            now: event.timestamp_ns,
            timeout: if event.protocol == 6 {
                TCP_TIMEOUT_NS
            } else {
                OTHER_TIMEOUT_NS
            },
        }
    }

    fn pair(&self) -> HostKey {
        let (a, b) = order(self.src, self.dst);
        HostKey::Pair(a, b)
    }
}

fn order<T: Ord>(a: T, b: T) -> (T, T) {
    if a <= b { (a, b) } else { (b, a) }
}

#[derive(Debug, Default)]
struct Flow {
    last: u64,
    bits: HashSet<String>,
    ints: HashMap<String, i64>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: u64,
    count: u32,
}

/// The state every flow, host and pair holds for the rules, and the
/// counters of their `detection_filter`s.
#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    /// Bit name to the time it expires.
    hosts: HashMap<HostKey, HashMap<String, u64>>,
    /// By rule index and what the rule tracks.
    filters: HashMap<(usize, Tracked), Window>,
}

impl FlowTable {
    /// Keep the packet's flow alive, if it holds anything.
    pub fn touch(&mut self, packet: &Packet) {
        if let Some(flow) = self.flows.get_mut(&packet.flow) {
            if packet.now.saturating_sub(flow.last) > packet.timeout {
                *flow = Flow::default();
            }
            flow.last = flow.last.max(packet.now);
        }
    }

    /// Forget the filters' counters, whose rule indices no longer hold.
    pub fn forget_filters(&mut self) {
        self.filters.clear();
    }

    fn flow(&mut self, packet: &Packet) -> &mut Flow {
        if !self.flows.contains_key(&packet.flow) && self.flows.len() >= MAX_ENTRIES {
            let now = packet.now;
            self.flows
                .retain(|_, f| now.saturating_sub(f.last) <= packet.timeout);
            if self.flows.len() >= MAX_ENTRIES {
                let mut ages: Vec<u64> = self.flows.values().map(|f| f.last).collect();
                let middle = ages.len() / 2;
                let (_, cut, _) = ages.select_nth_unstable(middle);
                let cut = *cut;
                self.flows.retain(|_, f| f.last > cut);
            }
        }
        let flow = self.flows.entry(packet.flow).or_default();
        if packet.now.saturating_sub(flow.last) > packet.timeout {
            *flow = Flow::default();
        }
        flow.last = flow.last.max(packet.now);
        flow
    }

    fn host_bit(&self, key: HostKey, name: &str, now: u64) -> bool {
        self.hosts
            .get(&key)
            .and_then(|bits| bits.get(name))
            .is_some_and(|expires| now <= *expires)
    }

    fn host_bits(&mut self, key: HostKey, now: u64) -> &mut HashMap<String, u64> {
        if !self.hosts.contains_key(&key) && self.hosts.len() >= MAX_ENTRIES {
            self.hosts.retain(|_, bits| {
                bits.retain(|_, expires| now <= *expires);
                !bits.is_empty()
            });
            if self.hosts.len() >= MAX_ENTRIES {
                let mut ends: Vec<u64> = self
                    .hosts
                    .values()
                    .map(|bits| bits.values().copied().max().unwrap_or(0))
                    .collect();
                let middle = ends.len() / 2;
                let (_, cut, _) = ends.select_nth_unstable(middle);
                let cut = *cut;
                self.hosts
                    .retain(|_, bits| bits.values().copied().max().unwrap_or(0) > cut);
            }
        }
        self.hosts.entry(key).or_default()
    }

    fn filter(&mut self, key: (usize, Tracked), now: u64, seconds: u64) -> &mut Window {
        if !self.filters.contains_key(&key) && self.filters.len() >= MAX_ENTRIES {
            self.filters
                .retain(|_, w| now.saturating_sub(w.start) <= seconds.saturating_mul(NS));
            if self.filters.len() >= MAX_ENTRIES {
                self.filters.clear();
            }
        }
        self.filters.entry(key).or_insert(Window {
            start: now,
            count: 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    Flow,
    Src,
    Dst,
    Pair,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arith {
    Set,
    Add,
    Sub,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Operand {
    Lit(i64),
    /// Another `flowint` of the flow.
    Var(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Test {
    Bits {
        place: Place,
        names: Vec<String>,
        /// `isset` rather than `isnotset`.
        set: bool,
    },
    Int {
        name: String,
        cmp: Cmp,
        value: Operand,
    },
    IntSet {
        name: String,
        set: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Write {
    Bit {
        place: Place,
        name: String,
        op: BitOp,
        expire: u64,
    },
    Int {
        name: String,
        op: Arith,
        value: Operand,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Filter {
    track: Track,
    count: u32,
    seconds: u64,
}

/// What one rule reads and writes outside the packet, ready to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    tests: Vec<Test>,
    writes: Vec<Write>,
    noalert: bool,
    filter: Option<Filter>,
}

impl State {
    /// The state a signature reads and writes, `None` when it touches none.
    ///
    /// # Errors
    ///
    /// Refuses an `xbits` bit kept on a transaction or kept nowhere, and a
    /// `detection_filter` counting distinct ports.
    pub fn compile(signature: &Signature) -> Compiled<Option<Self>> {
        let mut state = Self {
            tests: Vec::new(),
            writes: Vec::new(),
            noalert: signature.noalert,
            filter: signature.detection_filter.map(filter).transpose()?,
        };
        for check in &signature.checks {
            match check {
                Check::Bits(bits) => state.bits(bits)?,
                Check::Flowint(int) => state.flowint(int),
                _ => {}
            }
        }
        let empty = state.tests.is_empty()
            && state.writes.is_empty()
            && !state.noalert
            && state.filter.is_none();
        Ok((!empty).then_some(state))
    }

    fn bits(&mut self, bits: &Bits) -> Compiled<()> {
        let place = match bits.scope {
            BitScope::Flow => Place::Flow,
            BitScope::IpSrc => Place::Src,
            BitScope::IpDst => Place::Dst,
            BitScope::IpPair => Place::Pair,
            BitScope::Transaction => {
                return Err(Refused::new(
                    bits.keyword,
                    "with 'track tx' keeps its bit on an application transaction, and no parser hands transactions over yet",
                ));
            }
            BitScope::Untracked => {
                return Err(Refused::new(
                    bits.keyword,
                    "names no 'track', and Suricata then keeps the bit nowhere",
                ));
            }
        };
        let expire = bits
            .expire
            .map_or(DEFAULT_EXPIRE_SECS, u64::from)
            .saturating_mul(NS);
        match bits.op {
            BitOp::IsSet | BitOp::IsNotSet => self.tests.push(Test::Bits {
                place,
                names: bits.names.clone(),
                set: bits.op == BitOp::IsSet,
            }),
            op => self.writes.extend(bits.names.iter().map(|name| Write::Bit {
                place,
                name: name.clone(),
                op,
                expire,
            })),
        }
        Ok(())
    }

    fn flowint(&mut self, int: &Flowint) {
        let name = int.name.clone();
        let value = match &int.value {
            Some(Value::Lit(n)) => Operand::Lit(*n),
            Some(Value::Var(v)) => Operand::Var(v.clone()),
            None => Operand::Lit(0),
        };
        let cmp = |cmp| Test::Int {
            name: name.clone(),
            cmp,
            value: value.clone(),
        };
        let arith = |op| Write::Int {
            name: name.clone(),
            op,
            value: value.clone(),
        };
        match int.op {
            FlowintOp::Set => self.writes.push(arith(Arith::Set)),
            FlowintOp::Add => self.writes.push(arith(Arith::Add)),
            FlowintOp::Sub => self.writes.push(arith(Arith::Sub)),
            FlowintOp::Eq => self.tests.push(cmp(Cmp::Eq)),
            FlowintOp::Ne => self.tests.push(cmp(Cmp::Ne)),
            FlowintOp::Lt => self.tests.push(cmp(Cmp::Lt)),
            FlowintOp::Le => self.tests.push(cmp(Cmp::Le)),
            FlowintOp::Gt => self.tests.push(cmp(Cmp::Gt)),
            FlowintOp::Ge => self.tests.push(cmp(Cmp::Ge)),
            FlowintOp::IsSet => self.tests.push(Test::IntSet {
                name: name.clone(),
                set: true,
            }),
            FlowintOp::IsNotSet => self.tests.push(Test::IntSet {
                name: name.clone(),
                set: false,
            }),
        }
    }

    /// Where the rule runs among those a packet matched: a rule that writes
    /// state and reads it first, then one that only writes, then one that
    /// only reads, as Suricata orders them, so a bit set on a packet is seen
    /// by the rules that test it on that same packet.
    #[must_use]
    pub fn rank(&self) -> u8 {
        match (self.tests.is_empty(), self.writes.is_empty()) {
            (false, false) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (true, true) => 3,
        }
    }

    /// Run the rule's state on a packet its matches held on: whether every
    /// test holds, then, if so, its writes. Returns whether the rule
    /// alerts: its tests held, it carries no `noalert`, and its
    /// `detection_filter`, if any, has counted past its count.
    pub fn run(&self, table: &mut FlowTable, packet: &Packet, rule: usize) -> bool {
        if !self.tests.iter().all(|t| test(t, table, packet)) {
            return false;
        }
        for w in &self.writes {
            write(w, table, packet);
        }
        if self.noalert {
            return false;
        }
        let Some(f) = self.filter else {
            return true;
        };
        let tracked = match f.track {
            Track::BySrc => Tracked::Host(HostKey::Host(packet.src)),
            Track::ByDst => Tracked::Host(HostKey::Host(packet.dst)),
            Track::ByBoth => Tracked::Host(packet.pair()),
            Track::ByRule => Tracked::Rule,
            Track::ByFlow => Tracked::Flow(packet.flow),
        };
        let window = table.filter((rule, tracked), packet.now, f.seconds);
        if packet.now.saturating_sub(window.start) > f.seconds.saturating_mul(NS) {
            *window = Window {
                start: packet.now,
                count: 0,
            };
        }
        window.count = window.count.saturating_add(1);
        window.count > f.count
    }
}

fn filter(threshold: Threshold) -> Compiled<Filter> {
    if threshold.unique_on {
        return Err(Refused::new(
            "detection_filter",
            "with 'unique_on' counts distinct ports, which the engine does not count yet",
        ));
    }
    debug_assert_eq!(threshold.kind, ThresholdKind::Threshold);
    Ok(Filter {
        track: threshold.track,
        count: threshold.count,
        seconds: u64::from(threshold.seconds),
    })
}

fn host(place: Place, packet: &Packet) -> HostKey {
    match place {
        Place::Dst => HostKey::Host(packet.dst),
        Place::Pair => packet.pair(),
        Place::Src | Place::Flow => HostKey::Host(packet.src),
    }
}

fn bit(table: &mut FlowTable, place: Place, name: &str, packet: &Packet) -> bool {
    match place {
        Place::Flow => table.flow(packet).bits.contains(name),
        _ => table.host_bit(host(place, packet), name, packet.now),
    }
}

/// The right side of a `flowint` operation. A variable never set reads 0,
/// as in Suricata.
fn operand(value: &Operand, flow: &Flow) -> i64 {
    match value {
        Operand::Lit(n) => *n,
        Operand::Var(name) => flow.ints.get(name).copied().unwrap_or(0),
    }
}

fn test(t: &Test, table: &mut FlowTable, packet: &Packet) -> bool {
    match t {
        // One name, or the names of `a|b`: `isset` holds when any is set,
        // `isnotset` when any is not.
        Test::Bits { place, names, set } => names
            .iter()
            .any(|name| bit(table, *place, name, packet) == *set),
        Test::Int { name, cmp, value } => {
            let flow = table.flow(packet);
            let Some(left) = flow.ints.get(name).copied() else {
                return false;
            };
            let right = operand(value, flow);
            match cmp {
                Cmp::Eq => left == right,
                Cmp::Ne => left != right,
                Cmp::Lt => left < right,
                Cmp::Le => left <= right,
                Cmp::Gt => left > right,
                Cmp::Ge => left >= right,
            }
        }
        Test::IntSet { name, set } => table.flow(packet).ints.contains_key(name) == *set,
    }
}

fn write(w: &Write, table: &mut FlowTable, packet: &Packet) {
    match w {
        Write::Bit {
            place: Place::Flow,
            name,
            op,
            ..
        } => {
            let bits = &mut table.flow(packet).bits;
            let on = match op {
                BitOp::Set => true,
                BitOp::Unset => false,
                _ => !bits.contains(name.as_str()),
            };
            if on {
                bits.insert(name.clone());
            } else {
                bits.remove(name.as_str());
            }
        }
        Write::Bit {
            place,
            name,
            op,
            expire,
        } => {
            let now = packet.now;
            let was = table.host_bit(host(*place, packet), name, now);
            let on = match op {
                BitOp::Set => true,
                BitOp::Unset => false,
                _ => !was,
            };
            let bits = table.host_bits(host(*place, packet), now);
            match (on, was) {
                // A bit set again keeps the expiry its first setting gave it.
                (true, true) => {}
                (true, false) => {
                    bits.insert(name.clone(), now.saturating_add(*expire));
                }
                (false, _) => {
                    bits.remove(name.as_str());
                }
            }
        }
        Write::Int { name, op, value } => {
            let flow = table.flow(packet);
            let value = operand(value, flow);
            let current = flow.ints.get(name).copied().unwrap_or(0);
            let next = match op {
                Arith::Set => value,
                Arith::Add => current.saturating_add(value),
                Arith::Sub => current.saturating_sub(value),
            };
            flow.ints.insert(name.clone(), next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::sig::parse_signature;
    use crate::ids::suricata::SuricataVars;

    fn state(options: &str) -> Compiled<Option<State>> {
        let text =
            format!("alert tcp any any -> any 80 (msg:\"x\"; content:\"a\"; {options} sid:1;)");
        let signature = parse_signature(&text, &SuricataVars::default()).expect("parses");
        State::compile(&signature)
    }

    fn packet(src: u32, sport: u16, now_secs: u64) -> Packet {
        let event = PacketEvent {
            timestamp_ns: now_secs * NS,
            src_addr: [src, 0, 0, 0],
            dst_addr: [0x0A00_0002, 0, 0, 0],
            src_port: sport,
            dst_port: 80,
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
            pkt_len: 0,
            _pad: 0,
        };
        Packet::of(&event)
    }

    #[test]
    fn a_rule_touching_no_state_compiles_to_none() {
        assert_eq!(state(""), Ok(None));
    }

    #[test]
    fn refuses_bits_kept_nowhere_or_on_a_transaction() {
        let untracked = state("xbits:set,a;").expect_err("refused");
        assert!(untracked.reason.contains("nowhere"));
        let tx = state("xbits:set,a,track tx;").expect_err("refused");
        assert!(tx.reason.contains("transaction"));
        let unique =
            state("detection_filter:track by_src, count 1, seconds 5, unique_on dst_port;")
                .expect_err("refused");
        assert_eq!(unique.keyword, "detection_filter");
    }

    #[test]
    fn a_writer_runs_before_a_reader() {
        let set = state("flowbits:set,a;").expect("compiles").expect("state");
        let isset = state("flowbits:isset,a;")
            .expect("compiles")
            .expect("state");
        let both = state("flowbits:isset,b; flowbits:set,a;")
            .expect("compiles")
            .expect("state");
        assert!(both.rank() < set.rank() && set.rank() < isset.rank());
    }

    #[test]
    fn an_idle_flow_forgets_its_bits() {
        let set = state("flowbits:set,a;").expect("compiles").expect("state");
        let isset = state("flowbits:isset,a;")
            .expect("compiles")
            .expect("state");
        let mut table = FlowTable::default();
        assert!(set.run(&mut table, &packet(1, 1000, 0), 0));
        assert!(isset.run(&mut table, &packet(1, 1000, 600), 1));
        assert!(!isset.run(&mut table, &packet(1, 1000, 1201), 1));
    }

    #[test]
    fn a_full_table_drops_its_idle_flows_then_its_oldest() {
        let set = state("flowbits:set,a;").expect("compiles").expect("state");
        let isset = state("flowbits:isset,a;")
            .expect("compiles")
            .expect("state");
        let mut table = FlowTable::default();
        let total = u32::try_from(MAX_ENTRIES).expect("fits");
        for n in 0..total {
            let sport = u16::try_from(n % 60_000).expect("fits");
            set.run(&mut table, &packet(n / 60_000 + 1, sport, u64::from(n)), 0);
        }
        assert_eq!(table.flows.len(), MAX_ENTRIES);
        set.run(&mut table, &packet(100, 1, u64::from(total)), 0);
        assert!(table.flows.len() <= MAX_ENTRIES / 2 + 1);
        assert!(isset.run(&mut table, &packet(100, 1, u64::from(total)), 1));
        let last = total - 1;
        let sport = u16::try_from(last % 60_000).expect("fits");
        assert!(isset.run(
            &mut table,
            &packet(last / 60_000 + 1, sport, u64::from(total)),
            1
        ));
    }

    #[test]
    fn forgetting_filters_restarts_their_count() {
        let filter = state("detection_filter:track by_rule, count 1, seconds 60;")
            .expect("compiles")
            .expect("state");
        let mut table = FlowTable::default();
        assert!(!filter.run(&mut table, &packet(1, 1, 0), 0));
        assert!(filter.run(&mut table, &packet(1, 1, 1), 0));
        table.forget_filters();
        assert!(!filter.run(&mut table, &packet(1, 1, 2), 0));
    }
}
