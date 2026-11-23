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
//!
//! A flow handed over packet by packet also keeps its session, for `flow`
//! and its counters, held to Suricata by
//! `tests/fixtures/suricata/session-verdicts.txt`: the client is whoever
//! sent the flow's first packet; a TCP flow is established once its
//! handshake has completed, from the packet after the final ACK, or from
//! that ACK itself when it carries data, and stays so through its close; a
//! TCP flow first seen without its SYN is never established; another
//! protocol's flow is established from the first packet that answers it.
//! Counters include the packet being judged, count bytes from the link
//! layer, and `either` holds when either direction's count does. The age is
//! the second of the packet minus the second the flow began. ICMP between
//! two addresses is one flow, as Suricata keys it.

use std::collections::{HashMap, HashSet};

use ebpf_common::event::PacketEvent;

use super::applayer::{AppLayer, AppView};
use super::http1::Ready;
use super::sig::model::{
    BitOp, BitScope, Bits, Check, Flowint, FlowintOp, Signature, Threshold, ThresholdKind, Track,
    Value,
};
use super::stream::{Segment, Streams};
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
    sport: u16,
    now: u64,
    timeout: u64,
}

impl Packet {
    #[must_use]
    pub fn of(event: &PacketEvent) -> Self {
        let v6 = event.is_ipv6();
        let src = (event.src_addr, v6);
        let dst = (event.dst_addr, v6);
        let (sport, dport) = if matches!(event.protocol, 1 | 58) {
            (0, 0)
        } else {
            (event.src_port, event.dst_port)
        };
        let (low, high) = order((src, sport), (dst, dport));
        Self {
            flow: FlowKey {
                proto: event.protocol,
                low,
                high,
            },
            src,
            dst,
            sport,
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
    session: Option<Session>,
    /// A `pass`, `drop` or `reject` reached the flow: it is inspected no
    /// further.
    settled: bool,
}

/// How many transaction alerts a connection records before forgetting the
/// older transactions'.
const ALERTED_LIMIT: usize = 4096;
/// How many of the latest transactions keep their alerts past that.
const KEPT_TRANSACTIONS: u64 = 16;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// How far a TCP handshake has gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handshake {
    /// First seen without its SYN, or refused: never established.
    Midstream,
    SynSent,
    SynReceived,
    Established,
}

impl Handshake {
    /// The handshake after a packet with `flags` from the client (side 0)
    /// or the server (side 1).
    const fn after(self, side: usize, flags: u8) -> Self {
        let syn = flags & SYN != 0;
        let ack = flags & ACK != 0;
        match self {
            Self::SynSent | Self::SynReceived if flags & RST != 0 => Self::Midstream,
            Self::SynSent if side == 1 && syn && ack => Self::SynReceived,
            Self::SynReceived if side == 0 && ack && !syn => Self::Established,
            other => other,
        }
    }
}

/// What a flow handed over packet by packet knows of its session.
#[derive(Debug)]
struct Session {
    client: (Addr, u16),
    start_secs: u64,
    pkts: [u64; 2],
    bytes: [u64; 2],
    handshake: Handshake,
    /// The connection's byte streams, kept from its SYN on when rules read
    /// them.
    streams: Option<Box<Streams>>,
    /// The flow's application layer, kept beside the streams of a TCP
    /// connection or for a UDP flow when rules read it.
    app: Option<Box<AppLayer>>,
    /// The last packet each side sent, which the alerts raised when the
    /// flow ends are reported on.
    last: [Option<PacketEvent>; 2],
    /// Transaction sides parsed and waiting for the next packet their
    /// sender sends, which inspects them, client first.
    txs: [Vec<Ready>; 2],
    /// Each side's transaction sides inspected since its stream was last
    /// inspected, and the latest one before, which a rule reading the
    /// stream beside a transaction's buffers reads with the next window.
    open: [Open; 2],
    /// The rules that alerted on a transaction side: transaction, side,
    /// rule.
    alerted: HashSet<(u64, usize, usize)>,
    /// The transaction sides inspected for the last time: transaction,
    /// side.
    closed: HashSet<(u64, usize)>,
}

impl Session {
    /// Whether the flow's transactions are read beside its stream windows.
    fn windows(&self) -> bool {
        self.app.as_deref().is_some_and(AppLayer::windows)
    }

    fn seen(&self, side: usize, now: u64, established: bool) -> Seen {
        Seen {
            to_server: side == 0,
            established,
            age_secs: (now / NS).saturating_sub(self.start_secs),
            pkts: self.pkts,
            bytes: self.bytes,
            stream_size: self.streams.as_ref().map(|s| s.sizes()),
            app: self
                .app
                .as_ref()
                .map_or_else(AppView::default, |a| a.view(false)),
        }
    }
}

/// What the packet itself tells its session.
#[derive(Debug, Clone, Copy)]
pub struct Wire<'a> {
    /// The TCP flags, `None` for another protocol.
    pub tcp_flags: Option<u8>,
    /// Whether the packet carries a payload.
    pub payload: bool,
    /// The packet's length from the link layer.
    pub frame_len: u64,
    /// The TCP segment, for the connection's streams.
    pub segment: Option<Segment<'a>>,
    /// The UDP payload, for the flow's application layer.
    pub datagram: Option<&'a [u8]>,
}

/// What the session says of one packet, the packet counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Seen {
    /// Whether the client sent it.
    pub to_server: bool,
    pub established: bool,
    /// The packet's second minus the second the flow began.
    pub age_secs: u64,
    /// Packets towards the server, then towards the client.
    pub pkts: [u64; 2],
    /// Bytes towards the server, then towards the client.
    pub bytes: [u64; 2],
    /// Each side's `stream_size`, client first, when the connection's
    /// streams are kept: a TCP connection whose SYN was seen.
    pub stream_size: Option<[u64; 2]>,
    /// The flow's application protocol as the packet leaves it.
    pub app: AppView,
}

/// A side's bytes left when its flow ended, and what to report them on.
#[derive(Debug)]
pub struct Ended {
    /// The last packet the side sent.
    pub event: PacketEvent,
    /// The session as it stood, in the side's direction.
    pub seen: Seen,
    pub blocks: Vec<Vec<u8>>,
    /// The side's transactions not inspected yet.
    pub txs: Vec<Ready>,
    /// The side's transactions a window of its stream is read beside.
    pub open: Vec<Ready>,
}

/// What the session says of one packet and hands it to inspect.
#[derive(Debug)]
pub struct Observation {
    pub seen: Seen,
    /// The windows of the sender's stream the packet inspects.
    pub blocks: Vec<Vec<u8>>,
    /// The sender's transaction sides the packet inspects.
    pub txs: Vec<Ready>,
    /// The sender's transaction sides its windows are read beside.
    pub open: Vec<Ready>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: u64,
    count: u32,
}

/// A side's transaction sides a stream window is read beside.
#[derive(Debug, Clone, Default)]
struct Open {
    txs: Vec<Ready>,
    /// The one kept from the last window, which read it already.
    read: Option<u64>,
}

/// Add the transaction sides a packet inspects to those its side's stream
/// windows are read beside, each in its latest state, and hand them over
/// when the packet inspects a window: those not read by a window yet, or
/// the one the last window read when no other came. The next window is
/// then read beside the latest one alone, until more arrive. A flow whose
/// transactions are not `held` beside its stream hands none over.
fn hold_open(open: &mut Open, txs: &[Ready], window: bool, held: bool) -> Vec<Ready> {
    if !held {
        return Vec::new();
    }
    for tx in txs {
        open.txs.retain(|t| t.id != tx.id);
        open.txs.push(tx.clone());
        if open.read == Some(tx.id) {
            open.read = None;
        }
    }
    if !window {
        return Vec::new();
    }
    let read = open.read;
    let handed = if open.txs.iter().any(|t| Some(t.id) != read) {
        open.txs
            .iter()
            .filter(|t| Some(t.id) != read)
            .cloned()
            .collect()
    } else {
        open.txs.clone()
    };
    if let Some(latest) = open.txs.pop() {
        open.txs.clear();
        open.read = Some(latest.id);
        open.txs.push(latest);
    }
    handed
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
    /// Whether TCP connections keep their streams.
    streams: bool,
    /// Whether flows find their application protocol.
    app_layer: bool,
    /// The stream bytes every flow holds.
    held: u64,
    /// The second of the last sweep for ended flows.
    swept: u64,
}

/// The stream bytes a flow holds.
fn held(flow: &Flow) -> u64 {
    flow.session
        .as_ref()
        .and_then(|s| s.streams.as_ref())
        .map_or(0, |s| s.held())
}

impl FlowTable {
    /// Keep the packet's flow alive, if it holds anything.
    pub fn touch(&mut self, packet: &Packet) {
        if let Some(flow) = self.flows.get_mut(&packet.flow) {
            if packet.now.saturating_sub(flow.last) > packet.timeout {
                self.held = self.held.saturating_sub(held(flow));
                *flow = Flow::default();
            }
            flow.last = flow.last.max(packet.now);
        }
    }

    /// Keep the streams of TCP connections opened from now on, or not.
    pub fn keep_streams(&mut self, on: bool) {
        self.streams = on;
    }

    /// Find the application protocol of flows opened from now on, or not.
    /// A TCP connection needs its streams kept for it.
    pub fn keep_app_layer(&mut self, on: bool) {
        self.app_layer = on;
    }

    /// Count a packet handed over whole in its flow's session and say what
    /// the session knows of it, with the bytes of the sender's stream and
    /// the sender's transactions the packet inspects.
    pub fn observe(&mut self, packet: &Packet, event: &PacketEvent, wire: Wire<'_>) -> Observation {
        let streams = self.streams;
        let app_layer = self.app_layer;
        self.flow(packet);
        // The flow is in the table now; reach it through the field alone so
        // the memory the streams hold can be counted beside it.
        let flow = self.flows.entry(packet.flow).or_default();
        let session = flow.session.get_or_insert_with(|| {
            let opening = matches!(wire.tcp_flags, Some(flags) if flags & (SYN | ACK) == SYN);
            Session {
                client: (packet.src, packet.sport),
                start_secs: packet.now / NS,
                pkts: [0; 2],
                bytes: [0; 2],
                handshake: if opening {
                    Handshake::SynSent
                } else {
                    Handshake::Midstream
                },
                streams: (opening && streams).then(Box::default),
                app: match wire.tcp_flags {
                    Some(_) => opening && streams && app_layer,
                    None => event.protocol == 17 && app_layer,
                }
                .then(|| Box::new(AppLayer::new(wire.tcp_flags.is_none(), event.dst_port))),
                last: [None; 2],
                txs: [Vec::new(), Vec::new()],
                open: [Open::default(), Open::default()],
                alerted: HashSet::new(),
                closed: HashSet::new(),
            }
        });
        let side = usize::from((packet.src, packet.sport) != session.client);
        session.pkts[side] = session.pkts[side].saturating_add(1);
        session.bytes[side] = session.bytes[side].saturating_add(wire.frame_len);
        let established = match wire.tcp_flags {
            None => session.pkts.iter().all(|&n| n > 0),
            Some(flags) => {
                let before = session.handshake == Handshake::Established;
                session.handshake = session.handshake.after(side, flags);
                before || (session.handshake == Handshake::Established && wire.payload)
            }
        };
        let mut blocks = Vec::new();
        let mut sizes = None;
        let mut txs = std::mem::take(&mut session.txs[side]);
        let mut datagram_txs = Vec::new();
        let mut announced = session.app.as_mut().is_some_and(|app| app.begin(side));
        if let (Some(streams), Some(segment)) = (session.streams.as_mut(), wire.segment) {
            let observed = streams.observe(side, segment, &mut self.held);
            sizes = Some(observed.sizes);
            blocks = observed.blocks;
            session.last[side] = Some(*event);
            if let Some(app) = session.app.as_mut() {
                let other = 1 - side;
                let fed = app.feed(other, &observed.acked, side);
                announced |= fed.announced;
                if fed.inspect {
                    streams.inspect_next(other);
                }
                for tx in fed.txs {
                    if session.closed.contains(&(tx.id, tx.side)) {
                        continue;
                    }
                    // A side standing as a whole is read on this packet when
                    // it travels this way, and replaces the older one still
                    // waiting.
                    let queue = if tx.latest && tx.side == side {
                        &mut txs
                    } else {
                        &mut session.txs[tx.side]
                    };
                    if tx.latest {
                        queue.retain(|t| !(t.latest && t.id == tx.id));
                    }
                    queue.push(tx);
                }
                if segment.flags & (FIN | RST) != 0 {
                    announced |= app.close(side);
                }
            }
        } else if let (Some(app), Some(data)) = (session.app.as_mut(), wire.datagram) {
            // A datagram's transaction is read on the datagram itself.
            let fed = app.feed(side, data, side);
            announced |= fed.announced;
            datagram_txs = fed.txs;
        }
        let mut seen = session.seen(side, packet.now, established);
        if sizes.is_some() {
            seen.stream_size = sizes;
        }
        seen.app.announced = announced;
        txs.extend(datagram_txs);
        // A side's last state, inspected on this packet, is its last
        // inspection.
        for tx in txs.iter().filter(|t| t.last) {
            session.closed.insert((tx.id, tx.side));
        }
        let held = session.windows() && session.streams.is_some();
        let open = hold_open(&mut session.open[side], &txs, !blocks.is_empty(), held);
        Observation {
            seen,
            blocks,
            txs,
            open,
        }
    }

    /// Hand over the stream bytes of the flows idle past their timeout, at
    /// most once a second of packet time: the flows end, as Suricata ends
    /// them, and what they held is inspected.
    pub fn drain_idle(&mut self, now: u64) -> Vec<Ended> {
        if now / NS == self.swept {
            return Vec::new();
        }
        self.swept = now / NS;
        let timeout = |proto: u8| {
            if proto == 6 {
                TCP_TIMEOUT_NS
            } else {
                OTHER_TIMEOUT_NS
            }
        };
        self.drain(|key, flow| now.saturating_sub(flow.last) > timeout(key.proto))
    }

    /// Hand over the stream bytes every flow holds, as when the capture
    /// ends.
    pub fn drain_all(&mut self) -> Vec<Ended> {
        self.drain(|_, _| true)
    }

    fn drain(&mut self, ends: impl Fn(&FlowKey, &Flow) -> bool) -> Vec<Ended> {
        let mut ended = Vec::new();
        for (key, flow) in &mut self.flows {
            if !ends(key, flow) {
                continue;
            }
            let Some(session) = flow.session.as_mut() else {
                continue;
            };
            let mut txs = std::mem::take(&mut session.txs);
            let mut open = std::mem::take(&mut session.open);
            if let Some(app) = session.app.as_mut() {
                for tx in app.end() {
                    txs[tx.side].push(tx);
                }
            }
            let drained = match session.streams.as_mut().filter(|s| s.pending()) {
                Some(streams) => streams.drain(&mut self.held),
                None => [Vec::new(), Vec::new()],
            };
            let established = session.handshake == Handshake::Established;
            for (side, (blocks, txs)) in drained.into_iter().zip(txs).enumerate() {
                let Some(event) =
                    session.last[side].filter(|_| !blocks.is_empty() || !txs.is_empty())
                else {
                    continue;
                };
                let open = hold_open(&mut open[side], &txs, !blocks.is_empty(), session.windows());
                ended.push(Ended {
                    event,
                    seen: session.seen(side, flow.last, established),
                    blocks,
                    txs,
                    open,
                });
            }
        }
        ended
    }

    /// Whether a `pass`, `drop` or `reject` reached the packet's flow.
    #[must_use]
    pub fn settled(&self, packet: &Packet) -> bool {
        self.flows.get(&packet.flow).is_some_and(|f| f.settled)
    }

    /// Inspect the packet's flow no further.
    pub fn settle(&mut self, packet: &Packet) {
        self.flow(packet).settled = true;
    }

    /// Whether `rule` alerts on this side of the flow's transaction for the
    /// first time, which it then records. A connection remembers the
    /// latest transactions only, a transaction long answered being
    /// inspected no more.
    pub fn first_alert(&mut self, packet: &Packet, tx: u64, side: usize, rule: usize) -> bool {
        let Some(session) = self
            .flows
            .get_mut(&packet.flow)
            .and_then(|f| f.session.as_mut())
        else {
            return true;
        };
        if session.alerted.len() >= ALERTED_LIMIT {
            let floor = tx.saturating_sub(KEPT_TRANSACTIONS);
            session.alerted.retain(|&(id, _, _)| id >= floor);
        }
        session.alerted.insert((tx, side, rule))
    }

    /// Forget the filters' counters, whose rule indices no longer hold.
    pub fn forget_filters(&mut self) {
        self.filters.clear();
    }

    fn flow(&mut self, packet: &Packet) -> &mut Flow {
        if !self.flows.contains_key(&packet.flow) && self.flows.len() >= MAX_ENTRIES {
            let now = packet.now;
            let mut freed = 0;
            self.flows.retain(|_, f| {
                let keep = now.saturating_sub(f.last) <= packet.timeout;
                if !keep {
                    freed += held(f);
                }
                keep
            });
            if self.flows.len() >= MAX_ENTRIES {
                let mut ages: Vec<u64> = self.flows.values().map(|f| f.last).collect();
                let middle = ages.len() / 2;
                let (_, cut, _) = ages.select_nth_unstable(middle);
                let cut = *cut;
                self.flows.retain(|_, f| {
                    let keep = f.last > cut;
                    if !keep {
                        freed += held(f);
                    }
                    keep
                });
            }
            self.held = self.held.saturating_sub(freed);
        }
        let flow = self.flows.entry(packet.flow).or_default();
        if packet.now.saturating_sub(flow.last) > packet.timeout {
            self.held = self.held.saturating_sub(held(flow));
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
