//! The kernel connection tracking table, read and changed over ctnetlink.
//!
//! A dump is rendered in the text of `/proc/net/nf_conntrack`, which is what
//! the agent already parses, so a kernel built without that file answers the
//! agent with the same lines one built with it does.

use std::io;
use std::net::IpAddr;

use ebpfsentinel_warden_proto::{CONNTRACK_RESTORE_TIMEOUT_SECS, ConntrackRestore, ConntrackTuple};

use crate::netlink::{
    self, Message, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST, Socket,
};

const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_NEW: u16 = 0;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_STATUS: u16 = 3;
const CTA_PROTOINFO: u16 = 4;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_USE: u16 = 11;
const CTA_ZONE: u16 = 18;

const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_PROTO_ICMP_ID: u16 = 4;
const CTA_PROTO_ICMP_TYPE: u16 = 5;
const CTA_PROTO_ICMP_CODE: u16 = 6;
const CTA_PROTO_ICMPV6_ID: u16 = 7;
const CTA_PROTO_ICMPV6_TYPE: u16 = 8;
const CTA_PROTO_ICMPV6_CODE: u16 = 9;

const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const CTA_PROTOINFO_TCP_FLAGS_ORIGINAL: u16 = 4;
const CTA_PROTOINFO_TCP_FLAGS_REPLY: u16 = 5;

/// `IP_CT_TCP_FLAG_BE_LIBERAL`: the direction is not held to a tracked window.
const TCP_FLAG_BE_LIBERAL: u8 = 0x08;

const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;

const IPS_SEEN_REPLY: u32 = 1 << 1;
const IPS_ASSURED: u32 = 1 << 2;
const IPS_CONFIRMED: u32 = 1 << 3;
const TCP_CONNTRACK_ESTABLISHED: u8 = 3;

/// The kernel's names for its TCP tracking states, by number.
const TCP_STATES: [&str; 10] = [
    "NONE",
    "SYN_SENT",
    "SYN_RECV",
    "ESTABLISHED",
    "FIN_WAIT",
    "CLOSE_WAIT",
    "LAST_ACK",
    "TIME_WAIT",
    "CLOSE",
    "SYN_SENT2",
];

fn kind(msg: u16) -> u16 {
    (NFNL_SUBSYS_CTNETLINK << 8) | msg
}

/// The netfilter family header: the address family, version 0, no resource.
fn nfgenmsg(family: u8) -> [u8; 4] {
    [family, 0, 0, 0]
}

fn family_of(ip: IpAddr) -> u8 {
    let family = if ip.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    u8::try_from(family).unwrap_or(2)
}

/// One direction of a tracked connection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tuple {
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    proto: u8,
    ports: Option<(u16, u16)>,
    icmp: Option<(u8, u8, u16)>,
}

/// One tracked connection as a dump carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    family: u8,
    orig: Tuple,
    reply: Option<Tuple>,
    status: u32,
    timeout: u32,
    tcp_state: Option<u8>,
    counters_orig: Option<(u64, u64)>,
    counters_reply: Option<(u64, u64)>,
    mark: u32,
    zone: u16,
    use_count: u32,
    /// The original tuple and zone as the kernel wrote them, handed back
    /// verbatim to delete the entry.
    raw_orig: Vec<u8>,
    raw_zone: Option<Vec<u8>>,
}

fn address(payload: &[u8]) -> Option<IpAddr> {
    match payload.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(payload).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(payload).ok()?)),
        _ => None,
    }
}

fn first_byte(payload: &[u8]) -> Option<u8> {
    payload.first().copied()
}

fn parse_tuple(payload: &[u8]) -> Option<Tuple> {
    let ip = netlink::attribute(payload, CTA_TUPLE_IP).unwrap_or_default();
    let src = netlink::attribute(ip, CTA_IP_V4_SRC)
        .or_else(|| netlink::attribute(ip, CTA_IP_V6_SRC))
        .and_then(address);
    let dst = netlink::attribute(ip, CTA_IP_V4_DST)
        .or_else(|| netlink::attribute(ip, CTA_IP_V6_DST))
        .and_then(address);
    let proto_block = netlink::attribute(payload, CTA_TUPLE_PROTO)?;
    let proto = netlink::attribute(proto_block, CTA_PROTO_NUM).and_then(first_byte)?;
    let ports = match (
        netlink::attribute(proto_block, CTA_PROTO_SRC_PORT).and_then(netlink::be16),
        netlink::attribute(proto_block, CTA_PROTO_DST_PORT).and_then(netlink::be16),
    ) {
        (Some(s), Some(d)) => Some((s, d)),
        _ => None,
    };
    let (id, kind, code) = if proto == 58 {
        (
            CTA_PROTO_ICMPV6_ID,
            CTA_PROTO_ICMPV6_TYPE,
            CTA_PROTO_ICMPV6_CODE,
        )
    } else {
        (CTA_PROTO_ICMP_ID, CTA_PROTO_ICMP_TYPE, CTA_PROTO_ICMP_CODE)
    };
    let icmp = match (
        netlink::attribute(proto_block, kind).and_then(first_byte),
        netlink::attribute(proto_block, code).and_then(first_byte),
        netlink::attribute(proto_block, id).and_then(netlink::be16),
    ) {
        (Some(t), Some(c), Some(i)) => Some((t, c, i)),
        _ => None,
    };
    Some(Tuple {
        src,
        dst,
        proto,
        ports,
        icmp,
    })
}

fn parse_counters(payload: &[u8]) -> Option<(u64, u64)> {
    Some((
        netlink::attribute(payload, CTA_COUNTERS_PACKETS).and_then(netlink::be64)?,
        netlink::attribute(payload, CTA_COUNTERS_BYTES).and_then(netlink::be64)?,
    ))
}

/// One dump message: the family header, then the connection's attributes.
fn parse_entry(body: &[u8]) -> Option<Entry> {
    let family = *body.first()?;
    let attrs = body.get(4..)?;
    let raw_orig = netlink::attribute(attrs, CTA_TUPLE_ORIG)?;
    let tcp_state = netlink::attribute(attrs, CTA_PROTOINFO)
        .and_then(|p| netlink::attribute(p, CTA_PROTOINFO_TCP))
        .and_then(|t| netlink::attribute(t, CTA_PROTOINFO_TCP_STATE))
        .and_then(first_byte);
    let raw_zone = netlink::attribute(attrs, CTA_ZONE);
    Some(Entry {
        family,
        orig: parse_tuple(raw_orig)?,
        reply: netlink::attribute(attrs, CTA_TUPLE_REPLY).and_then(parse_tuple),
        status: netlink::attribute(attrs, CTA_STATUS)
            .and_then(netlink::be32)
            .unwrap_or(0),
        timeout: netlink::attribute(attrs, CTA_TIMEOUT)
            .and_then(netlink::be32)
            .unwrap_or(0),
        tcp_state,
        counters_orig: netlink::attribute(attrs, CTA_COUNTERS_ORIG).and_then(parse_counters),
        counters_reply: netlink::attribute(attrs, CTA_COUNTERS_REPLY).and_then(parse_counters),
        mark: netlink::attribute(attrs, CTA_MARK)
            .and_then(netlink::be32)
            .unwrap_or(0),
        zone: raw_zone.and_then(netlink::be16).unwrap_or(0),
        use_count: netlink::attribute(attrs, CTA_USE)
            .and_then(netlink::be32)
            .unwrap_or(0),
        raw_orig: raw_orig.to_vec(),
        raw_zone: raw_zone.map(<[u8]>::to_vec),
    })
}

fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        33 => "dccp",
        47 => "gre",
        58 => "icmpv6",
        132 => "sctp",
        136 => "udplite",
        _ => "unknown",
    }
}

fn render_tuple(out: &mut String, tuple: &Tuple, counters: Option<(u64, u64)>) {
    use std::fmt::Write as _;
    if let Some(src) = tuple.src {
        let _ = write!(out, " src={src}");
    }
    if let Some(dst) = tuple.dst {
        let _ = write!(out, " dst={dst}");
    }
    if let Some((sport, dport)) = tuple.ports {
        let _ = write!(out, " sport={sport} dport={dport}");
    } else if let Some((kind, code, id)) = tuple.icmp {
        let _ = write!(out, " type={kind} code={code} id={id}");
    }
    if let Some((packets, bytes)) = counters {
        let _ = write!(out, " packets={packets} bytes={bytes}");
    }
}

/// The entry as one line of `/proc/net/nf_conntrack`.
fn render(entry: &Entry) -> String {
    use std::fmt::Write as _;
    let ipv6 = i32::from(entry.family) == libc::AF_INET6;
    let mut out = String::with_capacity(256);
    let _ = write!(
        out,
        "{} {} {} {} {}",
        if ipv6 { "ipv6" } else { "ipv4" },
        entry.family,
        protocol_name(entry.orig.proto),
        entry.orig.proto,
        entry.timeout
    );
    if entry.orig.proto == 6 {
        let state = entry
            .tcp_state
            .and_then(|s| TCP_STATES.get(usize::from(s)))
            .unwrap_or(&"NONE");
        let _ = write!(out, " {state}");
    }
    render_tuple(&mut out, &entry.orig, entry.counters_orig);
    if entry.status & IPS_SEEN_REPLY == 0 {
        out.push_str(" [UNREPLIED]");
    }
    if let Some(reply) = &entry.reply {
        render_tuple(&mut out, reply, entry.counters_reply);
    }
    if entry.status & IPS_ASSURED != 0 {
        out.push_str(" [ASSURED]");
    }
    let _ = write!(out, " mark={}", entry.mark);
    if entry.zone != 0 {
        let _ = write!(out, " zone={}", entry.zone);
    }
    let _ = write!(out, " use={}", entry.use_count);
    out
}

/// Whether the error means connection tracking is not in this kernel at all,
/// which is an empty table rather than a failure.
fn tracking_absent(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EOPNOTSUPP | libc::EPROTONOSUPPORT | libc::ENOENT)
    )
}

fn entries() -> Result<Vec<Entry>, String> {
    let sock = Socket::open(libc::NETLINK_NETFILTER)
        .map_err(|e| format!("open the conntrack netlink socket: {e}"))?;
    let unspec = u8::try_from(libc::AF_UNSPEC).unwrap_or(0);
    let request = Message::new(
        kind(IPCTNL_MSG_CT_GET),
        NLM_F_REQUEST | NLM_F_DUMP,
        &nfgenmsg(unspec),
    )
    .finish();
    match sock.exchange(&request) {
        Ok(messages) => Ok(messages.iter().filter_map(|m| parse_entry(m)).collect()),
        Err(e) if tracking_absent(&e) => Ok(Vec::new()),
        Err(e) => Err(format!("dump the conntrack table: {e}")),
    }
}

/// The whole table, one `/proc/net/nf_conntrack` line per connection.
pub fn dump() -> Result<Vec<u8>, String> {
    let mut text = String::new();
    for entry in entries()? {
        text.push_str(&render(&entry));
        text.push('\n');
    }
    Ok(text.into_bytes())
}

/// What a delete names, every field but the protocol optional.
#[derive(Debug, PartialEq, Eq)]
struct Filter {
    proto: u8,
    src: Option<IpAddr>,
    dst: Option<IpAddr>,
    sport: Option<u16>,
    dport: Option<u16>,
}

impl Filter {
    /// `None` for a request that names an untargetable protocol, or narrows
    /// nothing, which would be a delete of every connection of a protocol.
    fn of(tuple: &ConntrackTuple) -> Result<Self, String> {
        let refused = || "conntrack delete needs a targetable protocol + tuple".to_owned();
        if !matches!(tuple.proto, 1 | 6 | 17 | 132) {
            return Err(refused());
        }
        let ip = |s: &str| -> Result<Option<IpAddr>, String> {
            if s.is_empty() {
                Ok(None)
            } else {
                s.parse()
                    .map(Some)
                    .map_err(|_| format!("invalid conntrack address '{s}'"))
            }
        };
        let filter = Self {
            proto: tuple.proto,
            src: ip(&tuple.src_ip)?,
            dst: ip(&tuple.dst_ip)?,
            sport: (tuple.src_port != 0).then_some(tuple.src_port),
            dport: (tuple.dst_port != 0).then_some(tuple.dst_port),
        };
        if filter.src.is_none()
            && filter.dst.is_none()
            && filter.sport.is_none()
            && filter.dport.is_none()
        {
            return Err(refused());
        }
        Ok(filter)
    }

    fn matches(&self, entry: &Entry) -> bool {
        let t = &entry.orig;
        let ports = t.ports;
        t.proto == self.proto
            && self.src.is_none_or(|s| t.src == Some(s))
            && self.dst.is_none_or(|d| t.dst == Some(d))
            && self
                .sport
                .is_none_or(|p| ports.is_some_and(|(s, _)| s == p))
            && self
                .dport
                .is_none_or(|p| ports.is_some_and(|(_, d)| d == p))
    }
}

fn delete_message(entry: &Entry) -> Vec<u8> {
    let mut msg = Message::new(
        kind(IPCTNL_MSG_CT_DELETE),
        NLM_F_REQUEST | NLM_F_ACK,
        &nfgenmsg(entry.family),
    );
    msg.nested(CTA_TUPLE_ORIG, &entry.raw_orig);
    if let Some(zone) = &entry.raw_zone {
        msg.attr(CTA_ZONE, zone);
    }
    msg.finish()
}

/// Deletes every connection whose original direction `tuple` names, and
/// answers how many the kernel removed. Nothing matching is not an error.
pub fn delete(tuple: &ConntrackTuple) -> Result<u64, String> {
    let filter = Filter::of(tuple)?;
    let doomed: Vec<Entry> = entries()?
        .into_iter()
        .filter(|e| filter.matches(e))
        .collect();
    if doomed.is_empty() {
        return Ok(0);
    }
    let sock = Socket::open(libc::NETLINK_NETFILTER)
        .map_err(|e| format!("open the conntrack netlink socket: {e}"))?;
    let mut deleted = 0;
    for entry in &doomed {
        match sock.exchange(&delete_message(entry)) {
            // Gone between the dump and the delete: what was asked for holds.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => return Err(format!("delete a conntrack entry: {e}")),
            Ok(_) => deleted += 1,
        }
    }
    Ok(deleted)
}

/// Empties the table, every family.
pub fn flush() -> Result<(), String> {
    let sock = Socket::open(libc::NETLINK_NETFILTER)
        .map_err(|e| format!("open the conntrack netlink socket: {e}"))?;
    let unspec = u8::try_from(libc::AF_UNSPEC).unwrap_or(0);
    let request = Message::new(
        kind(IPCTNL_MSG_CT_DELETE),
        NLM_F_REQUEST | NLM_F_ACK,
        &nfgenmsg(unspec),
    )
    .finish();
    match sock.exchange(&request) {
        Ok(_) => Ok(()),
        Err(e) if tracking_absent(&e) => Ok(()),
        Err(e) => Err(format!("flush the conntrack table: {e}")),
    }
}

fn write_tuple(msg: &mut Message, kind: u16, src: IpAddr, dst: IpAddr, sport: u16, dport: u16) {
    let (src_kind, dst_kind) = if src.is_ipv4() {
        (CTA_IP_V4_SRC, CTA_IP_V4_DST)
    } else {
        (CTA_IP_V6_SRC, CTA_IP_V6_DST)
    };
    let octets = |ip: IpAddr| match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    msg.begin(kind)
        .begin(CTA_TUPLE_IP)
        .attr(src_kind, &octets(src))
        .attr(dst_kind, &octets(dst))
        .end()
        .begin(CTA_TUPLE_PROTO)
        .attr(CTA_PROTO_NUM, &[6])
        .attr(CTA_PROTO_SRC_PORT, &sport.to_be_bytes())
        .attr(CTA_PROTO_DST_PORT, &dport.to_be_bytes())
        .end()
        .end();
}

/// The status of a restored flow: it saw both directions, it is assured, and
/// it carries the confirmation the kernel gives every entry it creates.
const RESTORE_STATUS: u32 = IPS_SEEN_REPLY | IPS_ASSURED | IPS_CONFIRMED;

/// The request writing one established TCP flow.
fn restore_message(restore: &ConntrackRestore) -> Result<Vec<u8>, String> {
    if !restore.is_restorable() {
        return Err("conntrack restore needs a fully named TCP flow".to_owned());
    }
    let parse = |s: &str| -> Result<IpAddr, String> {
        s.parse()
            .map_err(|_| format!("invalid conntrack address '{s}'"))
    };
    let f = &restore.flow;
    let (src, dst) = (parse(&f.src_ip)?, parse(&f.dst_ip)?);
    let (rsrc, rdst, rsport, rdport) = match &restore.reply {
        Some(r) => (parse(&r.src_ip)?, parse(&r.dst_ip)?, r.src_port, r.dst_port),
        None => (dst, src, f.dst_port, f.src_port),
    };
    if [dst, rsrc, rdst]
        .iter()
        .any(|ip| ip.is_ipv4() != src.is_ipv4())
    {
        return Err("conntrack restore mixes address families".to_owned());
    }
    let mut msg = Message::new(
        kind(IPCTNL_MSG_CT_NEW),
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        &nfgenmsg(family_of(src)),
    );
    write_tuple(&mut msg, CTA_TUPLE_ORIG, src, dst, f.src_port, f.dst_port);
    write_tuple(&mut msg, CTA_TUPLE_REPLY, rsrc, rdst, rsport, rdport);
    // The kernel marks a created entry confirmed before it applies the status
    // it was sent, and refuses with EBUSY a status that would clear the bit:
    // a status without it is a request to unconfirm, not a silence about it.
    //
    // A handed-over flow carries no window: neither end's scale factor nor
    // the sequence it reached is known here, so a tracked window would read
    // the peer's scaled window as bytes and call the next segment INVALID,
    // which a firewall in the forward path then drops. Both directions are
    // marked liberal (flags then mask), as conntrackd does for a flow it
    // picks up mid-stream; state, timeout and both tuples are still tracked.
    let liberal = [TCP_FLAG_BE_LIBERAL, TCP_FLAG_BE_LIBERAL];
    msg.attr(CTA_STATUS, &RESTORE_STATUS.to_be_bytes())
        .attr(CTA_TIMEOUT, &CONNTRACK_RESTORE_TIMEOUT_SECS.to_be_bytes())
        .begin(CTA_PROTOINFO)
        .begin(CTA_PROTOINFO_TCP)
        .attr(CTA_PROTOINFO_TCP_STATE, &[TCP_CONNTRACK_ESTABLISHED])
        .attr(CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, &liberal)
        .attr(CTA_PROTOINFO_TCP_FLAGS_REPLY, &liberal)
        .end()
        .end();
    Ok(msg.finish())
}

/// Writes one established TCP flow, answering `true` when the entry is new.
/// An entry the kernel already holds leaves the flow tracked and is not an
/// error: it answers `false`.
pub fn restore(restore: &ConntrackRestore) -> Result<bool, String> {
    let request = restore_message(restore)?;
    let sock = Socket::open(libc::NETLINK_NETFILTER)
        .map_err(|e| format!("open the conntrack netlink socket: {e}"))?;
    match sock.exchange(&request) {
        Ok(_) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(false),
        Err(e) => Err(format!("write the conntrack entry: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(proto: u8, src: &str, dst: &str, sp: u16, dp: u16) -> ConntrackTuple {
        ConntrackTuple {
            proto,
            src_ip: src.to_owned(),
            dst_ip: dst.to_owned(),
            src_port: sp,
            dst_port: dp,
        }
    }

    /// A dump message as the kernel writes one, built with the same writer.
    fn dump_body(proto: u8, status: u32, state: Option<u8>) -> Vec<u8> {
        let mut msg = Message::new(kind(IPCTNL_MSG_CT_NEW), 0, &nfgenmsg(2));
        let (a, b) = ("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
        for (k, s, d, sp, dp) in [
            (CTA_TUPLE_ORIG, a, b, 40000, 8080),
            (CTA_TUPLE_REPLY, b, a, 8080, 40000),
        ] {
            let IpAddr::V4(s) = s else { unreachable!() };
            let IpAddr::V4(d) = d else { unreachable!() };
            msg.begin(k)
                .begin(CTA_TUPLE_IP)
                .attr(CTA_IP_V4_SRC, &s.octets())
                .attr(CTA_IP_V4_DST, &d.octets())
                .end()
                .begin(CTA_TUPLE_PROTO)
                .attr(CTA_PROTO_NUM, &[proto])
                .attr(CTA_PROTO_SRC_PORT, &u16::to_be_bytes(sp))
                .attr(CTA_PROTO_DST_PORT, &u16::to_be_bytes(dp))
                .end()
                .end();
        }
        msg.begin(CTA_COUNTERS_ORIG)
            .attr(CTA_COUNTERS_PACKETS, &3u64.to_be_bytes())
            .attr(CTA_COUNTERS_BYTES, &180u64.to_be_bytes())
            .end();
        msg.attr(CTA_STATUS, &status.to_be_bytes())
            .attr(CTA_TIMEOUT, &431_999u32.to_be_bytes())
            .attr(CTA_MARK, &0u32.to_be_bytes())
            .attr(CTA_USE, &1u32.to_be_bytes());
        if let Some(state) = state {
            msg.begin(CTA_PROTOINFO)
                .begin(CTA_PROTOINFO_TCP)
                .attr(CTA_PROTOINFO_TCP_STATE, &[state])
                .end()
                .end();
        }
        msg.finish()[netlink::NLMSG_HDRLEN..].to_vec()
    }

    #[test]
    fn an_established_tcp_entry_reads_as_the_proc_line() {
        let entry = parse_entry(&dump_body(6, IPS_SEEN_REPLY | IPS_ASSURED, Some(3))).unwrap();
        assert_eq!(
            render(&entry),
            "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.1 dst=10.0.0.2 sport=40000 dport=8080 \
             packets=3 bytes=180 src=10.0.0.2 dst=10.0.0.1 sport=8080 dport=40000 [ASSURED] \
             mark=0 use=1"
        );
    }

    #[test]
    fn an_unanswered_udp_entry_says_so() {
        let entry = parse_entry(&dump_body(17, 0, None)).unwrap();
        let line = render(&entry);
        assert!(
            line.starts_with("ipv4 2 udp 17 431999 src=10.0.0.1"),
            "{line}"
        );
        assert!(line.contains("[UNREPLIED] src=10.0.0.2"), "{line}");
        assert!(!line.contains("ASSURED"), "{line}");
    }

    #[test]
    fn a_delete_hands_back_the_tuple_it_was_given() {
        let entry = parse_entry(&dump_body(6, IPS_SEEN_REPLY, Some(3))).unwrap();
        let msg = delete_message(&entry);
        let attrs = &msg[netlink::NLMSG_HDRLEN + 4..];
        assert_eq!(
            netlink::attribute(attrs, CTA_TUPLE_ORIG),
            Some(&entry.raw_orig[..])
        );
    }

    #[test]
    fn a_filter_matches_on_the_original_direction() {
        let entry = parse_entry(&dump_body(6, IPS_SEEN_REPLY, Some(3))).unwrap();
        assert!(
            Filter::of(&tuple(6, "", "", 0, 8080))
                .unwrap()
                .matches(&entry)
        );
        assert!(
            Filter::of(&tuple(6, "10.0.0.1", "10.0.0.2", 40000, 8080))
                .unwrap()
                .matches(&entry)
        );
        assert!(
            !Filter::of(&tuple(6, "", "", 0, 40000))
                .unwrap()
                .matches(&entry)
        );
        assert!(
            !Filter::of(&tuple(17, "", "", 0, 8080))
                .unwrap()
                .matches(&entry)
        );
    }

    #[test]
    fn an_untargetable_delete_is_refused() {
        assert!(Filter::of(&tuple(200, "1.2.3.4", "", 0, 0)).is_err());
        assert!(Filter::of(&tuple(6, "", "", 0, 0)).is_err());
        assert!(Filter::of(&tuple(6, "not-an-address", "", 0, 0)).is_err());
    }

    #[test]
    fn a_restore_writes_both_directions_established() {
        let restore = ConntrackRestore {
            flow: tuple(6, "10.0.0.1", "10.0.0.2", 40000, 8080),
            reply: None,
        };
        let msg = restore_message(&restore).unwrap();
        let attrs = &msg[netlink::NLMSG_HDRLEN + 4..];
        let reply = parse_tuple(netlink::attribute(attrs, CTA_TUPLE_REPLY).unwrap()).unwrap();
        assert_eq!(reply.src, Some("10.0.0.2".parse().unwrap()));
        assert_eq!(reply.ports, Some((8080, 40000)));
        assert_eq!(
            netlink::attribute(attrs, CTA_TIMEOUT).and_then(netlink::be32),
            Some(CONNTRACK_RESTORE_TIMEOUT_SECS)
        );
        let state = netlink::attribute(attrs, CTA_PROTOINFO)
            .and_then(|p| netlink::attribute(p, CTA_PROTOINFO_TCP))
            .and_then(|t| netlink::attribute(t, CTA_PROTOINFO_TCP_STATE));
        assert_eq!(state, Some(&[TCP_CONNTRACK_ESTABLISHED][..]));
    }

    #[test]
    fn a_restored_flow_is_not_held_to_a_window_it_never_saw() {
        let restore = ConntrackRestore {
            flow: tuple(6, "10.0.0.1", "10.0.0.2", 40000, 8080),
            reply: None,
        };
        let msg = restore_message(&restore).unwrap();
        let attrs = &msg[netlink::NLMSG_HDRLEN + 4..];
        let tcp = netlink::attribute(attrs, CTA_PROTOINFO)
            .and_then(|p| netlink::attribute(p, CTA_PROTOINFO_TCP))
            .unwrap();
        for dir in [
            CTA_PROTOINFO_TCP_FLAGS_ORIGINAL,
            CTA_PROTOINFO_TCP_FLAGS_REPLY,
        ] {
            assert_eq!(
                netlink::attribute(tcp, dir),
                Some(&[TCP_FLAG_BE_LIBERAL, TCP_FLAG_BE_LIBERAL][..]),
                "direction {dir}"
            );
        }
    }

    #[test]
    fn a_restore_keeps_the_confirmation_the_kernel_sets_on_create() {
        let restore = ConntrackRestore {
            flow: tuple(6, "10.0.0.1", "10.0.0.2", 40000, 8080),
            reply: None,
        };
        let msg = restore_message(&restore).unwrap();
        let attrs = &msg[netlink::NLMSG_HDRLEN + 4..];
        let status = netlink::attribute(attrs, CTA_STATUS)
            .and_then(netlink::be32)
            .unwrap();
        assert_eq!(status & IPS_CONFIRMED, IPS_CONFIRMED, "status {status:#x}");
        assert_eq!(
            status & (IPS_SEEN_REPLY | IPS_ASSURED),
            IPS_SEEN_REPLY | IPS_ASSURED
        );
    }

    #[test]
    fn a_restore_refuses_what_the_protocol_refuses() {
        let udp = ConntrackRestore {
            flow: tuple(17, "10.0.0.1", "10.0.0.2", 1, 2),
            reply: None,
        };
        assert!(restore_message(&udp).is_err());
        let mixed = ConntrackRestore {
            flow: tuple(6, "10.0.0.1", "10.0.0.2", 1, 2),
            reply: Some(tuple(6, "fd00::1", "fd00::2", 2, 1)),
        };
        assert!(restore_message(&mixed).is_err());
    }
}
