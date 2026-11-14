//! Privileged host-network operations the warden performs for the rootless agent.
//!
//! Conntrack teardown and restore, multi-WAN route programming, gratuitous ARP
//! on VIP takeover, and opening an `AF_PACKET` capture socket all need
//! `CAP_NET_ADMIN`/`CAP_NET_RAW` over the host network namespace - capabilities
//! the BPF token can never grant. They therefore live here in the warden, which
//! holds them, rather than in the agent.
//!
//! Conntrack and routes are spoken to over netlink, since the warden image
//! carries no `conntrack` and no `ip`. The message builders and
//! `build_garp_frame` are pure and unit-tested; the socket wrappers around them
//! are exercised on their error paths (a bogus interface fails
//! deterministically) and on the happy path in the VM lane.

use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use ebpfsentinel_warden_proto::{ConntrackRestore, ConntrackTuple, RouteSpec};

use crate::ctnetlink;
use crate::netlink::{self, Message, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST};

// ── interface name / ifindex / MAC ────────────────────────────────────────

/// `SIOCGIFINDEX` - get interface index (stable Linux ioctl).
const SIOCGIFINDEX: libc::Ioctl = 0x8933;
/// `SIOCGIFHWADDR` - get hardware (MAC) address (stable Linux ioctl).
const SIOCGIFHWADDR: libc::Ioctl = 0x8927;

const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ALL: u16 = 0x0003;
const ARP_HW_ETHERNET: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
const BROADCAST: [u8; 6] = [0xff; 6];

/// Flat 24-byte-tail `struct ifreq` - the stable kernel ABI every ifreq ioctl uses.
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_ifru: [u8; 24],
}

/// Validate and pack an interface name into a NUL-padded `ifr_name`. Rejects empty,
/// over-long, and non-`[A-Za-z0-9_.:-]` names (defence in depth even though the
/// exec paths pass argv, not a shell line).
fn name_to_cbuf(iface: &str) -> Result<[libc::c_char; libc::IFNAMSIZ], String> {
    let bytes = iface.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
        return Err(format!(
            "invalid interface name '{iface}' (1..{} bytes)",
            libc::IFNAMSIZ - 1
        ));
    }
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':')
    {
        return Err(format!(
            "interface name '{iface}' has disallowed characters"
        ));
    }
    let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
    for (dst, &src) in buf.iter_mut().zip(bytes) {
        *dst = libc::c_char::from_ne_bytes([src]);
    }
    Ok(buf)
}

/// An `AF_INET`/`SOCK_DGRAM` socket for `SIOCGIF*` ioctls.
fn ioctl_socket() -> Result<OwnedFd, String> {
    // SAFETY: socket() with valid constants; the fd is wrapped in OwnedFd.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(format!(
            "socket(AF_INET) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` is a valid, freshly-created descriptor we own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Resolve the ifindex of `iface` via `ioctl(SIOCGIFINDEX)`.
fn resolve_ifindex(iface: &str) -> Result<u32, String> {
    let sock = ioctl_socket()?;
    let mut req = IfReq {
        ifr_name: name_to_cbuf(iface)?,
        ifr_ifru: [0u8; 24],
    };
    // SAFETY: `sock` is a valid AF_INET datagram fd; the kernel fills ifr_ifindex
    // (a c_int at offset 0 of the union).
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFINDEX, std::ptr::addr_of_mut!(req)) };
    if rc < 0 {
        return Err(format!(
            "ioctl(SIOCGIFINDEX, {iface}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let idx = i32::from_ne_bytes([
        req.ifr_ifru[0],
        req.ifr_ifru[1],
        req.ifr_ifru[2],
        req.ifr_ifru[3],
    ]);
    u32::try_from(idx).map_err(|_| format!("ifindex {idx} for {iface} is negative"))
}

/// Resolve the 6-byte MAC of `iface` via `ioctl(SIOCGIFHWADDR)`.
fn resolve_mac(iface: &str) -> Result<[u8; 6], String> {
    let sock = ioctl_socket()?;
    let mut req = IfReq {
        ifr_name: name_to_cbuf(iface)?,
        ifr_ifru: [0u8; 24],
    };
    // SAFETY: `sock` is a valid AF_INET datagram fd; the kernel writes a
    // `struct sockaddr` whose sa_data[0..6] (ifr_ifru[2..8]) is the MAC.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFHWADDR, std::ptr::addr_of_mut!(req)) };
    if rc < 0 {
        return Err(format!(
            "ioctl(SIOCGIFHWADDR, {iface}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&req.ifr_ifru[2..8]);
    if mac == [0u8; 6] {
        return Err(format!("interface {iface} has an all-zero MAC"));
    }
    Ok(mac)
}

// ── conntrack ─────────────────────────────────────────────────────────────

/// Delete the flows `tuple` names, over ctnetlink.
pub fn conntrack_delete(tuple: &ConntrackTuple) -> Result<(), String> {
    ctnetlink::delete(tuple).map(|_| ())
}

/// Write one established TCP flow, over ctnetlink.
pub fn conntrack_restore(restore: &ConntrackRestore) -> Result<(), String> {
    ctnetlink::restore(restore).map(|_| ())
}

/// Flush the whole conntrack table, over ctnetlink.
pub fn conntrack_flush() -> Result<(), String> {
    ctnetlink::flush()
}

// ── multi-WAN routes ──────────────────────────────────────────────────────

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_TABLE: u16 = 15;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_NOWHERE: u8 = 255;
const RTN_UNICAST: u8 = 1;

/// Accept a route destination: the literal `default`, a bare host address
/// (v4/v6), or an `addr/prefix` CIDR with a prefix in range for the address
/// family.
fn valid_route_dst(dst: &str) -> bool {
    parse_route_dst(dst).is_some()
}

/// The destination as (address, prefix length); `None` for `default`'s
/// address, which names no address at all.
fn parse_route_dst(dst: &str) -> Option<(Option<IpAddr>, u8)> {
    if dst == "default" {
        return Some((None, 0));
    }
    let (addr, prefix) = match dst.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (dst, None),
    };
    let ip = addr.parse::<IpAddr>().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match prefix {
        None => max,
        Some(p) => p.parse::<u8>().ok().filter(|n| *n <= max)?,
    };
    Some((Some(ip), len))
}

fn octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// The rtnetlink request adding (replacing) or deleting `spec` through the
/// interface numbered `ifindex`.
fn route_message(add: bool, spec: &RouteSpec, ifindex: u32) -> Result<Vec<u8>, String> {
    let (dst, prefix) = parse_route_dst(&spec.dst_cidr)
        .ok_or_else(|| format!("invalid route destination '{}'", spec.dst_cidr))?;
    let gateway = spec
        .gateway
        .parse::<IpAddr>()
        .map_err(|_| format!("invalid route gateway '{}'", spec.gateway))?;
    if dst.is_some_and(|d| d.is_ipv4() != gateway.is_ipv4()) {
        return Err(format!(
            "route destination '{}' and gateway '{}' are of different families",
            spec.dst_cidr, spec.gateway
        ));
    }
    let family = if gateway.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let family = u8::try_from(family).unwrap_or(2);
    // A table past 255 is named only by its attribute.
    let header_table = u8::try_from(spec.table).unwrap_or(0);
    let (kind, flags, protocol, scope, route_type) = if add {
        (
            RTM_NEWROUTE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            RTPROT_BOOT,
            RT_SCOPE_UNIVERSE,
            RTN_UNICAST,
        )
    } else {
        (
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            0,
            RT_SCOPE_NOWHERE,
            0,
        )
    };
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
    // type, flags.
    let mut rtmsg = [0u8; 12];
    rtmsg[..8].copy_from_slice(&[
        family,
        prefix,
        0,
        0,
        header_table,
        protocol,
        scope,
        route_type,
    ]);
    let mut msg = Message::new(kind, flags, &rtmsg);
    if let Some(dst) = dst {
        msg.attr(RTA_DST, &octets(dst));
    }
    msg.attr(RTA_GATEWAY, &octets(gateway))
        .attr(RTA_OIF, &ifindex.to_ne_bytes())
        .attr(RTA_TABLE, &spec.table.to_ne_bytes());
    Ok(msg.finish())
}

/// Add (replacing) or delete a route, over rtnetlink.
pub fn route(add: bool, route_spec: &RouteSpec) -> Result<(), String> {
    name_to_cbuf(&route_spec.iface)?; // reject a malformed interface name early
    if !valid_route_dst(&route_spec.dst_cidr) {
        return Err(format!(
            "invalid route destination '{}'",
            route_spec.dst_cidr
        ));
    }
    let ifindex = resolve_ifindex(&route_spec.iface)?;
    let request = route_message(add, route_spec, ifindex)?;
    let sock = netlink::Socket::open(libc::NETLINK_ROUTE)
        .map_err(|e| format!("open the route netlink socket: {e}"))?;
    match sock.exchange(&request) {
        Ok(_) => Ok(()),
        // Already gone: what a delete asks for holds.
        Err(e) if !add && e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        Err(e) => Err(format!(
            "{} route {} via {} dev {} table {}: {e}",
            if add { "replace" } else { "delete" },
            route_spec.dst_cidr,
            route_spec.gateway,
            route_spec.iface,
            route_spec.table
        )),
    }
}

// ── gratuitous ARP ────────────────────────────────────────────────────────

/// A complete 42-byte gratuitous-ARP frame (Ethernet + ARP, no padding).
fn build_garp_frame(src_mac: [u8; 6], vip: [u8; 4]) -> [u8; 42] {
    let mut f = [0u8; 42];
    f[0..6].copy_from_slice(&BROADCAST);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    f[14..16].copy_from_slice(&ARP_HW_ETHERNET.to_be_bytes());
    f[16..18].copy_from_slice(&ETH_P_IP.to_be_bytes());
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    f[22..28].copy_from_slice(&src_mac);
    f[28..32].copy_from_slice(&vip);
    f[32..38].copy_from_slice(&BROADCAST);
    f[38..42].copy_from_slice(&vip);
    f
}

/// Broadcast a gratuitous ARP for `ip` on `iface`. IPv6 is a no-op (unsolicited
/// neighbour advertisement is out of scope), matching the agent's behaviour.
pub fn arp_announce(iface: &str, ip: &str) -> Result<(), String> {
    let addr: std::net::IpAddr = ip
        .parse()
        .map_err(|_| format!("invalid ARP announce address '{ip}'"))?;
    let std::net::IpAddr::V4(v4) = addr else {
        return Ok(());
    };
    let ifindex = resolve_ifindex(iface)?;
    let mac = resolve_mac(iface)?;
    let frame = build_garp_frame(mac, v4.octets());

    // SAFETY: AF_PACKET/SOCK_RAW with the ARP ethertype; fd wrapped in OwnedFd.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::c_int::from(ETH_P_ARP.to_be()),
        )
    };
    if fd < 0 {
        return Err(format!(
            "socket(AF_PACKET) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` is a valid freshly-created descriptor we own.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };

    // SAFETY: zeroed sockaddr_ll is valid; fields set below to a complete address.
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = ETH_P_ARP.to_be();
    sa.sll_ifindex = ifindex.cast_signed();
    sa.sll_halen = 6;
    sa.sll_addr[..6].copy_from_slice(&BROADCAST);

    // SAFETY: `frame` is readable; `sa` is a fully-initialised sockaddr_ll of the
    // declared length; `sock` is a valid AF_PACKET raw socket.
    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
            std::ptr::addr_of!(sa).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(format!(
            "sendto(AF_PACKET) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// ── pcap capture socket ───────────────────────────────────────────────────

/// Whether this process can create an `AF_PACKET` socket at all.
///
/// The warden normally runs as host root and can, which is what makes the
/// on-demand [`open_pcap_fd`] fallback worth trying when the pre-opened pool is
/// spent. A warden inside a user namespace cannot: `CAP_NET_RAW` is checked
/// against the initial user namespace, so every `socket()` there fails with
/// `EPERM` and the pool is the only capture there will ever be. Probed once at
/// startup with a protocol-`0` socket, which is silent and immediately closed,
/// so an exhausted pool can say so instead of failing inside an open that
/// cannot work.
#[must_use]
pub fn af_packet_available() -> bool {
    // SAFETY: protocol 0 keeps the socket silent; the fd is closed right away.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if fd < 0 {
        return false;
    }
    // SAFETY: `fd` is a valid descriptor this call owns.
    unsafe { libc::close(fd) };
    true
}

/// Open an `AF_PACKET`/`SOCK_RAW` socket bound to `iface` (`ETH_P_ALL`) and return
/// it for fd-passing to the agent. The agent installs its cBPF filter on the
/// received fd (as it already does for the pre-opened pool), so capture stays in
/// the agent's hands once the privileged `socket()`+`bind()` is done here.
pub fn open_pcap_fd(iface: &str) -> Result<OwnedFd, String> {
    let ifindex = resolve_ifindex(iface)?;
    // SAFETY: AF_PACKET/SOCK_RAW with ETH_P_ALL; fd wrapped in OwnedFd.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::c_int::from(ETH_P_ALL.to_be()),
        )
    };
    if fd < 0 {
        return Err(format!(
            "socket(AF_PACKET) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` is a valid freshly-created descriptor we own.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };

    // SAFETY: zeroed sockaddr_ll is valid; family/protocol/ifindex set below.
    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = ETH_P_ALL.to_be();
    sa.sll_ifindex = ifindex.cast_signed();

    // SAFETY: `sock` is a valid AF_PACKET fd; `sa` is a fully-initialised
    // sockaddr_ll of the declared length.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            std::ptr::addr_of!(sa).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(format!(
            "bind(AF_PACKET, {iface}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::{
        RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_TABLE, build_garp_frame, name_to_cbuf, netlink,
        route_message, valid_route_dst,
    };
    use ebpfsentinel_warden_proto::RouteSpec;

    #[test]
    fn a_route_names_its_table_gateway_and_interface() {
        let spec = RouteSpec {
            dst_cidr: "203.0.113.0/24".to_owned(),
            gateway: "10.0.0.254".to_owned(),
            iface: "enp0s2".to_owned(),
            table: 300,
        };
        let msg = route_message(true, &spec, 7).unwrap();
        let rtmsg = &msg[netlink::NLMSG_HDRLEN..netlink::NLMSG_HDRLEN + 12];
        assert_eq!(rtmsg[0], 2); // AF_INET
        assert_eq!(rtmsg[1], 24); // prefix length
        assert_eq!(rtmsg[4], 0); // table past 255 named by attribute only
        let attrs = &msg[netlink::NLMSG_HDRLEN + 12..];
        assert_eq!(
            netlink::attribute(attrs, RTA_DST),
            Some(&[203, 0, 113, 0][..])
        );
        assert_eq!(
            netlink::attribute(attrs, RTA_GATEWAY),
            Some(&[10, 0, 0, 254][..])
        );
        assert_eq!(
            netlink::attribute(attrs, RTA_OIF),
            Some(&7u32.to_ne_bytes()[..])
        );
        assert_eq!(
            netlink::attribute(attrs, RTA_TABLE),
            Some(&300u32.to_ne_bytes()[..])
        );
    }

    #[test]
    fn a_default_route_names_no_destination() {
        let spec = RouteSpec {
            dst_cidr: "default".to_owned(),
            gateway: "10.0.0.254".to_owned(),
            iface: "enp0s2".to_owned(),
            table: 100,
        };
        let msg = route_message(false, &spec, 7).unwrap();
        assert_eq!(msg[netlink::NLMSG_HDRLEN + 1], 0);
        assert_eq!(msg[netlink::NLMSG_HDRLEN + 4], 100);
        let attrs = &msg[netlink::NLMSG_HDRLEN + 12..];
        assert!(netlink::attribute(attrs, RTA_DST).is_none());
    }

    #[test]
    fn a_route_mixing_families_is_refused() {
        let spec = RouteSpec {
            dst_cidr: "2001:db8::/32".to_owned(),
            gateway: "10.0.0.254".to_owned(),
            iface: "enp0s2".to_owned(),
            table: 100,
        };
        assert!(route_message(true, &spec, 7).is_err());
    }

    #[test]
    fn garp_frame_is_well_formed() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let f = build_garp_frame(mac, [192, 0, 2, 10]);
        assert_eq!(&f[0..6], &[0xff; 6]); // dst broadcast
        assert_eq!(&f[6..12], &mac); // src MAC
        assert_eq!(&f[12..14], &0x0806u16.to_be_bytes()); // ARP ethertype
        assert_eq!(&f[20..22], &2u16.to_be_bytes()); // oper = REPLY
        assert_eq!(&f[28..32], &[192, 0, 2, 10]); // spa = VIP
        assert_eq!(&f[38..42], &[192, 0, 2, 10]); // tpa = VIP
    }

    #[test]
    fn route_dst_validation() {
        assert!(valid_route_dst("default"));
        assert!(valid_route_dst("0.0.0.0/0"));
        assert!(valid_route_dst("10.0.0.1"));
        assert!(valid_route_dst("203.0.113.0/24"));
        assert!(valid_route_dst("2001:db8::/32"));
        assert!(!valid_route_dst("")); // empty
        assert!(!valid_route_dst("10.0.0.0/33")); // v4 prefix out of range
        assert!(!valid_route_dst("2001:db8::/129")); // v6 prefix out of range
        assert!(!valid_route_dst("10.0.0.1 onlink")); // smuggled token
        assert!(!valid_route_dst("notanip"));
    }

    #[test]
    fn iface_name_validation() {
        assert!(name_to_cbuf("").is_err());
        assert!(name_to_cbuf("eth0;rm -rf").is_err());
        assert!(name_to_cbuf("enp0s2").is_ok());
    }
}
