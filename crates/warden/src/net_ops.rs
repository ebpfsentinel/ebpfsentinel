//! Privileged host-network operations the warden performs for the rootless agent.
//!
//! Conntrack teardown (`conntrack -D`/`-F`), multi-WAN route programming
//! (`ip route`), gratuitous ARP on VIP takeover, and opening an `AF_PACKET`
//! capture socket all need `CAP_NET_ADMIN`/`CAP_NET_RAW` over the host network
//! namespace — capabilities the BPF token can never grant. They therefore live
//! here in the warden, which holds them, rather than in the agent.
//!
//! The command-building cores (`conntrack_delete_args`, `route_args`,
//! `build_garp_frame`) are pure and unit-tested; the exec / raw-socket wrappers
//! around them are exercised on their error paths (a bogus interface fails
//! deterministically) and on the happy path in the VM lane.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

use ebpfsentinel_warden_proto::{ConntrackTuple, RouteSpec};

// ── interface name / ifindex / MAC ────────────────────────────────────────

/// `SIOCGIFINDEX` — get interface index (stable Linux ioctl).
const SIOCGIFINDEX: libc::Ioctl = 0x8933;
/// `SIOCGIFHWADDR` — get hardware (MAC) address (stable Linux ioctl).
const SIOCGIFHWADDR: libc::Ioctl = 0x8927;

const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ALL: u16 = 0x0003;
const ARP_HW_ETHERNET: u16 = 1;
const ARP_OP_REPLY: u16 = 2;
const BROADCAST: [u8; 6] = [0xff; 6];

/// Flat 24-byte-tail `struct ifreq` — the stable kernel ABI every ifreq ioctl uses.
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
        *dst = src.cast_signed();
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

// ── conntrack teardown ────────────────────────────────────────────────────

/// Map an IP protocol number to the `conntrack -p` name, if it is one the tool
/// can target precisely.
fn conntrack_proto(proto: u8) -> Option<&'static str> {
    match proto {
        6 => Some("tcp"),
        17 => Some("udp"),
        1 => Some("icmp"),
        132 => Some("sctp"),
        _ => None,
    }
}

/// Build the `conntrack -D` argument vector that targets exactly the flow in
/// `tuple`. Returns `None` for an untargetable request (unknown protocol, or no
/// address/port narrowing at all) so the warden refuses rather than risk a
/// table-wide delete.
#[must_use]
pub fn conntrack_delete_args(tuple: &ConntrackTuple) -> Option<Vec<String>> {
    let proto = conntrack_proto(tuple.proto)?;
    let mut args = vec!["-D".to_owned(), "-p".to_owned(), proto.to_owned()];
    let mut narrowed = false;
    if !tuple.src_ip.is_empty() {
        args.push("-s".to_owned());
        args.push(tuple.src_ip.clone());
        narrowed = true;
    }
    if !tuple.dst_ip.is_empty() {
        args.push("-d".to_owned());
        args.push(tuple.dst_ip.clone());
        narrowed = true;
    }
    if tuple.src_port != 0 {
        args.push("--sport".to_owned());
        args.push(tuple.src_port.to_string());
        narrowed = true;
    }
    if tuple.dst_port != 0 {
        args.push("--dport".to_owned());
        args.push(tuple.dst_port.to_string());
        narrowed = true;
    }
    narrowed.then_some(args)
}

/// Delete the flow described by `tuple` with `conntrack -D`.
pub fn conntrack_delete(tuple: &ConntrackTuple) -> Result<(), String> {
    let args = conntrack_delete_args(tuple)
        .ok_or_else(|| "conntrack delete needs a targetable protocol + tuple".to_owned())?;
    // `conntrack -D` exits non-zero when nothing matched; that is not an error.
    run_allow_nonzero("conntrack", &args)
}

/// Flush the whole conntrack table with `conntrack -F`.
pub fn conntrack_flush() -> Result<(), String> {
    run("conntrack", &["-F".to_owned()])
}

// ── multi-WAN routes ──────────────────────────────────────────────────────

/// Build the `ip route` argument vector. `add` uses `replace` (idempotent);
/// otherwise `del`.
#[must_use]
pub fn route_args(add: bool, route: &RouteSpec) -> Vec<String> {
    let verb = if add { "replace" } else { "del" };
    vec![
        "route".to_owned(),
        verb.to_owned(),
        route.dst_cidr.clone(),
        "via".to_owned(),
        route.gateway.clone(),
        "dev".to_owned(),
        route.iface.clone(),
        "table".to_owned(),
        route.table.to_string(),
    ]
}

/// Accept a route destination `ip` understands: the literal `default`, a bare
/// host address (v4/v6), or an `addr/prefix` CIDR with a prefix in range for the
/// address family. Defence in depth: the exec path passes argv (no shell), but a
/// parsed destination keeps a compromised agent from steering `ip route` with a
/// surprising token.
fn valid_route_dst(dst: &str) -> bool {
    use std::net::IpAddr;
    if dst == "default" {
        return true;
    }
    let (addr, prefix) = match dst.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (dst, None),
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    match prefix {
        None => true,
        Some(p) => {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            p.parse::<u8>().is_ok_and(|n| n <= max)
        }
    }
}

/// Add (`replace`) or delete a route via `ip route`.
pub fn route(add: bool, route_spec: &RouteSpec) -> Result<(), String> {
    name_to_cbuf(&route_spec.iface)?; // reject a malformed interface name early
    if !valid_route_dst(&route_spec.dst_cidr) {
        return Err(format!(
            "invalid route destination '{}'",
            route_spec.dst_cidr
        ));
    }
    route_spec
        .gateway
        .parse::<std::net::IpAddr>()
        .map_err(|_| format!("invalid route gateway '{}'", route_spec.gateway))?;
    run("ip", &route_args(add, route_spec))
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

// ── exec helpers ──────────────────────────────────────────────────────────

/// Run `cmd args`, requiring success.
fn run(cmd: &str, args: &[String]) -> Result<(), String> {
    let status = Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| {
            format!("failed to run `{cmd}`: {e} (is it installed in the warden image?)")
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`{cmd}` exited with {status}"))
    }
}

/// Run `cmd args`, treating a non-zero exit as success (used for `conntrack -D`,
/// which exits non-zero when no flow matched — not an error here).
fn run_allow_nonzero(cmd: &str, args: &[String]) -> Result<(), String> {
    Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| {
            format!("failed to run `{cmd}`: {e} (is it installed in the warden image?)")
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_garp_frame, conntrack_delete_args, name_to_cbuf, route_args, valid_route_dst,
    };
    use ebpfsentinel_warden_proto::{ConntrackTuple, RouteSpec};

    fn tuple(proto: u8, src: &str, dst: &str, sp: u16, dp: u16) -> ConntrackTuple {
        ConntrackTuple {
            proto,
            src_ip: src.to_owned(),
            dst_ip: dst.to_owned(),
            src_port: sp,
            dst_port: dp,
        }
    }

    #[test]
    fn conntrack_args_target_the_tuple() {
        let args = conntrack_delete_args(&tuple(6, "", "", 0, 443)).unwrap();
        assert_eq!(args, ["-D", "-p", "tcp", "--dport", "443"]);

        let args = conntrack_delete_args(&tuple(17, "10.0.0.1", "8.8.8.8", 5353, 53)).unwrap();
        assert_eq!(
            args,
            [
                "-D", "-p", "udp", "-s", "10.0.0.1", "-d", "8.8.8.8", "--sport", "5353", "--dport",
                "53"
            ]
        );
    }

    #[test]
    fn conntrack_refuses_untargetable() {
        // Unknown protocol.
        assert!(conntrack_delete_args(&tuple(200, "1.2.3.4", "", 0, 0)).is_none());
        // Known protocol but no narrowing at all → would be a table-wide delete.
        assert!(conntrack_delete_args(&tuple(6, "", "", 0, 0)).is_none());
    }

    #[test]
    fn route_args_build_ip_command() {
        let spec = RouteSpec {
            dst_cidr: "0.0.0.0/0".to_owned(),
            gateway: "10.0.0.254".to_owned(),
            iface: "enp0s2".to_owned(),
            table: 100,
        };
        assert_eq!(
            route_args(true, &spec),
            [
                "route",
                "replace",
                "0.0.0.0/0",
                "via",
                "10.0.0.254",
                "dev",
                "enp0s2",
                "table",
                "100"
            ]
        );
        assert_eq!(route_args(false, &spec)[1], "del");
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
