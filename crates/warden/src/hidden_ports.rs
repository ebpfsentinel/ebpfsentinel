//! The two readings a hidden port is found between, taken in every network
//! namespace `/proc` shows.
//!
//! Inside one namespace, on a thread that enters it and ends with the
//! reading:
//!
//! 1. The TCP and UDP sockets are listed twice over, from
//!    `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` and from a `sock_diag` dump
//!    asking for every state. A kernel built without `udp_diag` answers the
//!    UDP dump with an error, and the proc listing then stands alone.
//! 2. Every asked port is bound on `0.0.0.0` and on `::` with
//!    `IPV6_V6ONLY`, over TCP and over UDP, with no reuse option, and the
//!    socket is closed at once. `EADDRINUSE` is a refusal; any other failure
//!    means the port could not be asked and is counted as unprobed.
//! 3. Both listings are taken again and the refused binds are made a second
//!    time.
//!
//! A probe holds a port for the length of one `bind`, so a service starting
//! in that instant can be refused it once; the agent's interval and the
//! port set bound how often that window opens. Nothing is left open and
//! nothing but a bind is done in a namespace.

use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ebpfsentinel_warden_proto::{BindProbe, ListedPort, NamespacePortReading};

use crate::packet_sockets::{netns_of, processes};

/// `NETLINK_SOCK_DIAG` and `SOCK_DIAG_BY_FAMILY`.
const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `NLMSG_ERROR` and `NLMSG_DONE`.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// `struct nlmsghdr` and `struct inet_diag_msg` sizes.
const NLMSG_HDR_LEN: usize = 16;
const INET_DIAG_MSG_LEN: usize = 72;

/// Parse `/proc/net/{tcp,tcp6,udp,udp6}`: a header line, then one row per
/// socket whose second field is `ADDR:PORT` and fourth the state, both in
/// hex. A row that does not read is skipped rather than guessed.
#[must_use]
pub fn parse_proc_net_inet(text: &str, udp: bool) -> Vec<ListedPort> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local = fields.get(1)?;
            let (_, port) = local.rsplit_once(':')?;
            Some(ListedPort {
                udp,
                port: u16::from_str_radix(port, 16).ok()?,
                state: u8::from_str_radix(fields.get(3)?, 16).ok()?,
                sock_diag: false,
            })
        })
        .collect()
}

/// Read the messages of one `recv` of an `inet_diag` dump into `into`.
/// Returns `true` once the dump is complete.
///
/// # Errors
///
/// A message whose length runs past the buffer, and an error the kernel sent
/// in place of the dump.
pub fn read_inet_diag(mut buf: &[u8], udp: bool, into: &mut Vec<ListedPort>) -> io::Result<bool> {
    while buf.len() >= NLMSG_HDR_LEN {
        let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let kind = u16::from_ne_bytes([buf[4], buf[5]]);
        if len < NLMSG_HDR_LEN || len > buf.len() {
            return Err(io::Error::other("truncated sock_diag message"));
        }
        let payload = &buf[NLMSG_HDR_LEN..len];
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let errno = payload
                    .get(..4)
                    .map_or(0, |b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(-errno));
                }
            }
            SOCK_DIAG_BY_FAMILY if payload.len() >= INET_DIAG_MSG_LEN => {
                into.push(ListedPort {
                    udp,
                    port: u16::from_be_bytes([payload[4], payload[5]]),
                    state: payload[1],
                    sock_diag: true,
                });
            }
            _ => {}
        }
        let step = (len + 3) & !3;
        buf = buf.get(step..).unwrap_or_default();
    }
    Ok(false)
}

/// `struct nlmsghdr` followed by `struct inet_diag_req_v2`.
#[repr(C)]
struct InetDiagRequest {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
    sdiag_family: u8,
    sdiag_protocol: u8,
    idiag_ext: u8,
    pad: u8,
    idiag_states: u32,
    id: [u8; 48],
}

/// Dump every socket of one family and transport, in every state, from the
/// calling thread's network namespace.
fn dump_inet(family: libc::c_int, udp: bool, into: &mut Vec<ListedPort>) -> io::Result<()> {
    // SAFETY: plain socket(2) call; the result is checked before use.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a descriptor this function just created and owns alone.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let request = InetDiagRequest {
        nlmsg_len: std::mem::size_of::<InetDiagRequest>() as u32,
        nlmsg_type: SOCK_DIAG_BY_FAMILY,
        nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
        sdiag_family: family as u8,
        sdiag_protocol: if udp {
            libc::IPPROTO_UDP as u8
        } else {
            libc::IPPROTO_TCP as u8
        },
        idiag_ext: 0,
        pad: 0,
        idiag_states: u32::MAX,
        id: [0; 48],
    };
    // SAFETY: the pointer and length describe `request`, which outlives the call.
    let sent = unsafe {
        libc::send(
            sock.as_raw_fd(),
            (&raw const request).cast(),
            std::mem::size_of::<InetDiagRequest>(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        // SAFETY: the pointer and length describe `buf`, which outlives the call.
        let got = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        if got == 0 || read_inet_diag(&buf[..got as usize], udp, into)? {
            return Ok(());
        }
    }
}

/// Both listings of the calling thread's namespace, the proc one read
/// through `pid_dir`, folded so a port carrying a thousand connections in
/// one state is one entry.
fn listing(pid_dir: &Path) -> Vec<ListedPort> {
    let mut all = Vec::new();
    for (file, udp) in [
        ("tcp", false),
        ("tcp6", false),
        ("udp", true),
        ("udp6", true),
    ] {
        if let Ok(text) = std::fs::read_to_string(pid_dir.join("net").join(file)) {
            all.extend(parse_proc_net_inet(&text, udp));
        }
    }
    for family in [libc::AF_INET, libc::AF_INET6] {
        for udp in [false, true] {
            // A dump the kernel refuses (no `udp_diag`) leaves the proc
            // listing to stand alone; a partial dump still counts.
            let _ = dump_inet(family, udp, &mut all);
        }
    }
    let mut seen = HashSet::new();
    all.retain(|entry| seen.insert(*entry));
    all
}

/// What one bind found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Free,
    InUse,
    Unprobed,
}

/// Bind `probe` with no reuse option and close it at once.
fn bind_once(probe: BindProbe) -> Outcome {
    let family = if probe.ipv6 {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };
    let kind = if probe.udp {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
    // SAFETY: plain socket(2) call; the result is checked before use.
    let raw = unsafe { libc::socket(family, kind | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Outcome::Unprobed;
    }
    // SAFETY: `raw` is a descriptor this function just created and owns alone;
    // dropping it closes the probe.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let rc = if probe.ipv6 {
        let on: libc::c_int = 1;
        // SAFETY: the pointer and length describe `on`, which outlives the call.
        let set = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                (&raw const on).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if set != 0 {
            return Outcome::Unprobed;
        }
        // SAFETY: an all-zero `sockaddr_in6` is the unspecified address.
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        addr.sin6_port = probe.port.to_be();
        // SAFETY: the pointer and length describe `addr`, which outlives the call.
        unsafe {
            libc::bind(
                sock.as_raw_fd(),
                (&raw const addr).cast(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    } else {
        // SAFETY: an all-zero `sockaddr_in` is `0.0.0.0`.
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = probe.port.to_be();
        // SAFETY: the pointer and length describe `addr`, which outlives the call.
        unsafe {
            libc::bind(
                sock.as_raw_fd(),
                (&raw const addr).cast(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
    };
    if rc == 0 {
        Outcome::Free
    } else if io::Error::last_os_error().raw_os_error() == Some(libc::EADDRINUSE) {
        Outcome::InUse
    } else {
        Outcome::Unprobed
    }
}

/// The two passes, in the calling thread's namespace.
fn read_here(pid_dir: &Path, ports: &[u16], reading: &mut NamespacePortReading) {
    reading.first_listing = listing(pid_dir);
    for &port in ports {
        for udp in [false, true] {
            for ipv6 in [false, true] {
                let probe = BindProbe { udp, ipv6, port };
                reading.probed += 1;
                match bind_once(probe) {
                    Outcome::Free => {}
                    Outcome::InUse => reading.refused_first.push(probe),
                    Outcome::Unprobed => reading.unprobed += 1,
                }
            }
        }
    }
    reading.second_listing = listing(pid_dir);
    reading.refused_second = reading
        .refused_first
        .iter()
        .copied()
        .filter(|probe| bind_once(*probe) == Outcome::InUse)
        .collect();
}

/// Read one namespace, entering it on a thread of its own unless it is the
/// warden's.
fn read_namespace(
    pid_dir: PathBuf,
    own: bool,
    ports: &[u16],
    reading: NamespacePortReading,
) -> NamespacePortReading {
    let mut reading = reading;
    if own {
        read_here(&pid_dir, ports, &mut reading);
        return reading;
    }
    let ns = match File::open(pid_dir.join("ns").join("net")) {
        Ok(ns) => ns,
        Err(e) => {
            reading.error = Some(format!("the namespace could not be opened: {e}"));
            return reading;
        }
    };
    let ports = ports.to_vec();
    let netns = reading.netns;
    std::thread::spawn(move || {
        // SAFETY: `ns` is an open namespace descriptor; setns only moves this
        // thread, which ends when the closure returns.
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            reading.error = Some(format!(
                "the namespace could not be entered: {}",
                io::Error::last_os_error()
            ));
            return reading;
        }
        read_here(&pid_dir, &ports, &mut reading);
        reading
    })
    .join()
    .unwrap_or_else(|_| NamespacePortReading {
        error: Some("the reading thread failed".to_string()),
        ..empty(netns, false)
    })
}

fn empty(netns: u64, host_netns: bool) -> NamespacePortReading {
    NamespacePortReading {
        netns,
        host_netns,
        error: None,
        first_listing: Vec::new(),
        second_listing: Vec::new(),
        probed: 0,
        unprobed: 0,
        refused_first: Vec::new(),
        refused_second: Vec::new(),
    }
}

/// Read every network namespace under `proc_root` and probe `ports` in each.
/// Port zero and repeated ports are dropped.
#[must_use]
pub fn scan(proc_root: &Path, ports: &[u16]) -> Vec<NamespacePortReading> {
    let mut wanted: Vec<u16> = ports.iter().copied().filter(|p| *p != 0).collect();
    wanted.sort_unstable();
    wanted.dedup();
    let host_netns = netns_of(&proc_root.join("1").join("ns").join("net"));
    let own_netns = std::fs::metadata("/proc/self/ns/net").ok().map(|m| m.ino());
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (pid, netns) in processes(proc_root) {
        if !seen.insert(netns) {
            continue;
        }
        let host = Some(netns) == host_netns;
        out.push(read_namespace(
            proc_root.join(pid.to_string()),
            Some(netns) == own_netns,
            &wanted,
            empty(netns, host),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_NET_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1
   1: 0100007F:1F90 0100007F:D2A4 06 00000000:00000000 03:00000F9A 00000000     0        0 0 3
garbage
";

    const PROC_NET_TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99 1
";

    #[test]
    fn proc_net_rows_read_into_port_and_state() {
        let rows = parse_proc_net_inet(PROC_NET_TCP, false);
        assert_eq!(
            rows.iter().map(|r| (r.port, r.state)).collect::<Vec<_>>(),
            vec![(22, 10), (8080, 6)]
        );
        assert!(rows.iter().all(|r| !r.udp && !r.sock_diag));
        let six = parse_proc_net_inet(PROC_NET_TCP6, true);
        assert_eq!(six.len(), 1);
        assert_eq!((six[0].port, six[0].udp), (80, true));
    }

    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = (NLMSG_HDR_LEN + payload.len()) as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(payload);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn an_inet_diag_message_names_its_port_and_state() {
        let mut payload = vec![0u8; INET_DIAG_MSG_LEN];
        payload[0] = libc::AF_INET as u8;
        payload[1] = 10;
        payload[4..6].copy_from_slice(&31337u16.to_be_bytes());
        let mut buf = message(SOCK_DIAG_BY_FAMILY, &payload);
        buf.extend(message(NLMSG_DONE, &[0; 4]));
        let mut into = Vec::new();
        assert!(read_inet_diag(&buf, false, &mut into).expect("reads"));
        assert_eq!(
            into,
            vec![ListedPort {
                udp: false,
                port: 31337,
                state: 10,
                sock_diag: true,
            }]
        );
    }

    #[test]
    fn an_error_in_place_of_the_dump_is_returned() {
        let buf = message(NLMSG_ERROR, &(-libc::ENOENT).to_ne_bytes());
        let mut into = Vec::new();
        let err = read_inet_diag(&buf, true, &mut into).expect_err("refused");
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn a_truncated_message_is_refused_rather_than_read() {
        let mut buf = message(SOCK_DIAG_BY_FAMILY, &[0; INET_DIAG_MSG_LEN]);
        buf.truncate(40);
        let mut into = Vec::new();
        assert!(read_inet_diag(&buf, false, &mut into).is_err());
    }

    #[test]
    fn a_port_held_by_a_listener_refuses_the_probe_and_a_free_one_does_not() {
        let held = std::net::TcpListener::bind("0.0.0.0:0").expect("listener");
        let port = held.local_addr().expect("address").port();
        let probe = BindProbe {
            udp: false,
            ipv6: false,
            port,
        };
        assert_eq!(bind_once(probe), Outcome::InUse);
        drop(held);
        assert_eq!(bind_once(probe), Outcome::Free);
    }

    #[test]
    fn the_warden_s_own_namespace_reads_its_listener_and_its_refusal() {
        let held = std::net::TcpListener::bind("0.0.0.0:0").expect("listener");
        let port = held.local_addr().expect("address").port();
        let mut reading = empty(1, true);
        read_here(Path::new("/proc/self"), &[port], &mut reading);
        assert_eq!(reading.probed, 4);
        assert!(
            reading
                .first_listing
                .iter()
                .any(|l| l.port == port && !l.udp && l.state == 10)
        );
        assert!(
            reading
                .refused_first
                .iter()
                .any(|p| p.port == port && !p.udp && !p.ipv6)
        );
        assert_eq!(reading.refused_first, reading.refused_second);
    }
}
