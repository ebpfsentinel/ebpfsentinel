//! Every `AF_PACKET` socket on the node, who holds it, and whether a classic
//! BPF filter is attached to it.
//!
//! A packet socket receives frames before the network stack does. A capture
//! tool opens one, a DHCP client opens one, and a backdoor that waits for a
//! magic packet opens one with a filter matching that packet. The kernel lists
//! them per network namespace, so the scan works namespace by namespace:
//!
//! 1. Each process under `proc_root` names its network namespace through
//!    `ns/net`; one process per namespace is enough to read the namespace's
//!    list.
//! 2. `<pid>/net/packet` lists the namespace's packet sockets: type, ethertype,
//!    interface, uid and inode. It needs no privilege.
//! 3. The holder is the process whose `fd/` names `socket:[<inode>]`. Only
//!    processes in a namespace that has packet sockets are walked.
//! 4. The filter is read through `sock_diag` with `PACKET_SHOW_FILTER`, from
//!    inside the namespace, on a thread that enters it and ends with the
//!    dump. The kernel answers an empty attribute to a caller without
//!    `CAP_NET_ADMIN` over the namespace, so "could not be asked" is told
//!    apart from "no filter" without guessing.
//!
//! The namespaces entered are the ones `/proc` shows and nothing the agent
//! names, and the thread that entered one serves nothing else. A socket
//! filter attached as an eBPF program keeps no classic instructions, so it
//! reads as no classic filter here and is inventoried with the programs.

use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ebpfsentinel_warden_proto::PacketSocket;

/// `NETLINK_SOCK_DIAG`.
const NETLINK_SOCK_DIAG: libc::c_int = 4;
/// `SOCK_DIAG_BY_FAMILY`.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `NLMSG_ERROR` and `NLMSG_DONE`.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// `PACKET_SHOW_FILTER` in `packet_diag_req.pdiag_show`.
const PACKET_SHOW_FILTER: u32 = 0x20;
/// `PACKET_DIAG_FILTER`, the attribute carrying the classic filter.
const PACKET_DIAG_FILTER: u16 = 7;
/// Size of one classic BPF instruction (`struct sock_filter`).
const SOCK_FILTER_LEN: usize = 8;
/// `struct nlmsghdr`, `struct packet_diag_msg` and `struct nlattr` sizes.
const NLMSG_HDR_LEN: usize = 16;
const PACKET_DIAG_MSG_LEN: usize = 16;
const NLA_HDR_LEN: usize = 4;

/// One row of `/proc/<pid>/net/packet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRow {
    pub inode: u64,
    pub socket_type: u16,
    pub protocol: u16,
    pub ifindex: u32,
    pub uid: u32,
}

/// Parse `/proc/<pid>/net/packet`: a header line, then one row per socket as
/// `sk RefCnt Type Proto Iface R Rmem User Inode`, the ethertype in hex.
/// A row that does not read is skipped rather than guessed.
#[must_use]
pub fn parse_proc_net_packet(text: &str) -> Vec<PacketRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 9 {
                return None;
            }
            Some(PacketRow {
                socket_type: fields[2].parse().ok()?,
                protocol: u16::from_str_radix(fields[3], 16).ok()?,
                ifindex: fields[4].parse().ok()?,
                uid: fields[7].parse().ok()?,
                inode: fields[8].parse().ok()?,
            })
        })
        .collect()
}

/// The number inside a `kind:[number]` link, as `socket:[31337]` or
/// `net:[4026531840]`.
#[must_use]
pub fn bracketed(target: &str, kind: &str) -> Option<u64> {
    target
        .strip_prefix(kind)?
        .strip_prefix(":[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The inode of the namespace behind a `ns/net` link.
pub(crate) fn netns_of(link: &Path) -> Option<u64> {
    let target = std::fs::read_link(link).ok()?;
    bracketed(&target.to_string_lossy(), "net")
}

/// The processes under `proc_root`, as their pid and network namespace.
pub(crate) fn processes(proc_root: &Path) -> Vec<(u32, u64)> {
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return Vec::new();
    };
    let mut out: Vec<(u32, u64)> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let netns = netns_of(&entry.path().join("ns").join("net"))?;
            Some((pid, netns))
        })
        .collect();
    // Lowest pid first, so the holder named for a socket shared across a fork
    // is the process that opened it.
    out.sort_unstable();
    out
}

/// The socket inodes `pid` holds a descriptor on.
fn sockets_held(proc_root: &Path, pid: u32) -> Vec<u64> {
    let Ok(entries) = std::fs::read_dir(proc_root.join(pid.to_string()).join("fd")) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let target = std::fs::read_link(entry.path()).ok()?;
            bracketed(&target.to_string_lossy(), "socket")
        })
        .collect()
}

/// What one `packet_diag` dump said about each socket's filter: `Some(n)` for
/// `n` classic instructions (zero when none is attached), `None` when the
/// kernel withheld it from this caller.
pub type FilterReading = HashMap<u64, Option<u32>>;

/// Read the messages of one `recv` into `into`. Returns `true` once the dump
/// is complete.
///
/// # Errors
///
/// A message whose length runs past the buffer, and an error the kernel sent
/// in place of the dump.
pub fn read_diag_messages(mut buf: &[u8], into: &mut FilterReading) -> io::Result<bool> {
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
            SOCK_DIAG_BY_FAMILY if payload.len() >= PACKET_DIAG_MSG_LEN => {
                let inode = u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
                into.insert(u64::from(inode), filter_of(&payload[PACKET_DIAG_MSG_LEN..]));
            }
            _ => {}
        }
        let step = (len + 3) & !3;
        buf = buf.get(step..).unwrap_or_default();
    }
    Ok(false)
}

/// The filter attribute among one socket's attributes. Absent means no filter;
/// present and empty means the kernel would not say.
fn filter_of(mut attrs: &[u8]) -> Option<u32> {
    while attrs.len() >= NLA_HDR_LEN {
        let len = usize::from(u16::from_ne_bytes([attrs[0], attrs[1]]));
        let kind = u16::from_ne_bytes([attrs[2], attrs[3]]) & 0x3fff;
        if len < NLA_HDR_LEN || len > attrs.len() {
            return Some(0);
        }
        if kind == PACKET_DIAG_FILTER {
            let body = len - NLA_HDR_LEN;
            return if body == 0 {
                None
            } else {
                u32::try_from(body / SOCK_FILTER_LEN).ok()
            };
        }
        let step = (len + 3) & !3;
        attrs = attrs.get(step..).unwrap_or_default();
    }
    Some(0)
}

/// `struct nlmsghdr` followed by `struct packet_diag_req`.
#[repr(C)]
struct DiagRequest {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
    sdiag_family: u8,
    sdiag_protocol: u8,
    pad: u16,
    pdiag_ino: u32,
    pdiag_show: u32,
    pdiag_cookie: [u32; 2],
}

/// Dump the filters of every packet socket in the calling thread's network
/// namespace.
///
/// # Errors
///
/// The netlink socket, the request or the reply failing.
pub fn dump_filters() -> io::Result<FilterReading> {
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
    let request = DiagRequest {
        nlmsg_len: std::mem::size_of::<DiagRequest>() as u32,
        nlmsg_type: SOCK_DIAG_BY_FAMILY,
        nlmsg_flags: (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
        sdiag_family: libc::AF_PACKET as u8,
        sdiag_protocol: 0,
        pad: 0,
        pdiag_ino: 0,
        pdiag_show: PACKET_SHOW_FILTER,
        pdiag_cookie: [u32::MAX; 2],
    };
    // SAFETY: the pointer and length describe `request`, which outlives the call.
    let sent = unsafe {
        libc::send(
            sock.as_raw_fd(),
            (&raw const request).cast(),
            std::mem::size_of::<DiagRequest>(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut reading = FilterReading::new();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        // SAFETY: the pointer and length describe `buf`, which outlives the call.
        let got = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        if got == 0 || read_diag_messages(&buf[..got as usize], &mut reading)? {
            return Ok(reading);
        }
    }
}

/// Dump the filters from inside the network namespace at `ns_link`, on a
/// thread that enters it and ends with the dump, so nothing else the process
/// does ever runs in that namespace.
fn filters_in(ns_link: &Path) -> Option<FilterReading> {
    let ns = File::open(ns_link).ok()?;
    std::thread::spawn(move || {
        // SAFETY: `ns` is an open namespace descriptor; setns only moves this
        // thread, which ends when the closure returns.
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return None;
        }
        dump_filters().ok()
    })
    .join()
    .ok()
    .flatten()
}

/// The name of interface `ifindex` in the calling thread's namespace.
fn interface_name(ifindex: u32) -> Option<String> {
    if ifindex == 0 {
        return None;
    }
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, the size if_indextoname writes at most.
    let named = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if named.is_null() {
        return None;
    }
    // SAFETY: on success the buffer holds a NUL-terminated name.
    let name = unsafe { CStr::from_ptr(buf.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

/// Every packet socket under `proc_root`, in every network namespace a
/// process there lives in.
#[must_use]
pub fn scan(proc_root: &Path) -> Vec<PacketSocket> {
    let procs = processes(proc_root);
    let host_netns = netns_of(&proc_root.join("1").join("ns").join("net"));
    let own_netns = std::fs::metadata("/proc/self/ns/net").ok().map(|m| m.ino());

    // One reader per namespace: the first process found in it.
    let mut readers: Vec<(u64, u32)> = Vec::new();
    let mut seen = HashSet::new();
    for &(pid, netns) in &procs {
        if seen.insert(netns) {
            readers.push((netns, pid));
        }
    }

    let mut sockets = Vec::new();
    let mut with_sockets = HashSet::new();
    for (netns, pid) in readers {
        let pid_dir = proc_root.join(pid.to_string());
        let Ok(text) = std::fs::read_to_string(pid_dir.join("net").join("packet")) else {
            continue;
        };
        let rows = parse_proc_net_packet(&text);
        if rows.is_empty() {
            continue;
        }
        with_sockets.insert(netns);
        let filters = if Some(netns) == own_netns {
            dump_filters().ok()
        } else {
            filters_in(&pid_dir.join("ns").join("net"))
        };
        let names_here = Some(netns) == own_netns;
        for row in rows {
            sockets.push(PacketSocket {
                inode: row.inode,
                socket_type: row.socket_type,
                protocol: row.protocol,
                ifindex: row.ifindex,
                interface: if names_here {
                    interface_name(row.ifindex)
                } else {
                    None
                },
                uid: row.uid,
                netns,
                host_netns: Some(netns) == host_netns,
                pid: None,
                filter_instructions: filters
                    .as_ref()
                    .and_then(|f| f.get(&row.inode).copied().flatten()),
            });
        }
    }

    // The holders, walking only the processes of a namespace with sockets.
    let mut holders: HashMap<(u64, u64), u32> = HashMap::new();
    for &(pid, netns) in procs.iter().filter(|(_, n)| with_sockets.contains(n)) {
        for inode in sockets_held(proc_root, pid) {
            holders.entry((netns, inode)).or_insert(pid);
        }
    }
    for socket in &mut sockets {
        socket.pid = holders.get(&(socket.netns, socket.inode)).copied();
    }
    sockets
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_NET_PACKET: &str = "\
sk               RefCnt Type Proto  Iface R Rmem   User   Inode
0000000000000000 3      3    0003   2     1 0      0      31337
0000000000000000 3      2    0800   0     1 0      101    4242
garbage line
";

    #[test]
    fn proc_net_packet_reads_into_rows_and_skips_what_does_not_read() {
        let rows = parse_proc_net_packet(PROC_NET_PACKET);
        assert_eq!(
            rows,
            vec![
                PacketRow {
                    inode: 31_337,
                    socket_type: 3,
                    protocol: 0x0003,
                    ifindex: 2,
                    uid: 0,
                },
                PacketRow {
                    inode: 4242,
                    socket_type: 2,
                    protocol: 0x0800,
                    ifindex: 0,
                    uid: 101,
                },
            ]
        );
    }

    #[test]
    fn a_bracketed_link_names_its_number_only_for_its_kind() {
        assert_eq!(bracketed("socket:[31337]", "socket"), Some(31_337));
        assert_eq!(bracketed("net:[4026531840]", "net"), Some(4_026_531_840));
        assert_eq!(bracketed("pipe:[12]", "socket"), None);
        assert_eq!(bracketed("/dev/null", "socket"), None);
    }

    fn attr(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = ((NLA_HDR_LEN + body.len()) as u16).to_ne_bytes().to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(body);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = ((NLMSG_HDR_LEN + payload.len()) as u32)
            .to_ne_bytes()
            .to_vec();
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&[0; 10]);
        out.extend_from_slice(payload);
        out
    }

    fn diag(inode: u32, attrs: &[u8]) -> Vec<u8> {
        let mut payload = vec![17, 3, 0, 3];
        payload.extend_from_slice(&inode.to_ne_bytes());
        payload.extend_from_slice(&[0; 8]);
        payload.extend_from_slice(attrs);
        message(SOCK_DIAG_BY_FAMILY, &payload)
    }

    #[test]
    fn a_dump_tells_a_filter_from_none_and_from_a_withheld_answer() {
        let mut buf = diag(1, &attr(PACKET_DIAG_FILTER, &[0; 3 * SOCK_FILTER_LEN]));
        buf.extend(diag(2, &attr(0, &[0; 8])));
        buf.extend(diag(3, &attr(PACKET_DIAG_FILTER, &[])));
        buf.extend(message(NLMSG_DONE, &[0; 4]));
        let mut reading = FilterReading::new();
        let done = read_diag_messages(&buf, &mut reading).unwrap_or(false);
        assert!(done);
        assert_eq!(reading.get(&1), Some(&Some(3)));
        assert_eq!(reading.get(&2), Some(&Some(0)));
        assert_eq!(reading.get(&3), Some(&None));
    }

    #[test]
    fn a_kernel_error_and_a_truncated_message_are_refused() {
        let mut reading = FilterReading::new();
        let error = message(NLMSG_ERROR, &(-libc::EPERM).to_ne_bytes());
        assert!(read_diag_messages(&error, &mut reading).is_err());
        let mut truncated = diag(1, &[]);
        truncated.truncate(NLMSG_HDR_LEN + 4);
        truncated[0..4].copy_from_slice(&64u32.to_ne_bytes());
        assert!(read_diag_messages(&truncated, &mut reading).is_err());
    }

    #[test]
    fn a_scan_of_a_procfs_with_no_process_finds_nothing() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        assert!(scan(dir.path()).is_empty());
    }
}
