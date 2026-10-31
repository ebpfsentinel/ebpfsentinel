//! Every eBPF program on the node's network path, where it is attached and
//! which processes hold it.
//!
//! The agent is not the only thing that can put a program in front of the
//! network stack: a CNI, a load balancer, a monitoring tool, and anybody with
//! `CAP_BPF` and `CAP_NET_ADMIN`. A program ahead of the agent's can drop,
//! rewrite or redirect traffic before the agent sees it. The kernel keeps the
//! answer in four places, and the scan reads all four:
//!
//! 1. **BPF links**, enumerated by id: XDP, TCX, netkit, cgroup, netfilter
//!    and network-namespace links, from every namespace at once.
//! 2. **Legacy XDP**, attached through netlink with no link: the `IFLA_XDP`
//!    nest of each host interface.
//! 3. **Legacy `tc` filters**, `cls_bpf` on the `clsact` or `ingress` qdisc of
//!    each host interface.
//! 4. **Programs of a network type found on none of those**, listed as
//!    `unplaced`: a legacy cgroup attachment, an eBPF socket filter, a
//!    tail-call target, or a program loaded and not attached.
//!
//! A link names an interface by index only, and an index means nothing
//! outside its network namespace, so an interface is named only when the
//! host's own reading of it carries the same program. Legacy attachments are
//! read in the host namespace only.
//!
//! Enumerating by id and turning an id into a descriptor need `CAP_SYS_ADMIN`,
//! which no BPF token grants. The descriptors opened here are read and closed
//! within the scan, and none of them leaves the warden.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use ebpfsentinel_warden_proto::{HeldBpfObjects, NetworkProgram};

use crate::tcx_ops::{BPF_TCX_EGRESS, BPF_TCX_INGRESS, prog_query};

/// `enum bpf_cmd` values.
const BPF_PROG_GET_NEXT_ID: libc::c_int = 11;
const BPF_PROG_GET_FD_BY_ID: libc::c_int = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_int = 15;
const BPF_LINK_GET_FD_BY_ID: libc::c_int = 30;
const BPF_LINK_GET_NEXT_ID: libc::c_int = 31;

/// `enum bpf_link_type` values read here.
const LINK_CGROUP: u32 = 3;
const LINK_NETNS: u32 = 5;
const LINK_XDP: u32 = 6;
const LINK_NETFILTER: u32 = 10;
const LINK_TCX: u32 = 11;
const LINK_NETKIT: u32 = 13;

/// `BPF_NETKIT_PRIMARY` and `BPF_NETKIT_PEER` from `enum bpf_attach_type`.
const BPF_NETKIT_PRIMARY: u32 = 54;
const BPF_NETKIT_PEER: u32 = 55;

/// Bytes of `struct bpf_prog_info` read: up to and including `ifindex`.
const PROG_INFO_LEN: usize = 84;
/// Bytes of `struct bpf_link_info` read: the header and the largest union
/// member this scan parses.
const LINK_INFO_LEN: usize = 48;

/// rtnetlink message types and attributes.
const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const RTM_GETTFILTER: u16 = 46;
const RTM_NEWTFILTER: u16 = 44;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_HDR_LEN: usize = 16;
const NLA_HDR_LEN: usize = 4;
const IFINFOMSG_LEN: usize = 16;
const TCMSG_LEN: usize = 20;
const IFLA_IFNAME: u16 = 3;
const IFLA_XDP: u16 = 43;
/// `IFLA_XDP_PROG_ID` and the per-mode ids a multi-mode attachment reports.
const IFLA_XDP_PROG_IDS: [u16; 4] = [4, 5, 6, 7];
const TCA_KIND: u16 = 1;
const TCA_OPTIONS: u16 = 2;
const TCA_BPF_ID: u16 = 11;
/// `TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)` and its egress twin.
const TC_PARENT_INGRESS: u32 = 0xFFFF_FFF2;
const TC_PARENT_EGRESS: u32 = 0xFFFF_FFF3;

/// The program type's slug, for the types that touch packets or sockets.
#[must_use]
pub fn network_prog_type(prog_type: u32) -> Option<&'static str> {
    Some(match prog_type {
        1 => "socket_filter",
        3 => "sched_cls",
        4 => "sched_act",
        6 => "xdp",
        8 => "cgroup_skb",
        9 => "cgroup_sock",
        10 => "lwt_in",
        11 => "lwt_out",
        12 => "lwt_xmit",
        13 => "sock_ops",
        14 => "sk_skb",
        16 => "sk_msg",
        18 => "cgroup_sock_addr",
        21 => "sk_reuseport",
        22 => "flow_dissector",
        30 => "sk_lookup",
        32 => "netfilter",
        _ => return None,
    })
}

/// The cgroup attach type's slug, for the hooks on the network path.
#[must_use]
pub fn network_cgroup_attach(attach_type: u32) -> Option<&'static str> {
    Some(match attach_type {
        0 => "inet_ingress",
        1 => "inet_egress",
        2 => "inet_sock_create",
        3 => "sock_ops",
        8 => "inet4_bind",
        9 => "inet6_bind",
        10 => "inet4_connect",
        11 => "inet6_connect",
        12 => "inet4_post_bind",
        13 => "inet6_post_bind",
        14 => "udp4_sendmsg",
        15 => "udp6_sendmsg",
        19 => "udp4_recvmsg",
        20 => "udp6_recvmsg",
        21 => "getsockopt",
        22 => "setsockopt",
        29 => "inet4_getpeername",
        30 => "inet6_getpeername",
        31 => "inet4_getsockname",
        32 => "inet6_getsockname",
        34 => "inet_sock_release",
        49 => "unix_connect",
        50 => "unix_sendmsg",
        51 => "unix_recvmsg",
        52 => "unix_getpeername",
        53 => "unix_getsockname",
        _ => return None,
    })
}

/// A netfilter link's place, in the words `nft list hooks` uses.
#[must_use]
pub fn netfilter_place(pf: u32, hooknum: u32, priority: i32) -> String {
    let family = match pf {
        2 => "ipv4".to_owned(),
        10 => "ipv6".to_owned(),
        other => format!("family {other}"),
    };
    let hook = match hooknum {
        0 => "prerouting".to_owned(),
        1 => "input".to_owned(),
        2 => "forward".to_owned(),
        3 => "output".to_owned(),
        4 => "postrouting".to_owned(),
        other => format!("hook {other}"),
    };
    format!("{family} {hook} priority {priority}")
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    buf.get(at..at + 4)
        .map_or(0, |b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(buf: &[u8], at: usize) -> u64 {
    buf.get(at..at + 8).map_or(0, |b| {
        u64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// What `struct bpf_prog_info` says about one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgInfo {
    pub prog_type: u32,
    pub name: String,
    pub tag: String,
    pub created_by_uid: u32,
}

/// Read the fields this scan uses out of a `struct bpf_prog_info`.
#[must_use]
pub fn parse_prog_info(buf: &[u8]) -> ProgInfo {
    let name_bytes = buf.get(64..80).unwrap_or_default();
    let end = name_bytes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(name_bytes.len());
    let mut tag = String::with_capacity(16);
    for byte in buf.get(8..16).unwrap_or_default() {
        let _ = write!(tag, "{byte:02x}");
    }
    ProgInfo {
        prog_type: u32_at(buf, 0),
        name: String::from_utf8_lossy(&name_bytes[..end]).into_owned(),
        tag,
        created_by_uid: u32_at(buf, 48),
    }
}

/// Where one link places its program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPlace {
    pub link_id: u32,
    pub prog_id: u32,
    pub hook: &'static str,
    pub ifindex: Option<u32>,
    pub cgroup_id: Option<u64>,
    pub detail: Option<String>,
}

/// Read a `struct bpf_link_info`, or `None` for a link off the network path.
#[must_use]
pub fn parse_link_info(buf: &[u8]) -> Option<LinkPlace> {
    let link_type = u32_at(buf, 0);
    let link_id = u32_at(buf, 4);
    let prog_id = u32_at(buf, 8);
    let place = |hook, ifindex, cgroup_id, detail| LinkPlace {
        link_id,
        prog_id,
        hook,
        ifindex,
        cgroup_id,
        detail,
    };
    match link_type {
        LINK_XDP => Some(place("xdp", Some(u32_at(buf, 16)), None, None)),
        LINK_TCX => {
            let hook = match u32_at(buf, 20) {
                BPF_TCX_EGRESS => "tcx_egress",
                _ => "tcx_ingress",
            };
            Some(place(hook, Some(u32_at(buf, 16)), None, None))
        }
        LINK_NETKIT => {
            let hook = match u32_at(buf, 20) {
                BPF_NETKIT_PEER => "netkit_peer",
                _ => "netkit_primary",
            };
            Some(place(hook, Some(u32_at(buf, 16)), None, None))
        }
        LINK_CGROUP => {
            let attach = network_cgroup_attach(u32_at(buf, 24))?;
            Some(place(
                "cgroup",
                None,
                Some(u64_at(buf, 16)),
                Some(attach.to_owned()),
            ))
        }
        LINK_NETFILTER => {
            let priority = i32::from_ne_bytes(u32_at(buf, 24).to_ne_bytes());
            Some(place(
                "netfilter",
                None,
                None,
                Some(netfilter_place(u32_at(buf, 16), u32_at(buf, 20), priority)),
            ))
        }
        LINK_NETNS => {
            let what = match u32_at(buf, 20) {
                17 => "flow_dissector",
                37 => "sk_lookup",
                _ => return None,
            };
            Some(place(
                "netns",
                None,
                None,
                Some(format!("{what} in netns {}", u32_at(buf, 16))),
            ))
        }
        _ => None,
    }
}

/// `union bpf_attr` for the `*_GET_NEXT_ID` and `*_GET_FD_BY_ID` commands.
#[repr(C)]
#[derive(Default)]
struct IdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

/// `union bpf_attr` for `BPF_OBJ_GET_INFO_BY_FD`.
#[repr(C)]
#[derive(Default)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// The id after `start`, `None` past the last one.
fn next_id(cmd: libc::c_int, start: u32) -> io::Result<Option<u32>> {
    let mut attr = IdAttr {
        id: start,
        ..Default::default()
    };
    // SAFETY: `attr` is a fully initialised `bpf_attr` prefix of its size.
    let rc = unsafe { crate::bpf(cmd, (&raw mut attr).cast(), std::mem::size_of::<IdAttr>()) };
    if rc == 0 {
        return Ok(Some(attr.next_id));
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(err)
    }
}

/// Every id `cmd` enumerates.
fn all_ids(cmd: libc::c_int) -> io::Result<Vec<u32>> {
    let mut ids = Vec::new();
    let mut at = 0;
    while let Some(id) = next_id(cmd, at)? {
        ids.push(id);
        at = id;
    }
    Ok(ids)
}

/// A descriptor on object `id`, closed when dropped.
fn fd_by_id(cmd: libc::c_int, id: u32) -> io::Result<OwnedFd> {
    let mut attr = IdAttr {
        id,
        ..Default::default()
    };
    // SAFETY: `attr` is a fully initialised `bpf_attr` prefix of its size.
    let rc = unsafe { crate::bpf(cmd, (&raw mut attr).cast(), std::mem::size_of::<IdAttr>()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = RawFd::try_from(rc).map_err(io::Error::other)?;
    // SAFETY: the kernel just returned this descriptor and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Fill `buf` with the object info behind `fd`.
fn info_by_fd(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<()> {
    let mut attr = InfoAttr {
        bpf_fd: u32::try_from(fd.as_raw_fd()).map_err(io::Error::other)?,
        info_len: u32::try_from(buf.len()).map_err(io::Error::other)?,
        info: buf.as_mut_ptr() as u64,
    };
    // SAFETY: `info` points at `info_len` writable bytes that outlive the call.
    let rc = unsafe {
        crate::bpf(
            BPF_OBJ_GET_INFO_BY_FD,
            (&raw mut attr).cast(),
            std::mem::size_of::<InfoAttr>(),
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn prog_info(id: u32) -> Option<ProgInfo> {
    let fd = fd_by_id(BPF_PROG_GET_FD_BY_ID, id).ok()?;
    let mut buf = [0u8; PROG_INFO_LEN];
    info_by_fd(&fd, &mut buf).ok()?;
    Some(parse_prog_info(&buf))
}

fn link_place(id: u32) -> Option<LinkPlace> {
    let fd = fd_by_id(BPF_LINK_GET_FD_BY_ID, id).ok()?;
    let mut buf = [0u8; LINK_INFO_LEN];
    info_by_fd(&fd, &mut buf).ok()?;
    parse_link_info(&buf)
}

/// Walk the netlink attributes in `buf`, as `(type, body)`.
fn attributes(mut buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while buf.len() >= NLA_HDR_LEN {
        let len = usize::from(u16::from_ne_bytes([buf[0], buf[1]]));
        let kind = u16::from_ne_bytes([buf[2], buf[3]]) & 0x3fff;
        if len < NLA_HDR_LEN || len > buf.len() {
            break;
        }
        out.push((kind, &buf[NLA_HDR_LEN..len]));
        let step = (len + 3) & !3;
        buf = buf.get(step..).unwrap_or_default();
    }
    out
}

/// Split one `recv` of a dump into its messages, as `(type, payload)`.
/// Returns whether the dump is complete.
///
/// # Errors
///
/// A message running past the buffer, or an error the kernel sent.
pub fn split_messages(mut buf: &[u8], into: &mut Vec<(u16, Vec<u8>)>) -> io::Result<bool> {
    while buf.len() >= NLMSG_HDR_LEN {
        let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let kind = u16::from_ne_bytes([buf[4], buf[5]]);
        if len < NLMSG_HDR_LEN || len > buf.len() {
            return Err(io::Error::other("truncated rtnetlink message"));
        }
        let payload = &buf[NLMSG_HDR_LEN..len];
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let errno = i32::from_ne_bytes(u32_at(payload, 0).to_ne_bytes());
                if errno != 0 {
                    return Err(io::Error::from_raw_os_error(-errno));
                }
            }
            _ => into.push((kind, payload.to_vec())),
        }
        let step = (len + 3) & !3;
        buf = buf.get(step..).unwrap_or_default();
    }
    Ok(false)
}

/// Send one rtnetlink dump request carrying `body` and collect the replies.
fn rtnl_dump(msg_type: u16, body: &[u8]) -> io::Result<Vec<(u16, Vec<u8>)>> {
    // SAFETY: plain socket(2) call; the result is checked before use.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a descriptor this function just created and owns alone.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let total = NLMSG_HDR_LEN + body.len();
    let mut request = Vec::with_capacity(total);
    request.extend_from_slice(
        &u32::try_from(total)
            .map_err(io::Error::other)?
            .to_ne_bytes(),
    );
    request.extend_from_slice(&msg_type.to_ne_bytes());
    request.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    request.extend_from_slice(&1u32.to_ne_bytes());
    request.extend_from_slice(&0u32.to_ne_bytes());
    request.extend_from_slice(body);
    // SAFETY: the pointer and length describe `request`, which outlives the call.
    let sent = unsafe { libc::send(sock.as_raw_fd(), request.as_ptr().cast(), request.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut messages = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: the pointer and length describe `buf`, which outlives the call.
        let got = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        let got = usize::try_from(got).unwrap_or(0);
        if got == 0 || split_messages(&buf[..got], &mut messages)? {
            return Ok(messages);
        }
    }
}

/// One host interface: its name and the XDP programs on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostInterface {
    pub ifindex: u32,
    pub name: String,
    pub xdp: Vec<u32>,
}

/// Read one `RTM_NEWLINK` message.
#[must_use]
pub fn parse_link_message(payload: &[u8]) -> Option<HostInterface> {
    if payload.len() < IFINFOMSG_LEN {
        return None;
    }
    let ifindex = u32_at(payload, 4);
    let mut name = None;
    let mut xdp = BTreeSet::new();
    for (kind, body) in attributes(&payload[IFINFOMSG_LEN..]) {
        match kind {
            IFLA_IFNAME => {
                let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
                name = Some(String::from_utf8_lossy(&body[..end]).into_owned());
            }
            IFLA_XDP => {
                for (inner, value) in attributes(body) {
                    if IFLA_XDP_PROG_IDS.contains(&inner) {
                        let id = u32_at(value, 0);
                        if id != 0 {
                            xdp.insert(id);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Some(HostInterface {
        ifindex,
        name: name?,
        xdp: xdp.into_iter().collect(),
    })
}

/// The program ids of the `cls_bpf` filters in one `RTM_NEWTFILTER` message.
#[must_use]
pub fn parse_filter_message(payload: &[u8]) -> Option<u32> {
    if payload.len() < TCMSG_LEN {
        return None;
    }
    let attrs = attributes(&payload[TCMSG_LEN..]);
    let is_bpf = attrs
        .iter()
        .any(|(kind, body)| *kind == TCA_KIND && body.starts_with(b"bpf\0"));
    if !is_bpf {
        return None;
    }
    attrs
        .iter()
        .filter(|(kind, _)| *kind == TCA_OPTIONS)
        .flat_map(|(_, body)| attributes(body))
        .find(|(kind, _)| *kind == TCA_BPF_ID)
        .map(|(_, value)| u32_at(value, 0))
        .filter(|id| *id != 0)
}

fn host_interfaces() -> io::Result<Vec<HostInterface>> {
    let body = [0u8; IFINFOMSG_LEN];
    Ok(rtnl_dump(RTM_GETLINK, &body)?
        .into_iter()
        .filter(|(kind, _)| *kind == RTM_NEWLINK)
        .filter_map(|(_, payload)| parse_link_message(&payload))
        .collect())
}

fn tc_filters(ifindex: u32, parent: u32) -> Vec<u32> {
    let mut body = [0u8; TCMSG_LEN];
    body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    body[12..16].copy_from_slice(&parent.to_ne_bytes());
    let Ok(messages) = rtnl_dump(RTM_GETTFILTER, &body) else {
        return Vec::new();
    };
    let ids: BTreeSet<u32> = messages
        .into_iter()
        .filter(|(kind, _)| *kind == RTM_NEWTFILTER)
        .filter_map(|(_, payload)| parse_filter_message(&payload))
        .collect();
    ids.into_iter().collect()
}

/// The program and link ids the descriptors under `fd_dir` name, read from
/// the matching `fdinfo_dir`.
#[must_use]
pub fn held_in(fd_dir: &Path, fdinfo_dir: &Path) -> HeldBpfObjects {
    let mut prog_ids = BTreeSet::new();
    let mut link_ids = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(fd_dir) else {
        return HeldBpfObjects::default();
    };
    for entry in entries.filter_map(Result::ok) {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        let is_prog = target == "anon_inode:bpf-prog";
        let is_link = target == "anon_inode:bpf_link";
        if !is_prog && !is_link {
            continue;
        }
        let Ok(info) = std::fs::read_to_string(fdinfo_dir.join(entry.file_name())) else {
            continue;
        };
        let (prog, link) = parse_fdinfo(&info);
        prog_ids.extend(prog);
        if is_link {
            link_ids.extend(link);
        }
    }
    HeldBpfObjects {
        prog_ids: prog_ids.into_iter().collect(),
        link_ids: link_ids.into_iter().collect(),
    }
}

/// The `prog_id` and `link_id` lines of one `fdinfo` file.
#[must_use]
pub fn parse_fdinfo(text: &str) -> (Option<u32>, Option<u32>) {
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.trim().parse().ok())
    };
    (field("prog_id:"), field("link_id:"))
}

/// What the descriptors of process `pid` under `proc_root` hold; `pid` may be
/// `self`.
#[must_use]
pub fn held_by(proc_root: &Path, pid: &str) -> HeldBpfObjects {
    let dir = proc_root.join(pid);
    held_in(&dir.join("fd"), &dir.join("fdinfo"))
}

/// Who holds each program and each link, across every process.
fn holders(proc_root: &Path) -> (HashMap<u32, Vec<u32>>, HashMap<u32, Vec<u32>>) {
    let mut progs: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut links: HashMap<u32, Vec<u32>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return (progs, links);
    };
    let mut pids: Vec<u32> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    for pid in pids {
        let held = held_by(proc_root, &pid.to_string());
        for id in held.prog_ids {
            progs.entry(id).or_default().push(pid);
        }
        for id in held.link_ids {
            links.entry(id).or_default().push(pid);
        }
    }
    (progs, links)
}

/// Every program on the network path, from what the kernel holds now.
///
/// # Errors
///
/// The kernel refused to enumerate programs or links, which is what a caller
/// without `CAP_SYS_ADMIN` gets. A host interface or a filter dump that fails
/// is left out rather than failing the scan.
pub fn scan(proc_root: &Path) -> Result<Vec<NetworkProgram>, String> {
    let link_ids = all_ids(BPF_LINK_GET_NEXT_ID).map_err(|e| format!("listing BPF links: {e}"))?;
    let prog_ids =
        all_ids(BPF_PROG_GET_NEXT_ID).map_err(|e| format!("listing BPF programs: {e}"))?;
    let interfaces = host_interfaces().unwrap_or_default();
    let placed: Vec<LinkPlace> = link_ids.into_iter().filter_map(link_place).collect();
    let names = host_names(&placed, &interfaces);

    let linked_xdp: HashSet<(u32, u32)> = placed
        .iter()
        .filter(|p| p.hook == "xdp")
        .filter_map(|p| Some((p.ifindex?, p.prog_id)))
        .collect();
    let mut slots: Vec<Slot> = placed
        .into_iter()
        .map(|place| Slot {
            interface: names.get(&place.link_id).cloned(),
            prog_id: place.prog_id,
            link_id: Some(place.link_id),
            hook: place.hook,
            ifindex: place.ifindex,
            cgroup_id: place.cgroup_id,
            detail: place.detail,
        })
        .collect();
    slots.extend(legacy_slots(&interfaces, &linked_xdp));

    let mut infos: HashMap<u32, Option<ProgInfo>> = HashMap::new();
    for &id in prog_ids
        .iter()
        .chain(slots.iter().map(|slot| &slot.prog_id))
    {
        infos.entry(id).or_insert_with(|| prog_info(id));
    }
    let placed_ids: HashSet<u32> = slots.iter().map(|slot| slot.prog_id).collect();
    for prog_id in prog_ids {
        let network = infos
            .get(&prog_id)
            .and_then(Option::as_ref)
            .is_some_and(|info| network_prog_type(info.prog_type).is_some());
        if network && !placed_ids.contains(&prog_id) {
            slots.push(Slot {
                prog_id,
                link_id: None,
                hook: "unplaced",
                ifindex: None,
                interface: None,
                cgroup_id: None,
                detail: None,
            });
        }
    }

    let (prog_holders, link_holders) = holders(proc_root);
    Ok(slots
        .into_iter()
        .filter_map(|slot| {
            let info = infos.get(&slot.prog_id)?.as_ref()?;
            let mut pids: BTreeSet<u32> = prog_holders
                .get(&slot.prog_id)
                .into_iter()
                .flatten()
                .copied()
                .collect();
            if let Some(link) = slot.link_id {
                pids.extend(link_holders.get(&link).into_iter().flatten().copied());
            }
            Some(NetworkProgram {
                prog_id: slot.prog_id,
                prog_type: network_prog_type(info.prog_type)
                    .map_or_else(|| format!("type {}", info.prog_type), str::to_owned),
                name: info.name.clone(),
                tag: info.tag.clone(),
                link_id: slot.link_id,
                hook: slot.hook.to_owned(),
                ifindex: slot.ifindex,
                interface: slot.interface,
                cgroup_id: slot.cgroup_id,
                detail: slot.detail,
                created_by_uid: Some(info.created_by_uid),
                holders: pids.into_iter().collect(),
            })
        })
        .collect())
}

/// The interface name of each link whose program the host's own reading of
/// that interface carries: an index from another namespace names nothing here.
fn host_names(placed: &[LinkPlace], interfaces: &[HostInterface]) -> HashMap<u32, String> {
    let by_index: HashMap<u32, &HostInterface> =
        interfaces.iter().map(|i| (i.ifindex, i)).collect();

    let mut chains: HashMap<(u32, u32), Vec<u32>> = HashMap::new();
    let mut names: HashMap<u32, String> = HashMap::new();
    for place in placed {
        let Some(ifindex) = place.ifindex else {
            continue;
        };
        let Some(iface) = by_index.get(&ifindex) else {
            continue;
        };
        let attach_type = match place.hook {
            "xdp" => None,
            "tcx_ingress" => Some(BPF_TCX_INGRESS),
            "tcx_egress" => Some(BPF_TCX_EGRESS),
            "netkit_primary" => Some(BPF_NETKIT_PRIMARY),
            "netkit_peer" => Some(BPF_NETKIT_PEER),
            _ => continue,
        };
        let on_host = match attach_type {
            None => iface.xdp.contains(&place.prog_id),
            Some(attach) => chains
                .entry((ifindex, attach))
                .or_insert_with(|| prog_query(ifindex, attach).unwrap_or_default())
                .contains(&place.prog_id),
        };
        if on_host {
            names.insert(place.link_id, iface.name.clone());
        }
    }
    names
}

/// Programs attached to host interfaces the legacy way, through netlink with
/// no BPF link, leaving out an XDP program a link already accounts for.
fn legacy_slots(interfaces: &[HostInterface], linked_xdp: &HashSet<(u32, u32)>) -> Vec<Slot> {
    let mut slots = Vec::new();
    for iface in interfaces {
        let legacy = |prog_id: u32, hook: &'static str| Slot {
            prog_id,
            link_id: None,
            hook,
            ifindex: Some(iface.ifindex),
            interface: Some(iface.name.clone()),
            cgroup_id: None,
            detail: None,
        };
        for &prog_id in &iface.xdp {
            if !linked_xdp.contains(&(iface.ifindex, prog_id)) {
                slots.push(legacy(prog_id, "xdp"));
            }
        }
        for (parent, hook) in [
            (TC_PARENT_INGRESS, "tc_ingress"),
            (TC_PARENT_EGRESS, "tc_egress"),
        ] {
            for prog_id in tc_filters(iface.ifindex, parent) {
                slots.push(legacy(prog_id, hook));
            }
        }
    }
    slots
}

/// One program in one place, before its info and holders are read.
struct Slot {
    prog_id: u32,
    link_id: Option<u32>,
    hook: &'static str,
    ifindex: Option<u32>,
    interface: Option<String>,
    cgroup_id: Option<u64>,
    detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, body: &[u8]) -> Vec<u8> {
        let len = u16::try_from(NLA_HDR_LEN + body.len()).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&len.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(body);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn put(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_ne_bytes());
    }

    #[test]
    fn a_program_info_reads_its_type_name_tag_and_uid() {
        let mut buf = [0u8; PROG_INFO_LEN];
        put(&mut buf, 0, 6);
        buf[8..16].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3]);
        put(&mut buf, 48, 1000);
        buf[64..69].copy_from_slice(b"probe");
        let info = parse_prog_info(&buf);
        assert_eq!(info.prog_type, 6);
        assert_eq!(info.name, "probe");
        assert_eq!(info.tag, "deadbeef00010203");
        assert_eq!(info.created_by_uid, 1000);
    }

    #[test]
    fn links_are_placed_by_their_type_and_attach_point() {
        let mut buf = [0u8; LINK_INFO_LEN];
        put(&mut buf, 0, LINK_TCX);
        put(&mut buf, 4, 9);
        put(&mut buf, 8, 77);
        put(&mut buf, 16, 2);
        put(&mut buf, 20, BPF_TCX_EGRESS);
        let tcx = parse_link_info(&buf).unwrap();
        assert_eq!(
            (tcx.link_id, tcx.prog_id, tcx.hook, tcx.ifindex),
            (9, 77, "tcx_egress", Some(2))
        );

        let mut buf = [0u8; LINK_INFO_LEN];
        put(&mut buf, 0, LINK_CGROUP);
        buf[16..24].copy_from_slice(&4242u64.to_ne_bytes());
        put(&mut buf, 24, 10);
        let cgroup = parse_link_info(&buf).unwrap();
        assert_eq!(cgroup.cgroup_id, Some(4242));
        assert_eq!(cgroup.detail.as_deref(), Some("inet4_connect"));

        let mut buf = [0u8; LINK_INFO_LEN];
        put(&mut buf, 0, LINK_NETFILTER);
        put(&mut buf, 16, 2);
        put(&mut buf, 20, 1);
        put(&mut buf, 24, (-100i32).cast_unsigned());
        assert_eq!(
            parse_link_info(&buf).unwrap().detail.as_deref(),
            Some("ipv4 input priority -100")
        );
    }

    #[test]
    fn links_off_the_network_path_are_left_out() {
        let mut buf = [0u8; LINK_INFO_LEN];
        put(&mut buf, 0, 2);
        assert!(parse_link_info(&buf).is_none());
        // A cgroup link on the device controller is not on the network path.
        put(&mut buf, 0, LINK_CGROUP);
        put(&mut buf, 24, 6);
        assert!(parse_link_info(&buf).is_none());
    }

    #[test]
    fn a_link_message_names_the_interface_and_its_xdp_programs() {
        let mut payload = vec![0u8; IFINFOMSG_LEN];
        put(&mut payload, 4, 3);
        payload.extend(attr(IFLA_IFNAME, b"eth1\0"));
        let mut xdp = attr(2, &[1]);
        xdp.extend(attr(4, &55u32.to_ne_bytes()));
        payload.extend(attr(IFLA_XDP, &xdp));
        let iface = parse_link_message(&payload).unwrap();
        assert_eq!(
            iface,
            HostInterface {
                ifindex: 3,
                name: "eth1".into(),
                xdp: vec![55],
            }
        );
    }

    #[test]
    fn only_a_bpf_classifier_yields_a_program() {
        let mut payload = vec![0u8; TCMSG_LEN];
        payload.extend(attr(TCA_KIND, b"bpf\0"));
        payload.extend(attr(TCA_OPTIONS, &attr(TCA_BPF_ID, &31u32.to_ne_bytes())));
        assert_eq!(parse_filter_message(&payload), Some(31));

        let mut u32_filter = vec![0u8; TCMSG_LEN];
        u32_filter.extend(attr(TCA_KIND, b"u32\0"));
        assert_eq!(parse_filter_message(&u32_filter), None);
    }

    #[test]
    fn an_error_in_a_dump_is_refused() {
        let mut msg = Vec::new();
        msg.extend_from_slice(&20u32.to_ne_bytes());
        msg.extend_from_slice(&NLMSG_ERROR.to_ne_bytes());
        msg.extend_from_slice(&[0u8; 10]);
        msg.extend_from_slice(&(-libc::EPERM).to_ne_bytes());
        let mut into = Vec::new();
        assert!(split_messages(&msg, &mut into).is_err());
    }

    #[test]
    fn fdinfo_names_the_program_and_the_link() {
        let prog = "pos:\t0\nflags:\t02000002\nprog_type:\t6\nprog_id:\t812\n";
        assert_eq!(parse_fdinfo(prog), (Some(812), None));
        let link = "link_type:\ttcx\nlink_id:\t14\nprog_tag:\tab\nprog_id:\t812\n";
        assert_eq!(parse_fdinfo(link), (Some(812), Some(14)));
    }

    #[test]
    fn this_process_holds_no_bpf_object_it_did_not_open() {
        assert_eq!(
            held_by(Path::new("/proc"), "self"),
            HeldBpfObjects::default()
        );
    }

    #[test]
    fn slugs_cover_the_network_types_only() {
        assert_eq!(network_prog_type(6), Some("xdp"));
        assert_eq!(network_prog_type(26), None);
        assert_eq!(network_cgroup_attach(6), None);
        assert_eq!(network_cgroup_attach(1), Some("inet_egress"));
    }
}
