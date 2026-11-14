//! The id every network namespace carries as seen from the warden's own.
//!
//! The kernel reports a link's peer by the id its namespace carries in the
//! namespace the link lives in; finding the workload behind the link means
//! asking every namespace a process sits in for that id. Asking takes a
//! descriptor on `/proc/<pid>/ns/net`, which only a holder of the ptrace
//! right over the process may open, so a rootless agent asks the warden.
//! Nothing is entered and nothing is written: one `RTM_GETNSID` per
//! namespace, on a route socket in the warden's namespace.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use ebpfsentinel_warden_proto::NamespaceIdReading;

use crate::packet_sockets::processes;

const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;
const NETNSA_NSID: u16 = 1;
const NETNSA_FD: u16 = 3;
const NLMSG_HDRLEN: usize = 16;
const RTGENMSG_LEN: usize = 4;
const NLA_HDRLEN: usize = 4;

/// Every network namespace under `proc_root`, with its id and the lowest pid
/// sitting in it. A namespace whose file cannot be opened, or whose question
/// fails, is listed without an id.
#[must_use]
pub fn scan(proc_root: &Path) -> Vec<NamespaceIdReading> {
    let sock = route_socket().ok();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (pid, netns) in processes(proc_root) {
        if !seen.insert(netns) {
            continue;
        }
        let nsid = sock.as_ref().and_then(|sock| {
            let ns = File::open(proc_root.join(pid.to_string()).join("ns").join("net")).ok()?;
            namespace_id(sock, &ns).ok().flatten()
        });
        out.push(NamespaceIdReading { netns, nsid, pid });
    }
    out
}

fn route_socket() -> io::Result<OwnedFd> {
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
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The `RTM_GETNSID` request naming the namespace behind descriptor `fd`.
fn request(fd: u32) -> Vec<u8> {
    let len = NLMSG_HDRLEN + RTGENMSG_LEN + NLA_HDRLEN + 4;
    let mut msg = Vec::with_capacity(len);
    msg.extend_from_slice(&u32::try_from(len).unwrap_or(0).to_ne_bytes());
    msg.extend_from_slice(&RTM_GETNSID.to_ne_bytes());
    msg.extend_from_slice(
        &u16::try_from(libc::NLM_F_REQUEST)
            .unwrap_or(1)
            .to_ne_bytes(),
    );
    msg.extend_from_slice(&1u32.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&[0u8; RTGENMSG_LEN]);
    msg.extend_from_slice(&8u16.to_ne_bytes());
    msg.extend_from_slice(&NETNSA_FD.to_ne_bytes());
    msg.extend_from_slice(&fd.to_ne_bytes());
    msg
}

fn namespace_id(sock: &OwnedFd, ns: &File) -> io::Result<Option<i32>> {
    let fd = u32::try_from(ns.as_raw_fd()).map_err(io::Error::other)?;
    let msg = request(fd);
    // SAFETY: the pointer and length describe `msg`, which outlives the call.
    let sent = unsafe { libc::send(sock.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buf = [0u8; 4096];
    // SAFETY: the pointer and length describe `buf`, which outlives the call.
    let got = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    parse_reply(&buf[..usize::try_from(got).unwrap_or(0)])
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

/// The id a reply carries, `None` when the namespace has none yet, an error
/// when the kernel answered with one.
fn parse_reply(buf: &[u8]) -> io::Result<Option<i32>> {
    let mut at = 0;
    while let (Some(len), Some(kind)) = (u32_at(buf, at), u16_at(buf, at + 4)) {
        let len = len as usize;
        if len < NLMSG_HDRLEN || at + len > buf.len() {
            break;
        }
        let body = &buf[at + NLMSG_HDRLEN..at + len];
        if kind == u16::try_from(libc::NLMSG_ERROR).unwrap_or(2) {
            let errno = u32_at(body, 0).map_or(0, u32::cast_signed);
            if errno != 0 {
                return Err(io::Error::from_raw_os_error(-errno));
            }
        } else if kind == RTM_NEWNSID {
            let mut attr = RTGENMSG_LEN;
            while let (Some(alen), Some(akind)) = (u16_at(body, attr), u16_at(body, attr + 2)) {
                let alen = usize::from(alen);
                if alen < NLA_HDRLEN {
                    break;
                }
                if akind & 0x3fff == NETNSA_NSID {
                    return Ok(u32_at(body, attr + NLA_HDRLEN)
                        .map(u32::cast_signed)
                        .filter(|nsid| *nsid >= 0));
                }
                attr += (alen + 3) & !3;
            }
            return Ok(None);
        }
        at += (len + 3) & !3;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(kind: u16, body: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDRLEN + body.len();
        let mut msg = Vec::new();
        msg.extend_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        msg.extend_from_slice(&kind.to_ne_bytes());
        msg.extend_from_slice(&[0u8; 10]);
        msg.extend_from_slice(body);
        msg
    }

    fn nsid_body(nsid: i32) -> Vec<u8> {
        let mut body = vec![0u8; RTGENMSG_LEN];
        body.extend_from_slice(&8u16.to_ne_bytes());
        body.extend_from_slice(&NETNSA_NSID.to_ne_bytes());
        body.extend_from_slice(&nsid.to_ne_bytes());
        body
    }

    #[test]
    fn the_request_names_the_descriptor() {
        let msg = request(7);
        assert_eq!(msg.len(), 28);
        assert_eq!(u32_at(&msg, 0), Some(28));
        assert_eq!(u16_at(&msg, 4), Some(RTM_GETNSID));
        assert_eq!(u16_at(&msg, 22), Some(NETNSA_FD));
        assert_eq!(u32_at(&msg, 24), Some(7));
    }

    #[test]
    fn a_reply_carries_the_id() {
        assert_eq!(
            parse_reply(&reply(RTM_NEWNSID, &nsid_body(3))).unwrap(),
            Some(3)
        );
    }

    #[test]
    fn a_namespace_without_an_id_answers_none() {
        assert_eq!(
            parse_reply(&reply(RTM_NEWNSID, &nsid_body(-1))).unwrap(),
            None
        );
    }

    #[test]
    fn an_error_reply_is_an_error() {
        let body = (-libc::EPERM).to_ne_bytes();
        let err = parse_reply(&reply(2, &body)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn this_process_namespace_is_listed() {
        let own = std::process::id();
        let found = scan(Path::new("/proc"));
        assert!(found.iter().any(|reading| reading.pid <= own));
    }
}
