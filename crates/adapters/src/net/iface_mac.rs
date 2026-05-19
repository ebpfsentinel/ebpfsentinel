#![allow(unsafe_code)] // Required for libc ioctl(SIOCGIFHWADDR / SIOCGIFINDEX)

//! Netlink-equivalent interface MAC / ifindex resolver.
//!
//! Uses the classic `ioctl(SIOCGIFHWADDR)` / `ioctl(SIOCGIFINDEX)` kernel
//! queries on an `AF_INET`/`SOCK_DGRAM` socket. This is the same
//! information `netlink RTM_GETLINK` returns and is reused by the L2 DSR
//! path and the bounded XDP VIP announcer (`IFACE_MAC` map keyed by
//! ifindex).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use domain::common::error::DomainError;
use ports::secondary::vip_announcer_port::IfaceMacResolverPort;

/// `SIOCGIFHWADDR` — get hardware (MAC) address. Stable Linux ioctl.
const SIOCGIFHWADDR: libc::c_ulong = 0x8927;
/// `SIOCGIFINDEX` — get interface index. Stable Linux ioctl.
const SIOCGIFINDEX: libc::c_ulong = 0x8933;

/// Hand-rolled `struct ifreq`. libc's `ifreq` exposes its `ifr_ifru`
/// union via version-churning accessors; a flat 24-byte tail is the
/// stable kernel ABI and what every ifreq-based ioctl actually uses.
#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_ifru: [u8; 24],
}

fn name_to_cbuf(interface: &str) -> Result<[libc::c_char; libc::IFNAMSIZ], DomainError> {
    let bytes = interface.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
        return Err(DomainError::InvalidConfig(format!(
            "invalid interface name '{interface}' (1..{} bytes)",
            libc::IFNAMSIZ - 1
        )));
    }
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b':')
    {
        return Err(DomainError::InvalidConfig(format!(
            "interface name '{interface}' has disallowed characters"
        )));
    }
    let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
    for (dst, &src) in buf.iter_mut().zip(bytes) {
        *dst = src.cast_signed();
    }
    Ok(buf)
}

fn ioctl_socket() -> Result<OwnedFd, DomainError> {
    // SAFETY: socket() with valid constants; the returned fd is wrapped
    // in OwnedFd which closes it on drop.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(DomainError::EngineError(format!(
            "socket(AF_INET) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `fd` is a valid, freshly-created descriptor we exclusively
    // own; OwnedFd takes responsibility for closing it on drop.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Resolve the ifindex of a named interface via `ioctl(SIOCGIFINDEX)`.
pub fn resolve_ifindex(interface: &str) -> Result<u32, DomainError> {
    let sock = ioctl_socket()?;
    let mut req = IfReq {
        ifr_name: name_to_cbuf(interface)?,
        ifr_ifru: [0u8; 24],
    };
    // SAFETY: `sock` is a valid AF_INET datagram fd; `req` is a properly
    // sized ifreq the kernel fills with ifr_ifindex (a c_int at offset 0
    // of the union).
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFINDEX, std::ptr::addr_of_mut!(req)) };
    if rc < 0 {
        return Err(DomainError::EngineError(format!(
            "ioctl(SIOCGIFINDEX, {interface}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let idx = i32::from_ne_bytes([
        req.ifr_ifru[0],
        req.ifr_ifru[1],
        req.ifr_ifru[2],
        req.ifr_ifru[3],
    ]);
    u32::try_from(idx)
        .map_err(|_| DomainError::EngineError(format!("ifindex {idx} for {interface} is negative")))
}

/// Resolve the 6-byte MAC of a named interface via `ioctl(SIOCGIFHWADDR)`.
pub fn resolve_mac(interface: &str) -> Result<[u8; 6], DomainError> {
    let sock = ioctl_socket()?;
    let mut req = IfReq {
        ifr_name: name_to_cbuf(interface)?,
        ifr_ifru: [0u8; 24],
    };
    // SAFETY: `sock` is a valid AF_INET datagram fd; the kernel writes a
    // `struct sockaddr` into ifr_ifru (sa_family:2, sa_data:14); the MAC
    // occupies sa_data[0..6] i.e. ifr_ifru[2..8].
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), SIOCGIFHWADDR, std::ptr::addr_of_mut!(req)) };
    if rc < 0 {
        return Err(DomainError::EngineError(format!(
            "ioctl(SIOCGIFHWADDR, {interface}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&req.ifr_ifru[2..8]);
    if mac == [0u8; 6] {
        return Err(DomainError::EngineError(format!(
            "interface {interface} has an all-zero MAC"
        )));
    }
    Ok(mac)
}

/// `IfaceMacResolverPort` backed by `SIOCGIF*` ioctls.
#[derive(Debug, Default, Clone, Copy)]
pub struct IoctlIfaceMacResolver;

impl IfaceMacResolverPort for IoctlIfaceMacResolver {
    fn ifindex(&self, interface: &str) -> Result<u32, DomainError> {
        resolve_ifindex(interface)
    }

    fn mac(&self, interface: &str) -> Result<[u8; 6], DomainError> {
        resolve_mac(interface)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_interface_names() {
        assert!(name_to_cbuf("").is_err());
        assert!(name_to_cbuf("waaaaaaaaaaaaaaaytoolong").is_err());
        assert!(name_to_cbuf("eth0;rm").is_err());
        assert!(name_to_cbuf("eth0").is_ok());
    }

    #[test]
    fn loopback_has_an_index() {
        // `lo` exists on every Linux host the tests run on.
        let idx = resolve_ifindex("lo").expect("lo ifindex");
        assert!(idx >= 1);
    }
}
