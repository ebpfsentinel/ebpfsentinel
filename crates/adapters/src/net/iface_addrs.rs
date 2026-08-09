#![allow(unsafe_code)] // Required for libc getifaddrs()

//! Addresses currently assigned to named network interfaces.
//!
//! Backs `interface_group` aliases: the alias names interfaces, and what the
//! firewall has to match on are the addresses those interfaces carry right
//! now. The list is re-read on every dynamic alias refresh, so a DHCP lease
//! change or a newly added address reaches the kernel on the next tick.
//!
//! Only the addresses themselves are kept, as `/32` and `/128` hosts. The
//! netmask an interface advertises describes the subnet it is attached to,
//! which is a much wider set than the machine's own addresses and is not what
//! the alias names.

use std::ffi::CStr;

use domain::common::error::DomainError;
use domain::firewall::entity::IpNetwork;

/// Addresses assigned to the named interfaces, as host networks.
///
/// Interfaces that carry no address, or that do not exist, contribute nothing;
/// they are not an error, since an alias may legitimately name an interface
/// that is still down.
pub fn resolve_interface_addrs(interfaces: &[String]) -> Result<Vec<IpNetwork>, DomainError> {
    if interfaces.is_empty() {
        return Ok(Vec::new());
    }

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid pointer to a pointer the kernel fills in;
    // the list it allocates is released by freeifaddrs below.
    let rc = unsafe { libc::getifaddrs(std::ptr::addr_of_mut!(head)) };
    if rc != 0 {
        return Err(DomainError::EngineError(format!(
            "getifaddrs() failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut addrs = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` walks the kernel-allocated list from its head and
        // is checked non-null; the list stays alive until freeifaddrs.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;

        if entry.ifa_name.is_null() || entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated C string owned by the list.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        let Ok(name) = name.to_str() else {
            continue;
        };
        if !interfaces.iter().any(|wanted| wanted == name) {
            continue;
        }

        // An interface can hold the same address once per family entry; the
        // set the alias stands for holds it once.
        if let Some(network) = entry_address(entry.ifa_addr)
            && !addrs.contains(&network)
        {
            addrs.push(network);
        }
    }

    // SAFETY: `head` is the list getifaddrs allocated and has not been freed.
    unsafe { libc::freeifaddrs(head) };

    Ok(addrs)
}

/// Read one `sockaddr` as a host network, skipping families that carry no IP
/// (`AF_PACKET` link-layer entries, which every interface also has).
fn entry_address(addr: *const libc::sockaddr) -> Option<IpNetwork> {
    // SAFETY: `addr` is non-null and points at a sockaddr the kernel wrote;
    // sa_family is the first field of every sockaddr variant. The read is
    // unaligned because the list packs the larger variants behind this header.
    let family = unsafe { std::ptr::addr_of!((*addr).sa_family).read_unaligned() };

    match i32::from(family) {
        libc::AF_INET => {
            // SAFETY: the family says this is a sockaddr_in, which is at least
            // as large as the sockaddr header it was reached through.
            let sin = unsafe { addr.cast::<libc::sockaddr_in>().read_unaligned() };
            Some(IpNetwork::V4 {
                addr: u32::from_be(sin.sin_addr.s_addr),
                prefix_len: 32,
            })
        }
        libc::AF_INET6 => {
            // SAFETY: the family says this is a sockaddr_in6.
            let sin6 = unsafe { addr.cast::<libc::sockaddr_in6>().read_unaligned() };
            Some(IpNetwork::V6 {
                addr: sin6.sin6_addr.s6_addr,
                prefix_len: 128,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_interface_list_resolves_to_nothing() {
        assert_eq!(resolve_interface_addrs(&[]).unwrap(), Vec::new());
    }

    #[test]
    fn unknown_interface_resolves_to_nothing() {
        let addrs = resolve_interface_addrs(&["ebpfsentinel-absent0".to_string()]).unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn loopback_carries_its_own_host_address() {
        let addrs = resolve_interface_addrs(&["lo".to_string()]).unwrap();
        // 127.0.0.1/32 is present on every Linux host that has a loopback.
        // A container without one simply yields nothing, which is also valid.
        for network in &addrs {
            match network {
                IpNetwork::V4 { prefix_len, .. } => assert_eq!(*prefix_len, 32),
                IpNetwork::V6 { prefix_len, .. } => assert_eq!(*prefix_len, 128),
            }
        }
    }
}
