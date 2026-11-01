//! A network namespace's addresses, read through procfs.
//!
//! `/proc/<pid>/net` is the network view of the namespace `<pid>` is in, so
//! the addresses of any container can be read from the host without entering
//! it and without asking its runtime: IPv4 from the local routes of
//! `fib_trie`, IPv6 from `if_inet6`. The namespace itself is named by the
//! inode `/proc/<pid>/ns/net` resolves to.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use ports::secondary::namespace_address_port::NamespaceAddressReader;

/// Reads namespaces under one procfs root, the host's when it is mounted
/// into the agent's container.
#[derive(Debug, Clone)]
pub struct ProcNamespaceAddresses {
    proc_root: PathBuf,
}

impl ProcNamespaceAddresses {
    #[must_use]
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    fn namespace_at(&self, task: &str) -> Option<u64> {
        std::fs::metadata(self.proc_root.join(task).join("ns/net"))
            .ok()
            .map(|meta| meta.ino())
    }

    fn addresses_at(&self, task: &str) -> Option<Vec<IpAddr>> {
        let net = self.proc_root.join(task).join("net");
        let v4 = std::fs::read_to_string(net.join("fib_trie")).ok();
        // A kernel without IPv6, or a namespace where it is disabled, has no
        // such file, which is no address rather than an unreadable namespace.
        let v6 = std::fs::read_to_string(net.join("if_inet6")).unwrap_or_default();
        let v4 = v4?;
        let mut addresses: BTreeSet<IpAddr> = local_ipv4(&v4).into_iter().map(IpAddr::V4).collect();
        addresses.extend(ipv6_addresses(&v6).into_iter().map(IpAddr::V6));
        Some(addresses.into_iter().collect())
    }
}

impl NamespaceAddressReader for ProcNamespaceAddresses {
    fn namespace_of(&self, pid: u32) -> Option<u64> {
        self.namespace_at(&pid.to_string())
    }

    fn host_namespace(&self) -> Option<u64> {
        self.namespace_at("1")
    }

    fn addresses_of(&self, pid: u32) -> Option<Vec<IpAddr>> {
        self.addresses_at(&pid.to_string())
    }

    fn host_addresses(&self) -> Option<Vec<IpAddr>> {
        self.addresses_at("1")
    }
}

/// The addresses `fib_trie` lists as local host routes.
///
/// Each leaf is a `|-- <address>` line followed by its routes; an address of
/// the namespace's own is the one carrying a `/32 host LOCAL` route. The trie
/// is printed once per table, so an address appears more than once.
fn local_ipv4(fib_trie: &str) -> BTreeSet<Ipv4Addr> {
    let mut found = BTreeSet::new();
    let mut leaf: Option<Ipv4Addr> = None;
    for line in fib_trie.lines() {
        let trimmed = line.trim_start_matches([' ', '|', '+', '-']).trim();
        if let Some(rest) = line.trim_start().strip_prefix("|-- ") {
            leaf = rest.trim().parse().ok();
        } else if trimmed.starts_with("/32 host LOCAL")
            && let Some(address) = leaf
        {
            found.insert(address);
        }
    }
    found
}

/// The addresses `if_inet6` lists: thirty-two hex digits per line.
fn ipv6_addresses(if_inet6: &str) -> Vec<Ipv6Addr> {
    if_inet6
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(|hex| {
            u128::from_str_radix(hex, 16)
                .ok()
                .filter(|_| hex.len() == 32)
        })
        .map(Ipv6Addr::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIB_TRIE: &str = "\
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.244.0.0/24 2 0 2
        |-- 10.244.0.0
           /24 link UNICAST
        |-- 10.244.0.7
           /32 host LOCAL
     |-- 127.0.0.1
        /32 host LOCAL
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 10.244.0.7
        /32 host LOCAL
     |-- 10.244.0.255
        /32 link BROADCAST
";

    const IF_INET6: &str = "\
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000a8c1abfffe2b3c4d 02 40 20 80     eth0
20010db8000000000000000000000007 02 40 00 80     eth0
";

    #[test]
    fn local_ipv4_addresses_are_the_host_routes_of_the_trie() {
        let found: Vec<Ipv4Addr> = local_ipv4(FIB_TRIE).into_iter().collect();
        assert_eq!(
            found,
            [Ipv4Addr::new(10, 244, 0, 7), Ipv4Addr::LOCALHOST]
        );
    }

    #[test]
    fn ipv6_addresses_are_read_from_their_hex_form() {
        let found = ipv6_addresses(IF_INET6);
        assert_eq!(
            found,
            [
                Ipv6Addr::LOCALHOST,
                "fe80::a8c1:abff:fe2b:3c4d".parse::<Ipv6Addr>().expect("v6"),
                "2001:db8::7".parse::<Ipv6Addr>().expect("v6"),
            ]
        );
        assert!(ipv6_addresses("zz 01\nshort 02\n").is_empty());
    }

    #[test]
    fn a_namespace_is_read_under_the_root_given() {
        let root = tempfile::tempdir().expect("dir");
        let net = root.path().join("42/net");
        std::fs::create_dir_all(&net).expect("net");
        std::fs::write(net.join("fib_trie"), FIB_TRIE).expect("trie");
        std::fs::write(net.join("if_inet6"), IF_INET6).expect("v6");
        let ns = root.path().join("42/ns");
        std::fs::create_dir_all(&ns).expect("ns");
        std::fs::write(ns.join("net"), "").expect("ns file");

        let reader = ProcNamespaceAddresses::new(root.path());
        let addresses = reader.addresses_of(42).expect("read");
        assert_eq!(addresses.len(), 5);
        assert!(addresses.contains(&"10.244.0.7".parse().expect("v4")));
        assert!(reader.namespace_of(42).is_some());
        assert_eq!(reader.namespace_of(43), None);
        assert_eq!(reader.addresses_of(43), None);
        assert_eq!(reader.host_addresses(), None);
    }

    #[test]
    fn a_namespace_without_ipv6_still_answers_its_ipv4() {
        let root = tempfile::tempdir().expect("dir");
        let net = root.path().join("1/net");
        std::fs::create_dir_all(&net).expect("net");
        std::fs::write(net.join("fib_trie"), FIB_TRIE).expect("trie");
        let reader = ProcNamespaceAddresses::new(root.path());
        assert_eq!(reader.host_addresses().map(|a| a.len()), Some(2));
    }
}
