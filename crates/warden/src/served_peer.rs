//! The client a file service process serves, read for a rootless agent.
//!
//! A file server forks one process per client, so the client of a write is
//! the one established connection that process holds on a file-service port.
//! The socket inodes come from the process's `fd` links, which the rootless
//! agent may not read against a service running as root, and the connections
//! from the TCP tables of the process's own network namespace. A process
//! holding no such connection, or connections from several addresses, names
//! nobody.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// The ports a file service listens on: SMB, the `NetBIOS` session, NFS.
const FILE_SERVICE_PORTS: [u16; 3] = [445, 139, 2049];

/// `TCP_ESTABLISHED` in the `st` column.
const ESTABLISHED: &str = "01";

/// The one client `pid` serves on a file-service port in the procfs at
/// `proc_root`.
#[must_use]
pub fn read(proc_root: &Path, pid: u32) -> Option<IpAddr> {
    let pid_dir = proc_root.join(pid.to_string());
    let inodes = socket_inodes(&pid_dir);
    if inodes.is_empty() {
        return None;
    }
    let mut peers = HashSet::new();
    for (table, v6) in [("tcp", false), ("tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(pid_dir.join("net").join(table)) else {
            continue;
        };
        peers.extend(served_peers(&text, v6, &inodes));
    }
    let mut peers = peers.into_iter();
    match (peers.next(), peers.next()) {
        (Some(peer), None) => Some(peer),
        _ => None,
    }
}

/// The socket inodes of every descriptor the process holds.
fn socket_inodes(pid_dir: &Path) -> HashSet<u64> {
    let Ok(entries) = std::fs::read_dir(pid_dir.join("fd")) else {
        return HashSet::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_link(entry.path()).ok())
        .filter_map(|target| {
            target
                .to_string_lossy()
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()
        })
        .collect()
}

/// The remote addresses of the established connections in one TCP table
/// whose local port is a file service's and whose socket is in `inodes`.
fn served_peers<'a>(
    text: &'a str,
    v6: bool,
    inodes: &'a HashSet<u64>,
) -> impl Iterator<Item = IpAddr> + 'a {
    text.lines().skip(1).filter_map(move |line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (local, remote, state, inode) = (
            fields.get(1)?,
            fields.get(2)?,
            fields.get(3)?,
            fields.get(9)?,
        );
        if *state != ESTABLISHED || !inodes.contains(&inode.parse().ok()?) {
            return None;
        }
        let (_, local_port) = local.split_once(':')?;
        if !FILE_SERVICE_PORTS.contains(&u16::from_str_radix(local_port, 16).ok()?) {
            return None;
        }
        let (addr, _) = remote.split_once(':')?;
        if v6 { v6_addr(addr) } else { v4_addr(addr) }
    })
}

/// An IPv4 address as the kernel prints it: one word in host order.
fn v4_addr(hex: &str) -> Option<IpAddr> {
    let word = u32::from_str_radix(hex, 16).ok()?;
    Some(IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes())))
}

/// An IPv6 address as the kernel prints it: four words in host order. An
/// IPv4 client reaching a dual-stack socket is named by its IPv4 address.
fn v6_addr(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in bytes.chunks_mut(4).enumerate() {
        let word = u32::from_str_radix(hex.get(i * 8..i * 8 + 8)?, 16).ok()?;
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    let addr = Ipv6Addr::from(bytes);
    Some(addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    fn v4_hex(addr: Ipv4Addr) -> String {
        format!("{:08X}", u32::from_ne_bytes(addr.octets()))
    }

    fn v6_hex(addr: Ipv6Addr) -> String {
        let words: Vec<String> = addr
            .octets()
            .chunks(4)
            .map(|c| format!("{:08X}", u32::from_ne_bytes([c[0], c[1], c[2], c[3]])))
            .collect();
        words.concat()
    }

    fn row(local: &str, port: u16, remote: &str, state: &str, inode: u64) -> String {
        format!(
            "   0: {local}:{port:04X} {remote}:C350 {state} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0000000000000000 20 4 30 10 -1\n"
        )
    }

    fn proc_with(sockets: &[u64], tcp: &str, tcp6: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        let pid_dir = root.path().join("7");
        std::fs::create_dir_all(pid_dir.join("fd")).expect("fd");
        std::fs::create_dir_all(pid_dir.join("net")).expect("net");
        for (fd, inode) in sockets.iter().enumerate() {
            symlink(
                format!("socket:[{inode}]"),
                pid_dir.join("fd").join(fd.to_string()),
            )
            .expect("link");
        }
        symlink("/dev/null", pid_dir.join("fd").join("99")).expect("link");
        std::fs::write(pid_dir.join("net/tcp"), format!("{HEADER}{tcp}")).expect("tcp");
        std::fs::write(pid_dir.join("net/tcp6"), format!("{HEADER}{tcp6}")).expect("tcp6");
        root
    }

    fn here() -> String {
        v4_hex(Ipv4Addr::new(10, 0, 0, 2))
    }

    #[test]
    fn the_one_client_of_a_samba_process_is_named() {
        let client = v4_hex(Ipv4Addr::new(10, 0, 0, 7));
        let tcp = row(&here(), 445, &client, ESTABLISHED, 4242)
            + &row(
                &here(),
                22,
                &v4_hex(Ipv4Addr::new(10, 0, 0, 9)),
                ESTABLISHED,
                4243,
            );
        let root = proc_with(&[4242, 4243], &tcp, "");
        assert_eq!(
            read(root.path(), 7),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
        );
    }

    #[test]
    fn another_process_s_connection_a_listener_or_two_clients_name_nobody() {
        let client = v4_hex(Ipv4Addr::new(10, 0, 0, 7));
        let tcp = row(&here(), 445, &client, ESTABLISHED, 5000)
            + &row(&here(), 445, "00000000", "0A", 4242);
        assert_eq!(read(proc_with(&[4242], &tcp, "").path(), 7), None);
        let tcp = row(&here(), 445, &client, ESTABLISHED, 1)
            + &row(
                &here(),
                445,
                &v4_hex(Ipv4Addr::new(10, 0, 0, 8)),
                ESTABLISHED,
                2,
            );
        assert_eq!(read(proc_with(&[1, 2], &tcp, "").path(), 7), None);
    }

    #[test]
    fn a_dual_stack_socket_names_a_mapped_ipv4_client_by_its_ipv4_address() {
        let local = v6_hex(Ipv6Addr::LOCALHOST);
        let mapped = Ipv4Addr::new(10, 0, 0, 7).to_ipv6_mapped();
        let root = proc_with(&[1], "", &row(&local, 445, &v6_hex(mapped), ESTABLISHED, 1));
        assert_eq!(
            read(root.path(), 7),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
        );
    }

    #[test]
    fn a_process_that_is_gone_names_nobody() {
        let root = tempfile::tempdir().expect("tempdir");
        assert_eq!(read(root.path(), 7), None);
    }
}
