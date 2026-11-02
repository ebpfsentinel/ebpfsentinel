//! File-service connections read off `/proc`, from either end.
//!
//! On a file server: Samba forks one process per client, so the client of a
//! write is the one established connection that process holds on a
//! file-service port. The process's socket inodes come from its `fd` links
//! and the connections from the TCP tables of its own network namespace; a
//! process holding no such connection, or connections from several
//! addresses, names nobody.
//!
//! On a client: the processes holding an established connection to a
//! file-service port of one of a set of servers, which is what a host writing
//! to other hosts' shares is made of when a process opened them. A share
//! mounted by the kernel is written by the kernel's own socket, which no
//! process holds, so it names nobody here.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// The ports a file service listens on: SMB, the `NetBIOS` session, NFS.
const FILE_SERVICE_PORTS: [u16; 3] = [445, 139, 2049];

/// `TCP_ESTABLISHED` in the `st` column.
const ESTABLISHED: &str = "01";

/// Reads the client of a file service's process under a configurable proc
/// root, so an agent holding the host procfs at `/host/proc` reads the
/// node's processes.
pub struct ProcServedPeer {
    proc_root: PathBuf,
}

impl ProcServedPeer {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    /// The one client `pid` is connected to on a file-service port.
    #[must_use]
    pub fn read(&self, pid: u32) -> Option<IpAddr> {
        let pid_dir = self.proc_root.join(pid.to_string());
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
}

/// Reads the processes connected to a set of file servers, under a
/// configurable proc root.
pub struct ProcShareWriters {
    proc_root: PathBuf,
}

impl ProcShareWriters {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    /// Every process holding an established connection to a file-service
    /// port of one of `servers`, lowest pid first.
    ///
    /// The TCP tables are read once per network namespace rather than once
    /// per process, since every process of a namespace reads the same ones.
    #[must_use]
    pub fn read(&self, servers: &[IpAddr]) -> Vec<u32> {
        if servers.is_empty() {
            return Vec::new();
        }
        let Ok(entries) = std::fs::read_dir(&self.proc_root) else {
            return Vec::new();
        };
        let mut tables: HashMap<String, HashSet<u64>> = HashMap::new();
        let mut writers: Vec<u32> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                let pid_dir = self.proc_root.join(pid.to_string());
                let inodes = socket_inodes(&pid_dir);
                if inodes.is_empty() {
                    return false;
                }
                let namespace = std::fs::read_link(pid_dir.join("ns/net"))
                    .map_or_else(|_| pid.to_string(), |n| n.to_string_lossy().into_owned());
                let held = tables
                    .entry(namespace)
                    .or_insert_with(|| server_sockets(&pid_dir, servers));
                !held.is_disjoint(&inodes)
            })
            .collect();
        writers.sort_unstable();
        writers
    }
}

/// The inodes of the established connections, in the TCP tables of the
/// namespace `pid_dir` lives in, to a file-service port of one of `servers`.
fn server_sockets(pid_dir: &Path, servers: &[IpAddr]) -> HashSet<u64> {
    let mut held = HashSet::new();
    for (table, v6) in [("tcp", false), ("tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(pid_dir.join("net").join(table)) else {
            continue;
        };
        held.extend(
            established(&text, v6)
                .filter(|c| FILE_SERVICE_PORTS.contains(&c.remote_port))
                .filter(|c| servers.contains(&c.remote))
                .map(|c| c.inode),
        );
    }
    held
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
    established(text, v6)
        .filter(|c| inodes.contains(&c.inode) && FILE_SERVICE_PORTS.contains(&c.local_port))
        .map(|c| c.remote)
}

/// One established connection of a TCP table.
struct Connection {
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
    inode: u64,
}

/// The established connections of one TCP table.
fn established(text: &str, v6: bool) -> impl Iterator<Item = Connection> + '_ {
    text.lines().skip(1).filter_map(move |line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (local, remote, state, inode) = (
            fields.get(1)?,
            fields.get(2)?,
            fields.get(3)?,
            fields.get(9)?,
        );
        if *state != ESTABLISHED {
            return None;
        }
        let (_, local_port) = local.split_once(':')?;
        let (addr, remote_port) = remote.split_once(':')?;
        Some(Connection {
            local_port: u16::from_str_radix(local_port, 16).ok()?,
            remote: if v6 { v6_addr(addr)? } else { v4_addr(addr)? },
            remote_port: u16::from_str_radix(remote_port, 16).ok()?,
            inode: inode.parse().ok()?,
        })
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

    fn client_row(remote: &str, port: u16, inode: u64) -> String {
        format!(
            "   0: {}:C350 {remote}:{port:04X} {ESTABLISHED} 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0000000000000000 20 4 30 10 -1\n",
            local()
        )
    }

    fn add_process(root: &Path, pid: u32, sockets: &[u64], tcp: &str) {
        let pid_dir = root.join(pid.to_string());
        std::fs::create_dir_all(pid_dir.join("fd")).expect("fd");
        std::fs::create_dir_all(pid_dir.join("net")).expect("net");
        std::fs::create_dir_all(pid_dir.join("ns")).expect("ns");
        symlink("net:[4026531840]", pid_dir.join("ns/net")).expect("ns");
        for (fd, inode) in sockets.iter().enumerate() {
            symlink(
                format!("socket:[{inode}]"),
                pid_dir.join("fd").join(fd.to_string()),
            )
            .expect("link");
        }
        std::fs::write(pid_dir.join("net/tcp"), format!("{HEADER}{tcp}")).expect("tcp");
        std::fs::write(pid_dir.join("net/tcp6"), HEADER).expect("tcp6");
    }

    #[test]
    fn the_processes_connected_to_the_named_shares_are_the_writers() {
        let share = Ipv4Addr::new(10, 0, 0, 20);
        let other = Ipv4Addr::new(10, 0, 0, 21);
        let tcp = client_row(&v4_hex(share), 445, 10)
            + &client_row(&v4_hex(other), 445, 11)
            + &client_row(&v4_hex(share), 22, 12)
            + &client_row(&v4_hex(share), 2049, 13);
        let root = tempfile::tempdir().expect("tempdir");
        add_process(root.path(), 900, &[10], &tcp);
        add_process(root.path(), 300, &[13], &tcp);
        add_process(root.path(), 400, &[11], &tcp);
        add_process(root.path(), 500, &[12], &tcp);
        std::fs::create_dir_all(root.path().join("self")).expect("self");
        assert_eq!(
            ProcShareWriters::new(root.path()).read(&[IpAddr::V4(share)]),
            vec![300, 900]
        );
        assert!(ProcShareWriters::new(root.path()).read(&[]).is_empty());
    }

    #[test]
    fn a_share_reached_by_no_process_names_no_writer() {
        let root = tempfile::tempdir().expect("tempdir");
        add_process(root.path(), 900, &[], "");
        assert!(
            ProcShareWriters::new(root.path())
                .read(&[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20))])
                .is_empty()
        );
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

    fn local() -> String {
        v4_hex(Ipv4Addr::new(10, 0, 0, 2))
    }

    #[test]
    fn the_one_client_of_a_samba_process_is_named() {
        let client = v4_hex(Ipv4Addr::new(10, 0, 0, 7));
        let tcp = row(&local(), 445, &client, ESTABLISHED, 4242)
            + &row(
                &local(),
                22,
                &v4_hex(Ipv4Addr::new(10, 0, 0, 9)),
                ESTABLISHED,
                4243,
            );
        let root = proc_with(&[4242, 4243], &tcp, "");
        assert_eq!(
            ProcServedPeer::new(root.path()).read(7),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
        );
    }

    #[test]
    fn another_process_s_connection_or_a_listener_names_nobody() {
        let client = v4_hex(Ipv4Addr::new(10, 0, 0, 7));
        let tcp = row(&local(), 445, &client, ESTABLISHED, 5000)
            + &row(&local(), 445, "00000000", "0A", 4242);
        let root = proc_with(&[4242], &tcp, "");
        assert_eq!(ProcServedPeer::new(root.path()).read(7), None);
    }

    #[test]
    fn two_clients_on_one_process_name_nobody() {
        let tcp = row(
            &local(),
            445,
            &v4_hex(Ipv4Addr::new(10, 0, 0, 7)),
            ESTABLISHED,
            1,
        ) + &row(
            &local(),
            445,
            &v4_hex(Ipv4Addr::new(10, 0, 0, 8)),
            ESTABLISHED,
            2,
        );
        let root = proc_with(&[1, 2], &tcp, "");
        assert_eq!(ProcServedPeer::new(root.path()).read(7), None);
    }

    #[test]
    fn a_dual_stack_socket_names_ipv6_and_mapped_ipv4_clients() {
        let here = v6_hex(Ipv6Addr::LOCALHOST);
        let client: Ipv6Addr = "fd00::7".parse().expect("ip");
        let root = proc_with(&[1], "", &row(&here, 445, &v6_hex(client), ESTABLISHED, 1));
        assert_eq!(
            ProcServedPeer::new(root.path()).read(7),
            Some(IpAddr::V6(client))
        );
        let mapped = Ipv4Addr::new(10, 0, 0, 7).to_ipv6_mapped();
        let root = proc_with(&[1], "", &row(&here, 445, &v6_hex(mapped), ESTABLISHED, 1));
        assert_eq!(
            ProcServedPeer::new(root.path()).read(7),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)))
        );
    }

    #[test]
    fn an_unreadable_process_names_nobody() {
        let root = tempfile::tempdir().expect("tempdir");
        assert_eq!(ProcServedPeer::new(root.path()).read(7), None);
    }
}
