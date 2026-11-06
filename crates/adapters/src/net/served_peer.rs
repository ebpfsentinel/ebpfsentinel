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
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ebpfsentinel_warden_client::ReconnectingClient;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// The ports a file service listens on: SMB, the `NetBIOS` session, NFS.
const FILE_SERVICE_PORTS: [u16; 3] = [445, 139, 2049];

/// `TCP_ESTABLISHED` in the `st` column.
const ESTABLISHED: &str = "01";

/// Reads the client of a file service's process under a configurable proc
/// root, so an agent holding the host procfs at `/host/proc` reads the
/// node's processes.
///
/// A rootless agent fails the ptrace check the `fd` links ask for against a
/// service running as root, which is how a file server usually runs. When
/// `EBPFSENTINEL_WARDEN_SOCK` is set, a process whose descriptors the agent
/// may not list is read by the warden instead; without a warden, or when it
/// refuses, the process names nobody rather than a guess.
pub struct ProcServedPeer {
    proc_root: PathBuf,
    /// The warden, in a rootless deployment. Held behind a `Mutex` because the
    /// client caches its connection and the reader is shared.
    warden: Option<Mutex<ReconnectingClient>>,
}

impl ProcServedPeer {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            warden: warden_from_env(),
        }
    }

    /// Read through the warden at `sock` whenever the descriptors are not
    /// readable here, whatever the environment says.
    #[cfg(test)]
    fn with_warden(proc_root: impl Into<PathBuf>, sock: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            warden: Some(Mutex::new(ReconnectingClient::new(sock))),
        }
    }

    /// The one client `pid` is connected to on a file-service port.
    #[must_use]
    pub fn read(&self, pid: u32) -> Option<IpAddr> {
        let pid_dir = self.proc_root.join(pid.to_string());
        // An agent in a user namespace of its own may list the directory
        // and still be refused every link in it, which is the same refusal.
        let inodes = match std::fs::read_dir(pid_dir.join("fd")).map(socket_inodes) {
            Ok(Some(inodes)) => inodes,
            Ok(None) => return self.read_through_warden(pid),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return self.read_through_warden(pid);
            }
            Err(_) => return None,
        };
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

    /// Ask the warden for the client of a process the agent may not read. A
    /// warden that is down or refuses leaves the client unnamed, as a local
    /// failure does.
    fn read_through_warden(&self, pid: u32) -> Option<IpAddr> {
        let warden = self.warden.as_ref()?;
        let mut client = warden
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match client.read_served_peer(pid) {
            Ok(peer) => peer,
            Err(e) => {
                tracing::debug!(pid, error = %e, "warden could not read the served client");
                None
            }
        }
    }
}

/// Reads the processes connected to a set of file servers, under a
/// configurable proc root.
///
/// A rootless agent fails the ptrace check the `fd` links ask for against
/// every process of another user, which is most of the processes that
/// write to a share. When `EBPFSENTINEL_WARDEN_SOCK` is set and a process's
/// descriptors were refused, the whole list is read by the warden instead;
/// without a warden, or when it refuses, the list holds what this side
/// could read.
pub struct ProcShareWriters {
    proc_root: PathBuf,
    /// The warden, in a rootless deployment.
    warden: Option<Mutex<ReconnectingClient>>,
}

impl ProcShareWriters {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            warden: warden_from_env(),
        }
    }

    /// Read through the warden at `sock` whenever a process's descriptors
    /// are not readable here, whatever the environment says.
    #[cfg(test)]
    fn with_warden(proc_root: impl Into<PathBuf>, sock: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            warden: Some(Mutex::new(ReconnectingClient::new(sock))),
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
        let mut refused = false;
        let mut writers: Vec<u32> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                let pid_dir = self.proc_root.join(pid.to_string());
                let inodes = match std::fs::read_dir(pid_dir.join("fd")).map(socket_inodes) {
                    Ok(Some(inodes)) => inodes,
                    Ok(None) => {
                        refused = true;
                        return false;
                    }
                    Err(e) => {
                        refused |= e.kind() == ErrorKind::PermissionDenied;
                        return false;
                    }
                };
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
        if refused && let Some(pids) = self.read_through_warden(servers) {
            return pids;
        }
        writers.sort_unstable();
        writers
    }

    /// Ask the warden for the writers when this side was refused a process.
    /// `None` without a warden or when it fails, so what was read here
    /// stands.
    fn read_through_warden(&self, servers: &[IpAddr]) -> Option<Vec<u32>> {
        let warden = self.warden.as_ref()?;
        let mut client = warden
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match client.read_share_writers(servers) {
            Ok(pids) => Some(pids),
            Err(e) => {
                tracing::debug!(error = %e, "warden could not list the share writers");
                None
            }
        }
    }
}

/// The warden named by `EBPFSENTINEL_WARDEN_SOCK`, in a rootless deployment.
fn warden_from_env() -> Option<Mutex<ReconnectingClient>> {
    std::env::var_os(WARDEN_SOCK_ENV)
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| Mutex::new(ReconnectingClient::new(p)))
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

/// The socket inodes of every descriptor in one process's `fd` directory, or
/// `None` when a link in it was refused, which is the ptrace access check a
/// process in another user namespace fails.
fn socket_inodes(entries: std::fs::ReadDir) -> Option<HashSet<u64>> {
    let mut inodes = HashSet::new();
    for entry in entries.filter_map(Result::ok) {
        let target = match std::fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return None,
            Err(_) => continue,
        };
        if let Some(inode) = target
            .to_string_lossy()
            .strip_prefix("socket:[")
            .and_then(|t| t.strip_suffix(']'))
            .and_then(|t| t.parse().ok())
        {
            inodes.insert(inode);
        }
    }
    Some(inodes)
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

    /// Answer one connection as the warden would: the handshake, then every
    /// `ReadServedPeer` with `answer`. Returns how many reads it served.
    fn fake_warden(sock: &Path, answer: IpAddr) -> std::thread::JoinHandle<usize> {
        use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response};
        use ebpfsentinel_warden_proto::{read_frame, write_frame};
        let listener = std::os::unix::net::UnixListener::bind(sock).expect("bind");
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let Ok(Command::Hello { .. }) = read_frame::<_, Command>(&mut conn) else {
                return 0;
            };
            write_frame(
                &mut conn,
                &Response::HelloOk {
                    version: PROTOCOL_VERSION,
                },
            )
            .expect("hello");
            let mut served = 0;
            while let Ok(cmd) = read_frame::<_, Command>(&mut conn) {
                let Command::ReadServedPeer { pid: 7 } = cmd else {
                    panic!("unexpected command {cmd:?}");
                };
                served += 1;
                write_frame(&mut conn, &Response::ServedPeer { peer: Some(answer) })
                    .expect("answer");
            }
            served
        })
    }

    #[test]
    fn a_service_the_agent_may_not_read_is_read_by_the_warden() {
        use std::os::unix::fs::PermissionsExt;
        let client = Ipv4Addr::new(10, 0, 0, 7);
        let tcp = row(&local(), 445, &v4_hex(client), ESTABLISHED, 1);
        let root = proc_with(&[1], &tcp, "");
        let fd_dir = root.path().join("7/fd");
        std::fs::set_permissions(&fd_dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        // A privileged test run lists the closed directory anyway, and then
        // the warden is never asked.
        let privileged = std::fs::read_dir(&fd_dir).is_ok();

        let sock = root.path().join("warden.sock");
        let warden = fake_warden(&sock, IpAddr::V4(client));
        let peer = ProcServedPeer::with_warden(root.path(), &sock).read(7);
        assert_eq!(peer, Some(IpAddr::V4(client)));

        // Without a warden the same process names nobody.
        let alone = ProcServedPeer {
            proc_root: root.path().to_path_buf(),
            warden: None,
        }
        .read(7);
        std::fs::set_permissions(&fd_dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        if !privileged {
            assert_eq!(alone, None);
        }
        drop(std::os::unix::net::UnixStream::connect(&sock));
        let served = warden.join().expect("warden");
        assert_eq!(served, usize::from(!privileged));
    }

    #[test]
    fn an_unreadable_process_names_nobody() {
        let root = tempfile::tempdir().expect("tempdir");
        assert_eq!(ProcServedPeer::new(root.path()).read(7), None);
    }

    #[test]
    fn writers_the_agent_may_not_read_are_listed_by_the_warden() {
        use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response};
        use ebpfsentinel_warden_proto::{read_frame, write_frame};
        use std::os::unix::fs::PermissionsExt;
        let share = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20));
        let tcp = client_row(&v4_hex(Ipv4Addr::new(10, 0, 0, 20)), 445, 10);
        let root = tempfile::tempdir().expect("tempdir");
        add_process(root.path(), 900, &[10], &tcp);
        let fd_dir = root.path().join("900/fd");
        std::fs::set_permissions(&fd_dir, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        // A privileged test run lists the closed directory anyway, and then
        // the warden is never asked.
        let privileged = std::fs::read_dir(&fd_dir).is_ok();

        let sock = root.path().join("warden.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        let warden = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().expect("accept");
            let Ok(Command::Hello { .. }) = read_frame::<_, Command>(&mut conn) else {
                return 0;
            };
            write_frame(
                &mut conn,
                &Response::HelloOk {
                    version: PROTOCOL_VERSION,
                },
            )
            .expect("hello");
            let mut served = 0;
            while let Ok(cmd) = read_frame::<_, Command>(&mut conn) {
                let Command::ReadShareWriters { servers } = cmd else {
                    panic!("unexpected command {cmd:?}");
                };
                assert_eq!(servers, vec![share]);
                served += 1;
                write_frame(&mut conn, &Response::ShareWriters { pids: vec![900] })
                    .expect("answer");
            }
            served
        });
        let writers = ProcShareWriters::with_warden(root.path(), &sock).read(&[share]);
        let alone = ProcShareWriters {
            proc_root: root.path().to_path_buf(),
            warden: None,
        }
        .read(&[share]);
        std::fs::set_permissions(&fd_dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(writers, vec![900]);
        if !privileged {
            assert!(alone.is_empty());
        }
        drop(std::os::unix::net::UnixStream::connect(&sock));
        let served = warden.join().expect("warden");
        assert_eq!(served, usize::from(!privileged));
    }
}
