use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use domain::process::detection::ProcessFacts;
use ebpfsentinel_warden_client::ReconnectingClient;
use ports::secondary::process_facts_port::ProcessFactsReader;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// Suffix the kernel appends to `/proc/<pid>/exe` once the binary is unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// The file name the kernel gives an anonymous memory file.
const MEMFD_PREFIX: &str = "/memfd:";

/// The tables of the process's own network namespace that hold its internet
/// sockets, one line each, the inode in the tenth column.
const INET_TABLES: [&str; 4] = ["tcp", "tcp6", "udp", "udp6"];

/// The standard streams a remote operator types into and reads from.
const STREAMS: [u32; 2] = [0, 1];

/// Reads the two facts from `/proc/<pid>`, under a configurable proc root so
/// an agent holding the host procfs at `/host/proc` reads the node's
/// processes.
///
/// The image is read off the `exe` link before anything strips the marker the
/// kernel leaves on a removed file. A stream is an internet socket when its
/// link names a socket inode that one of the process's own namespace's
/// internet tables lists, which is what tells a shell typed into from the
/// network apart from a service whose output goes to the journal over a unix
/// socket.
///
/// A rootless agent fails the ptrace check these links ask for against every
/// process outside its user namespace. When `EBPFSENTINEL_WARDEN_SOCK` is set,
/// a process whose `exe` link the agent may not read is read by the warden
/// instead; without a warden, or when it refuses, the process answers nothing
/// rather than a guess. A process that is simply gone costs no round trip.
pub struct ProcFactsReader {
    proc_root: PathBuf,
    /// The warden, in a rootless deployment. Held behind a `Mutex` because the
    /// client caches its connection and the port reads through `&self`.
    warden: Option<Mutex<ReconnectingClient>>,
}

impl ProcFactsReader {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| Mutex::new(ReconnectingClient::new(p)));
        Self {
            proc_root: proc_root.into(),
            warden,
        }
    }

    /// Read through the warden at `sock` whenever the local link is not
    /// readable, whatever the environment says.
    #[cfg(test)]
    fn with_warden(proc_root: impl Into<PathBuf>, sock: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            warden: Some(Mutex::new(ReconnectingClient::new(sock))),
        }
    }

    /// Ask the warden for the facts of a process the agent may not read. A
    /// warden that is down or refuses leaves the process unread, as a local
    /// failure does.
    fn read_through_warden(&self, pid: u32) -> Option<ProcessFacts> {
        let warden = self.warden.as_ref()?;
        // The client holds a connection and nothing the facts depend on, so
        // a poisoned lock leaves it usable.
        let mut client = warden
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match client.read_process_facts(pid) {
            Ok(found) => found.map(|facts| ProcessFacts {
                streams_on_socket: facts.streams_on_socket,
                fileless: facts.fileless,
            }),
            Err(e) => {
                tracing::debug!(pid, error = %e, "warden could not read the process facts");
                None
            }
        }
    }

    /// Convenience constructor that defaults to `/proc`.
    pub fn with_default_proc() -> Self {
        Self::new(Path::new("/proc"))
    }

    /// The socket inodes the standard streams point at.
    fn stream_sockets(pid_dir: &Path) -> Vec<u64> {
        STREAMS
            .iter()
            .filter_map(|fd| std::fs::read_link(pid_dir.join("fd").join(fd.to_string())).ok())
            .filter_map(|target| socket_inode(&target.to_string_lossy()))
            .collect()
    }

    /// Whether one of `inodes` is an internet socket in the namespace of the
    /// process whose directory is `pid_dir`.
    fn any_inet(pid_dir: &Path, inodes: &[u64]) -> bool {
        let wanted: HashSet<u64> = inodes.iter().copied().collect();
        INET_TABLES.iter().any(|table| {
            std::fs::read_to_string(pid_dir.join("net").join(table))
                .is_ok_and(|text| table_inodes(&text).any(|inode| wanted.contains(&inode)))
        })
    }
}

impl ProcessFactsReader for ProcFactsReader {
    fn read_facts(&self, pid: u32) -> Option<ProcessFacts> {
        let pid_dir = self.proc_root.join(pid.to_string());
        let exe = match std::fs::read_link(pid_dir.join("exe")) {
            Ok(exe) => exe,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                return self.read_through_warden(pid);
            }
            Err(_) => return None,
        };
        let exe = exe.to_string_lossy();
        let fileless = exe.ends_with(DELETED_SUFFIX) || exe.starts_with(MEMFD_PREFIX);
        let sockets = Self::stream_sockets(&pid_dir);
        let streams_on_socket = !sockets.is_empty() && Self::any_inet(&pid_dir, &sockets);
        Some(ProcessFacts {
            streams_on_socket,
            fileless,
        })
    }
}

/// The inode of a `socket:[N]` link target.
fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The inode column of every row of a `/proc/net/{tcp,udp}{,6}` table.
fn table_inodes(text: &str) -> impl Iterator<Item = u64> + '_ {
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().nth(9)?.parse().ok())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    fn tcp_row(inode: u64) -> String {
        format!(
            "   0: 0100007F:1F90 0100007F:D2A4 01 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0000000000000000 20 4 30 10 -1\n"
        )
    }

    /// A proc root holding one process, pid 7.
    fn proc_with(exe: &str, streams: &[&str], tcp: &[u64]) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        let pid = root.path().join("7");
        std::fs::create_dir_all(pid.join("fd")).expect("fd dir");
        std::fs::create_dir_all(pid.join("net")).expect("net dir");
        symlink(exe, pid.join("exe")).expect("exe link");
        for (fd, target) in streams.iter().enumerate() {
            symlink(target, pid.join("fd").join(fd.to_string())).expect("fd link");
        }
        let mut table = TCP_HEADER.to_string();
        for inode in tcp {
            table.push_str(&tcp_row(*inode));
        }
        std::fs::write(pid.join("net").join("tcp"), table).expect("tcp table");
        root
    }

    #[test]
    fn a_stream_on_an_internet_socket_is_seen() {
        let root = proc_with(
            "/usr/bin/bash",
            &["socket:[4242]", "socket:[4242]"],
            &[4242],
        );
        let facts = ProcFactsReader::new(root.path())
            .read_facts(7)
            .expect("facts");
        assert!(facts.streams_on_socket);
        assert!(!facts.fileless);
    }

    #[test]
    fn a_stream_on_a_unix_socket_is_not_a_network_stream() {
        // What every service writing to the journal looks like.
        let root = proc_with("/usr/bin/bash", &["/dev/null", "socket:[999]"], &[4242]);
        let facts = ProcFactsReader::new(root.path())
            .read_facts(7)
            .expect("facts");
        assert!(!facts.streams_on_socket);
    }

    #[test]
    fn a_removed_or_anonymous_image_has_no_file() {
        for exe in [
            "/usr/bin/payload (deleted)",
            "/memfd:x (deleted)",
            "/memfd:x",
        ] {
            let root = proc_with(exe, &["/dev/pts/0"], &[]);
            let facts = ProcFactsReader::new(root.path())
                .read_facts(7)
                .expect("facts");
            assert!(facts.fileless, "{exe}");
        }
        let root = proc_with("/usr/bin/curl", &["/dev/pts/0"], &[]);
        assert!(
            !ProcFactsReader::new(root.path())
                .read_facts(7)
                .expect("facts")
                .fileless
        );
    }

    #[test]
    fn a_gone_process_answers_nothing() {
        let root = tempfile::tempdir().expect("tempdir");
        assert_eq!(ProcFactsReader::new(root.path()).read_facts(7), None);
    }

    /// Answer one connection as the warden would: the handshake, then every
    /// `ReadProcessFacts` with `answer`. Returns how many reads it served.
    fn fake_warden(
        sock: &Path,
        answer: ebpfsentinel_warden_proto::ProcessFactsReading,
    ) -> std::thread::JoinHandle<usize> {
        use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response};
        use ebpfsentinel_warden_proto::{read_frame, write_frame};
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let Ok(Command::Hello { .. }) = read_frame::<_, Command>(&mut conn) else {
                return 0;
            };
            write_frame(
                &mut conn,
                &Response::HelloOk {
                    version: PROTOCOL_VERSION,
                },
            )
            .unwrap();
            let mut served = 0;
            while let Ok(cmd) = read_frame::<_, Command>(&mut conn) {
                let Command::ReadProcessFacts { .. } = cmd else {
                    panic!("unexpected command {cmd:?}");
                };
                served += 1;
                write_frame(
                    &mut conn,
                    &Response::ProcessFacts {
                        facts: Some(answer),
                    },
                )
                .unwrap();
            }
            served
        })
    }

    #[test]
    fn a_process_the_agent_may_not_read_is_read_by_the_warden() {
        use std::os::unix::fs::PermissionsExt;
        let root = proc_with("/usr/bin/bash", &["/dev/null", "/dev/null"], &[]);
        let pid_dir = root.path().join("7");
        std::fs::set_permissions(&pid_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        // A privileged test run reads through the closed directory anyway,
        // and then the warden is never asked.
        let privileged = std::fs::read_dir(&pid_dir).is_ok();

        let sock = root.path().join("warden.sock");
        let warden = fake_warden(
            &sock,
            ebpfsentinel_warden_proto::ProcessFactsReading {
                streams_on_socket: true,
                fileless: true,
            },
        );
        let reader = ProcFactsReader::with_warden(root.path(), &sock);
        let facts = reader.read_facts(7).expect("facts");
        if !privileged {
            assert!(
                facts.streams_on_socket && facts.fileless,
                "the warden's answer"
            );
        }

        // A process that is gone is not worth a round trip.
        assert_eq!(reader.read_facts(999_999), None);

        drop(reader);
        if privileged {
            // Nobody connected; unblock the accept so the thread ends.
            drop(std::os::unix::net::UnixStream::connect(&sock));
        }
        let served = warden.join().unwrap();
        std::fs::set_permissions(&pid_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !privileged {
            assert_eq!(served, 1);
        }
    }

    #[test]
    fn without_a_warden_an_unreadable_process_answers_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let root = proc_with("/usr/bin/bash", &[], &[]);
        let pid_dir = root.path().join("7");
        std::fs::set_permissions(&pid_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let privileged = std::fs::read_dir(&pid_dir).is_ok();
        let reader = ProcFactsReader {
            proc_root: root.path().to_path_buf(),
            warden: None,
        };
        let facts = reader.read_facts(7);
        std::fs::set_permissions(&pid_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !privileged {
            assert_eq!(facts, None);
        }
    }

    #[test]
    fn socket_links_and_table_rows_parse() {
        assert_eq!(socket_inode("socket:[12]"), Some(12));
        assert_eq!(socket_inode("pipe:[12]"), None);
        let table = format!("{TCP_HEADER}{}{}", tcp_row(1), tcp_row(2));
        assert_eq!(table_inodes(&table).collect::<Vec<_>>(), vec![1, 2]);
    }
}
