use std::collections::HashSet;
use std::path::{Path, PathBuf};

use domain::process::detection::ProcessFacts;
use ports::secondary::process_facts_port::ProcessFactsReader;

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
/// A link the agent may not read, which is every process outside its user
/// namespace when it runs rootless, answers nothing rather than a guess.
pub struct ProcFactsReader {
    proc_root: PathBuf,
}

impl ProcFactsReader {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
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
        let exe = std::fs::read_link(pid_dir.join("exe")).ok()?;
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

    #[test]
    fn socket_links_and_table_rows_parse() {
        assert_eq!(socket_inode("socket:[12]"), Some(12));
        assert_eq!(socket_inode("pipe:[12]"), None);
        let table = format!("{TCP_HEADER}{}{}", tcp_row(1), tcp_row(2));
        assert_eq!(table_inodes(&table).collect::<Vec<_>>(), vec![1, 2]);
    }
}
