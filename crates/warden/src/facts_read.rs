//! The two facts the process detection weighs about a process.
//!
//! Whether its standard streams are internet sockets and whether its image
//! still has a file on disk both rest on links under `/proc/<pid>` that are
//! ptrace access checks, which the rootless agent fails against every process
//! outside its user namespace. The warden reads them and answers two
//! booleans: no link target, no path and no file name crosses back.

use std::collections::HashSet;
use std::path::Path;

use ebpfsentinel_warden_proto::ProcessFactsReading;

/// Suffix the kernel appends to `/proc/<pid>/exe` once the binary is unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// The file name the kernel gives an anonymous memory file.
const MEMFD_PREFIX: &str = "/memfd:";

/// The tables of the process's own network namespace that hold its internet
/// sockets, the inode in the tenth column.
const INET_TABLES: [&str; 4] = ["tcp", "tcp6", "udp", "udp6"];

/// The standard streams a remote operator types into and reads from.
const STREAMS: [u32; 2] = [0, 1];

/// The facts of `pid` in the procfs at `proc_root`, or `None` when the process
/// is gone or its `exe` link cannot be read.
pub fn read_facts(proc_root: &Path, pid: u32) -> Option<ProcessFactsReading> {
    let pid_dir = proc_root.join(pid.to_string());
    let exe = std::fs::read_link(pid_dir.join("exe")).ok()?;
    let exe = exe.to_string_lossy();
    let fileless = exe.ends_with(DELETED_SUFFIX) || exe.starts_with(MEMFD_PREFIX);
    let sockets: HashSet<u64> = STREAMS
        .iter()
        .filter_map(|fd| std::fs::read_link(pid_dir.join("fd").join(fd.to_string())).ok())
        .filter_map(|target| socket_inode(&target.to_string_lossy()))
        .collect();
    let streams_on_socket = !sockets.is_empty()
        && INET_TABLES.iter().any(|table| {
            std::fs::read_to_string(pid_dir.join("net").join(table))
                .is_ok_and(|text| table_inodes(&text).any(|inode| sockets.contains(&inode)))
        });
    Some(ProcessFactsReading {
        streams_on_socket,
        fileless,
    })
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
    use std::fmt::Write;
    use std::os::unix::fs::symlink;

    use super::read_facts;

    const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

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
            writeln!(
                table,
                "   0: 0100007F:1F90 0100007F:D2A4 01 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0000000000000000 20 4 30 10 -1"
            )
            .expect("write to a string");
        }
        std::fs::write(pid.join("net").join("tcp"), table).expect("tcp table");
        root
    }

    #[test]
    fn a_shell_on_an_internet_socket_is_seen() {
        let root = proc_with("/usr/bin/bash", &["socket:[42]", "socket:[42]"], &[42]);
        let facts = read_facts(root.path(), 7).expect("facts");
        assert!(facts.streams_on_socket);
        assert!(!facts.fileless);
    }

    #[test]
    fn a_unix_socket_is_not_a_network_stream() {
        let root = proc_with("/usr/bin/bash", &["/dev/null", "socket:[9]"], &[42]);
        assert!(!read_facts(root.path(), 7).expect("facts").streams_on_socket);
    }

    #[test]
    fn a_removed_or_anonymous_image_is_fileless() {
        for exe in ["/usr/bin/payload (deleted)", "/memfd:x"] {
            let root = proc_with(exe, &[], &[]);
            assert!(read_facts(root.path(), 7).expect("facts").fileless, "{exe}");
        }
    }

    #[test]
    fn a_gone_process_answers_nothing() {
        let root = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_facts(root.path(), 7), None);
    }
}
