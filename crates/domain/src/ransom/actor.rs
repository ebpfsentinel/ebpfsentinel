//! Who a signal counts against.
//!
//! A run that forks one worker per directory defeats a count kept per
//! process: twenty workers writing ten files each look like twenty processes
//! doing little. Signals therefore count against the **actor**, the oldest
//! ancestor in the unbroken chain of processes running the same executable
//! file as the one that produced the signal. A fork runs its parent's image
//! until it execs, so every worker of a forking run lands on the process
//! that started it, and a second exec of the same binary does too.
//!
//! The chain stops at the first ancestor running something else, so a shell
//! is never the actor of the programs it launches, and it never climbs onto
//! the first process of the pid namespace. A process whose executable could
//! not be read is its own actor: an unknown file matches nothing.
//!
//! A file service writing for a client on another host is the exception: the
//! run is the client's, so the actor is that client as the service saw it,
//! and it is never merged with an actor of this host's own.

use std::net::IpAddr;

use serde::Serialize;

use crate::process::engine::Lineage;
use crate::process::entity::{ProcessEntry, ProcessIdentity, ProcessKey};

/// The lineage a signal counts against.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Actor {
    /// The pid and start that name the actor and no later holder of its pid.
    #[serde(skip)]
    pub key: ProcessKey,
    pub pid: u32,
    /// The executable every process of the chain runs, where it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// Set where the writer is a file service writing for a client on
    /// another host: the run is that client's, and the process is only the
    /// service it reached. Never set on an actor of this host's own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteClient>,
}

/// The client on another host a file service wrote for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct RemoteClient {
    /// The client's address, where the service's connections named exactly
    /// one; `None` where the service is the kernel's, which holds no socket
    /// a process table can read, or where it served several clients at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<IpAddr>,
}

impl RemoteClient {
    /// The client in a sentence: its address, or that it was not read.
    #[must_use]
    pub fn describe(&self) -> String {
        self.peer.map_or_else(
            || "a client on another host, address not read".to_string(),
            |peer| format!("the client at {peer}"),
        )
    }
}

/// The file services whose writes are made for a client on another host:
/// Samba's `smbd` by its executable, and the kernel's own SMB and NFS
/// servers by the name of their threads, which carry no executable.
const FILE_SERVICE_EXES: [&str; 1] = ["smbd"];
const KERNEL_FILE_SERVICE_THREADS: [&str; 2] = ["ksmbd", "nfsd"];

/// Whether `entry` is a file service writing for a remote client.
#[must_use]
pub fn serves_files(entry: &ProcessEntry) -> bool {
    match entry.identity.path() {
        Some(path) => {
            let name = path.rsplit('/').next().unwrap_or(path);
            FILE_SERVICE_EXES.contains(&name)
        }
        None => KERNEL_FILE_SERVICE_THREADS
            .iter()
            .any(|thread| entry.comm.starts_with(thread)),
    }
}

/// The actor of a write a file service made for the client at `peer`.
/// The service's process is not climbed: Samba forks one process per
/// client from one parent, so climbing would make every client one actor.
#[must_use]
pub fn served_actor(entry: &ProcessEntry, peer: Option<IpAddr>) -> Actor {
    Actor {
        key: entry.key(),
        pid: entry.pid,
        exe: Some(
            entry
                .identity
                .path()
                .map_or_else(|| entry.comm.clone(), ToOwned::to_owned),
        ),
        remote: Some(RemoteClient { peer }),
    }
}

fn same_file(a: &ProcessIdentity, b: &ProcessIdentity) -> bool {
    match (a, b) {
        (
            ProcessIdentity::Path { dev, inode, .. },
            ProcessIdentity::Path {
                dev: other_dev,
                inode: other_inode,
                ..
            },
        ) => dev == other_dev && inode == other_inode,
        _ => false,
    }
}

/// The actor of `entry`, given its ancestry, parent first.
#[must_use]
pub fn actor_of(entry: &ProcessEntry, lineage: &Lineage) -> Actor {
    let mut top = entry;
    for ancestor in &lineage.ancestors {
        if ancestor.pid <= 1 || !same_file(&entry.identity, &ancestor.identity) {
            break;
        }
        top = ancestor;
    }
    Actor {
        key: top.key(),
        pid: top.pid,
        exe: entry.identity.path().map(ToOwned::to_owned),
        remote: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(pid: u32, start: u64, path: &str, inode: u64) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "p", start);
        entry.start_ns = Some(start);
        entry.identity = ProcessIdentity::Path {
            path: path.to_string(),
            dev: 8,
            inode,
        };
        entry
    }

    fn lineage(ancestors: Vec<ProcessEntry>) -> Lineage {
        Lineage {
            ancestors,
            truncated: false,
            incomplete: false,
        }
    }

    #[test]
    fn samba_and_the_kernel_servers_serve_files_and_nothing_else_does() {
        assert!(serves_files(&running(300, 30, "/usr/sbin/smbd", 4)));
        assert!(!serves_files(&running(301, 31, "/usr/bin/rsync", 5)));
        let mut thread = ProcessEntry::new(302, "ksmbd:445", 32);
        assert!(serves_files(&thread));
        thread.comm = "nfsd".to_string();
        assert!(serves_files(&thread));
        thread.comm = "kworker/0:1".to_string();
        assert!(!serves_files(&thread));
    }

    #[test]
    fn two_clients_of_one_samba_are_two_actors_and_neither_is_local() {
        let master = running(300, 30, "/usr/sbin/smbd", 4);
        let first = running(301, 31, "/usr/sbin/smbd", 4);
        let second = running(302, 32, "/usr/sbin/smbd", 4);
        let a = served_actor(&first, Some("10.0.0.7".parse().expect("ip")));
        let b = served_actor(&second, Some("10.0.0.8".parse().expect("ip")));
        assert_ne!(a, b);
        assert_eq!(a.pid, 301);
        let local = actor_of(&first, &lineage(vec![master]));
        assert_eq!(local.pid, 300);
        assert_ne!(a, local);
        assert!(local.remote.is_none());
        assert_eq!(
            a.remote.as_ref().map(RemoteClient::describe).as_deref(),
            Some("the client at 10.0.0.7")
        );
    }

    #[test]
    fn one_client_seen_twice_by_one_process_is_one_actor() {
        let worker = running(301, 31, "/usr/sbin/smbd", 4);
        let peer = Some("10.0.0.7".parse().expect("ip"));
        assert_eq!(served_actor(&worker, peer), served_actor(&worker, peer));
    }

    #[test]
    fn a_kernel_server_is_named_by_its_thread_and_its_client_is_unread() {
        let thread = ProcessEntry::new(302, "nfsd", 32);
        let actor = served_actor(&thread, None);
        assert_eq!(actor.exe.as_deref(), Some("nfsd"));
        assert_eq!(
            actor.remote.as_ref().map(RemoteClient::describe).as_deref(),
            Some("a client on another host, address not read")
        );
    }

    #[test]
    fn workers_forked_from_one_run_are_one_actor() {
        let run = running(100, 10, "/tmp/enc", 7);
        let shell = running(50, 5, "/bin/sh", 3);
        let first = running(101, 11, "/tmp/enc", 7);
        let second = running(102, 12, "/tmp/enc", 7);
        let a = actor_of(&first, &lineage(vec![run.clone(), shell.clone()]));
        let b = actor_of(&second, &lineage(vec![run.clone(), shell]));
        assert_eq!(a, b);
        assert_eq!(a.pid, 100);
        assert_eq!(a.key, run.key());
        assert_eq!(a.exe.as_deref(), Some("/tmp/enc"));
    }

    #[test]
    fn a_worker_of_a_worker_climbs_to_the_first_of_the_chain() {
        let run = running(100, 10, "/tmp/enc", 7);
        let mid = running(101, 11, "/tmp/enc", 7);
        let leaf = running(102, 12, "/tmp/enc", 7);
        assert_eq!(actor_of(&leaf, &lineage(vec![mid, run])).pid, 100);
    }

    #[test]
    fn a_shell_is_not_the_actor_of_what_it_launches() {
        let shell = running(50, 5, "/bin/sh", 3);
        let child = running(60, 6, "/usr/bin/openssl", 9);
        assert_eq!(actor_of(&child, &lineage(vec![shell])).pid, 60);
    }

    #[test]
    fn the_chain_never_climbs_onto_the_first_process() {
        let init = running(1, 1, "/sbin/init", 2);
        let again = running(40, 4, "/sbin/init", 2);
        assert_eq!(actor_of(&again, &lineage(vec![init])).pid, 40);
    }

    #[test]
    fn an_unread_executable_is_its_own_actor() {
        let parent = ProcessEntry::new(100, "p", 1);
        let child = ProcessEntry::new(101, "p", 2);
        let actor = actor_of(&child, &lineage(vec![parent]));
        assert_eq!(actor.pid, 101);
        assert_eq!(actor.exe, None);
    }

    #[test]
    fn the_same_path_on_another_file_is_another_executable() {
        let old = running(100, 10, "/tmp/enc", 7);
        let replaced = running(101, 11, "/tmp/enc", 8);
        assert_eq!(actor_of(&replaced, &lineage(vec![old])).pid, 101);
    }
}
