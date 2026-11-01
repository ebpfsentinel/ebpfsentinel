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
