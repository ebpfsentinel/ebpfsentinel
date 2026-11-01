//! Stopping a run once its verdict is reached, and what stopping it cost.
//!
//! The run is the actor and everything it started, because a run that forks
//! a worker per directory survives the death of whichever process wrote the
//! file that tipped the verdict. The members are read before the first
//! signal is sent: once a parent dies its children are adopted elsewhere and
//! no longer descend from it. The promise is a bound and not a prevention,
//! so what the stop reports first is how many files the run had already
//! written when it died.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};

use crate::process::entity::{ProcessEntry, ProcessKey};
use crate::response::signal::ProcessKillOutcome;

use super::engine::RANSOM_ACTORS_MAX;

/// Distinct files counted per actor at most; past it the count says so.
pub const RANSOM_FILES_COUNTED_MAX: usize = 1 << 16;

/// How long after the last member is stopped the count is read, so the file
/// watch has read back what the run wrote before it died.
pub const RANSOM_STOP_SETTLE_MS: u64 = 2_000;

/// The members of the run rooted at `root`, `root` first and then every
/// descendant breadth first, by pid. A child is matched on its parent's start
/// as well as its pid where both are known, so a reused pid adopts nothing.
#[must_use]
pub fn run_members(entries: &[ProcessEntry], root: ProcessKey) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<&ProcessEntry>> = HashMap::new();
    for entry in entries {
        if let Some(parent) = entry.parent_pid {
            children.entry(parent).or_default().push(entry);
        }
    }
    let mut members = vec![root.pid];
    let mut seen: HashSet<u32> = HashSet::from([root.pid]);
    let mut queue = VecDeque::from([root]);
    while let Some(parent) = queue.pop_front() {
        for child in children.get(&parent.pid).into_iter().flatten() {
            let same_parent = child
                .parent_start_ns
                .is_none_or(|start| parent.start_ns == 0 || start == parent.start_ns);
            if same_parent && seen.insert(child.pid) {
                members.push(child.pid);
                queue.push_back(child.key());
            }
        }
    }
    members
}

fn hash(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug, Default)]
struct Written {
    last_ns: u64,
    paths: HashSet<u64>,
}

/// The distinct files each actor wrote, so a stop can say what was already
/// lost. Bounded in actors and in files per actor.
#[derive(Debug, Default)]
pub struct FilesWritten {
    actors: HashMap<ProcessKey, Written>,
}

impl FilesWritten {
    /// `path` written on behalf of `actor` at `at_ns`.
    pub fn record(&mut self, actor: ProcessKey, path: &str, at_ns: u64) {
        if !self.actors.contains_key(&actor) && self.actors.len() >= RANSOM_ACTORS_MAX {
            let oldest = self
                .actors
                .iter()
                .min_by_key(|(_, written)| written.last_ns)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.actors.remove(&oldest);
            }
        }
        let written = self.actors.entry(actor).or_default();
        written.last_ns = written.last_ns.max(at_ns);
        if written.paths.len() < RANSOM_FILES_COUNTED_MAX {
            written.paths.insert(hash(path));
        }
    }

    /// How many distinct files `actor` wrote.
    #[must_use]
    pub fn count(&self, actor: ProcessKey) -> usize {
        self.actors
            .get(&actor)
            .map_or(0, |written| written.paths.len())
    }
}

/// What stopping one run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RansomStop {
    /// Each member of the run and what became of it, the actor first.
    pub outcomes: Vec<ProcessKillOutcome>,
    /// Distinct files the run wrote before it was stopped, read once the
    /// watch had settled.
    pub files_written: usize,
    /// From the verdict to the last member reported gone, in milliseconds.
    pub latency_ms: u64,
}

impl RansomStop {
    /// Whether every member of the run is gone.
    #[must_use]
    pub fn all_stopped(&self) -> bool {
        !self.outcomes.is_empty() && self.outcomes.iter().all(ProcessKillOutcome::is_killed)
    }

    /// The stop in one sentence, the files lost first.
    #[must_use]
    pub fn describe(&self) -> String {
        let killed = self.outcomes.iter().filter(|o| o.is_killed()).count();
        let total = self.outcomes.len();
        let capped = if self.files_written >= RANSOM_FILES_COUNTED_MAX {
            " or more"
        } else {
            ""
        };
        let mut out = format!(
            "{} files{capped} written before the run was stopped; {killed} of {total} processes of the run gone {} ms after the verdict",
            self.files_written, self.latency_ms
        );
        let rest: Vec<String> = self
            .outcomes
            .iter()
            .filter(|o| !o.is_killed())
            .map(ProcessKillOutcome::as_sentence)
            .collect();
        if !rest.is_empty() {
            out.push_str("; ");
            out.push_str(&rest.join("; "));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pid: u32, parent: Option<(u32, u64)>, start_ns: u64) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "enc", start_ns);
        entry.parent_pid = parent.map(|(p, _)| p);
        entry.parent_start_ns = parent.map(|(_, s)| s);
        entry.start_ns = Some(start_ns);
        entry
    }

    #[test]
    fn the_run_is_the_actor_and_every_worker_it_forked() {
        let entries = vec![
            entry(10, Some((1, 1)), 5),
            entry(11, Some((10, 5)), 6),
            entry(12, Some((10, 5)), 7),
            entry(13, Some((11, 6)), 8),
            // A pid reused under another parent start is not adopted.
            entry(14, Some((10, 99)), 9),
            entry(20, Some((1, 1)), 10),
        ];
        let members = run_members(
            &entries,
            ProcessKey {
                pid: 10,
                start_ns: 5,
            },
        );
        assert_eq!(members, vec![10, 11, 12, 13]);
    }

    #[test]
    fn files_are_counted_once_per_actor_and_bounded() {
        let mut written = FilesWritten::default();
        let a = ProcessKey {
            pid: 1,
            start_ns: 1,
        };
        written.record(a, "/d/a", 1);
        written.record(a, "/d/a", 2);
        written.record(a, "/d/b", 3);
        assert_eq!(written.count(a), 2);
        assert_eq!(
            written.count(ProcessKey {
                pid: 2,
                start_ns: 1
            }),
            0
        );
        for n in 0..=RANSOM_ACTORS_MAX {
            written.record(
                ProcessKey {
                    pid: 100 + u32::try_from(n).unwrap(),
                    start_ns: 1,
                },
                "/d/x",
                10 + u64::try_from(n).unwrap(),
            );
        }
        assert_eq!(written.count(a), 0, "the actor idle longest went first");
    }

    #[test]
    fn the_stop_names_the_files_lost_first_and_every_survivor() {
        let stop = RansomStop {
            outcomes: vec![
                ProcessKillOutcome::Killed {
                    tgid: 10,
                    signal: 9,
                },
                ProcessKillOutcome::Survived {
                    tgid: 11,
                    signal: 9,
                    signal_sent: false,
                },
            ],
            files_written: 212,
            latency_ms: 41,
        };
        assert!(!stop.all_stopped());
        assert_eq!(
            stop.describe(),
            "212 files written before the run was stopped; 1 of 2 processes of the run gone 41 ms after the verdict; process 11 was never reached before the arming expired"
        );
    }
}
