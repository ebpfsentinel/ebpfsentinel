//! A process the kernel will signal and `/proc` does not list.
//!
//! The process directory is read with `getdents`, which is what `ps`, `top`
//! and every tool reading `/proc` see. The pid space is then swept with
//! `kill(pid, 0)`, which delivers nothing and answers whether the pid exists:
//! success and `EPERM` both mean it does. A pid that answers and was not
//! listed is observed through its own `/proc/<pid>` entry, which a directory
//! listing filter leaves reachable, and is then read again: a fresh listing
//! and a second signal.
//!
//! What explains a pid that answers and is not listed is counted by its kind,
//! so a clean result says how it was reached:
//!
//! - a thread, whose id answers a signal and is never listed, since `/proc`
//!   lists thread groups;
//! - a thread group exiting, a zombie or a dead task still holding its pid;
//! - a pid gone by the second signal, or listed by the second listing, which
//!   is a process that started or ended between the readings;
//! - a pid whose start time changed between the two observations, which is a
//!   pid reused by another process.
//!
//! The sweep is only meaningful when the signals and the listing address the
//! same pid namespace. When they do not, it is not taken, and the reason is
//! reported rather than an empty result.

use std::collections::{BTreeMap, BTreeSet};

use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;

/// The component every hidden process alert carries.
pub const HIDDEN_PROCESS_COMPONENT: &str = "hidden_process";
/// The rule every hidden process alert carries.
pub const HIDDEN_PROCESS_RULE_ID: &str = "process-hidden";

/// What `/proc/<pid>` said about a pid that answered a signal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PidObservation {
    pub pid: u32,
    /// The thread group the pid belongs to, from `status`, absent when the
    /// entry could not be read.
    pub tgid: Option<u32>,
    /// The start time in clock ticks since boot, from `stat`.
    pub start_time: Option<u64>,
    /// The one-letter state from `stat`.
    pub state: Option<char>,
    /// The command name from `stat`.
    pub comm: Option<String>,
}

impl PidObservation {
    /// A zombie or a dead task: a thread group on its way out.
    #[must_use]
    pub fn exiting(&self) -> bool {
        matches!(self.state, Some('Z' | 'X' | 'x'))
    }

    /// A thread that is not its group's leader.
    #[must_use]
    pub fn thread(&self) -> bool {
        self.tgid.is_some_and(|tgid| tgid != self.pid)
    }
}

/// The two readings of one sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessReading {
    /// The highest pid the kernel hands out, plus one.
    pub pid_space: u32,
    /// Pids signalled in the first pass.
    pub probed: u32,
    /// Thread groups the first listing of `/proc` held.
    pub listed: u32,
    /// Pids that answered and that a listed group's `task` directory held.
    pub threads: u32,
    /// Pids that answered the first signal and were listed nowhere.
    pub first: Vec<PidObservation>,
    /// Of the pids above, those the second listing held.
    pub relisted: BTreeSet<u32>,
    /// Of the pids above, those that answered the second signal.
    pub second: Vec<PidObservation>,
}

/// One process the kernel signals and `/proc` does not list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenProcess {
    pub pid: u32,
    /// The command name, where its `/proc` entry could be read.
    pub comm: Option<String>,
}

impl HiddenProcess {
    #[must_use]
    pub fn rule_id() -> RuleId {
        RuleId(HIDDEN_PROCESS_RULE_ID.to_string())
    }

    /// A process hidden from `/proc` is a rootkit concealing its own work.
    #[must_use]
    pub fn mitre() -> MitreAttackInfo {
        MitreAttackInfo {
            technique_id: "T1014".to_string(),
            technique_name: "Rootkit".to_string(),
            tactic: "defense-evasion".to_string(),
        }
    }

    /// The alert's sentence, naming the ordinary causes before the
    /// malicious one.
    #[must_use]
    pub fn message(&self) -> String {
        let name = self
            .comm
            .as_deref()
            .map_or_else(String::new, |c| format!(" ({c})"));
        format!(
            "pid {}{name} answered a signal twice and appeared in neither listing of /proc; \
             ordinary causes are a pid namespace the agent misread or a /proc it could not \
             list in full, otherwise the kernel is hiding a process from its own listing",
            self.pid
        )
    }
}

/// How one sweep reached its result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessSweepCounts {
    /// The pid space swept.
    pub pid_space: u32,
    /// Pids signalled.
    pub probed: u32,
    /// Thread groups the first listing held.
    pub listed: u32,
    /// Pids that answered and were not listed as a thread group.
    pub answered_unlisted: u32,
    /// Of those, threads of another group.
    pub explained_by_thread: u32,
    /// Thread groups exiting.
    pub explained_by_exit: u32,
    /// Pids gone by the second signal, or listed by the second listing.
    pub unconfirmed: u32,
    /// Pids that changed hands between the two observations.
    pub reused: u32,
    /// Processes reported hidden.
    pub hidden: u32,
}

/// The result of one sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessSweep {
    pub hidden: Vec<HiddenProcess>,
    pub counts: ProcessSweepCounts,
}

fn saturating(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Explain every pid that answered and was not listed, and report the rest.
#[must_use]
pub fn sweep_processes(reading: &ProcessReading) -> ProcessSweep {
    let mut counts = ProcessSweepCounts {
        pid_space: reading.pid_space,
        probed: reading.probed,
        listed: reading.listed,
        answered_unlisted: reading
            .threads
            .saturating_add(saturating(reading.first.len())),
        explained_by_thread: reading.threads,
        ..ProcessSweepCounts::default()
    };
    let second: BTreeMap<u32, &PidObservation> =
        reading.second.iter().map(|o| (o.pid, o)).collect();
    let mut hidden = Vec::new();
    for first in &reading.first {
        if first.thread() {
            counts.explained_by_thread += 1;
            continue;
        }
        if first.exiting() {
            counts.explained_by_exit += 1;
            continue;
        }
        let Some(again) = second.get(&first.pid) else {
            counts.unconfirmed += 1;
            continue;
        };
        if reading.relisted.contains(&first.pid) {
            counts.unconfirmed += 1;
            continue;
        }
        if again.thread() {
            counts.explained_by_thread += 1;
            continue;
        }
        if again.exiting() {
            counts.explained_by_exit += 1;
            continue;
        }
        if matches!((first.start_time, again.start_time), (Some(a), Some(b)) if a != b) {
            counts.reused += 1;
            continue;
        }
        hidden.push(HiddenProcess {
            pid: first.pid,
            comm: again.comm.clone().or_else(|| first.comm.clone()),
        });
    }
    counts.hidden = saturating(hidden.len());
    ProcessSweep { hidden, counts }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(pid: u32) -> PidObservation {
        PidObservation {
            pid,
            tgid: Some(pid),
            start_time: Some(1000 + u64::from(pid)),
            state: Some('S'),
            comm: Some(format!("p{pid}")),
        }
    }

    fn reading(first: Vec<PidObservation>, second: Vec<PidObservation>) -> ProcessReading {
        ProcessReading {
            pid_space: 4_194_304,
            probed: 4_194_304,
            listed: 3,
            threads: 5,
            first,
            relisted: BTreeSet::new(),
            second,
        }
    }

    #[test]
    fn a_busy_host_with_only_listed_pids_reports_nothing() {
        let sweep = sweep_processes(&reading(Vec::new(), Vec::new()));
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.listed, 3);
        assert_eq!(sweep.counts.answered_unlisted, 5);
        assert_eq!(sweep.counts.explained_by_thread, 5);
    }

    #[test]
    fn a_thread_answers_and_is_never_listed() {
        let thread = PidObservation {
            tgid: Some(2),
            ..seen(40)
        };
        let sweep = sweep_processes(&reading(vec![thread.clone()], vec![thread]));
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.explained_by_thread, 6);
    }

    #[test]
    fn a_group_on_its_way_out_is_not_hidden() {
        let zombie = PidObservation {
            state: Some('Z'),
            ..seen(41)
        };
        let sweep = sweep_processes(&reading(vec![zombie], Vec::new()));
        assert_eq!(sweep.counts.explained_by_exit, 1);

        let dying = PidObservation {
            state: Some('X'),
            ..seen(41)
        };
        let sweep = sweep_processes(&reading(vec![seen(41)], vec![dying]));
        assert_eq!(sweep.counts.explained_by_exit, 1);
        assert!(sweep.hidden.is_empty());
    }

    #[test]
    fn a_process_that_started_or_ended_between_readings_is_unconfirmed() {
        let gone = sweep_processes(&reading(vec![seen(42)], Vec::new()));
        assert_eq!(gone.counts.unconfirmed, 1);

        let mut started = reading(vec![seen(42)], vec![seen(42)]);
        started.relisted.insert(42);
        let started = sweep_processes(&started);
        assert_eq!(started.counts.unconfirmed, 1);
        assert!(started.hidden.is_empty());
    }

    #[test]
    fn a_reused_pid_is_not_hidden() {
        let other = PidObservation {
            start_time: Some(9),
            ..seen(43)
        };
        let sweep = sweep_processes(&reading(vec![seen(43)], vec![other]));
        assert_eq!(sweep.counts.reused, 1);
        assert!(sweep.hidden.is_empty());
    }

    #[test]
    fn a_pid_signalled_twice_and_listed_neither_time_is_hidden() {
        let sweep = sweep_processes(&reading(vec![seen(44)], vec![seen(44)]));
        assert_eq!(
            sweep.hidden,
            vec![HiddenProcess {
                pid: 44,
                comm: Some("p44".to_string())
            }]
        );
        assert_eq!(sweep.counts.hidden, 1);
        let message = sweep.hidden[0].message();
        assert!(message.starts_with("pid 44 (p44) answered a signal twice"));
    }

    #[test]
    fn an_unreadable_entry_is_still_hidden_when_confirmed() {
        let blind = PidObservation {
            pid: 45,
            ..PidObservation::default()
        };
        let sweep = sweep_processes(&reading(vec![blind.clone()], vec![blind]));
        assert_eq!(sweep.counts.hidden, 1);
        assert_eq!(sweep.hidden[0].comm, None);
    }
}
