//! Two-step rules: a first event held for a window, a second one closing it.
//!
//! A sequence follows one process: the second step is about the process the
//! first was about, or one started below it, so "a shell under the web
//! server, then a connection out" is written once and holds whether the
//! shell connects itself or through a `curl` it started. Every first step
//! waits in a set bounded in entries as well as in time, and a first step
//! refused because the set is full is counted rather than evicting one
//! that is waiting.

use std::collections::HashMap;

use crate::firewall::workload::WorkloadFacts;
use crate::process::entity::ProcessKey;

use super::event::IntentEvent;
use super::rule::{HostRule, HostRuleSet};

/// The first steps a node holds at once, across every rule.
pub const HOST_RULE_PENDING_MAX: usize = 8_192;

/// The process an event is about and the ones above it, parent first.
#[derive(Debug, Clone, Copy, Default)]
pub struct Subject<'a> {
    pub process: Option<ProcessKey>,
    pub ancestors: &'a [ProcessKey],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Waiting {
    since_ns: u64,
    until_ns: u64,
}

/// First steps waiting for their second, keyed by rule and process.
#[derive(Debug, Clone)]
pub struct PendingSequences {
    waiting: HashMap<(usize, ProcessKey), Waiting>,
    capacity: usize,
    refused: u64,
}

impl Default for PendingSequences {
    fn default() -> Self {
        Self::new(HOST_RULE_PENDING_MAX)
    }
}

impl PendingSequences {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            waiting: HashMap::new(),
            capacity,
            refused: 0,
        }
    }

    /// First steps waiting now, expired ones included until the next sweep.
    #[must_use]
    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// First steps not held because the set was full of live ones.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused
    }

    fn hold(&mut self, key: (usize, ProcessKey), at_ns: u64, window_ns: u64) {
        let waiting = Waiting {
            since_ns: at_ns,
            until_ns: at_ns.saturating_add(window_ns),
        };
        if let Some(slot) = self.waiting.get_mut(&key) {
            *slot = waiting;
            return;
        }
        if self.waiting.len() >= self.capacity {
            self.waiting.retain(|_, w| w.until_ns >= at_ns);
        }
        if self.waiting.len() >= self.capacity {
            self.refused += 1;
            return;
        }
        self.waiting.insert(key, waiting);
    }

    /// Whether a first step of rule `index` waits for this process or one
    /// above it, taken out of the set either way once it is found.
    fn close(&mut self, index: usize, subject: &Subject<'_>, at_ns: u64) -> bool {
        let candidates = subject.process.iter().chain(subject.ancestors.iter());
        for process in candidates {
            if let Some(waiting) = self.waiting.remove(&(index, *process))
                && waiting.since_ns <= at_ns
                && at_ns <= waiting.until_ns
            {
                return true;
            }
        }
        false
    }
}

impl HostRuleSet {
    /// The rules `event` completes: a single-step rule it matches, or a
    /// sequence whose first step waits for this process or one above it
    /// and whose second step it matches. A first step it matches is held
    /// after the second steps are tried, so one event never both opens
    /// and closes the same sequence.
    pub fn evaluate<'a>(
        &'a self,
        pending: &mut PendingSequences,
        event: &IntentEvent,
        workload: Option<&WorkloadFacts<'_>>,
        subject: &Subject<'_>,
        at_ns: u64,
    ) -> Vec<&'a HostRule> {
        let mut fired = Vec::new();
        for (index, rule) in self.rules().iter().enumerate() {
            let Some(followed_by) = &rule.followed_by else {
                if rule.matches(event, workload) {
                    fired.push(rule);
                }
                continue;
            };
            if followed_by.then.blocks().iter().any(|b| b.holds(event))
                && pending.close(index, subject, at_ns)
            {
                fired.push(rule);
            }
            if let Some(process) = subject.process
                && rule.matches(event, workload)
            {
                pending.hold((index, process), at_ns, followed_by.within_ns);
            }
        }
        fired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostrule::field::FieldValue;
    use crate::hostrule::intent::Intent;
    use crate::hostrule::rule::HostRuleSpec;

    const SECOND: u64 = 1_000_000_000;

    fn set(json: &str) -> HostRuleSet {
        let specs: Vec<HostRuleSpec> = serde_json::from_str(json).unwrap();
        HostRuleSet::compile(specs).unwrap()
    }

    fn start(exe: &str) -> IntentEvent {
        IntentEvent::new(Intent::ProcessStarts)
            .with("exe", FieldValue::Text(exe.to_string()))
            .unwrap()
    }

    fn key(pid: u32) -> ProcessKey {
        ProcessKey { pid, start_ns: 1 }
    }

    fn shell_then_curl() -> HostRuleSet {
        set(r#"[{"id":"shell-then-curl",
                 "when":{"process.starts":{"exe":"/bin/sh"}},
                 "followed_by":{"within":"10s","process.starts":{"exe":"/usr/bin/curl"}}}]"#)
    }

    fn fired(
        rules: &HostRuleSet,
        pending: &mut PendingSequences,
        event: &IntentEvent,
        subject: &Subject<'_>,
        at: u64,
    ) -> Vec<String> {
        rules
            .evaluate(pending, event, None, subject, at)
            .into_iter()
            .map(|r| r.id().to_string())
            .collect()
    }

    #[test]
    fn the_second_step_below_the_first_closes_the_sequence_once() {
        let rules = shell_then_curl();
        let mut pending = PendingSequences::default();
        let shell = Subject {
            process: Some(key(10)),
            ancestors: &[],
        };
        assert!(fired(&rules, &mut pending, &start("/bin/sh"), &shell, SECOND).is_empty());
        assert_eq!(pending.len(), 1);
        let parents = [key(10)];
        let curl = Subject {
            process: Some(key(11)),
            ancestors: &parents,
        };
        assert_eq!(
            fired(
                &rules,
                &mut pending,
                &start("/usr/bin/curl"),
                &curl,
                5 * SECOND
            ),
            vec!["shell-then-curl"]
        );
        assert!(pending.is_empty());
        assert!(
            fired(
                &rules,
                &mut pending,
                &start("/usr/bin/curl"),
                &curl,
                6 * SECOND
            )
            .is_empty()
        );
    }

    #[test]
    fn the_window_expires() {
        let rules = shell_then_curl();
        let mut pending = PendingSequences::default();
        let process = Subject {
            process: Some(key(10)),
            ancestors: &[],
        };
        fired(&rules, &mut pending, &start("/bin/sh"), &process, SECOND);
        assert!(
            fired(
                &rules,
                &mut pending,
                &start("/usr/bin/curl"),
                &process,
                11 * SECOND + 1
            )
            .is_empty()
        );
        assert!(
            pending.is_empty(),
            "an expired first step is dropped once read"
        );
        fired(
            &rules,
            &mut pending,
            &start("/bin/sh"),
            &process,
            20 * SECOND,
        );
        assert_eq!(
            fired(
                &rules,
                &mut pending,
                &start("/usr/bin/curl"),
                &process,
                30 * SECOND
            ),
            vec!["shell-then-curl"],
            "the window is inclusive"
        );
    }

    #[test]
    fn another_process_does_not_close_it() {
        let rules = shell_then_curl();
        let mut pending = PendingSequences::default();
        let shell = Subject {
            process: Some(key(10)),
            ancestors: &[],
        };
        fired(&rules, &mut pending, &start("/bin/sh"), &shell, SECOND);
        let reused = Subject {
            process: Some(ProcessKey {
                pid: 10,
                start_ns: 2,
            }),
            ancestors: &[],
        };
        assert!(
            fired(
                &rules,
                &mut pending,
                &start("/usr/bin/curl"),
                &reused,
                2 * SECOND
            )
            .is_empty()
        );
        let sibling = Subject {
            process: Some(key(12)),
            ancestors: &[],
        };
        assert!(
            fired(
                &rules,
                &mut pending,
                &start("/usr/bin/curl"),
                &sibling,
                2 * SECOND
            )
            .is_empty()
        );
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn the_bound_is_hit_counted_and_expired_entries_make_room() {
        let rules = shell_then_curl();
        let mut pending = PendingSequences::new(2);
        for pid in 1..=3 {
            let subject = Subject {
                process: Some(key(pid)),
                ancestors: &[],
            };
            fired(&rules, &mut pending, &start("/bin/sh"), &subject, SECOND);
        }
        assert_eq!((pending.len(), pending.refused()), (2, 1));
        let late = Subject {
            process: Some(key(4)),
            ancestors: &[],
        };
        fired(&rules, &mut pending, &start("/bin/sh"), &late, 20 * SECOND);
        assert_eq!((pending.len(), pending.refused()), (1, 1));
    }

    #[test]
    fn a_first_step_that_never_fires_holds_nothing() {
        let rules = shell_then_curl();
        let mut pending = PendingSequences::default();
        for pid in 1..100 {
            let subject = Subject {
                process: Some(key(pid)),
                ancestors: &[],
            };
            fired(
                &rules,
                &mut pending,
                &start("/usr/bin/curl"),
                &subject,
                SECOND,
            );
            fired(&rules, &mut pending, &start("/bin/ls"), &subject, SECOND);
        }
        assert!(pending.is_empty());
        assert_eq!(pending.refused(), 0);
    }

    #[test]
    fn one_event_does_not_open_and_close_the_same_sequence() {
        let rules = set(r#"[{"id":"twice",
                 "when":{"process.starts":{"exe":"/bin/sh"}},
                 "followed_by":{"within":"10s","process.starts":{"exe":"/bin/sh"}}}]"#);
        let mut pending = PendingSequences::default();
        let shell = Subject {
            process: Some(key(10)),
            ancestors: &[],
        };
        assert!(fired(&rules, &mut pending, &start("/bin/sh"), &shell, SECOND).is_empty());
        let parents = [key(10)];
        let child = Subject {
            process: Some(key(11)),
            ancestors: &parents,
        };
        assert_eq!(
            fired(&rules, &mut pending, &start("/bin/sh"), &child, 2 * SECOND),
            vec!["twice"]
        );
        assert_eq!(pending.len(), 1, "the child's own start opens its own");
    }

    #[test]
    fn a_single_step_rule_fires_beside_a_sequence() {
        let mut specs: Vec<HostRuleSpec> = serde_json::from_str(
            r#"[{"id":"any-shell","when":{"process.starts":{"exe":"/bin/sh"}}}]"#,
        )
        .unwrap();
        specs.extend(shell_then_curl().rules().iter().map(|r| r.spec.clone()));
        let rules = HostRuleSet::compile(specs).unwrap();
        let mut pending = PendingSequences::default();
        let shell = Subject {
            process: Some(key(10)),
            ancestors: &[],
        };
        assert_eq!(
            fired(&rules, &mut pending, &start("/bin/sh"), &shell, SECOND),
            vec!["any-shell"]
        );
        let unkeyed = Subject::default();
        assert_eq!(
            fired(&rules, &mut pending, &start("/bin/sh"), &unkeyed, SECOND),
            vec!["any-shell"],
        );
        assert_eq!(pending.len(), 1, "an event with no process opens nothing");
    }
}
