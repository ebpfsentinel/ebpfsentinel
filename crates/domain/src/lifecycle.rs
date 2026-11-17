//! How the agent's runs end, and the service unit that starts it.
//!
//! A host agent is stopped through its own `stop` command, which records who
//! asked and why, then ends with a status of its own so the supervisor leaves
//! it stopped. Anything else that ends it is a stop nobody accounted for:
//! a signal from a `systemctl kill`, a `SIGKILL`, a crash. Each run writes a
//! record when it starts and completes it when it ends, so the next start
//! reads how the last one went and says so.
//!
//! The unit that keeps the agent running is part of the defence: a masked
//! unit or a drop-in that removes the restart policy is how the agent is kept
//! down after the next stop. Its files are fingerprinted at start and compared
//! on every heartbeat.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::alert::entity::Alert;
use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::Severity;

/// The component every lifecycle alert is filed under.
pub const AGENT_LIFECYCLE_COMPONENT: &str = "agent_lifecycle";

/// The status the agent exits with after its own `stop` command, so a
/// supervisor restarting it on any other exit leaves this one stopped. The
/// enterprise layer's signed stop ends with the same status.
pub const STOP_EXIT_CODE: i32 = 79;

/// The rule raised when the previous run ended on a signal on this boot.
pub const RULE_STOPPED_BY_SIGNAL: &str = "agent-stopped-by-signal";
/// The rule raised when the previous run ended without completing its record.
pub const RULE_ENDED_UNRECORDED: &str = "agent-ended-unrecorded";
/// The rule raised when the agent's service unit is masked.
pub const RULE_UNIT_MASKED: &str = "agent-unit-masked";
/// The rule raised when the agent's service unit files change.
pub const RULE_UNIT_CHANGED: &str = "agent-unit-changed";

/// The longest reason or requester kept in a record.
pub const MAX_STOP_TEXT: usize = 256;

/// Stopping the agent, or keeping it from starting again, is turning a
/// defence off.
#[must_use]
pub fn mitre() -> MitreAttackInfo {
    MitreAttackInfo {
        technique_id: "T1562.001".to_string(),
        technique_name: "Impair Defenses: Disable or Modify Tools".to_string(),
        tactic: "defense-evasion".to_string(),
    }
}

/// What one run wrote about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    /// The kernel's boot identifier when the run started.
    pub boot_id: String,
    pub pid: u32,
    /// Seconds since the epoch.
    pub started_at: u64,
    /// Filled when the run ends in order; absent, it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended: Option<RunEnd>,
}

/// How a run that ended in order ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunEnd {
    /// Seconds since the epoch.
    pub at: u64,
    pub how: EndCause,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// What ended a run that ended in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndCause {
    /// The agent's own `stop` command, by an authenticated caller.
    Command,
    /// `SIGTERM` or `SIGINT`, from whoever could send it.
    Signal,
    /// An error the run could not continue past, at start or later.
    Failure,
}

/// Cut `text` to [`MAX_STOP_TEXT`] bytes on a character boundary, dropping
/// control characters, so a reason cannot forge a log line.
#[must_use]
pub fn clean_stop_text(text: &str) -> String {
    let mut out = String::new();
    for c in text.trim().chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_STOP_TEXT {
            break;
        }
        out.push(c);
    }
    out
}

/// What the previous run's record says about how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviousRun {
    /// No record: a first start, or a state directory nobody kept.
    Unknown,
    /// Stopped through its own command.
    Commanded(RunEnd),
    /// Ended on a signal on an earlier boot: the host shut down.
    HostShutdown,
    /// Ended on a signal on this boot: somebody stopped the service.
    Signalled(RunEnd),
    /// Ended on an error it logged; its supervisor restarts it.
    Failed(RunEnd),
    /// Never completed its record: killed, crashed, or the power went.
    Unrecorded {
        record: RunRecord,
        /// Whether the host has been up since that run started.
        same_boot: bool,
    },
}

impl PreviousRun {
    /// Read `record` against the boot this start happens on.
    #[must_use]
    pub fn judge(record: Option<RunRecord>, this_boot: &str) -> Self {
        let Some(record) = record else {
            return Self::Unknown;
        };
        let same_boot = !this_boot.is_empty() && record.boot_id == this_boot;
        match record.ended {
            Some(end) if end.how == EndCause::Command => Self::Commanded(end),
            Some(end) if end.how == EndCause::Failure => Self::Failed(end),
            Some(end) if same_boot => Self::Signalled(end),
            Some(_) => Self::HostShutdown,
            None => Self::Unrecorded { record, same_boot },
        }
    }

    /// The alert this ending deserves, if any. A stop through the command and
    /// a host shutdown are the ordinary ways a run ends; a run lost to a
    /// power cut is worth a line, not an analyst.
    #[must_use]
    pub fn alert(&self, at_ns: u64) -> Option<Alert> {
        let (rule, severity) = match self {
            Self::Unknown | Self::Commanded(_) | Self::HostShutdown | Self::Failed(_) => {
                return None;
            }
            Self::Signalled(_) => (RULE_STOPPED_BY_SIGNAL, Severity::High),
            Self::Unrecorded {
                same_boot: true, ..
            } => (RULE_ENDED_UNRECORDED, Severity::High),
            Self::Unrecorded {
                same_boot: false, ..
            } => (RULE_ENDED_UNRECORDED, Severity::Low),
        };
        let mut alert = Alert::operational(
            AGENT_LIFECYCLE_COMPONENT,
            rule,
            severity,
            self.message(),
            at_ns,
        );
        alert.mitre_attack = Some(mitre());
        Some(alert)
    }

    /// One sentence saying how the previous run ended.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Unknown => "no record of a previous run".to_string(),
            Self::Commanded(end) => format!(
                "the previous run was stopped through the stop command{}{}",
                by(end.requested_by.as_deref()),
                because(end.reason.as_deref())
            ),
            Self::HostShutdown => "the previous run ended with the host's shutdown".to_string(),
            Self::Failed(_) => {
                "the previous run ended on an error, logged at the time".to_string()
            }
            Self::Signalled(_) => {
                "the previous run was ended by a signal on this boot, without the stop command: the service was stopped or killed by hand".to_string()
            }
            Self::Unrecorded {
                record,
                same_boot: true,
            } => format!(
                "the previous run (pid {}) ended without recording its end on this boot: it was killed with SIGKILL, frozen out or crashed",
                record.pid
            ),
            Self::Unrecorded {
                record,
                same_boot: false,
            } => format!(
                "the previous run (pid {}) ended without recording its end, on an earlier boot: the host lost power or crashed, or the agent was killed before it went down",
                record.pid
            ),
        }
    }
}

fn by(who: Option<&str>) -> String {
    who.map_or_else(String::new, |w| format!(" by {w}"))
}

fn because(reason: Option<&str>) -> String {
    reason.map_or_else(String::new, |r| format!(": {r}"))
}

/// One file of the agent's service unit, as read from disk.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnitEntry {
    /// A link to `/dev/null`: the unit is masked.
    Masked,
    /// A regular file, by the SHA-256 of its content.
    File(String),
    /// A link elsewhere, by its target.
    Link(String),
}

/// The files that define the agent's units, by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitFingerprint {
    entries: BTreeMap<String, UnitEntry>,
}

impl UnitFingerprint {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: impl Into<String>, entry: UnitEntry) {
        self.entries.insert(path.into(), entry);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The paths masking a unit.
    pub fn masks(&self) -> impl Iterator<Item = &str> {
        self.entries
            .iter()
            .filter(|(_, e)| **e == UnitEntry::Masked)
            .map(|(p, _)| p.as_str())
    }

    /// What changed from `baseline` to `self`, or nothing.
    #[must_use]
    pub fn compare(&self, baseline: &Self) -> Option<UnitTamper> {
        let mut tamper = UnitTamper::default();
        for (path, entry) in &self.entries {
            match baseline.entries.get(path) {
                None if *entry == UnitEntry::Masked => tamper.masked.push(path.clone()),
                None => tamper.added.push(path.clone()),
                Some(before) if before == entry => {}
                Some(_) if *entry == UnitEntry::Masked => tamper.masked.push(path.clone()),
                Some(_) => tamper.changed.push(path.clone()),
            }
        }
        for path in baseline.entries.keys() {
            if !self.entries.contains_key(path) {
                tamper.removed.push(path.clone());
            }
        }
        (!tamper.is_empty()).then_some(tamper)
    }
}

/// How the agent's unit files differ from what they were.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitTamper {
    pub masked: Vec<String>,
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub removed: Vec<String>,
}

impl UnitTamper {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.masked.is_empty()
            && self.added.is_empty()
            && self.changed.is_empty()
            && self.removed.is_empty()
    }

    /// The rule this difference is raised under: a mask outranks an edit.
    #[must_use]
    pub fn rule_id(&self) -> &'static str {
        if self.masked.is_empty() {
            RULE_UNIT_CHANGED
        } else {
            RULE_UNIT_MASKED
        }
    }

    /// One sentence listing what differs.
    #[must_use]
    pub fn message(&self) -> String {
        let mut parts = Vec::new();
        for (label, paths) in [
            ("masked", &self.masked),
            ("added", &self.added),
            ("changed", &self.changed),
            ("removed", &self.removed),
        ] {
            if !paths.is_empty() {
                parts.push(format!("{label} {}", paths.join(", ")));
            }
        }
        if self.masked.is_empty() {
            format!(
                "the agent's service unit changed under it, and takes effect at the next start: {}",
                parts.join("; ")
            )
        } else {
            format!(
                "the agent's service unit was masked: the next stop keeps it down. {}",
                parts.join("; ")
            )
        }
    }

    /// The alert, high either way: whoever edits the unit decides whether the
    /// agent comes back.
    #[must_use]
    pub fn alert(&self, at_ns: u64) -> Alert {
        let mut alert = Alert::operational(
            AGENT_LIFECYCLE_COMPONENT,
            self.rule_id(),
            Severity::High,
            self.message(),
            at_ns,
        );
        alert.mitre_attack = Some(mitre());
        alert
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(boot: &str, ended: Option<EndCause>) -> RunRecord {
        RunRecord {
            boot_id: boot.to_string(),
            pid: 42,
            started_at: 1,
            ended: ended.map(|how| RunEnd {
                at: 2,
                how,
                requested_by: Some("ops".to_string()),
                reason: Some("upgrade".to_string()),
            }),
        }
    }

    #[test]
    fn a_commanded_stop_and_a_host_shutdown_raise_nothing() {
        let commanded = PreviousRun::judge(Some(record("b1", Some(EndCause::Command))), "b1");
        assert!(matches!(commanded, PreviousRun::Commanded(_)));
        assert!(commanded.alert(1).is_none());
        assert!(commanded.message().contains("by ops: upgrade"));
        let shutdown = PreviousRun::judge(Some(record("b0", Some(EndCause::Signal))), "b1");
        assert_eq!(shutdown, PreviousRun::HostShutdown);
        assert!(shutdown.alert(1).is_none());
        assert_eq!(PreviousRun::judge(None, "b1"), PreviousRun::Unknown);
    }

    #[test]
    fn a_failure_is_logged_and_never_raised() {
        let failed = PreviousRun::judge(Some(record("b1", Some(EndCause::Failure))), "b1");
        assert!(matches!(failed, PreviousRun::Failed(_)));
        assert!(failed.alert(1).is_none());
    }

    #[test]
    fn a_signal_on_this_boot_is_a_high_alert() {
        let signalled = PreviousRun::judge(Some(record("b1", Some(EndCause::Signal))), "b1");
        let alert = signalled.alert(1).expect("alert");
        assert_eq!(alert.rule_id.0, RULE_STOPPED_BY_SIGNAL);
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.component, AGENT_LIFECYCLE_COMPONENT);
    }

    #[test]
    fn an_unrecorded_end_is_high_on_this_boot_and_low_across_one() {
        let killed = PreviousRun::judge(Some(record("b1", None)), "b1");
        assert_eq!(killed.alert(1).expect("alert").severity, Severity::High);
        let lost = PreviousRun::judge(Some(record("b0", None)), "b1");
        let alert = lost.alert(1).expect("alert");
        assert_eq!(alert.severity, Severity::Low);
        assert_eq!(alert.rule_id.0, RULE_ENDED_UNRECORDED);
    }

    #[test]
    fn an_unknown_boot_never_counts_as_the_same_one() {
        let signalled = PreviousRun::judge(Some(record("", Some(EndCause::Signal))), "");
        assert_eq!(signalled, PreviousRun::HostShutdown);
    }

    #[test]
    fn stop_text_is_cut_and_stripped_of_control_characters() {
        assert_eq!(clean_stop_text("  up\ngrade\r "), "upgrade");
        let long = "é".repeat(MAX_STOP_TEXT);
        let cut = clean_stop_text(&long);
        assert!(cut.len() <= MAX_STOP_TEXT);
        assert!(cut.chars().all(|c| c == 'é'));
    }

    fn fingerprint(entries: &[(&str, UnitEntry)]) -> UnitFingerprint {
        let mut f = UnitFingerprint::new();
        for (p, e) in entries {
            f.insert(*p, e.clone());
        }
        f
    }

    #[test]
    fn a_mask_outranks_every_other_difference() {
        let before = fingerprint(&[("/usr/lib/a.service", UnitEntry::File("h1".into()))]);
        let after = fingerprint(&[
            ("/usr/lib/a.service", UnitEntry::File("h1".into())),
            ("/etc/a.service", UnitEntry::Masked),
            ("/etc/a.service.d/x.conf", UnitEntry::File("h2".into())),
        ]);
        let tamper = after.compare(&before).expect("tamper");
        assert_eq!(tamper.masked, vec!["/etc/a.service".to_string()]);
        assert_eq!(tamper.added, vec!["/etc/a.service.d/x.conf".to_string()]);
        assert_eq!(tamper.rule_id(), RULE_UNIT_MASKED);
        assert!(tamper.alert(1).message.contains("masked"));
    }

    #[test]
    fn an_edit_or_a_removal_is_a_change_and_nothing_is_nothing() {
        let before = fingerprint(&[
            ("/usr/lib/a.service", UnitEntry::File("h1".into())),
            ("/etc/a.service.d/x.conf", UnitEntry::File("h2".into())),
        ]);
        let after = fingerprint(&[("/usr/lib/a.service", UnitEntry::File("h3".into()))]);
        let tamper = after.compare(&before).expect("tamper");
        assert_eq!(tamper.changed, vec!["/usr/lib/a.service".to_string()]);
        assert_eq!(tamper.removed, vec!["/etc/a.service.d/x.conf".to_string()]);
        assert_eq!(tamper.rule_id(), RULE_UNIT_CHANGED);
        assert!(before.compare(&before).is_none());
    }

    #[test]
    fn a_file_replaced_by_a_mask_is_a_mask() {
        let before = fingerprint(&[("/etc/a.service", UnitEntry::File("h1".into()))]);
        let after = fingerprint(&[("/etc/a.service", UnitEntry::Masked)]);
        let tamper = after.compare(&before).expect("tamper");
        assert_eq!(tamper.masked.len(), 1);
        assert!(tamper.changed.is_empty());
    }
}
