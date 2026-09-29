//! What an operator has done with an alert, kept beside it rather than in it.
//!
//! An alert is what the datapath saw and never changes after it was raised;
//! the triage is what a person decided about it afterwards. Keeping the two
//! apart means a detection is never rewritten by the queue, and an alert
//! nobody has touched carries no triage at all.

use serde::{Deserialize, Serialize};

use super::error::AlertError;

/// Longest assignee name accepted.
pub const MAX_ASSIGNEE_LEN: usize = 128;
/// Longest note accepted, in characters.
pub const MAX_NOTE_LEN: usize = 4096;
/// Most notes one alert keeps; past it the alert refuses another rather
/// than dropping the oldest, because a thread losing its start is a thread
/// nobody can follow.
pub const MAX_NOTES: usize = 200;
/// Most alerts one bulk change may name.
pub const MAX_BULK: usize = 1000;

/// Where an alert stands in the queue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    /// Nobody has looked at it yet.
    #[default]
    Open,
    /// Somebody has seen it and owns the next step.
    Acknowledged,
    /// Somebody is working it.
    Investigating,
    /// Nothing more is expected of anybody.
    Resolved,
}

impl AlertStatus {
    /// The word the API writes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Investigating => "investigating",
            Self::Resolved => "resolved",
        }
    }

    /// Read the API's word back, case-insensitively.
    pub fn parse(word: &str) -> Option<Self> {
        match word.to_ascii_lowercase().as_str() {
            "open" => Some(Self::Open),
            "acknowledged" => Some(Self::Acknowledged),
            "investigating" => Some(Self::Investigating),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }
}

/// One line somebody wrote on an alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertNote {
    /// Who the caller said wrote it.
    pub author: String,
    /// The identity the agent authenticated the write under, which can
    /// differ from `author` when a console writes on a person's behalf.
    pub via: String,
    /// When it was written, nanoseconds since epoch.
    pub at_ns: u64,
    /// What was written.
    pub text: String,
}

/// Everything an operator decided about one alert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertTriage {
    #[serde(default)]
    pub status: AlertStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<AlertNote>,
    /// When it last changed, nanoseconds since epoch; zero when untouched.
    #[serde(default)]
    pub updated_ns: u64,
}

/// What a change does to who holds an alert.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AssigneeChange {
    /// Leave it with whoever holds it.
    #[default]
    Keep,
    /// Take it off whoever holds it.
    Clear,
    /// Hand it to somebody.
    Set(String),
}

/// A change somebody asked for. Every field left out stays as it was.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TriageChange {
    pub status: Option<AlertStatus>,
    pub assignee: AssigneeChange,
    pub note: Option<AlertNote>,
}

impl TriageChange {
    /// A change that changes nothing is refused rather than recorded,
    /// because it would move `updated_ns` for no reason.
    pub fn is_empty(&self) -> bool {
        self.status.is_none() && self.assignee == AssigneeChange::Keep && self.note.is_none()
    }

    /// Refuse what the store must never hold.
    pub fn validate(&self) -> Result<(), AlertError> {
        if self.is_empty() {
            return Err(AlertError::InvalidTriage("nothing to change".to_string()));
        }
        if let AssigneeChange::Set(name) = &self.assignee {
            let name = name.trim();
            if name.is_empty() {
                return Err(AlertError::InvalidTriage(
                    "assignee is empty; send null to unassign".to_string(),
                ));
            }
            if name.chars().count() > MAX_ASSIGNEE_LEN {
                return Err(AlertError::InvalidTriage(format!(
                    "assignee is longer than {MAX_ASSIGNEE_LEN} characters"
                )));
            }
        }
        if let Some(note) = &self.note {
            let len = note.text.trim().chars().count();
            if len == 0 {
                return Err(AlertError::InvalidTriage("note is empty".to_string()));
            }
            if len > MAX_NOTE_LEN {
                return Err(AlertError::InvalidTriage(format!(
                    "note is longer than {MAX_NOTE_LEN} characters"
                )));
            }
        }
        Ok(())
    }
}

impl AlertTriage {
    /// True for an alert nobody has done anything with.
    pub fn is_untouched(&self) -> bool {
        self.updated_ns == 0
    }

    /// Apply a validated change at `now_ns`.
    pub fn apply(&mut self, change: &TriageChange, now_ns: u64) -> Result<(), AlertError> {
        change.validate()?;
        if change.note.is_some() && self.notes.len() >= MAX_NOTES {
            return Err(AlertError::InvalidTriage(format!(
                "alert already carries {MAX_NOTES} notes"
            )));
        }
        if let Some(status) = change.status {
            self.status = status;
        }
        match &change.assignee {
            AssigneeChange::Keep => {}
            AssigneeChange::Clear => self.assignee = None,
            AssigneeChange::Set(name) => self.assignee = Some(name.trim().to_string()),
        }
        if let Some(note) = &change.note {
            let mut note = note.clone();
            note.text = note.text.trim().to_string();
            note.at_ns = now_ns;
            self.notes.push(note);
        }
        self.updated_ns = now_ns;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(text: &str) -> AlertNote {
        AlertNote {
            author: "alice".to_string(),
            via: "dashboard".to_string(),
            at_ns: 0,
            text: text.to_string(),
        }
    }

    #[test]
    fn default_is_open_and_untouched() {
        let t = AlertTriage::default();
        assert_eq!(t.status, AlertStatus::Open);
        assert!(t.is_untouched());
    }

    #[test]
    fn status_words_round_trip() {
        for s in [
            AlertStatus::Open,
            AlertStatus::Acknowledged,
            AlertStatus::Investigating,
            AlertStatus::Resolved,
        ] {
            assert_eq!(AlertStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(AlertStatus::parse("RESOLVED"), Some(AlertStatus::Resolved));
        assert_eq!(AlertStatus::parse("closed"), None);
    }

    #[test]
    fn apply_sets_status_assignee_and_stamps_the_note() {
        let mut t = AlertTriage::default();
        let change = TriageChange {
            status: Some(AlertStatus::Investigating),
            assignee: AssigneeChange::Set("  bob ".to_string()),
            note: Some(note("  looking at it ")),
        };
        t.apply(&change, 42).unwrap();
        assert_eq!(t.status, AlertStatus::Investigating);
        assert_eq!(t.assignee.as_deref(), Some("bob"));
        assert_eq!(t.notes.len(), 1);
        assert_eq!(t.notes[0].text, "looking at it");
        assert_eq!(t.notes[0].at_ns, 42);
        assert_eq!(t.updated_ns, 42);
    }

    #[test]
    fn null_assignee_unassigns_and_absent_keeps() {
        let mut t = AlertTriage {
            assignee: Some("bob".to_string()),
            ..AlertTriage::default()
        };
        t.apply(
            &TriageChange {
                status: Some(AlertStatus::Acknowledged),
                ..TriageChange::default()
            },
            1,
        )
        .unwrap();
        assert_eq!(t.assignee.as_deref(), Some("bob"));
        t.apply(
            &TriageChange {
                assignee: AssigneeChange::Clear,
                ..TriageChange::default()
            },
            2,
        )
        .unwrap();
        assert_eq!(t.assignee, None);
    }

    #[test]
    fn refuses_empty_change_blank_note_and_long_values() {
        let mut t = AlertTriage::default();
        assert!(t.apply(&TriageChange::default(), 1).is_err());
        assert!(
            t.apply(
                &TriageChange {
                    note: Some(note("   ")),
                    ..TriageChange::default()
                },
                1
            )
            .is_err()
        );
        assert!(
            t.apply(
                &TriageChange {
                    assignee: AssigneeChange::Set("x".repeat(MAX_ASSIGNEE_LEN + 1)),
                    ..TriageChange::default()
                },
                1
            )
            .is_err()
        );
        assert!(
            t.apply(
                &TriageChange {
                    note: Some(note(&"y".repeat(MAX_NOTE_LEN + 1))),
                    ..TriageChange::default()
                },
                1
            )
            .is_err()
        );
        assert!(t.is_untouched());
    }

    #[test]
    fn refuses_a_note_past_the_ceiling() {
        let mut t = AlertTriage::default();
        for i in 0..MAX_NOTES {
            t.apply(
                &TriageChange {
                    note: Some(note("n")),
                    ..TriageChange::default()
                },
                i as u64 + 1,
            )
            .unwrap();
        }
        assert!(
            t.apply(
                &TriageChange {
                    note: Some(note("one more")),
                    ..TriageChange::default()
                },
                9_999
            )
            .is_err()
        );
        assert_eq!(t.notes.len(), MAX_NOTES);
    }
}
