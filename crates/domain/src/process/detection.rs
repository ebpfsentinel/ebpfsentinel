//! Three detections read off the process tree where it touches the network.
//!
//! Each one is a question about a process that holds a connection, answered
//! from what the table already knows about it and its ancestors plus two facts
//! only the running process can give: whether its standard streams are an
//! internet socket, and whether the file it runs still exists.
//!
//! - A **reverse shell** is a shell or an interpreter whose standard input or
//!   output is an internet socket, or which connects out with a server process
//!   among its ancestors. Either way somebody is typing into it from the
//!   network.
//! - A **binary with no file** is a process holding a connection while running
//!   an image that was never on disk (`memfd:`) or has been removed since it
//!   started. Nothing an operator can hash, scan or reinstall is behind it.
//! - An **unexpected descendant of a server** is a process a server started,
//!   directly or not, that connects out and is neither the server itself nor a
//!   program the operator listed as expected there.
//!
//! The lists are names, compared the way an operator writes them: an entry
//! carrying a `/` is a full path, any other entry is a file name, and a
//! trailing `*` makes either a prefix. The defaults are the common shells,
//! interpreters and web servers; a server whose workers are scripts the
//! operator expects belongs in `expected` rather than in an exception.

use serde::{Deserialize, Serialize};

use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;
use crate::workload::entity::Workload;

/// The component every alert raised here answers to.
pub const PROCESS_DETECTION_COMPONENT: &str = "process";

/// The shells and interpreters a reverse shell is made of.
pub const DEFAULT_INTERPRETERS: [&str; 14] = [
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "ash",
    "busybox",
    "python*",
    "perl*",
    "ruby*",
    "php",
    "php[0-9]*",
    "node",
    "lua*",
];

/// The servers whose descendants are expected to answer rather than to dial.
pub const DEFAULT_SERVERS: [&str; 7] = [
    "nginx", "apache2", "httpd", "php-fpm*", "lighttpd", "caddy", "uwsgi",
];

/// One of the three detections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessDetectionKind {
    ReverseShell,
    Fileless,
    ServerDescendant,
}

impl ProcessDetectionKind {
    /// Every detection, in the order a process is tested against them.
    pub const ALL: [Self; 3] = [Self::Fileless, Self::ReverseShell, Self::ServerDescendant];

    /// The rule id an alert carries, which is what a route or a response
    /// policy filters on.
    #[must_use]
    pub fn rule_id(self) -> RuleId {
        RuleId(
            match self {
                Self::ReverseShell => "process-reverse-shell",
                Self::Fileless => "process-fileless",
                Self::ServerDescendant => "process-server-descendant",
            }
            .to_string(),
        )
    }

    /// The ATT&CK technique each detection is evidence of.
    #[must_use]
    pub fn mitre(self) -> MitreAttackInfo {
        let (id, name, tactic) = match self {
            Self::ReverseShell => ("T1059", "Command and Scripting Interpreter", "execution"),
            Self::Fileless => ("T1620", "Reflective Code Loading", "defense-evasion"),
            Self::ServerDescendant => (
                "T1190",
                "Exploit Public-Facing Application",
                "initial-access",
            ),
        };
        MitreAttackInfo {
            technique_id: id.to_string(),
            technique_name: name.to_string(),
            tactic: tactic.to_string(),
        }
    }
}

/// What only the running process can say about itself, read when it is
/// tested.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessFacts {
    /// Standard input or standard output is an internet socket.
    pub streams_on_socket: bool,
    /// The image it runs is a `memfd:` file or has been removed.
    pub fileless: bool,
}

/// A detection that fired, with the sentence the alert carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessDetection {
    pub kind: ProcessDetectionKind,
    pub message: String,
}

/// The lists the three detections read, already validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessDetectionPolicy {
    pub reverse_shell: bool,
    pub fileless: bool,
    pub server_descendant: bool,
    pub interpreters: Vec<String>,
    pub servers: Vec<String>,
    pub expected: Vec<String>,
}

impl Default for ProcessDetectionPolicy {
    fn default() -> Self {
        Self {
            reverse_shell: true,
            fileless: true,
            server_descendant: true,
            interpreters: DEFAULT_INTERPRETERS
                .iter()
                .map(ToString::to_string)
                .collect(),
            servers: DEFAULT_SERVERS.iter().map(ToString::to_string).collect(),
            expected: Vec::new(),
        }
    }
}

impl ProcessDetectionPolicy {
    /// Whether `exe` is one of the shells or interpreters listed.
    #[must_use]
    pub fn is_interpreter(&self, exe: &str) -> bool {
        listed(&self.interpreters, exe)
    }

    /// Test a process holding a connection, the most specific detection
    /// first: a binary with no file is reported as that even when it is also
    /// a shell, and a shell under a server as a reverse shell rather than as
    /// a descendant.
    #[must_use]
    pub fn evaluate(&self, workload: &Workload, facts: ProcessFacts) -> Option<ProcessDetection> {
        let exe = workload.exe.as_deref();
        let shown = exe.unwrap_or("an unnamed executable");
        if self.fileless && facts.fileless {
            return Some(ProcessDetection {
                kind: ProcessDetectionKind::Fileless,
                message: format!(
                    "pid {} holds a connection while running {shown}, a file that is not on disk",
                    workload.pid
                ),
            });
        }
        let exe = exe?;
        // A server's own workers run the server's file; they are the server.
        if listed(&self.servers, exe) {
            return None;
        }
        let server = self.server_ancestor(workload);
        if self.reverse_shell && self.is_interpreter(exe) {
            if facts.streams_on_socket {
                return Some(ProcessDetection {
                    kind: ProcessDetectionKind::ReverseShell,
                    message: format!(
                        "pid {} runs {exe} with its standard streams on a network socket",
                        workload.pid
                    ),
                });
            }
            if let Some(server) = server {
                return Some(ProcessDetection {
                    kind: ProcessDetectionKind::ReverseShell,
                    message: format!(
                        "pid {} runs {exe} under the server {server} and connects out",
                        workload.pid
                    ),
                });
            }
        }
        if self.server_descendant
            && let Some(server) = server
            && !listed(&self.expected, exe)
        {
            return Some(ProcessDetection {
                kind: ProcessDetectionKind::ServerDescendant,
                message: format!(
                    "pid {} runs {exe}, started under the server {server}, and connects out",
                    workload.pid
                ),
            });
        }
        None
    }

    /// The closest ancestor that is a listed server, as its executable.
    fn server_ancestor<'a>(&self, workload: &'a Workload) -> Option<&'a str> {
        workload
            .ancestry
            .as_ref()?
            .ancestors
            .iter()
            .filter_map(|a| a.exe.as_deref())
            .find(|exe| listed(&self.servers, exe))
    }
}

/// Whether `exe` is named by one of `entries`.
fn listed(entries: &[String], exe: &str) -> bool {
    let name = exe.rsplit('/').next().unwrap_or(exe);
    entries.iter().any(|entry| {
        let subject = if entry.contains('/') { exe } else { name };
        matches(entry, subject)
    })
}

/// A name or a path, with `[0-9]` standing for one digit and a trailing `*`
/// for anything.
fn matches(pattern: &str, subject: &str) -> bool {
    let (pattern, prefix) = match pattern.strip_suffix('*') {
        Some(head) => (head, true),
        None => (pattern, false),
    };
    let mut rest = subject;
    let mut pattern = pattern;
    while !pattern.is_empty() {
        if let Some(after) = pattern.strip_prefix("[0-9]") {
            let mut chars = rest.chars();
            if !chars.next().is_some_and(|c| c.is_ascii_digit()) {
                return false;
            }
            rest = chars.as_str();
            pattern = after;
            continue;
        }
        let mut chars = pattern.chars();
        let Some(expected) = chars.next() else { break };
        let mut got = rest.chars();
        if got.next() != Some(expected) {
            return false;
        }
        rest = got.as_str();
        pattern = chars.as_str();
    }
    prefix || rest.is_empty()
}

/// Why a list entry cannot be used, for the configuration to refuse it.
///
/// # Errors
///
/// An empty entry, or a `*` anywhere but at the end.
pub fn validate_entry(entry: &str) -> Result<(), String> {
    if entry.trim().is_empty() {
        return Err("an entry is empty".to_string());
    }
    let head = entry.strip_suffix('*').unwrap_or(entry);
    if head.contains('*') {
        return Err(format!(
            "`{entry}`: a `*` is allowed only at the end, as a prefix"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::entity::{WorkloadAncestor, WorkloadAncestry, WorkloadSource};

    fn ancestor(pid: u32, exe: &str) -> WorkloadAncestor {
        WorkloadAncestor {
            pid,
            exe: Some(exe.to_string()),
            name: exe.rsplit('/').next().unwrap_or(exe).to_string(),
            uid: 33,
            start_ns: None,
            exited: false,
        }
    }

    fn workload(exe: &str, ancestors: &[&str]) -> Workload {
        let mut w = Workload::new(4242, WorkloadSource::Socket).expect("pid is not zero");
        w.exe = Some(exe.to_string());
        if !ancestors.is_empty() {
            w.ancestry = Some(WorkloadAncestry {
                ancestors: ancestors
                    .iter()
                    .enumerate()
                    .map(|(i, exe)| ancestor(100 + u32::try_from(i).unwrap_or(0), exe))
                    .collect(),
                truncated: false,
                incomplete: false,
            });
        }
        w
    }

    const NONE: ProcessFacts = ProcessFacts {
        streams_on_socket: false,
        fileless: false,
    };

    fn kind(w: &Workload, facts: ProcessFacts) -> Option<ProcessDetectionKind> {
        ProcessDetectionPolicy::default()
            .evaluate(w, facts)
            .map(|d| d.kind)
    }

    #[test]
    fn a_shell_whose_streams_are_a_socket_is_a_reverse_shell() {
        let w = workload("/usr/bin/bash", &["/usr/sbin/sshd"]);
        let facts = ProcessFacts {
            streams_on_socket: true,
            ..NONE
        };
        assert_eq!(kind(&w, facts), Some(ProcessDetectionKind::ReverseShell));
        assert_eq!(kind(&w, NONE), None);
    }

    #[test]
    fn an_interpreter_connecting_out_under_a_server_is_a_reverse_shell() {
        let w = workload(
            "/usr/bin/python3.12",
            &["/usr/sbin/nginx", "/usr/lib/systemd/systemd"],
        );
        let hit = ProcessDetectionPolicy::default()
            .evaluate(&w, NONE)
            .expect("fires");
        assert_eq!(hit.kind, ProcessDetectionKind::ReverseShell);
        assert!(hit.message.contains("/usr/sbin/nginx"), "{}", hit.message);
    }

    #[test]
    fn a_program_under_a_server_is_a_descendant_unless_it_is_expected() {
        let w = workload("/usr/bin/curl", &["/usr/sbin/php-fpm8.3"]);
        assert_eq!(kind(&w, NONE), Some(ProcessDetectionKind::ServerDescendant));
        let policy = ProcessDetectionPolicy {
            expected: vec!["curl".to_string()],
            ..ProcessDetectionPolicy::default()
        };
        assert_eq!(policy.evaluate(&w, NONE), None);
    }

    #[test]
    fn a_server_worker_is_the_server() {
        let w = workload("/usr/sbin/nginx", &["/usr/sbin/nginx"]);
        assert_eq!(kind(&w, NONE), None);
    }

    #[test]
    fn a_binary_with_no_file_wins_over_everything_else() {
        let w = workload("/memfd:payload", &["/usr/sbin/nginx"]);
        let facts = ProcessFacts {
            streams_on_socket: true,
            fileless: true,
        };
        assert_eq!(kind(&w, facts), Some(ProcessDetectionKind::Fileless));
    }

    #[test]
    fn a_switched_off_detection_stays_silent() {
        let policy = ProcessDetectionPolicy {
            fileless: false,
            reverse_shell: false,
            ..ProcessDetectionPolicy::default()
        };
        let facts = ProcessFacts {
            streams_on_socket: true,
            fileless: true,
        };
        assert_eq!(
            policy.evaluate(&workload("/usr/bin/bash", &[]), facts),
            None
        );
        // A shell under a server still answers as a descendant.
        assert_eq!(
            policy
                .evaluate(&workload("/usr/bin/bash", &["/usr/sbin/httpd"]), NONE)
                .map(|d| d.kind),
            Some(ProcessDetectionKind::ServerDescendant)
        );
    }

    #[test]
    fn nothing_fires_away_from_a_server_and_off_a_socket() {
        assert_eq!(
            kind(&workload("/usr/bin/python3", &["/usr/bin/bash"]), NONE),
            None
        );
        assert_eq!(kind(&workload("/usr/bin/curl", &[]), NONE), None);
    }

    #[test]
    fn an_entry_is_a_name_a_path_or_a_prefix() {
        let entries = |e: &[&str]| e.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(listed(&entries(&["bash"]), "/usr/bin/bash"));
        assert!(!listed(&entries(&["bash"]), "/usr/bin/bashful"));
        assert!(listed(&entries(&["python*"]), "/usr/bin/python3.12"));
        assert!(listed(&entries(&["php[0-9]*"]), "/usr/bin/php8.3"));
        assert!(!listed(&entries(&["php[0-9]*"]), "/usr/sbin/php-fpm8.3"));
        assert!(listed(&entries(&["/opt/app/bin/*"]), "/opt/app/bin/worker"));
        assert!(!listed(&entries(&["/opt/app/bin/*"]), "/usr/bin/worker"));
    }

    #[test]
    fn an_entry_with_a_star_inside_is_refused() {
        assert!(validate_entry("py*thon").is_err());
        assert!(validate_entry(" ").is_err());
        assert!(validate_entry("python*").is_ok());
    }

    #[test]
    fn each_detection_names_its_rule_and_technique() {
        for kind in ProcessDetectionKind::ALL {
            assert!(kind.rule_id().0.starts_with("process-"));
            assert!(kind.mitre().technique_id.starts_with('T'));
        }
    }
}
