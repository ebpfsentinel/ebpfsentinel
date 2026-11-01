//! The closed catalogue of intentions.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::error::HostRuleError;
use super::field::{self, FieldSpec};

/// What a workload does, in the product's words.
///
/// The catalogue is closed. An operator asks for one of these and nothing
/// else; the kernel hook that serves each one is the agent's business and
/// is probed on the host it runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Intent {
    /// A process executed a program.
    #[serde(rename = "process.starts")]
    ProcessStarts,
    /// A process exited.
    #[serde(rename = "process.ends")]
    ProcessEnds,
    /// A process opened a connection or sent a first datagram.
    #[serde(rename = "process.connects")]
    ProcessConnects,
    /// A process started listening on a port.
    #[serde(rename = "process.listens")]
    ProcessListens,
    /// A process asked for a name to be resolved.
    #[serde(rename = "process.resolves")]
    ProcessResolves,
    /// A process opened a TLS session as a client.
    #[serde(rename = "process.sends_tls")]
    ProcessSendsTls,
    /// A file was written to.
    #[serde(rename = "file.changes")]
    FileChanges,
    /// A file was created.
    #[serde(rename = "file.appears")]
    FileAppears,
    /// A file was removed.
    #[serde(rename = "file.disappears")]
    FileDisappears,
    /// A file's mode or owner changed.
    #[serde(rename = "file.permissions_change")]
    FilePermissionsChange,
    /// A file no longer has the digest its baseline recorded.
    #[serde(rename = "file.integrity_breaks")]
    FileIntegrityBreaks,
    /// A port is bound in the kernel and absent from what userspace lists.
    #[serde(rename = "port.hidden")]
    PortHidden,
    /// A process is known to the kernel and absent from what userspace lists.
    #[serde(rename = "process.hidden")]
    ProcessHidden,
    /// An eBPF program the agent did not load sits on the network path.
    #[serde(rename = "bpf.foreign_program")]
    BpfForeignProgram,
    /// A process opened a raw packet socket.
    #[serde(rename = "packet_socket.appears")]
    PacketSocketAppears,
    /// An installed package carrying a known vulnerability is reachable
    /// from the network.
    #[serde(rename = "package.vulnerable_reachable")]
    PackageVulnerableReachable,
}

/// Which part of the host an intention is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentFamily {
    /// What processes run and whom they talk to.
    Process,
    /// What happens to files.
    File,
    /// What the host hides from its own listings.
    Posture,
    /// What is installed and reachable.
    Surface,
}

impl Intent {
    /// Every intention, in catalogue order.
    pub const ALL: [Intent; 16] = [
        Self::ProcessStarts,
        Self::ProcessEnds,
        Self::ProcessConnects,
        Self::ProcessListens,
        Self::ProcessResolves,
        Self::ProcessSendsTls,
        Self::FileChanges,
        Self::FileAppears,
        Self::FileDisappears,
        Self::FilePermissionsChange,
        Self::FileIntegrityBreaks,
        Self::PortHidden,
        Self::ProcessHidden,
        Self::BpfForeignProgram,
        Self::PacketSocketAppears,
        Self::PackageVulnerableReachable,
    ];

    /// The name a rule writes.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessStarts => "process.starts",
            Self::ProcessEnds => "process.ends",
            Self::ProcessConnects => "process.connects",
            Self::ProcessListens => "process.listens",
            Self::ProcessResolves => "process.resolves",
            Self::ProcessSendsTls => "process.sends_tls",
            Self::FileChanges => "file.changes",
            Self::FileAppears => "file.appears",
            Self::FileDisappears => "file.disappears",
            Self::FilePermissionsChange => "file.permissions_change",
            Self::FileIntegrityBreaks => "file.integrity_breaks",
            Self::PortHidden => "port.hidden",
            Self::ProcessHidden => "process.hidden",
            Self::BpfForeignProgram => "bpf.foreign_program",
            Self::PacketSocketAppears => "packet_socket.appears",
            Self::PackageVulnerableReachable => "package.vulnerable_reachable",
        }
    }

    /// Read an intention by the name a rule writes.
    ///
    /// # Errors
    ///
    /// [`HostRuleError::UnknownIntent`] naming every intention that exists,
    /// so the refusal is also the answer.
    pub fn parse(name: &str) -> Result<Self, HostRuleError> {
        Self::ALL
            .into_iter()
            .find(|intent| intent.as_str() == name)
            .ok_or_else(|| HostRuleError::UnknownIntent {
                name: name.to_string(),
                known: Self::ALL.map(Self::as_str).join(", "),
            })
    }

    /// Which part of the host it is about.
    #[must_use]
    pub fn family(self) -> IntentFamily {
        match self {
            Self::ProcessStarts
            | Self::ProcessEnds
            | Self::ProcessConnects
            | Self::ProcessListens
            | Self::ProcessResolves
            | Self::ProcessSendsTls => IntentFamily::Process,
            Self::FileChanges
            | Self::FileAppears
            | Self::FileDisappears
            | Self::FilePermissionsChange
            | Self::FileIntegrityBreaks => IntentFamily::File,
            Self::PortHidden
            | Self::ProcessHidden
            | Self::BpfForeignProgram
            | Self::PacketSocketAppears => IntentFamily::Posture,
            Self::PackageVulnerableReachable => IntentFamily::Surface,
        }
    }

    /// The fields an event of this intention carries.
    ///
    /// The `workload` block - executable, unit, cgroup, container, pod -
    /// is not among them: it is the same selector the firewall's workload
    /// rules use, beside the intention rather than inside it, so it is
    /// learned once.
    #[must_use]
    pub fn fields(self) -> &'static [FieldSpec] {
        match self {
            Self::ProcessStarts => field::PROCESS_STARTS,
            Self::ProcessEnds => field::PROCESS_ENDS,
            Self::ProcessConnects => field::PROCESS_CONNECTS,
            Self::ProcessListens => field::PROCESS_LISTENS,
            Self::ProcessResolves => field::PROCESS_RESOLVES,
            Self::ProcessSendsTls => field::PROCESS_SENDS_TLS,
            Self::FileChanges => field::FILE_CHANGES,
            Self::FileAppears => field::FILE_APPEARS,
            Self::FileDisappears => field::FILE_DISAPPEARS,
            Self::FilePermissionsChange => field::FILE_PERMISSIONS_CHANGE,
            Self::FileIntegrityBreaks => field::FILE_INTEGRITY_BREAKS,
            Self::PortHidden => field::PORT_HIDDEN,
            Self::ProcessHidden => field::PROCESS_HIDDEN,
            Self::BpfForeignProgram => field::BPF_FOREIGN_PROGRAM,
            Self::PacketSocketAppears => field::PACKET_SOCKET_APPEARS,
            Self::PackageVulnerableReachable => field::PACKAGE_VULNERABLE_REACHABLE,
        }
    }

    /// One field by name.
    ///
    /// # Errors
    ///
    /// [`HostRuleError::UnknownField`] naming the fields the intention does
    /// carry.
    pub fn field(self, name: &str) -> Result<&'static FieldSpec, HostRuleError> {
        self.fields()
            .iter()
            .find(|spec| spec.name == name)
            .ok_or_else(|| HostRuleError::UnknownField {
                intent: self.as_str(),
                field: name.to_string(),
                known: self
                    .fields()
                    .iter()
                    .map(|spec| spec.name)
                    .collect::<Vec<_>>()
                    .join(", "),
            })
    }
}

impl fmt::Display for Intent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Intent {
    type Err = HostRuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::hostrule::field::{FieldType, MATCHER_SUFFIXES, RESERVED_KEYS};

    #[test]
    fn every_intent_round_trips_through_its_name() {
        for intent in Intent::ALL {
            assert_eq!(Intent::parse(intent.as_str()), Ok(intent));
            let json = serde_json::to_string(&intent).unwrap();
            assert_eq!(json, format!("\"{}\"", intent.as_str()));
            assert_eq!(serde_json::from_str::<Intent>(&json).unwrap(), intent);
        }
    }

    #[test]
    fn the_catalogue_has_no_duplicate_name() {
        let names: HashSet<_> = Intent::ALL.iter().map(|i| i.as_str()).collect();
        assert_eq!(names.len(), Intent::ALL.len());
    }

    #[test]
    fn the_name_prefix_is_the_subject_and_the_family_follows_from_it() {
        for intent in Intent::ALL {
            let subject = intent.as_str().split('.').next().unwrap();
            let expected = match subject {
                "file" => IntentFamily::File,
                "package" => IntentFamily::Surface,
                "port" | "bpf" | "packet_socket" => IntentFamily::Posture,
                "process" if intent == Intent::ProcessHidden => IntentFamily::Posture,
                "process" => IntentFamily::Process,
                other => panic!("subject {other} has no family"),
            };
            assert_eq!(intent.family(), expected, "{intent}");
        }
    }

    #[test]
    fn an_unknown_intent_is_refused_with_the_list_of_those_that_exist() {
        let err = Intent::parse("execve").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("unknown intent `execve`"), "{message}");
        for intent in Intent::ALL {
            assert!(message.contains(intent.as_str()), "{message}");
        }
        assert!(serde_json::from_str::<Intent>("\"sys_enter_openat\"").is_err());
    }

    #[test]
    fn every_intent_carries_fields_with_unique_names() {
        for intent in Intent::ALL {
            assert!(!intent.fields().is_empty(), "{intent}");
            let names: HashSet<_> = intent.fields().iter().map(|f| f.name).collect();
            assert_eq!(names.len(), intent.fields().len(), "{intent}");
        }
    }

    #[test]
    fn no_field_takes_a_reserved_key_or_ends_with_a_matcher_suffix() {
        for intent in Intent::ALL {
            for spec in intent.fields() {
                assert!(
                    !RESERVED_KEYS.contains(&spec.name),
                    "{intent}.{}",
                    spec.name
                );
                for suffix in MATCHER_SUFFIXES {
                    assert!(
                        !spec.name.ends_with(suffix),
                        "{intent}.{} ends with {suffix}",
                        spec.name
                    );
                }
                assert!(
                    spec.name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                        && spec.name.starts_with(|c: char| c.is_ascii_lowercase()),
                    "{intent}.{}",
                    spec.name
                );
                assert!(!spec.doc.is_empty());
            }
        }
    }

    #[test]
    fn a_field_shared_between_intents_has_one_type_everywhere() {
        let mut seen: std::collections::HashMap<&str, FieldType> = std::collections::HashMap::new();
        for intent in Intent::ALL {
            for spec in intent.fields() {
                let previous = *seen.entry(spec.name).or_insert(spec.ty);
                assert_eq!(
                    previous, spec.ty,
                    "`{}` changes type at {intent}",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn a_system_account_is_expressible_on_every_process_intent() {
        for intent in Intent::ALL
            .into_iter()
            .filter(|i| i.family() == IntentFamily::Process)
        {
            assert!(intent.field("uid").unwrap().ty.is_numeric(), "{intent}");
            assert_eq!(intent.field("exe").unwrap().ty, FieldType::Path, "{intent}");
        }
    }

    #[test]
    fn an_unknown_field_is_refused_with_the_fields_that_exist() {
        let message = Intent::FileChanges.field("inode").unwrap_err().to_string();
        assert!(
            message.contains("`file.changes` has no field `inode`"),
            "{message}"
        );
        assert!(message.contains("path, extension, exe, uid"), "{message}");
    }
}
