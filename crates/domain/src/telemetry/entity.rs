//! What one installation says about itself, and nothing else.
//!
//! The shape here is the whole of the wire format. It carries three things: a
//! random name for the installation, the agent version, and which eBPF programs
//! are loaded. There is deliberately no map, no free-text field and no
//! `serde_json::Value` anywhere in it, so there is no field a rule, an address,
//! an interface name, a hostname or a line of configuration could travel in
//! even by accident. Widening it means editing this file, which is where the
//! decision belongs.

use serde::{Deserialize, Serialize};

use super::error::TelemetryError;

/// How many hex characters an installation identifier carries.
///
/// Sixteen random bytes: enough that two installations will not collide, small
/// enough to read out of a log line.
pub const INSTALLATION_ID_CHARS: usize = 32;

/// The longest version string the beat will carry.
///
/// A version comes from this build rather than from a config file, so the bound
/// is a guard against a broken build rather than against a hostile one.
pub const MAX_VERSION_CHARS: usize = 64;

/// The most programs one beat reports.
///
/// The agent carries a fixed set, so anything past this is a bug upstream and
/// the beat is refused rather than sent.
pub const MAX_PROGRAMS: usize = 64;

/// The random name one installation answers to.
///
/// Random rather than derived: nothing about the machine goes into it, so it
/// cannot be reversed into a hostname, a MAC address or a network. It exists
/// only so that counting beats counts installations rather than requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InstallationId(String);

impl InstallationId {
    /// Accepts an identifier read back from disk.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Malformed`] when the value is not exactly
    /// [`INSTALLATION_ID_CHARS`] lowercase hex characters. A file somebody
    /// edited by hand is refused rather than sent, because an identifier with a
    /// name in it would be the one piece of this beat that identified a person.
    pub fn parse(raw: &str) -> Result<Self, TelemetryError> {
        let trimmed = raw.trim();

        if trimmed.chars().count() != INSTALLATION_ID_CHARS {
            return Err(TelemetryError::Malformed(format!(
                "expected {INSTALLATION_ID_CHARS} characters, found {}",
                trimmed.chars().count()
            )));
        }

        if !trimmed
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        {
            return Err(TelemetryError::Malformed(
                "expected lowercase hex only".to_string(),
            ));
        }

        Ok(Self(trimmed.to_string()))
    }

    /// Builds an identifier from sixteen random bytes.
    ///
    /// The bytes come from the adapter, because the domain has no business
    /// opening `/dev/urandom`, and their quality is that adapter's problem.
    #[must_use]
    pub fn from_bytes(bytes: [u8; INSTALLATION_ID_CHARS / 2]) -> Self {
        let mut hex = String::with_capacity(INSTALLATION_ID_CHARS);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        Self(hex)
    }

    /// The identifier as it goes on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether one eBPF program is running.
///
/// Two states rather than three: the agent counts programs it could not attach
/// after loading, but it counts them as a total rather than per program, so
/// there is nothing here to fill an `AttachBlocked` variant with and inventing
/// one would report a fact this build does not measure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramState {
    /// The program loaded and attached.
    Loaded,
    /// The program is switched off, or it failed to load.
    NotLoaded,
}

impl ProgramState {
    /// The word this state goes on the wire as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::NotLoaded => "not_loaded",
        }
    }
}

impl From<bool> for ProgramState {
    fn from(loaded: bool) -> Self {
        if loaded {
            Self::Loaded
        } else {
            Self::NotLoaded
        }
    }
}

/// One program and whether it is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramReport {
    /// The program's name, out of the fixed set this build carries.
    pub program: String,
    /// Whether it is loaded.
    pub state: ProgramState,
}

/// One beat.
///
/// Everything an installation ever sends. Built through [`Heartbeat::new`] so
/// the bounds are enforced before a request exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// The installation this beat is from.
    pub installation_id: InstallationId,
    /// The agent version that sent it.
    pub version: String,
    /// Every program this build carries, with its state.
    ///
    /// Ordered by name, so two beats from one installation differ only where
    /// something actually changed.
    pub programs: Vec<ProgramReport>,
}

impl Heartbeat {
    /// Assembles one beat.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Malformed`] when the version is empty, longer
    /// than [`MAX_VERSION_CHARS`], or carries a control character, and when
    /// there are more than [`MAX_PROGRAMS`] of them. All three are faults in
    /// this build rather than in the network, and are worth refusing on the
    /// machine rather than posting.
    pub fn new(
        installation_id: InstallationId,
        version: &str,
        mut programs: Vec<ProgramReport>,
    ) -> Result<Self, TelemetryError> {
        let version = version.trim();

        if version.is_empty() {
            return Err(TelemetryError::Malformed(
                "the agent version is empty".to_string(),
            ));
        }

        if version.chars().count() > MAX_VERSION_CHARS {
            return Err(TelemetryError::Malformed(format!(
                "the agent version is longer than {MAX_VERSION_CHARS} characters"
            )));
        }

        if version.chars().any(char::is_control) {
            return Err(TelemetryError::Malformed(
                "the agent version carries a control character".to_string(),
            ));
        }

        if programs.len() > MAX_PROGRAMS {
            return Err(TelemetryError::Malformed(format!(
                "more than {MAX_PROGRAMS} programs were reported"
            )));
        }

        programs.sort_by(|a, b| a.program.cmp(&b.program));

        Ok(Self {
            installation_id,
            version: version.to_string(),
            programs,
        })
    }

    /// How many of the reported programs are loaded.
    #[must_use]
    pub fn loaded_count(&self) -> usize {
        self.programs
            .iter()
            .filter(|p| p.state == ProgramState::Loaded)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an_id() -> InstallationId {
        InstallationId::from_bytes([0xab; 16])
    }

    #[test]
    fn sixteen_bytes_become_thirty_two_lowercase_hex_characters() {
        let id = an_id();
        assert_eq!(id.as_str().len(), INSTALLATION_ID_CHARS);
        assert_eq!(id.as_str(), "abababababababababababababababab");
        assert_eq!(InstallationId::parse(id.as_str()).expect("parsed"), id);
    }

    #[test]
    fn an_identifier_somebody_edited_by_hand_is_refused() {
        // The case that matters: a file with a machine name in it would be the
        // one part of this beat that identified anybody.
        assert!(InstallationId::parse("prod-gateway-01").is_err());
        assert!(InstallationId::parse("").is_err());
        assert!(InstallationId::parse("ABABABABABABABABABABABABABABABAB").is_err());
        assert!(InstallationId::parse("abababababababababababababababa").is_err());
    }

    #[test]
    fn programs_are_ordered_so_two_beats_differ_only_where_something_changed() {
        let beat = Heartbeat::new(
            an_id(),
            "1.2.3",
            vec![
                ProgramReport {
                    program: "tc_ids".into(),
                    state: ProgramState::Loaded,
                },
                ProgramReport {
                    program: "xdp_firewall".into(),
                    state: ProgramState::Loaded,
                },
                ProgramReport {
                    program: "tc_dns".into(),
                    state: ProgramState::NotLoaded,
                },
            ],
        )
        .expect("built");

        let names: Vec<&str> = beat.programs.iter().map(|p| p.program.as_str()).collect();
        assert_eq!(names, ["tc_dns", "tc_ids", "xdp_firewall"]);
        assert_eq!(beat.loaded_count(), 2);
    }

    #[test]
    fn a_version_this_build_could_not_have_produced_is_refused() {
        assert!(Heartbeat::new(an_id(), "", vec![]).is_err());
        assert!(Heartbeat::new(an_id(), "1.0\n0", vec![]).is_err());
        assert!(Heartbeat::new(an_id(), &"9".repeat(MAX_VERSION_CHARS + 1), vec![]).is_err());
    }

    #[test]
    fn more_programs_than_this_build_carries_is_refused_rather_than_sent() {
        let programs: Vec<ProgramReport> = (0..=MAX_PROGRAMS)
            .map(|n| ProgramReport {
                program: format!("p{n}"),
                state: ProgramState::Loaded,
            })
            .collect();
        assert!(Heartbeat::new(an_id(), "1.2.3", programs).is_err());
    }

    #[test]
    fn the_wire_shape_carries_three_keys_and_no_fourth() {
        // This is the privacy fence, asserted rather than described: the body
        // that leaves the machine has exactly these keys, so a field added
        // upstream fails here before it reaches anybody's endpoint.
        let beat = Heartbeat::new(
            an_id(),
            "1.2.3",
            vec![ProgramReport {
                program: "xdp_firewall".into(),
                state: ProgramState::Loaded,
            }],
        )
        .expect("built");

        let body: serde_json::Value = serde_json::to_value(&beat).expect("serialised");
        let object = body.as_object().expect("an object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["installation_id", "programs", "version"]);

        let program = body["programs"][0].as_object().expect("an object");
        let mut program_keys: Vec<&str> = program.keys().map(String::as_str).collect();
        program_keys.sort_unstable();
        assert_eq!(program_keys, ["program", "state"]);

        assert_eq!(body["programs"][0]["state"], "loaded");
    }
}
