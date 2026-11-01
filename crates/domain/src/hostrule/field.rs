//! The typed field registry: what each intention carries, and of what type.
//!
//! The type of a field is declared here once, so a rule comparing a path
//! with a number is refused when it is loaded rather than evaluated to
//! `false` on every event for as long as nobody notices.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// The type a field is declared with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// Free text: a command line, a domain, a program name.
    Text,
    /// An absolute path, compared on its text.
    Path,
    /// A signed integer: an identifier, a mode, a count.
    Integer,
    /// A TCP or UDP port, an integer from 0 to 65535.
    Port,
    /// An IPv4 or IPv6 address.
    Address,
    /// True or false.
    Boolean,
    /// A SHA-256 digest, as 64 lowercase hexadecimal characters.
    Hash,
}

impl FieldType {
    /// The name the type is written with in a message.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Path => "a path",
            Self::Integer => "an integer",
            Self::Port => "a port",
            Self::Address => "an address",
            Self::Boolean => "a boolean",
            Self::Hash => "a SHA-256 digest",
        }
    }

    /// The type's own name, as an API reports it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Path => "path",
            Self::Integer => "integer",
            Self::Port => "port",
            Self::Address => "address",
            Self::Boolean => "boolean",
            Self::Hash => "hash",
        }
    }

    /// Whether the type orders, so that "greater than" means something.
    #[must_use]
    pub fn is_numeric(self) -> bool {
        matches!(self, Self::Integer | Self::Port)
    }

    /// Whether a value of this shape may be stored in a field of this type.
    ///
    /// Range and format, a port above 65535 or a digest of the wrong
    /// length, are checked by the caller that knows the field's name.
    #[must_use]
    pub fn accepts(self, value: &FieldValue) -> bool {
        matches!(
            (self, value),
            (Self::Text | Self::Path | Self::Hash, FieldValue::Text(_))
                | (Self::Integer | Self::Port, FieldValue::Integer(_))
                | (Self::Address, FieldValue::Address(_))
                | (Self::Boolean, FieldValue::Boolean(_))
        )
    }
}

/// One value of one field of an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    /// True or false.
    Boolean(bool),
    /// An integer, which a port is as well.
    Integer(i64),
    /// An address.
    Address(IpAddr),
    /// Text, a path or a digest.
    Text(String),
}

impl FieldValue {
    /// The shape of the value, for a message refusing it.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Boolean(_) => "a boolean",
            Self::Integer(_) => "an integer",
            Self::Address(_) => "an address",
            Self::Text(_) => "text",
        }
    }
}

/// One field an intention carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    /// Name of the field, the key a rule writes.
    pub name: &'static str,
    /// Its type.
    pub ty: FieldType,
    /// What it holds, one line, for the documentation and for a refusal.
    pub doc: &'static str,
}

impl FieldSpec {
    const fn new(name: &'static str, ty: FieldType, doc: &'static str) -> Self {
        Self { name, ty, doc }
    }
}

/// Keys a rule writes inside or beside an intent block that are not fields.
///
/// A field may never take one of these names, so a key in a rule is always
/// either a field with its matcher suffix or one of these, and never
/// ambiguous between the two.
pub const RESERVED_KEYS: [&str; 5] = ["count", "workload", "any_of", "followed_by", "within"];

/// The suffixes a matcher appends to a field name.
///
/// No field name ends with one, for the same reason no field takes a
/// reserved key: `exe_in` must read as the field `exe` and the matcher
/// `_in`, with nothing to resolve.
pub const MATCHER_SUFFIXES: [&str; 8] = [
    "_in",
    "_not_in",
    "_matches",
    "_regex",
    "_gt",
    "_lt",
    "_eq_field",
    "_ne_field",
];

use FieldType as Ty;

const EXE: FieldSpec = FieldSpec::new("exe", Ty::Path, "executable of the process");
const UID: FieldSpec = FieldSpec::new("uid", Ty::Integer, "user id the process runs as");
const COMMAND_LINE: FieldSpec = FieldSpec::new(
    "command_line",
    Ty::Text,
    "command line, arguments joined by a space",
);
const EXE_ON_DISK: FieldSpec = FieldSpec::new(
    "exe_on_disk",
    Ty::Boolean,
    "false when the executable has no file left on disk, deleted or memory-backed",
);
const REMOTE_ADDRESS: FieldSpec =
    FieldSpec::new("remote_address", Ty::Address, "address of the peer");
const REMOTE_PORT: FieldSpec = FieldSpec::new("remote_port", Ty::Port, "port of the peer");
const LOCAL_ADDRESS: FieldSpec = FieldSpec::new("local_address", Ty::Address, "local address");
const LOCAL_PORT: FieldSpec = FieldSpec::new("local_port", Ty::Port, "local port");
const PROTOCOL: FieldSpec =
    FieldSpec::new("protocol", Ty::Text, "transport protocol, `tcp` or `udp`");
const FILE_PATH: FieldSpec = FieldSpec::new("path", Ty::Path, "path of the file");
const EXTENSION: FieldSpec = FieldSpec::new(
    "extension",
    Ty::Text,
    "extension of the file name, without the dot",
);

pub(super) const PROCESS_STARTS: &[FieldSpec] = &[
    EXE,
    UID,
    COMMAND_LINE,
    EXE_ON_DISK,
    FieldSpec::new("parent_exe", Ty::Path, "executable of the parent process"),
    FieldSpec::new(
        "parent_uid",
        Ty::Integer,
        "user id the parent process runs as",
    ),
];

pub(super) const PROCESS_ENDS: &[FieldSpec] = &[
    EXE,
    UID,
    FieldSpec::new(
        "exit_code",
        Ty::Integer,
        "exit status, or the number of the signal that ended it",
    ),
];

pub(super) const PROCESS_CONNECTS: &[FieldSpec] =
    &[EXE, UID, EXE_ON_DISK, REMOTE_ADDRESS, REMOTE_PORT, PROTOCOL];

pub(super) const PROCESS_LISTENS: &[FieldSpec] =
    &[EXE, UID, EXE_ON_DISK, LOCAL_ADDRESS, LOCAL_PORT, PROTOCOL];

pub(super) const PROCESS_RESOLVES: &[FieldSpec] = &[
    EXE,
    UID,
    FieldSpec::new(
        "domain",
        Ty::Text,
        "name asked for, lowercase, without the trailing dot",
    ),
    FieldSpec::new(
        "query_type",
        Ty::Text,
        "record type asked for, such as `A` or `TXT`",
    ),
];

pub(super) const PROCESS_SENDS_TLS: &[FieldSpec] = &[
    EXE,
    UID,
    REMOTE_ADDRESS,
    REMOTE_PORT,
    FieldSpec::new(
        "server_name",
        Ty::Text,
        "server name the client sent, empty when it sent none",
    ),
    FieldSpec::new("ja4", Ty::Text, "JA4 fingerprint of the client hello"),
];

pub(super) const FILE_CHANGES: &[FieldSpec] = &[FILE_PATH, EXTENSION, EXE, UID];

pub(super) const FILE_APPEARS: &[FieldSpec] = &[FILE_PATH, EXTENSION, EXE, UID];

pub(super) const FILE_DISAPPEARS: &[FieldSpec] = &[FILE_PATH, EXTENSION, EXE, UID];

pub(super) const FILE_PERMISSIONS_CHANGE: &[FieldSpec] = &[
    FILE_PATH,
    EXE,
    UID,
    FieldSpec::new("mode", Ty::Integer, "permission bits after the change"),
    FieldSpec::new(
        "previous_mode",
        Ty::Integer,
        "permission bits before the change",
    ),
    FieldSpec::new(
        "owner_uid",
        Ty::Integer,
        "user id owning the file after the change",
    ),
];

pub(super) const FILE_INTEGRITY_BREAKS: &[FieldSpec] = &[
    FILE_PATH,
    FieldSpec::new("expected_hash", Ty::Hash, "digest the baseline recorded"),
    FieldSpec::new("actual_hash", Ty::Hash, "digest read now"),
];

pub(super) const PORT_HIDDEN: &[FieldSpec] = &[LOCAL_ADDRESS, LOCAL_PORT, PROTOCOL];

pub(super) const PROCESS_HIDDEN: &[FieldSpec] = &[
    FieldSpec::new(
        "pid",
        Ty::Integer,
        "process id the kernel knows and the process listing omits",
    ),
    FieldSpec::new("comm", Ty::Text, "command name the kernel holds for it"),
];

pub(super) const BPF_FOREIGN_PROGRAM: &[FieldSpec] = &[
    FieldSpec::new("program_id", Ty::Integer, "id the kernel gave the program"),
    FieldSpec::new("program_name", Ty::Text, "name the program was loaded with"),
    FieldSpec::new(
        "program_type",
        Ty::Text,
        "program type, such as `xdp` or `sched_cls`",
    ),
    FieldSpec::new(
        "attach_point",
        Ty::Text,
        "where it is attached, an interface or a hook",
    ),
    FieldSpec::new(
        "loader_exe",
        Ty::Path,
        "executable of the process that loaded it, when known",
    ),
];

pub(super) const PACKET_SOCKET_APPEARS: &[FieldSpec] = &[
    EXE,
    UID,
    FieldSpec::new(
        "interface",
        Ty::Text,
        "interface the socket is bound to, empty for every interface",
    ),
];

pub(super) const PACKAGE_VULNERABLE_REACHABLE: &[FieldSpec] = &[
    FieldSpec::new("package", Ty::Text, "name of the installed package"),
    FieldSpec::new("version", Ty::Text, "installed version"),
    FieldSpec::new(
        "vulnerability",
        Ty::Text,
        "advisory identifier, such as a CVE",
    ),
    FieldSpec::new("severity", Ty::Text, "severity the advisory states"),
    EXE,
    FieldSpec::new(
        "listening_port",
        Ty::Port,
        "port through which the vulnerable code is reachable",
    ),
];
