use serde::{Deserialize, Serialize};

use crate::common::entity::{DomainMode, RuleId, Severity};
use ebpf_common::dlp::{
    DLP_FLOW_FAMILY_IPV6, DLP_FLOW_SOURCE_CORRELATED, DLP_FLOW_SOURCE_KERNEL_SOCKET, DlpEvent,
    DlpSocket,
};

/// A DLP pattern defining what sensitive data to detect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPattern {
    pub id: RuleId,
    pub name: String,
    pub regex: String,
    pub severity: Severity,
    pub mode: DomainMode,
    /// Category: "pci", "pii", "credentials", "custom".
    pub data_type: String,
    pub description: String,
    pub enabled: bool,
}

/// Maximum regex source length (4 KiB) to reject unreasonably large patterns early.
const MAX_REGEX_SOURCE_LEN: usize = 4096;

/// Maximum compiled regex size (10 MiB) - matches engine limit.
const REGEX_SIZE_LIMIT: usize = 10 * (1 << 20);

/// Maximum regex nesting depth - matches engine limit.
const REGEX_NEST_LIMIT: u32 = 200;

impl DlpPattern {
    /// Validate pattern fields.
    ///
    /// Pre-compiles the regex with size and nesting limits to reject invalid
    /// or denial-of-service patterns at config load time rather than at runtime.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.id.validate()?;
        if self.regex.is_empty() {
            return Err("regex must not be empty");
        }
        if self.regex.len() > MAX_REGEX_SOURCE_LEN {
            return Err("regex source exceeds maximum length (4 KiB)");
        }
        // Pre-compile with bounded limits to catch invalid/dangerous patterns early.
        regex::RegexBuilder::new(&self.regex)
            .size_limit(REGEX_SIZE_LIMIT)
            .nest_limit(REGEX_NEST_LIMIT)
            .build()
            .map_err(|_| "regex failed to compile (invalid or too complex)")?;
        if self.data_type.is_empty() {
            return Err("data_type must not be empty");
        }
        Ok(())
    }
}

/// Result of scanning data against a compiled DLP pattern.
/// Contains NO raw matched text - only offset and length for redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpMatch {
    pub pattern_index: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
}

/// How a piece of a DLP alert's identity was come by.
///
/// Every identity on an alert carries one of these, because the three are not
/// worth the same: a path read out of `/proc` while the process is still
/// alive, a five-tuple read off the socket the kernel was writing through, and
/// a tuple remembered from the same task's previous write are three different
/// claims. Nothing is filled in by guessing: what cannot be obtained is
/// absent, and an absent field is how an alert says it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpIdentitySource {
    /// Resolved from the running process when the alert was raised.
    ProcessAtAlertTime,
    /// Read from the socket the kernel TLS call was made on.
    KernelSocket,
    /// Taken from the last socket the same task wrote through, inside the
    /// datapath's correlation window. The destination of that write, not
    /// proof that these bytes went the same way.
    TaskSocketCorrelation,
}

impl DlpIdentitySource {
    /// The wire spelling, which is also what the console shows beside the
    /// field so a reader can tell a reading from a correlation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcessAtAlertTime => "process_at_alert_time",
            Self::KernelSocket => "kernel_socket",
            Self::TaskSocketCorrelation => "task_socket_correlation",
        }
    }
}

/// The executable the process that leaked was running, with the identity that
/// survives a rename: a path is what an operator reads, `(dev, ino)` is what
/// two alerts are compared on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpExecutable {
    /// Absolute path as the agent resolved it, in the agent's own mount view.
    pub path: String,
    /// Device the executable's inode lives on.
    pub dev: u64,
    /// Inode number.
    pub inode: u64,
    /// How the path was obtained.
    pub source: DlpIdentitySource,
}

/// The flow the plaintext went through, as the datapath could account for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpFlow {
    /// Local address, four words: IPv4 in word 0, IPv6 across all four.
    pub src_addr: [u32; 4],
    /// Peer address, same encoding.
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    /// IP protocol number.
    pub protocol: u8,
    pub is_ipv6: bool,
    /// How the tuple was obtained.
    pub source: DlpIdentitySource,
}

impl DlpFlow {
    /// Read a flow out of a kernel event's socket block.
    ///
    /// `None` where the probe had no socket: the block is zeroed and its
    /// source says so, and a zeroed block is never turned into `0.0.0.0:0`.
    pub fn from_socket(socket: &DlpSocket) -> Option<Self> {
        let source = match socket.source {
            DLP_FLOW_SOURCE_KERNEL_SOCKET => DlpIdentitySource::KernelSocket,
            DLP_FLOW_SOURCE_CORRELATED => DlpIdentitySource::TaskSocketCorrelation,
            _ => return None,
        };
        Some(Self {
            src_addr: socket.src_addr,
            dst_addr: socket.dst_addr,
            src_port: socket.src_port,
            dst_port: socket.dst_port,
            protocol: socket.protocol,
            is_ipv6: socket.family == DLP_FLOW_FAMILY_IPV6,
            source,
        })
    }
}

/// Domain-level DLP alert produced when a pattern matches captured data.
/// The actual sensitive data is NEVER included - only a redacted placeholder (FR17).
#[derive(Debug, Clone)]
pub struct DlpAlert {
    pub pattern_id: RuleId,
    pub pattern_name: String,
    pub severity: Severity,
    pub mode: DomainMode,
    pub data_type: String,
    pub pid: u32,
    pub tgid: u32,
    pub direction: u8,
    /// Always `[REDACTED:{data_type}]` - never the actual matched content.
    pub redacted_excerpt: String,
    pub timestamp_ns: u64,
    /// Container context resolved from the event's `cgroup_id` (if any).
    pub container: Option<crate::container::entity::ContainerInfo>,
    /// The binary the process was running, where the agent could still read
    /// it. A process gone by the time the alert is raised leaves this absent.
    pub executable: Option<DlpExecutable>,
    /// Where the data went, where the datapath could account for it. Absent
    /// is the honest answer for a plain userspace TLS write the probes saw no
    /// socket for, and an absent flow is not a flow of zeroes.
    pub flow: Option<DlpFlow>,
}

impl DlpAlert {
    /// Create an alert from a kernel DLP event and the matched pattern.
    /// Matched text is systematically replaced with `[REDACTED:{data_type}]`.
    pub fn from_event(event: &DlpEvent, pattern: &DlpPattern) -> Self {
        Self {
            pattern_id: pattern.id.clone(),
            pattern_name: pattern.name.clone(),
            severity: pattern.severity,
            mode: pattern.mode,
            data_type: pattern.data_type.clone(),
            pid: event.pid,
            tgid: event.tgid,
            direction: event.direction,
            redacted_excerpt: format!("[REDACTED:{}]", pattern.data_type),
            timestamp_ns: event.timestamp_ns,
            container: None,
            executable: None,
            flow: DlpFlow::from_socket(&event.flow),
        }
    }
}

/// Built-in pattern ID prefixes (OSS-available categories).
const BUILTIN_PREFIXES: &[&str] = &["dlp-pci-", "dlp-pii-", "dlp-cred-"];

/// Check whether a pattern ID corresponds to a built-in pattern.
pub fn is_builtin_pattern_id(id: &str) -> bool {
    BUILTIN_PREFIXES.iter().any(|prefix| id.starts_with(prefix))
}

/// Return the predefined DLP patterns:
/// - PCI: Visa, Mastercard, Amex
/// - PII: email, and national identifiers for the United States, France,
///   the United Kingdom, Spain, Italy, Belgium, Canada, Brazil and India,
///   each confirmed by its scheme's check digit (see [`super::checksum`])
/// - Credentials: AWS key, GitHub token, generic password, Bearer token
#[allow(clippy::too_many_lines)] // one literal per pattern, nothing to factor
pub fn default_patterns() -> Vec<DlpPattern> {
    vec![
        // ── PCI ──────────────────────────────────────────────────
        DlpPattern {
            id: RuleId("dlp-pci-visa".to_string()),
            name: "Visa Card Number".to_string(),
            regex: r"\b4[0-9]{12}(?:[0-9]{3})?\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            description: "Visa credit card number (13 or 16 digits starting with 4)".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pci-mastercard".to_string()),
            name: "Mastercard Number".to_string(),
            regex: r"\b5[1-5][0-9]{14}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            description: "Mastercard credit card number (16 digits starting with 51-55)"
                .to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pci-amex".to_string()),
            name: "American Express Number".to_string(),
            regex: r"\b3[47][0-9]{13}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            description: "American Express card number (15 digits starting with 34 or 37)"
                .to_string(),
            enabled: true,
        },
        // ── PII ──────────────────────────────────────────────────
        DlpPattern {
            id: RuleId("dlp-pii-email".to_string()),
            name: "Email Address".to_string(),
            regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".to_string(),
            severity: Severity::Medium,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "Email address".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-ssn".to_string()),
            name: "US Social Security Number".to_string(),
            regex: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "US Social Security Number (XXX-XX-XXXX), unissued ranges excluded"
                .to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-fr-nir".to_string()),
            name: "French Social Security Number (NIR)".to_string(),
            regex:
                r"\b[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b"
                    .to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "French NIR, 15 characters, confirmed by its mod-97 key".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-uk-nino".to_string()),
            name: "UK National Insurance Number".to_string(),
            regex: r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"
                .to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "UK National Insurance number (AB 12 34 56 C), unissued prefixes excluded"
                .to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-es-dni".to_string()),
            name: "Spanish DNI / NIE".to_string(),
            regex: r"\b(?:\d{8}|[XYZ]\d{7})-?[A-Z]\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "Spanish DNI or NIE, confirmed by its mod-23 check letter".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-it-cf".to_string()),
            name: "Italian Codice Fiscale".to_string(),
            regex: r"\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "Italian codice fiscale, confirmed by its check letter".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-be-nrn".to_string()),
            name: "Belgian National Register Number".to_string(),
            regex: r"\b\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description:
                "Belgian national register number (YY.MM.DD-XXX.CC), confirmed by its mod-97 key"
                    .to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-ca-sin".to_string()),
            name: "Canadian Social Insurance Number".to_string(),
            regex: r"\b\d{3}[ -]\d{3}[ -]\d{3}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "Canadian SIN (XXX XXX XXX), confirmed by Luhn".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-br-cpf".to_string()),
            name: "Brazilian CPF".to_string(),
            regex: r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "Brazilian CPF (XXX.XXX.XXX-XX), confirmed by its two check digits"
                .to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-pii-in-aadhaar".to_string()),
            name: "Indian Aadhaar Number".to_string(),
            regex: r"\b[2-9]\d{3} \d{4} \d{4}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pii".to_string(),
            description: "Indian Aadhaar number (XXXX XXXX XXXX), confirmed by Verhoeff"
                .to_string(),
            enabled: true,
        },
        // ── Credentials ──────────────────────────────────────────
        DlpPattern {
            id: RuleId("dlp-cred-aws-key".to_string()),
            name: "AWS Access Key".to_string(),
            regex: r"\bAKIA[0-9A-Z]{16}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "credentials".to_string(),
            description: "AWS Access Key ID (starts with AKIA)".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-cred-github-token".to_string()),
            name: "GitHub Personal Access Token".to_string(),
            regex: r"\bghp_[a-zA-Z0-9]{36}\b".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "credentials".to_string(),
            description: "GitHub personal access token (ghp_...)".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-cred-password".to_string()),
            name: "Generic Password".to_string(),
            regex: r"(?i)(password|passwd|pwd)\s*[:=]\s*\S{8,}".to_string(),
            severity: Severity::High,
            mode: DomainMode::Alert,
            data_type: "credentials".to_string(),
            description: "Generic password assignment (password=..., pwd:..., etc.)".to_string(),
            enabled: true,
        },
        DlpPattern {
            id: RuleId("dlp-cred-bearer".to_string()),
            name: "Bearer Token".to_string(),
            regex: r"Bearer\s+[A-Za-z0-9\-._~+/]+=*".to_string(),
            severity: Severity::High,
            mode: DomainMode::Alert,
            data_type: "credentials".to_string(),
            description: "HTTP Bearer authentication token".to_string(),
            enabled: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::dlp::{
        DLP_DIRECTION_READ, DLP_DIRECTION_WRITE, DLP_FLOW_FAMILY_IPV4, DLP_FLOW_FAMILY_IPV6,
        DLP_FLOW_PROTOCOL_TCP, DLP_FLOW_SOURCE_CORRELATED, DLP_FLOW_SOURCE_KERNEL_SOCKET,
        DLP_FLOW_SOURCE_NONE, DLP_MAX_EXCERPT,
    };

    fn sample_pattern() -> DlpPattern {
        DlpPattern {
            id: RuleId("dlp-001".to_string()),
            name: "Test Pattern".to_string(),
            regex: r"\b\d{4}\b".to_string(),
            severity: Severity::High,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            description: "Test pattern".to_string(),
            enabled: true,
        }
    }

    fn sample_event() -> DlpEvent {
        DlpEvent {
            pid: 1234,
            tgid: 5678,
            timestamp_ns: 1_000_000_000,
            cgroup_id: 0,
            data_len: 100,
            direction: DLP_DIRECTION_WRITE,
            _padding: [0; 3],
            flow: DlpSocket::default(),
            data_excerpt: [0u8; DLP_MAX_EXCERPT],
        }
    }

    /// An event whose probe read the socket: 10.1.2.3:44001 -> 93.184.216.34:443.
    fn sample_event_with_socket(source: u8) -> DlpEvent {
        let mut event = sample_event();
        event.flow = DlpSocket {
            src_addr: [0x0a01_0203, 0, 0, 0],
            dst_addr: [0x5db8_d822, 0, 0, 0],
            src_port: 44001,
            dst_port: 443,
            family: DLP_FLOW_FAMILY_IPV4,
            protocol: DLP_FLOW_PROTOCOL_TCP,
            source,
            _pad: 0,
        };
        event
    }

    // ── DlpPattern validation ────────────────────────────────────

    #[test]
    fn validate_ok() {
        assert!(sample_pattern().validate().is_ok());
    }

    #[test]
    fn validate_empty_id() {
        let mut p = sample_pattern();
        p.id = RuleId(String::new());
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_empty_regex() {
        let mut p = sample_pattern();
        p.regex = String::new();
        assert_eq!(p.validate(), Err("regex must not be empty"));
    }

    #[test]
    fn validate_empty_data_type() {
        let mut p = sample_pattern();
        p.data_type = String::new();
        assert_eq!(p.validate(), Err("data_type must not be empty"));
    }

    #[test]
    fn validate_invalid_regex_rejected() {
        let mut p = sample_pattern();
        p.regex = r"[unclosed".to_string();
        assert_eq!(
            p.validate(),
            Err("regex failed to compile (invalid or too complex)")
        );
    }

    #[test]
    fn validate_overlong_regex_rejected() {
        let mut p = sample_pattern();
        p.regex = "a".repeat(MAX_REGEX_SOURCE_LEN + 1);
        assert_eq!(
            p.validate(),
            Err("regex source exceeds maximum length (4 KiB)")
        );
    }

    // ── DlpAlert from_event ──────────────────────────────────────

    #[test]
    fn from_event_maps_fields() {
        let event = sample_event();
        let pattern = sample_pattern();
        let alert = DlpAlert::from_event(&event, &pattern);

        assert_eq!(alert.pattern_id, pattern.id);
        assert_eq!(alert.pattern_name, "Test Pattern");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.mode, DomainMode::Alert);
        assert_eq!(alert.data_type, "pci");
        assert_eq!(alert.pid, 1234);
        assert_eq!(alert.tgid, 5678);
        assert_eq!(alert.direction, DLP_DIRECTION_WRITE);
        assert_eq!(alert.timestamp_ns, 1_000_000_000);
    }

    #[test]
    fn from_event_redacts_content() {
        // The excerpt the probe captured is a credit card number followed by
        // a password, and no field of the alert may carry either - including
        // the identity fields the alert gained: a path, a device, an inode
        // and a five-tuple are metadata about the leak, never the leak.
        let mut event = sample_event_with_socket(DLP_FLOW_SOURCE_KERNEL_SOCKET);
        let secret = b"4111111111111111 password=hunter2";
        event.data_excerpt[..secret.len()].copy_from_slice(secret);
        event.data_len = secret.len() as u32;

        let pattern = sample_pattern();
        let mut alert = DlpAlert::from_event(&event, &pattern);
        alert.executable = Some(DlpExecutable {
            path: "/usr/bin/curl".to_string(),
            dev: 66_306,
            inode: 1_234_567,
            source: DlpIdentitySource::ProcessAtAlertTime,
        });

        assert_eq!(alert.redacted_excerpt, "[REDACTED:pci]");

        let rendered = format!("{alert:?}");
        for leaked in ["4111111111111111", "hunter2", "password="] {
            assert!(
                !rendered.contains(leaked),
                "alert carries matched content: {leaked}"
            );
        }
    }

    #[test]
    fn from_event_carries_the_socket_the_probe_read() {
        let event = sample_event_with_socket(DLP_FLOW_SOURCE_KERNEL_SOCKET);
        let alert = DlpAlert::from_event(&event, &sample_pattern());

        let flow = alert.flow.expect("a read socket is a flow");
        assert_eq!(flow.dst_addr, [0x5db8_d822, 0, 0, 0]);
        assert_eq!(flow.dst_port, 443);
        assert_eq!(flow.src_port, 44001);
        assert_eq!(flow.protocol, DLP_FLOW_PROTOCOL_TCP);
        assert!(!flow.is_ipv6);
        assert_eq!(flow.source, DlpIdentitySource::KernelSocket);
    }

    #[test]
    fn from_event_says_when_the_tuple_is_a_correlation() {
        let event = sample_event_with_socket(DLP_FLOW_SOURCE_CORRELATED);
        let alert = DlpAlert::from_event(&event, &sample_pattern());

        let flow = alert.flow.expect("a correlated socket is still a flow");
        assert_eq!(flow.source, DlpIdentitySource::TaskSocketCorrelation);
        assert_ne!(flow.source, DlpIdentitySource::KernelSocket);
    }

    #[test]
    fn an_unresolved_socket_is_absent_rather_than_zero() {
        let event = sample_event();
        assert_eq!(event.flow.source, DLP_FLOW_SOURCE_NONE);

        let alert = DlpAlert::from_event(&event, &sample_pattern());
        assert!(alert.flow.is_none());
        assert!(alert.executable.is_none());
    }

    #[test]
    fn a_zeroed_socket_claiming_a_source_is_still_read_as_none() {
        // Every address word is zero, but the block says a socket was read:
        // a connection to 0.0.0.0:0 cannot happen, so this is the shape a
        // failed read would leave, and the flow is dropped rather than shown.
        let mut event = sample_event();
        event.flow.source = DLP_FLOW_SOURCE_NONE;
        assert!(DlpFlow::from_socket(&event.flow).is_none());
    }

    #[test]
    fn an_ipv6_socket_keeps_all_four_words() {
        let mut event = sample_event_with_socket(DLP_FLOW_SOURCE_KERNEL_SOCKET);
        event.flow.family = DLP_FLOW_FAMILY_IPV6;
        event.flow.dst_addr = [0x2606_2800, 0x0220_0001, 0x0248_1893, 0x25c8_1946];

        let flow = DlpFlow::from_socket(&event.flow).expect("an IPv6 socket is a flow");
        assert!(flow.is_ipv6);
        assert_eq!(flow.dst_addr[3], 0x25c8_1946);
    }

    #[test]
    fn identity_sources_spell_themselves_for_the_wire() {
        assert_eq!(
            DlpIdentitySource::ProcessAtAlertTime.as_str(),
            "process_at_alert_time"
        );
        assert_eq!(DlpIdentitySource::KernelSocket.as_str(), "kernel_socket");
        assert_eq!(
            DlpIdentitySource::TaskSocketCorrelation.as_str(),
            "task_socket_correlation"
        );
    }

    #[test]
    fn from_event_read_direction() {
        let mut event = sample_event();
        event.direction = DLP_DIRECTION_READ;
        let pattern = sample_pattern();
        let alert = DlpAlert::from_event(&event, &pattern);

        assert_eq!(alert.direction, DLP_DIRECTION_READ);
    }

    #[test]
    fn from_event_credentials_redaction() {
        let event = sample_event();
        let mut pattern = sample_pattern();
        pattern.data_type = "credentials".to_string();
        let alert = DlpAlert::from_event(&event, &pattern);

        assert_eq!(alert.redacted_excerpt, "[REDACTED:credentials]");
    }

    // ── DlpMatch ─────────────────────────────────────────────────

    #[test]
    fn dlp_match_fields() {
        let m = DlpMatch {
            pattern_index: 2,
            byte_offset: 100,
            byte_length: 16,
        };
        assert_eq!(m.pattern_index, 2);
        assert_eq!(m.byte_offset, 100);
        assert_eq!(m.byte_length, 16);
    }

    // ── default_patterns ─────────────────────────────────────────

    #[test]
    fn default_patterns_count() {
        let patterns = default_patterns();
        assert_eq!(patterns.len(), 17);
    }

    #[test]
    fn default_patterns_all_valid() {
        for pattern in &default_patterns() {
            assert!(
                pattern.validate().is_ok(),
                "pattern {} failed validation",
                pattern.id
            );
        }
    }

    #[test]
    fn default_patterns_all_enabled() {
        for pattern in &default_patterns() {
            assert!(pattern.enabled, "pattern {} should be enabled", pattern.id);
        }
    }

    #[test]
    fn default_patterns_unique_ids() {
        let patterns = default_patterns();
        let mut ids: Vec<&str> = patterns.iter().map(|p| p.id.0.as_str()).collect();
        let len_before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "duplicate pattern IDs found");
    }

    #[test]
    fn default_patterns_cover_all_categories() {
        let patterns = default_patterns();
        let types: Vec<&str> = patterns.iter().map(|p| p.data_type.as_str()).collect();
        assert!(types.contains(&"pci"), "missing PCI patterns");
        assert!(types.contains(&"pii"), "missing PII patterns");
        assert!(
            types.contains(&"credentials"),
            "missing credential patterns"
        );
    }

    #[test]
    fn default_patterns_regexes_compile() {
        for pattern in &default_patterns() {
            assert!(
                regex::Regex::new(&pattern.regex).is_ok(),
                "pattern {} has invalid regex: {}",
                pattern.id,
                pattern.regex
            );
        }
    }
}
