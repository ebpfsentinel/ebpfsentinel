use serde::{Deserialize, Serialize};

use crate::common::entity::{DomainMode, RuleId, Severity};
use ebpf_common::dlp::DlpEvent;

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

impl DlpPattern {
    /// Validate pattern fields.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.id.validate()?;
        if self.regex.is_empty() {
            return Err("regex must not be empty");
        }
        if self.data_type.is_empty() {
            return Err("data_type must not be empty");
        }
        Ok(())
    }
}

/// Result of scanning data against a compiled DLP pattern.
/// Contains NO raw matched text — only offset and length for redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpMatch {
    pub pattern_index: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
}

/// Domain-level DLP alert produced when a pattern matches captured data.
/// The actual sensitive data is NEVER included — only a redacted placeholder (FR17).
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
    /// Always `[REDACTED:{data_type}]` — never the actual matched content.
    pub redacted_excerpt: String,
    pub timestamp_ns: u64,
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
        }
    }
}

/// Return the predefined DLP patterns covering FR15:
/// - PCI: Visa, Mastercard, Amex
/// - PII: Email, SSN
/// - Credentials: AWS key, GitHub token, generic password, Bearer token
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
            description: "US Social Security Number (XXX-XX-XXXX)".to_string(),
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
    use ebpf_common::dlp::{DLP_DIRECTION_READ, DLP_DIRECTION_WRITE, DLP_MAX_EXCERPT};

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
            data_len: 100,
            direction: DLP_DIRECTION_WRITE,
            _padding: [0; 3],
            data_excerpt: [0u8; DLP_MAX_EXCERPT],
        }
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
        let event = sample_event();
        let pattern = sample_pattern();
        let alert = DlpAlert::from_event(&event, &pattern);

        assert_eq!(alert.redacted_excerpt, "[REDACTED:pci]");
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
        assert_eq!(patterns.len(), 9);
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
