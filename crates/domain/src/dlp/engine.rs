use regex::Regex;

use crate::common::error::DomainError;

use super::checksum::confirms;
use super::entity::{DlpMatch, DlpPattern, is_builtin_pattern};
use super::error::DlpError;

/// DLP engine: validates, stores, and manages DLP patterns.
/// Regex patterns are compiled at pattern load time (not per-scan).
#[derive(Debug, Clone)]
pub struct DlpEngine {
    patterns: Vec<DlpPattern>,
    compiled_patterns: Vec<Regex>,
}

impl DlpEngine {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            compiled_patterns: Vec::new(),
        }
    }

    /// Add a single DLP pattern. Validates, checks for duplicates,
    /// and compiles the regex.
    ///
    /// Only built-in patterns are accepted: a built-in id with its own
    /// expression.
    pub fn add_pattern(&mut self, pattern: DlpPattern) -> Result<(), DomainError> {
        if !is_builtin_pattern(&pattern.id.0, &pattern.regex) {
            return Err(DlpError::EnterpriseRequired {
                reason: format!(
                    "DLP pattern '{}' is not a built-in with its own expression; custom \
                     patterns and changed built-ins require a paid license (Professional and up)",
                    pattern.id.0,
                ),
            }
            .into());
        }

        pattern
            .validate()
            .map_err(|reason| DlpError::InvalidPattern(reason.to_string()))?;

        if self.patterns.iter().any(|p| p.id == pattern.id) {
            return Err(DlpError::DuplicatePattern {
                id: pattern.id.0.clone(),
            }
            .into());
        }

        let compiled = compile_pattern(&pattern.regex)?;
        self.patterns.push(pattern);
        self.compiled_patterns.push(compiled);
        Ok(())
    }

    /// Remove a pattern by ID.
    pub fn remove_pattern(
        &mut self,
        id: &crate::common::entity::RuleId,
    ) -> Result<(), DomainError> {
        let pos = self
            .patterns
            .iter()
            .position(|p| p.id == *id)
            .ok_or_else(|| DlpError::PatternNotFound { id: id.0.clone() })?;
        self.patterns.remove(pos);
        self.compiled_patterns.remove(pos);
        Ok(())
    }

    /// Atomically replace all patterns. Validates all patterns and compiles
    /// all regexes before replacing. Rolls back on any error.
    ///
    /// Only built-in patterns are accepted, each with its own expression.
    pub fn reload(&mut self, patterns: Vec<DlpPattern>) -> Result<(), DomainError> {
        // Validate all patterns first
        for pattern in &patterns {
            if !is_builtin_pattern(&pattern.id.0, &pattern.regex) {
                return Err(DlpError::EnterpriseRequired {
                    reason: format!(
                        "DLP pattern '{}' is not a built-in with its own expression; custom \
                         patterns and changed built-ins require a paid license (Professional and up)",
                        pattern.id.0,
                    ),
                }
                .into());
            }

            pattern
                .validate()
                .map_err(|reason| DlpError::InvalidPattern(reason.to_string()))?;
        }

        // Check for duplicates
        for (i, pattern) in patterns.iter().enumerate() {
            if patterns[i + 1..].iter().any(|p| p.id == pattern.id) {
                return Err(DlpError::DuplicatePattern {
                    id: pattern.id.0.clone(),
                }
                .into());
            }
        }

        // Compile all regexes
        let mut compiled = Vec::with_capacity(patterns.len());
        for pattern in &patterns {
            compiled.push(compile_pattern(&pattern.regex)?);
        }

        // Atomic replace
        self.patterns = patterns;
        self.compiled_patterns = compiled;
        Ok(())
    }

    /// Read-only access to the loaded patterns.
    pub fn patterns(&self) -> &[DlpPattern] {
        &self.patterns
    }

    /// Number of loaded patterns.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Scan a byte slice against all enabled compiled patterns.
    /// Returns all matches with pattern index, byte offset, and byte length.
    /// A match on a pattern with a check digit is kept only when the matched
    /// text passes it.
    /// Data is treated as lossy UTF-8 for regex matching.
    pub fn scan_data(&self, data: &[u8]) -> Vec<DlpMatch> {
        let text = String::from_utf8_lossy(data);
        let mut matches = Vec::new();

        for (idx, (pattern, compiled)) in self
            .patterns
            .iter()
            .zip(self.compiled_patterns.iter())
            .enumerate()
        {
            if !pattern.enabled {
                continue;
            }

            for m in compiled.find_iter(&text) {
                if !confirms(&pattern.id.0, m.as_str().as_bytes()) {
                    continue;
                }
                matches.push(DlpMatch {
                    pattern_index: idx,
                    byte_offset: m.start(),
                    byte_length: m.len(),
                });
            }
        }

        matches
    }
}

impl Default for DlpEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum compiled regex size (10 MiB) to prevent regex denial-of-service.
const REGEX_SIZE_LIMIT: usize = 10 * (1 << 20);

/// Maximum regex nesting depth to prevent stack overflow.
const REGEX_NEST_LIMIT: u32 = 200;

/// Compile a regex pattern string. DLP patterns always require a non-empty regex,
/// so this always returns a `Regex` (unlike IDS which allows empty patterns).
///
/// Uses `RegexBuilder` with size and nesting limits to prevent
/// denial-of-service via malicious patterns.
fn compile_pattern(pattern: &str) -> Result<Regex, DomainError> {
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|e| DomainError::InvalidRule(format!("invalid regex pattern '{pattern}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::RuleId;
    use crate::dlp::entity::{DlpPattern, default_patterns};

    /// A built-in exactly as it ships.
    fn builtin(id: &str) -> DlpPattern {
        default_patterns()
            .into_iter()
            .find(|p| p.id.0 == id)
            .unwrap_or_else(|| panic!("no built-in {id}"))
    }

    fn ids(engine: &DlpEngine, data: &[u8]) -> Vec<String> {
        engine
            .scan_data(data)
            .iter()
            .map(|m| engine.patterns()[m.pattern_index].id.0.clone())
            .collect()
    }

    // ── new / default ────────────────────────────────────────────

    #[test]
    fn new_engine_is_empty() {
        let engine = DlpEngine::new();
        assert_eq!(engine.pattern_count(), 0);
        assert!(engine.patterns().is_empty());
    }

    #[test]
    fn default_is_same_as_new() {
        let engine = DlpEngine::default();
        assert_eq!(engine.pattern_count(), 0);
    }

    // ── the open source ceiling ──────────────────────────────────

    #[test]
    fn every_builtin_is_accepted_as_shipped() {
        let mut engine = DlpEngine::new();
        for pattern in default_patterns() {
            engine.add_pattern(pattern).unwrap();
        }
        assert_eq!(engine.pattern_count(), default_patterns().len());
    }

    #[test]
    fn an_unknown_id_is_refused_whatever_its_prefix() {
        let mut engine = DlpEngine::new();
        let mut p = builtin("dlp-pii-ssn");
        p.id = RuleId("dlp-pii-badge".to_string());
        let err = engine.add_pattern(p).unwrap_err().to_string();
        assert!(err.contains("Professional"), "{err}");
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn a_builtin_with_a_changed_expression_is_refused() {
        let mut engine = DlpEngine::new();
        let mut p = builtin("dlp-pii-ssn");
        p.regex = r"ITB-[0-9]{8}".to_string();
        assert!(engine.add_pattern(p).is_err());
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn a_builtin_may_be_renamed_retuned_and_switched_off() {
        let mut engine = DlpEngine::new();
        let mut p = builtin("dlp-pii-ssn");
        p.name = "US social security number".to_string();
        p.severity = crate::common::entity::Severity::Low;
        p.description = "re-tuned".to_string();
        p.enabled = false;
        engine.add_pattern(p).unwrap();
        assert_eq!(engine.pattern_count(), 1);
    }

    #[test]
    fn reload_refuses_a_set_holding_one_changed_builtin() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();
        let mut changed = builtin("dlp-pii-email");
        changed.regex = r"\w+@\w+".to_string();
        assert!(
            engine
                .reload(vec![builtin("dlp-pii-ssn"), changed])
                .is_err()
        );
        // The set in place is kept.
        assert_eq!(engine.pattern_count(), 1);
        assert_eq!(engine.patterns()[0].id.0, "dlp-pci-visa");
    }

    // ── add_pattern ──────────────────────────────────────────────

    #[test]
    fn add_pattern_compiles_regex() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();
        assert_eq!(
            ids(&engine, b"card 4111111111111111 here"),
            ["dlp-pci-visa"]
        );
    }

    #[test]
    fn add_duplicate_pattern_fails() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();
        assert!(engine.add_pattern(builtin("dlp-pci-visa")).is_err());
        assert_eq!(engine.pattern_count(), 1);
    }

    #[test]
    fn add_pattern_empty_id_rejected() {
        let mut engine = DlpEngine::new();
        let mut p = builtin("dlp-pci-visa");
        p.id = RuleId(String::new());
        assert!(engine.add_pattern(p).is_err());
    }

    // ── remove_pattern ───────────────────────────────────────────

    #[test]
    fn remove_pattern_succeeds() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();
        engine.add_pattern(builtin("dlp-pii-ssn")).unwrap();
        engine
            .remove_pattern(&RuleId("dlp-pci-visa".to_string()))
            .unwrap();
        assert_eq!(engine.pattern_count(), 1);
        assert_eq!(engine.patterns()[0].id.0, "dlp-pii-ssn");
    }

    #[test]
    fn remove_nonexistent_pattern_fails() {
        let mut engine = DlpEngine::new();
        assert!(engine.remove_pattern(&RuleId("nope".to_string())).is_err());
    }

    #[test]
    fn remove_keeps_compiled_in_sync() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();
        engine.add_pattern(builtin("dlp-pii-ssn")).unwrap();
        engine
            .remove_pattern(&RuleId("dlp-pci-visa".to_string()))
            .unwrap();
        // The SSN pattern is now at index 0 and still matches.
        let matches = engine.scan_data(b"ssn is 123-45-6789 here");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_index, 0);
    }

    // ── reload ───────────────────────────────────────────────────

    #[test]
    fn reload_replaces_all_patterns() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();
        engine
            .reload(vec![builtin("dlp-pii-email"), builtin("dlp-pii-ssn")])
            .unwrap();
        assert_eq!(engine.pattern_count(), 2);
        assert_eq!(engine.patterns()[0].id.0, "dlp-pii-email");
        assert_eq!(engine.patterns()[1].id.0, "dlp-pii-ssn");
    }

    #[test]
    fn reload_empty_clears_all() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();
        engine.reload(vec![]).unwrap();
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn reload_rejects_duplicates() {
        let mut engine = DlpEngine::new();
        let result = engine.reload(vec![builtin("dlp-pci-visa"), builtin("dlp-pci-visa")]);
        assert!(result.is_err());
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn reload_validates_all_patterns() {
        let mut engine = DlpEngine::new();
        let mut p = builtin("dlp-pci-visa");
        p.id = RuleId(String::new());
        assert!(engine.reload(vec![p]).is_err());
    }

    // ── scan_data ────────────────────────────────────────────────

    #[test]
    fn scan_data_finds_credit_card() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();

        let matches = engine.scan_data(b"payment with card 4111111111111111 confirmed");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_index, 0);
        assert_eq!(matches[0].byte_length, 16);
    }

    #[test]
    fn scan_data_finds_email() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pii-email")).unwrap();
        assert_eq!(
            ids(&engine, b"contact: user@example.com for info"),
            ["dlp-pii-email"]
        );
    }

    #[test]
    fn scan_data_finds_aws_key() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-cred-aws-key")).unwrap();
        assert_eq!(
            ids(&engine, b"key=AKIAIOSFODNN7EXAMPLE "),
            ["dlp-cred-aws-key"]
        );
    }

    #[test]
    fn scan_data_finds_ssn() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pii-ssn")).unwrap();
        assert_eq!(ids(&engine, b"SSN: 123-45-6789"), ["dlp-pii-ssn"]);
    }

    #[test]
    fn scan_data_drops_a_national_id_that_fails_its_check_digit() {
        let mut engine = DlpEngine::new();
        engine.reload(default_patterns()).unwrap();

        assert_eq!(
            ids(&engine, b"nir=1 85 05 78 006 084 91"),
            ["dlp-pii-fr-nir"]
        );
        assert!(ids(&engine, b"nir=1 85 05 78 006 084 92").is_empty());
        assert_eq!(ids(&engine, b"cf RSSMRA85T10A562S"), ["dlp-pii-it-cf"]);
        assert_eq!(ids(&engine, b"dni 12345678Z"), ["dlp-pii-es-dni"]);
        assert!(ids(&engine, b"dni 12345678A").is_empty());
        // Nine separated digits are a phone number until Luhn says otherwise.
        assert!(ids(&engine, b"call 293 456 787").is_empty());
        assert_eq!(ids(&engine, b"sin 293 456 786"), ["dlp-pii-ca-sin"]);
    }

    #[test]
    fn scan_data_multiple_matches() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pii-ssn")).unwrap();

        let matches = engine.scan_data(b"ids 123-45-6789 and 234-56-7891 here");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].byte_offset, 4);
        assert_eq!(matches[1].byte_offset, 20);
    }

    #[test]
    fn scan_data_multiple_patterns() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pii-email")).unwrap();
        engine.add_pattern(builtin("dlp-pii-ssn")).unwrap();

        let matches = engine.scan_data(b"user@test.com and 123-45-6789");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].pattern_index, 0); // email
        assert_eq!(matches[1].pattern_index, 1); // ssn
    }

    #[test]
    fn scan_data_no_match() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();
        assert!(
            engine
                .scan_data(b"nothing sensitive here at all")
                .is_empty()
        );
    }

    #[test]
    fn scan_data_disabled_pattern_skipped() {
        let mut engine = DlpEngine::new();
        let mut p = builtin("dlp-pii-ssn");
        p.enabled = false;
        engine.add_pattern(p).unwrap();
        assert!(engine.scan_data(b"SSN: 123-45-6789").is_empty());
    }

    #[test]
    fn scan_data_empty_input() {
        let mut engine = DlpEngine::new();
        engine.reload(default_patterns()).unwrap();
        assert!(engine.scan_data(b"").is_empty());
    }

    #[test]
    fn scan_data_no_false_positive_random_numbers() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pci-visa")).unwrap();

        // Short number should not match Visa pattern (needs 13 or 16 digits)
        assert!(engine.scan_data(b"order 4123 confirmed").is_empty());
    }

    #[test]
    fn scan_data_handles_binary_lossy() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(builtin("dlp-pii-ssn")).unwrap();

        // Binary data around a readable identifier
        let mut data = vec![0xFF, 0xFE, b' '];
        data.extend_from_slice(b"123-45-6789");
        data.push(b' ');
        data.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(engine.scan_data(&data).len(), 1);
    }
}
