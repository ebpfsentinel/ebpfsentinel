use regex::Regex;

use crate::common::error::DomainError;

use super::entity::{DlpMatch, DlpPattern};
use super::error::DlpError;

/// DLP engine: validates, stores, and manages DLP patterns.
/// Regex patterns are compiled at pattern load time (not per-scan).
#[derive(Debug)]
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
    pub fn add_pattern(&mut self, pattern: DlpPattern) -> Result<(), DomainError> {
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
    pub fn reload(&mut self, patterns: Vec<DlpPattern>) -> Result<(), DomainError> {
        // Validate all patterns first
        for pattern in &patterns {
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
    use crate::common::entity::{DomainMode, RuleId, Severity};
    use crate::dlp::entity::DlpPattern;

    fn pattern(id: &str, regex: &str) -> DlpPattern {
        DlpPattern {
            id: RuleId(id.to_string()),
            name: format!("Test {id}"),
            regex: regex.to_string(),
            severity: Severity::High,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            description: String::new(),
            enabled: true,
        }
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

    // ── add_pattern ──────────────────────────────────────────────

    #[test]
    fn add_pattern_succeeds() {
        let mut engine = DlpEngine::new();
        assert!(engine.add_pattern(pattern("dlp-001", r"\d{4}")).is_ok());
        assert_eq!(engine.pattern_count(), 1);
        assert_eq!(engine.patterns()[0].id.0, "dlp-001");
    }

    #[test]
    fn add_pattern_compiles_regex() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern("dlp-001", r"\b4[0-9]{12}\b"))
            .unwrap();
        // If it compiled, scan_data should work
        let matches = engine.scan_data(b"card 4111111111111 here");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn add_pattern_invalid_regex_rejected() {
        let mut engine = DlpEngine::new();
        let result = engine.add_pattern(pattern("dlp-001", r"[invalid"));
        assert!(result.is_err());
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn add_duplicate_pattern_fails() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(pattern("dlp-001", r"\d+")).unwrap();
        assert!(engine.add_pattern(pattern("dlp-001", r"\w+")).is_err());
        assert_eq!(engine.pattern_count(), 1);
    }

    #[test]
    fn add_pattern_empty_id_rejected() {
        let mut engine = DlpEngine::new();
        let result = engine.add_pattern(pattern("", r"\d+"));
        assert!(result.is_err());
    }

    #[test]
    fn add_pattern_empty_regex_rejected() {
        let mut engine = DlpEngine::new();
        let result = engine.add_pattern(pattern("dlp-001", ""));
        assert!(result.is_err());
    }

    // ── remove_pattern ───────────────────────────────────────────

    #[test]
    fn remove_pattern_succeeds() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(pattern("dlp-001", r"\d+")).unwrap();
        engine.add_pattern(pattern("dlp-002", r"\w+")).unwrap();
        engine
            .remove_pattern(&RuleId("dlp-001".to_string()))
            .unwrap();
        assert_eq!(engine.pattern_count(), 1);
        assert_eq!(engine.patterns()[0].id.0, "dlp-002");
    }

    #[test]
    fn remove_nonexistent_pattern_fails() {
        let mut engine = DlpEngine::new();
        assert!(engine.remove_pattern(&RuleId("nope".to_string())).is_err());
    }

    #[test]
    fn remove_keeps_compiled_in_sync() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern("dlp-001", r"\b4\d{12}\b"))
            .unwrap();
        engine
            .add_pattern(pattern("dlp-002", r"\d{3}-\d{2}-\d{4}"))
            .unwrap();
        engine
            .remove_pattern(&RuleId("dlp-001".to_string()))
            .unwrap();
        // Now dlp-002 is at index 0, should match SSN format
        let matches = engine.scan_data(b"ssn is 123-45-6789 here");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_index, 0);
    }

    // ── reload ───────────────────────────────────────────────────

    #[test]
    fn reload_replaces_all_patterns() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(pattern("dlp-001", r"\d+")).unwrap();
        engine
            .reload(vec![
                pattern("dlp-010", r"\w+"),
                pattern("dlp-020", r"\d{4}"),
            ])
            .unwrap();
        assert_eq!(engine.pattern_count(), 2);
        assert_eq!(engine.patterns()[0].id.0, "dlp-010");
        assert_eq!(engine.patterns()[1].id.0, "dlp-020");
    }

    #[test]
    fn reload_empty_clears_all() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(pattern("dlp-001", r"\d+")).unwrap();
        engine.reload(vec![]).unwrap();
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn reload_rejects_duplicates() {
        let mut engine = DlpEngine::new();
        let result = engine.reload(vec![pattern("dlp-001", r"\d+"), pattern("dlp-001", r"\w+")]);
        assert!(result.is_err());
        assert_eq!(engine.pattern_count(), 0);
    }

    #[test]
    fn reload_rejects_invalid_regex() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(pattern("dlp-old", r"\d+")).unwrap();
        let result = engine.reload(vec![pattern("dlp-001", r"[bad")]);
        assert!(result.is_err());
        // Original patterns preserved on failure
        assert_eq!(engine.pattern_count(), 1);
        assert_eq!(engine.patterns()[0].id.0, "dlp-old");
    }

    #[test]
    fn reload_validates_all_patterns() {
        let mut engine = DlpEngine::new();
        let result = engine.reload(vec![pattern("", r"\d+")]);
        assert!(result.is_err());
    }

    // ── scan_data ────────────────────────────────────────────────

    #[test]
    fn scan_data_finds_credit_card() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern("visa", r"\b4[0-9]{12}(?:[0-9]{3})?\b"))
            .unwrap();

        let data = b"payment with card 4111111111111111 confirmed";
        let matches = engine.scan_data(data);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_index, 0);
        assert_eq!(matches[0].byte_length, 16);
    }

    #[test]
    fn scan_data_finds_email() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern(
                "email",
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            ))
            .unwrap();

        let data = b"contact: user@example.com for info";
        let matches = engine.scan_data(data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn scan_data_finds_aws_key() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern("aws", r"\bAKIA[0-9A-Z]{16}\b"))
            .unwrap();

        let data = b"key=AKIAIOSFODNN7EXAMPLE";
        let matches = engine.scan_data(data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn scan_data_finds_ssn() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern("ssn", r"\b\d{3}-\d{2}-\d{4}\b"))
            .unwrap();

        let data = b"SSN: 123-45-6789";
        let matches = engine.scan_data(data);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn scan_data_multiple_matches() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(pattern("digits", r"\b\d{4}\b")).unwrap();

        let data = b"codes 1234 and 5678 here";
        let matches = engine.scan_data(data);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].byte_offset, 6);
        assert_eq!(matches[1].byte_offset, 15);
    }

    #[test]
    fn scan_data_multiple_patterns() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern("email", r"\b\w+@\w+\.\w+\b"))
            .unwrap();
        engine
            .add_pattern(pattern("ssn", r"\b\d{3}-\d{2}-\d{4}\b"))
            .unwrap();

        let data = b"user@test.com and 123-45-6789";
        let matches = engine.scan_data(data);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].pattern_index, 0); // email
        assert_eq!(matches[1].pattern_index, 1); // ssn
    }

    #[test]
    fn scan_data_no_match() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern("visa", r"\b4[0-9]{15}\b"))
            .unwrap();

        let data = b"nothing sensitive here at all";
        let matches = engine.scan_data(data);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_data_disabled_pattern_skipped() {
        let mut engine = DlpEngine::new();
        let mut p = pattern("digits", r"\b\d{4}\b");
        p.enabled = false;
        engine.add_pattern(p).unwrap();

        let data = b"code 1234 here";
        let matches = engine.scan_data(data);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_data_empty_input() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(pattern("any", r"\d+")).unwrap();
        let matches = engine.scan_data(b"");
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_data_no_false_positive_random_numbers() {
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(pattern("visa", r"\b4[0-9]{12}(?:[0-9]{3})?\b"))
            .unwrap();

        // Short number should not match Visa pattern (needs 13 or 16 digits)
        let data = b"order 4123 confirmed";
        let matches = engine.scan_data(data);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_data_handles_binary_lossy() {
        let mut engine = DlpEngine::new();
        engine.add_pattern(pattern("digits", r"\b\d{4}\b")).unwrap();

        // Binary data with embedded digits
        let mut data = vec![0xFF, 0xFE, b' '];
        data.extend_from_slice(b"1234");
        data.push(b' ');
        data.extend_from_slice(&[0xFF, 0xFE]);
        let matches = engine.scan_data(&data);
        assert_eq!(matches.len(), 1);
    }

    // ── regex DoS prevention ──────────────────────────────────────

    #[test]
    fn deeply_nested_regex_rejected() {
        let mut engine = DlpEngine::new();
        let deep = "(".repeat(300) + &")".repeat(300);
        let result = engine.add_pattern(pattern("dlp-redos", &deep));
        assert!(result.is_err());
    }
}
