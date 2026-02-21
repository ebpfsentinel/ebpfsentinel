#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::common::entity::{DomainMode, RuleId, Severity};
use domain::dlp::engine::DlpEngine;
use domain::dlp::entity::DlpPattern;

/// Pre-built engine with realistic DLP patterns (SSN, credit card, email, etc.).
fn build_engine() -> DlpEngine {
    let patterns = [
        ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
        ("cc-visa", r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        ("cc-mc", r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        ("aws-key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("ipv4", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ];

    let mut engine = DlpEngine::new();
    for (id, regex) in &patterns {
        let pattern = DlpPattern {
            id: RuleId(id.to_string()),
            name: format!("fuzz-{id}"),
            description: String::new(),
            regex: regex.to_string(),
            severity: Severity::Medium,
            mode: DomainMode::Alert,
            data_type: "custom".to_string(),
            enabled: true,
        };
        engine.add_pattern(pattern).unwrap();
    }
    engine
}

fuzz_target!(|data: &[u8]| {
    // Use a thread-local engine to avoid rebuilding on every iteration.
    thread_local! {
        static ENGINE: DlpEngine = build_engine();
    }

    ENGINE.with(|engine| {
        let _ = engine.scan_data(data);
    });
});
