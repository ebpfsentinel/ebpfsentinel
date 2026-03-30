#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::dlp::engine::DlpEngine;
use domain::dlp::entity::default_patterns;

/// Pre-built engine using the built-in DLP patterns (SSN, credit card, email, etc.).
fn build_engine() -> DlpEngine {
    let mut engine = DlpEngine::new();
    for pattern in default_patterns() {
        let _ = engine.add_pattern(pattern);
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
