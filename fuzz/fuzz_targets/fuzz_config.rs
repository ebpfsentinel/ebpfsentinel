#![no_main]

use libfuzzer_sys::fuzz_target;

use infrastructure::config::AgentConfig;

// Fuzz the configuration parser with arbitrary YAML input.
//
// Exercises serde_yaml_ng deserialization + AgentConfig::validate().
// Must never panic — only return Ok or Err.
fuzz_target!(|data: &[u8]| {
    // Only try UTF-8 valid strings (YAML requires valid text)
    if let Ok(yaml) = std::str::from_utf8(data) {
        // Limit input size to avoid excessive parsing time
        if yaml.len() <= 64 * 1024 {
            let _ = AgentConfig::from_yaml(yaml);
        }
    }
});
