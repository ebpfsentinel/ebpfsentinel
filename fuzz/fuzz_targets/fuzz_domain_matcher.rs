#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::l7::domain_matcher::DomainMatcher;

// Fuzz the DomainMatcher: pattern compilation and matching.
//
// Layout:
//   [0]        = selector (0=new, 1=exact, 2=new+match, 3=serde roundtrip)
//   [1]        = pattern_len
//   [2..2+len] = pattern bytes
//   rest       = domain strings to match against (null-separated)
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let selector = data[0] % 4;
    let pattern_len = (data[1] as usize).min(data.len() - 2);
    let pattern_bytes = &data[2..2 + pattern_len];

    // Only try UTF-8 valid patterns
    let Ok(pattern) = std::str::from_utf8(pattern_bytes) else {
        return;
    };

    match selector {
        // Sub-target 0: DomainMatcher::new() — exercise all pattern types
        0 => {
            let _ = DomainMatcher::new(pattern);
        }
        // Sub-target 1: DomainMatcher::exact()
        1 => {
            let _ = DomainMatcher::exact(pattern);
        }
        // Sub-target 2: compile pattern then match against fuzzed domains
        2 => {
            if let Ok(matcher) = DomainMatcher::new(pattern) {
                let rest = &data[2 + pattern_len..];
                // Split remaining bytes on null to get domain strings
                for domain_bytes in rest.split(|&b| b == 0) {
                    if let Ok(domain) = std::str::from_utf8(domain_bytes) {
                        let _ = matcher.matches(domain);
                    }
                }
            }
        }
        // Sub-target 3: serde roundtrip
        _ => {
            if let Ok(matcher) = DomainMatcher::new(pattern) {
                if let Ok(json) = serde_json::to_string(&matcher) {
                    let _ = serde_json::from_str::<DomainMatcher>(&json);
                }
            }
        }
    }
});
