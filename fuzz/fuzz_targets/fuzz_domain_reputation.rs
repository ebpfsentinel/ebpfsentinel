#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::dns::entity::ReputationConfig;
use domain::dns::entity::ReputationFactor;
use domain::dns::reputation::DomainReputationEngine;

// Fuzz the DomainReputationEngine: updates, scoring, LRU eviction, auto-block.
//
// Layout:
//   [0]    = max_tracked_domains (1–50)
//   [1]    = auto_block_threshold byte (threshold = byte / 255.0)
//   [2]    = flags (bit 0: auto_block_enabled)
//   rest   = consumed in 12-byte chunks as reputation events
fuzz_target!(|data: &[u8]| {
    if data.len() < 15 {
        return;
    }

    let max_tracked = ((data[0] as usize) % 50) + 1;
    let threshold = (data[1] as f64) / 255.0;
    let auto_block_enabled = data[2] & 1 != 0;

    let config = ReputationConfig {
        enabled: true,
        max_tracked_domains: max_tracked,
        auto_block_threshold: threshold,
        auto_block_enabled,
        auto_block_ttl_secs: 3600,
        decay_half_life_hours: 24,
    };

    let mut engine = DomainReputationEngine::new(config);
    let mut cursor = 3;

    // Domain name pool to exercise both new entries and updates to existing ones
    let domains = [
        "evil.com",
        "malware.example.org",
        "clean-site.net",
        "dga-a1b2c3d4e5.biz",
        "legitimate-corp.io",
        "tracker.ads.co",
        "phishing.bank-login.info",
        "cdn.trusted.com",
    ];

    while cursor + 12 <= data.len() {
        let chunk = &data[cursor..cursor + 12];
        cursor += 12;

        let domain = domains[(chunk[0] as usize) % domains.len()];
        let now_ns = u64::from_le_bytes([
            chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7], chunk[8],
        ]);

        let factor = match chunk[9] % 6 {
            0 => ReputationFactor::BlocklistHit {
                list_name: format!("list-{}", chunk[10] % 5),
            },
            1 => ReputationFactor::CtiMatch {
                feed_name: format!("feed-{}", chunk[10] % 3),
                threat_type: match chunk[11] % 4 {
                    0 => "c2".to_string(),
                    1 => "malware".to_string(),
                    2 => "phishing".to_string(),
                    _ => "botnet".to_string(),
                },
            },
            2 => ReputationFactor::HighEntropy {
                entropy: (chunk[10] as f64) / 50.0,
            },
            3 => ReputationFactor::ShortTtl {
                avg_ttl: u64::from(chunk[10]) * 10,
            },
            4 => ReputationFactor::L7RuleMatch {
                rule_id: format!("l7-{}", chunk[10] % 10),
            },
            _ => ReputationFactor::FrequentQueries {
                rate_per_min: (chunk[10] as f64) / 10.0,
            },
        };

        let _score = engine.update(domain, factor, now_ns);

        // Occasionally exercise other methods
        if chunk[11] % 4 == 0 {
            engine.record_connection(domain, now_ns);
        }
        if chunk[11] % 8 == 0 {
            let _ = engine.list_high_risk(0.5, now_ns);
        }
        if chunk[11] % 16 == 0 {
            let _ = engine.get_auto_block_candidates(now_ns);
        }
        if chunk[11] % 32 == 0 {
            let _ = engine.stats(now_ns);
        }
    }

    // Final operations
    let final_ns = u64::MAX / 2;
    let _ = engine.tracked_count();
    let _ = engine.auto_block_threshold();
    let _ = engine.list_all(0, 10, final_ns);
    let _ = engine.get_auto_block_candidates(final_ns);
});
