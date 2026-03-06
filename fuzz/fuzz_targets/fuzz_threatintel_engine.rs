#![no_main]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;

use domain::threatintel::engine::ThreatIntelEngine;
use domain::threatintel::entity::{Ioc, ThreatType};

/// Build an IOC from fuzz bytes.
fn ioc_from_bytes(chunk: &[u8]) -> Ioc {
    let ip: IpAddr = if chunk[0] & 1 == 0 {
        IpAddr::V4(Ipv4Addr::new(chunk[1], chunk[2], chunk[3], chunk[4]))
    } else {
        let mut octets = [0u8; 16];
        octets[..5].copy_from_slice(&chunk[..5]);
        IpAddr::V6(Ipv6Addr::from(octets))
    };

    let threat_type = ThreatType::from_u8(chunk[5] % 5);
    let confidence = chunk[6];
    let feed_idx = chunk[7] % 4;
    let feed_id = match feed_idx {
        0 => String::new(), // intentionally invalid
        1 => "feed-a".to_string(),
        2 => "feed-b".to_string(),
        _ => "feed-c".to_string(),
    };
    let last_seen = u64::from_le_bytes([
        chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15],
    ]);

    Ioc {
        ip,
        feed_id: feed_id.clone(),
        confidence,
        threat_type,
        last_seen,
        source_feed: feed_id,
    }
}

// Fuzz the ThreatIntelEngine: add/remove/reload/lookup + country boost.
//
// Layout:
//   [0] = selector (0=CRUD, 1=reload+lookup, 2=country boost)
//   [1] = capacity (1-64)
//   rest = consumed in 16-byte chunks per IOC
fuzz_target!(|data: &[u8]| {
    if data.len() < 18 {
        return;
    }

    let selector = data[0] % 3;
    let capacity = (data[1] as usize % 64) + 1;
    let mut cursor = 2;
    let mut iocs = Vec::new();

    while cursor + 16 <= data.len() && iocs.len() < 32 {
        iocs.push(ioc_from_bytes(&data[cursor..cursor + 16]));
        cursor += 16;
    }

    let mut engine = ThreatIntelEngine::new(capacity);

    match selector {
        // Sub-target 0: add, lookup, remove cycle
        0 => {
            for ioc in &iocs {
                let _ = engine.add_ioc(ioc.clone());
            }
            let _ = engine.ioc_count();
            for ioc in &iocs {
                let _ = engine.lookup(&ioc.ip);
            }
            let _ = engine.iocs_by_feed("feed-a");
            let _ = engine.all_iocs().count();
            for ioc in &iocs {
                let _ = engine.remove_ioc(&ioc.ip);
            }
        }
        // Sub-target 1: reload then lookup
        1 => {
            let _ = engine.reload(iocs.clone());
            let _ = engine.ioc_count();
            for ioc in &iocs {
                let _ = engine.lookup(&ioc.ip);
            }
            // Reload with empty
            let _ = engine.reload(vec![]);
            assert_eq!(engine.ioc_count(), 0);
        }
        // Sub-target 2: country confidence boost
        _ => {
            let mut boost = HashMap::new();
            if let Some(chunk) = iocs.first() {
                // Use first IOC's bytes to build boost values (wrapping cast to avoid overflow)
                boost.insert("RU".to_string(), (chunk.confidence % 128) as i8);
                boost.insert("CN".to_string(), -((chunk.threat_type.to_u8() % 128) as i8));
            }
            engine.set_country_confidence_boost(boost);

            for ioc in &iocs {
                let _ = engine.add_ioc(ioc.clone());
            }
            // Apply boost to all IOCs
            for ioc in &iocs {
                let mut entry = ioc.clone();
                let countries = ["RU", "CN", "US", ""];
                let cc = countries[entry.confidence as usize % countries.len()];
                let before = entry.confidence;
                engine.apply_country_boost(&mut entry, Some(cc));
                // If boost was applied, confidence must be clamped 0-100
                if entry.confidence != before {
                    assert!(entry.confidence <= 100);
                }
            }
            // Apply with None country — must be no-op
            for ioc in &iocs {
                let mut entry = ioc.clone();
                let original = entry.confidence;
                engine.apply_country_boost(&mut entry, None);
                assert_eq!(entry.confidence, original);
            }
        }
    }
});
