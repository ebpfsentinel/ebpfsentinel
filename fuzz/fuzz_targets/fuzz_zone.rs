#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::zone::entity::{Zone, ZoneConfig, ZonePair, ZonePolicy};

// Fuzz the zone subsystem: ZoneConfig validation, interface overlap detection,
// zone pair reference checking, lookups.
//
// Layout:
//   [0]    = selector (0=validate, 1=lookups, 2=zone pairs)
//   [1]    = number of zones (1–8)
//   rest   = consumed in chunks (zones + pairs)
fuzz_target!(|data: &[u8]| {
    if data.len() < 14 {
        return;
    }

    let selector = data[0] % 3;
    let num_zones = ((data[1] as usize) % 8) + 1;
    let mut cursor = 2;

    // Parse zones (4 bytes each: id_byte, iface1, iface2, policy)
    let mut zones = Vec::new();
    for _ in 0..num_zones {
        if cursor + 4 > data.len() {
            break;
        }
        let chunk = &data[cursor..cursor + 4];
        cursor += 4;

        let id = if chunk[0] == 0 {
            // Empty ID to test validation
            String::new()
        } else {
            format!("zone-{}", chunk[0])
        };

        let mut interfaces = Vec::new();
        if chunk[1] != 0 {
            interfaces.push(format!("eth{}", chunk[1]));
        }
        if chunk[2] != 0 && chunk[2] != chunk[1] {
            interfaces.push(format!("eth{}", chunk[2]));
        }
        // Possibly empty interfaces to test validation

        let default_policy = if chunk[3] & 1 == 0 {
            ZonePolicy::Allow
        } else {
            ZonePolicy::Deny
        };

        zones.push(Zone {
            id,
            interfaces,
            default_policy,
        });
    }

    // Parse zone pairs (3 bytes each: from_idx, to_idx, policy)
    let mut zone_policies = Vec::new();
    while cursor + 3 <= data.len() && zone_policies.len() < 16 {
        let chunk = &data[cursor..cursor + 3];
        cursor += 3;

        let from = if chunk[0] == 0 {
            String::new()
        } else if !zones.is_empty() {
            zones[(chunk[0] as usize) % zones.len()].id.clone()
        } else {
            format!("zone-{}", chunk[0])
        };

        let to = if chunk[1] == 0 {
            String::new()
        } else if !zones.is_empty() {
            zones[(chunk[1] as usize) % zones.len()].id.clone()
        } else {
            format!("zone-{}", chunk[1])
        };

        let policy = if chunk[2] & 1 == 0 {
            ZonePolicy::Allow
        } else {
            ZonePolicy::Deny
        };

        zone_policies.push(ZonePair {
            from,
            to,
            policy,
        });
    }

    let config = ZoneConfig {
        zones,
        zone_policies,
    };

    match selector {
        // Sub-target 0: validate config (exercises duplicate, overlap, ref checks)
        0 => {
            let _ = config.validate();
        }
        // Sub-target 1: validate then do lookups
        1 => {
            let _ = config.validate();

            // Lookup interfaces from fuzz data
            for &byte in &data[cursor.min(data.len())..] {
                let iface = format!("eth{byte}");
                let _ = config.zone_for_interface(&iface);
            }

            // Lookup policies between zones
            for z1 in &config.zones {
                for z2 in &config.zones {
                    let _ = config.policy(&z1.id, &z2.id);
                }
            }
        }
        // Sub-target 2: validate individual zones and pairs
        _ => {
            for zone in &config.zones {
                let _ = zone.validate();
            }
            for pair in &config.zone_policies {
                let _ = pair.validate();
            }
            let _ = config.validate();

            // Exercise zone_for_interface with empty/special
            let _ = config.zone_for_interface("");
            let _ = config.zone_for_interface("lo");
            let _ = config.zone_for_interface("nonexistent-iface-12345");
        }
    }
});
