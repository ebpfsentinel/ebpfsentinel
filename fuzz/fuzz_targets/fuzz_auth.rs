#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::auth::entity::JwtClaims;
use domain::auth::rbac::Role;

// Fuzz the auth subsystem: Role parsing, JwtClaims deserialization, namespace
// access checks.
//
// Layout:
//   [0]    = selector (0=Role::from_str, 1=JwtClaims JSON, 2=namespace checks)
//   rest   = fuzz input
fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    let selector = data[0] % 3;

    match selector {
        // Sub-target 0: Role::from_str with arbitrary strings
        0 => {
            let s = String::from_utf8_lossy(&data[1..]);
            let _ = s.parse::<Role>();

            // Also test Display roundtrip for valid roles
            for role in [Role::Admin, Role::Operator, Role::Viewer] {
                let s = role.to_string();
                let parsed: Result<Role, _> = s.parse();
                let _ = parsed;
            }
        }
        // Sub-target 1: JwtClaims JSON deserialization
        1 => {
            // Try deserializing arbitrary bytes as JSON -> JwtClaims
            if let Ok(claims) = serde_json::from_slice::<JwtClaims>(&data[1..]) {
                let _ = claims.role();
                let _ = claims.has_namespace("default");
                let _ = claims.has_namespace("");
            }

            // Also try with structured JSON from fuzz bytes
            if data.len() >= 10 {
                let sub_len = (data[1] as usize % 20) + 1;
                let sub: String = data[2..].iter()
                    .take(sub_len)
                    .map(|b| (b % 26 + b'a') as char)
                    .collect();

                let exp = u64::from_le_bytes([
                    data[2], data[3], data[4], data[5],
                    data[6], data[7], data[8], data[9],
                ]);

                let role_str = match data[1] % 4 {
                    0 => "admin",
                    1 => "operator",
                    2 => "viewer",
                    _ => "unknown",
                };

                let json = format!(
                    r#"{{"sub":"{}","exp":{},"role":"{}"}}"#,
                    sub, exp, role_str
                );

                if let Ok(claims) = serde_json::from_str::<JwtClaims>(&json) {
                    let _ = claims.role();
                    let _ = claims.has_namespace("test-ns");
                }
            }
        }
        // Sub-target 2: namespace access checks with varied claims
        _ => {
            let mut cursor = 1;

            while cursor + 6 <= data.len() {
                let chunk = &data[cursor..cursor + 6];
                cursor += 6;

                let has_ns = chunk[0] & 1 != 0;
                let ns_count = (chunk[1] % 4) as usize;

                let namespaces = if has_ns {
                    let mut ns = Vec::new();
                    for i in 0..ns_count {
                        ns.push(format!("ns-{}", (chunk[2 + i % 4]) % 10));
                    }
                    Some(ns)
                } else {
                    None
                };

                let role_str = match chunk[2] % 4 {
                    0 => Some("admin".to_string()),
                    1 => Some("operator".to_string()),
                    2 => Some("viewer".to_string()),
                    _ => None,
                };

                let claims = JwtClaims {
                    sub: format!("user-{}", chunk[3]),
                    exp: u64::from(u16::from_le_bytes([chunk[4], chunk[5]])),
                    iat: 0,
                    iss: None,
                    aud: None,
                    role: role_str,
                    namespaces,
                };

                let _ = claims.role();
                let _ = claims.has_namespace("default");
                let _ = claims.has_namespace(&format!("ns-{}", chunk[3] % 10));
                let _ = claims.has_namespace("");
            }
        }
    }
});
