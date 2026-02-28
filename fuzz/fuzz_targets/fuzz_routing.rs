#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::routing::entity::{Gateway, GatewayState, HealthCheck, HealthCheckProto};

// Fuzz the routing subsystem: GatewayState transitions (record_success/failure),
// threshold edge cases, counter overflow.
//
// Layout:
//   [0]    = selector (0=success/failure sequence, 1=alternating, 2=threshold edge)
//   [1..5] = failure_threshold (u32)
//   [5..9] = recovery_threshold (u32)
//   rest   = event stream (1 byte per event: 0=failure, 1=success)
fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }

    let selector = data[0] % 3;

    let failure_threshold = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let recovery_threshold = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);

    let gateway = Gateway {
        id: data[9],
        name: format!("gw-fuzz-{}", data[9]),
        interface: format!("eth{}", data[10] % 4),
        gateway_ip: format!(
            "{}.{}.{}.1",
            data[10],
            data[11],
            data[9]
        ),
        priority: u32::from(data[10]),
        enabled: data[11] & 1 == 0,
        health_check: if data[11] & 2 != 0 {
            Some(HealthCheck {
                target: format!("{}.{}.{}.1", data[10], data[11], data[9]),
                protocol: if data[11] & 4 != 0 {
                    HealthCheckProto::Tcp {
                        port: u16::from_le_bytes([data[9], data[10]]),
                    }
                } else {
                    HealthCheckProto::Icmp
                },
                ..HealthCheck::default()
            })
        } else {
            None
        },
    };

    let mut state = GatewayState::new(gateway);
    let cursor = 12;

    match selector {
        // Sub-target 0: pure failure sequence then success sequence
        0 => {
            let mid = (data.len() - cursor) / 2 + cursor;
            for _ in cursor..mid {
                state.record_failure(failure_threshold);
                let _ = state.is_usable();
            }
            for _ in mid..data.len() {
                state.record_success(recovery_threshold);
                let _ = state.is_usable();
            }
        }
        // Sub-target 1: alternating success/failure driven by bytes
        1 => {
            for &byte in &data[cursor..] {
                if byte & 1 == 0 {
                    state.record_failure(failure_threshold);
                } else {
                    state.record_success(recovery_threshold);
                }
                let _ = state.is_usable();
            }
        }
        // Sub-target 2: rapid threshold edge testing
        _ => {
            // Drive to failure threshold boundary
            for _ in 0..failure_threshold.min(1000) {
                state.record_failure(failure_threshold);
            }
            let _ = state.is_usable();

            // Then recover
            for _ in 0..recovery_threshold.min(1000) {
                state.record_success(recovery_threshold);
            }
            let _ = state.is_usable();

            // Then interleave from remaining data
            for &byte in &data[cursor..] {
                match byte % 3 {
                    0 => state.record_failure(failure_threshold),
                    1 => state.record_success(recovery_threshold),
                    _ => {
                        let _ = state.is_usable();
                    }
                }
            }
        }
    }
});
