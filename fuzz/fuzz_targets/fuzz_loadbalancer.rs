#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;

use domain::common::entity::RuleId;
use domain::loadbalancer::engine::LbEngine;
use domain::loadbalancer::entity::{LbAlgorithm, LbBackend, LbProtocol, LbService};

// Fuzz the LbEngine with random services, backend selection, connection
// tracking, and health transitions.
//
// Layout:
//   [0] = selector (0=service CRUD, 1=selection+connections, 2=mixed lifecycle)
//   rest = consumed in chunks per operation
fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let selector = data[0] % 3;
    let mut cursor = 1;

    // Parse services from fuzz data (10 bytes per service, up to 8 services)
    let mut services = Vec::new();
    while cursor + 10 <= data.len() && services.len() < 8 {
        let chunk = &data[cursor..cursor + 10];
        cursor += 10;

        let protocol = match chunk[0] % 3 {
            0 => LbProtocol::Tcp,
            1 => LbProtocol::Udp,
            _ => LbProtocol::TlsPassthrough,
        };

        let algorithm = match chunk[1] % 4 {
            0 => LbAlgorithm::RoundRobin,
            1 => LbAlgorithm::Weighted,
            2 => LbAlgorithm::IpHash,
            _ => LbAlgorithm::LeastConn,
        };

        let listen_port = u16::from_le_bytes([chunk[2], chunk[3]]);
        // Avoid port 0 which is rejected by validation
        let listen_port = if listen_port == 0 { 1 } else { listen_port };

        let backend_count = (chunk[4] % 4) + 1; // 1..=4 backends
        let mut backends = Vec::new();
        for i in 0..backend_count {
            let weight = u32::from(chunk[5 + (i as usize) % 5]).max(1);
            backends.push(LbBackend {
                id: format!("be-{}-{i}", services.len()),
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, services.len() as u8, i + 1)),
                port: 8080 + u16::from(i),
                weight,
                enabled: chunk[9] & (1 << (i % 8)) == 0 || i == 0, // ensure at least one enabled
            });
        }

        let id = format!("svc-fuzz-{}", services.len());
        let service = LbService {
            id: RuleId(id),
            name: format!("fuzz-service-{}", services.len()),
            protocol,
            listen_port,
            algorithm,
            backends,
            enabled: chunk[8] & 1 == 0,
            health_check: None,
        };
        services.push(service);
    }

    let mut engine = LbEngine::new();

    match selector {
        // Sub-target 0: service CRUD
        0 => {
            for service in &services {
                let _ = engine.add_service(service.clone());
            }
            let _ = engine.service_count();
            let _ = engine.services();
            for service in &services {
                let _ = engine.backend_states(&service.id.0);
                let _ = engine.remove_service(&service.id);
            }
            // Reload
            let _ = engine.reload(services);
        }
        // Sub-target 1: backend selection + connection tracking + health
        1 => {
            for service in &services {
                let _ = engine.add_service(service.clone());
            }

            let mut event_cursor = cursor;
            while event_cursor + 4 <= data.len() {
                let eb = &data[event_cursor..event_cursor + 4];
                event_cursor += 4;

                let op = eb[0] % 4;
                let svc_idx = (eb[1] as usize) % services.len().max(1);
                let svc_id = format!("svc-fuzz-{svc_idx}");

                match op {
                    // Select backend
                    0 => {
                        let client_addr = [u32::from(eb[2]), u32::from(eb[3]), 0, 0];
                        let _ = engine.select_backend(&svc_id, client_addr);
                    }
                    // Record connection
                    1 => {
                        let be_idx = eb[2] % 4;
                        let be_id = format!("be-{svc_idx}-{be_idx}");
                        let _ = engine.record_connection(&svc_id, &be_id);
                    }
                    // Release connection
                    2 => {
                        let be_idx = eb[2] % 4;
                        let be_id = format!("be-{svc_idx}-{be_idx}");
                        let _ = engine.release_connection(&svc_id, &be_id);
                    }
                    // Health update
                    _ => {
                        let be_idx = eb[2] % 4;
                        let be_id = format!("be-{svc_idx}-{be_idx}");
                        let healthy = eb[3] & 1 != 0;
                        let threshold = u32::from(eb[3] >> 1).max(1);
                        let _ = engine.update_backend_health(&svc_id, &be_id, healthy, threshold);
                    }
                }
            }

            // Query final state
            let _ = engine.service_count();
            let _ = engine.services();
            for service in &services {
                let _ = engine.backend_states(&service.id.0);
            }
        }
        // Sub-target 2: mixed lifecycle (CRUD + selection + health interleaved)
        _ => {
            let mid = services.len() / 2;
            for service in &services[..mid] {
                let _ = engine.add_service(service.clone());
            }
            let _ = engine.reload(services[mid..].to_vec());

            let mut event_cursor = cursor;
            while event_cursor + 3 <= data.len() {
                let eb = &data[event_cursor..event_cursor + 3];
                event_cursor += 3;

                let svc_idx = (eb[0] as usize) % services.len().max(1);
                let svc_id = format!("svc-fuzz-{svc_idx}");
                let be_idx = eb[1] % 4;
                let be_id = format!("be-{svc_idx}-{be_idx}");

                match eb[2] % 5 {
                    0 => {
                        let client_addr = [u32::from(eb[0]) ^ u32::from(eb[1]), 0, 0, 0];
                        let _ = engine.select_backend(&svc_id, client_addr);
                    }
                    1 => {
                        let _ = engine.record_connection(&svc_id, &be_id);
                    }
                    2 => {
                        let _ = engine.release_connection(&svc_id, &be_id);
                    }
                    3 => {
                        let healthy = eb[1] & 1 != 0;
                        let threshold = u32::from(eb[1] >> 4).max(1);
                        let _ = engine.update_backend_health(&svc_id, &be_id, healthy, threshold);
                    }
                    _ => {
                        // Remove and re-add a service
                        let _ = engine.remove_service(&RuleId(svc_id.clone()));
                        if svc_idx < services.len() {
                            let _ = engine.add_service(services[svc_idx].clone());
                        }
                    }
                }
            }

            let _ = engine.service_count();
            let _ = engine.services();
        }
    }
});
