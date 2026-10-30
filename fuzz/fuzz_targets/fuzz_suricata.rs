#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::ids::engine::IdsEngine;
use domain::ids::suricata::{SuricataVars, compile_ruleset};
use ebpf_common::event::PacketEvent;

// The rule text is the whole input. Whatever compiles must load into the
// engine and be evaluated against the input itself as a payload, so a
// pattern the compiler wrote and the matcher cannot read is a crash here
// rather than an agent refusing its own import.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let compiled = compile_ruleset(text, &SuricataVars::default());
    assert_eq!(
        compiled.report.total,
        compiled.report.compiled + compiled.report.refused.len()
    );
    if compiled.rules.is_empty() {
        return;
    }
    let ports: Vec<(Option<u16>, Option<u16>)> = compiled
        .rules
        .iter()
        .map(|rule| (rule.src_port, rule.dst_port))
        .collect();
    let mut engine = IdsEngine::new();
    if let Err(e) = engine.reload(compiled.rules) {
        panic!("a compiled rule did not load: {e}");
    }
    for (src_port, dst_port) in ports {
        let event = PacketEvent {
            timestamp_ns: 0,
            src_addr: [0x0a00_0001, 0, 0, 0],
            dst_addr: [0xcb00_7109, 0, 0, 0],
            src_port: src_port.unwrap_or(40000),
            dst_port: dst_port.unwrap_or(40000),
            protocol: 6,
            event_type: 0,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            cgroup1_id: 0,
            rss_hash: 0,
            rss_hash_type: 0,
            rx_hw_timestamp_ns: 0,
        };
        let _ = engine.evaluate_payload_with_context(&event, data, None);
    }
});
