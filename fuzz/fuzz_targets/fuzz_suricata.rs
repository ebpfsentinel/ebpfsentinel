#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::ids::engine::IdsEngine;
use domain::ids::suricata::{SuricataVars, compile_ruleset};
use ebpf_common::event::PacketEvent;

// The rule text is the whole input. Whatever compiles must load into the
// engine and be evaluated against the input itself as a TCP segment, so a
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
    let mut engine = IdsEngine::new();
    if let Err(e) = engine.reload(compiled.rules) {
        panic!("a compiled rule did not load: {e}");
    }
    // A connection from its handshake on, carrying the input as one segment
    // then closed: each rule is read on the packets and on the stream.
    let payload = &data[..data.len().min(1400)];
    let len = payload.len() as u32;
    let (client, server) = (([10, 0, 0, 1], 40000), ([203, 0, 113, 9], 80));
    let steps: [(_, _, u32, u32, u8, &[u8]); 6] = [
        (client, server, 1000, 0, 0x02, b""),
        (server, client, 5000, 1001, 0x12, b""),
        (client, server, 1001, 5001, 0x10, b""),
        (client, server, 1001, 5001, 0x18, payload),
        (server, client, 5001, 1001 + len, 0x10, b""),
        (client, server, 1001 + len, 5001, 0x11, b""),
    ];
    for (n, ((src, sport), (dst, dport), seq, ack, flags, bytes)) in steps.into_iter().enumerate() {
        let total = (40 + bytes.len()) as u16;
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0]);
        packet.extend_from_slice(&src);
        packet.extend_from_slice(&dst);
        packet.extend_from_slice(&u16::to_be_bytes(sport));
        packet.extend_from_slice(&u16::to_be_bytes(dport));
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&ack.to_be_bytes());
        packet.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        packet.extend_from_slice(bytes);
        let event = PacketEvent {
            timestamp_ns: n as u64,
            src_addr: [u32::from_be_bytes(src), 0, 0, 0],
            dst_addr: [u32::from_be_bytes(dst), 0, 0, 0],
            src_port: sport,
            dst_port: dport,
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
            pkt_len: u32::from(total) + 14,
            _pad: 0,
        };
        let _ = engine.evaluate_packet(&event, &packet, None);
    }
    let _ = engine.flush_all();
});
