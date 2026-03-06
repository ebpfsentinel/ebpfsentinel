#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::conntrack::entity::ConnTrackSettings;

// Fuzz ConnTrackSettings.validate() + to_ebpf_config() with extreme timeout values.
//
// The to_ebpf_config() multiplies u64 seconds by 1_000_000_000 — this can overflow
// on large values. This fuzzer ensures no panic occurs on arbitrary inputs.
//
// Layout: 56 bytes per settings struct (7 × u64 timeout fields)
fuzz_target!(|data: &[u8]| {
    if data.len() < 49 {
        return;
    }

    let tcp_established = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let tcp_syn = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let tcp_fin = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let udp = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let udp_stream = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let icmp = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let enabled = data[48] & 1 != 0;
    let max_src_states = 0;
    let max_src_conn_rate = 0;
    let conn_rate_window = 5;

    let settings = ConnTrackSettings {
        enabled,
        tcp_established_timeout_secs: tcp_established,
        tcp_syn_timeout_secs: tcp_syn,
        tcp_fin_timeout_secs: tcp_fin,
        udp_timeout_secs: udp,
        udp_stream_timeout_secs: udp_stream,
        icmp_timeout_secs: icmp,
        max_src_states,
        max_src_conn_rate,
        conn_rate_window_secs: conn_rate_window,
        overload_ttl_secs: 3600,
    };

    // validate() should not panic
    let _ = settings.validate();

    // to_ebpf_config() multiplies u64 × 1_000_000_000 — must not panic
    let cfg = settings.to_ebpf_config();
    let _ = cfg.enabled;
    let _ = cfg.tcp_established_timeout_ns;
    let _ = cfg.tcp_syn_timeout_ns;
    let _ = cfg.tcp_fin_timeout_ns;
    let _ = cfg.udp_timeout_ns;
    let _ = cfg.udp_stream_timeout_ns;
    let _ = cfg.icmp_timeout_ns;
});
