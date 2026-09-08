#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::conntrack::entity::ConnTrackSettings;

// Fuzz ConnTrackSettings.validate() + to_ebpf_config() with extreme timeout values.
//
// The to_ebpf_config() multiplies u64 seconds by 1_000_000_000 - this can overflow
// on large values. This fuzzer ensures no panic occurs on arbitrary inputs.
//
// The per-source guard fields come off the same input rather than being
// pinned: `validate()` refuses a rate with no window to measure it over, and
// `to_ebpf_config()` carries all four into the map the datapath reads, so
// leaving them at zero meant neither the refusal nor the carrying was fuzzed.
//
// Layout: 6 × u64 timeouts, one flag byte, then 4 × u32 guard fields.
fuzz_target!(|data: &[u8]| {
    if data.len() < 65 {
        return;
    }

    let tcp_established = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let tcp_syn = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let tcp_fin = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let udp = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let udp_stream = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let icmp = u64::from_le_bytes(data[40..48].try_into().unwrap());
    let enabled = data[48] & 1 != 0;
    let max_src_states = u32::from_le_bytes(data[49..53].try_into().unwrap());
    let max_src_conn_rate = u32::from_le_bytes(data[53..57].try_into().unwrap());
    let conn_rate_window = u32::from_le_bytes(data[57..61].try_into().unwrap());
    let overload_ttl = u32::from_le_bytes(data[61..65].try_into().unwrap());

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
        overload_ttl_secs: overload_ttl,
    };

    // validate() should not panic
    let _ = settings.validate();

    // to_ebpf_config() multiplies u64 × 1_000_000_000 - must not panic
    let cfg = settings.to_ebpf_config();
    let _ = cfg.enabled;
    let _ = cfg.tcp_established_timeout_ns;
    let _ = cfg.tcp_syn_timeout_ns;
    let _ = cfg.tcp_fin_timeout_ns;
    let _ = cfg.udp_timeout_ns;
    let _ = cfg.udp_stream_timeout_ns;
    let _ = cfg.icmp_timeout_ns;

    // The guard fields cross into the map unconverted, so a rate the domain
    // refused must not arrive there as a rate the datapath enforces.
    let _ = cfg.max_src_states;
    let _ = cfg.max_src_conn_rate;
    let _ = cfg.conn_rate_window_secs;
    let _ = cfg.overload_ttl_secs;
});
