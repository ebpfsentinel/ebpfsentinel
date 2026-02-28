#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::conntrack::entity::{ConnTrackSettings, ConnectionState};

// Fuzz the conntrack subsystem: ConnectionState roundtrip, ConnTrackSettings
// validation, eBPF config conversion (overflow testing).
//
// Layout:
//   [0]    = selector (0=state roundtrip, 1=settings validate, 2=ebpf conversion)
//   rest   = consumed per operation
fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    let selector = data[0] % 3;

    match selector {
        // Sub-target 0: ConnectionState from_u8 roundtrip for all byte values
        0 => {
            for &byte in &data[1..] {
                let state = ConnectionState::from_u8(byte);
                let back = state.to_u8();
                let _ = state.as_str();
                let _ = format!("{state}");

                // Valid values should roundtrip
                if byte <= 8 && byte != 3 {
                    assert_eq!(ConnectionState::from_u8(back).to_u8(), back);
                }
            }
        }
        // Sub-target 1: ConnTrackSettings validation with fuzzed timeouts
        1 => {
            let mut cursor = 1;
            while cursor + 48 <= data.len() {
                let chunk = &data[cursor..cursor + 48];
                cursor += 48;

                let settings = ConnTrackSettings {
                    enabled: chunk[0] & 1 != 0,
                    tcp_established_timeout_secs: u64::from_le_bytes([
                        chunk[1], chunk[2], chunk[3], chunk[4],
                        chunk[5], chunk[6], chunk[7], chunk[8],
                    ]),
                    tcp_syn_timeout_secs: u64::from_le_bytes([
                        chunk[9], chunk[10], chunk[11], chunk[12],
                        chunk[13], chunk[14], chunk[15], chunk[16],
                    ]),
                    tcp_fin_timeout_secs: u64::from_le_bytes([
                        chunk[17], chunk[18], chunk[19], chunk[20],
                        chunk[21], chunk[22], chunk[23], chunk[24],
                    ]),
                    udp_timeout_secs: u64::from_le_bytes([
                        chunk[25], chunk[26], chunk[27], chunk[28],
                        chunk[29], chunk[30], chunk[31], chunk[32],
                    ]),
                    udp_stream_timeout_secs: u64::from_le_bytes([
                        chunk[33], chunk[34], chunk[35], chunk[36],
                        chunk[37], chunk[38], chunk[39], chunk[40],
                    ]),
                    icmp_timeout_secs: u64::from_le_bytes([
                        chunk[41], chunk[42], chunk[43], chunk[44],
                        chunk[45], chunk[46], chunk[47], chunk[40],
                    ]),
                    max_src_states: u32::from_le_bytes([chunk[1], chunk[5], chunk[9], chunk[13]]),
                    max_src_conn_rate: u32::from_le_bytes([chunk[2], chunk[6], chunk[10], chunk[14]]),
                    conn_rate_window_secs: u32::from_le_bytes([chunk[3], chunk[7], chunk[11], chunk[15]]),
                    overload_ttl_secs: u32::from_le_bytes([chunk[4], chunk[8], chunk[12], chunk[16]]),
                };

                let _ = settings.validate();
            }
        }
        // Sub-target 2: validate then convert to eBPF config (overflow exercise)
        _ => {
            let mut cursor = 1;
            while cursor + 48 <= data.len() {
                let chunk = &data[cursor..cursor + 48];
                cursor += 48;

                let settings = ConnTrackSettings {
                    enabled: chunk[0] & 1 != 0,
                    tcp_established_timeout_secs: u64::from_le_bytes([
                        chunk[1], chunk[2], chunk[3], chunk[4],
                        chunk[5], chunk[6], chunk[7], chunk[8],
                    ]),
                    tcp_syn_timeout_secs: u64::from_le_bytes([
                        chunk[9], chunk[10], chunk[11], chunk[12],
                        chunk[13], chunk[14], chunk[15], chunk[16],
                    ]),
                    tcp_fin_timeout_secs: u64::from_le_bytes([
                        chunk[17], chunk[18], chunk[19], chunk[20],
                        chunk[21], chunk[22], chunk[23], chunk[24],
                    ]),
                    udp_timeout_secs: u64::from_le_bytes([
                        chunk[25], chunk[26], chunk[27], chunk[28],
                        chunk[29], chunk[30], chunk[31], chunk[32],
                    ]),
                    udp_stream_timeout_secs: u64::from_le_bytes([
                        chunk[33], chunk[34], chunk[35], chunk[36],
                        chunk[37], chunk[38], chunk[39], chunk[40],
                    ]),
                    icmp_timeout_secs: u64::from_le_bytes([
                        chunk[41], chunk[42], chunk[43], chunk[44],
                        chunk[45], chunk[46], chunk[47], chunk[40],
                    ]),
                    max_src_states: 0,
                    max_src_conn_rate: 0,
                    conn_rate_window_secs: 5,
                    overload_ttl_secs: 3600,
                };

                if settings.validate().is_ok() {
                    // Exercise eBPF conversion — may overflow on large timeout values
                    let _ = settings.to_ebpf_config();
                }
            }
        }
    }
});
