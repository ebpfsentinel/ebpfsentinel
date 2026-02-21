#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::l7::parser::{
    detect_protocol, parse_ftp, parse_grpc, parse_http, parse_payload, parse_smb, parse_smtp,
    parse_tls_client_hello,
};

fuzz_target!(|data: &[u8]| {
    // Top-level dispatcher — must never panic on any input.
    let _ = parse_payload(data);

    // Individual parsers — each must gracefully handle arbitrary bytes.
    let _ = detect_protocol(data);
    let _ = parse_http(data);
    let _ = parse_tls_client_hello(data);
    let _ = parse_grpc(data);
    let _ = parse_smtp(data);
    let _ = parse_ftp(data);
    let _ = parse_smb(data);
});
