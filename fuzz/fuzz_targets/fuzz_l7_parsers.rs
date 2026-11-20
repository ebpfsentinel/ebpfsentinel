#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::l7::crypto_posture::clear_text_request;
use domain::l7::handshake::read_server_flight;
use domain::l7::ja4::compute_ja4;
use domain::l7::parser::{
    detect_protocol, parse_dns_tcp, parse_ftp, parse_grpc, parse_http, parse_imap, parse_mysql,
    parse_payload, parse_pop3, parse_postgres, parse_redis, parse_smb, parse_smtp, parse_ssh,
    parse_tls_client_hello, parse_tls_server_hello,
};

fn is_hex_section(section: &str) -> bool {
    section.len() == 12 && section.bytes().all(|b| b.is_ascii_hexdigit())
}

fuzz_target!(|data: &[u8]| {
    let _ = parse_payload(data);

    let _ = detect_protocol(data);
    let _ = parse_http(data);
    let _ = parse_grpc(data);
    let _ = parse_smtp(data);
    let _ = parse_ftp(data);
    let _ = parse_smb(data);
    let _ = parse_ssh(data);
    let _ = parse_redis(data);
    let _ = parse_mysql(data);
    let _ = parse_postgres(data);
    let _ = parse_dns_tcp(data);
    let _ = parse_imap(data);
    let _ = parse_pop3(data);
    let _ = parse_tls_server_hello(data);
    let _ = read_server_flight(data);
    for label in ["http", "redis", "smtp", "postgres", "unknown"] {
        let _ = clear_text_request(label, data);
    }

    // Every hello the parser accepts is fingerprinted on the live path, so the
    // fingerprint must hold its shape whatever the hello carries: a readable
    // ten-character prefix, two twelve-digit hex sections, joined by `_`, and
    // the same answer twice.
    if let Ok(hello) = parse_tls_client_hello(data) {
        let fp = compute_ja4(&hello);
        assert_eq!(fp.ja4_a.len(), 10, "section a {:?}", fp.ja4_a);
        assert!(fp.ja4_a.is_ascii(), "section a {:?}", fp.ja4_a);
        assert!(is_hex_section(&fp.ja4_b), "section b {:?}", fp.ja4_b);
        assert!(is_hex_section(&fp.ja4_c), "section c {:?}", fp.ja4_c);
        assert_eq!(fp.ja4, format!("{}_{}_{}", fp.ja4_a, fp.ja4_b, fp.ja4_c));
        assert_eq!(fp, compute_ja4(&hello));
    }
});
