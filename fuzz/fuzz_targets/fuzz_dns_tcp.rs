#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::l7::parser::parse_dns_tcp;

// A DNS message over TCP carries its own length prefix, which the sender
// chooses and which need not agree with the bytes that follow.
fuzz_target!(|data: &[u8]| {
    let _ = parse_dns_tcp(data);
});
