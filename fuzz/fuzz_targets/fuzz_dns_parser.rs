#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;

use domain::dns::blocklist::{parse_blocklist_feed, BlocklistFeedFormat};
use domain::dns::entity::DomainPattern;
use domain::dns::parser::parse_dns_packet;
use domain::dns::reputation::domain_entropy;

fuzz_target!(|data: &[u8]| {
    // ── DNS packet parsing ──────────────────────────────────────────
    // Binary DNS wire format: header parsing, name decompression,
    // pointer loop detection, record type handling.
    let _ = parse_dns_packet(data, IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let _ = parse_dns_packet(data, IpAddr::V6(Ipv6Addr::LOCALHOST), 0);

    // ── Blocklist feed parsing ──────────────────────────────────────
    // Text-based domain list formats: plaintext and hosts-file.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_blocklist_feed(text, BlocklistFeedFormat::Plaintext);
        let _ = parse_blocklist_feed(text, BlocklistFeedFormat::Hosts);

        // ── Domain pattern parsing ──────────────────────────────────
        // Exact and wildcard (`*.example.com`) domain patterns.
        let _ = DomainPattern::parse(text);

        // ── Domain entropy (DGA detection) ──────────────────────────
        // Shannon entropy computation on second-level label.
        let _ = domain_entropy(text);
    }
});
