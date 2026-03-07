#![allow(clippy::cast_possible_truncation)]

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use domain::dns::parser::parse_dns_packet;

const TEST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
const TEST_TS: u64 = 1_234_567_890;

/// Build a DNS header with given fields.
fn build_header(id: u16, is_response: bool, rcode: u8, qdcount: u16, ancount: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    let mut flags: u16 = 0;
    if is_response {
        flags |= 1 << 15;
    }
    flags |= u16::from(rcode) & 0x000F;
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&qdcount.to_be_bytes());
    buf.extend_from_slice(&ancount.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
    buf
}

/// Encode a domain name as DNS wire format labels.
fn encode_name(domain: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf
}

fn build_question(domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = encode_name(domain);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    buf
}

fn build_a_record(name: &[u8], ttl: u32, ip: [u8; 4]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(name);
    buf.extend_from_slice(&1u16.to_be_bytes()); // type A
    buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
    buf.extend_from_slice(&ttl.to_be_bytes());
    buf.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    buf.extend_from_slice(&ip);
    buf
}

/// Build a DNS query packet for a given domain.
fn build_query_packet(domain: &str) -> Vec<u8> {
    let mut payload = build_header(0x1234, false, 0, 1, 0);
    payload.extend(build_question(domain, 1));
    payload
}

/// Build a DNS A response with N answer records.
fn build_response_packet(domain: &str, n_answers: u16) -> Vec<u8> {
    let name_wire = encode_name(domain);
    let mut payload = build_header(0xABCD, true, 0, 1, n_answers);
    payload.extend(build_question(domain, 1));
    for i in 0..n_answers {
        let ip = [10, 0, (i >> 8) as u8, (i & 0xFF) as u8];
        payload.extend(build_a_record(&name_wire, 300, ip));
    }
    payload
}

/// Build a response using a compression pointer for the answer name.
fn build_compressed_response(domain: &str) -> Vec<u8> {
    let mut payload = build_header(0x0003, true, 0, 1, 1);
    payload.extend(build_question(domain, 1));
    // Answer name: pointer to offset 12 (question name)
    let pointer = [0xC0, 12];
    payload.extend_from_slice(&pointer);
    payload.extend_from_slice(&1u16.to_be_bytes()); // type A
    payload.extend_from_slice(&1u16.to_be_bytes()); // class IN
    payload.extend_from_slice(&120u32.to_be_bytes()); // TTL
    payload.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    payload.extend_from_slice(&[10, 0, 0, 1]); // IP
    payload
}

fn bench_parse_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_parse_query");

    for domain in &[
        "a.com",
        "example.com",
        "very.deep.nested.subdomain.example.co.uk",
    ] {
        let packet = build_query_packet(domain);
        group.bench_with_input(BenchmarkId::from_parameter(domain), &packet, |b, packet| {
            b.iter(|| parse_dns_packet(black_box(packet), TEST_ADDR, TEST_TS));
        });
    }

    group.finish();
}

fn bench_parse_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_parse_response");

    for &n_answers in &[1, 5, 10, 20] {
        let packet = build_response_packet("example.com", n_answers);
        group.bench_with_input(
            BenchmarkId::new("answers", n_answers),
            &packet,
            |b, packet| {
                b.iter(|| parse_dns_packet(black_box(packet), TEST_ADDR, TEST_TS));
            },
        );
    }

    group.finish();
}

fn bench_parse_compressed(c: &mut Criterion) {
    let packet = build_compressed_response("example.com");
    c.bench_function("dns_parse_compressed_response", |b| {
        b.iter(|| parse_dns_packet(black_box(&packet), TEST_ADDR, TEST_TS));
    });
}

criterion_group!(
    benches,
    bench_parse_query,
    bench_parse_response,
    bench_parse_compressed
);
criterion_main!(benches);
