#![allow(clippy::cast_possible_truncation)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use domain::l7::parser::{
    detect_protocol, parse_ftp, parse_http, parse_payload, parse_smb, parse_smtp,
    parse_tls_client_hello,
};

// ── HTTP payloads ──────────────────────────────────────────────────────

const HTTP_GET_MINIMAL: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

const HTTP_GET_HEADERS: &[u8] = b"GET /api/v1/users?page=1&limit=50 HTTP/1.1\r\n\
Host: api.example.com\r\n\
Accept: application/json\r\n\
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\r\n\
Content-Type: application/json\r\n\
X-Request-Id: a1b2c3d4-e5f6-7890-abcd-ef1234567890\r\n\
User-Agent: eBPFsentinel-bench/1.0\r\n\
\r\n";

const HTTP_POST: &[u8] = b"POST /api/data HTTP/1.1\r\n\
Host: example.com\r\n\
Content-Type: application/json\r\n\
Content-Length: 42\r\n\
\r\n\
{\"key\":\"value\",\"number\":42,\"active\":true}";

// ── TLS payloads ───────────────────────────────────────────────────────

fn build_tls_client_hello(hostname: &str) -> Vec<u8> {
    let name_bytes = hostname.as_bytes();
    let sni_value_len = 2 + 1 + 2 + name_bytes.len();
    let sni_list_len = 1 + 2 + name_bytes.len();
    let ext_data_len = 4 + sni_value_len;
    let ch_body_len = 2 + 32 + 1 + 4 + 2 + 2 + ext_data_len;
    let hs_len = 4 + ch_body_len;

    let mut pkt = Vec::with_capacity(5 + hs_len);
    pkt.push(0x16);
    pkt.extend_from_slice(&[0x03, 0x01]);
    pkt.extend_from_slice(&(hs_len as u16).to_be_bytes());
    pkt.push(0x01);
    let ch_u32 = ch_body_len as u32;
    pkt.push((ch_u32 >> 16) as u8);
    pkt.push((ch_u32 >> 8) as u8);
    pkt.push(ch_u32 as u8);
    pkt.extend_from_slice(&[0x03, 0x03]);
    pkt.extend_from_slice(&[0xAA; 32]);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
    pkt.push(0x01);
    pkt.push(0x00);
    pkt.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&(sni_value_len as u16).to_be_bytes());
    pkt.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    pkt.push(0x00);
    pkt.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    pkt.extend_from_slice(name_bytes);
    pkt
}

// ── SMTP payloads ──────────────────────────────────────────────────────

const SMTP_EHLO: &[u8] = b"EHLO mail.example.com\r\n";
const SMTP_MAIL_FROM: &[u8] = b"MAIL FROM:<sender@example.com>\r\n";

// ── FTP payloads ───────────────────────────────────────────────────────

const FTP_USER: &[u8] = b"USER anonymous\r\n";
const FTP_RETR: &[u8] = b"RETR /pub/data/report.csv\r\n";

// ── SMB payloads ───────────────────────────────────────────────────────

fn build_smb1() -> Vec<u8> {
    let mut payload = vec![0x00, 0x00, 0x00, 0x20];
    payload.extend_from_slice(b"\xffSMB");
    payload.push(0x72); // Negotiate
    payload.extend_from_slice(&[0x00; 23]);
    payload
}

fn build_smb2() -> Vec<u8> {
    let mut payload = vec![0x00, 0x00, 0x00, 0x40];
    payload.extend_from_slice(b"\xfeSMB");
    payload.extend_from_slice(&[0x00; 8]);
    payload.extend_from_slice(&[0x01, 0x00]); // SESSION_SETUP
    payload.extend_from_slice(&[0x00; 14]);
    payload
}

// ── Benchmarks ─────────────────────────────────────────────────────────

fn bench_detect_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_detect_protocol");
    let tls = build_tls_client_hello("example.com");
    let smb1 = build_smb1();

    group.bench_function("http", |b| {
        b.iter(|| detect_protocol(black_box(HTTP_GET_MINIMAL)));
    });
    group.bench_function("tls", |b| {
        b.iter(|| detect_protocol(black_box(&tls)));
    });
    group.bench_function("smtp", |b| {
        b.iter(|| detect_protocol(black_box(SMTP_EHLO)));
    });
    group.bench_function("ftp", |b| {
        b.iter(|| detect_protocol(black_box(FTP_USER)));
    });
    group.bench_function("smb", |b| {
        b.iter(|| detect_protocol(black_box(&smb1)));
    });
    group.bench_function("unknown", |b| {
        b.iter(|| detect_protocol(black_box(&[0x01, 0x02, 0x03, 0x04])));
    });

    group.finish();
}

fn bench_parse_http(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_parse_http");

    group.bench_function("minimal", |b| {
        b.iter(|| parse_http(black_box(HTTP_GET_MINIMAL)));
    });
    group.bench_function("with_headers", |b| {
        b.iter(|| parse_http(black_box(HTTP_GET_HEADERS)));
    });
    group.bench_function("post", |b| {
        b.iter(|| parse_http(black_box(HTTP_POST)));
    });

    group.finish();
}

fn bench_parse_tls(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_parse_tls");

    let short_sni = build_tls_client_hello("a.com");
    let long_sni = build_tls_client_hello("very-long-subdomain.deep.nested.example.co.uk");

    group.bench_function("short_sni", |b| {
        b.iter(|| parse_tls_client_hello(black_box(&short_sni)));
    });
    group.bench_function("long_sni", |b| {
        b.iter(|| parse_tls_client_hello(black_box(&long_sni)));
    });

    group.finish();
}

fn bench_parse_smtp(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_parse_smtp");

    group.bench_function("ehlo", |b| {
        b.iter(|| parse_smtp(black_box(SMTP_EHLO)));
    });
    group.bench_function("mail_from", |b| {
        b.iter(|| parse_smtp(black_box(SMTP_MAIL_FROM)));
    });

    group.finish();
}

fn bench_parse_ftp(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_parse_ftp");

    group.bench_function("user", |b| {
        b.iter(|| parse_ftp(black_box(FTP_USER)));
    });
    group.bench_function("retr", |b| {
        b.iter(|| parse_ftp(black_box(FTP_RETR)));
    });

    group.finish();
}

fn bench_parse_smb(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_parse_smb");

    let smb1 = build_smb1();
    let smb2 = build_smb2();

    group.bench_function("smb1", |b| {
        b.iter(|| parse_smb(black_box(&smb1)));
    });
    group.bench_function("smb2", |b| {
        b.iter(|| parse_smb(black_box(&smb2)));
    });

    group.finish();
}

fn bench_parse_payload(c: &mut Criterion) {
    let mut group = c.benchmark_group("l7_parse_payload");
    let tls = build_tls_client_hello("api.example.com");

    group.bench_function("http", |b| {
        b.iter(|| parse_payload(black_box(HTTP_GET_HEADERS)));
    });
    group.bench_function("tls", |b| {
        b.iter(|| parse_payload(black_box(&tls)));
    });
    group.bench_function("smtp", |b| {
        b.iter(|| parse_payload(black_box(SMTP_EHLO)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_detect_protocol,
    bench_parse_http,
    bench_parse_tls,
    bench_parse_smtp,
    bench_parse_ftp,
    bench_parse_smb,
    bench_parse_payload
);
criterion_main!(benches);
