use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::entity::{DnsPacket, DnsQuery, DnsRecord, DnsRecordType, DnsResponse, DnsResponseCode};
use super::error::DnsError;

// ── Constants ───────────────────────────────────────────────────────

/// DNS header is always 12 bytes.
const DNS_HEADER_LEN: usize = 12;
/// Maximum label length per RFC 1035.
const MAX_LABEL_LEN: usize = 63;
/// Maximum domain name length per RFC 1035.
const MAX_DOMAIN_LEN: usize = 253;
/// Maximum pointer hops to prevent infinite loops.
const MAX_POINTER_HOPS: usize = 10;
/// Maximum answer records we'll parse per response.
const MAX_ANSWER_RECORDS: u16 = 20;
/// Maximum question entries we'll parse per packet.
const MAX_QUESTIONS: u16 = 10;

// ── Public API ──────────────────────────────────────────────────────

/// Parse a raw DNS payload into a `DnsPacket`.
///
/// `payload` is the raw DNS message bytes (after UDP header).
/// `src_addr` is the source IP of the packet (who sent the DNS message).
/// `timestamp_ns` is the kernel timestamp from the eBPF event.
pub fn parse_dns_packet(
    payload: &[u8],
    src_addr: IpAddr,
    timestamp_ns: u64,
) -> Result<DnsPacket, DnsError> {
    if payload.len() < DNS_HEADER_LEN {
        return Err(DnsError::TruncatedPayload {
            need: DNS_HEADER_LEN,
            got: payload.len(),
        });
    }

    let header = parse_header(payload);

    // QR bit: 0 = query, 1 = response
    if header.is_response {
        parse_response_packet(payload, &header, src_addr, timestamp_ns)
    } else {
        parse_query_packet(payload, &header, src_addr, timestamp_ns)
    }
}

// ── Header parsing ──────────────────────────────────────────────────

struct DnsHeader {
    transaction_id: u16,
    is_response: bool,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

#[allow(clippy::similar_names)] // ancount/arcount are RFC 1035 field names
fn parse_header(payload: &[u8]) -> DnsHeader {
    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags >> 15) & 1 == 1;
    let rcode = (flags & 0x000F) as u8;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);

    DnsHeader {
        transaction_id,
        is_response,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    }
}

// ── Query packet parsing ────────────────────────────────────────────

fn parse_query_packet(
    payload: &[u8],
    header: &DnsHeader,
    src_addr: IpAddr,
    timestamp_ns: u64,
) -> Result<DnsPacket, DnsError> {
    if header.qdcount == 0 {
        return Err(DnsError::MalformedPacket(
            "query with zero questions".to_string(),
        ));
    }
    if header.qdcount > MAX_QUESTIONS {
        return Err(DnsError::TooManyRecords {
            count: header.qdcount,
            max: MAX_QUESTIONS,
        });
    }

    let mut offset = DNS_HEADER_LEN;
    let (domain, new_offset) = parse_name(payload, offset)?;
    offset = new_offset;

    // qtype (2) + qclass (2)
    if offset + 4 > payload.len() {
        return Err(DnsError::TruncatedPayload {
            need: offset + 4,
            got: payload.len(),
        });
    }
    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);

    Ok(DnsPacket::Query(DnsQuery {
        domain,
        query_type: DnsRecordType::from_wire(qtype),
        src_addr,
        timestamp_ns,
    }))
}

// ── Response packet parsing ─────────────────────────────────────────

fn parse_response_packet(
    payload: &[u8],
    header: &DnsHeader,
    src_addr: IpAddr,
    timestamp_ns: u64,
) -> Result<DnsPacket, DnsError> {
    if header.qdcount > MAX_QUESTIONS {
        return Err(DnsError::TooManyRecords {
            count: header.qdcount,
            max: MAX_QUESTIONS,
        });
    }
    if header.ancount > MAX_ANSWER_RECORDS {
        return Err(DnsError::TooManyRecords {
            count: header.ancount,
            max: MAX_ANSWER_RECORDS,
        });
    }

    let mut offset = DNS_HEADER_LEN;

    // Parse question section
    let mut queries = Vec::with_capacity(header.qdcount as usize);
    for _ in 0..header.qdcount {
        let (domain, new_offset) = parse_name(payload, offset)?;
        offset = new_offset;

        if offset + 4 > payload.len() {
            return Err(DnsError::TruncatedPayload {
                need: offset + 4,
                got: payload.len(),
            });
        }
        let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        // skip qclass
        offset += 4;

        queries.push(DnsQuery {
            domain,
            query_type: DnsRecordType::from_wire(qtype),
            src_addr,
            timestamp_ns,
        });
    }

    // Parse answer section
    let mut answers = Vec::with_capacity(header.ancount as usize);
    for _ in 0..header.ancount {
        if offset >= payload.len() {
            break;
        }
        let (record, new_offset) = parse_resource_record(payload, offset, timestamp_ns)?;
        offset = new_offset;
        answers.push(record);
    }

    Ok(DnsPacket::Response(DnsResponse {
        transaction_id: header.transaction_id,
        rcode: DnsResponseCode::from_wire(header.rcode),
        queries,
        answers,
        authority_count: header.nscount,
        additional_count: header.arcount,
    }))
}

// ── Resource record parsing ─────────────────────────────────────────

fn parse_resource_record(
    payload: &[u8],
    offset: usize,
    timestamp_ns: u64,
) -> Result<(DnsRecord, usize), DnsError> {
    let (domain, mut offset) = parse_name(payload, offset)?;

    // type (2) + class (2) + ttl (4) + rdlength (2) = 10 bytes
    if offset + 10 > payload.len() {
        return Err(DnsError::TruncatedPayload {
            need: offset + 10,
            got: payload.len(),
        });
    }

    let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    // skip class
    let ttl = u32::from_be_bytes([
        payload[offset + 4],
        payload[offset + 5],
        payload[offset + 6],
        payload[offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
    offset += 10;

    if offset + rdlength > payload.len() {
        return Err(DnsError::TruncatedPayload {
            need: offset + rdlength,
            got: payload.len(),
        });
    }

    let record_type = DnsRecordType::from_wire(rtype);
    let mut resolved_ips = Vec::new();
    let mut cname_target = None;

    match record_type {
        DnsRecordType::A => {
            if rdlength == 4 {
                let ip = Ipv4Addr::new(
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                );
                resolved_ips.push(IpAddr::V4(ip));
            }
        }
        DnsRecordType::AAAA => {
            if rdlength == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&payload[offset..offset + 16]);
                resolved_ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
        }
        DnsRecordType::CNAME => {
            let (target, _) = parse_name(payload, offset)?;
            cname_target = Some(target);
        }
        _ => {
            // Skip unknown record types
        }
    }

    let next_offset = offset + rdlength;
    let record = DnsRecord {
        domain,
        record_type,
        resolved_ips,
        cname_target,
        ttl,
        timestamp_ns,
    };

    Ok((record, next_offset))
}

// ── DNS name decompression (RFC 1035 section 4.1.4) ─────────────────

/// Parse a DNS domain name starting at `offset` in `payload`.
/// Handles label compression (pointer references).
/// Returns the parsed name and the offset after the name in the wire data.
fn parse_name(payload: &[u8], start_offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut total_len: usize = 0;
    let mut offset = start_offset;
    let mut pointer_hops = 0;
    // The "real" offset to return (advances only for non-pointer labels)
    let mut wire_offset_end: Option<usize> = None;

    loop {
        if offset >= payload.len() {
            return Err(DnsError::TruncatedPayload {
                need: offset + 1,
                got: payload.len(),
            });
        }

        let label_byte = payload[offset];

        // Null label = end of name
        if label_byte == 0 {
            if wire_offset_end.is_none() {
                wire_offset_end = Some(offset + 1);
            }
            break;
        }

        // Compression pointer: top 2 bits = 11
        if label_byte & 0xC0 == 0xC0 {
            if offset + 1 >= payload.len() {
                return Err(DnsError::TruncatedPayload {
                    need: offset + 2,
                    got: payload.len(),
                });
            }
            let pointer = ((label_byte as usize & 0x3F) << 8) | payload[offset + 1] as usize;

            if wire_offset_end.is_none() {
                wire_offset_end = Some(offset + 2);
            }

            pointer_hops += 1;
            if pointer_hops > MAX_POINTER_HOPS {
                return Err(DnsError::CompressionLoop);
            }

            if pointer >= payload.len() {
                return Err(DnsError::MalformedPacket(format!(
                    "compression pointer {pointer} beyond payload length {}",
                    payload.len()
                )));
            }

            offset = pointer;
            continue;
        }

        // Regular label
        let label_len = label_byte as usize;
        if label_len > MAX_LABEL_LEN {
            return Err(DnsError::LabelTooLong { length: label_len });
        }

        if offset + 1 + label_len > payload.len() {
            return Err(DnsError::TruncatedPayload {
                need: offset + 1 + label_len,
                got: payload.len(),
            });
        }

        let label = &payload[offset + 1..offset + 1 + label_len];
        // Normalize to lowercase (DNS is case-insensitive)
        let label_str: String = label
            .iter()
            .map(|&b| (b as char).to_ascii_lowercase())
            .collect();

        // Track total domain name length (labels + dots)
        total_len += label_len;
        if !labels.is_empty() {
            total_len += 1; // dot separator
        }
        if total_len > MAX_DOMAIN_LEN {
            return Err(DnsError::DomainTooLong { length: total_len });
        }

        labels.push(label_str);
        offset += 1 + label_len;
    }

    let name = labels.join(".");
    let end = wire_offset_end.unwrap_or(offset + 1);
    Ok((name, end))
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const TEST_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const TEST_TS: u64 = 1234567890;

    /// Build a DNS header with given fields.
    fn build_header(id: u16, is_response: bool, rcode: u8, qdcount: u16, ancount: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        let mut flags: u16 = 0;
        if is_response {
            flags |= 1 << 15; // QR bit
        }
        flags |= (rcode as u16) & 0x000F;
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
        buf.push(0); // null terminator
        buf
    }

    /// Build a question section entry (name + qtype + qclass).
    fn build_question(domain: &str, qtype: u16) -> Vec<u8> {
        let mut buf = encode_name(domain);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        buf
    }

    /// Build an A resource record.
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

    /// Build an AAAA resource record.
    fn build_aaaa_record(name: &[u8], ttl: u32, ip: [u8; 16]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(name);
        buf.extend_from_slice(&28u16.to_be_bytes()); // type AAAA
        buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&16u16.to_be_bytes()); // rdlength
        buf.extend_from_slice(&ip);
        buf
    }

    /// Build a CNAME resource record.
    fn build_cname_record(name: &[u8], ttl: u32, target_name: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(name);
        buf.extend_from_slice(&5u16.to_be_bytes()); // type CNAME
        buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&(target_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(target_name);
        buf
    }

    // ── Test: standard A query ──────────────────────────────────────

    #[test]
    fn test_parse_a_query() {
        let mut payload = build_header(0x1234, false, 0, 1, 0);
        payload.extend(build_question("example.com", 1));

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Query(q) => {
                assert_eq!(q.domain, "example.com");
                assert_eq!(q.query_type, DnsRecordType::A);
                assert_eq!(q.src_addr, TEST_ADDR);
                assert_eq!(q.timestamp_ns, TEST_TS);
            }
            _ => panic!("expected Query"),
        }
    }

    // ── Test: A response with 2 answers ─────────────────────────────

    #[test]
    fn test_parse_a_response_two_answers() {
        let name_wire = encode_name("example.com");
        let mut payload = build_header(0xABCD, true, 0, 1, 2);
        payload.extend(build_question("example.com", 1));
        payload.extend(build_a_record(&name_wire, 300, [93, 184, 216, 34]));
        payload.extend(build_a_record(&name_wire, 300, [93, 184, 216, 35]));

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Response(r) => {
                assert_eq!(r.transaction_id, 0xABCD);
                assert_eq!(r.rcode, DnsResponseCode::NoError);
                assert_eq!(r.queries.len(), 1);
                assert_eq!(r.queries[0].domain, "example.com");
                assert_eq!(r.answers.len(), 2);
                assert_eq!(
                    r.answers[0].resolved_ips,
                    vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
                );
                assert_eq!(
                    r.answers[1].resolved_ips,
                    vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))]
                );
                assert_eq!(r.answers[0].ttl, 300);
            }
            _ => panic!("expected Response"),
        }
    }

    // ── Test: AAAA response (IPv6) ──────────────────────────────────

    #[test]
    fn test_parse_aaaa_response() {
        let name_wire = encode_name("ipv6.example.com");
        let ipv6_bytes: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let mut payload = build_header(0x0001, true, 0, 1, 1);
        payload.extend(build_question("ipv6.example.com", 28));
        payload.extend(build_aaaa_record(&name_wire, 600, ipv6_bytes));

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Response(r) => {
                assert_eq!(r.answers.len(), 1);
                assert_eq!(r.answers[0].record_type, DnsRecordType::AAAA);
                assert_eq!(
                    r.answers[0].resolved_ips,
                    vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))]
                );
                assert_eq!(r.answers[0].ttl, 600);
            }
            _ => panic!("expected Response"),
        }
    }

    // ── Test: CNAME chain (CNAME → A) ───────────────────────────────

    #[test]
    fn test_parse_cname_chain() {
        let alias_wire = encode_name("www.example.com");
        let target_wire = encode_name("cdn.example.net");
        let mut payload = build_header(0x0002, true, 0, 1, 2);
        payload.extend(build_question("www.example.com", 1));
        payload.extend(build_cname_record(&alias_wire, 3600, &target_wire));
        payload.extend(build_a_record(&target_wire, 60, [1, 2, 3, 4]));

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Response(r) => {
                assert_eq!(r.answers.len(), 2);
                // First answer: CNAME
                assert_eq!(r.answers[0].record_type, DnsRecordType::CNAME);
                assert_eq!(r.answers[0].domain, "www.example.com");
                assert_eq!(
                    r.answers[0].cname_target,
                    Some("cdn.example.net".to_string())
                );
                assert!(r.answers[0].resolved_ips.is_empty());
                // Second answer: A record for the CNAME target
                assert_eq!(r.answers[1].record_type, DnsRecordType::A);
                assert_eq!(r.answers[1].domain, "cdn.example.net");
                assert_eq!(
                    r.answers[1].resolved_ips,
                    vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
                );
            }
            _ => panic!("expected Response"),
        }
    }

    // ── Test: compressed labels ─────────────────────────────────────

    #[test]
    fn test_parse_compressed_labels() {
        // Build a response where the answer name uses a compression pointer
        // back to the question section name.
        let mut payload = build_header(0x0003, true, 0, 1, 1);
        // Question: "example.com" at offset 12
        payload.extend(build_question("example.com", 1));

        // Answer: name is a pointer to offset 12 (the question name)
        let name_offset = 12u16; // offset of "example.com" in the question
        let pointer = [
            0xC0 | ((name_offset >> 8) as u8),
            (name_offset & 0xFF) as u8,
        ];
        let mut answer = Vec::new();
        answer.extend_from_slice(&pointer); // compressed name
        answer.extend_from_slice(&1u16.to_be_bytes()); // type A
        answer.extend_from_slice(&1u16.to_be_bytes()); // class IN
        answer.extend_from_slice(&120u32.to_be_bytes()); // TTL
        answer.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        answer.extend_from_slice(&[10, 0, 0, 1]); // IP
        payload.extend(answer);

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Response(r) => {
                assert_eq!(r.answers.len(), 1);
                assert_eq!(r.answers[0].domain, "example.com");
                assert_eq!(
                    r.answers[0].resolved_ips,
                    vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
                );
                assert_eq!(r.answers[0].ttl, 120);
            }
            _ => panic!("expected Response"),
        }
    }

    // ── Test: truncated payload ─────────────────────────────────────

    #[test]
    fn test_truncated_payload_too_short() {
        let payload = [0u8; 5];
        let err = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap_err();
        assert!(matches!(
            err,
            DnsError::TruncatedPayload { need: 12, got: 5 }
        ));
    }

    #[test]
    fn test_truncated_payload_header_only() {
        // Header says 1 question but no question data follows
        let payload = build_header(0x0000, false, 0, 1, 0);
        let err = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap_err();
        assert!(matches!(err, DnsError::TruncatedPayload { .. }));
    }

    // ── Test: oversized label ───────────────────────────────────────

    #[test]
    fn test_label_too_long() {
        let mut payload = build_header(0x0000, false, 0, 1, 0);
        // Label with length 64 (exceeds max 63)
        payload.push(64);
        payload.extend_from_slice(&[b'a'; 64]);
        payload.push(0);
        payload.extend_from_slice(&1u16.to_be_bytes()); // qtype
        payload.extend_from_slice(&1u16.to_be_bytes()); // qclass

        let err = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap_err();
        assert!(matches!(err, DnsError::LabelTooLong { length: 64 }));
    }

    // ── Test: compression pointer loop ──────────────────────────────

    #[test]
    fn test_compression_pointer_loop() {
        let mut payload = build_header(0x0000, false, 0, 1, 0);
        // Two pointers pointing at each other: offset 12 → offset 14, offset 14 → offset 12
        payload.extend_from_slice(&[0xC0, 14]); // pointer to offset 14
        payload.extend_from_slice(&[0xC0, 12]); // pointer to offset 12

        let err = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap_err();
        assert!(matches!(err, DnsError::CompressionLoop));
    }

    // ── Test: empty response (no answers) ───────────────────────────

    #[test]
    fn test_empty_response() {
        let mut payload = build_header(0x0004, true, 0, 1, 0);
        payload.extend(build_question("noexist.example.com", 1));

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Response(r) => {
                assert_eq!(r.queries.len(), 1);
                assert_eq!(r.queries[0].domain, "noexist.example.com");
                assert!(r.answers.is_empty());
            }
            _ => panic!("expected Response"),
        }
    }

    // ── Test: NXDOMAIN response code ────────────────────────────────

    #[test]
    fn test_nxdomain_response() {
        let mut payload = build_header(0x0005, true, 3, 1, 0);
        payload.extend(build_question("doesnotexist.com", 1));

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Response(r) => {
                assert_eq!(r.rcode, DnsResponseCode::NXDomain);
                assert!(r.answers.is_empty());
            }
            _ => panic!("expected Response"),
        }
    }

    // ── Test: too many answer records ────────────────────────────────

    #[test]
    fn test_too_many_records() {
        let payload = build_header(0x0000, true, 0, 1, 21);
        // We only need the header to trigger the check
        let mut buf = payload;
        buf.extend(build_question("example.com", 1));

        let err = parse_dns_packet(&buf, TEST_ADDR, TEST_TS).unwrap_err();
        assert!(matches!(
            err,
            DnsError::TooManyRecords { count: 21, max: 20 }
        ));
    }

    // ── Test: case-insensitive normalization ─────────────────────────

    #[test]
    fn test_case_normalization() {
        let mut payload = build_header(0x0000, false, 0, 1, 0);
        // Manually encode "EXAMPLE.COM" in uppercase
        payload.push(7);
        payload.extend_from_slice(b"EXAMPLE");
        payload.push(3);
        payload.extend_from_slice(b"COM");
        payload.push(0);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Query(q) => {
                assert_eq!(q.domain, "example.com");
            }
            _ => panic!("expected Query"),
        }
    }

    // ── Test: domain name too long ──────────────────────────────────

    #[test]
    fn test_domain_too_long() {
        let mut payload = build_header(0x0000, false, 0, 1, 0);
        // Build a domain with many labels totaling > 253 chars
        // Each label is 63 chars = "a" * 63, need 4 labels + dots = 4*63 + 3 = 255 > 253
        for _ in 0..4 {
            payload.push(63);
            payload.extend_from_slice(&[b'a'; 63]);
        }
        payload.push(0);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&1u16.to_be_bytes());

        let err = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap_err();
        assert!(matches!(err, DnsError::DomainTooLong { .. }));
    }

    // ── Test: mixed A + AAAA response ───────────────────────────────

    #[test]
    fn test_mixed_a_and_aaaa() {
        let name_wire = encode_name("dual.example.com");
        let ipv6_bytes: [u8; 16] = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        let mut payload = build_header(0x0006, true, 0, 1, 2);
        payload.extend(build_question("dual.example.com", 1));
        payload.extend(build_a_record(&name_wire, 200, [10, 0, 0, 1]));
        payload.extend(build_aaaa_record(&name_wire, 200, ipv6_bytes));

        let result = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap();
        match result {
            DnsPacket::Response(r) => {
                assert_eq!(r.answers.len(), 2);
                assert_eq!(r.answers[0].record_type, DnsRecordType::A);
                assert_eq!(r.answers[1].record_type, DnsRecordType::AAAA);
                assert_eq!(
                    r.answers[1].resolved_ips,
                    vec![IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))]
                );
            }
            _ => panic!("expected Response"),
        }
    }

    // ── Test: query with zero questions ─────────────────────────────

    #[test]
    fn test_query_zero_questions() {
        let payload = build_header(0x0000, false, 0, 0, 0);
        let err = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap_err();
        assert!(matches!(err, DnsError::MalformedPacket(_)));
    }

    // ── Test: compression pointer beyond payload ────────────────────

    #[test]
    fn test_compression_pointer_out_of_bounds() {
        let mut payload = build_header(0x0000, false, 0, 1, 0);
        // Pointer to offset 500 (beyond the payload)
        payload.extend_from_slice(&[0xC1, 0xF4]); // 0xC1F4 → offset 500

        let err = parse_dns_packet(&payload, TEST_ADDR, TEST_TS).unwrap_err();
        assert!(matches!(err, DnsError::MalformedPacket(_)));
    }
}
