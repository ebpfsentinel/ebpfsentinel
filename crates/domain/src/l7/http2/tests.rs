use super::*;

/// Two gRPC calls curl sent on one connection, written by
/// `tests/fixtures/http2/make-captures.sh`.
const TWO_GRPC_CALLS: &[u8] =
    include_bytes!("../../../tests/fixtures/http2/curl-two-grpc-calls.bin");

/// Two GET requests curl sent on one connection, same script.
const TWO_GETS: &[u8] = include_bytes!("../../../tests/fixtures/http2/curl-two-gets.bin");

fn flow() -> FlowId {
    FlowId::new([10, 0, 0, 0], [10, 0, 0, 1], 40_000, 50_051, false)
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "every caller passes it straight to `offer`, which takes the option"
)]
fn seg(tcp_seq: u32, wire_len: usize) -> Option<L7Segment> {
    Some(L7Segment {
        tcp_seq,
        wire_len: u32::try_from(wire_len).unwrap(),
    })
}

fn grpc_calls(requests: &[Http2Request]) -> Vec<(String, String)> {
    requests
        .iter()
        .filter_map(Http2Request::grpc)
        .map(|g| (g.service, g.method))
        .collect()
}

fn expected_grpc() -> Vec<(String, String)> {
    vec![
        ("admin.AdminService".into(), "DeleteUser".into()),
        ("helloworld.Greeter".into(), "SayHello".into()),
    ]
}

/// Offset at which the second request's HEADERS frame starts.
fn second_headers_at(capture: &[u8]) -> usize {
    let mut pos = PREFACE.len();
    let mut seen = 0;
    loop {
        let len = usize::from(capture[pos]) << 16
            | usize::from(capture[pos + 1]) << 8
            | usize::from(capture[pos + 2]);
        if capture[pos + 3] == FRAME_HEADERS {
            seen += 1;
            if seen == 2 {
                return pos;
            }
        }
        pos += FRAME_HEADER_LEN + len;
    }
}

#[test]
fn the_capture_hides_the_path_from_a_byte_scan() {
    // The path is Huffman-coded, so its text is nowhere in the bytes.
    assert!(
        !TWO_GRPC_CALLS
            .windows(b"AdminService".len())
            .any(|w| w == b"AdminService")
    );
}

#[test]
fn curl_grpc_calls_decode_in_one_buffer() {
    let requests = read_buffer(TWO_GRPC_CALLS);
    assert_eq!(grpc_calls(&requests), expected_grpc());
    assert_eq!(requests[0].stream_id, 1);
    assert_eq!(requests[1].stream_id, 3);
    assert_eq!(requests[0].method, "POST");
    // The second request takes its authority from the dynamic table.
    assert_eq!(
        requests[1].authority.as_deref(),
        Some(requests[0].authority.as_deref().unwrap())
    );
    assert!(
        requests[1]
            .authority
            .as_deref()
            .unwrap()
            .starts_with("grpc.internal:")
    );
}

#[test]
fn curl_gets_decode_as_http_requests() {
    let requests = read_buffer(TWO_GETS);
    let parsed: Vec<_> = requests
        .into_iter()
        .map(Http2Request::into_parsed)
        .collect();
    let paths: Vec<_> = parsed
        .iter()
        .map(|p| match p {
            ParsedProtocol::Http(h) => (h.method.as_str(), h.path.as_str(), h.version.as_str()),
            other => panic!("expected HTTP, got {other:?}"),
        })
        .collect();
    assert_eq!(
        paths,
        vec![
            ("GET", "/api/v1/users?page=2", "HTTP/2"),
            ("GET", "/admin/delete", "HTTP/2"),
        ]
    );
}

#[test]
fn every_split_into_two_segments_reads_the_same() {
    // The segment that opens the connection carries the whole preface.
    for cut in PREFACE.len()..TWO_GRPC_CALLS.len() {
        let mut tracker = Http2Connections::default();
        let mut requests = Vec::new();
        for (seq, part) in [
            (1000u32, &TWO_GRPC_CALLS[..cut]),
            (1000 + cut as u32, &TWO_GRPC_CALLS[cut..]),
        ] {
            match tracker.offer(flow(), seg(seq, part.len()), part) {
                Offer::Tracked {
                    requests: r,
                    failed: None,
                    ..
                } => requests.extend(r),
                other => panic!("cut {cut}: {other:?}"),
            }
        }
        assert_eq!(grpc_calls(&requests), expected_grpc(), "cut {cut}");
    }
}

#[test]
fn byte_by_byte_without_segments_reads_the_same() {
    let mut connection = Connection::new();
    let mut requests = Vec::new();
    for byte in TWO_GRPC_CALLS.chunks(1) {
        connection.read_segment(None, byte, &mut requests).unwrap();
    }
    assert_eq!(grpc_calls(&requests), expected_grpc());
}

#[test]
fn a_retransmitted_segment_is_read_once() {
    let cut = second_headers_at(TWO_GRPC_CALLS);
    let (head, tail) = TWO_GRPC_CALLS.split_at(cut);
    let mut tracker = Http2Connections::default();
    let mut requests = Vec::new();
    let tail_seq = 7 + cut as u32;
    for (seq, part) in [(7u32, head), (7, head), (tail_seq, tail), (tail_seq, tail)] {
        if let Offer::Tracked {
            requests: r,
            failed,
            ..
        } = tracker.offer(flow(), seg(seq, part.len()), part)
        {
            assert_eq!(failed, None);
            requests.extend(r);
        }
    }
    assert_eq!(grpc_calls(&requests), expected_grpc());
}

#[test]
fn an_overlapping_segment_reads_only_its_new_bytes() {
    let mut tracker = Http2Connections::default();
    let mut requests = Vec::new();
    let first = &TWO_GRPC_CALLS[..100];
    let overlapping = &TWO_GRPC_CALLS[60..];
    for (seq, part) in [(0u32, first), (60, overlapping)] {
        if let Offer::Tracked {
            requests: r,
            failed,
            ..
        } = tracker.offer(flow(), seg(seq, part.len()), part)
        {
            assert_eq!(failed, None);
            requests.extend(r);
        }
    }
    assert_eq!(grpc_calls(&requests), expected_grpc());
}

#[test]
fn sequence_numbers_wrap() {
    let start = u32::MAX - 50;
    let mut tracker = Http2Connections::default();
    let mut requests = Vec::new();
    let (head, tail) = TWO_GRPC_CALLS.split_at(120);
    for (seq, part) in [(start, head), (start.wrapping_add(120), tail)] {
        if let Offer::Tracked {
            requests: r,
            failed,
            ..
        } = tracker.offer(flow(), seg(seq, part.len()), part)
        {
            assert_eq!(failed, None);
            requests.extend(r);
        }
    }
    assert_eq!(grpc_calls(&requests), expected_grpc());
}

/// Build a connection: preface, an empty SETTINGS, a HEADERS frame from
/// `block`, then a DATA frame of `data_len` bytes, then HEADERS again.
fn with_big_data(data_len: usize) -> (Vec<u8>, usize, usize) {
    let block = {
        // :method POST, :scheme http, literal :path, content-type grpc.
        let mut b = vec![0x83, 0x86, 0x44, 0x0f];
        b.extend_from_slice(b"/pkg.Svc/Method");
        b.extend_from_slice(&[0x5f, 0x10]);
        b.extend_from_slice(b"application/grpc");
        b
    };
    let frame = |kind: u8, flags: u8, stream: u32, payload: &[u8]| {
        let len = payload.len();
        let mut f = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, kind, flags];
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    };
    let mut bytes = PREFACE.to_vec();
    bytes.extend(frame(0x4, 0, 0, &[]));
    bytes.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block));
    let data_at = bytes.len() + FRAME_HEADER_LEN;
    bytes.extend(frame(0x0, 0x1, 1, &vec![0xab; data_len]));
    let data_end = bytes.len();
    bytes.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &block));
    (bytes, data_at, data_end)
}

#[test]
fn bytes_lost_inside_a_data_payload_cost_nothing() {
    let (bytes, data_at, data_end) = with_big_data(6000);
    let mut tracker = Http2Connections::default();
    let mut requests = Vec::new();
    // The capture keeps 2048 bytes of each 3000-byte segment.
    let mut seq = 0usize;
    while seq < bytes.len() {
        let wire = 3000.min(bytes.len() - seq);
        let kept = &bytes[seq..seq + wire.min(2048)];
        if let Offer::Tracked {
            requests: r,
            failed,
            ..
        } = tracker.offer(flow(), seg(seq as u32, wire), kept)
        {
            assert_eq!(failed, None, "segment at {seq}");
            requests.extend(r);
        }
        seq += wire;
    }
    assert!(data_at < 3000 && data_end > 6000);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].grpc().unwrap().method, "Method");
}

#[test]
fn a_lost_segment_inside_a_data_payload_costs_nothing() {
    let (bytes, data_at, data_end) = with_big_data(6000);
    let mut tracker = Http2Connections::default();
    let mut requests = Vec::new();
    let lost_from = data_at + 100;
    let lost_to = data_end - 100;
    for (from, to) in [(0, lost_from), (lost_to, bytes.len())] {
        if let Offer::Tracked {
            requests: r,
            failed,
            ..
        } = tracker.offer(flow(), seg(from as u32, to - from), &bytes[from..to])
        {
            assert_eq!(failed, None);
            requests.extend(r);
        }
    }
    assert_eq!(requests.len(), 2);
}

#[test]
fn a_lost_header_block_stops_the_connection_once() {
    let cut = second_headers_at(TWO_GRPC_CALLS);
    let mut tracker = Http2Connections::default();
    let first = &TWO_GRPC_CALLS[..cut + 4];
    let after = &TWO_GRPC_CALLS[cut + 20..];
    assert!(matches!(
        tracker.offer(flow(), seg(0, first.len()), first),
        Offer::Tracked { failed: None, .. }
    ));
    assert_eq!(
        tracker.offer(flow(), seg((cut + 20) as u32, after.len()), after),
        Offer::Tracked {
            requests: Vec::new(),
            failed: Some(Unreadable::LostBytes),
            evicted: false,
        }
    );
    // Later segments are claimed by the connection but read nothing.
    assert_eq!(
        tracker.offer(flow(), seg(TWO_GRPC_CALLS.len() as u32, 4), b"\0\0\0\0"),
        Offer::Tracked {
            requests: Vec::new(),
            failed: None,
            evicted: false,
        }
    );
}

#[test]
fn a_truncated_header_block_stops_the_connection() {
    let cut = second_headers_at(TWO_GRPC_CALLS);
    let mut tracker = Http2Connections::default();
    // The segment holding the second HEADERS was longer on the wire.
    let kept = &TWO_GRPC_CALLS[..cut + 12];
    assert!(matches!(
        tracker.offer(flow(), seg(0, cut + 40), kept),
        Offer::Tracked {
            failed: Some(Unreadable::LostBytes),
            ..
        }
    ));
}

#[test]
fn a_flow_without_the_preface_is_not_tracked() {
    let mut tracker = Http2Connections::default();
    assert_eq!(
        tracker.offer(flow(), seg(0, 18), b"GET / HTTP/1.1\r\n\r\n"),
        Offer::Untracked
    );
    assert!(tracker.is_empty());
}

#[test]
fn a_new_preface_on_the_same_flow_starts_over() {
    let mut tracker = Http2Connections::default();
    let cut = second_headers_at(TWO_GRPC_CALLS) + 3;
    tracker.offer(flow(), seg(0, cut), &TWO_GRPC_CALLS[..cut]);
    // The port was reused: a new connection opens with another sequence.
    match tracker.offer(flow(), seg(90_000, TWO_GRPC_CALLS.len()), TWO_GRPC_CALLS) {
        Offer::Tracked {
            requests,
            failed: None,
            ..
        } => {
            assert_eq!(grpc_calls(&requests), expected_grpc());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_oldest_connection_is_dropped_past_capacity() {
    let mut tracker = Http2Connections::new(1);
    let other = FlowId::new([10, 0, 0, 2], [10, 0, 0, 1], 40_001, 50_051, false);
    tracker.offer(flow(), seg(0, PREFACE.len()), PREFACE);
    assert!(matches!(
        tracker.offer(other, seg(0, PREFACE.len()), PREFACE),
        Offer::Tracked { evicted: true, .. }
    ));
    assert_eq!(tracker.len(), 1);
}

#[test]
fn a_continuation_frame_completes_a_header_block() {
    let block = [0x83, 0x86, 0x44, 0x05, b'/', b'a', b'/', b'b', b'c'];
    let mut bytes = PREFACE.to_vec();
    // HEADERS with the first four bytes, no END_HEADERS; padded, priority.
    let mut headers = vec![2u8];
    headers.extend_from_slice(&[0, 0, 0, 0, 16]);
    headers.extend_from_slice(&block[..4]);
    headers.extend_from_slice(&[0, 0]);
    let len = headers.len();
    bytes.extend_from_slice(&[
        0,
        0,
        len as u8,
        FRAME_HEADERS,
        FLAG_PADDED | FLAG_PRIORITY,
        0,
        0,
        0,
        5,
    ]);
    bytes.extend_from_slice(&headers);
    bytes.extend_from_slice(&[0, 0, 5, FRAME_CONTINUATION, FLAG_END_HEADERS, 0, 0, 0, 5]);
    bytes.extend_from_slice(&block[4..]);
    let requests = read_buffer(&bytes);
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/a/bc");
    assert_eq!(requests[0].stream_id, 5);
}

#[test]
fn a_frame_inside_a_header_block_is_refused() {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&[0, 0, 1, FRAME_HEADERS, 0, 0, 0, 0, 1, 0x83]);
    bytes.extend_from_slice(&[0, 0, 0, 0x8, 0, 0, 0, 0, 0]);
    let mut connection = Connection::new();
    assert_eq!(
        connection.read_segment(None, &bytes, &mut Vec::new()),
        Err(Unreadable::BadFrame)
    );
    assert_eq!(connection.failed(), Some(Unreadable::BadFrame));
}

#[test]
fn a_header_block_past_the_cap_is_refused() {
    let mut bytes = PREFACE.to_vec();
    let len = MAX_HEADER_BLOCK + 1024;
    bytes.extend_from_slice(&[
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        FRAME_HEADERS,
        FLAG_END_HEADERS,
        0,
        0,
        0,
        1,
    ]);
    assert_eq!(
        Connection::new().read_segment(None, &bytes, &mut Vec::new()),
        Err(Unreadable::TooLarge)
    );
}

#[test]
fn grpc_needs_the_grpc_content_type() {
    let mut request = read_buffer(TWO_GRPC_CALLS).remove(0);
    request.content_type = Some("application/json".into());
    assert_eq!(request.grpc(), None);
    assert!(matches!(request.into_parsed(), ParsedProtocol::Http(_)));
}

#[test]
fn grpc_path_needs_two_segments() {
    assert_eq!(grpc_path("/svc"), None);
    assert_eq!(grpc_path("/svc/"), None);
    assert_eq!(grpc_path("/a/b/c"), None);
    assert_eq!(grpc_path("svc/m"), None);
    assert_eq!(
        grpc_path("/pkg.Svc/M"),
        Some(GrpcRequest {
            service: "pkg.Svc".into(),
            method: "M".into()
        })
    );
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let mut bytes = PREFACE.to_vec();
            bytes.extend(tail);
            let _ = read_buffer(&bytes);
        }

        #[test]
        fn arbitrary_segments_never_panic(
            parts in proptest::collection::vec(
                (any::<u32>(), 0u32..5000, proptest::collection::vec(any::<u8>(), 0..300)),
                0..12,
            )
        ) {
            let mut tracker = Http2Connections::new(4);
            tracker.offer(flow(), seg(0, PREFACE.len()), PREFACE);
            for (seq, wire, bytes) in parts {
                let _ = tracker.offer(flow(), Some(L7Segment { tcp_seq: seq, wire_len: wire }), &bytes);
            }
        }

        #[test]
        fn any_split_of_the_capture_reads_both_calls(cuts in proptest::collection::btree_set(24usize..316, 0..8)) {
            let mut tracker = Http2Connections::default();
            let mut requests = Vec::new();
            let mut from = 0;
            for to in cuts.into_iter().chain([TWO_GRPC_CALLS.len()]) {
                if to <= from || to > TWO_GRPC_CALLS.len() { continue; }
                if let Offer::Tracked { requests: r, failed, .. } = tracker.offer(flow(), seg(from as u32, to - from), &TWO_GRPC_CALLS[from..to]) {
                    prop_assert_eq!(failed, None);
                    requests.extend(r);
                }
                from = to;
            }
            prop_assert_eq!(grpc_calls(&requests), expected_grpc());
        }
    }
}
