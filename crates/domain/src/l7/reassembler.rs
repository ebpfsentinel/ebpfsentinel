//! TCP stream reassembly for L7 protocol parsing.
//!
//! eBPF captures at most `MAX_L7_PAYLOAD` bytes per RingBuf event, so large
//! HTTP POST bodies, multi-frame gRPC messages, and multi-packet SQL queries
//! arrive in pieces. `StreamReassembler` stitches them back together in
//! userspace before handing the reconstructed buffer to [`parse_payload`].
//!
//! Design goals:
//!
//! - **Pure, single-threaded friendly.** All state is guarded by a single
//!   `Mutex<LruCache>`; there is no async work inside the reassembler
//!   itself. Callers drive it from the packet pipeline task.
//! - **Bounded memory.** `max_flows` caps the number of in-flight flows
//!   (LRU eviction), and `max_buffer_per_flow` caps per-flow byte count.
//!   With the defaults (1 000 flows × 16 KiB) the total footprint stays
//!   under 16 MiB regardless of traffic.
//! - **Protocol-aware completion.** HTTP/1.x is detected via
//!   `Content-Length:` so full request/response bodies trigger an
//!   immediate emit; everything else falls back to the idle-timeout
//!   flush driven by the caller.
//!
//! [`parse_payload`]: crate::l7::parser::parse_payload

use std::num::NonZeroUsize;
use std::sync::Mutex;

use lru::LruCache;
use serde::{Deserialize, Serialize};

/// 5-tuple identifier for a TCP flow. Protocol is always TCP in practice
/// (L7 capture is TCP-only), but we keep the field so IPv6 vs IPv4 and
/// future UDP flows do not collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowId {
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub is_ipv6: bool,
}

impl FlowId {
    /// Convenience constructor matching the packet pipeline's `PacketEvent`
    /// field order.
    pub fn new(
        src_addr: [u32; 4],
        dst_addr: [u32; 4],
        src_port: u16,
        dst_port: u16,
        is_ipv6: bool,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            is_ipv6,
        }
    }
}

/// Tunables for the reassembler. All fields are capped at config load
/// time — zero/negative values are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReassemblerConfig {
    /// Maximum number of tracked flows. Oldest flow is evicted on overflow.
    pub max_flows: usize,
    /// Maximum bytes retained per flow. Additional bytes are dropped.
    pub max_buffer_per_flow: usize,
    /// Idle timeout in nanoseconds. Flows not seeing new bytes for this
    /// long are considered complete and returned by `flush_expired`.
    pub idle_timeout_ns: u64,
}

impl Default for ReassemblerConfig {
    fn default() -> Self {
        Self {
            max_flows: 1_000,
            max_buffer_per_flow: 16 * 1024,
            idle_timeout_ns: 5 * 1_000_000_000,
        }
    }
}

#[derive(Debug, Clone)]
struct FlowBuffer {
    bytes: Vec<u8>,
    last_seen_ns: u64,
}

/// Outcome returned by [`StreamReassembler::ingest`].
///
/// `Complete` means the reassembler recognised a protocol boundary and
/// the caller should parse the returned bytes now. `Pending` means the
/// bytes were buffered and no boundary was detected — the next call or
/// an `flush_expired` sweep may emit them later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingest {
    Complete(Vec<u8>),
    Pending,
}

/// Stream reassembler.
pub struct StreamReassembler {
    config: ReassemblerConfig,
    flows: Mutex<LruCache<FlowId, FlowBuffer>>,
}

impl StreamReassembler {
    pub fn new(config: ReassemblerConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_flows.max(1)).expect("max(1) > 0");
        Self {
            config,
            flows: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn config(&self) -> &ReassemblerConfig {
        &self.config
    }

    pub fn flow_count(&self) -> usize {
        self.flows.lock().map(|lock| lock.len()).unwrap_or(0)
    }

    /// Append `payload` to the flow's buffer. Returns [`Ingest::Complete`]
    /// when a protocol boundary is recognised (currently: HTTP/1.x
    /// `Content-Length` request/response), otherwise [`Ingest::Pending`].
    ///
    /// `now_ns` is the caller's notion of "now" in nanoseconds —
    /// `PacketEvent::timestamp_ns` or `CLOCK_MONOTONIC` are both fine.
    pub fn ingest(&self, flow: FlowId, payload: &[u8], now_ns: u64) -> Ingest {
        if payload.is_empty() {
            return Ingest::Pending;
        }
        let Ok(mut lock) = self.flows.lock() else {
            return Ingest::Pending;
        };

        let limit = self.config.max_buffer_per_flow;
        if let Some(buf) = lock.get_mut(&flow) {
            let room = limit.saturating_sub(buf.bytes.len());
            let take = payload.len().min(room);
            buf.bytes.extend_from_slice(&payload[..take]);
            buf.last_seen_ns = now_ns;
        } else {
            let mut bytes = Vec::with_capacity(payload.len().min(limit));
            bytes.extend_from_slice(&payload[..payload.len().min(limit)]);
            lock.put(
                flow,
                FlowBuffer {
                    bytes,
                    last_seen_ns: now_ns,
                },
            );
        }

        // Check HTTP Content-Length completion after the update.
        if let Some(buf) = lock.peek(&flow)
            && http_is_complete(&buf.bytes)
        {
            if let Some(entry) = lock.pop(&flow) {
                return Ingest::Complete(entry.bytes);
            }
        }

        Ingest::Pending
    }

    /// Drop and return every flow whose last ingest is older than the
    /// configured idle timeout. Called on a periodic sweep by the caller.
    ///
    /// The returned buffers may be partial (truncated at
    /// `max_buffer_per_flow`). Callers that still want to parse them can
    /// feed them to [`parse_payload`] — the protocol parser tolerates
    /// truncated data.
    ///
    /// [`parse_payload`]: crate::l7::parser::parse_payload
    pub fn flush_expired(&self, now_ns: u64) -> Vec<(FlowId, Vec<u8>)> {
        let Ok(mut lock) = self.flows.lock() else {
            return Vec::new();
        };
        let timeout = self.config.idle_timeout_ns;

        let expired_flows: Vec<FlowId> = lock
            .iter()
            .filter_map(|(flow, buf)| {
                if now_ns.saturating_sub(buf.last_seen_ns) >= timeout {
                    Some(*flow)
                } else {
                    None
                }
            })
            .collect();

        let mut out = Vec::with_capacity(expired_flows.len());
        for flow in expired_flows {
            if let Some(entry) = lock.pop(&flow) {
                out.push((flow, entry.bytes));
            }
        }
        out
    }

    /// Drain a specific flow unconditionally. Useful when the caller
    /// already knows the flow is complete (e.g. TCP FIN observed).
    pub fn take(&self, flow: FlowId) -> Option<Vec<u8>> {
        let mut lock = self.flows.lock().ok()?;
        lock.pop(&flow).map(|entry| entry.bytes)
    }
}

/// Check whether the buffered bytes contain a full HTTP/1.x message
/// (header terminator `\r\n\r\n` + `Content-Length` bytes of body).
///
/// This is deliberately conservative: chunked encoding, HTTP/2 framing,
/// and responses without `Content-Length` return `false` and let the
/// idle-timeout flush handle them.
fn http_is_complete(buf: &[u8]) -> bool {
    let Some(header_end) = find_double_crlf(buf) else {
        return false;
    };
    let headers = &buf[..header_end];
    let body_start = header_end + 4; // skip "\r\n\r\n"
    let Some(content_length) = extract_content_length(headers) else {
        return false;
    };
    body_start
        .checked_add(content_length)
        .is_some_and(|end| buf.len() >= end)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Case-insensitive `Content-Length:` value extractor. Returns `None`
/// when the header is absent, malformed, or larger than `usize::MAX`.
fn extract_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            // Request/status line has no colon — skip instead of aborting.
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            return value.trim().parse::<usize>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(port: u16) -> FlowId {
        FlowId::new([0xC0A8_0001, 0, 0, 0], [0x0A00_0001, 0, 0, 0], 12345, port, false)
    }

    #[test]
    fn default_config_has_bounded_memory_budget() {
        let cfg = ReassemblerConfig::default();
        // 1 000 × 16 KiB = 16 MiB — matches the story budget.
        assert_eq!(cfg.max_flows * cfg.max_buffer_per_flow, 16 * 1024 * 1000);
        assert_eq!(cfg.idle_timeout_ns, 5_000_000_000);
    }

    #[test]
    fn ingest_empty_payload_is_noop() {
        let r = StreamReassembler::new(ReassemblerConfig::default());
        let out = r.ingest(flow(80), b"", 0);
        assert_eq!(out, Ingest::Pending);
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn http_request_with_content_length_completes() {
        let r = StreamReassembler::new(ReassemblerConfig::default());
        let flow = flow(80);
        let chunk1 = b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\nhello";
        assert_eq!(r.ingest(flow, chunk1, 1), Ingest::Pending);
        let out = r.ingest(flow, b" world", 2);
        match out {
            Ingest::Complete(buf) => {
                let text = std::str::from_utf8(&buf).unwrap();
                assert!(text.contains("hello world"));
                assert!(text.contains("Content-Length: 11"));
            }
            Ingest::Pending => panic!("expected Complete"),
        }
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn http_response_without_content_length_stays_pending() {
        let r = StreamReassembler::new(ReassemblerConfig::default());
        let out = r.ingest(
            flow(80),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            1,
        );
        assert_eq!(out, Ingest::Pending);
        assert_eq!(r.flow_count(), 1);
    }

    #[test]
    fn multi_fragment_sql_query_buffered_until_timeout() {
        let cfg = ReassemblerConfig {
            idle_timeout_ns: 100,
            ..ReassemblerConfig::default()
        };
        let r = StreamReassembler::new(cfg);
        let f = flow(3306);
        assert_eq!(r.ingest(f, b"SELECT * FROM ", 10), Ingest::Pending);
        assert_eq!(r.ingest(f, b"users WHERE id=42", 20), Ingest::Pending);
        assert!(r.flush_expired(50).is_empty());
        let expired = r.flush_expired(1_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, f);
        assert_eq!(expired[0].1, b"SELECT * FROM users WHERE id=42");
        assert_eq!(r.flow_count(), 0);
    }

    #[test]
    fn per_flow_buffer_cap_is_enforced() {
        let cfg = ReassemblerConfig {
            max_buffer_per_flow: 8,
            ..ReassemblerConfig::default()
        };
        let r = StreamReassembler::new(cfg);
        r.ingest(flow(80), b"123456789", 1);
        let buf = r.take(flow(80)).unwrap();
        assert_eq!(buf.len(), 8);
        assert_eq!(buf, b"12345678");
    }

    #[test]
    fn lru_eviction_respects_max_flows() {
        let cfg = ReassemblerConfig {
            max_flows: 2,
            ..ReassemblerConfig::default()
        };
        let r = StreamReassembler::new(cfg);
        r.ingest(flow(80), b"a", 1);
        r.ingest(flow(443), b"b", 2);
        r.ingest(flow(3306), b"c", 3);
        assert_eq!(r.flow_count(), 2);
        // Oldest (port 80) got evicted.
        assert!(r.take(flow(80)).is_none());
        assert!(r.take(flow(443)).is_some());
        assert!(r.take(flow(3306)).is_some());
    }

    #[test]
    fn zero_max_flows_coerces_to_one() {
        let cfg = ReassemblerConfig {
            max_flows: 0,
            ..ReassemblerConfig::default()
        };
        let r = StreamReassembler::new(cfg);
        r.ingest(flow(80), b"x", 1);
        assert_eq!(r.flow_count(), 1);
    }

    #[test]
    fn flush_expired_ignores_fresh_flows() {
        let cfg = ReassemblerConfig {
            idle_timeout_ns: 1_000,
            ..ReassemblerConfig::default()
        };
        let r = StreamReassembler::new(cfg);
        r.ingest(flow(80), b"hello", 500);
        assert!(r.flush_expired(600).is_empty());
        assert_eq!(r.flow_count(), 1);
    }

    #[test]
    fn take_returns_none_for_unknown_flow() {
        let r = StreamReassembler::new(ReassemblerConfig::default());
        assert!(r.take(flow(22)).is_none());
    }

    #[test]
    fn http_content_length_case_insensitive() {
        let r = StreamReassembler::new(ReassemblerConfig::default());
        let out = r.ingest(
            flow(80),
            b"POST / HTTP/1.1\r\ncontent-length: 3\r\n\r\nabc",
            1,
        );
        assert!(matches!(out, Ingest::Complete(_)));
    }

    #[test]
    fn http_malformed_content_length_stays_pending() {
        let r = StreamReassembler::new(ReassemblerConfig::default());
        let out = r.ingest(
            flow(80),
            b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\nbody",
            1,
        );
        assert_eq!(out, Ingest::Pending);
    }

    #[test]
    fn ingest_updates_last_seen_on_reentry() {
        let cfg = ReassemblerConfig {
            idle_timeout_ns: 100,
            ..ReassemblerConfig::default()
        };
        let r = StreamReassembler::new(cfg);
        r.ingest(flow(80), b"a", 10);
        r.ingest(flow(80), b"b", 150);
        assert!(r.flush_expired(200).is_empty());
        assert_eq!(r.flow_count(), 1);
        let expired = r.flush_expired(500);
        assert_eq!(expired.len(), 1);
    }
}
