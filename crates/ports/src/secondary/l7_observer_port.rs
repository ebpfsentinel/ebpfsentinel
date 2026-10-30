//! Optional observer of every L7 exchange the dispatcher parsed.
//!
//! The dispatcher already detects the protocol, parses the request and,
//! when the socket tables are wired, knows which workload opened the
//! connection. An observer registered through
//! `EventDispatcher::with_l7_observer` is handed all three for each payload,
//! after the built-in rules have run, so an extension can classify traffic
//! without parsing it a second time.
//!
//! An observer is on the hot path: it must not block, and it decides what it
//! keeps. The parsed request is lent, not given, so nothing is retained
//! unless the observer copies it out.

use std::net::IpAddr;

use domain::l7::entity::ParsedProtocol;
use domain::workload::entity::Workload;

/// One parsed L7 payload, seen from the side that opened the connection.
#[derive(Debug, Clone, Copy)]
pub struct L7Exchange<'a> {
    /// Kernel monotonic timestamp of the packet, in nanoseconds.
    pub timestamp_ns: u64,
    /// Address of the side that sent the payload.
    pub client: IpAddr,
    /// Address the payload was sent to.
    pub server: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    /// IP protocol number of the flow (6 for TCP).
    pub ip_protocol: u8,
    /// Stable lowercase protocol label (`"http"`, `"tls"`, ...).
    pub protocol: &'static str,
    /// The parsed request, borrowed for the duration of the call.
    pub parsed: &'a ParsedProtocol,
    /// Size of the payload in bytes. The bytes themselves are not lent.
    pub payload_len: usize,
    /// The workload that opened the connection, when the socket or process
    /// tables could name it. Its `source` says whether that was read off the
    /// socket or correlated from the flow.
    pub workload: Option<&'a Workload>,
}

/// Secondary port consulted once per parsed L7 payload.
pub trait L7Observer: Send + Sync {
    fn observe(&self, exchange: &L7Exchange<'_>);

    /// Stable name of the observer, used in logs.
    fn name(&self) -> &'static str {
        "observer"
    }
}
