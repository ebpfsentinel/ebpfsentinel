//! Optional L7 protocol parser extension point.
//!
//! The OSS `domain::l7::parser` ships built-in detection for HTTP, TLS,
//! gRPC, SMTP, FTP, SMB, SSH, Redis, `MySQL`, `PostgreSQL`, DNS-over-TCP,
//! IMAP, and POP3. The enterprise edition implements this trait to add
//! coverage for message brokers (MQTT, AMQP, NATS) and distributed
//! databases (Cassandra) without polluting the OSS enum surface.
//!
//! Implementations live in `enterprise-domain` / `enterprise-adapters`
//! and are registered on `EventDispatcher` via
//! `EventDispatcher::with_extended_l7_parser`.

/// Optional secondary port consulted by the L7 dispatcher when the
/// built-in detector returns [`Unknown`](DetectedProtocol::Unknown).
///
/// Implementations are stateless and can run on the hot path. They are
/// expected to short-circuit on the first byte mismatch and never
/// allocate on a miss.
///
/// [`Unknown`]: domain::l7::entity::DetectedProtocol::Unknown
pub trait L7ExtendedParser: Send + Sync {
    /// Return a stable lowercase label (`"mqtt"`, `"amqp"`, …) when the
    /// payload matches one of the parser's protocols, or `None` when
    /// nothing recognises the bytes.
    fn detect_label(&self, payload: &[u8]) -> Option<&'static str>;

    /// Stable name of the parser, used in metrics / logs. Defaults to
    /// `"extended"` so existing implementations need no override.
    fn name(&self) -> &'static str {
        "extended"
    }
}
