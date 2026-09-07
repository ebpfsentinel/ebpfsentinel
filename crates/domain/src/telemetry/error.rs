use thiserror::Error;

/// Anything that can stop one heartbeat.
///
/// None of these is fatal to the agent: telemetry is a side channel, so every
/// variant is logged and the next interval tries again from scratch.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// The build carries no endpoint, or the one it carries is unusable.
    #[error("telemetry not configured: {0}")]
    NotConfigured(String),

    /// The installation identifier could not be read into the shape the
    /// endpoint accepts.
    #[error("malformed installation id: {0}")]
    Malformed(String),

    /// The identifier file could not be read or written.
    #[error("installation id persistence failed: {0}")]
    Persistence(String),

    /// The endpoint could not be reached, or refused the beat.
    #[error("telemetry transport failed: {0}")]
    Transport(String),
}
