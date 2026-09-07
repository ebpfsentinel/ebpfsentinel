//! Secondary ports for saying that this installation exists.
//!
//! Three of them, because the three things the beat needs come from three
//! different worlds: one crosses the network, one survives a restart, and one
//! reads state this process already holds. Keeping them apart is what lets a
//! test drive an endpoint that refuses everything while the file on disk
//! behaves perfectly, which is the case hardest to reproduce against a real
//! endpoint.

use std::future::Future;
use std::pin::Pin;

use domain::telemetry::entity::{Heartbeat, InstallationId, ProgramReport};
use domain::telemetry::error::TelemetryError;

/// Sends one beat.
///
/// The implementation holds the endpoint and the client; neither the
/// application layer nor the domain knows there is HTTP underneath, which is
/// what keeps the cadence testable without a socket.
pub trait TelemetryTransport: Send + Sync {
    /// Hands over one beat.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Transport`] when the endpoint could not be
    /// reached or refused the beat, and [`TelemetryError::NotConfigured`] when
    /// this build carries no endpoint at all.
    fn send<'a>(
        &'a self,
        beat: Heartbeat,
    ) -> Pin<Box<dyn Future<Output = Result<(), TelemetryError>> + Send + 'a>>;

    /// Where the beats go.
    ///
    /// On the port rather than kept private to the adapter, because the one
    /// line the agent logs at boot has to name it: telemetry somebody cannot
    /// see the destination of is telemetry they were not told about.
    fn endpoint(&self) -> &str;
}

/// Keeps this installation's identifier across restarts.
///
/// Synchronous on purpose: it is a small local file, and making it async would
/// buy nothing but a runtime requirement in a test that has no runtime.
pub trait InstallationStore: Send + Sync {
    /// The identifier this installation already holds, if it holds one.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Persistence`] when the file exists and cannot
    /// be read. A missing file is `Ok(None)` rather than an error, because that
    /// is simply the first boot.
    fn load(&self) -> Result<Option<InstallationId>, TelemetryError>;

    /// Keeps an identifier for the next restart.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Persistence`] when the file cannot be written.
    fn save(&self, id: &InstallationId) -> Result<(), TelemetryError>;

    /// Sixteen random bytes for a first identifier.
    ///
    /// Lives beside the store rather than in the domain because drawing them
    /// means opening something on this machine, and the domain opens nothing.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Persistence`] when the machine has no usable
    /// source of randomness, which is worth refusing over: a predictable
    /// identifier would be shared by every installation that booted the same
    /// way, and the count would collapse.
    fn random_bytes(&self) -> Result<[u8; 16], TelemetryError>;
}

/// Reads which eBPF programs are loaded.
///
/// Async because the answer lives behind the same lock the agent's own status
/// endpoint reads, and there is exactly one of those: a second inventory would
/// drift from the one the operator sees on `/api/v1/ebpf/programs`, and the
/// first time those two disagree is the last time either is believed.
pub trait ProgramInventory: Send + Sync {
    /// Every program this build carries, with whether it is loaded.
    fn programs<'a>(&'a self) -> Pin<Box<dyn Future<Output = Vec<ProgramReport>> + Send + 'a>>;
}
