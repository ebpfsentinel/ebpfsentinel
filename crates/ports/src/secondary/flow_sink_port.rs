//! Where flow records go once they are written.
//!
//! One port, one implementation per format, and the application layer never
//! learns which. What the port asks of a sink is exactly what the epic's
//! contract asks: take a batch, say whether it landed, and be able to answer
//! for itself afterwards. A sink that cannot reach its destination answers
//! `Err` and keeps its own backoff, because a pipeline that blocks on a SIEM
//! outage has turned an observability failure into a traffic failure.

use std::future::Future;
use std::pin::Pin;

use domain::common::error::DomainError;
use domain::flow::entity::FlowRecord;

/// What a sink says about itself, for the health endpoint and for the CLI.
///
/// It names no address: the detail is a reason, not an endpoint, because the
/// unauthenticated readiness probe renders the same field and a collector's
/// address is somebody's internal topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSinkHealth {
    /// The sink's name, which is the format plus its index in configuration.
    pub name: String,
    /// Whether the last attempt reached the destination.
    pub healthy: bool,
    /// Why not, in one sentence, when it is not.
    pub detail: Option<String>,
    /// Records this sink has written since the agent started.
    pub records_sent: u64,
    /// Records it could not write.
    pub records_failed: u64,
    /// Attempts that failed in a row, which is what the backoff is computed
    /// from.
    pub consecutive_failures: u32,
}

impl FlowSinkHealth {
    /// A sink that has done nothing yet, which is healthy: a destination is
    /// not broken until something has been sent to it.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            healthy: true,
            detail: None,
            records_sent: 0,
            records_failed: 0,
            consecutive_failures: 0,
        }
    }
}

/// A destination for flow records.
pub trait FlowSink: Send + Sync {
    /// The sink's name, stable for the life of the process, used as the
    /// metric label and in the health endpoint.
    fn name(&self) -> &str;

    /// Write a batch. The slice is in the order the exporter produced it, and
    /// a sink must preserve that order: a format whose records arrive
    /// reordered is a format whose byte output is not reproducible.
    fn send<'a>(
        &'a self,
        records: &'a [FlowRecord],
    ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>>;

    /// What the sink has to say about itself.
    fn health<'a>(&'a self) -> Pin<Box<dyn Future<Output = FlowSinkHealth> + Send + 'a>>;

    /// Write anything the sink is holding and close what it holds open. What
    /// shutdown calls, after the flow table's own flush.
    fn close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}
