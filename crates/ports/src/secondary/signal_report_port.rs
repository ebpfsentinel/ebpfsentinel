use std::future::Future;
use std::pin::Pin;

use domain::common::error::DomainError;
use domain::threatintel::crowdsec::Signal;

/// Secondary port for writing the agent's own blocks back to a community
/// threat-intelligence service.
///
/// Uses `Pin<Box<dyn Future>>` so the trait is dyn-compatible.
pub trait SignalReportPort: Send + Sync {
    /// Report one window of signals. An empty slice is never passed.
    fn report<'a>(
        &'a self,
        signals: &'a [Signal],
    ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>>;
}
