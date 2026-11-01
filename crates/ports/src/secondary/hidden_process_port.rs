use domain::common::error::DomainError;
use domain::hidden::ProcessReading;

/// Takes the two readings a hidden process is found between - the listing of
/// `/proc` and a null signal sent across the pid space.
pub trait HiddenProcessReader: Send + Sync {
    /// List `/proc` and signal every pid at about `rate` pids a second, then
    /// read again what answered and was not listed.
    ///
    /// # Errors
    ///
    /// The reading could not be taken: the warden refused or is unreachable,
    /// or the `/proc` it would list belongs to another pid namespace, where a
    /// pid that answers and is not listed means nothing.
    fn read(&self, rate: u32) -> Result<ProcessReading, DomainError>;

    /// Where the reading comes from: `warden` or `local`.
    fn source(&self) -> &'static str;
}
