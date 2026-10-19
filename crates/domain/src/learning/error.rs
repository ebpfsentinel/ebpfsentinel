use thiserror::Error;

/// Anything that can refuse a learning session, or stop one from being read
/// back.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LearningError {
    /// A session is already running, and a second one would observe the same
    /// flows into a second aggregate.
    #[error("a learning session is already running: {id}")]
    AlreadyRunning { id: String },

    /// Nothing is running, so there is nothing to stop, read or render.
    #[error("no learning session is running")]
    NotRunning,

    /// No session was ever recorded under that id.
    #[error("unknown learning session: {id}")]
    Unknown { id: String },

    /// The requested window is shorter or longer than the agent accepts.
    #[error("invalid window: {reason}")]
    InvalidDuration { reason: String },

    /// The scope names nothing, or names it in a shape no matcher can decide.
    #[error("invalid scope: {reason}")]
    InvalidScope { reason: String },
}
