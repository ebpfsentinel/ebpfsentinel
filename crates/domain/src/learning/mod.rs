//! Watching a node for a window, and holding what it reached.
//!
//! A learning session is a declared window over a declared scope: it records
//! which workload reached which destination on which port, in a bounded
//! aggregate rather than per flow, and reports how long it has run, how many
//! distinct edges it holds and when it last saw a new one. That last figure is
//! what tells an operator the window was long enough.
//!
//! What this module deliberately does not claim: the aggregate is a
//! description of a window and not a specification. A destination that was not
//! reached during the window is missing from it, and every figure the session
//! reports is there so the operator can decide whether the window was long
//! enough before turning the aggregate into a policy.

pub mod aggregate;
pub mod document;
pub mod engine;
pub mod entity;
pub mod error;
pub mod segmentation;
