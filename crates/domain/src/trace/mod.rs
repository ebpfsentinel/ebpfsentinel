//! "Why is this packet dropped", asked of the programs that are loaded.
//!
//! A trace is a packet crafted from a five-tuple and run through the loaded
//! programs in the order the hooks run them, each program reporting what it
//! decided and the rule that decided it. The packet carries a marker every
//! program reads before it writes, so a trace changes no state.
//!
//! This module holds what a trace is asked with ([`TraceRequest`]), the bytes
//! it sends ([`packet::craft`]), how a program's record reads
//! ([`StageReport`]) and the answer ([`TraceReport`]). What a record's rule
//! identifier names is the business of the stage that wrote it; the firewall's
//! is resolved through [`FirewallTraceIndex`], because the firewall places one
//! rule in one of three maps and the kernel only reports which.

pub mod entity;
pub mod index;
pub mod packet;

pub use entity::{
    EPHEMERAL_PORT, ProgramRun, Reason, Stage, StageReport, StateDependence, TraceDirection,
    TraceError, TraceHook, TraceProtocol, TraceReport, TraceRequest, Verdict, program_stage,
};
pub use index::{FirewallTraceIndex, RulePlacement};
