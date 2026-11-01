//! What the kernel holds and its own listings leave out.
//!
//! A rootkit hides its channel by filtering what userspace is shown, and it
//! rarely filters every reading of the same state. Each check here asks the
//! kernel the same question two ways and reports where the answers part: a
//! port the listings omit and a bind refuses, a process the `/proc`
//! directory omits and a signal reaches. Neither carries a signature and
//! neither needs a feed; a rootkit that hides consistently from both
//! readings is not found, and that is stated rather than implied.
//!
//! Both readings disagree for ordinary reasons too, so every ordinary cause
//! is excluded by name and counted, and a disagreement is confirmed by a
//! second reading before it is reported.

pub mod port;
pub mod process;

pub use port::{
    HIDDEN_PORT_COMPONENT, HIDDEN_PORT_RULE_ID, HiddenPort, ListedPort, Listing, NamespacePorts,
    PortFamily, PortProbe, PortReading, PortSweep, PortSweepCounts, Transport, sweep_ports,
};
pub use process::{
    HIDDEN_PROCESS_COMPONENT, HIDDEN_PROCESS_RULE_ID, HiddenProcess, PidObservation,
    ProcessReading, ProcessSweep, ProcessSweepCounts, sweep_processes,
};
