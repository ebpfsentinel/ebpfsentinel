use domain::trace::{ProgramRun, TraceDirection, TraceError};

/// What the datapath answered for one crafted packet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DatapathRuns {
    /// Each program the packet went through, in hook order, up to the one
    /// that stopped it.
    pub runs: Vec<ProgramRun>,
    /// Programs of the direction asked about that are not loaded, so the
    /// packet could not be shown to them.
    pub not_loaded: Vec<String>,
}

/// Secondary port: run a crafted packet through the loaded programs.
///
/// The packet must carry nothing a program would write state for; the
/// implementation presents it with the trace marker every program checks.
pub trait DatapathTracePort: Send + Sync {
    /// Run `packet` through the programs of `direction`, in the order the
    /// hooks run them, passing each the packet as the previous one left it.
    ///
    /// # Errors
    ///
    /// [`TraceError::Unavailable`] when the kernel refuses the run.
    fn run(&self, packet: &[u8], direction: TraceDirection) -> Result<DatapathRuns, TraceError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datapath_trace_port_is_object_safe() {
        let port: Option<&dyn DatapathTracePort> = None;
        assert!(port.is_none());
    }
}
