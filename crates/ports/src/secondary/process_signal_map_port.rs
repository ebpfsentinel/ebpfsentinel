use domain::common::error::DomainError;
use ebpf_common::signal::SignalEvent;

/// Secondary port for the maps behind the signal tracepoint.
///
/// Four maps written together: the protected fence, the armed targets, the
/// count the kernel reads as its fast path, and the ring the outcomes come
/// back on. One trait rather than four, because arming a target without
/// raising the count arms nothing at all, and the implementation is the only
/// place that ordering is known.
///
/// The program's counters are not here. They are read by the agent's kernel
/// metrics loop like every other program's, so a figure an operator reads on
/// a dashboard comes from one path rather than two.
///
/// Implemented by `SignalMapManager` in the adapter layer.
pub trait ProcessSignalMapPort: Send + Sync {
    /// Replace the kernel's protected set with these thread group ids.
    ///
    /// Called once at start-up and whenever the agent's own thread group or
    /// the configured list changes. Replacing rather than adding, because a
    /// protected id that stayed behind after the process it named exited is a
    /// new process inheriting an immunity nobody granted.
    fn set_protected(&mut self, tgids: &[u32]) -> Result<(), DomainError>;

    /// Arm `tgid` to receive `signal` for the next `window_ns` nanoseconds.
    ///
    /// A window rather than an instant: the kernel compares against its own
    /// boot clock, and the implementation is the only layer that can read the
    /// same clock without inventing an offset.
    ///
    /// The armed count is raised before the target is visible, so the kernel
    /// never sees a target it was told not to look for.
    fn arm(&mut self, tgid: u32, signal: u32, window_ns: u64) -> Result<(), DomainError>;

    /// Forget an arming, whether or not the kernel already acted on it.
    ///
    /// Idempotent: a target the kernel removed itself is not an error here,
    /// because the service disarms on its way out of every decision.
    fn disarm(&mut self, tgid: u32) -> Result<(), DomainError>;

    /// Take whatever outcomes the kernel has written since the last call.
    ///
    /// Drains without blocking: an empty vector means nothing happened yet,
    /// which during a grace window is the normal answer.
    fn drain_events(&mut self) -> Result<Vec<SignalEvent>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_signal_map_port_is_object_safe() {
        fn takes_dyn(_: &dyn ProcessSignalMapPort) {}
        struct Nothing;
        impl ProcessSignalMapPort for Nothing {
            fn set_protected(&mut self, _tgids: &[u32]) -> Result<(), DomainError> {
                Ok(())
            }
            fn arm(
                &mut self,
                _tgid: u32,
                _signal: u32,
                _window_ns: u64,
            ) -> Result<(), DomainError> {
                Ok(())
            }
            fn disarm(&mut self, _tgid: u32) -> Result<(), DomainError> {
                Ok(())
            }
            fn drain_events(&mut self) -> Result<Vec<SignalEvent>, DomainError> {
                Ok(Vec::new())
            }
        }
        takes_dyn(&Nothing);
    }
}
