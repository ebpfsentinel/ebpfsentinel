use ebpf_common::event::PacketEvent;

/// Secondary port handed every L4 event the datapath reports, after the
/// dispatcher has acted on it.
///
/// An observer reads the stream; it raises nothing through this call and must
/// not block, because it runs on the dispatcher's worker for that event. What
/// it learns it keeps and reports through its own path, which is how a
/// detector building a per-host baseline sees the same traffic the rules saw
/// without a second ring buffer.
pub trait PacketObserver: Send + Sync {
    fn observe(&self, event: &PacketEvent);

    /// Stable name of the observer, used in logs.
    fn name(&self) -> &'static str {
        "observer"
    }
}
