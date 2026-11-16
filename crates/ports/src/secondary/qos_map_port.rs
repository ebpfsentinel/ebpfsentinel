use domain::common::error::DomainError;
use domain::qos::entity::{QosClassifier, QosPipe, QosQueue};

/// Secondary port for `QoS` / traffic shaping eBPF map operations.
///
/// Provides a typed interface to the kernel `QoS` maps (pipes, queues,
/// classifiers). Implemented by `QosMapManager` in the adapter layer.
pub trait QosMapPort: Send + Sync {
    /// Load the whole rule set into the eBPF maps.
    ///
    /// One call, because the three levels refer to each other by position in
    /// the maps: a queue is written with its pipe's index and its share of
    /// that pipe, which takes every queue of the pipe to compute, and a
    /// classifier with its queue's index. A queue naming no loaded pipe and a
    /// classifier naming no loaded queue are not written.
    fn load(
        &mut self,
        pipes: &[QosPipe],
        queues: &[QosQueue],
        classifiers: &[QosClassifier],
    ) -> Result<(), DomainError>;

    /// Remove all pipe, queue, and classifier entries from the maps.
    fn clear_all(&mut self) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qos_map_port_is_object_safe() {
        fn _check(port: &mut dyn QosMapPort) {
            let _ = port.clear_all();
        }
    }
}
