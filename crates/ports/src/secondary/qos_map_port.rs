use domain::common::error::DomainError;
use domain::qos::entity::{QosClassifier, QosPipe, QosQueue};

/// Secondary port for `QoS` / traffic shaping eBPF map operations.
///
/// Provides a typed interface to the kernel `QoS` maps (pipes, queues,
/// classifiers). Implemented by `QosMapManager` in the adapter layer.
pub trait QosMapPort: Send + Sync {
    /// Load pipe definitions into the eBPF pipe map.
    ///
    /// Clears existing pipe entries, then inserts the supplied pipes.
    fn load_pipes(&mut self, pipes: &[QosPipe]) -> Result<(), DomainError>;

    /// Load queue definitions into the eBPF queue map.
    ///
    /// Clears existing queue entries, then inserts the supplied queues.
    fn load_queues(&mut self, queues: &[QosQueue]) -> Result<(), DomainError>;

    /// Load classifier definitions into the eBPF classifier map.
    ///
    /// Clears existing classifier entries, then inserts the supplied classifiers.
    fn load_classifiers(&mut self, classifiers: &[QosClassifier]) -> Result<(), DomainError>;

    /// Remove all pipe, queue, and classifier entries from the maps.
    fn clear_all(&mut self) -> Result<(), DomainError>;

    /// Return the number of pipe entries currently in the map.
    fn pipe_count(&self) -> Result<usize, DomainError>;

    /// Return the number of queue entries currently in the map.
    fn queue_count(&self) -> Result<usize, DomainError>;

    /// Return the number of classifier entries currently in the map.
    fn classifier_count(&self) -> Result<usize, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qos_map_port_is_object_safe() {
        fn _check(port: &dyn QosMapPort) {
            let _ = port.pipe_count();
            let _ = port.queue_count();
            let _ = port.classifier_count();
        }
    }
}
