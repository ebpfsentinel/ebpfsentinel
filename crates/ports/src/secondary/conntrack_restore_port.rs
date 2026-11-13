use domain::common::error::DomainError;
use domain::conntrack::entity::Connection;

/// Secondary port for writing a tracked flow into the kernel table.
///
/// The agent turns off the kernel's mid-stream pickup, so a node that starts
/// carrying a TCP flow whose opening it never saw treats every packet of it as
/// invalid. A node taking over a failed peer's traffic restores the peer's
/// established flows through this port while its datapath loads, and the
/// connections carry on instead of being reset.
pub trait ConnTrackRestorePort: Send + Sync {
    /// Insert `flow` as established, with its reply tuple where it carries
    /// one. Returns `false` when the kernel already tracks it, which is not an
    /// error: the flow survives either way.
    fn restore_flow(&self, flow: &Connection) -> Result<bool, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_restore_port_is_object_safe() {
        fn _check(port: &dyn ConnTrackRestorePort, flow: &Connection) {
            let _ = port.restore_flow(flow);
        }
    }
}
