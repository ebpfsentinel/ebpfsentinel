use domain::common::error::DomainError;

/// Secondary port for targeted destruction of kernel conntrack entries.
///
/// The XDP firewall runs before netfilter, so when a deny rule is added
/// against an already-ESTABLISHED flow the datapath drop cannot evict the
/// existing conntrack entry (and the reply direction keeps refreshing it).
/// Userspace must delete the matching entries so the flow is torn down and
/// the kernel stops treating it as established.
///
/// One flow, named completely enough that deleting it cannot take another with
/// it.
///
/// [`ConnTrackKillPort::delete_matching`] names a flow by protocol and
/// destination port, which is what a deny rule knows and all it needs. A
/// quarantine knows more and must say more: cutting one workload off by
/// protocol and port would tear down every other workload's connections to the
/// same port on the node, which on a shared host is most of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnTrackFlow {
    pub protocol: u8,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
}

/// Implemented by conntrack adapters in the adapter layer.
pub trait ConnTrackKillPort: Send + Sync {
    /// Delete conntrack entries whose original-direction tuple matches the
    /// given protocol and destination port. Returns the number of entries
    /// removed (0 when nothing matched).
    fn delete_matching(&self, protocol: u8, dst_port: u16) -> Result<u64, DomainError>;

    /// Delete the one entry matching this five-tuple in the original
    /// direction. Returns the number of entries removed, which is 0 when the
    /// flow closed on its own between the read and the delete - the ordinary
    /// case, and not an error.
    fn delete_flow(&self, flow: &ConnTrackFlow) -> Result<u64, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_kill_port_is_object_safe() {
        fn _check(port: &dyn ConnTrackKillPort) {
            let _ = port.delete_matching(6, 443);
            let _ = port.delete_flow(&ConnTrackFlow {
                protocol: 6,
                src_ip: "10.0.0.2".into(),
                dst_ip: "10.0.0.3".into(),
                src_port: 51_234,
                dst_port: 443,
            });
        }
    }
}
