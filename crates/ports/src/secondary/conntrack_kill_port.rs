use domain::common::error::DomainError;

/// Secondary port for targeted destruction of kernel conntrack entries.
///
/// The XDP firewall runs before netfilter, so when a deny rule is added
/// against an already-ESTABLISHED flow the datapath drop cannot evict the
/// existing conntrack entry (and the reply direction keeps refreshing it).
/// Userspace must delete the matching entries so the flow is torn down and
/// the kernel stops treating it as established.
///
/// Implemented by conntrack adapters in the adapter layer.
pub trait ConnTrackKillPort: Send + Sync {
    /// Delete conntrack entries whose original-direction tuple matches the
    /// given protocol and destination port. Returns the number of entries
    /// removed (0 when nothing matched).
    fn delete_matching(&self, protocol: u8, dst_port: u16) -> Result<u64, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_kill_port_is_object_safe() {
        fn _check(port: &dyn ConnTrackKillPort) {
            let _ = port.delete_matching(6, 443);
        }
    }
}
