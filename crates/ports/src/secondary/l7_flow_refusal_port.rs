use domain::common::error::DomainError;

/// One TCP connection an L7 rule refused, named by the direction the
/// refused request travelled. Addresses use the layout of a datapath event:
/// an IPv4 address in the first word, host byte order, the other three zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusedL7Flow {
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub ipv6: bool,
    /// Stable 32-bit hash of the rule id, carried for a reader of the table.
    pub rule_hash: u32,
}

/// The kernel table of refused connections, which the classifier capturing
/// L7 payloads reads to shoot every later packet of such a connection, in
/// both directions.
///
/// Implemented by the eBPF adapter over the loaded `tc-ids` object.
pub trait L7FlowRefusalMapPort: Send + Sync {
    /// Refuse the connection in both directions until the table's own expiry.
    fn refuse(&mut self, flow: &RefusedL7Flow) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l7_flow_refusal_map_port_is_object_safe() {
        fn _check(port: &mut dyn L7FlowRefusalMapPort) {
            let _ = port.refuse(&RefusedL7Flow {
                src_addr: [0x0a00_0001, 0, 0, 0],
                dst_addr: [0x0a00_0002, 0, 0, 0],
                src_port: 40_000,
                dst_port: 8888,
                ipv6: false,
                rule_hash: 7,
            });
        }
    }
}
