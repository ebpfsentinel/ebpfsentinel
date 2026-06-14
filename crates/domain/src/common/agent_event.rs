use ebpf_common::dlp::DlpEvent;
use ebpf_common::dns::DnsEvent;
use ebpf_common::event::PacketEvent;

/// Wrapper around events flowing from the eBPF event reader to the dispatcher.
///
/// `L4` carries the 32-byte `PacketEvent` as before. `L7` carries the same
/// header plus a variable-length payload extracted from the `RingBuf`.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    L4(PacketEvent),
    L7 {
        header: PacketEvent,
        payload: Vec<u8>,
    },
    Dns {
        header: DnsEvent,
        payload: Vec<u8>,
    },
    Dlp(Box<DlpEvent>),
}
