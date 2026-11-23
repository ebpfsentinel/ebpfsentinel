use ebpf_common::dlp::DlpEvent;
use ebpf_common::dns::DnsEvent;
use ebpf_common::event::{L7Segment, PacketCapture, PacketEvent};

/// Wrapper around events flowing from the eBPF event reader to the dispatcher.
///
/// `L4` carries the 32-byte `PacketEvent` as before. `L7` carries the same
/// header plus a variable-length payload extracted from the `RingBuf`.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    L4(PacketEvent),
    L7 {
        header: PacketEvent,
        /// Where the payload sits in its TCP stream, when the capture said.
        segment: Option<L7Segment>,
        payload: Vec<u8>,
    },
    Dns {
        header: DnsEvent,
        payload: Vec<u8>,
    },
    /// A whole packet from its IP header on, for the IDS rules decided on
    /// each packet. `bytes` holds what was copied, at most the record's size;
    /// `capture.wire_len` how long the packet was.
    Packet {
        header: PacketEvent,
        capture: PacketCapture,
        bytes: Vec<u8>,
    },
    Dlp(Box<DlpEvent>),
}
