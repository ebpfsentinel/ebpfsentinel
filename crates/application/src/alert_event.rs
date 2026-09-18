use domain::alert::entity::{Alert, PacketSecurityAlert};
use domain::ddos::entity::DdosAttack;
use domain::dlp::entity::DlpAlert;
use domain::dns::entity::DnsAlert;
use domain::ids::entity::IdsAlert;
use domain::threatintel::entity::ThreatIntelAlert;

/// Unified alert event type for the alert pipeline channel.
///
/// Replaces the previous `mpsc::Sender<IdsAlert>` with a polymorphic
/// envelope so that all security domains flow through the same channel.
pub enum AlertEvent {
    Ids(IdsAlert),
    Dlp(DlpAlert),
    Ddos {
        attack: DdosAttack,
        src_addr: [u32; 4],
        dst_addr: [u32; 4],
        is_ipv6: bool,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    },
    Dns(DnsAlert),
    /// An IOC match. It travels on its own arm rather than as an IDS alert
    /// so the alert it becomes carries the feed, the confidence and the
    /// threat type, and answers to the component an operator filters on.
    ThreatIntel(ThreatIntelAlert),
    PacketSecurity(PacketSecurityAlert),
    /// A pre-built system alert (e.g. multi-WAN total failure) that does not
    /// originate from a kernel security event. Boxed to keep the envelope small.
    System(Box<Alert>),
}
