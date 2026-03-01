use domain::ddos::entity::DdosAttack;
use domain::dlp::entity::DlpAlert;
use domain::ids::entity::IdsAlert;

/// Unified alert event type for the alert pipeline channel.
///
/// Replaces the previous `mpsc::Sender<IdsAlert>` with a polymorphic
/// envelope so that DLP and `DDoS` alerts also flow through the same channel.
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
}
