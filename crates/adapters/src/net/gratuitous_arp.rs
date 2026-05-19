#![allow(unsafe_code)] // Required for AF_PACKET raw socket + sendto

//! Gratuitous-ARP emitter (userspace, raw socket).
//!
//! On speaker takeover the agent broadcasts a gratuitous ARP for every
//! owned VIP so upstream switches/hosts relearn the MAC immediately.
//! This is a rare control-plane event and intentionally never runs in
//! eBPF. IPv6 VIPs are a no-op here (unsolicited NA is out of scope).

use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use domain::common::error::DomainError;
use domain::loadbalancer::vip::Vip;
use ports::secondary::vip_announcer_port::GratuitousArpPort;
use tracing::debug;

use super::iface_mac::resolve_ifindex;

const ETH_P_ARP: u16 = 0x0806;
const ARP_HW_ETHERNET: u16 = 1;
const ETH_P_IP: u16 = 0x0800;
const ARP_OP_REPLY: u16 = 2;
const BROADCAST: [u8; 6] = [0xff; 6];

/// A complete 42-byte gratuitous ARP frame (Ethernet + ARP, no padding).
fn build_frame(src_mac: [u8; 6], vip: [u8; 4]) -> [u8; 42] {
    let mut f = [0u8; 42];
    // ── Ethernet ──
    f[0..6].copy_from_slice(&BROADCAST); // dst = broadcast
    f[6..12].copy_from_slice(&src_mac); // src = our NIC MAC
    f[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
    // ── ARP ──
    f[14..16].copy_from_slice(&ARP_HW_ETHERNET.to_be_bytes());
    f[16..18].copy_from_slice(&ETH_P_IP.to_be_bytes());
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    f[22..28].copy_from_slice(&src_mac); // sha = our NIC MAC
    f[28..32].copy_from_slice(&vip); // spa = the VIP
    f[32..38].copy_from_slice(&BROADCAST); // tha = broadcast
    f[38..42].copy_from_slice(&vip); // tpa = the VIP (gratuitous)
    f
}

fn send_on(ifindex: u32, frame: &[u8]) -> Result<(), DomainError> {
    // SAFETY: AF_PACKET/SOCK_RAW with a valid protocol; fd wrapped in
    // OwnedFd which closes it on drop.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::c_int::from(ETH_P_ARP.to_be()),
        )
    };
    if fd < 0 {
        return Err(DomainError::EngineError(format!(
            "socket(AF_PACKET) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `fd` is a valid, freshly-created descriptor we own.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut sa: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sa.sll_family = libc::AF_PACKET as u16;
    sa.sll_protocol = ETH_P_ARP.to_be();
    sa.sll_ifindex = ifindex.cast_signed();
    sa.sll_halen = 6;
    sa.sll_addr[..6].copy_from_slice(&BROADCAST);

    // SAFETY: `frame` is a valid readable slice; `sa` is a fully
    // initialized sockaddr_ll of the declared length; `sock` is a valid
    // AF_PACKET raw socket fd.
    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            frame.as_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
            std::ptr::addr_of!(sa).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(DomainError::EngineError(format!(
            "sendto(AF_PACKET) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// `GratuitousArpPort` backed by an `AF_PACKET`/`SOCK_RAW` socket.
#[derive(Debug, Default, Clone, Copy)]
pub struct RawSocketGratuitousArp;

impl GratuitousArpPort for RawSocketGratuitousArp {
    fn send_gratuitous_arp(
        &self,
        interface: &str,
        src_mac: [u8; 6],
        vip: &Vip,
    ) -> Result<(), DomainError> {
        let v4 = match vip.addr {
            IpAddr::V4(v4) => v4.octets(),
            IpAddr::V6(_) => {
                debug!(vip = %vip.name, "gratuitous ARP skipped for IPv6 VIP (ND is out of scope)");
                return Ok(());
            }
        };
        let ifindex = resolve_ifindex(interface)?;
        let frame = build_frame(src_mac, v4);
        send_on(ifindex, &frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout_is_a_well_formed_gratuitous_arp() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let f = build_frame(mac, [192, 0, 2, 10]);
        assert_eq!(&f[0..6], &BROADCAST); // eth dst broadcast
        assert_eq!(&f[6..12], &mac); // eth src = NIC MAC
        assert_eq!(&f[12..14], &0x0806u16.to_be_bytes()); // ARP ethertype
        assert_eq!(&f[20..22], &2u16.to_be_bytes()); // oper = REPLY
        assert_eq!(&f[22..28], &mac); // sha = NIC MAC
        assert_eq!(&f[28..32], &[192, 0, 2, 10]); // spa = VIP
        assert_eq!(&f[38..42], &[192, 0, 2, 10]); // tpa = VIP (gratuitous)
        assert_eq!(f.len(), 42);
    }

    #[test]
    fn ipv6_vip_is_a_noop() {
        let g = RawSocketGratuitousArp;
        let vip = Vip {
            name: "v6".into(),
            addr: "2001:db8::1".parse().unwrap(),
        };
        assert!(g.send_gratuitous_arp("lo", [0; 6], &vip).is_ok());
    }
}
