//! Minimal pass-through XDP program.
//!
//! Returns `XDP_PASS` for every frame. Its only purpose is to be attached to
//! the peer end of a veth pair: the kernel only arms a veth's receive-side
//! XDP path (and therefore delivers `XDP_TX`'d frames from the other end) when
//! that end has an XDP program loaded. The integration test rig attaches this
//! on the netns-side veth so the agent's native `XDP_TX` reflections (forged
//! ARP replies, TCP RSTs) reach the probing namespace. On a physical NIC no
//! such helper is needed, so this program is never attached in production.
#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
