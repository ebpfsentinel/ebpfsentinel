#![no_main]

use libfuzzer_sys::fuzz_target;

use ebpf_common::event::{PacketEvent, has_vlan, is_ipv6};

fuzz_target!(|data: &[u8]| {
    // PacketEvent is 56 bytes. Simulate userspace parsing of raw RingBuf data.
    if data.len() < core::mem::size_of::<PacketEvent>() {
        return;
    }

    // SAFETY: we only read from a byte slice of sufficient length.
    // This mirrors what the adapter does when reading from the eBPF RingBuf.
    let event: PacketEvent = unsafe { core::ptr::read_unaligned(data.as_ptr().cast()) };

    // Exercise all accessor methods — none should panic.
    let _ = event.src_ip();
    let _ = event.dst_ip();
    let _ = event.is_ipv6();
    let _ = event.has_vlan();
    let _ = is_ipv6(event.flags);
    let _ = has_vlan(event.flags);

    // Exercise Debug formatting — should never panic.
    let _ = format!("{event:?}");
});
