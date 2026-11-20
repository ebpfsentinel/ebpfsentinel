#![no_main]

use libfuzzer_sys::fuzz_target;

use ebpfsentinel_warden::bpf_inventory::{
    parse_filter_message, parse_link_info, parse_link_message, parse_prog_info,
};
use ebpfsentinel_warden::fim_watch::parse_events;

/// `struct fanotify_event_metadata`: the shortest record `parse_events` takes.
const FANOTIFY_METADATA_LEN: usize = 24;

// The warden reads these buffers as root from the kernel: `bpf_prog_info` and
// `bpf_link_info` out of `BPF_OBJ_GET_INFO_BY_FD`, `RTM_NEWLINK` and
// `RTM_NEWTFILTER` payloads off a netlink socket, fanotify records off its
// group. None of them may panic or read past the buffer whatever it holds.
fuzz_target!(|data: &[u8]| {
    let prog = parse_prog_info(data);
    // The tag is the eight bytes after the first eight, in hex, or as many of
    // them as the buffer holds.
    assert!(prog.tag.len() == 16 || (data.len() < 16 && prog.tag.is_empty()));
    assert!(prog.tag.bytes().all(|b| b.is_ascii_hexdigit()));

    let _ = parse_link_info(data);
    let _ = parse_link_message(data);
    let _ = parse_filter_message(data);

    // Each event comes out of a record of at least the metadata length, so a
    // buffer cannot yield more events than it holds records.
    let parsed = parse_events(data);
    assert!(parsed.events.len() <= data.len() / FANOTIFY_METADATA_LEN);
});
