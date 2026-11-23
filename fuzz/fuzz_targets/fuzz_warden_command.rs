#![no_main]

//! What the warden reads off its socket: a frame of any bytes is read as a
//! command or refused, never panics, and a command that names a family is
//! refused by a warden whose policy switches nothing on. Commands are not
//! dispatched here: dispatching acts on the host this runs on.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

use ebpfsentinel_warden::policy::WardenPolicy;
use ebpfsentinel_warden_proto::{MAX_FRAME_LEN, read_command};

fuzz_target!(|data: &[u8]| {
    let Ok(cmd) = read_command(&mut Cursor::new(data)) else {
        return;
    };
    assert!(cmd.frame_limit() <= MAX_FRAME_LEN);
    let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    assert!(
        length <= cmd.frame_limit(),
        "{} read past its bound",
        cmd.name()
    );
    let off = WardenPolicy::default();
    if cmd.family().is_some() {
        assert!(
            off.check(&cmd).is_err(),
            "{} served with every family off",
            cmd.name()
        );
    }
});
