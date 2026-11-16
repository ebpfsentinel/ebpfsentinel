#![no_main]

use libfuzzer_sys::fuzz_target;

use adapters::container::docker_events::parse_event;
use adapters::container::proc_details::{
    MAX_COMMAND_LINE, TRUNCATION_MARKER, parse_command_line, parse_parent_pid,
};

// A Docker event line names container attributes the container's author
// chose, and /proc/<pid>/cmdline and status are the process's own to write.
fuzz_target!(|data: &[u8]| {
    let _ = parse_event(data);
    if let Some(line) = parse_command_line(data) {
        assert!(line.len() <= MAX_COMMAND_LINE + TRUNCATION_MARKER.len());
    }
    let _ = parse_parent_pid(&String::from_utf8_lossy(data));
});
