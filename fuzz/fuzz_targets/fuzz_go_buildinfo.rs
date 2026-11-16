#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::inventory::parse_go_buildinfo;

// The build information section is read out of a binary found in a
// container's root, so every byte of it is the container's to choose.
fuzz_target!(|data: &[u8]| {
    let _ = parse_go_buildinfo(data);
});
