#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::inventory::{parse_rpm_header, read_rpm_sqlite};

// The rpm database comes from inside a container's root: a SQLite file the
// agent walks page by page itself, and the header blobs stored in it.
fuzz_target!(|data: &[u8]| {
    let _ = read_rpm_sqlite(data);
    let _ = parse_rpm_header(data);
});
