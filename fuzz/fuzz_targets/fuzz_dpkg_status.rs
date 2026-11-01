#![no_main]

use libfuzzer_sys::fuzz_target;

use domain::inventory::{apk_reading, dpkg_reading, parse_dpkg_list};

// A package database is read from inside a container's root, so every byte
// of it is the container's to choose. The first byte splits the input in two:
// a status file, and the list handed back for every package it names.
fuzz_target!(|data: &[u8]| {
    let Some((&cut, rest)) = data.split_first() else {
        return;
    };
    let (status, list) = rest.split_at(usize::from(cut) * rest.len() / 255);
    let _ = dpkg_reading(status, |_| Some(list.to_vec()));
    let _ = dpkg_reading(rest, |_| None);
    let _ = parse_dpkg_list(&String::from_utf8_lossy(rest));
    let _ = apk_reading("/lib/apk/db/installed", rest);
});
