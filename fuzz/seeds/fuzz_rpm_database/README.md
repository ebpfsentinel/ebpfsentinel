# Seeds for `fuzz_rpm_database`

The rpm SQLite database of `crates/domain/tests/fixtures/inventory`, nineteen
packages and one public key, so the fuzzer starts from pages, cells and
header blobs that read rather than from a file the first check refuses.

    cargo +nightly fuzz run fuzz_rpm_database fuzz/corpus/fuzz_rpm_database fuzz/seeds/fuzz_rpm_database

The first directory is where the fuzzer writes what it finds and is ignored by
git; the second is read only.
