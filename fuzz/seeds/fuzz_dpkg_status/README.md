# Seeds for `fuzz_dpkg_status`

The dpkg status file and the Alpine installed database of
`crates/domain/tests/fixtures/inventory`, each behind one leading `0xff` byte.
The target splits its input at a point the first byte chooses and hands the
rest to the status reader and the second half as every package's file list,
so `0xff` puts the whole database on the status side.

    cargo +nightly fuzz run fuzz_dpkg_status fuzz/corpus/fuzz_dpkg_status fuzz/seeds/fuzz_dpkg_status

The first directory is where the fuzzer writes what it finds and is ignored by
git; the second is read only.
