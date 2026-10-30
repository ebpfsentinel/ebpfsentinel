# Seeds for `fuzz_suricata`

Each `.rules` file is one rule copied verbatim from Emerging Threats Open, in
the sid range 2000000 to 2799999 that Proofpoint publishes under the BSD
licence. They cover what the compiler accepts (chained contents, hex bytes,
port ranges, thresholds) and what it refuses (a relative pcre, a
backreference), so the fuzzer starts from real-world syntax rather than from
nothing.

    cargo +nightly fuzz run fuzz_suricata fuzz/corpus/fuzz_suricata fuzz/seeds/fuzz_suricata

The first directory is where the fuzzer writes what it finds and is ignored by
git; the second is read only.
