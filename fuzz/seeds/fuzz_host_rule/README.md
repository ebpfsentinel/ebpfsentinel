# Seeds for `fuzz_host_rule`

Each `.json` file is one rule of `crates/infrastructure/src/config/host_rules_shipped.yaml`
written as the one-element list the API and the configuration carry: plain
matchers, a negated boolean, a count with a distinct field, a sequence with its
window. The fuzzer starts from rules that load, so it spends its time on the
compiler's refusals and on the matcher rather than on finding a valid shape.

    cargo +nightly fuzz run fuzz_host_rule fuzz/corpus/fuzz_host_rule fuzz/seeds/fuzz_host_rule

The first directory is where the fuzzer writes what it finds and is ignored by
git; the second is read only.
