## Summary

<!-- What changes and why, in a paragraph. -->

## Checks

CI runs these on the pull request; running them first saves a round trip (see `CONTRIBUTING.md`):

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo deny check`
- [ ] `cargo run -p xtask -- emit-openapi` leaves `openapi.json` unchanged, if a route moved
- [ ] the eBPF programs build (`cargo xtask ebpf-build`), if anything under `crates/ebpf-programs/` or `crates/ebpf-common/` changed

## How to verify

<!-- What a reviewer runs, or which bats suite covers it. A change to a kernel program says which kernel it was loaded on. -->

## Notes

<!-- Risk, follow-ups, anything else worth knowing. -->
