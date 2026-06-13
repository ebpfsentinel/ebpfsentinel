# eBPFsentinel — Performance & Benchmark Tests

Dedicated home for the **performance** test suites (throughput overhead, per-feature
cost, control-plane map-op latency, high-pps). They are kept separate from the
functional integration suites (`../integration/suites/`) because they are heavier,
run on the **nightly** CI tier, and assert on latency/throughput/CPU budgets rather
than correctness.

## Layout

```text
tests/perf/
├── README.md
├── Makefile                       # convenience targets (run on the agent VM, as root)
├── BENCHMARK-RESULTS.md           # methodology + recorded resource-consumption numbers
├── fixtures/                      # perf-only agent configs
└── *.bats                         # the perf suites
```

The suites **reuse the integration harness**: they `load '../integration/lib/...'`
(shared helpers, eBPF/VM helpers, `perf_helpers.bash`) and run on the **same agent
VM** provisioned by `../integration/vagrant/`. Only the `.bats` files and their
fixtures live here; there is no separate Vagrant box.

## Suites

| Suite | Measures | Lane |
|-------|----------|------|
| `01-performance-benchmark` | full-stack TCP/UDP throughput overhead + RSS (< 20 % / < 256 MB) | 2VM |
| `02-ebpf-feature-overhead` | incremental per-feature CPU overhead (firewall → IDS → ratelimit → threatintel → conntrack/DDoS) | 2VM |
| `03-ebpf-map-operation-bench` | control-plane map-op latency (rule / IOC / policy / backend / blocklist bulk load) | local |
| `04-pktgen-high-pps` | ≥ 1 Mpps XDP-drop CPU savings + SYN-cookie path | 2VM (pktgen) |
| `05-ebpf-feature-overhead-extended` | isolated per-feature throughput overhead: scrub, DNS, QoS, conntrack | 2VM |

Remaining per-feature datapath suites — **NAT** + **L4 LB** (forwarded, 3VM),
**L7** (HTTP via `run_http_bench`), **DLP** (uprobe-on-TLS), **IPS** (block
latency) — are planned alongside these; they need the 3VM transit lane / an HTTP
or TLS target and are added once calibrated on the agent VM.

## Running

Perf tests run on the agent VM as root. From `../integration/`:

```bash
make vagrant-up                # bring up the agent VM (shared with integration)
make test-performance          # just the throughput-overhead benchmark (perf/01)
make test-perf                 # the full perf suite (all of tests/perf/*.bats)
```

Or directly on the agent VM:

```bash
cd /home/vagrant/ebpfsentinel/tests/perf
sudo bats 02-ebpf-feature-overhead.bats        # one suite
sudo bats *.bats                               # all
```

Methodology (baseline subtraction, 3-run averaging, thresholds) is documented in
[BENCHMARK-RESULTS.md](BENCHMARK-RESULTS.md).

## Notes

- These are **nightly** in CI (heavy); they are not part of the fast PR lane.
- 3VM-lane suites (forwarded NAT / LB perf) need the transit topology — see
  `../integration/vagrant/` and the per-suite headers.
- Numbers are environment-sensitive (vCPU, NIC, nesting). Thresholds are set with
  headroom; treat absolute figures as indicative, regressions as the signal.
