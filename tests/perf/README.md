# eBPFsentinel - Performance & Benchmark Tests

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
├── measure-footprint.sh           # memory per configuration: maps, RSS, steady cgroup, startup peak (run from the host)
├── fixtures/                      # perf-only agent configs
│   └── bpf-qdisc/                 # benchmark-only BPF qdiscs perf/09 builds on the agent VM, and its traffic runner
├── results/                       # dated output of a run, the source of every figure quoted elsewhere
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
| `03-ebpf-map-operation-bench` | control-plane map-op latency (firewall / IOC / ratelimit / LB / DNS / IPS-blacklist / NPTv6 bulk load) | local |
| `04-pktgen-high-pps` | ≥ 1 Mpps XDP-drop CPU savings + SYN-cookie path | 2VM (pktgen) |
| `05-ebpf-feature-overhead-extended` | isolated per-feature throughput overhead: scrub, DNS, QoS, conntrack | 2VM |
| `06-ebpf-feature-overhead-nat-dlp` | NAT translation overhead (SNAT egress / DNAT ingress / both) + DLP uprobe SSL-inspection cost | local + 2VM |
| `07-attribution-overhead` | cost of naming the workload behind a flow, per connect() and per execve() | local |
| `08-mass-encryption-kill-latency` | time from a mass encryption verdict to the last process of the run gone, alone and forking a worker per directory | local |
| `09-bpf-qdisc-vs-edt-fq` | shaping by cgroup three ways on the same traffic: tc-qos departure times served by sch_fq, the same served by a BPF qdisc registered as fq, and a BPF qdisc shaping by itself; cost per packet, rate accuracy, fairness, latency | 2VM |

Remaining per-feature datapath suites - **L4 LB** (forwarded, 3VM) and **L7**
(HTTP via `run_http_bench`) - are planned alongside these; they need the 3VM
transit lane / an HTTP target and are added once calibrated on the agent VM.

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

### BPF qdisc against the departure time served by fq (perf/09)

The suite runs from the attacker VM, sending from the agent VM to it, so it
runs on the two-machine lane only. On its own, from `../integration/vagrant/`:

```bash
vagrant ssh attacker -c 'cd /home/vagrant/ebpfsentinel/tests/integration && \
  EBPF_2VM_MODE=true AGENT_VM_IP=192.168.56.10 ATTACKER_VM_IP=192.168.56.20 \
  AGENT_CTL_IP=192.168.56.10 AGENT_SSH_KEY=~/.ssh/agent_key \
  EBPFSENTINEL_STRICT_SKIPS=1 bats --timing ../perf/09-bpf-qdisc-vs-edt-fq.bats'
```

or with every other perf suite through `scripts/run-in-2vm.sh --performance`.
`QDISC_BENCH_SECONDS` (default 20) and `QDISC_BENCH_RUNS` (default 3) set the
length and number of runs per profile. The agent VM needs `clang` (provisioner
`bpf-c-toolchain`) and a kernel built with `CONFIG_NET_SCH_BPF`; the qdiscs are
built there by `fixtures/bpf-qdisc/build.sh`, which fetches the kernel's
`bpf_fq` selftest at the running kernel's tag and never commits it. Where the
kernel's BTF carries its kfuncs without the tag bpftool reads to print their
prototypes (Ubuntu's 7.0), `fixtures/bpf-qdisc/kfunc-externs.py` declares the
ones the sources call. The fq arm backed by the BPF qdisc runs first, because
it needs `sch_fq` out of the kernel: the lab boots with
`net.core.default_qdisc=fq`, so the arm lowers the default to `fq_codel`, puts
every interface still on fq back to its default, unloads the module, and
restores the default when it ends. Where the module is built in the arm is
skipped with its reason, and fails under `EBPFSENTINEL_STRICT_SKIPS=1`.

Nothing in `fixtures/bpf-qdisc/` is part of the agent: no crate loads it and no
release carries it. The suite registers each qdisc, measures it, and
unregisters it in teardown, so that no later suite is handed a BPF `fq`.

The report is `/tmp/ebpfsentinel-bpf-qdisc-vs-edt-fq.json` on the attacker VM:
every run's figures, the medians per arm and profile, and each BPF arm's
verdict against today's arm on the criteria written above the last test. Copy
it into `results/` under the run's date, as the other results are kept.

Methodology (baseline subtraction, 3-run averaging, thresholds) is documented in
[BENCHMARK-RESULTS.md](BENCHMARK-RESULTS.md).

## Per-program cost, off any lane

A suite measures what a packet pays through the whole chain, and the kernel
bills a tail call to whichever program was entered, so no suite here says what
one program costs. That is a separate command, needing root and the built
objects and no VM at all:

```bash
cargo xtask ebpf-build
sudo modprobe -a fou fou6 xfrm_interface     # kfuncs three programs call
sudo target/release/xtask ebpf-cost
```

It loads one object at a time under a pin directory of its own, runs each
program a million times on one 64-byte UDP frame with `BPF_PROG_TEST_RUN`, and
reports the cost twice: with the emptiness gates open and with every gate set.
It is a floor rather than a live figure, since no rule and no configuration are
loaded, and the recorded run is in
[BENCHMARK-RESULTS.md](BENCHMARK-RESULTS.md). It doubles as the cheapest way to
find out whether every program still loads past the verifier.

## Notes

- These are **nightly** in CI (heavy); they are not part of the fast PR lane.
- 3VM-lane suites (forwarded NAT / LB perf) need the transit topology - see
  `../integration/vagrant/` and the per-suite headers.
- Numbers are environment-sensitive (vCPU, NIC, nesting). Thresholds are set with
  headroom; treat absolute figures as indicative, regressions as the signal.
