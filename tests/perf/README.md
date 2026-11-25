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
│   ├── bpf-qdisc/                 # benchmark-only BPF qdiscs perf/09 builds on the agent VM, and its traffic runner
│   ├── xdp-frags/                 # perf/10's agent-side reader: snapshots and BPF_PROG_TEST_RUN timing
│   ├── tx-timestamps/             # perf/12's agent-side iperf3 sender with its CPU and bpf_stats readings
│   └── xdp-tc-meta-handoff/       # benchmark-only XDP and tc programs perf/13 builds on the agent VM, and their runner
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
| `10-xdp-frags-pull-cost` | what declaring multi-buffer frames costs xdp_firewall on 1500-byte and jumbo frames against the objects from before the declaration (ns per run, pps, kernel CPU per packet), and what pulling a frame's head into its first buffer costs (`BPF_PROG_TEST_RUN`) | 2VM (pktgen) |
| `11-tamper-guard-verified-insns` | instructions the verifier walks per lsm-tamper-guard program, now and before the cgroup file name comparison moved to `bpf_strcmp`, on one kernel | local |
| `12-tcp-tx-timestamp-cost` | throughput and CPU per write of a TCP sender with `tcp_health` off, with it on and `send_latency` off, and with both on; small writes and bulk writes; sock_ops runs and ns per write | 2VM |
| `13-xdp-tc-meta-handoff` | the parse XDP made handed to the tc ingress chain through the packet's metadata (`bpf_dynptr_from_skb_meta`) against today's parse in the first tc program handed on in `skb->cb`; ns per packet, pps, CPU, and whether the metadata reaches tc on vmxnet3 and veth, tagged or not | 2VM |

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

### Multi-buffer XDP frames and the head pull (perf/10)

Answers two questions the header of the suite states with its pass criteria
and limits: whether declaring multi-buffer frames (`BPF_F_XDP_HAS_FRAGS`) costs
xdp_firewall anything on frames that fit one buffer and on jumbo frames, and
what the pull of a frame's head into its first buffer
(`bpf_xdp_pull_data`, counted in `frags_pulled`) costs when it runs. The first
is measured on the wire, pktgen from the attacker VM flooding the agent VM's
`eth1`, current objects against baseline objects in interleaved pairs. The
second is measured with `BPF_PROG_TEST_RUN` on the live program, because a
vmxnet3 or veth frame keeps its headers in the first buffer and the pull never
runs on the wire here: one jumbo frame laid out whole against the same frame
with a 34-byte first buffer (the Ethernet and IPv4 headers in it, the UDP
header past it, so the parse fails and the pull runs), one run per call.

The baseline is the seven `xdp-*` objects of the commit before the
declaration, built and signed on the host, then put on the agent VM where the
suite lays them over a copy of `/usr/local/lib/ebpfsentinel` and bind-mounts
the copy for the baseline arm only, so the agent binary, the other objects,
the kernel and the configuration stay the same. From the repository root:

```bash
git worktree add /tmp/xdp-baseline 44d05584^
(cd /tmp/xdp-baseline && cargo xtask ebpf-build)
mkdir -p /tmp/xdp-baseline-objects
for o in xdp-firewall xdp-firewall-reject xdp-ratelimit xdp-ratelimit-syncookie \
         xdp-loadbalancer xdp-vip-announcer xdp-pass; do
  cp /tmp/xdp-baseline/target/bpfel-unknown-none/release/$o /tmp/xdp-baseline-objects/
done
git rev-parse 44d05584^ > /tmp/xdp-baseline-objects/COMMIT
# Signed with this tree's xtask and the key the lab's objects carry (the
# committed test key unless EBPFSENTINEL_LOADER_SIGNING_KEY/_CERT are set).
cargo xtask ebpf-sign --dir /tmp/xdp-baseline-objects
cd tests/integration/vagrant
vagrant upload /tmp/xdp-baseline-objects /var/tmp/ebpfsentinel-xdp-baseline agent
git worktree remove /tmp/xdp-baseline
```

The suite refuses to start when the baseline's `loader-signing.der` differs
from the one under `/usr/local/lib/ebpfsentinel`. Then, from
`../integration/vagrant/`, with a host-side bound:

```bash
timeout 2700 vagrant ssh attacker -c 'cd /home/vagrant/ebpfsentinel/tests/integration && \
  EBPF_2VM_MODE=true AGENT_VM_IP=192.168.56.10 ATTACKER_VM_IP=192.168.56.20 \
  AGENT_CTL_IP=192.168.56.10 AGENT_SSH_KEY=~/.ssh/agent_key \
  EBPFSENTINEL_STRICT_SKIPS=1 bats --timing ../perf/10-xdp-frags-pull-cost.bats'
```

`XDP_BASELINE_DIR` (default `/var/tmp/ebpfsentinel-xdp-baseline`, on the agent
VM), `XDP_BENCH_SECONDS` (default 20), `XDP_BENCH_PAIRS` (default 3),
`XDP_TESTRUN_RUNS` (default 2000, after `XDP_TESTRUN_WARMUP` 200), `JUMBO_MTU`
(default 9000) and `PULL_LINEAR` (default 34) set the runs; `XDP_MAX_NS_RATIO`,
`XDP_MAX_NS_ABS`, `XDP_MIN_PPS_RATIO` and `XDP_PULL_MAX_NS` the bounds. The
agent VM needs `python3` and `bpftool`. The jumbo test sets both VMs' `eth1` to
`JUMBO_MTU` with the agent stopped, skips with the reason when the path between
the VMs refuses such frames, and puts the MTUs back in teardown. A baseline
that does not attach at the jumbo MTU is recorded as such and leaves the jumbo
criteria without a baseline, which the report says.

### Verifier instruction count of the tamper guard (perf/11)

Reads `verified_insns` for each lsm-tamper-guard program from the objects the
agent VM runs and from the object of the commit before the cgroup file name
comparison moved to `bpf_strcmp`, on the same kernel, loaded three times each.
It is a perf suite because it measures a cost and keeps a dated result; it
asserts nothing about what the guard does. It runs on the agent VM as root
(local lane), since the count belongs to the kernel that verifies.

Build the baseline object on the host and put it on the agent VM:

```bash
git worktree add /tmp/tamper-baseline 33c5e585^
(cd /tmp/tamper-baseline && cargo xtask ebpf-build)
mkdir -p /tmp/tamper-baseline-objects
cp /tmp/tamper-baseline/target/bpfel-unknown-none/release/lsm-tamper-guard /tmp/tamper-baseline-objects/
git rev-parse 33c5e585^ > /tmp/tamper-baseline-objects/COMMIT
cd tests/integration/vagrant
vagrant upload /tmp/tamper-baseline-objects /var/tmp/ebpfsentinel-tamper-guard-baseline agent
git worktree remove /tmp/tamper-baseline
```

Two loaders can answer, and the criteria read one loader for both trees:
`cargo xtask ebpf-load` (the agent's own loader, preferred) and
`bpftool prog loadall`. The rsync to the VM leaves `target/` out, so the
xtask binary is uploaded where it should be used (`cargo build -p xtask`, then
`vagrant upload ../../../target/debug/xtask /var/tmp/xtask agent`); a binary
built against a newer C library than the VM's will not start there, and
bpftool answers alone. Then:

```bash
timeout 600 vagrant ssh agent -c 'cd /home/vagrant/ebpfsentinel/tests/perf && \
  sudo EBPFSENTINEL_STRICT_SKIPS=1 XTASK_BIN=/var/tmp/xtask bats --timing 11-tamper-guard-verified-insns.bats'
```

`TAMPER_GUARD_BASELINE_DIR` (default
`/var/tmp/ebpfsentinel-tamper-guard-baseline`), `TAMPER_GUARD_CURRENT_DIR`
(default `EBPF_PROGRAM_DIR`, else `/usr/local/lib/ebpfsentinel`, else the
tree's release build), `LOADS` (default 3) and `TAMPER_GUARD_MAX_GROWTH_INSNS`
(default 0) set the run.

### Per-write cost of the TCP transmit timestamps (perf/12)

Runs an iperf3 sender on the agent VM, where `tcp_health.send_latency`
attaches its sock_ops program, to an iperf3 server on the attacker VM, in
three arms (`tcp_health` off; on with `send_latency` off; both on) and two
write profiles (64-byte writes with `TCP_NODELAY`, 128 KiB writes), interleaved
per round. The arms, criteria and limits are written at the top of the suite.
From `../integration/vagrant/`, with a host-side bound:

```bash
timeout 2700 vagrant ssh attacker -c 'cd /home/vagrant/ebpfsentinel/tests/integration && \
  EBPF_2VM_MODE=true AGENT_VM_IP=192.168.56.10 ATTACKER_VM_IP=192.168.56.20 \
  AGENT_CTL_IP=192.168.56.10 AGENT_SSH_KEY=~/.ssh/agent_key \
  EBPFSENTINEL_STRICT_SKIPS=1 bats --timing ../perf/12-tcp-tx-timestamp-cost.bats'
```

`TS_BENCH_SECONDS` (default 15), `TS_BENCH_RUNS` (default 5 rounds),
`TS_SMALL_LEN` (64), `TS_BULK_LEN` (131072), `TS_PORT` (5412) and
`TS_SENDER_CPU` (default `auto`: the agent VM's last CPU; empty to leave the
sender unpinned) set the runs; `TS_SMALL_MIN_TPUT_RATIO`,
`TS_SMALL_MAX_CPU_RATIO`, `TS_BULK_MIN_TPUT_RATIO` and `TS_BULK_MAX_CPU_RATIO`
the bounds. The agent VM needs `iperf3`, `python3` and `bpftool`.
`kernel.bpf_stats_enabled` is set for the run and put back in teardown.

### Where perf/10, perf/11 and perf/12 write

Each writes `/tmp/ebpfsentinel-<name>.json` and
`results/<date>-<name>/` beside the suite (`report.json` and the raw readings
under `raw/`), on the machine bats ran on: the attacker VM for perf/10 and
perf/12, the agent VM for perf/11. `PERF_RESULTS_DIR` moves the second. The
lanes' trees are rsync copies, so bring the directory back to this tree after
the run, for instance from `../integration/vagrant/`:

```bash
vagrant ssh attacker -c 'tar -C /home/vagrant/ebpfsentinel/tests/perf/results -cf - <date>-xdp-frags-pull-cost' \
  | tar -C ../../perf/results -xf -
```

(`agent` in place of `attacker` for perf/11). No figure from these suites is
quoted in [BENCHMARK-RESULTS.md](BENCHMARK-RESULTS.md) until such a run exists.

### XDP to tc handoff through the packet metadata (perf/13)

Decides whether the tc ingress chain should read the parse the XDP program
already made, written in front of the packet with `bpf_xdp_adjust_meta` and
read through `bpf_dynptr_from_skb_meta`, instead of parsing again in its first
program as `pktmeta::resolve` does today. The pass criteria, the arms, why the
fixtures stand for the product and what the suite cannot tell are written at
the top of the suite. It floods the agent VM's `eth1` from the attacker VM, so
it runs on the two-machine lane only, with the agent stopped (it refuses to
attach next to an XDP or tcx program it did not load). On its own, from
`../integration/vagrant/`, with a host-side bound:

```bash
timeout 2700 vagrant ssh attacker -c 'cd /home/vagrant/ebpfsentinel/tests/integration && \
  EBPF_2VM_MODE=true AGENT_VM_IP=192.168.56.10 ATTACKER_VM_IP=192.168.56.20 \
  AGENT_CTL_IP=192.168.56.10 AGENT_SSH_KEY=~/.ssh/agent_key \
  EBPFSENTINEL_STRICT_SKIPS=1 bats --timing ../perf/13-xdp-tc-meta-handoff.bats'
```

or with the other perf suites through `scripts/run-in-2vm.sh --performance`.
`HANDOFF_SECONDS` (default 15, at least 8), `HANDOFF_RUNS` (default 3) and
`HANDOFF_CHAIN` (default 6, the tc programs in the chain) set the runs. The
agent VM needs `clang` (provisioner `bpf-c-toolchain`), `bpftool`, `python3`,
`ethtool` and `iperf3`, and a kernel whose BTF carries
`bpf_dynptr_from_skb_meta`; `fixtures/xdp-tc-meta-handoff/build.sh` builds the
object there from the running kernel's BTF and fetches nothing, borrowing
`fixtures/bpf-qdisc/kfunc-externs.py` where the BTF does not tag its kfuncs.
The facts tests switch `eth1`'s receive VLAN offload on and off and put the
value it had back, add VLAN links on both VMs and a veth pair into a namespace
on the agent VM, and remove them when they end.

Nothing in `fixtures/xdp-tc-meta-handoff/` is part of the agent: no crate loads
it and no release carries it. The suite pins its programs under
`/sys/fs/bpf/hm-handoff`, detaches them by their own descriptors, and removes
the pins in teardown.

The report goes to `results/<date>-xdp-tc-meta-handoff/report.json` beside the
suite, with the build log, and to `/tmp/ebpfsentinel-xdp-tc-meta-handoff.json`,
both on the attacker VM: every run's readings, the probe's counts per cell, the
medians, the four criteria and the decision. The lane's tree is an rsync copy,
so bring the directory back to this tree after the run, for instance
`vagrant ssh attacker -c 'tar -C /home/vagrant/ebpfsentinel/tests/perf/results -cf - <date>-xdp-tc-meta-handoff' | tar -C ../../perf/results -xf -`
from `../integration/vagrant/`.

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
