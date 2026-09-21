# eBPFsentinel - Performance Benchmarks

**In one line: a packet walks 6 eBPF programs for about 1 microsecond of kernel
time, and the full stack locks 71 MB of maps on a 4-vCPU node.** That is the
section below; the other two datasets answer different questions.

| dataset | question it answers | when |
|---|---|---|
| Cross-VM measurement | what a real vmxnet3 NIC does with the agent in the path | 2026-06-14 |
| Cost of the full stack | what one packet costs, and what the maps cost | 2026-09-21 |
| Production CPU matrix | CPU% per feature at fixed traffic volumes | 2026-03-22 |

The 2026-03-22 matrix is kept for its per-feature CPU shape; its `RSS (MB)`
columns predate the conntrack migration of 2026-04-16 and are superseded by the
memory table in the 2026-09-21 section.

> **On absolute throughput.** iperf3 over the paravirtual vmxnet3 NIC is
> CPU-bound on the host, so the *baseline* (no-agent) link rate varies with how
> busy the host is - ~8.3 Gbps on an idle host, ~3-4 Gbps when the host is
> loaded. What is **reproducible** is the agent's *own* behaviour relative to a
> baseline measured the same way on the same path - that is what the tables
> below report. Earlier revisions of this file showed ~59 Gbps "throughput":
> that was an in-VM **veth** measurement (no NIC in the path, kernel `memcpy`
> ceiling) and has been removed as misleading.

---

## Cross-VM measurement (real NIC)

| Parameter    | Value                                                      |
| ------------ | ---------------------------------------------------------- |
| Kernel       | 6.17.0-35-generic                                          |
| Topology     | 2 VMs over vmxnet3, `192.168.56.0/24` (attacker → agent)   |
| Agent load   | BPF-token launcher (rootless, kernel 6.9+ token)           |
| Traffic tool | iperf3 (TCP/UDP)                                            |

### Link baseline (no agent)

iperf3 between the two VMs, no agent in the path - the link ceiling under the
current host load.

| Test               | Idle host  | Loaded host |
| ------------------ | ---------- | ----------- |
| TCP, single stream | 8.31 Gbps  | ~3.2 Gbps   |
| TCP, 4 streams     | 8.69 Gbps  | -           |
| UDP, single stream | 1.40 Gbps  | iperf3 sender-CPU bound |

### Per-feature datapath cost (isolated, idle host)

Each feature measured alone over a firewall-pass base, vs the no-agent baseline
on the same path (idle host, ~8-8.7 Gbps baseline). This is the **true
per-packet eBPF cost** - every program here is cheap:

| Feature              | Overhead | Source   |
| -------------------- | -------- | -------- |
| firewall (xdp)       | ~0 (noise) | perf/02 |
| ids (tc)             | ~0 (noise) | perf/02 |
| nat egress (tc)      | 1.5 %    | perf/06  |
| scrub (tc)           | 1.5 %    | perf/05  |
| dns capture (tc)     | 2.5 %    | perf/05  |
| qos (tc)             | 3.1 %    | perf/05  |
| conntrack (tc)       | 5.5 %    | perf/05  |

- **The whole datapath costs ≤ ~5.5 % per feature** on a single TCP flow.
  Firewall and IDS are within noise - the XDP HashMap/LPM fast-path is effectively
  free for iperf3's single 5-tuple. The TC programs (scrub/dns/qos/conntrack/nat)
  add a few percent each. Consistent with the production CPU matrix below.

### XDP attachment mode - native vs generic (vmxnet3)

The agent's XDP datapath loads in either **native** (driver, pre-`sk_buff`) or
**generic** (SKB, post-`sk_buff`) mode; `xdp_mode: auto` (default) picks native.
vmxnet3 supports both - **offloaded is not available** (paravirtual NIC, no
SmartNIC). Same firewall-pass config, single TCP flow, idle host:

| Mode                  | Throughput | Overhead vs baseline |
| --------------------- | ---------- | -------------------- |
| baseline (no agent)   | ~7.76 Gbps | -                    |
| native (`xdp`)        | ~7.84 Gbps | ~0 %                 |
| generic (`xdpgeneric`)| ~6.0 Gbps  | **~23 %**            |

- **Generic XDP costs ~23 % throughput vs native** on vmxnet3 because the program
  runs after the kernel allocates an `sk_buff` (same position as a TC hook),
  losing native's pre-allocation fast-path. This is why `xdp_mode: auto`
  (native-first) is the right default, and a large part of why the earlier
  single-VM **veth** lane (generic XDP, no NIC) showed 85-95 % "overhead" -
  generic mode *and* no physical NIC compounded.

### Full eBPF stack - throughput is rate-limit-bound, not CPU-bound

With **every** program enabled the single-flow TCP throughput collapses to
~1.4-2 Gbps ("73-83 % overhead"). **This is not eBPF CPU cost - it is the rate
limiter enforcing its policy.** The benchmark config enables a **global rate
limit of 100 000 pps**; iperf3 floods at ~666 000 pps (8 Gbps ÷ 1500 B), so
xdp-ratelimit drops the excess and pins throughput at ~the configured rate.

| Step (cumulative)            | Throughput | "Overhead" | What it shows |
| ---------------------------- | ---------- | ---------- | ------------- |
| firewall                     | 8.33 Gbps  | ~0         | free          |
| + ids                        | ~8.2 Gbps  | ~0         | free          |
| **+ ratelimit**              | **1.40 Gbps** | **83 %** | **rate-limit enforcing (100k pps), not CPU** |
| + threatintel … all          | 1.38 Gbps  | 83 %       | already rate-capped |

- **The ~1.6 Gbps "cap" seen throughout this work was the rate limiter doing its
  job**, not contamination and not a CPU ceiling. Disable ratelimit (or raise its
  rate above the test's pps) and the full-stack throughput tracks the cheap
  per-feature costs above. For a CPU-overhead view at a held sub-limit rate, see
  the production matrix below.
- **Agent RSS ~2 MB.**

### Control-plane map-op latency (perf/03)

End-to-end REST latency of the two newly-covered write paths, run from
`127.0.0.1` (loopback is exempt from the write rate limit by default, so the
full bulk lands). Lane-independent - these are control-plane, not datapath.

| Op                    | Count | Wall      | per-op | ok        |
| --------------------- | ----- | --------- | ------ | --------- |
| IPS blacklist inject  | 100   | 2054 ms   | ~21 ms | 100/100   |
| IPS blacklist inject  | 1000  | 23531 ms  | ~24 ms | 1000/1000 |
| NPTv6 prefix-rule add | 10    | 377 ms    | ~38 ms | 10/10     |
| NPTv6 prefix-rule add | 100   | 2620 ms   | ~26 ms | 100/100   |

Per-op latency is dominated by the `curl` round-trip, not the kernel map write -
an end-to-end REST cost for capacity planning of bulk reconfiguration. The write
API is governed at 60 burst / 1 req-s per IP; loopback is exempt (configurable
via `agent.api_rate_limit.*`), so bulk loads from the same host are not throttled
- from a remote host past the burst they 429 by design.

> **perf/04 (pktgen ≥ 1 Mpps)** is not in this table - it drives pktgen from the
> attacker NIC and needs a calibrated high-pps setup; its XDP-drop CPU-savings
> figures are in the production matrix.

---

## Cost of the full stack (2026-09-21)

Measured by `../../../ebpfsentinel-enterprise/tests/perf/bench-oss-vs-enterprise.sh`
on two VMware guests (agent VM: 4 vCPU, 3.9 GB, vmxnet3 at 10 Gbps, kernel 7.0),
pktgen 64-byte UDP frames, three windows of 15 s per cell, median reported.
Reference run: `ebpfsentinel-enterprise/tests/perf/results/2026-09-21-pktgen-64-head/`,
both agents built from a clean checkout. Every earlier run is indexed in
`results/README.md`.

### Headline

**A received packet walks 6 eBPF programs and pays about 1 microsecond of kernel
time for the lot.** At the rate this pair of guests reaches - 90 kpps, 0.05 Gbps
- that is under 0.1 of one core out of 4, and the whole guest's CPU is within
0.01 core of the same guest with no agent loaded.

| | OSS | Enterprise |
|---|---:|---:|
| eBPF programs a received packet walks | 6 | 6 |
| ns per packet at 25 kpps | 1458 | 1219 |
| ns per packet at 50 kpps | 1057 | 1041 |
| ns per packet at 90+ kpps | 967 | 865 |
| eBPF cores at 90+ kpps | 0.087 | 0.082 |
| guest cores above the no-agent baseline | +0.00 | +0.01 |
| agent RSS | 60 MB | 89 MB |
| map memory locked | 67.7 MB | 67.6 MB |

Per-packet cost falls as the rate rises: the fixed part - a cold map line, the
first packet of a flow - is amortised over more packets. Rank two profiles on
ns/pkt and never on ns/run, since a profile running one extra cheap program
reads as a lower ns/run while costing the packet more.

### Where the time goes (25 kpps)

| program | OSS | Enterprise |
|---|---:|---:|
| `xdp_firewall` | 712 ns (50%) | 630 ns (52%) |
| `tc_conntrack` | 292 ns | 226 ns |
| `tc_ids` | 215 ns | 234 ns |
| `tc_threatintel` | 126 ns | 60 ns |
| `tc_dns` | 41 ns | 23 ns |
| `tc_nat_ingress` | 39 ns | 34 ns |
| `tc_nat_egress` | 0 ns | 0 ns |
| **whole chain** | **1425 ns** | **1208 ns** |

`tc_nat_egress` reads zero because it is on the egress path: it runs on what the
machine sends, not on what it receives.

Read the first row as a subtree rather than as a program. The kernel bills a
tail call to whichever program was entered, so the 712 ns against
`xdp_firewall` is the firewall plus `xdp_ratelimit` plus `xdp_loadbalancer`,
and no row here says what any single program costs. The table below does.

### Per-program cost (`BPF_PROG_TEST_RUN`)

`cargo xtask ebpf-cost` loads one object at a time, pins its maps under a
directory of its own so no table another program filled can be hit, and runs
each program a million times on one 64-byte UDP frame, keeping the best of
three rounds. Root, and the built objects. Two kernel modules export kfuncs
three of the programs call, so `modprobe -a fou fou6 xfrm_interface` comes
first or those three report a missing kfunc rather than a cost.

Every program is measured twice: with the emptiness gates open, which is what a
lookup costs when it runs and misses, and with every gate set, which is what
the program costs when userspace has told it the tables behind it are empty.

| program | hook | gates open | gates set | saved |
|---|---|---:|---:|---:|
| `tc_qos_ingress` | TC | 221 ns | 5 ns | 98% |
| `tc_qos` | TC | 220 ns | 5 ns | 98% |
| `xdp_firewall` | XDP | 46 ns | 18 ns | 61% |
| `xdp_ratelimit` | XDP | 38 ns | 25 ns | 34% |
| `tc_ids` | TC | 29 ns | 10 ns | 66% |
| `xdp_firewall_reject` | XDP | 23 ns | 23 ns | 0% |
| `xdp_loadbalancer` | XDP | 14 ns | 15 ns | 0% |
| `xdp_ratelimit_syncookie` | XDP | 11 ns | 13 ns | 0% |
| `tc_nat_ingress` | TC | 8 ns | 8 ns | 0% |
| `tc_nat_egress` | TC | 7 ns | 7 ns | 0% |
| `tc_dns`, `tc_conntrack` | TC | 6 ns | 6 ns | 0% |
| `tc_threatintel`, `tc_scrub` | TC | 5 ns | 5 ns | 0% |
| `xdp_vip_announcer`, `xdp_pass` | XDP | 4 ns | 9 ns | noise |
| **sum** | | **647 ns** | **169 ns** | |

The shaper is the most expensive program in the tree, ahead of the firewall by
a factor of five, which the live lane could not show because it sits on the
other hook. Its classification ladder walks a rule shape at a time from the
exact five-tuple down to the catch-all, twice, once scoped to the packet's VLAN
and once for the rules naming none, so an unmarked packet costs sixteen hash
lookups and a marked one thirty. An estate loading no shaping rule pays none of
it.

Four cautions, because these numbers are not the live lane's and do not
replace them:

1. A tight loop on a warm cache with no DMA and no NIC. The floor is about
   4 ns, which is the loop itself, so every row at 5 or 6 ns is at the floor
   and has nothing left to give. The two rows marked noise read slower with
   their gates set although they read no gate at all, which is the same floor
   seen from below.
2. No rule is loaded. The left column is a lookup that misses, not one that
   matches, so it is a lower bound on what a configured estate pays.
3. No configuration is loaded either, so `tc_conntrack`, `tc_dns`, `tc_scrub`
   and `tc_threatintel` measure their disabled path and return before doing
   any work. `tc_conntrack` costs 292 ns on the live lane and 6 ns here for
   that reason, and its conntrack kfunc is never called.
4. `uprobe-dlp` is absent: `BPF_PROG_TEST_RUN` takes a packet, so it reaches
   the two hooks that carry one and no other.

A TC program returns -1, which is `TCX_NEXT` and the pass verdict under TCX; an
XDP program returns 2 for `XDP_PASS`. The two tail-call targets return 1,
`XDP_DROP`, because nothing configured them.

### Memory

Measured on the agent VM, one agent start per configuration, `bytes_memlock`
summed over every loaded map.

| configuration | programs | maps | map memory | agent RSS |
|---|---:|---:|---:|---:|
| no feature enabled | 15 | 2 | 0.3 MB | 27 MB |
| firewall only | 17 | 40 | 14.9 MB | 42 MB |
| rate limiting only | 17 | 27 | 48.0 MB | 42 MB |
| threat intelligence only | 16 | 9 | 2.0 MB | 42 MB |
| everything (lane fixture) | 24 | 89 | 71.0 MB | 57 MB |

The warden adds 2.3 MB whatever the configuration. Rate limiting is most of the
map bill: `RL_BUCKETS` 22 MB and `CONN_TABLE` 12 MB, both LRU per-CPU hashes.
**A per-CPU map costs its entries once per online CPU**, so these figures, read
on a 4-vCPU VM, are larger on a bigger node - that is the one number to scale
before sizing a container limit. Against the 512Mi the chart sets, the full
fixture leaves comfortable room; it did not in September, see below.

### What the September work bought

| change | what it did | measured effect |
|---|---|---|
| tc chain on egress, parse once (2026-09-21) | SNAT moved to the egress hook, the parse result handed down the chain in `skb->cb` | 7 to 6 programs per received packet |
| map capacity from the configuration (2026-09-21) | tables sized at load from what is configured rather than from a compile-time constant | 365 to 71 MB of locked maps, same fixture |
| conntrack BTF offsets (2026-09-20) | offsets read from the BTF the kfunc loader already parses, instead of shelling out to `bpftool btf dump -j` and parsing the whole vmlinux as JSON | agent RSS 360-408 MB down to 57 MB |
| empty-table gates (2026-09-21) | a lookup whose table is empty is skipped; userspace publishes a bitmask, an unwritten entry reads 0 so a stale value can only cost a lookup, never change a verdict | below the lane's resolution; measured per program with `BPF_PROG_TEST_RUN` |

### What these numbers are not

- **The lane resolves about 15%.** Builds differing by gates worth tens of
  nanoseconds read 1241, 1458, 1487, 1566 and 1707 ns/pkt across the day's runs.
  The lane proves the absence of a regression; a change to one program is
  measured with `BPF_PROG_TEST_RUN`, which is repeatable to a few percent.
- **90 kpps is the pair of guests, not the NIC.** Absolute throughput on a real
  NIC is the cross-VM dataset above.
- **Enterprise reading lower than OSS is not a property of enterprise.** The two
  run under different launchers - OSS under the warden broker and a BPF token in
  a user namespace, enterprise as root - and the gap sits inside the spread.

---

## Production reference - 2-VM real-NIC CPU overhead (2026-03-22)

> Headline: **with all eBPF programs enabled the agent adds 0 % measurable CPU at
> 1 Gbps and < 1 % at 5 Gbps** at fixed traffic volumes below the configured rate
> limit. This is the CPU-cost view; the cross-VM section above is the max
> single-flow throughput (which the rate-limit policy, not CPU, bounds).

Per-feature: system CPU with the agent minus system CPU without it (baseline) at
the same traffic volume, averaged over 3 runs.

### Test environment

| Parameter          | Value                             |
| ------------------ | --------------------------------- |
| Kernel             | 6.8.0-86-generic                  |
| vCPU / RAM         | 2 vCPU / 2 GB                     |
| Topology           | 2-VM (real NIC, 192.168.56.0/24)  |
| Traffic tool       | iperf3 (TCP)                      |
| Max link bandwidth | ~9.4 Gbps                         |

### Individual features

| Feature     | Idle | 100 Mbps | 500 Mbps | 1 Gbps | 5 Gbps | RSS (MB) |
| ----------- | ---- | -------- | -------- | ------ | ------- | -------- |
| firewall    | 0.0% | 0.0%     | 0.0%     | 0.0%   | 0.9%    | 6.5      |
| ids         | 0.0% | 0.0%     | 0.0%     | 0.0%   | 3.0%    | 6.6      |
| ips         | 0.0% | 0.0%     | 0.0%     | 0.0%   | 1.6%    | 6.6      |
| ratelimit   | 0.1% | 0.0%     | 0.1%     | 0.0%   | 0.0%    | 6.6      |
| threatintel | 0.0% | 0.0%     | 0.0%     | 0.0%   | 0.0%    | 6.6      |
| conntrack   | 0.0% | 0.0%     | 0.0%     | 0.0%   | 1.8%    | 6.6      |
| ddos        | 0.0% | 0.0%     | 0.2%     | 0.0%   | 1.2%    | 6.6      |
| dns         | 0.0% | 0.0%     | 0.0%     | 0.0%   | 1.4%    | 6.4      |

- At 1 Gbps and below every feature adds 0 % measurable CPU. At 5 Gbps the
  costliest are IDS (3.0 %) and conntrack (1.8 %); firewall is cheap (0.9 %).
  RSS constant at 6.4-6.6 MB.

### Feature combinations

| Features                         | 5 Gbps | RSS (MB) |
| -------------------------------- | ------ | -------- |
| firewall + ids                   | 0.0%   | 6.6      |
| ids + ips                        | 4.7%   | 6.6      |
| ids + threatintel                | 2.1%   | 6.6      |
| conntrack + ddos                 | 2.7%   | 6.5      |
| firewall + ids + ips + ratelimit | 0.0%   | 6.6      |

- Feature stacking is **sublinear** (ids+ips 4.7 % < 3.0 + 1.6). The XDP
  tail-call chain (firewall + ratelimit) adds 0 % even at 5 Gbps.

### Realistic workload scenarios

Production-like config (100 firewall rules + ids + ips + conntrack + ratelimit +
threatintel + ddos + dns) under attack-like traffic.

| Scenario        | What it exercises                       | eBPF cost |
| --------------- | --------------------------------------- | --------- |
| **SYN flood**   | ratelimit + syncookie + DDoS detection  | **3.5 %** |
| DNS (UDP:53)    | tc-dns packet capture                   | 1.8 %     |
| IDS payloads    | tc-ids pattern matching                 | 0.8 %     |
| UDP flood       | DDoS amp detection                      | 0.7 %     |
| TCP multi-port  | firewall rule scan + conntrack          | 0.2 %     |

### Sizing recommendations

| Throughput Target | Recommended vCPUs | Notes                              |
| ----------------- | ----------------- | ---------------------------------- |
| ≤ 1 Gbps          | 1 vCPU            | All features, 0 % eBPF overhead    |
| 1-5 Gbps          | 1 vCPU            | All features, < 3 % eBPF overhead  |
| 5-10 Gbps         | 2 vCPU            | comfortable headroom               |
| 10+ Gbps          | scale w/ traffic + flows | DPI is per-flow CPU-bound - spread load across flows/queues |

Memory: the `RSS (MB)` columns of this section are from 2026-03-22 and were
true then; the conntrack migration of 2026-04-16 moved the agent's resident
size. Size memory from the `### Memory` table of the 2026-09-21 section.

---

## Reproducing

The cross-VM suites run from the attacker VM against the agent VM:

```bash
# From tests/integration/  (boots both VMs, runs perf suites in 2-VM mode)
./scripts/run-in-2vm.sh --performance

# Or a single suite from the attacker VM:
EBPF_2VM_MODE=true AGENT_VM_IP=192.168.56.10 ATTACKER_VM_IP=192.168.56.20 \
  AGENT_SSH_KEY=~/.ssh/agent_key bats ../perf/01-performance-benchmark.bats
```

> **Reliable numbers need an idle host** (the vmxnet3 baseline halves under host
> load) and **one suite at a time / a clean agent between suites** - the per-suite
> teardown reaps the launcher's userns child by process name and strips eth1, but
> a contended host or a back-to-back sweep can still skew the absolute baselines.
> The per-feature *ratios* are stable; the absolute Gbps are host-dependent.

JSON reports land in `/tmp/ebpfsentinel-*.json` on the machine running bats.
