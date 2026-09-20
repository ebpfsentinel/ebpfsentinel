# eBPFsentinel - Performance Benchmarks

Three complementary datasets:

1. **Cross-VM measurement (2026-06-14)** - the bats perf suites (`tests/perf/`)
   run over the **real vmxnet3 NIC** between two VMs (attacker → agent), kernel
   6.17, agent loaded via the BPF-token launcher. Real network path, real eBPF.
2. **Held-rate cost of the full stack (2026-09-20)** - whole-guest CPU with and
   without the agent at rates held by iperf3, the eBPF share read off
   `kernel.bpf_stats_enabled`, and the agent's resident size per feature. This
   is the current sizing reference for memory.
3. **Production CPU-overhead matrix (2026-03-22)** - a per-feature CPU% matrix at
   fixed traffic volumes, kept as the production-sizing reference for CPU. Its
   `RSS (MB)` columns predate the conntrack migration of 2026-04-16 and are
   superseded by the memory footprint table in dataset 2.

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

## Held-rate cost of the full stack (2026-09-20)

A driver on the host holds a TCP rate with four iperf3 client processes on the
attacker VM and samples the agent VM for three windows of 15 s per rate; the
median is reported. No agent runs in the baseline, so the difference between
the two rows at the same rate is what the agent costs, softirq included. The
agent is measured the way it is run: in its own user namespace over a BPF token
behind the warden, whose cost is counted with it, with every feature of
`fixtures/config-ebpf-benchmark.yaml` on at once (firewall, IDS, IPS, rate
limit, conntrack, NAT, threat intelligence, alerting, audit; 24 programs). The
rate-limit rule is keyed on the attacker with a rate above the link, so the
bucket is walked on every packet and never drops.

### Environment

| Parameter   | Value                                                             |
| ----------- | ----------------------------------------------------------------- |
| Kernel      | 7.0.0-28-generic, both VMs                                        |
| Agent VM    | 4 vCPU / 3.9 GB, vmxnet3 at 10 Gbps, native XDP on eth1           |
| Attacker VM | 4 vCPU, vmxnet3                                                   |
| Traffic     | iperf3 3.16 TCP, 4 client processes, each held at a quarter of the rate; then pktgen, 64-byte UDP frames from the attacker kernel, one thread |
| Windows     | 3 x 15 s per rate, median                                         |
| Host        | 20 cores, one-minute load under 35 % of the cores in every window |

### Whole guest, baseline against agent

| Target   | rx Gbps (baseline / agent) | Baseline busy cores | Agent busy cores | Agent cost | of which eBPF | ns per packet in eBPF | Agent RSS |
| -------- | -------------------------- | ------------------- | ---------------- | ---------- | ------------- | --------------------- | --------- |
| idle     | 0 / 0                      | 0.01                | 0.02             | +0.00      | 0.000         | -                     | 58 MB     |
| 1 Gbps   | 1.05 / 1.05                | 0.12                | 0.17             | +0.05      | 0.052         | 600                   | 58 MB     |
| 2.5 Gbps | 2.62 / 2.62                | 0.48                | 0.60             | +0.12      | 0.130         | 590                   | 58 MB     |
| 5 Gbps   | 5.09 / 5.44                | 1.91                | 2.24             | +0.33      | 0.211         | 470                   | 58 MB     |
| uncapped | 5.69 / 4.84                | 1.83                | 1.94             | +0.11      | 0.208         | 520                   | 58 MB     |

- Busy cores are user+system+irq+softirq of the whole guest. The eBPF column
  is `run_time_ns` summed over every loaded program, already inside the busy
  figure; ns per packet is that sum over the packets the NIC counted.
- At 1 and 2.5 Gbps the agent's cost is its eBPF run time and nothing else:
  userspace stays at 0.001 cores because no rule fires, so what the process
  does is metrics and heartbeats. `xdp_firewall` carries about 90 % of the eBPF
  time, and that figure includes the programs it tail-calls (rate limit,
  conntrack), which the kernel does not time apart.
- At 5 Gbps and uncapped the vmxnet3 link is CPU-bound on the host (300 000
  retransmits per window with the agent, 70 000 to 100 000 without), so the
  two rows measure whichever side ran out of CPU first and their difference
  is noise. The 1 and 2.5 Gbps rows are the comparable ones.
- The loaded maps lock 365 MB (`bytes_memlock` over every map). That is kernel
  memory, not RSS, and it is charged to the cgroup that created the maps, so a
  container limit has to hold both: the chart's 512 Mi limit leaves about
  90 MB over the agent and the fixture's maps.

### Per-packet cost under a pktgen flood (2026-09-20)

The same driver, with the attacker kernel's pktgen in place of iperf3: 64-byte
UDP frames to the discard port, one kernel thread, the rate held in packets
per second, three windows of 15 s per rate. This is the pass that prices the
datapath per packet, which is what an XDP program is priced in; the TCP pass
above prices it per byte on four flows.

| Target   | rx kpps (baseline / agent) | Baseline busy cores | Agent busy cores | eBPF cores | eBPF runs per packet | ns per run | ns per packet in eBPF | Agent RSS |
| -------- | -------------------------- | ------------------- | ---------------- | ---------- | -------------------- | ---------- | --------------------- | --------- |
| 25 kpps  | 25 / 25                    | 0.02                | 0.02             | 0.053      | 7.0                  | 303        | 2 120                 | 61 MB     |
| 50 kpps  | 50 / 50                    | 0.02                | 0.03             | 0.082      | 7.0                  | 236        | 1 650                 | 61 MB     |
| uncapped | 82 / 81                    | 0.04                | 0.04             | 0.125      | 7.0                  | 216        | 1 510                 | 61 MB     |

- Every UDP packet runs seven programs: `xdp_firewall`, with what it
  tail-calls timed inside it, then the tc ingress chain (conntrack, NAT, IDS,
  rate limit, audit). The TCP pass above ran about 1.2 per frame the NIC
  counted, because XDP runs once per frame but tc runs once per skb and GRO
  has merged the segments by then; a UDP flood is not merged, so it is the
  honest count. `xdp_firewall` is half of the per-packet time, `tc_ids`,
  `tc_conntrack` and `tc_nat_ingress` most of the rest.
- The per-run cost falls as the rate rises, from 303 ns at 25 kpps to 216 ns
  uncapped, which is cache warmth: the maps stay resident when the next packet
  arrives sooner. Read the uncapped row as the per-packet figure and the
  25 kpps row as the cold one.
- The guest's busy-core columns undercount this pass. The kernel is built
  without `CONFIG_IRQ_TIME_ACCOUNTING`, so softirq time is charged only when
  a tick lands inside it, and at 80 000 small packets a second on an idle CPU
  most of the packet path falls between ticks: the guest reads 0.04 busy cores
  while the eBPF column, timed by `sched_clock` around every run, reads 0.125.
  The eBPF column is the figure; the difference between the two busy columns
  is not.
- The virtual link carries about 105 000 small packets a second and no more,
  from one pktgen thread or four, at 64 bytes or 1 400: the ceiling is the
  hypervisor's per-packet cost on the vmnet path. At 1.5 µs a packet the
  datapath would take about 650 000 pps of one core, but that number is an
  extrapolation from two orders of magnitude below it and it is not claimed
  here. The million-packet figure needs a physical NIC or a passed-through
  one.
- Userspace stays at 0.001 cores and the resident size at 61 MB: no rule
  fires, so the process does metrics and heartbeats. The 3 MB over the TCP
  pass is the peak over the window rather than the value at rest.

### Memory footprint (2026-09-20)

Resident size of the agent's own processes (agent plus warden, `VmRSS` once the datapath is up and before any traffic) on kernel 7.0.0-28-generic, taken from the benchmark fixture with every section but the named one turned off. Map memory is `bytes_memlock` summed over the loaded maps: it is charged to the cgroup that created them, preallocated at load, and the same at idle and under flood, which is why it sits beside the resident size rather than inside it.

| Configuration | eBPF programs | RSS (MB) | Map memory (MB) |
|---|---|---|---|
| No feature enabled | 15 | 28 | 0.3 |
| Firewall only | 17 | 43 | 28 |
| Rate limiting only | 17 | 43 | 160 |
| Threat intelligence only | 16 | 42 | 180 |
| Full benchmark fixture | 24 | 58 | 365 |

The two big map holders are the threat intelligence IOC tables and the rate-limit buckets, both LRU hashes sized for their worst case at load; the conntrack table is 24 MB. Under the held-rate windows above the resident size stayed at 58 MB from idle to 5 Gbps, so what an operator sizes for is the map memory: with the fixture as it is, 58 MB resident plus 365 MB of maps against the 512Mi limit the chart sets leaves about 90 MB, and a feature that widens a map is a change to that limit.

What changed on 2026-09-20: from 2026-04-16 the agent's resident size on this fixture was 360 to 408 MB, and the enterprise agent's about 430 MB, against the 6.5 MB the previous section reports for 2026-03-22. The cause was the conntrack offset resolution, which shelled out to `bpftool btf dump -j` for the whole vmlinux BTF and parsed the result as JSON; the parsed document was dropped but the allocator kept the arenas it had grown. The two struct members are now read from the BTF the kfunc loader already parses, and the figures in the table are what that build measures. The `RSS (MB)` columns of the 2026-03-22 matrix below are from a build that did not carry the regression and are consistent with this table's order of magnitude, not with its exact values.

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
size and the current figures, and the sizing that follows from them, are in
the memory footprint table above.

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
