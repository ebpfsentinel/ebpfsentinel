# eBPFsentinel — Performance Benchmarks

Two complementary datasets:

1. **Cross-VM measurement (2026-06-14)** — the bats perf suites (`tests/perf/`)
   run over the **real vmxnet3 NIC** between two VMs (attacker → agent), kernel
   6.17, agent loaded via the BPF-token launcher. Real network path, real eBPF.
2. **Production CPU-overhead matrix (2026-03-22)** — a per-feature CPU% matrix at
   fixed traffic volumes, kept as the production-sizing reference.

> **On absolute throughput.** iperf3 over the paravirtual vmxnet3 NIC is
> CPU-bound on the host, so the *baseline* (no-agent) link rate varies with how
> busy the host is — ~8.3 Gbps on an idle host, ~3–4 Gbps when the host is
> loaded. What is **reproducible** is the agent's *own* behaviour relative to a
> baseline measured the same way on the same path — that is what the tables
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

iperf3 between the two VMs, no agent in the path — the link ceiling under the
current host load.

| Test               | Idle host  | Loaded host |
| ------------------ | ---------- | ----------- |
| TCP, single stream | 8.31 Gbps  | ~3.2 Gbps   |
| TCP, 4 streams     | 8.69 Gbps  | —           |
| UDP, single stream | 1.40 Gbps  | iperf3 sender-CPU bound |

### Per-feature datapath cost (isolated, idle host)

Each feature measured alone over a firewall-pass base, vs the no-agent baseline
on the same path (idle host, ~8–8.7 Gbps baseline). This is the **true
per-packet eBPF cost** — every program here is cheap:

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
  Firewall and IDS are within noise — the XDP HashMap/LPM fast-path is effectively
  free for iperf3's single 5-tuple. The TC programs (scrub/dns/qos/conntrack/nat)
  add a few percent each. Consistent with the production CPU matrix below.

### XDP attachment mode — native vs generic (vmxnet3)

The agent's XDP datapath loads in either **native** (driver, pre-`sk_buff`) or
**generic** (SKB, post-`sk_buff`) mode; `xdp_mode: auto` (default) picks native.
vmxnet3 supports both — **offloaded is not available** (paravirtual NIC, no
SmartNIC). Same firewall-pass config, single TCP flow, idle host:

| Mode                  | Throughput | Overhead vs baseline |
| --------------------- | ---------- | -------------------- |
| baseline (no agent)   | ~7.76 Gbps | —                    |
| native (`xdp`)        | ~7.84 Gbps | ~0 %                 |
| generic (`xdpgeneric`)| ~6.0 Gbps  | **~23 %**            |

- **Generic XDP costs ~23 % throughput vs native** on vmxnet3 because the program
  runs after the kernel allocates an `sk_buff` (same position as a TC hook),
  losing native's pre-allocation fast-path. This is why `xdp_mode: auto`
  (native-first) is the right default, and a large part of why the earlier
  single-VM **veth** lane (generic XDP, no NIC) showed 85–95 % "overhead" —
  generic mode *and* no physical NIC compounded.

### Full eBPF stack — throughput is rate-limit-bound, not CPU-bound

With **every** program enabled the single-flow TCP throughput collapses to
~1.4–2 Gbps ("73–83 % overhead"). **This is not eBPF CPU cost — it is the rate
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
full bulk lands). Lane-independent — these are control-plane, not datapath.

| Op                    | Count | Wall      | per-op | ok        |
| --------------------- | ----- | --------- | ------ | --------- |
| IPS blacklist inject  | 100   | 2054 ms   | ~21 ms | 100/100   |
| IPS blacklist inject  | 1000  | 23531 ms  | ~24 ms | 1000/1000 |
| NPTv6 prefix-rule add | 10    | 377 ms    | ~38 ms | 10/10     |
| NPTv6 prefix-rule add | 100   | 2620 ms   | ~26 ms | 100/100   |

Per-op latency is dominated by the `curl` round-trip, not the kernel map write —
an end-to-end REST cost for capacity planning of bulk reconfiguration. The write
API is governed at 60 burst / 1 req-s per IP; loopback is exempt (configurable
via `agent.api_rate_limit.*`), so bulk loads from the same host are not throttled
— from a remote host past the burst they 429 by design.

> **perf/04 (pktgen ≥ 1 Mpps)** is not in this table — it drives pktgen from the
> attacker NIC and needs a calibrated high-pps setup; its XDP-drop CPU-savings
> figures are in the production matrix.

---

## Production reference — 2-VM real-NIC CPU overhead (2026-03-22)

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
  RSS constant at 6.4–6.6 MB.

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
| 1–5 Gbps          | 1 vCPU            | All features, < 3 % eBPF overhead  |
| 5–10 Gbps         | 2 vCPU            | comfortable headroom               |
| 10+ Gbps          | scale w/ traffic + flows | DPI is per-flow CPU-bound — spread load across flows/queues |

Memory: **32 MB minimum**, 64 MB recommended (agent ~6.5 MB constant).

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
> load) and **one suite at a time / a clean agent between suites** — the per-suite
> teardown reaps the launcher's userns child by process name and strips eth1, but
> a contended host or a back-to-back sweep can still skew the absolute baselines.
> The per-feature *ratios* are stable; the absolute Gbps are host-dependent.

JSON reports land in `/tmp/ebpfsentinel-*.json` on the machine running bats.
