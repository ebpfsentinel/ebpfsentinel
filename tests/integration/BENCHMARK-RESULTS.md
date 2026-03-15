# eBPFsentinel — Resource Consumption Benchmark

Measures system-wide CPU% and agent RSS (MB) per eBPF feature under different
traffic volumes. CPU% captures kernel softirq overhead from eBPF programs via
`/proc/stat` delta. RSS is read from `/proc/PID/status VmRSS`.

## Test Environment

| Parameter          | 4 vCPU / 4 GB        | 2 vCPU / 2 GB        |
| ------------------ | -------------------- | -------------------- |
| Kernel             | 6.8.0-86-generic     | 6.8.0-86-generic     |
| Topology           | 2-VM VirtualBox      | 2-VM VirtualBox      |
| Traffic tool       | iperf3 (TCP)         | iperf3 (TCP)         |
| Duration           | 15 s per measurement | 15 s per measurement |
| Max link bandwidth | ~7.8 Gbps            | ~3.4 Gbps            |
| Date               | 2026-03-15           | 2026-03-15           |

### How to Read

- **CPU%** is system-wide busy time (user + system + irq + softirq) divided by
  total. Includes eBPF packet processing in kernel softirq context.
- **RSS** is the agent process resident memory. eBPF maps are preallocated —
  RSS is constant regardless of traffic volume.
- **max-bandwidth** = iperf3 with no rate cap (link maximum).

---

## Individual Features

Each feature tested alone, no other eBPF program active.

### 4 vCPU / 4 GB — max BW ~7.8 Gbps

| Feature     | Idle | 100 Mbps | 1 Gbps | Max BW (~7.8G) | RSS (MB) |
| ----------- | ---- | -------- | ------ | -------------- | -------- |
| no-agent    | 0.0% | 0.0%     | 0.0%   | 0.0%           | —        |
| firewall    | 0.3% | 0.5%     | 1.9%   | 21.2%          | 27.2     |
| ids         | 0.3% | 0.7%     | 2.1%   | 13.4%          | 27.4     |
| ips         | 0.5% | 0.6%     | 1.8%   | 11.5%          | 28.6     |
| ratelimit   | 0.4% | 0.5%     | 2.1%   | 11.3%          | 25.4     |
| threatintel | 0.3% | 0.5%     | 2.2%   | 15.3%          | 27.4     |
| conntrack   | 0.3% | 0.8%     | 1.8%   | 12.8%          | 25.7     |
| ddos        | 0.5% | 0.5%     | 1.8%   | 11.9%          | 28.6     |
| dns         | 0.3% | 0.6%     | 1.9%   | 14.2%          | 26.0     |

### 2 vCPU / 2 GB — max BW ~3.4 Gbps

| Feature     | Idle | 100 Mbps | 1 Gbps | Max BW (~3.4G) | RSS (MB) |
| ----------- | ---- | -------- | ------ | -------------- | -------- |
| no-agent    | 0.0% | 0.0%     | 0.0%   | 0.0%           | —        |
| firewall    | 0.7% | 1.7%     | 5.1%   | 81.5%          | 27.4     |
| ids         | 0.7% | 1.3%     | 4.2%   | 36.8%          | 27.6     |
| ips         | 0.7% | 1.0%     | 2.6%   | 33.4%          | 28.5     |
| ratelimit   | 0.8% | 1.3%     | 4.0%   | 38.8%          | 25.4     |
| threatintel | 0.9% | 1.8%     | 2.9%   | 34.2%          | 27.5     |
| conntrack   | 0.7% | 1.0%     | 2.7%   | 34.9%          | 25.9     |
| ddos        | 1.2% | 1.0%     | 3.3%   | 37.8%          | 28.4     |
| dns         | 0.7% | 1.0%     | 3.9%   | 33.2%          | 26.2     |

**Observations:**

- At 1 Gbps with 4 vCPU, all features stay under 2.2% — negligible overhead.
- At 1 Gbps with 2 vCPU, the firewall is at 5.1% while other features remain
  under 4.2%. The HashMap fast-path significantly reduces per-packet cost for
  exact-match rules.
- At max bandwidth, the 2-vCPU profile reveals the true limits: the firewall
  alone consumes 81.5% of 2 cores (~3.4 Gbps), meaning 1 vCPU can handle
  ~1.9 Gbps with firewall enabled.
- RSS is consistent between profiles (25–29 MB) — memory usage is independent
  of CPU count. Consolidated maps (ratelimit union, LB V2) reduce RSS slightly.

---

## Feature Combinations

### 4 vCPU / 4 GB — max BW ~7.8 Gbps

| Features                         | Idle | 100 Mbps | 1 Gbps | Max BW (~7.8G) | RSS (MB) |
| -------------------------------- | ---- | -------- | ------ | -------------- | -------- |
| firewall + ids                   | 0.3% | 0.5%     | 2.0%   | 12.2%          | 29.2     |
| ids + ips                        | 0.4% | 0.8%     | 2.2%   | 13.8%          | 27.4     |
| firewall + ratelimit             | 0.4% | 0.6%     | 2.4%   | 17.8%          | 27.4     |
| ids + threatintel                | 0.3% | 0.5%     | 1.7%   | 14.7%          | 29.2     |
| conntrack + ddos                 | 0.3% | 0.5%     | 1.9%   | 14.3%          | 25.6     |
| firewall + ids + ips + ratelimit | 0.3% | 0.5%     | 2.0%   | 14.1%          | 29.5     |

### 2 vCPU / 2 GB — max BW ~3.4 Gbps

| Features                         | Idle | 100 Mbps | 1 Gbps | Max BW (~3.4G) | RSS (MB) |
| -------------------------------- | ---- | -------- | ------ | -------------- | -------- |
| firewall + ids                   | 0.8% | 1.4%     | 5.4%   | 81.9%          | 29.6     |
| ids + ips                        | 0.8% | 1.1%     | 4.5%   | 38.7%          | 27.8     |
| firewall + ratelimit             | 0.8% | 1.4%     | 6.0%   | 81.5%          | 27.3     |
| ids + threatintel                | 0.6% | 2.0%     | 4.8%   | 41.3%          | 29.7     |
| conntrack + ddos                 | 0.8% | 1.3%     | 3.8%   | 41.2%          | 25.6     |
| firewall + ids + ips + ratelimit | 1.3% | 1.6%     | 6.7%   | 82.9%          | 29.5     |

**Observations:**

- Combinations without firewall stay efficient: ids+ips at max BW costs 13.8%
  (4vCPU) and 38.7% (2vCPU).
- The firewall dominates the CPU budget in every combination it appears in.
- At 1 Gbps, even 4-feature combinations stay under 2.4% on 4 vCPU and under
  7% on 2 vCPU.

---

## All Features

All 8 eBPF features enabled (firewall, ids, ips, ratelimit, threatintel,
conntrack, ddos, dns).

| Profile                   | Idle | 100 Mbps | 1 Gbps | Max BW    | RSS (MB) |
| ------------------------- | ---- | -------- | ------ | --------- | -------- |
| 4 vCPU / 4 GB (max ~7.8G) | 0.3% | 0.7%     | 2.1%   | **23.7%** | 31.9     |
| 2 vCPU / 2 GB (max ~3.4G) | 0.7% | 1.4%     | 5.8%   | **81.9%** | 31.9     |

**Observations:**

- On 4 vCPU at ~7.8 Gbps: 23.7% system CPU — leaves 76% headroom for the OS,
  agent API, and other workloads.
- On 2 vCPU at ~3.4 Gbps: 81.9% system CPU — the agent uses roughly 1.6
  cores, leaving ~0.4 core free.
- At 1 Gbps both profiles are comfortable: 2.1% (4vCPU) and 5.8% (2vCPU).
- RSS is identical (~32 MB) — memory is not a bottleneck.

---

## Summary

| Metric                | 4 vCPU / 4 GB | 2 vCPU / 2 GB |
| --------------------- | ------------- | ------------- |
| Max link bandwidth    | ~7.8 Gbps     | ~3.4 Gbps     |
| All features idle CPU | 0.3%          | 0.7%          |
| All features @ 1 Gbps | 2.1%          | 5.8%          |
| All features @ max BW | 23.7%         | 81.9%         |
| All features RSS      | 31.9 MB       | 31.9 MB       |

### Sizing Recommendations

| Throughput Target | Recommended vCPUs  | Notes                              |
| ----------------- | ------------------ | ---------------------------------- |
| ≤ 1 Gbps          | 1 vCPU             | All features, ~6% CPU              |
| 1–3 Gbps          | 2 vCPU             | All features, comfortable headroom |
| 3–8 Gbps          | 4 vCPU             | All features, ~24% CPU at 8 Gbps   |
| 8+ Gbps           | Scale with traffic | ~3% CPU per Gbps with all features |

Memory: **64 MB minimum**, 128 MB recommended. The agent itself uses ~32 MB
(constant). Additional memory is used by the OS, kernel eBPF subsystem, and
ring buffers.

### Key Takeaways

1. **At 1 Gbps, the agent is nearly invisible**: 2.1% CPU on 4 vCPU, 5.8% on
   2 vCPU, with all 8 features enabled.
2. **Firewall (XDP) is the most CPU-intensive feature** — 81.5% of 2 vCPU at
   3.4 Gbps vs 33–39% for TC-based features. This is because XDP processes
   packets before the kernel network stack.
3. **Feature stacking is sublinear**: all 8 features together cost only
   slightly more than 2–3 individual features, because TC programs share the
   packet processing path.
4. **Memory is constant at ~32 MB** regardless of traffic volume or CPU count,
   thanks to preallocated eBPF maps and consolidated map unions.
5. **2 vCPU can handle 3+ Gbps** with all features at ~82% CPU. For production
   use, 2 vCPU with 128 MB RAM covers most deployments up to 3 Gbps.

---

## Reproducing

```bash
# From tests/integration/

# Run benchmark (auto-detects VM profile)
make bench-resource-matrix-2vm

# Configure VM resources via environment
AGENT_VM_CPUS=4 AGENT_VM_MEMORY=4096 vagrant up agent

# Merge two profile reports for comparison
make bench-resource-merge \
  F1=/tmp/ebpfsentinel-resource-matrix-4vCPU-4GB.json \
  F2=/tmp/ebpfsentinel-resource-matrix-2vCPU-2GB.json
```
