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
| Date               | 2026-03-08           | 2026-03-08           |

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
| firewall    | 0.5% | 0.7%     | 2.6%   | 23.9%          | 28.9     |
| ids         | 0.4% | 1.0%     | 2.3%   | 14.4%          | 28.8     |
| ips         | 0.7% | 0.8%     | 2.1%   | 12.4%          | 29.9     |
| ratelimit   | 0.5% | 0.7%     | 2.4%   | 12.2%          | 26.9     |
| threatintel | 0.4% | 0.6%     | 2.6%   | 14.0%          | 29.0     |
| conntrack   | 0.4% | 1.0%     | 2.0%   | 14.6%          | 27.1     |
| ddos        | 0.7% | 0.7%     | 2.0%   | 14.4%          | 30.2     |
| dns         | 0.4% | 0.8%     | 2.1%   | 15.4%          | 27.5     |

### 2 vCPU / 2 GB — max BW ~3.4 Gbps

| Feature     | Idle | 100 Mbps | 1 Gbps | Max BW (~3.4G) | RSS (MB) |
| ----------- | ---- | -------- | ------ | -------------- | -------- |
| no-agent    | 0.0% | 0.0%     | 0.0%   | 0.0%           | —        |
| firewall    | 1.0% | 2.1%     | 12.0%  | 69.5%          | 28.8     |
| ids         | 1.1% | 3.2%     | 5.3%   | 50.8%          | 29.1     |
| ips         | 2.4% | 1.5%     | 8.2%   | 49.4%          | 30.5     |
| ratelimit   | 0.9% | 1.8%     | 6.9%   | 42.6%          | 26.8     |
| threatintel | 1.1% | 1.6%     | 7.3%   | 47.2%          | 29.3     |
| conntrack   | 0.9% | 3.2%     | 4.4%   | 36.0%          | 27.0     |
| ddos        | 2.3% | 1.9%     | 5.0%   | 31.7%          | 30.1     |
| dns         | 0.9% | 1.9%     | 4.8%   | 39.1%          | 27.5     |

**Observations:**

- At 1 Gbps with 4 vCPU, all features stay under 3% — negligible overhead.
- At 1 Gbps with 2 vCPU, the firewall jumps to 12% while other features remain
  under 9%. The XDP firewall has higher per-packet cost due to rule map lookups.
- At max bandwidth, the 2-vCPU profile reveals the true limits: the firewall
  alone consumes 69.5% of 2 cores (~3.4 Gbps), meaning 1 vCPU can handle
  ~2.4 Gbps with firewall enabled.
- RSS is identical between profiles (27–30 MB) — memory usage is independent
  of CPU count.

---

## Feature Combinations

### 4 vCPU / 4 GB — max BW ~7.8 Gbps

| Features                         | Idle | 100 Mbps | 1 Gbps | Max BW (~7.8G) | RSS (MB) |
| -------------------------------- | ---- | -------- | ------ | -------------- | -------- |
| firewall + ids                   | 0.4% | 0.7%     | 2.7%   | 22.9%          | 31.1     |
| ids + ips                        | 0.4% | 1.0%     | 2.5%   | 11.3%          | 29.2     |
| firewall + ratelimit             | 0.6% | 0.7%     | 3.1%   | 21.4%          | 28.9     |
| ids + threatintel                | 0.4% | 0.7%     | 1.9%   | 15.2%          | 31.1     |
| conntrack + ddos                 | 0.4% | 0.7%     | 2.1%   | 14.5%          | 27.0     |
| firewall + ids + ips + ratelimit | 0.4% | 1.0%     | 2.8%   | 25.0%          | 30.8     |

### 2 vCPU / 2 GB — max BW ~3.4 Gbps

| Features                         | Idle | 100 Mbps | 1 Gbps | Max BW (~3.4G) | RSS (MB) |
| -------------------------------- | ---- | -------- | ------ | -------------- | -------- |
| firewall + ids                   | 1.0% | 2.1%     | 16.2%  | 62.5%          | 31.1     |
| ids + ips                        | 1.1% | 3.1%     | 5.9%   | 43.9%          | 29.1     |
| firewall + ratelimit             | 2.5% | 2.0%     | 13.7%  | 29.1%          | 29.3     |
| ids + threatintel                | 1.1% | 1.9%     | 6.5%   | 43.9%          | 31.1     |
| conntrack + ddos                 | 1.0% | 3.3%     | 5.3%   | 50.1%          | 27.1     |
| firewall + ids + ips + ratelimit | 2.3% | 2.0%     | 13.9%  | 64.6%          | 31.3     |

**Observations:**

- Combinations without firewall stay efficient: ids+ips at max BW costs 11.3%
  (4vCPU) and 43.9% (2vCPU).
- The firewall dominates the CPU budget in every combination it appears in.
- At 1 Gbps, even 4-feature combinations stay under 3% on 4 vCPU and under
  17% on 2 vCPU.

---

## All Features

All 8 eBPF features enabled (firewall, ids, ips, ratelimit, threatintel,
conntrack, ddos, dns).

| Profile                   | Idle | 100 Mbps | 1 Gbps | Max BW    | RSS (MB) |
| ------------------------- | ---- | -------- | ------ | --------- | -------- |
| 4 vCPU / 4 GB (max ~7.8G) | 0.7% | 0.6%     | 2.9%   | **25.4%** | 33.6     |
| 2 vCPU / 2 GB (max ~3.4G) | 1.0% | 2.0%     | 15.1%  | **64.1%** | 33.4     |

**Observations:**

- On 4 vCPU at ~7.8 Gbps: 25.4% system CPU — leaves 75% headroom for the OS,
  agent API, and other workloads.
- On 2 vCPU at ~3.4 Gbps: 64.1% system CPU — the agent uses roughly 1.3
  cores, leaving ~0.7 core free.
- At 1 Gbps both profiles are comfortable: 2.9% (4vCPU) and 15.1% (2vCPU).
- RSS is identical (~33.5 MB) — memory is not a bottleneck.

---

## Summary

| Metric                | 4 vCPU / 4 GB | 2 vCPU / 2 GB |
| --------------------- | ------------- | ------------- |
| Max link bandwidth    | ~7.8 Gbps     | ~3.4 Gbps     |
| All features idle CPU | 0.7%          | 1.0%          |
| All features @ 1 Gbps | 2.9%          | 15.1%         |
| All features @ max BW | 25.4%         | 64.1%         |
| All features RSS      | 33.6 MB       | 33.4 MB       |

### Sizing Recommendations

| Throughput Target | Recommended vCPUs  | Notes                              |
| ----------------- | ------------------ | ---------------------------------- |
| ≤ 1 Gbps          | 1 vCPU             | All features, ~15% CPU             |
| 1–3 Gbps          | 2 vCPU             | All features, comfortable headroom |
| 3–8 Gbps          | 4 vCPU             | All features, ~25% CPU at 8 Gbps   |
| 8+ Gbps           | Scale with traffic | ~3% CPU per Gbps with all features |

Memory: **64 MB minimum**, 128 MB recommended. The agent itself uses ~34 MB
(constant). Additional memory is used by the OS, kernel eBPF subsystem, and
ring buffers.

### Key Takeaways

1. **At 1 Gbps, the agent is nearly invisible**: 2.9% CPU on 4 vCPU, 15.1% on
   2 vCPU, with all 8 features enabled.
2. **Firewall (XDP) is the most CPU-intensive feature** — 69.5% of 2 vCPU at
   3.4 Gbps vs 31–50% for TC-based features. This is because XDP processes
   packets before the kernel network stack.
3. **Feature stacking is sublinear**: all 8 features together cost only
   slightly more than 2–3 individual features, because TC programs share the
   packet processing path.
4. **Memory is constant at ~34 MB** regardless of traffic volume or CPU count,
   thanks to preallocated eBPF maps.
5. **2 vCPU can handle 3+ Gbps** with all features at ~64% CPU. For production
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
