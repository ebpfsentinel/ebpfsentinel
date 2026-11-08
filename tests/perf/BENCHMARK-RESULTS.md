# eBPFsentinel - Performance

## Summary

| question | answer |
|---|---|
| kernel time per received packet, full stack | about **1 µs** (6 eBPF programs) |
| packets one core can inspect | about **1 Mpps** |
| CPU added at 90 kpps on a 4-vCPU node | under 0.1 core, host CPU unchanged within 0.01 core |
| throughput loss, native XDP on a real NIC | within noise |
| throughput loss, generic XDP | about 23% (why `xdp_mode: auto` picks native) |
| locked map memory, every feature on | 229 MB on 4 vCPUs, 265 MB on 8 (about 9 MB per CPU) |
| agent RSS, every feature on | 151 MB, plus 7 MB for the warden |
| agent container memory, every feature on | 336 MiB steady, 872 MiB peak while loading |

## CPU per packet

The agent runs a fixture with every feature enabled; each figure is the median
of three 15 s windows.

| rate | OSS | Enterprise |
|---|---:|---:|
| 25 kpps | 1458 ns/pkt | 1219 ns/pkt |
| 50 kpps | 1057 ns/pkt | 1041 ns/pkt |
| 90 kpps | 967 ns/pkt | 865 ns/pkt |

Cost per packet falls as the rate rises, because the fixed part (a cold cache
line, the first packet of a flow) is shared by more packets. The lane is
repeatable to about 15%, so the OSS/Enterprise gap is noise: they run under
different launchers, not different datapaths.

### Test environment

| parameter | value |
|---|---|
| Measured | 2026-09-21 |
| Kernel | 7.0.0-28-generic |
| Machine | 4 vCPU / 3.9 GB |
| Topology | two VMware guests, vmxnet3 at 10 Gbps |
| Traffic | pktgen, 64-byte UDP frames |

### What that means in cores

Taking 1 µs per packet as an upper bound:

| packet rate | eBPF CPU | example |
|---:|---:|---|
| 100 kpps | 0.1 core | 1.2 Gbps of 1500-byte packets |
| 400 kpps | 0.4 core | 5 Gbps of 1500-byte packets |
| 830 kpps | 0.8 core | 10 Gbps of 1500-byte packets |
| 1.5 Mpps | 1.5 cores | 1 Gbps of 64-byte packets |

The rate that matters is packets per second, not bits: a flood of small packets
costs far more than the same bandwidth of full-size ones. The kernel spreads
packets over the NIC's receive queues, so this CPU is spread over as many cores.

### Where the time goes (25 kpps)

| program | OSS | Enterprise |
|---|---:|---:|
| `xdp_firewall`, `xdp_ratelimit`, `xdp_loadbalancer` | 712 ns | 630 ns |
| `tc_conntrack` | 292 ns | 226 ns |
| `tc_ids` | 215 ns | 234 ns |
| `tc_threatintel` | 126 ns | 60 ns |
| `tc_dns` | 41 ns | 23 ns |
| `tc_nat_ingress` | 39 ns | 34 ns |
| **total** | **1425 ns** | **1208 ns** |

The kernel bills a tail call to the program that was entered, so the three XDP
programs chained by tail calls read as one row. `tc_nat_egress` is on the egress hook and costs nothing
on a received packet.

## Cost of each program

`cargo xtask ebpf-cost` runs each program alone, a million times on one 64-byte
UDP frame, best of three, through `BPF_PROG_TEST_RUN`. It is repeatable to a
few nanoseconds, so it is the tool for measuring a change to one program.

Each program is run twice: once with its lookups running and missing, and once
with userspace having marked its tables empty so the lookups are skipped.

| program | hook | lookups run | lookups skipped |
|---|---|---:|---:|
| `tc_qos`, `tc_qos_ingress` | TC | 220 ns | 5 ns |
| `xdp_firewall` | XDP | 47 ns | 19 ns |
| `xdp_ratelimit` | XDP | 39 ns | 27 ns |
| `tc_ids` | TC | 31 ns | 11 ns |
| `xdp_firewall_reject` | XDP | 23 ns | 24 ns |
| `xdp_loadbalancer` | XDP | 15 ns | 16 ns |
| `xdp_ratelimit_syncookie` | XDP | 12 ns | 13 ns |
| `tc_nat_ingress`, `tc_nat_egress`, `tc_conntrack` | TC | 7-8 ns | 7-8 ns |
| `tc_dns`, `tc_threatintel`, `tc_scrub`, `xdp_pass`, `xdp_vip_announcer` | both | 5-7 ns | 5-11 ns |

How to read it:

- **5 ns is the floor**, the cost of the test loop itself. Differences of a few
  nanoseconds near it are noise.
- **The shaper is the heaviest program when it runs**: it walks up to thirty
  hash lookups to classify a packet. With no shaping rule loaded it costs
  nothing, and with rules it pays only for the rule shapes in use.
- **These are lower bounds.** No rule matches and no configuration is loaded,
  so `tc_conntrack`, `tc_dns`, `tc_scrub` and `tc_threatintel` return early:
  `tc_conntrack` is 6 ns here and 292 ns on live traffic. Use the per-packet
  figures above for sizing.
- `uprobe-dlp` is not measured: `BPF_PROG_TEST_RUN` only takes packets.

## Memory

Measured 2026-11-08 on kernel 7.0.0-42-generic, in the VMware agent guest of
`tests/integration/vagrant` with 3.9 GB of memory, at 4 and again at 8 vCPUs.
Each figure is the median of three agent starts on an otherwise idle guest,
the peak the highest of the three. The OSS agent runs under the warden in its
own user namespace over a BPF token, as the chart runs it. The table is the
4 vCPU run; at 8 vCPUs the steady cgroup and the peak moved by under 5 MiB.
Every start is in `results/2026-11-08-memory-footprint.json`.

| configuration | programs | maps | map memory | agent RSS | steady cgroup | startup peak |
|---|---:|---:|---:|---:|---:|---:|
| No feature enabled | 20 | 27 | 31.0 MB | 123 MB | 167 MiB | 183 MiB |
| Firewall only | 22 | 71 | 47.5 MB | 121 MB | 181 MiB | 869 MiB |
| Rate limiting only | 24 | 91 | 95.1 MB | 123 MB | 201 MiB | 869 MiB |
| Threat intelligence only | 21 | 36 | 32.8 MB | 120 MB | 163 MiB | 186 MiB |
| Benchmark configuration | 29 | 127 | 133.7 MB | 134 MB | 240 MiB | 869 MiB |
| Every feature enabled | 51 | 189 | 229.3 MB | 151 MB | 336 MiB | 872 MiB |

- **map memory** is `bytes_memlock` summed over every map the start created:
  what the kernel reserved for the maps, whether a slot is used or not.
- **agent RSS** is the agent's `VmRSS`, about 40 MB of it the mapped binary.
  The warden adds about 7 MB in a container of its own.
- **steady cgroup** is `memory.current` of the agent's cgroup 30 s after it is
  ready, which is what a container memory limit is compared with.
- **startup peak** is `memory.peak` of the same cgroup: what the limit has to
  hold while the agent loads and the kernel verifies its programs.
- "No feature enabled" still loads the programs that run whatever the
  configuration says (process and drop tracepoints, socket attribution, the
  BPF LSM guards). "Benchmark configuration" is the fixture the CPU figures
  above were measured with; "Every feature enabled" is
  `tests/integration/fixtures/config-ebpf-all-programs.yaml`, which loads every
  program the agent has.

The peak is set by loading an XDP program rather than by the tables: every
configuration that attaches the XDP firewall or the rate limiter peaks at
about 870 MiB, the ones that attach neither stay under 190 MiB, and the peak
is the same at 8 vCPUs as at 4. That peak is what sets the chart's 1Gi default
limit, and why 512Mi got the agent OOMKilled before it was ever Ready.

### Enterprise

The enterprise agent with the perf lane's enterprise block
(`ebpfsentinel-enterprise/tests/perf/fixtures/enterprise-features.yaml`)
appended to each configuration but the first, 4 vCPUs. Under the warden over a
BPF token is how the enterprise chart runs it; as root with capabilities is how
the enterprise lab runs it.

| configuration | launch | programs | map memory | agent RSS | steady cgroup | startup peak |
|---|---|---:|---:|---:|---:|---:|
| No feature enabled | BPF token | 20 | 31.0 MB | 173 MB | 240 MiB | 261 MiB |
| Firewall only | BPF token | 21 | 47.4 MB | 196 MB | 273 MiB | 928 MiB |
| Rate limiting only | BPF token | 22 | 95.0 MB | 200 MB | 295 MiB | 927 MiB |
| Threat intelligence only | BPF token | 21 | 32.8 MB | 200 MB | 261 MiB | 281 MiB |
| Benchmark configuration | BPF token | 27 | 133.6 MB | 212 MB | 335 MiB | 928 MiB |
| Every feature enabled | BPF token | 49 | 229.2 MB | 229 MB | 429 MiB | 928 MiB |
| No feature enabled | root | 20 | 31.0 MB | 172 MB | 266 MiB | 284 MiB |
| Benchmark configuration | root | 27 | 133.6 MB | 213 MB | 361 MiB | 737 MiB |
| Every feature enabled | root | 49 | 229.2 MB | 229 MB | 455 MiB | 737 MiB |

At 8 vCPUs, every feature enabled: 265.2 MB of maps, 431 MiB steady and a
929 MiB peak over a BPF token, 456 MiB and 738 MiB as root. Loading over a
BPF token peaks about 190 MiB higher than loading with capabilities, for the
same programs; the steady figures are within 30 MiB of each other.

### Which memory a container limit sees

The map memory column and the steady cgroup column do not add up, and they are
not meant to. A map's memory is charged to the cgroup of the process that
created it, with one exception that matters for sizing: **the per-CPU copies
of a per-CPU map's values are charged to no cgroup at all.** They come from
the kernel's per-CPU allocator and, on this kernel, show in the node's
`Percpu` line and in no cgroup's `memory.stat`, so the node pays for them and
no container limit sees them.

Measured by snapshotting every cgroup's `memory.stat` and the node's
`/proc/meminfo` before a start and again at steady state, every feature
enabled, OSS agent:

| | 4 vCPUs | 8 vCPUs |
|---|---:|---:|
| map memory (`bytes_memlock`) | 229.3 MB | 265.3 MB |
| of which per-CPU map types | 62.0 MB | 97.4 MB |
| agent cgroup, `kernel` | 193 MiB | 194 MiB |
| agent cgroup, `percpu` | 14 KiB | 24 KiB |
| agent cgroup, `memory.current` | 336 MiB | 337 MiB |
| node `Percpu` growth (`/proc/meminfo`) | 31.7 MiB | 63.0 MiB |
| node `VmallocUsed` growth | 187.5 MiB | 181.9 MiB |

No cgroup's `percpu` counter grew by as much as a MiB, the root's included,
while the node's `Percpu` line grew by the size of the per-CPU values. The
same holds as root with capabilities (`Percpu` +33.2 MiB at 4 vCPUs, +66.8 MiB
at 8, nothing charged), so it is the kernel's accounting and not the BPF token
path. Everything else the start allocates (the other maps, the programs,
their BTF) is charged to the agent's cgroup as `kernel` memory; the warden's
cgroup gains about 6 MiB of its own.

So, for sizing:

- **The container limit** sees the steady cgroup figure, 336 MiB (352 MB)
  with every feature enabled, and before that the startup peak, 872 MiB.
  Neither moves with the CPU count: 337 MiB and 872 MiB at 8 vCPUs.
- **The node** pays the per-CPU values outside any container, so no pod
  limit holds them and the scheduler, which counts requests, never sees them.
  With every feature enabled at the default capacities that is about
  7.9 MiB per possible CPU, measured as 31.7 MiB on 4 vCPUs and 63.0 MiB on
  8. At the same rate, which is what both measurements fit, a 32-CPU node
  pays about 250 MiB and a 64-CPU node about 500 MiB. On large nodes, reserve
  it in the kubelet's `kube-reserved` or `system-reserved` memory, so the
  scheduler does not hand it to pods.
- **Almost all of it comes from three features.** Rate limiting and DDoS
  protection (`xdp-ratelimit`: `RL_BUCKETS`, `CONN_TABLE` and the per-source
  DDoS tables) and QoS (`QOS_FLOW_STATE`, `QOS_CGROUP_COUNTERS`) carry
  8.1 MB of the 9.0 MB the map memory grows by per CPU. With all three off,
  the programs that load whatever the configuration (socket attribution, TCP
  health, the drop counter) still keep about 0.7 MB per CPU in per-CPU maps:
  6.2 MB on 4 vCPUs and 9.1 MB on 8.
- **The map memory column** is the kernel's own reckoning and includes both.
  It is the figure to compare between configurations, not the one to set a
  limit with.

A kernel that does charge per-CPU memory to the cgroup would move those
7.9 MiB per CPU inside the container limit, on top of both figures; the script
reports where the memory went, so that is one run to find out.

### Per-CPU growth

Per-CPU maps are sized by the CPUs the kernel could ever bring online,
`/sys/devices/system/cpu/possible`, not by the CPUs running now. In this
guest the two are the same (`0-3` with 4 online, `0-7` with 8 online); a
hypervisor that reserves CPUs for hotplug declares more possible CPUs than
it runs, and every per-CPU map pays for them.

Every feature enabled, OSS agent, map memory by type:

| map type | maps | 4 vCPUs | 8 vCPUs | per extra CPU |
|---|---:|---:|---:|---:|
| hash | 43 | 84.3 MB | 84.8 MB | 0.13 MB |
| lru_hash | 22 | 66.7 MB | 66.7 MB | 0 |
| lru_percpu_hash | 9 | 57.4 MB | 90.4 MB | 8.26 MB |
| ringbuf | 12 | 15.5 MB | 15.5 MB | 0 |
| percpu_hash | 5 | 4.3 MB | 6.6 MB | 0.56 MB |
| array | 51 | 0.9 MB | 0.9 MB | 0 |
| percpu_array | 33 | 0.2 MB | 0.4 MB | 0.04 MB |
| bloom_filter, devmap, prog_array, lpm_trie | 14 | under 0.1 MB | under 0.1 MB | 0 |
| total | 189 | 229.3 MB | 265.3 MB | 8.99 MB |

`hash` grows a little because a preallocated hash map keeps one spare element
per CPU, and `LB_MAGLEV`'s element is 128 KiB. The per-CPU tables, each
growing by its value size per slot per CPU:

| map | type | max_entries | value | 4 vCPUs | 8 vCPUs | per extra CPU |
|---|---|---:|---:|---:|---:|---:|
| `RL_BUCKETS` | lru_percpu_hash | 65,536 | 64 B | 22.02 MB | 38.80 MB | 4.19 MB |
| `CONN_TABLE` | lru_percpu_hash | 65,536 | 24 B | 12.06 MB | 18.35 MB | 1.57 MB |
| `QOS_FLOW_STATE` | lru_percpu_hash | 65,536 | 16 B | 9.44 MB | 13.63 MB | 1.05 MB |
| `TCP_EDGES` | percpu_hash | 8,192 | 48 B | 2.56 MB | 4.13 MB | 0.39 MB |
| `LISTENER_ACCEPTS` | lru_percpu_hash | 16,384 | 16 B | 2.62 MB | 3.67 MB | 0.26 MB |
| `SYN_RATE_TRACKER`, `ICMP_RATE_BUCKETS`, `AMP_RATE_BUCKETS`, `FLOOD_COUNTERS` | lru_percpu_hash | 16,384 each | 16 B | 2.36 MB each | 3.41 MB each | 0.26 MB each |
| `HALF_OPEN_COUNTERS` | lru_percpu_hash | 16,384 | 8 B | 1.84 MB | 2.36 MB | 0.13 MB |
| `QOS_CGROUP_COUNTERS` | percpu_hash | 4,096 | 24 B | 0.72 MB | 1.12 MB | 0.10 MB |
| `DROP_COUNTS`, `DROP_WORKLOADS` | percpu_hash | 4,096 each | 8 B | 0.53 and 0.49 MB | 0.66 and 0.62 MB | 0.03 MB each |
| `LB_RR_STATE` | percpu_array | 4,096 | 4 B | 0.16 MB | 0.30 MB | 0.03 MB |
| 32 other maps, metrics and scratch space | percpu_array | 1 to 256 each | 4 to 76 B | 0.06 MB together | 0.10 MB together | 0.01 MB together |

The capacities of `RL_BUCKETS`, `CONN_TABLE` and the five per-source DDoS
tables are configuration keys applied at agent start; the
[performance tuning guide](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/docs/operations/performance-tuning.md#ebpf-map-sizes)
names them.

### Largest maps

Every feature enabled, OSS agent, the 25 largest maps by `bytes_memlock`.
`bpftool` shows the first 15 characters of a map's name.

| map | type | max_entries | key | value | 4 vCPUs | 8 vCPUs |
|---|---|---:|---:|---:|---:|---:|
| `LB_MAGLEV` | hash | 256 | 4 B | 131,074 B | 34.10 MB | 34.62 MB |
| `RL_BUCKETS` | lru_percpu_hash | 65,536 | 8 B | 64 B | 22.02 MB | 38.80 MB |
| `CONN_TABLE` | lru_percpu_hash | 65,536 | 12 B | 24 B | 12.06 MB | 18.35 MB |
| `QOS_FLOW_STATE` | lru_percpu_hash | 65,536 | 4 B | 16 B | 9.44 MB | 13.63 MB |
| `SOCKET_FLOW` | lru_hash | 65,536 | 40 B | 40 B | 9.44 MB | 9.44 MB |
| `NAT_DNAT_REVERSE_V6` | lru_hash | 65,536 | 40 B | 20 B | 8.39 MB | 8.39 MB |
| `NAT_SNAT_REVERSE_V6` | lru_hash | 65,536 | 40 B | 20 B | 8.39 MB | 8.39 MB |
| `SOCKET_IDENTITY` | lru_hash | 65,536 | 8 B | 40 B | 7.34 MB | 7.34 MB |
| `LB_BACKENDS` | hash | 65,536 | 4 B | 28 B | 6.82 MB | 6.82 MB |
| `NETPOL_REPLIES` | lru_hash | 65,536 | 32 B | 8 B | 6.82 MB | 6.82 MB |
| `WORKLOAD_PEER_DESTINATIONS` | hash | 65,536 | 20 B | 8 B | 6.29 MB | 6.29 MB |
| `WORKLOAD_PEER_SOURCES` | hash | 65,536 | 20 B | 8 B | 6.29 MB | 6.29 MB |
| `FW_HASH_5TUPLE` | hash | 65,536 | 16 B | 4 B | 5.77 MB | 5.77 MB |
| `NAT_DNAT_REVERSE` | lru_hash | 65,536 | 16 B | 8 B | 5.77 MB | 5.77 MB |
| `NAT_SNAT_REVERSE` | lru_hash | 65,536 | 16 B | 8 B | 5.77 MB | 5.77 MB |
| `FW_IPSET_V4` | hash | 65,536 | 8 B | 1 B | 5.24 MB | 5.24 MB |
| `LB_BACKEND_MAC` | hash | 65,536 | 4 B | 8 B | 5.24 MB | 5.24 MB |
| `EVENTS` | ringbuf | 4,194,304 | 0 B | 0 B | 4.22 MB | 4.22 MB |
| `EVENTS` | ringbuf | 4,194,304 | 0 B | 0 B | 4.22 MB | 4.22 MB |
| `LISTENER_ACCEPTS` | lru_percpu_hash | 16,384 | 20 B | 16 B | 2.62 MB | 3.67 MB |
| `TCP_EDGES` | percpu_hash | 8,192 | 48 B | 48 B | 2.56 MB | 4.13 MB |
| `AMP_RATE_BUCKETS` | lru_percpu_hash | 16,384 | 8 B | 16 B | 2.36 MB | 3.41 MB |
| `FLOOD_COUNTERS` | lru_percpu_hash | 16,384 | 8 B | 16 B | 2.36 MB | 3.41 MB |
| `ICMP_RATE_BUCKETS` | lru_percpu_hash | 16,384 | 8 B | 16 B | 2.36 MB | 3.41 MB |
| `SYN_RATE_TRACKER` | lru_percpu_hash | 16,384 | 8 B | 16 B | 2.36 MB | 3.41 MB |

The two `EVENTS` maps are the event rings of two programs, 4 MiB each.
`LB_MAGLEV` is the single largest: 256 Maglev lookup tables of 131,074 bytes
each.

### Measuring it

`tests/perf/measure-footprint.sh`, from the host, with the agent VM of
`tests/integration/vagrant` up and the build synced to it:

- Each agent start runs in a transient systemd service of its own, so its
  cgroup holds the agent and nothing else; the warden, when used, runs in a
  second one.
- Before each start the script stops every agent, detaches every XDP and tc
  program, removes the pins, drops the page cache, and snapshots the existing
  maps and programs, the node's `/proc/meminfo` and every cgroup's
  `memory.stat`. Map and program figures count only what appeared after.
- The agent is ready when `/readyz` reports `ebpf_loaded`, or, for the
  configurations that attach no XDP firewall, when `/readyz` answers and the
  number of loaded programs has not changed for three seconds. It was ready
  within 5 s in every start.
- The steady reading is taken 30 s after ready: `memory.current` and
  `memory.stat` of the agent's cgroup, `VmRSS` of each process in it, and
  `bpftool map show` for every new map. The peak is the cgroup's
  `memory.peak` at the same moment.
- Three starts per configuration; the table keeps the start with the median
  steady cgroup figure and the highest peak of the three. The three starts
  agreed within 5 MiB steady and 4 MiB peak.
- The 8 vCPU run is the same VM, halted and brought up again with
  `AGENT_VM_CPUS=8`.

## Throughput on a real NIC

Two VMs over vmxnet3, iperf3, single TCP flow, idle host, kernel 6.17. The
link reaches about 8.3 Gbps with no agent. The paravirtual NIC is CPU-bound on
the host, so absolute Gbps depend on host load; the overheads below are
measured against a baseline taken on the same path at the same time.

| feature enabled alone | throughput loss |
|---|---:|
| firewall (XDP) | within noise |
| IDS (TC) | within noise |
| NAT egress (TC) | 1.5% |
| scrub (TC) | 1.5% |
| DNS capture (TC) | 2.5% |
| QoS (TC) | 3.1% |
| conntrack (TC) | 5.5% |

| XDP mode | throughput | loss |
|---|---:|---:|
| no agent | 7.76 Gbps | - |
| native (`xdp`) | 7.84 Gbps | within noise |
| generic (`xdpgeneric`) | 6.0 Gbps | 23% |

Generic XDP runs after the kernel has built an `sk_buff`, so it loses what
makes XDP fast. `xdp_mode: auto` picks native wherever the driver supports it.

A benchmark with every feature on and a rate limit configured measures the
rate limit, not the agent: at 100 000 pps allowed, an iperf3 flood is cut to
about 1.4 Gbps by design.

## API write latency

Bulk writes through the REST API from the same host (loopback is exempt from
the write rate limit). The cost is the HTTP round trip, not the map write.

| operation | per call |
|---|---:|
| IPS blacklist entry | 21-24 ms |
| NPTv6 prefix rule | 26-38 ms |

From another host the API allows a burst of 60 then 1 request per second per
address (`agent.api_rate_limit.*`).

## Reproducing

```bash
# Cost of each program (root, built objects; three programs call kfuncs
# exported by these modules)
sudo modprobe -a fou fou6 xfrm_interface
cargo xtask ebpf-build && sudo target/release/xtask ebpf-cost

# CPU per packet (two VMs, pktgen)
../../../ebpfsentinel-enterprise/tests/perf/bench-oss-vs-enterprise.sh

# Memory: maps, RSS, steady cgroup and startup peak (agent VM), then the
# tables; again with AGENT_VM_CPUS=8 for the per-CPU growth
tests/perf/measure-footprint.sh --launch oss --out DIR
tests/perf/measure-footprint.sh --launch enterprise-token \
    --enterprise-bin PATH --license FILE --out DIR
tests/perf/measure-footprint.sh --summary DIR

# Throughput on a real NIC (two VMs, iperf3), from tests/integration/
./scripts/run-in-2vm.sh --performance
```

Run on an idle host, one suite at a time: the vmxnet3 baseline halves when the
host is busy.
