# eBPFsentinel - Performance

## Summary

| question | answer |
|---|---|
| kernel time per received packet, full stack | about **1 µs** (6 eBPF programs) |
| packets one core can inspect | about **1 Mpps** |
| CPU added at 90 kpps on a 4-vCPU node | under 0.1 core, host CPU unchanged within 0.01 core |
| throughput loss, native XDP on a real NIC | within noise |
| throughput loss, generic XDP | about 23% (why `xdp_mode: auto` picks native) |
| locked map memory, every feature on | 71 MB on 4 vCPUs (grows with CPU count) |
| agent RSS, every feature on | 57 MB, plus 2.3 MB for the warden |

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

Same machine, one agent start per configuration, `bytes_memlock` summed over
every map.

| configuration | programs | maps | map memory | agent RSS |
|---|---:|---:|---:|---:|
| No feature enabled | 15 | 2 | 0.3 MB | 27 MB |
| Firewall only | 17 | 40 | 14.9 MB | 42 MB |
| Rate limiting only | 17 | 27 | 48.0 MB | 42 MB |
| Threat intelligence only | 16 | 9 | 2.0 MB | 42 MB |
| Every feature enabled | 24 | 89 | 71.0 MB | 57 MB |

Rate limiting is most of it: `RL_BUCKETS` (22 MB) and `CONN_TABLE` (12 MB) are
per-CPU maps, which **hold one copy of every entry per CPU**. On a 32-core node
they are eight times larger, so scale this column by core count before setting
a container memory limit. The chart's default of 512Mi fits the full fixture on
a small node.

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

# CPU per packet, map memory and RSS (two VMs, pktgen)
../../../ebpfsentinel-enterprise/tests/perf/bench-oss-vs-enterprise.sh

# Throughput on a real NIC (two VMs, iperf3), from tests/integration/
./scripts/run-in-2vm.sh --performance
```

Run on an idle host, one suite at a time: the vmxnet3 baseline halves when the
host is busy.
