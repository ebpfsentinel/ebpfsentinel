# Measured results

What a run of a suite in `tests/perf/` actually produced, on a named host, on
a named day. A figure quoted anywhere else in this repository - the docs, the
website's feature matrix, a deck - comes from a file here, and a file here is
the output of the suite rather than a number somebody typed.

Nothing in this directory is a target. A guest with four vCPUs is not a
production node, and the suite says so in its own output: the bounds it
asserts are what the lane can hold, not what the product promises.

## `2026-10-24-ids-workload-scope.json`

`cargo xtask ebpf-cost`, run twice through `BPF_PROG_TEST_RUN` on a developer
workstation, kernel 7.0.0-38-generic, i7-1370P, with a desktop session running.
The harness installs one IDS rule on the frame's destination port and times the
classifier on four arms: the rule applying to every workload, then the same
rule scoped to a workload with the container link known and the workload in
scope, with the link known and the workload out of scope, and with no container
link and no socket to ask. Event emission is sampled out on every arm, so the
figure is the decision and not the ring buffer.

| run | every workload | scoped, in scope | scoped, out of scope | scoped, no link |
|---|---|---|---|---|
| 1 | 39 ns | 64 ns (+25) | 62 ns (+23) | 59 ns (+20) |
| 2 | 34 ns | 50 ns (+16) | 43 ns (+9) | 43 ns (+9) |

The two tables lock 330016 bytes (`WORKLOAD_LINKS`, 4096 links) and 1444288
bytes (`IDS_WORKLOAD_SCOPE`, 16384 cgroup and rule pairs) as the kernel reports
them in the map's fdinfo, whether or not a rule is scoped.

**What to quote.** A rule scoped to a workload costs two hash lookups more than
one that is not, measured between 9 and 25 ns on a packet the rule's port
already claimed, and nothing at all on a packet no rule claims: the scope is
read only after the pattern lookup hit. It replaces no bitmap, so there is no
ceiling of 31 scopes to quote, and the bound is the scope table's 16384
entries. The spread between the two runs is the workstation, which is why the
range and not a single figure is what this file supports.

## `2026-10-19-attribution-overhead.json`

`07-attribution-overhead.bats`, run twice on an idle Vagrant guest, kernel
7.0.0-28-generic, 4 vCPU, agent `0.0.0-dev` running rootless with eBPF loaded
through the BPF token and the warden broker. All seven attribution hooks
attached on both runs, `attribution_degraded_reason` empty. The JSON is the
second run.

Each arm is 200000 connects or 10000 execs. The arms are interleaved in pairs,
baseline then measured, back to back, seven pairs; the driver and the listener
are pinned to CPUs 2 and 3. The figure kept is the median of the per-pair
differences, so a slow minute costs both arms of a pair the same.

| run | connect baseline | connect delta (median) | per-pair spread | exec baseline | exec delta (median) | per-pair spread |
|---|---|---|---|---|---|---|
| 1 | 13200.8 ns | +823.9 ns | -74.3 to +7850.2 ns | 329399.9 ns | +1546.5 ns | -6139.0 to +4918.6 ns |
| 2 | 12731.0 ns | +803.3 ns | +9.3 to +2261.1 ns | 329422.2 ns | +1407.1 ns | -7747.4 to +8179.5 ns |

**The kernel's own clock is the stable instrument.** With
`kernel.bpf_stats_enabled=1` the kernel times every program run itself, and
`bpftool prog show` reports the total and the count, so the figure does not
depend on the guest's scheduling at all:

| run | attribution, per run | runs per connect | attribution, per connect | process, per run | runs per exec | process, per exec |
|---|---|---|---|---|---|---|
| 1 | 216.3 ns | 7.00 | 1514.2 ns | 10657.9 ns | 2.00 | 21333.9 ns |
| 2 | 194.8 ns | 7.00 | 1363.6 ns | 10712.6 ns | 2.00 | 21443.5 ns |

`runs per connect` of exactly 7.00 is the hooks saying what they are: a loopback
`connect()` runs connect4, post_bind4, the `sock_ops` join and the rest once
each. The two numbers the suite publishes for the same thing disagree on
purpose and the disagreement is the caveat: `bpf_stats` measures from program
entry to program exit including any preemption in between, so it is an upper
bound, while the paired subtraction measures what the caller actually waited
for. Where they differ, the subtraction is the cost to a workload and the
kernel clock is the cost the kernel attributes to the program.

**What to quote.** Socket attribution costs under a microsecond per
`connect()` on this lane, somewhere between the ~800 ns the paired runs
measure and the ~1.4 us the kernel's clock bounds it at. The process table
costs single-digit microseconds per `execve()` by subtraction, bounded at
~21 us by the kernel's clock, against a 330 us baseline; it is paid once per
process start, not per packet and not per connection. Neither is a target: the
bounds the suite asserts are what a four-vCPU guest can hold.

**What was published before.** A run of 2026-10-18 reported six hooks and a
`sock_ops` join refused with `errno 22`, and that was read at the time as a
kernel refusing `bpf_get_socket_cookie` under a tokenized rootless load. It was
not: the loader sent the join as program type 15 rather than 13, so the kernel
loaded it as a different program type and refused the helper that type is not
allowed. The file is gone rather than kept beside this one, because it measured
a defect of ours on a host that does not have the limitation it was used to
describe.
