# Datapath matrix, 2026-11-08

The suite matrix run on the real datapath after the kernel half of aya moved to
0.3.0: every lane below loaded the eBPF objects built from this tree, on VMware
guests, with `EBPFSENTINEL_STRICT_SKIPS=1`, so a skip the lane owns a
prerequisite for fails instead of passing. Each lane ran alone and its VMs were
halted before the next one started. This record also stands for the two-machine
and three-machine run that the previous aya move owed and never dated.

## Binaries

| agent | built from | tree | where |
|---|---|---|---|
| OSS, 2VM default, 2VM perf, 3VM | content of `5fbb272a` + `bc31eb0c` | clean | built in the agent VM by the `setup` provisioner |
| OSS, local lane final rerun, pktgen bench | `d38a58d4` (sha256 `32acf921...`) | clean | built in the agent VM by the `setup` provisioner |
| enterprise, pktgen bench | `4b50c3a` | clean | `tests/perf/build-enterprise-for-vm.sh` on the host, in the builder image |
| enterprise, node1/node2 lane | `f27e24d` (code identical to `4b50c3a`) | clean | built on each node by `build-enterprise.sh` |

The enterprise bench recorded its tree as `4b50c3a-dirty`. The only change in
the tree was the bench writing its own results directory, which the dirty-tree
check counted; the check now leaves the output directory out
(enterprise `3d5a235`) and the stamp in the committed results was corrected by
hand to the clean revision.

## Lanes

Every VM ran kernel `7.0.0-42-generic` (Ubuntu 24.04.3, HWE).

| lane | where | tests | pass | skip | fail |
|---|---|---:|---:|---:|---:|
| 2VM default (XDP and TC on vmxnet3) | agent + attacker | 90 | 84, then 88 | 2 | 4, then 0 |
| 2VM perf (real NIC) | agent + attacker | 55 | 47 | 8 | 0 |
| 3VM transit (suites 44 45 46 47 50 55) | agent + attacker + backend | 35 | 34 | 1 | 0 |
| local lane (DLP uprobe, ring buffer, LSM, cgroup, load) | agent | see below | all | 4 | 0 |
| enterprise (45 suites) | node1 + node2 | 402 | 343, then 402 | 43, then 0 | 16, then 0 |

### 2VM default

90 tests. The first run failed four tests, all in suite 54 (container
attribution): the harness wrote the agent's maps through bpftool, which the BPF
LSM guard refuses a writable descriptor, and the process table's resolver
counters reported a container's first lookup as a hit. Both were fixed (see
below), suite 54 then passed 8 of 8, and the lane stands at 88 pass and 2 skip.

| test | skip reason |
|---|---|
| 76 | v6 netns IDS wire probe is local-lane only |
| 77 | test requires the 3-VM transit topology |

### 2VM perf

Eight skips, all of the local-lane kind: DLP uprobe goodput (48), process
attribution overhead (50 to 53) and the encryptor (54, 55) measure a workload
on the agent itself and run in the local lane.

TCP through the agent: 5.85 Gbps without it, 5.18 Gbps with it, 12% overhead
against the suite's 24.5% bound; agent RSS 134 MB. Per feature: firewall 11.6%,
firewall plus IDS 9.0%, scrub 13.1%, DNS 23.9%, QoS 32.8%, conntrack 35.6%,
NAT egress 3.9%, ingress -7.1%, both 5.4%; the rate limit holds at its
configured 1.39 Gbps. Run-to-run noise on this lane was 24 to 40%, so the
per-feature figures are indicative only. XDP drop costs no less CPU than pass at
the packet rate a virtual NIC reaches, which is the lane's limit rather than a
finding.

### 3VM transit

35 tests, 34 pass, 1 skip: test 33, the v6 netns IDS wire probe, which is
local-lane only; the three-machine v6 path is covered by the forward test.

### Local lane

Run on the agent VM through `scripts/run-local-lane.sh`, one suite at a time.

| suite | tests | suite | tests | suite | tests |
|---|---:|---|---:|---|---:|
| 06 | 6 | 22 | 25 | 84 | 10 |
| 11 | 24 | 27 | 28 | 86 | 2 |
| 12 | 13 | 34 | 5 | 88 | 5 |
| 13 | 9 | 51 | 4 | 91 | 3 |
| 14 | 14 | 57 | 10 | 92 | 7 |
| 15 | 9 | 58 | 6 | 95 | 4 |
| 16 | 39 | 59 | 8 | 98 | 6 |
| 17 | 15 | 60 | 9 | 99 | 5 |
| 18 | 9 | 62 | 12 | 100 | 8 |
| 19 | 9 | 64 | 6 | 103 | 4 |
| 20 | 17 | 67 | 6 | 104 | 4 |
| 21 | 15 | 70 | 5 | 132 | 4 |
| | | 72 | 4 | 133 | 3 |
| | | 74 | 5 | | |
| | | 83 | 11 | | |

Every test above passed. The last rerun, on the binary carrying the DNS clients
fix and the namespace teardown fix, covered 67, 70, 72, 74, 86, 91, 92, 95, 98,
99, 100 and 103 and left no mount behind. Suite 91 failed once on an alert count
and passed three of three on rerun; it is recorded as a flake.

| suite | skips | reason |
|---|---:|---|
| 130 | 2 | podman not installed |
| 131 | 2 | podman not installed |

### Enterprise

Both nodes ran `7.0.0-42-generic`, with a dual-signed (Ed25519 and ML-DSA-65)
licence, through `scripts/run-local-lane.sh` on node1 with
`EBPFSENTINEL_STRICT_SKIPS=1`; the HA suites reach node2 over SSH from there.
The first run covered all 45 suites: 402 tests, 343 pass, 43 skip, 16 fail. 39
suites passed outright. The other six were reworked and rerun, then every
failing test rerun alone through `BATS_FILTER` after its fix:

| suite | first run | final | cause |
|---|---|---|---|
| 07 HA | 19 skipped | 19 pass | node2 could not SSH to node1; then one fail, see below |
| 08 HA mirror | 11 skipped | 11 pass | node2 could not SSH to node1 |
| 21 HA active-active | 13 skipped | 13 pass | node2 could not SSH to node1 |
| 14 TLS intelligence | 10 pass, 5 fail | 15 pass | the suite predated provenance on built-in threats (enterprise `3c61bc5`, 2026-10-18): it counted them without it and posted a custom one with no source, reference or confirmation date |
| 19 datapath revalidation | 15 pass, 9 fail | 24 pass | a forensics mirror loop (seven tests), then the tenant rule writes (two) |
| 23 tenant attribution | 2 pass, 2 fail | 4 pass | the staged pod asked a CNI the node does not run and handed runc a cgroup parent it cannot parse under systemd |

No skip is left in the enterprise lane.

**The mirror loop is a product defect.** The link watcher attaches the TC chain
to every veth, tap and netkit device, which includes the device the IDS mirrors
to, and the IDS cloned whatever reached it on that device back to the same
target. Each copy was cloned again until the kernel logged a dead loop and
recursion limit, and node1 ran out of memory and oopsed. The IDS now marks the
copy it hands the kernel and passes a marked packet without inspecting or
cloning it, restoring the packet's own mark after the clone. With the fix, the
enabled mirror carried 10 frames, the disabled one 0, and the kernel logged no
dead loop. The suite now also bounds the frame count, so a loop fails the test
rather than the machine. Both halves predate `76c9fc94`: the mirror
since 2026-03-20, the link watcher since 2026-10-24.

**The tenant rule writes were refused by the BPF LSM guard** (2026-10-31),
which gives no task but the agent a writable descriptor on its maps; bpftool
lookups still work. The suite now writes through the agent's own descriptor, as
the OSS lane already did, and that helper's delete was itself broken: it left a
value pointer in the attribute, which the kernel refuses for a delete with
EINVAL. Suite 54 calls the same delete only in a cleanup that ignores its exit,
which is why it never showed there.

**Suite 07 test 17, descriptors across ten failovers, is a harness defect.** The
per-cycle series is flat: a stepped-down standby held 88 descriptors on all
five step-downs of each node, and the leader ended where it started. The
assertion compared the node that started as standby, never promoted, with
itself after it had once led. Since enterprise `4b412e7` (2026-09-07) a load
rebinds the services' map ports to its own maps and a step-down does not unbind
them, so a stepped-down standby holds one generation's handles until the next
promotion replaces them. That is bounded, the same at every step-down; the test
now takes that node's first stepped-down sample as its baseline. It was 20
descriptors over the cold count in the full run and 1 in the filtered one.

## Perf against the last baseline

pktgen, 64-byte UDP frames, one stream, three windows of 15 s, median. Results
in `ebpfsentinel-enterprise/tests/perf/results/2026-11-08-pktgen-64/`. Host load
stayed under 4.1 of 20 cores, so no cell is marked busy. Baseline:
`2026-09-21-pktgen-64-head`, kernel 7.0.0-28.

| rate | OSS now | OSS baseline | enterprise now | enterprise baseline |
|---|---:|---:|---:|---:|
| 25 kpps | 1548 | 1458 | 1711 | 1219 |
| 50 kpps | 1231 | 1057 | 1352 | 1041 |
| max | 1145 (84 kpps) | 967 (90 kpps) | 1289 (84 kpps) | 865 (90 kpps) |
| whole chain at 25 kpps | 1530 | 1425 | 1719 | 1208 |

All figures are ns per received packet.

The chain is seven programs now, not six. `drop_reason_kfree_skb`, the kernel
drop reason tracepoint added on 2026-10-30, runs once per packet and costs
216 ns (OSS) and 242 ns (enterprise) at 25 kpps. Without it the OSS chain is
1314 ns, under the baseline, and every OSS cell is within the 15% this lane
resolves.

The enterprise chain without that program is 1477 ns against 1208, about 22%
over the head baseline. Almost all of the gap is `xdp_firewall`, which costs
952 ns against 630. An earlier build measured 749 ns on the same lane the same
day as the baseline, so the head baseline sits at the low end of the lane's
spread. This run does not say
whether the move to aya 0.3.0 caused the gap; a run at the start commit, or
`BPF_PROG_TEST_RUN` on `xdp_firewall` from both builds, would.

Locked map memory is 127.5 MB against 67.7 MB, and agent RSS is 160 MB (OSS)
and 222 MB (enterprise) against 60 and 89. Among the maps the baseline did not
have are the socket identity, socket flow, listener and DLP task tables; the
bench lists every map above 1 MiB with its size.

## Fixes made during the run

| commit | repository | kind | what |
|---|---|---|---|
| `ad363959` | OSS | test | `--ebpf` on the two-machine lane selects the matrix rows on an XDP or TC surface |
| `088ca0d0` | OSS | test | write the agent's maps through its own descriptor where the BPF LSM guard refuses bpftool a writable one |
| `bc31eb0c` | OSS | product | the process table counts its resolver lookups, so a container's first lookup shows as a miss |
| `5fbb272a` | OSS | test | replace the STIX fixture directory on provision |
| `5cf858fe` | OSS | test | stop a namespaced warden broker with SIGKILL after SIGTERM, and clear a leftover broker session between local-lane suites |
| `d38a58d4` | OSS | product | the DNS clients block decides what a task sends, so a server on the node may still bind port 53 or 853 |
| `498ef8b9` | OSS | test | end the LXC suite's containers before its namespace goes and free a namespace file buried under a second bind |
| `3d5a235` | enterprise | test | the bench's dirty-tree check leaves its own output directory out |
| `f4df540e` | OSS | product | mark the forensics mirror copy so a target carrying the chain passes it instead of cloning it again |
| `517bda20` | OSS | test | a map delete through the agent's descriptor carries no value pointer |
| `d003f51` | enterprise | test | node2 re-trusts node1's key on every provision |
| `55dfcf6` | enterprise | test | count built-in threats by provenance and post a custom one carrying it |
| `26c507f` | enterprise | test | write the agent's maps through its own descriptor and bound the mirrored frame count |
| `e121d39` | enterprise | test | stage the attribution pod on the host network under a systemd cgroup parent |
| `1fb17ed` | enterprise | test | compare a stepped-down standby with its first step-down |
| `a2e5228` | enterprise | test | `BATS_FILTER` through the local lane, so a fix reruns only the failing tests |

The DNS clients bind refusal, the LXC namespace leak, the mirror loop and every
enterprise failure above predate the aya move: the code each one lives in is an
ancestor of the commit the move started from, `76c9fc94`.

## Addendum, 2026-11-08: the container runtimes lane

The two skips the local lane recorded for suites 130 and 131 were the wrong
lane, not a missing tool: both suites are written for `vagrant-runtimes/`, the
VM that carries Podman (rootful and rootless), containerd and CRI-O, and the
agent VM carries none of them. The agent VM's lane ran them only because they
had no row in `coverage-matrix.yaml`, and a suite without a row defaults to the
local lane.

They now have one, with `lanes: ["runtimes"]`, and `scripts/run-local-lane.sh`
drives that lane under `EBPFSENTINEL_LANE=runtimes` (`make test-runtimes` from
the host). The agent VM's lane leaves them out, reports `NOT RUN` naming the
runtimes lane if one is passed to it by number, and the suites' own skip says
where they run rather than which tool is absent (`07d628f9`).

Run on the runtimes VM (kernel `7.0.0-42-generic`, `bpf` in `lsm=`) with
`EBPFSENTINEL_STRICT_SKIPS=1`, on the agent, warden and objects built on the
host from `19e9ad75` (agent sha256 `2aa72cf4...`) and synced as its Vagrantfile
intends:

| suite | tests | pass | skip | fail |
|---|---:|---:|---:|---:|
| 130 Podman attribution, rootful and rootless | 2 | 2 | 0 | 0 |
| 131 containerd and CRI-O through the CRI | 2 | 2 | 0 | 0 |
| 132 start-up refusals, also on this lane | 4 | 4 | 0 | 0 |

No provisioner change and no product or harness fix was needed beyond the lane
selection. The local lane's skip table above is superseded: no skip is left in
it.
