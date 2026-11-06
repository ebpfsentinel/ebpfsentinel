# Integration Tests

End-to-end test suite for the eBPFsentinel agent. Covers agent lifecycle, REST/gRPC APIs (all domains), eBPF packet processing scenarios, performance benchmarks, Docker/Kubernetes deployments, and host-to-VM network testing.

## Directory Structure

```
tests/integration/
├── Makefile                            # Test orchestration (30+ targets)
├── suites/                             # BATS test suites (01-94)
│   ├── 01-agent-lifecycle.bats
│   ├── 02-rest-api-health.bats
│   ├── ...
│   └── 03-ebpf-map-operation-bench.bats
├── lib/                                # Shared bash helper libraries
│   ├── helpers.bash                    # Core: agent start/stop, HTTP/gRPC wrappers
│   ├── assertions.bash                 # Custom BATS assertions
│   ├── constants.bash                  # Ports, paths, network constants
│   ├── retry.bash                      # Exponential backoff retry
│   ├── ebpf_helpers.bash               # Netns/veth, packet gen, eBPF guards
│   ├── perf_helpers.bash               # iperf3/hping3/hey measurement functions
│   └── vm_helpers.bash                 # Cross-VM overrides for 2-VM topology
├── scripts/                            # Standalone utilities
│   ├── start-agent.sh                  # Launch agent in background
│   ├── stop-agent.sh                   # Graceful agent shutdown
│   ├── wait-for-agent.sh              # Poll /healthz
│   ├── wait-for-ready.sh              # Poll /readyz (eBPF loaded)
│   ├── generate-certs.sh               # Self-signed CA + server cert
│   ├── generate-jwt-keys.sh            # RSA keypair + test JWT tokens
│   ├── run-in-vm.sh                    # Main test runner (suite discovery)
│   ├── run-in-2vm.sh                   # 2-VM test runner (attacker -> agent)
│   ├── run-ebpf-docker.sh              # eBPF tests in privileged Docker
│   ├── push-docker-image.sh            # Build + stream Docker image to agent VM
│   ├── perf-test-docker.sh             # Intra-VM performance tests
│   ├── perf-test-vagrant.sh            # Binary vs Docker comparison (intra-VM)
│   ├── perf-test-host-to-vm.sh         # Host-to-VM perf over VirtualBox
│   └── vm-measure-resources.sh         # CPU/RSS sampling helper (runs in VM)
├── fixtures/                           # Config templates + test data
│   ├── config-minimal.yaml
│   ├── config-full.yaml
│   ├── config-docker-test.yaml         # Docker smoke test config
│   ├── config-docker-perf.yaml         # Docker overhead/stress test config
│   ├── config-ebpf-*.yaml              # eBPF scenario configs
│   ├── config-perf-*.yaml              # Performance test configs
│   ├── docker-compose-test.yml         # Docker smoke test compose
│   ├── docker-compose-perf.yml         # Docker overhead test compose
│   ├── health.proto                    # gRPC health check proto
│   └── k8s/                            # Kubernetes manifests (DaemonSet)
└── vagrant/                            # VM-based test environment
    ├── Vagrantfile                     # 2-VM definition (agent + attacker)
    └── provision/
        ├── setup.sh                    # Legacy single-VM provisioner
        ├── setup-agent.sh              # Agent VM: build/install agent, certs, iperf3
        ├── setup-attacker.sh           # Attacker VM: SSH keys, test tools, env vars
        └── teardown.sh                 # Cleanup
```

## Quick Start

```bash
# Run all suites locally (agent binary must be pre-built)
make test

# Run a single suite
make test-suite SUITE=01-agent-lifecycle

# Run eBPF scenario tests (requires root + kernel >= 6.12)
make test-ebpf-scenarios

# Quick performance test
make test-perf-docker-quick

# Host-to-VM performance test over VirtualBox private network
make test-perf-host-to-vm-quick
```

## Test Suites

### Functional Tests (suites 01-10, 16-17)

Run without root. Require the agent binary built (`cargo build --release`).

| Suite                    | Tests | What it covers                                                                                                                                                                   |
| ------------------------ | ----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **01-agent-lifecycle**   |     7 | Startup, graceful shutdown, SIGHUP reload, invalid config rejection, PID file management                                                                                         |
| **02-rest-api-health**   |     6 | `/healthz`, `/readyz`, `/metrics` (Prometheus), system metrics (CPU/memory/uptime)                                                                                               |
| **03-rest-api-firewall** |     8 | Firewall rule CRUD via REST: create, read, update, delete, priority ordering, bulk operations                                                                                    |
| **04-rest-api-domains**  |    23 | Domain-specific REST APIs: IPS blacklist, rate limit config, threat intel feeds, alerting routes, L7 inspection, DNS cache/blocklist, domain reputation |
| **05-grpc-streaming**    |     4 | gRPC health check, server reflection, event streaming subscription                                                                                                               |
| **06-ebpf-programs**     |     3 | eBPF program loading and attachment to a veth interface (requires kernel >= 6.12)                                                                                                |
| **07-authentication**    |    11 | JWT RS256 validation, OIDC JWKS endpoint, API key auth, role-based access control (admin/operator/viewer), token expiry, composite auth                                          |
| **08-tls**               |     5 | HTTPS termination on port 8443, gRPC over TLS, self-signed certificate validation, mTLS                                                                                         |
| **09-docker**            |    11 | Docker image build, compose deployment, healthz, baseline/Docker TCP throughput, ICMP latency, RSS/CPU overhead, API latency under load, memory stability, clean shutdown         |
| **10-kubernetes**        |     5 | Minikube DaemonSet deployment, ConfigMap injection, RBAC, pod health (VM-only)                                                                                                   |
| **15-rest-api-ddos**     |     9 | DDoS protection: status, attacks, history, policy CRUD, validation (invalid type, zero threshold, nonexistent delete)                                                            |
| **16-rest-api-extended** |    26 | Extended domains: IDS, DLP, conntrack, NAT, routing, aliases, LB (CRUD + validation), operations (config, eBPF status, reload), IPS domain-blocks                               |

### eBPF Scenario Tests (suites 11-14, 18-24)

Require **root** and **kernel >= 6.12**. Use isolated network namespaces with veth pairs (10.200.0.0/24) to test real eBPF packet processing. In 2-VM mode, root is not required locally.

| Suite                              | Tests | What it covers                                                                                                                                    |
| ---------------------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **11-ebpf-firewall-scenarios**     |     9 | Packet matching: source/dest CIDR, port ranges, protocol filters, priority-based rule ordering, default policy (pass/deny), IPv6, VLAN tagging    |
| **12-ebpf-ids-scenarios**          |     6 | Intrusion detection: reverse shell detection (port 4444), SSH brute-force threshold alerts, alert deduplication, REST alert notification pipeline |
| **13-ebpf-ips-scenarios**          |     6 | Intrusion prevention: auto-blacklist after threshold, dynamic rule injection, whitelist bypass for trusted subnets, blacklist expiry, TTL         |
| **14-ebpf-ratelimit-scenarios**    |     5 | Token bucket rate limiting: per-rule rate enforcement, ICMP/TCP/UDP rate control, burst handling, global vs per-source tracking                   |
| **17-ebpf-threatintel-scenarios**  |     5 | Threat intel: TC program attachment, status/feeds/IOC API access, metrics counters                                                                |
| **18-ebpf-conntrack-scenarios**    |     6 | Connection tracking: TC program attachment, connection table population, connection count, flush, metrics                                         |
| **19-ebpf-dns-scenarios**          |     6 | DNS intelligence: TC program attachment, cache/stats/blocklist API, cache flush, UDP:53 packet observation                                       |
| **20-ebpf-loadbalancer-scenarios** |     7 | Load balancer: XDP program attachment, service CRUD with eBPF map sync, backend detail, service deletion, metrics                                |
| **21-ebpf-nat-scenarios**          |    15 | NAT: TC ingress/egress program attachment, status/rules API, conntrack co-dependency, metrics, NPTv6 CRUD, UDP and TCP redirect round trips      |
| **22-ebpf-ddos-scenarios**         |     8 | DDoS/scrub: TC scrub program attachment, policy loading, ICMP/SYN flood detection, attack history, metrics                                       |
| **23-ebpf-scrub-scenarios**        |     5 | Packet scrub: program attachment, metrics increment, fragmented packet handling, API access                                                      |

### End-to-End & Advanced Tests (suites 24-28)

Require **root** and **kernel >= 6.12** (or 2-VM mode).

| Suite                          | Tests | What it covers                                                                                                |
| ------------------------------ | ----: | ------------------------------------------------------------------------------------------------------------- |
| **24-packet-accountability**   |     6 | Firewall packet counters: total_seen increments, total_seen >= passed + dropped, UDP/TCP delta accuracy       |
| **25-alert-end-to-end**        |     7 | Alert pipeline: IDS alert generation, REST query, source/destination fields, count increment, false positive   |
| **26-hot-reload-rules**        |     4 | Config hot-reload: initial rule count, SIGHUP adds rules, invalid config rollback, agent stays healthy        |
| **27-ebpf-dlp-scenarios**      |     5 | DLP: program attachment, configuration API, metrics, pattern loading, mode verification                       |

### Performance & Benchmark Suites (suites 15, 29-30)

Require **root** and **kernel >= 6.12** (or 2-VM mode). Measure agent overhead using iperf3, hping3, and `/proc` sampling.

| Suite                          | Tests | What it covers                                                                                                   |
| ------------------------------ | ----: | ---------------------------------------------------------------------------------------------------------------- |
| **01-performance-benchmark**   |     9 | TCP/UDP throughput, ICMP latency, TCP SYN latency, packets-per-second, CPU/RSS overhead, JSON report generation  |
| **02-ebpf-feature-overhead**   |     8 | Per-feature overhead: baseline, then cumulative (firewall, +IDS, +ratelimit, +threatintel, +all), NFR2 threshold |
| **03-ebpf-map-operation-bench**|    12 | Bulk API latency: firewall rules (100/1K/10K), threatintel IOCs, ratelimit policies, LB backends, DNS blocklist  |

## Coverage Matrix

`coverage-matrix.yaml` is the single source of truth that maps every observable agent surface - each eBPF program, each CLI subcommand, each domain module, each capability of `capabilities.json` - to the bats suite(s) that exercise it. Every path of `openapi.json` must be requested by a suite, which the audit finds by reading the suites themselves, or be listed under `routes:` with the suites that build it at run time or the owner of the suite it waits on. The matrix is enforced by `scripts/audit-coverage.sh`, which runs on every PR and fails the build if a new feature or route lands without a row, or a gap without an owner.

**Workflow when adding a feature** (new eBPF program / new CLI subcommand / new domain module):

1. Land the code change.
2. Add a row to `coverage-matrix.yaml` (kind / feature / suites / topology / kernel_min / profile / notes). If the suite doesn't exist yet, use `suites: [TBD]` with an `owner:` naming a key of `owners:` - this is tracked as a gap, rendered as "No suite yet" in the table below, and does not fail CI; a gap without an owner does.
3. Run `tests/integration/scripts/audit-coverage.sh --render` to regenerate the table below.
4. Commit the matrix + README in the same PR as the code change.

**Profiles** (consumed by `.github/workflows/integration.yml`):

- `pr` - runs on every pull request + push to `main` (≤30 s/suite p95, ≤15 min total budget). Existing fast functional suites (01-40 except heavy benches).
- `nightly` - runs on the 02:00 UTC cron schedule. Attack-realism suites (41-63), perf benches (15, 29, 30), routing/multi-WAN, soak job.
- `manual` - opt-in via `workflow_dispatch` with `profile=full`.

Per-suite mapping lives in the `suite_profiles:` block of `coverage-matrix.yaml`. The audit gate (`scripts/audit-coverage.sh`) fails the build if a new suite lands without an explicit profile pin. The workflow reads this block via `scripts/list-suites-by-profile.sh`, so adding a new suite needs **no** workflow edit.

**Lanes** (consumed by the three runners):

- `scripts/run-local-lane.sh` - one machine. The suite runs on the host that runs the agent, and traffic comes out of a network namespace beside it.
- `scripts/run-in-2vm.sh` - the suite runs on the attacker VM and drives an agent on a machine of its own.
- `scripts/run-in-3vm.sh` - the same, with a backend behind the agent so the agent is a transit hop.

The `lanes` field on each `attack_suites` row names the lanes a suite is written for, and is the one field the three runners select on. It is deliberately not `topology`, which is the fewest machines a suite needs: a suite needing a second machine for its wire assertions can still carry API-surface tests that run on a single one, and a suite can be unrunnable on a lane for a reason of the lane rather than of the product - suite 59 drives TCP/22, which sshd already holds on the machine the two-machine lane reaches over SSH, so seven of its eight tests skipped there while all eight pass on one machine. A suite with no row runs on the local lane, which is every suite below 38.

Running every suite on every lane was the older behaviour and it reported skips that were a fact about the lane rather than about the product: forty-one of the fifty-seven skips a full local run printed were a suite asking for a machine that lane does not have. Passing suite numbers to a runner still overrides the list, which is how a single suite is re-run after a fix.

What scoping cannot remove is a suite written for more than one lane whose individual tests are not: suites 50 and 55 carry both a single-machine probe and a `skip_if_not_3vm` test, so each of those tests runs on exactly one of the three lanes and skips on the others. That is a test needing more machines than the lane has, not a gap: every one of them runs somewhere.

### CI profiles & budget guard

| Trigger | Profile resolved | Jobs that run |
|---|---|---|
| `pull_request`, `push` to main | `pr` | `pr-suites`, `pr-docker`, `pr-ebpf` |
| `schedule` (02:00 UTC) | `nightly` | `nightly-suites` (matrix per suite), `nightly-soak` (8 h), `nightly-triage` on failure. **Commented out** until a `[self-hosted, linux, vagrant]` runner is registered: these jobs bring Vagrant VMs up on the runner itself |
| `workflow_dispatch` profile=`pr`/`nightly`/`full` | as input | corresponding jobs (`full` runs both PR and nightly sets) |

**`pr-ebpf` is the only lane that loads the programs into a kernel**, so it runs with `EBPFSENTINEL_STRICT_SKIPS=1` and on the pull request rather than after the merge: a program the verifier refuses is caught nowhere else, and a gate that speaks only on `main` reports a datapath that is already broken for everybody. Whether a hosted runner can load them is what the first strict run answers; if it cannot, the job moves to the self-hosted Vagrant runner the nightly jobs use, where suites 06 and 67 were proven, rather than losing the strictness.

**Budget guard** - the `pr-suites` job records its start epoch and asserts wall-clock ≤ `PR_BUDGET_MINUTES` (default 15) before exiting. Exceeding the budget fails the run rather than silently growing.

**Soak job** - `nightly-soak` invokes `scripts/perf-test-host-to-vm.sh --soak-duration N`. On a schedule run, `N` defaults to **28800 s (8 h)**; `workflow_dispatch` accepts a `soak_duration_secs` override. The script asserts RSS growth < `THRESH_SOAK_RSS_GROWTH` (10 % short, scaled for long runs) **and** FD-count growth < `THRESH_SOAK_FD_GROWTH` (25 % over 8 h). Reports are archived as the `nightly-soak-report` artifact for 30 days.

**Auto-issue** - `nightly-triage` opens a `nightly-regression` issue on soak failure or `nightly-flake` on suite-only failure when the cron run is red. Same UTC day → one issue + comment, fresh day → new issue. Logs are linked via artifact names.

<!-- coverage:start -->
<!-- AUTO-GENERATED by tests/integration/scripts/audit-coverage.sh --render. Do not edit by hand. -->

_Generated from `coverage-matrix.yaml`. Run `scripts/audit-coverage.sh --render` after adding/removing a feature._

#### eBPF programs (28)

| Feature | Suites | Topology | Kernel | Profile | Notes |
|---|---|---|---|---|---|
| `cgroup-attribution` | 67, perf/07 | none | 6.12 | pr | Socket hooks naming the cgroup and the process behind a connection; loaded on its defaults in 67, connect() cost with and without it measured in perf/07 |
| `cgroup-clusterip` | No suite yet (kernel-network) | none | 6.12 | manual | Resolves the Service cluster addresses of opted-in pods at connect4/connect6 and answers with the cluster address at getpeername and recvmsg. Asserted beside Cilium and Calico in the operator's coexistence lane, which needs a cluster no lane here provisions |
| `cgroup-connect-redirect` | No suite yet (kernel-network) | none | 6.12 | manual | Steers the TCP connections of selected cgroups to a local listener at connect4/connect6. No suite yet: the listener and the selection are the enterprise TLS interception's, so the suite that asserts a steered connection lands on the listener belongs beside it |
| `cgroup-workload-firewall` | 67, 70, 92, 98 | 2vm | 6.12 | nightly | Workload rules decided at connect/sendmsg/bind; suite 70 refuses a connect by the executable of the direct parent and of any ancestor, read from the live chain of parents |
| `lsm-bpf-guard` | 88 | none | 6.12 | nightly | No task but the agent and its warden opens the agent's maps for writing or its links at all, at the bpf and bpf_map hooks; 88 has a detach of the agent's link refused with the BPF LSM active, which the agent VM's boot line now sets |
| `lsm-exec-network` | 91 | none | 6.12 | nightly | Only the executables in the set reach the network, at socket_create and socket_connect: observe reports by pid and inode, enforce refuses with a permission error, the agent's own sockets and the listed binary pass. Needs the BPF LSM active at boot (lsm=bpf), which the agent VM's boot line sets |
| `lsm-write-refusal` | 83 | none | 6.12 | nightly | A writer's write-opens and truncations under a watched directory refused past a count inside a window, nothing refused once the agent is gone, and in shadow nothing refused or raised while the reading counts it by workload. Needs the BPF LSM active at boot (lsm=bpf); the suite skips where it is not |
| `tc-conntrack` | 18, 24, 47, 67 | 3vm | 6.12 | pr | Connection tracking; kernel-CT kill via kill_flow_via_xdp_ct/skb_ct asserted in 47 |
| `tc-dns` | 19, 45, 67 | 3vm | 6.12 | pr | Passive DNS capture; DoH/DoT detection via ClientHello SNI + dst_port 853 asserted in 45 |
| `tc-ids` | 12, 25, perf/04, 39, 66, 67, 77 | 2vm | 6.12 | pr | Intrusion detection (TC); ringbuf overrun behaviour at >1 Mpps in perf/04; slow-attack signatures in 39; what the agent decided to drop against what the kernel confirmed it tore down in 66, driven from both sides of the tc hook so the confirmation is not read as a copy of the drop count; refused by name with fou unloaded in 77 |
| `tc-nat-egress` | 21, 50, perf/06, 67 | 2vm | 6.12 | pr | SNAT (TC egress); NPTv6 (RFC 6296) checksum-neutral prefix swap config + CLI/REST surface asserted in 50 (wire-level swap gated on IPv6 routability); SNAT/masquerade datapath throughput overhead measured in perf/06 |
| `tc-nat-ingress` | 21, 50, perf/06, 67 | 2vm | 6.12 | pr | DNAT (TC ingress); NPTv6 reverse-prefix translation surface asserted via REST + CLI in 50; DNAT datapath throughput overhead measured in perf/06 |
| `tc-qos` | 28, 67 | 2vm | 6.12 | pr | Traffic shaping (TC egress) |
| `tc-scrub` | 23, 40, 46, 67 | 3vm | 6.12 | pr | Packet normalization; spoofed-source amplification drop in 40; byte-level pcap assertions (TTL floor, MSS clamp, DF clear, IP-ID rand) in 46 |
| `tc-threatintel` | 17, 33, 67 | 2vm | 6.12 | pr | OSINT feed IOC matching (TC) |
| `tracepoint-drop-reason` | 90 | none | 6.12 | nightly | Counts the packets the kernel frees undelivered, under the skb_drop_reason it gives; 90 sends datagrams to a closed port and reads them back as NO_SOCKET on the interface they arrived on |
| `tracepoint-process` | 67, 70, perf/07 | none | 6.12 | pr | Exec, fork and exit feeding the process table; 67 reads a program that execed after the hooks attached, 70 decides workload rules on the chain of parents it records, exec() cost measured in perf/07 |
| `tracepoint-signal` | 82, 93 | none | 6.12 | nightly | Signals the named task at its next syscall: the mass encryption run stopped in 82, the reverse shell stopped in 93 |
| `tracepoint-tcp-health` | 71 | none | 6.12 | nightly | Retransmissions, resets and connections opened, failed and closed, counted per pair of ends at the TCP stack's own tracepoints; 71 provokes resets to a closed port and full connections, and reads both ends back |
| `uprobe-crypto` | No suite yet (host-integrity) | none | 6.12 | manual | Calls into the encryption entry point of libcrypto, libgcrypt and libsodium, counted per process for the mass encryption engine. No suite yet: nothing runs a program that encrypts files through the library and reads the signal back |
| `uprobe-dlp` | 27, 60, 62, perf/06, 67 | 2vm | 6.12 | pr | SSL/TLS DLP via uprobes; per-container uprobe attach across cgroups in suite 60; TLS-MITM inspection is enterprise-only; uprobe SSL-inspection goodput cost (loopback libssl) measured in perf/06 |
| `xdp-firewall` | 11, 24, 26, perf/04, 40, 67, 69 | 2vm | 6.12 | pr | L3/L4 stateful firewall (XDP); XDP-drop CPU savings measured in perf/04; amplification ports denied in 40; a port Docker publishes refused before its DNAT in 69 |
| `xdp-firewall-reject` | 42 | 2vm | 6.12 | nightly | TCP RST / ICMP forging tail-call; perf/04 wire-validates checksums + src/dst swap + whitelist bypass |
| `xdp-loadbalancer` | 20, 44, 67 | 2vm | 6.12 | pr | L4 LB + Maglev; suite 44 (3-VM) covers L2 DSR end-to-end and Maglev disruption bound |
| `xdp-pass` | 42, 46 | 2vm | 6.12 | nightly | Test-only XDP_PASS stub attached to the netns side of the veth pair by lib/ebpf_helpers.bash (create_test_netns) so XDP_TX reflections from xdp-firewall-reject reach the namespace; a physical NIC needs no such helper |
| `xdp-ratelimit` | 14, 15, perf/04, 67 | 2vm | 6.12 | pr | Token bucket + sliding window + leaky bucket; SYN cookie at >1 Mpps in perf/04 |
| `xdp-ratelimit-syncookie` | 43 | 2vm | 6.12 | nightly | SYN cookie forging tail-call; suite 43 asserts TcpExtSyncookiesSent + agent metric grow, legit ncat completes, spoofed flood leaves TcpExtSyncookiesRecv flat |
| `xdp-vip-announcer` | 37, 44, 67 | 2vm | 6.12 | nightly | L2 VIP announcer / ARP responder; suite 44 (3-VM) drives the responder + gratuitous-ARP + is_self_announced predicate from a real client |

#### CLI subcommands (44)

| Feature | Suites | Topology | Kernel | Profile | Notes |
|---|---|---|---|---|---|
| `alerts` | 04, 25, 34 | 2vm | 6.12 | pr | Alert list + e2e + SSE stream |
| `aliases` | 16 | 2vm | 6.12 | pr | Alias status and resolved content read back through /api/v1/aliases in 16, including an alias that does not exist |
| `audit` | 04 | none | n/a | pr | Audit log + rule history |
| `capture` | 49 | 2vm | 6.12 | nightly | Manual packet capture (start/list/stop) with tcpdump-parseable pcap export asserted in 49 |
| `config` | 16, 17, 23, 25, 35, 52 | 2vm | 6.12 | pr | Effective configuration and reload through /api/v1/config; reload asserted under sustained load in 52 and against the operator-managed flag in 35 |
| `conntrack` | 18, 16 | 2vm | 6.12 | pr | Connection tracking inspection + flush |
| `ddos` | 15, 22, 38, 39, 40 | 2vm | 6.12 | pr | DDoS protection + scrub; MHDDoS flood matrix in 38; slow-attack T1499.002 in 39; amplification T1498.002 in 40 |
| `dlp` | 16, 27 | 2vm | 6.12 | pr | DLP status and pattern list; the uprobe datapath behind them is asserted in 27 |
| `dns` | 04, 19 | 2vm | 6.12 | pr | DNS cache, stats, blocklist |
| `domains` | 04 | none | n/a | pr | Domain reputation + blocklist |
| `ebpf` | 16, 60, 62, 77, 79 | 2vm | 6.12 | pr | Program load status through /api/v1/ebpf/status; the per-container uprobe inventory in 60; the kernel floor refusal and the kernel-features verdicts in 77; the hidden port and hidden process sweeps in 79 |
| `exposure` | 90 | none | 6.12 | nightly | exposure listeners; 90 reads the same listing through the API, and no suite drives the CLI |
| `fingerprints` | 29, 41 | 2vm | 6.12 | nightly | JA4+ cache + client-diversity (curl/openssl/python/go/MHDDoS) on suite 41 |
| `firewall` | 03, 11, 26, 40 | 2vm | 6.12 | pr | L3/L4 rule CRUD + eBPF scenarios; amplification UDP-port denies in 40 |
| `flows` | 04, 18 | 2vm | 6.12 | pr | Aggregated connection map |
| `geoip` | 30 | 2vm | 6.12 | pr | GeoIP status and address lookup against the fixture database in 30 |
| `health` | 02 | none | n/a | pr | /healthz + /readyz |
| `hostrules` | 78 | none | 6.12 | nightly | Host rules through /api/v1/host-rules and /api/v1/host-rules/intents: a written rule loads in shadow beside the shipped ones, its shadow count rises per workload with no alert, promotion to enforce kills the process and alerts, and an intention the host does not feed carries the same reason everywhere it is named |
| `identity` | 35 | none | n/a | pr | Operator-managed flag, hostname, version |
| `ids` | 12, 16, 33, 55, 59 | 2vm | 6.12 | pr | IDS status and rule list; the rules are asserted over IPv6 in 55 and under a real SSH brute force in 59 |
| `investigate` | 04 | none | n/a | pr | IP correlation across alerts/CT/DNS/blacklist |
| `ips` | 13, 16, 38, 39 | 2vm | 6.12 | pr | Intrusion prevention + auto-blacklist; MHDDoS flood matrix in 38; slowhttptest in 39 |
| `l7` | 16, 29, 38, 39 | 2vm | 6.12 | pr | L7 firewall rules (HTTP/SMTP/FTP/SMB inspection); MHDDoS flood matrix in 38; slow-request timeout in 39 |
| `lb` | 16, 20, 37 | 2vm | 6.12 | pr | Load balancer services + VIPs |
| `learning` | 87 | none | 6.12 | nightly | Learning window list and status, read back in 87 after the window came back from a restart |
| `metrics` | 02 | none | n/a | pr | Prometheus metrics |
| `mitre` | 16, 51, 87 | 2vm | 6.12 | nightly | MITRE coverage matrix; suite 87 asserts a disabled IDS is listed under switched_off and not as coverage; suite 16 asserts GET /api/v1/mitre/coverage (technique/tactic consistency), suite 51 enforces that every alert-producing suite carries a MITRE assertion |
| `nat` | 16, 21, 50 | 2vm | 6.12 | pr | NAT + NPTv6; NPTv6 prefix translation covered by suite 50 |
| `netpol` | No suite yet (kernel-network) | k8s | 6.12 | manual | NetworkPolicy compiled for the pods of one node. No suite yet: the kubernetes lane does not apply a policy and read the compiled rules back |
| `processes` | 93 | none | 6.12 | nightly | What a pid is, from its exec to its exit. The REST route it reads is asserted in 67; show and list are driven in 93 on the shell a detection named |
| `qos` | 16, 28 | 2vm | 6.12 | pr | QoS / traffic shaping |
| `ratelimit` | 04, 14, 16, 38 | 2vm | 6.12 | pr | Rate limit policies; MHDDoS flood matrix in 38 |
| `responses` | 48 | 2vm | 6.12 | nightly | Manual time-bounded response actions (create/list/revoke + TTL auto-expire) asserted via REST + CLI parity in 48 |
| `routing` | 16, 32, 53 | 2vm | 6.12 | pr | Gateway and route list through /api/v1/routing; failover ordering in 53 |
| `score` | 04 | none | n/a | pr | 0-10 network risk score |
| `status` | 01, 02 | none | n/a | pr | Runtime status query |
| `surface` | 80 | none | 6.12 | nightly | What is installed, root by root, through /api/v1/surface/packages, and the modules a running Go program (containerd or dockerd) states from its own build information, and every file live processes map executable through /api/v1/surface/loaded, joined to the package owning it in that process's root (a program started in the suite appears with its libc owned by libc6 and leaves when stopped, a chrooted process is attributed to its own root), and every listener through /api/v1/surface/listening with the packages its process maps, the connections it took and who the policy lets reach it (a Python server started in the suite names libc6 and its interpreter's package and leaves when stopped), and the whole of it summed through /api/v1/surface and the bare surface command (every installed package mapped or not, every listener under one origin, a server reachable from anywhere listed with its packages): the CLI's tables and JSON agree with the four routes |
| `threatintel` | 16, 17, 33 | 2vm | 6.12 | pr | OSINT feed CRUD + IOC matching + STIX feed |
| `tls` | 58 | none | n/a | nightly | TLS status through /api/v1/tls/status, read while the PQ-hybrid handshake sweep runs in 58 |
| `top` | 04 | none | n/a | pr | Top talkers by traffic volume |
| `trace` | 87 | none | 6.12 | nightly | trace through the loaded programs, naming the deny rule a crafted packet meets, in 87 |
| `version` | 01 | none | n/a | pr | Version + build info |
| `watch` | 34 | none | n/a | pr | SSE alerts stream (tail -f) |
| `zones` | 31 | 2vm | 6.12 | pr | Zone, policy and status reads through /api/v1/zones in 31 |

#### Domain modules (45)

| Feature | Suites | Topology | Kernel | Profile | Notes |
|---|---|---|---|---|---|
| `alert` | 04, 25, 34, 61 | 2vm | 6.12 | pr | Alert pipeline + routing; outbound delivery asserted in 61 across all three senders - webhook (POST + JSON body identity + route headers + 5xx retry + SSRF refusal of a loopback target), email (SMTP envelope + body) and OTLP (export on /v1/logs with the alert attributes) |
| `alias` | 16 | none | n/a | pr | AliasSet (CIDR aliases); suite 16 covers alias_count plus PUT /api/v1/aliases/{id}/content on an External alias (accept) and on ip_set / unknown / invalid-CIDR inputs (reject) |
| `audit` | 04 | none | n/a | pr | Audit trail + rule history |
| `auth` | 07, 36 | none | n/a | pr | JWT/OIDC/JWKS/API-key + RBAC |
| `capture` | 49, 62 | 2vm | 6.12 | nightly | Pcap export lifecycle (Running → Completed) + on-disk pcap validity asserted in 49; broker-provided AF_PACKET sockets (PcapOpen fd hand-off) asserted in 62 |
| `clusterip` | No suite yet (kernel-network) | none | 6.12 | manual | The plan deciding which Services an opted-in workload resolves at connect and which stay with kube-proxy. No suite yet: nothing connects to a cluster address from a selected cgroup and reads the backend it reached |
| `conntrack` | 16, 18, 24, 47, 62, 66 | 3vm | 6.12 | pr | Connection tracking; kernel-CT kill on block-rule injection mid-flow in 47; what the kernel confirmed it tore down against what the agent decided, on both sides of the tc hook order, in 66; GET /api/v1/conntrack/events SSE stream asserted in 16 (skipped when /proc/net/nf_conntrack is absent); brokered teardown from the user-namespace agent asserted in 62 |
| `container` | 54 | 2vm | 6.12 | nightly | cgroup_id enrichment via Docker enricher + resolver metric surface asserted in 54; AlertResponse container fields and k8s pod enrichment tracked as deferred ACs in the suite header. Per-tenant cgroup filtering is enterprise-only and is tested in the enterprise repo |
| `coverage` | No suite yet (restart-state) | k8s | 6.12 | manual | What the node agent sees of each pod and why it misses what it misses. No suite reads the per-pod coverage report; 87 asserts only the refusal on a node without a pod inventory |
| `ddos` | 15, 22, 38, 39, 40 | 2vm | 6.12 | pr | DDoS detection + policy; MHDDoS flood matrix in 38; service-exhaustion in 39; amplification in 40 |
| `dlp` | 16, 27, 60, 62, perf/06 | 2vm | 6.12 | pr | Data loss prevention; suite 27 covers pattern match + uprobe attach, suite 60 the per-container attach path, suite 62 the brokered DlpScan + AttachUprobe half. TLS-MITM proxy is enterprise-only; wire-level malicious-MITM + decrypted-payload assertions remain 3-VM deferrals (need mitmproxy + injected-CA topology). uprobe SSL-inspection goodput cost benched in perf/06 |
| `dns` | 04, 19, 45, 55 | 3vm | 6.12 | pr | DNS intel; DoH/DoT detection via ClientHello SNI + dst_port 853 in 45; AAAA query parser-readiness asserted in 55 |
| `drops` | 90 | none | 6.12 | nightly | Kernel drop reasons as readable counts, fed by tracepoint-drop-reason; 90 reads NO_SOCKET back with its description |
| `exposure` | 90 | none | 6.12 | nightly | What this node exposes, read off the socket hooks, and who bound it; 90 binds two listeners after start and reads one reachable by the default policy and one closed by a deny rule |
| `file_watch` | 94, 97 | none | 6.12 | nightly | Changes to watched files and the process that made them on the host, and a change to the agent's own configuration, asserted in 94. A file a container writes, matched by a host rule at the path the container sees and never at the path under Docker storage, asserted in 97 |
| `firewall` | 03, 11, 24, 26, 40, 47, 55 | 3vm | 6.12 | pr | Stateful L3/L4 firewall; amplification UDP-port denies in 40; mid-flow block + CT-kill in 47; IPv6 CIDR rule round-trip + v4↔v6 co-existence asserted in 55 |
| `flow` | 90 | none | 6.12 | nightly | Flow records and their IPFIX, OTLP, JSON and SIEM encodings; 90 exports a connection to the JSON lines sink and reads it back with the export status, and no suite decodes IPFIX, OTLP or the SIEM encodings at a collector |
| `guest` | 73, 74, 75 | none | 6.12 | nightly | The virtual machines whose traffic crosses this host: a tap device in 73, a policy decided on a guest in 74, a libvirt domain in 75 |
| `hidden` | 79 | none | 6.12 | nightly | Hidden ports and hidden processes on a busy host: listeners in two network namespaces, SO_REUSEPORT, TIME_WAIT, a many-threaded process and process churn, and neither sweep reports anything twice in a row; the process sweep stays inside its time and CPU budget. The positive case is unit-tested at the port boundary, since a real one needs a rootkit |
| `hostrule` | 78 | none | 6.12 | nightly | Intent catalogue, typed matchers, shadow book and promotion, decided on process start and exit fed by tracepoint-process; the rule and event grammar is also fuzzed by fuzz_host_rule |
| `identity` | No suite yet (workload-identity) | 2vm | 6.12 | manual | This node's addresses as names another node can read, and the peer's names on a flow. No suite yet: the two-end reading needs a second agent on the attacker VM |
| `ids` | 12, 25, 38, 39, 55, 59, 66 | 2vm | 6.12 | pr | Intrusion detection engine; the block branch's two counters - the attempt and the kernel's own confirmation of the conntrack tear-down - asserted against each other in 66; behavioural signatures stressed in 38; slow-attack signatures in 39; IPv6-scoped signature surface asserted in 55 (wire-level v6 IDS alert via tc-ids deferred - needs dual-stack 2-VM topology); SSH brute-force threshold rule surface + MITRE T1110(.001) alert path asserted in 59 (real hydra/ncrack credential bursts deferred - same dataplane contract is driven by the SYN-burst path) |
| `inventory` | 80 | none | 6.12 | nightly | The host's dpkg database agrees with dpkg-query, a chroot's Alpine database is read under kind other, and a link climbing out of a root finds nothing. rpm's sqlite reader and every parser are unit-tested against databases taken from real images |
| `ips` | 13, 16, 38, 39, 55, 59, perf/03 | 2vm | 6.12 | pr | Auto-blacklist + whitelist; MHDDoS flood matrix in 38; slowhttptest in 39; IPv6 blacklist-write surface asserted in 55; SSH brute-force auto-block under threshold count + auto-blacklist capture asserted in 59; in-kernel blacklist-injection control-plane latency (100/1K) benched in perf/03 |
| `l2` | 37, 44, 62 | 2vm | 6.12 | nightly | L2 binding + self-whitelist; DSR end-to-end covered by suite 44; gratuitous ARP brokered through the warden (ArpAnnounce) asserted in 62 |
| `l7` | 16, 29, 38, 39, 56 | 2vm | 6.12 | pr | HTTP/TLS/SNI/gRPC/SMTP/FTP/SMB; slow-request timeout in 39; SMTP/FTP/SMB matcher round-trip + parser robustness (truncated TCP, invalid-protocol POST rejection) asserted in 56. Wire-level swaks/lftp/smbclient per-command behaviour deferred (needs extra deps on test VMs; covered by domain l7::engine unit tests) |
| `learning` | 87 | none | 6.12 | nightly | Watching a node for a window and holding what it reached; 87 opens windows, restarts the agent and reads one back running with the downtime as a gap and one interrupted past its deadline, then its edges, policy, segmentation and stop |
| `loadbalancer` | 16, 20, 37, 44 | 2vm | 6.12 | pr | Maglev + DSR; 3-VM end-to-end coverage via suite 44 |
| `nat` | 16, 21, 50, perf/03, perf/06 | 2vm | 6.12 | pr | SNAT/DNAT/NPTv6; NPTv6 rule CRUD + tc-nat-egress config surface asserted in 50; NPTv6 control-plane add latency in perf/03; SNAT/DNAT datapath throughput overhead in perf/06 |
| `netpol` | No suite yet (kernel-network) | k8s | 6.12 | manual | Kubernetes NetworkPolicy compiled for the pods of one node. No suite applies a policy |
| `network_program` | 88 | none | 6.12 | nightly | Programs other than the agent's on the node's network path; 88 attaches an XDP program from outside the agent and reads it back as foreign, and detaches the agent's own link without the guard and reads the alert |
| `process` | 67, 70, 93 | none | 6.12 | nightly | The process table: a pid from exec to exit with its chain of ancestors; read through REST in 67, the chain decides workload rules in 70, the reverse shell, fileless and server-descendant detections and their process kill in 93 |
| `qos` | 16, 28 | 2vm | 6.12 | pr | Traffic shaping policies |
| `ransom` | 81, 82, 83, 84, 96 | none | 6.12 | nightly | Mass encryption recognised by signals that agree: the shadow verdict in 81, the stop in 82, the write refusal with the BPF LSM in 83 and through fanotify in 84, and in 96 a partial encryption raised on the header while the sampled entropy stays flat, and one past the sampled window that nothing reads |
| `ratelimit` | 04, 14, 38 | 2vm | 6.12 | pr | Token bucket + variants; exhaustion under flood in 38 |
| `raw_socket` | 88 | none | 6.12 | nightly | Packet sockets open on the node and the classic BPF filter behind them; 88 opens an AF_PACKET socket, with and without a classic filter, and reads its holder, its filter length and the alert |
| `response` | 48 | 2vm | 6.12 | nightly | In-memory ResponseEngine create/list/revoke + TTL auto-expire asserted in 48; auto_response → IpsService → firewall-map mirroring exercised separately by the auto-response pipeline (not in 48) |
| `routing` | 32, 53 | 2vm | 6.12 | nightly | Multi-WAN routing; failover ordering + REST + metrics surface asserted in 53 (priority-ordered list, gateways_total gauge, failovers_total counter, SIGHUP-driven priority swap). Active health probe loop + WAN_ALL_DOWN alert + real link-down egress reroute tracked as deferred ACs in the suite header |
| `share_writes` | 85 | none | 6.12 | nightly | A host writing to file shares it never wrote to, read off its own flows, including the sealed SMB 3 case |
| `tcp_health` | 71 | none | 6.12 | nightly | TCP health per edge as named counters, fed by tracepoint-tcp-health; 71 reads the no_listener resets and both ends of a connection |
| `telemetry` | No suite yet (unplanned) | none | n/a | manual | Anonymous heartbeat of version and eBPF load state. No suite exercises it: the destination is a build-time constant that no test build carries, so a community or CI binary has nowhere to send one and there is nothing to receive it |
| `threatintel` | 16, 17, 33 | 2vm | 6.12 | pr | OSINT feeds + IOC + STIX |
| `trace` | 87 | none | 6.12 | nightly | One crafted packet run through the loaded programs, each stage's verdict; 87 traces a five-tuple a deny rule names and reads the stage that stopped it, and one it does not name |
| `workload` | 67, 70, 92, 95 | none | 6.12 | nightly | The workload block naming the process, cgroup and container behind a flow; 70 asserts rules decided on its ancestry, 92 on its executable, unit and cgroup, 95 the processes allowed to resolve and the resolvers every process may use |
| `zone` | 31 | 2vm | 6.12 | pr | Zone-based policy |

#### Capabilities above the floor (14)

| Feature | Suites | Topology | Kernel | Profile | Notes |
|---|---|---|---|---|---|
| `attribution` | 70 | none | 6.12 | nightly | The workload named on a flow |
| `bpf_lsm` | 83, 86 | none | 6.12 | nightly | A write refused at an LSM hook in 83; the boot parameter named when bpf is missing from the module list in 86 |
| `copy_from_user_str` | 86 | none | 6.12 | nightly | No shipped program rests on it yet, so the report in 86 is all there is to assert |
| `file_kfuncs` | 77 | none | 6.12 | nightly | Probed and reported in 77 |
| `immediate_signal` | 82 | none | 6.12 | nightly | A run spinning without a syscall after its writes killed at once; skipped where the kernel signals at the next syscall only |
| `kprobe_session` | 86 | none | 6.12 | nightly | No shipped program rests on it yet, so the report in 86 is all there is to assert |
| `network_executables` | 91 | none | 6.12 | nightly | Needs the BPF LSM active at boot, which the agent VM's boot line sets |
| `process_signal` | 82 | none | 6.12 | nightly | A run encrypting files stopped by the signal |
| `process_tracing` | 70 | none | 6.12 | nightly | The process and its lineage behind a flow |
| `quarantine` | No suite yet (workload-identity) | none | 6.12 | manual | No suite yet: nothing in this agent arms a quarantine, which only the enterprise automated response calls, so the suite that reads a workload's connections refused for the window belongs beside that response |
| `self_protection` | 88 | none | 6.12 | nightly | 88 reads the guard as protected and has a detach of the agent's XDP link refused where the BPF LSM runs, and reads it unprotected with the detach succeeding where bpf is masked out of the module list |
| `tcp_reqsk_assign` | 86 | none | 6.12 | nightly | No shipped program rests on it yet, so the report in 86 is all there is to assert |
| `workload_firewall` | 70, 72, 92, 98, 99 | none | 6.12 | nightly | Rules on a workload's ancestry in 70, inside LXC containers in 72, and written as Docker container labels in 98: an enforced deny, an allow list with a default deny, observe raising without refusing, a malformed label refused and reported, and a container started after the agent policed without a reload. Hooks the kernel refused to attach stop an agent whose rule or labels would refuse, are reported off with the reason under a rule that observes, and turn a reload to enforce away in 99 |
| `write_refusal` | 83, 84 | none | 6.12 | nightly | At the LSM hook in 83 and through the fanotify permission group in 84 |

#### API paths (133)

| Path | Suites |
|---|---|
| `/api/v1/agent/identity` | 35, 36 |
| `/api/v1/agent/status` | 02, 08, 30 |
| `/api/v1/alerts` | 04, 12, 13, 14, 25, 27, 29, 30, 31, 38, 39, 40, 41, 43, 44, 45, 52, 53, 54, 55, 56, 59, 60, 61, 71, 79, 83, 84, 91, 92, 93, 94, 95, 96, 97 |
| `/api/v1/alerts/stream` | 25, 34 |
| `/api/v1/alerts/triage` | No suite yet (unplanned) |
| `/api/v1/alerts/{id}` | 25, 34 |
| `/api/v1/alerts/{id}/false-positive` | 25 |
| `/api/v1/alerts/{id}/triage` | No suite yet (unplanned) |
| `/api/v1/aliases/status` | 16 |
| `/api/v1/aliases/{id}/content` | 16 |
| `/api/v1/audit/logs` | 04, 56 |
| `/api/v1/audit/rules/{id}/history` | 04 |
| `/api/v1/captures` | 49 |
| `/api/v1/captures/manual` | 49, 62 |
| `/api/v1/captures/{id}` | 49, 62 |
| `/api/v1/config` | 16, 23, 25 |
| `/api/v1/config/reload` | 16, 17, 35, 52, 99 |
| `/api/v1/config/{section}` | 16, 17, 27, 35, 52, 99 |
| `/api/v1/conntrack/connections` | 16, 18 |
| `/api/v1/conntrack/events` | 16 |
| `/api/v1/conntrack/flush` | 16, 18, 62 |
| `/api/v1/conntrack/status` | 16, 18, 21, 65 |
| `/api/v1/ddos/attacks` | 15, 22 |
| `/api/v1/ddos/attacks/history` | 15, 22 |
| `/api/v1/ddos/policies` | 15, 22, 30 |
| `/api/v1/ddos/policies/{id}` | 15, 22 |
| `/api/v1/ddos/status` | 15, 22, 30 |
| `/api/v1/dlp/patterns` | 16, 27 |
| `/api/v1/dlp/scope` | 87 |
| `/api/v1/dlp/status` | 16, 27 |
| `/api/v1/dns/blocklist` | 04, 17, 19, 33 |
| `/api/v1/dns/cache` | 04, 19 |
| `/api/v1/dns/stats` | 04, 19 |
| `/api/v1/dns/status` | 33 |
| `/api/v1/domains/blocklist` | 04 |
| `/api/v1/domains/blocklist/{domain}` | 04 |
| `/api/v1/domains/reputation` | 04 |
| `/api/v1/ebpf/coverage` | 87 |
| `/api/v1/ebpf/drop-reasons` | 90 |
| `/api/v1/ebpf/foreign-programs` | 88 |
| `/api/v1/ebpf/guests` | 73, 74, 75 |
| `/api/v1/ebpf/hidden-ports` | 79 |
| `/api/v1/ebpf/hidden-processes` | 79 |
| `/api/v1/ebpf/kernel-features` | 27, 77, 82, 83, 84, 86, 88, 95, 99 |
| `/api/v1/ebpf/raw-sockets` | 88 |
| `/api/v1/ebpf/status` | 06, 16, 62, 68 |
| `/api/v1/ebpf/uprobes` | 60 |
| `/api/v1/exposure/listeners` | 90 |
| `/api/v1/fingerprints/ja4s` | 41 |
| `/api/v1/fingerprints/summary` | 41 |
| `/api/v1/firewall/l7-rules` | 04, 29, 30, 56 |
| `/api/v1/firewall/l7-rules/{id}` | 04, 29, 56 |
| `/api/v1/firewall/rules` | 03, 07, 11, 26, 30, 47, 55, 76 |
| `/api/v1/firewall/rules/{id}` | 03, 07, 11, 47, 76 |
| `/api/v1/firewall/shadow` | 76 |
| `/api/v1/firewall/workload/fqdn` | 92 |
| `/api/v1/firewall/workload/labels` | 92, 98 |
| `/api/v1/firewall/workload/reach` | 70 |
| `/api/v1/firewall/workload/rules` | 70, 72, 92, 95, 98 |
| `/api/v1/flows/export` | 90 |
| `/api/v1/geoip/lookup` | 30 |
| `/api/v1/geoip/status` | 30 |
| `/api/v1/host-rules` | 78 |
| `/api/v1/host-rules/intents` | 78 |
| `/api/v1/host-rules/mass-encryption` | 81, 82, 96 |
| `/api/v1/host-rules/write-refusal` | 83, 84 |
| `/api/v1/ids/rules` | 12, 16, 55, 59 |
| `/api/v1/ids/status` | 12, 16, 33 |
| `/api/v1/ids/suricata/report` | No suite yet (unplanned) |
| `/api/v1/ips/blacklist` | 04, 13, 38, 39, 55, 59 |
| `/api/v1/ips/blacklist/{ip}` | 38, 39, 55 |
| `/api/v1/ips/domain-blocks` | 13, 16 |
| `/api/v1/ips/rules` | 04, 13, 59 |
| `/api/v1/ips/rules/{id}` | 13 |
| `/api/v1/lb/services` | 16, 20 |
| `/api/v1/lb/services/{id}` | 16, 20 |
| `/api/v1/lb/status` | 16, 20 |
| `/api/v1/lb/vips` | No suite yet (unplanned) |
| `/api/v1/lb/vips/bgp` | No suite yet (unplanned) |
| `/api/v1/lb/vips/grant` | No suite yet (unplanned) |
| `/api/v1/learning/sessions` | 87 |
| `/api/v1/learning/sessions/{id}` | 87 |
| `/api/v1/learning/sessions/{id}/edges` | 87 |
| `/api/v1/learning/sessions/{id}/policy` | 87 |
| `/api/v1/learning/sessions/{id}/segmentation` | 87 |
| `/api/v1/learning/sessions/{id}/stop` | 87 |
| `/api/v1/mitre/coverage` | 16, 87 |
| `/api/v1/nat/nptv6` | 21, 50 |
| `/api/v1/nat/nptv6/{id}` | 21, 50 |
| `/api/v1/nat/rules` | 16, 21 |
| `/api/v1/nat/status` | 16, 21 |
| `/api/v1/netpol/replay` | No suite yet (kernel-network) |
| `/api/v1/processes` | 67 |
| `/api/v1/processes/{pid}` | 72 |
| `/api/v1/qos/classifiers` | 28 |
| `/api/v1/qos/classifiers/{id}` | 28 |
| `/api/v1/qos/pipes` | 28 |
| `/api/v1/qos/pipes/{id}` | 28 |
| `/api/v1/qos/queues` | 28 |
| `/api/v1/qos/queues/{id}` | 28 |
| `/api/v1/qos/shaping` | No suite yet (kernel-network) |
| `/api/v1/qos/status` | 28 |
| `/api/v1/ratelimit/rules` | 04, 14, 55 |
| `/api/v1/ratelimit/rules/{id}` | 04, 14, 55 |
| `/api/v1/responses` | 48 |
| `/api/v1/responses/manual` | 48 |
| `/api/v1/responses/{id}` | 48 |
| `/api/v1/routing/gateways` | 16, 32, 53 |
| `/api/v1/routing/gateways/{id}` | 32, 53 |
| `/api/v1/routing/routes` | 32 |
| `/api/v1/routing/status` | 16, 32, 53 |
| `/api/v1/services/graph` | 90 |
| `/api/v1/surface` | 80 |
| `/api/v1/surface/listening` | 80 |
| `/api/v1/surface/loaded` | 80 |
| `/api/v1/surface/packages` | 80 |
| `/api/v1/threatintel/feeds` | 04, 17, 33 |
| `/api/v1/threatintel/feeds/refresh` | 33 |
| `/api/v1/threatintel/iocs` | 04, 17, 33 |
| `/api/v1/threatintel/status` | 04, 17, 33 |
| `/api/v1/threatintel/urls` | 33 |
| `/api/v1/tls/handshakes` | 89 |
| `/api/v1/tls/posture` | 89 |
| `/api/v1/tls/status` | 58 |
| `/api/v1/trace` | 87 |
| `/api/v1/zones` | 31 |
| `/api/v1/zones/policies` | 31 |
| `/api/v1/zones/policies/{id}` | 31 |
| `/api/v1/zones/status` | 31 |
| `/api/v1/zones/{id}` | 31 |
| `/healthz` | 01, 02, 06, 07, 08, 09, 11, 17, 23, 26, 27, 38, 43, 52, 55, 56, 58, 60, 68, 91, 99 |
| `/metrics` | 02, 06, 10, 11, 12, 14, 17, 18, 19, 20, 21, 22, 23, 24, 27, 28, 29, 30, 31, 32, 33, 34, 38, 40, 52, 53, 54, 61, 62, 64, 65, 66, 67, 71 |
| `/readyz` | 01, 02, 06, 07, 23, 55, 56 |

<!-- coverage:end -->

## Performance Test Scripts

### Resource Matrix Benchmark (`benchmark-resource-matrix.sh`)

Measures **CPU%** and **RSS** for each eBPF feature under different traffic volumes. Designed to be run on two VM sizes to compare how CPU vs RAM impacts performance.

```bash
# Run on current VM (auto-detects profile: "4vCPU-4GB", "8vCPU-8GB", etc.)
./scripts/benchmark-resource-matrix.sh

# Run in 2VM mode
./scripts/benchmark-resource-matrix.sh --2vm

# Custom duration and profile name
./scripts/benchmark-resource-matrix.sh --2vm --duration 30 --profile "4vCPU-4GB"

# Merge two profiles into a comparison table
./scripts/benchmark-resource-matrix.sh --merge report-4vcpu.json report-8vcpu.json
```

**Features tested individually:** firewall, firewall+ids, firewall+ratelimit, firewall+threatintel, firewall+conntrack, all-features.

**Traffic volumes:** idle (0), 100 Mbps (UDP), 1 Gbps (UDP).

**Single profile output:**

| Feature | Traffic | CPU % | RSS (MB) |
|---------|---------|------:|---------:|
| no-agent | idle | 0.0% | 0.0 |
| firewall | idle | 0.3% | 24.5 |
| firewall | 100mbps | 1.2% | 25.1 |
| firewall | 1gbps | 4.8% | 26.0 |
| all-features | 1gbps | 12.3% | 38.2 |

**Merged comparison output (two VM profiles):**

| Feature | Traffic | CPU % (4vCPU-4GB) | RSS MB (4vCPU-4GB) | CPU % (8vCPU-8GB) | RSS MB (8vCPU-8GB) |
|---------|---------|-------------------|--------------------|-------------------|--------------------|
| firewall | 1gbps | 4.8% | 26.0 | 2.1% | 25.8 |
| all-features | 1gbps | 12.3% | 38.2 | 6.5% | 37.9 |

*(Values above are examples - run the benchmark to get real numbers.)*

**Makefile targets:**

```bash
make bench-resource-matrix          # Local mode
make bench-resource-matrix-2vm      # 2VM mode
make bench-resource-merge F1=report1.json F2=report2.json  # Merge
```

### Performance Test Scripts

Three complementary performance test scripts measure agent overhead at different levels of realism.

### Intra-VM Tests (`perf-test-docker.sh`)

```bash
sudo ./scripts/perf-test-docker.sh [--mode binary|docker] [--quick] [--soak]
```

Runs inside a single machine (or VM) using a **veth pair** in a network namespace. Traffic is memory-to-memory (~200 Gbps baseline), so this measures pure eBPF overhead with near-zero network latency.

**Phases:**

1. **Baseline** -- No agent, raw veth throughput
2. **Alert mode** -- Full agent stack observing traffic (no blocking)
3. **Block mode** -- Firewall actively blocking ports 9999/7777
4. **Domain isolation** -- Firewall-only and ratelimit-only overhead comparison
5. **API benchmarks** -- REST API latency under load (`hey`)
6. **Soak test** -- 10-minute sustained load with RSS leak detection (optional)

**Thresholds:** > 5 Gbps TCP, > 2 Gbps UDP, < 200 us ICMP, < 30% CPU, < 256 MB RSS

### Binary vs Docker Comparison (`perf-test-vagrant.sh`)

```bash
./scripts/perf-test-vagrant.sh [--quick] [--skip-provision]
```

Boots a Vagrant VM, runs `perf-test-docker.sh` twice (binary mode then Docker mode), and prints a side-by-side comparison table with overhead percentages.

### Host-to-VM Tests (`perf-test-host-to-vm.sh`)

```bash
./scripts/perf-test-host-to-vm.sh [--mode binary|docker|both] [--quick] [--soak]
```

The most realistic topology: traffic crosses a **VirtualBox host-only network** (192.168.56.0/24) from the host machine to the VM. Measures real cross-host overhead including NIC driver and hypervisor.

```
Host (192.168.56.1)                      Vagrant VM (192.168.56.10)
├── iperf3 -c 192.168.56.10 ──────────> iperf3 -s (port 5201)
├── hping3 -S 192.168.56.10 ──────────> agent XDP/TC on eth1
├── ping 192.168.56.10 ───────────────> agent
├── hey http://192.168.56.10:8080 ────> agent REST API
```

**Phases:** Baseline, Alert mode (with CPU/RSS from VM), Block mode (port verification), API benchmarks, Soak test (optional).

When `--mode both` (default), runs binary then Docker and prints a comparison table:

```
  Metric                          Binary          Docker          Overhead
  ------------------------------  --------------  --------------  ----------
  TCP throughput                  6621.94 Mbps    6459.38 Mbps    +2.5%
  UDP throughput                  7414.11 Mbps    6493.14 Mbps    +12.4%
  ICMP latency                    0.462 ms        0.436 ms        -5.6%
  RSS                             42300 KB        29940 KB        -29.2%
  API p99                         1.20 ms         1.70 ms         +41.7%
```

**Thresholds:** > 500 Mbps TCP, > 200 Mbps UDP, < 5 ms ICMP, < 256 MB RSS, < 100 ms API p99

**Reports:** JSON files at `/tmp/ebpfsentinel-host-perf-{mode}-TIMESTAMP.json`

**Requirements (host):** `vagrant`, `iperf3`, `ping`, `curl`, `jq`. Optional: `hping3` (sudo, for PPS/TCP latency), `hey` (API benchmarks).

## Config Fixtures

All fixtures use `__PLACEHOLDER__` tokens substituted at runtime:

| Placeholder            | Substituted with                                                |
| ---------------------- | --------------------------------------------------------------- |
| `__INTERFACE__`        | Network interface name (e.g., `veth-ebpf0`, `eth1`)             |
| `__DATA_DIR__`         | Temporary data directory for audit/redb storage                 |
| `__EBPF_DIR__`         | eBPF program directory path                                     |
| `__WHITELIST_SUBNET__` | IPS whitelist CIDR (e.g., `10.200.0.0/24` or `192.168.56.0/24`) |

| Config                            | Use case                                                         |
| --------------------------------- | ---------------------------------------------------------------- |
| `config-minimal.yaml`             | Smoke tests -- firewall only on loopback                         |
| `config-full.yaml`                | Full feature integration -- all domains enabled                  |
| `config-invalid.yaml`             | Negative test -- malformed YAML (duplicate port)                 |
| `config-auth-jwt.yaml`            | JWT/OIDC authentication tests                                    |
| `config-tls.yaml`                 | TLS termination (port 8443)                                      |
| `config-docker-test.yaml`         | Docker smoke tests (loopback, minimal features)                  |
| `config-docker-perf.yaml`         | Docker overhead/stress tests (host networking)                   |
| `config-ebpf-firewall.yaml`       | Firewall scenario tests (block mode, CIDR rules)                 |
| `config-ebpf-ids.yaml`            | IDS scenario tests (alert mode, threshold detection)             |
| `config-ebpf-ips.yaml`            | IPS scenario tests (auto-blacklist, whitelist bypass)            |
| `config-ebpf-ratelimit.yaml`      | Rate limit tests (token bucket, per-rule rates)                  |
| `config-ebpf-threatintel.yaml`    | Threat intel scenario tests (IOC blocking, feeds)                |
| `config-ebpf-conntrack.yaml`      | Connection tracking tests (state tracking, flush)                |
| `config-ebpf-dns.yaml`            | DNS intelligence tests (cache, blocklist, reputation)            |
| `config-ebpf-loadbalancer.yaml`   | Load balancer tests (XDP service CRUD, backend selection)        |
| `config-ebpf-nat.yaml`            | NAT tests (SNAT/DNAT rules, conntrack co-dependency)             |
| `config-ebpf-ddos.yaml`           | DDoS/scrub tests (flood detection, policy enforcement)           |
| `config-ebpf-scrub.yaml`          | Packet scrub tests (fragmentation, metrics)                      |
| `config-ebpf-alert-e2e.yaml`      | Alert end-to-end pipeline tests                                  |
| `config-ebpf-hot-reload.yaml`     | Hot-reload tests (SIGHUP with rule changes)                      |
| `config-ebpf-dlp.yaml`            | DLP scenario tests (pattern matching, mode)                      |
| `config-ebpf-benchmark.yaml`      | eBPF map operation benchmark config                              |
| `config-perf-alert.yaml`          | Performance -- all domains, alert mode (observe only)            |
| `config-perf-block.yaml`          | Performance -- all domains, block mode (ports 9999/7777 denied)  |
| `config-perf-firewall-only.yaml`  | Perf isolation -- firewall domain only                           |
| `config-perf-ratelimit-only.yaml` | Perf isolation -- ratelimit domain only                          |
| `docker-compose-test.yml`         | Docker smoke test compose (loopback, BTF mounts)                 |
| `docker-compose-perf.yml`         | Docker overhead test compose (host networking, privileged)       |

## Attacker Toolkit

The attacker VM (192.168.56.20) is provisioned with a complete L3-L7
attack and load-generation toolkit so suites can run reproducibly
without per-suite installs.

| Tool | Purpose |
|---|---|
| `pktgen` (kmod) | >1 Mpps L4 floods (loaded via `/etc/modules-load.d/pktgen.conf`) |
| `MHDDoS` (`/opt/MHDDoS/.venv`) | L7 multi-method: GET/POST/STRESS/BYPASS/SLOW/TLS/UDP/SYN |
| `slowhttptest` | Slowloris / RUDY / slowread |
| `scapy` (`/opt/scapy-venv`) | Custom packet crafting, amplification simulation |
| `nping` | Fine-grained packet crafting (from `nmap`) |
| `t50` | Multi-protocol stress |
| `hyenae-ng` | L2 attack crafting |
| `wrk`, `vegeta`, `k6` | HTTP load generators with different profiles |
| `dnsperf` | DNS load |
| `mitmproxy` (`/opt/mitmproxy-venv`) | TLS MITM (enterprise DLP MITM suite) |
| `hydra`, `ncrack` | SSH / HTTP brute-force |
| `nuclei` | Template-based attack/scan patterns |
| `dnscrypt-proxy`, `cloudflared` | DoH / DoT clients (DNS detection suite) |

Pinned versions live in
[`vagrant/provision/TOOL_VERSIONS.md`](vagrant/provision/TOOL_VERSIONS.md).
MHDDoS is vendored as a git submodule at
[`vendor/MHDDoS`](vendor/) (GPL-3.0, runtime fork only - see
[`vendor/README.md`](vendor/README.md)).

```bash
# Verify the toolkit on a running attacker VM
vagrant ssh attacker -c \
    'bash /home/vagrant/ebpfsentinel/tests/integration/vagrant/provision/attacker_tools_check.sh'

# Initialize the MHDDoS submodule on a fresh checkout (host side)
git submodule update --init --depth 1 --recursive \
    tests/integration/vendor/MHDDoS
```

The provisioner runs `attacker_tools_check.sh` at the tail of
`setup-attacker.sh`; a failed check aborts the VM boot so a broken
toolkit cannot quietly mask a test failure.

## 2-VM Topology (Recommended)

The recommended way to run eBPF integration tests. Uses two VMs connected over a VirtualBox private network -- no root permissions needed on the developer machine.

```
Developer Machine (host)
│
├── make test-2vm          # Orchestrates everything
│
└── VirtualBox Private Network (192.168.56.0/24)
    │
    ├── Agent VM (192.168.56.10)          Attacker VM (192.168.56.20)
    │   ├── ebpfsentinel-agent            ├── bats test runner
    │   ├── eBPF programs (XDP/TC)        ├── hping3, ncat, iperf3
    │   ├── iperf3 server (:5201)         ├── SSH access to agent VM
    │   ├── Docker (for comparison)       └── grpcurl, curl, jq
    │   └── 4 CPU / 4 GB RAM                 2 CPU / 2 GB RAM
```

### Quick Start (2-VM)

```bash
# First time: boot both VMs and run all suites
make test-2vm

# Run only eBPF scenario suites (11-14, 18-24)
make test-2vm-ebpf

# Run a single suite
make test-2vm-suite SUITE=11

# Build Docker image on host and push to agent VM
make docker-push-agent

# Build without cache and push
make docker-push-agent-nocache

# Push existing image only (skip build)
make docker-push-agent-only

# Binary vs Docker performance comparison
make test-2vm-perf-comparison

# Quick perf comparison (~10 min)
make test-2vm-perf-comparison-quick

# SSH into VMs for manual debugging
make vagrant-ssh-agent
make vagrant-ssh-attacker
```

### How It Works

1. `vagrant up` provisions both VMs from a single Vagrantfile
2. The **agent VM** installs the agent binary, generates TLS certs/JWT keys, starts iperf3
3. The **attacker VM** generates an SSH key and copies it to the agent VM via `sshpass`
4. Tests run on the attacker VM with `EBPF_2VM_MODE=true`, which causes `ebpf_helpers.bash` to source `vm_helpers.bash`
5. `vm_helpers.bash` overrides `start_ebpf_agent` (SSH to agent VM), `create_test_netns` (no-op), and packet helpers (send directly over the network instead of through a netns)
6. Attack traffic goes to the agent's private address (192.168.56.10, `eth1`, where the datapath is attached), while SSH, scp and readings that must survive a blacklist go to its management address (`eth0`, `AGENT_CTL_IP`). The runners resolve that address from the Vagrant host, so a suite that gets the attacker blacklisted keeps its control session; without it the helpers fall back to the private address

### Docker Image Push

The `push-docker-image.sh` script builds the Docker image on the host machine and streams it to the agent VM via SSH, avoiding slow in-VM builds:

```bash
# Build + push (~8 min build, ~5s transfer)
bash scripts/push-docker-image.sh

# Build without Docker cache
bash scripts/push-docker-image.sh --no-cache

# Push existing image (skip build)
bash scripts/push-docker-image.sh --skip-build
```

Uses `docker save | gzip | ssh 'gunzip | docker load'` for efficient transfer.

### Performance Comparison

The `--perf-comparison` flag runs the performance benchmark twice on the agent VM: once with the native binary and once inside Docker. Results are saved to `/tmp/ebpfsentinel-2vm-perf-{binary,docker}.txt`.

## Legacy Single-VM

The single-VM setup is still available for simpler use cases.

```bash
make vagrant-up            # Create and provision VM
make vagrant-ssh           # SSH into VM
make vagrant-halt          # Stop VM
make vagrant-destroy       # Delete VM
```

**VM specs:** Ubuntu 24.04, 4 CPU, 4 GB RAM, VirtualBox (nested virt enabled).

**Provisioned software:** Rust (stable + nightly), Docker, Minikube, kubectl, BATS, grpcurl, iperf3, hping3, bpftool, ncat, stress-ng.

**Networks:**

- NAT (eth0) -- default Vagrant connectivity
- Host-only (eth1, 192.168.56.10) -- host-to-VM performance testing

**Port forwards:** 8080 (HTTP), 50051 (gRPC), 9090 (metrics), 8443 (TLS)

## Makefile Targets

### Test Execution

| Target                    | Description                  | Requirements         |
| ------------------------- | ---------------------------- | -------------------- |
| `test`                    | Run all suites locally       | agent binary         |
| `test-build-and-run`      | Build + run all suites       | Rust toolchain       |
| `test-vm`                 | Run all suites in Vagrant VM | Vagrant              |
| `test-suite SUITE=<name>` | Run a single suite           | agent binary         |
| `test-k8s`                | Kubernetes suite only        | Minikube             |
| `test-ebpf-scenarios`     | Suites 11-14, 18-24          | root, kernel >= 6.12 |
| `test-performance`        | Suite 15                     | root, kernel >= 6.12 |
| `test-ebpf-all`           | Suites 11-15                 | root, kernel >= 6.12 |
| `test-ebpf-vm`            | eBPF suites in Vagrant VM    | Vagrant              |

### 2-VM Topology

| Target                           | Description                             | Requirements |
| -------------------------------- | --------------------------------------- | ------------ |
| `test-2vm`                       | Run all suites via 2-VM topology        | Vagrant      |
| `test-2vm-suite SUITE=<num>`     | Run single suite in 2-VM mode           | Vagrant      |
| `test-2vm-ebpf`                  | eBPF scenario suites only               | Vagrant      |
| `test-2vm-perf`                  | Performance suites only                 | Vagrant      |
| `test-2vm-perf-comparison`       | Binary vs Docker perf comparison        | Vagrant      |
| `test-2vm-perf-comparison-quick` | Quick binary vs Docker comparison       | Vagrant      |
| `vagrant-2vm-up`                 | Start both VMs                          | Vagrant      |
| `vagrant-2vm-halt`               | Stop both VMs                           | Vagrant      |
| `vagrant-2vm-destroy`            | Destroy both VMs                        | Vagrant      |
| `vagrant-ssh-agent`              | SSH into agent VM                       | Vagrant      |
| `vagrant-ssh-attacker`           | SSH into attacker VM                    | Vagrant      |

### Docker Image

| Target                    | Description                                          | Requirements |
| ------------------------- | ---------------------------------------------------- | ------------ |
| `docker-push-agent`       | Build Docker image on host and push to agent VM      | Docker       |
| `docker-push-agent-nocache`| Build (no cache) and push Docker image to agent VM  | Docker       |
| `docker-push-agent-only`  | Push existing Docker image to agent VM (skip build)  | Docker       |

### Performance Tests

| Target                       | Description                              | Duration |
| ---------------------------- | ---------------------------------------- | -------- |
| `test-perf-docker`           | Full Docker perf test                    | ~15 min  |
| `test-perf-docker-quick`     | Quick Docker perf                        | ~3 min   |
| `test-perf-docker-soak`      | Docker soak test (leak detection)        | ~20 min  |
| `test-perf-vagrant`          | Binary vs Docker comparison in VM        | ~30 min  |
| `test-perf-vagrant-quick`    | Quick binary vs Docker                   | ~10 min  |
| `test-perf-host-to-vm`       | Host-to-VM over VirtualBox               | ~30 min  |
| `test-perf-host-to-vm-quick` | Quick host-to-VM                         | ~10 min  |

### Resource Matrix Benchmark

| Target                        | Description                                          | Duration |
| ----------------------------- | ---------------------------------------------------- | -------- |
| `bench-resource-matrix`       | CPU/RSS per feature x volume (local)                 | ~10 min  |
| `bench-resource-matrix-2vm`   | CPU/RSS per feature x volume (2VM)                   | ~10 min  |
| `bench-resource-merge F1= F2=`| Merge two profiles into comparison table             | instant  |

### Utilities

| Target  | Description                            |
| ------- | -------------------------------------- |
| `clean` | Remove temp files, stop running agents |
| `nuke`  | Destroy VM + clean all artifacts       |

## Design Patterns

- **Template substitution** -- Fixture configs use `__PLACEHOLDER__` tokens replaced by `prepare_ebpf_config()` at runtime, enabling the same config templates for veth, Docker, and VM topologies.
- **Skip guards** -- `require_root()`, `require_kernel()`, `require_tool()` functions skip tests gracefully on unsupported environments instead of failing. In 2-VM mode, `require_root` is bypassed since the agent runs remotely via SSH.
- **Triple launch strategy** -- eBPF tests try: (1) 2-VM mode via SSH when `EBPF_2VM_MODE=true`, (2) local binary, (3) `docker run --privileged` fallback.
- **Network isolation** -- Single-VM mode uses a veth pair in a network namespace (`10.200.0.0/24`). 2-VM mode uses the VirtualBox private network (`192.168.56.0/24`) for real cross-host testing.
- **JSON reports** -- Performance tests produce structured JSON reports (`/tmp/ebpfsentinel-*.json`) with metadata, per-phase measurements, threshold results, and a pass/fail verdict.
- **Exponential backoff** -- Agent readiness checks use `retry()` with configurable backoff (0.2s to 10s) to handle variable startup times.
- **Agent health gating** -- Benchmark tests use `_require_agent_alive()` (curl-based health check) to skip gracefully if the agent crashes mid-suite, avoiding cascading failures.
