# Integration Tests

End-to-end test suite for the eBPFsentinel agent. Covers agent lifecycle, REST/gRPC APIs (all domains), eBPF packet processing scenarios, performance benchmarks, Docker/Kubernetes deployments, and host-to-VM network testing.

## Directory Structure

```
tests/integration/
├── Makefile                            # Test orchestration (30+ targets)
├── suites/                             # BATS test suites (01-30)
│   ├── 01-agent-lifecycle.bats
│   ├── 02-rest-api-health.bats
│   ├── ...
│   └── 30-ebpf-map-operation-bench.bats
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

# Run eBPF scenario tests (requires root + kernel >= 6.1)
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
| **06-ebpf-programs**     |     3 | eBPF program loading and attachment to a veth interface (requires kernel >= 6.1)                                                                                                |
| **07-authentication**    |    11 | JWT RS256 validation, OIDC JWKS endpoint, API key auth, role-based access control (admin/operator/viewer), token expiry, composite auth                                          |
| **08-tls**               |     5 | HTTPS termination on port 8443, gRPC over TLS, self-signed certificate validation, mTLS                                                                                         |
| **09-docker**            |    11 | Docker image build, compose deployment, healthz, baseline/Docker TCP throughput, ICMP latency, RSS/CPU overhead, API latency under load, memory stability, clean shutdown         |
| **10-kubernetes**        |     5 | Minikube DaemonSet deployment, ConfigMap injection, RBAC, pod health (VM-only)                                                                                                   |
| **16-rest-api-ddos**     |     9 | DDoS protection: status, attacks, history, policy CRUD, validation (invalid type, zero threshold, nonexistent delete)                                                            |
| **17-rest-api-extended** |    26 | Extended domains: IDS, DLP, conntrack, NAT, routing, aliases, LB (CRUD + validation), operations (config, eBPF status, reload), IPS domain-blocks                               |

### eBPF Scenario Tests (suites 11-14, 18-24)

Require **root** and **kernel >= 6.1**. Use isolated network namespaces with veth pairs (10.200.0.0/24) to test real eBPF packet processing. In 2-VM mode, root is not required locally.

| Suite                              | Tests | What it covers                                                                                                                                    |
| ---------------------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **11-ebpf-firewall-scenarios**     |     9 | Packet matching: source/dest CIDR, port ranges, protocol filters, priority-based rule ordering, default policy (pass/deny), IPv6, VLAN tagging    |
| **12-ebpf-ids-scenarios**          |     6 | Intrusion detection: reverse shell detection (port 4444), SSH brute-force threshold alerts, alert deduplication, REST alert notification pipeline |
| **13-ebpf-ips-scenarios**          |     6 | Intrusion prevention: auto-blacklist after threshold, dynamic rule injection, whitelist bypass for trusted subnets, blacklist expiry, TTL         |
| **14-ebpf-ratelimit-scenarios**    |     5 | Token bucket rate limiting: per-rule rate enforcement, ICMP/TCP/UDP rate control, burst handling, global vs per-source tracking                   |
| **18-ebpf-threatintel-scenarios**  |     5 | Threat intel: TC program attachment, status/feeds/IOC API access, metrics counters                                                                |
| **19-ebpf-conntrack-scenarios**    |     6 | Connection tracking: TC program attachment, connection table population, connection count, flush, metrics                                         |
| **20-ebpf-dns-scenarios**          |     6 | DNS intelligence: TC program attachment, cache/stats/blocklist API, cache flush, UDP:53 packet observation                                       |
| **21-ebpf-loadbalancer-scenarios** |     7 | Load balancer: XDP program attachment, service CRUD with eBPF map sync, backend detail, service deletion, metrics                                |
| **22-ebpf-nat-scenarios**          |     5 | NAT: TC ingress/egress program attachment, status/rules API, conntrack co-dependency, metrics                                                    |
| **23-ebpf-ddos-scenarios**         |     8 | DDoS/scrub: TC scrub program attachment, policy loading, ICMP/SYN flood detection, attack history, metrics                                       |
| **24-ebpf-scrub-scenarios**        |     5 | Packet scrub: program attachment, metrics increment, fragmented packet handling, API access                                                      |

### End-to-End & Advanced Tests (suites 25-28)

Require **root** and **kernel >= 6.1** (or 2-VM mode).

| Suite                          | Tests | What it covers                                                                                                |
| ------------------------------ | ----: | ------------------------------------------------------------------------------------------------------------- |
| **25-packet-accountability**   |     6 | Firewall packet counters: total_seen increments, total_seen >= passed + dropped, UDP/TCP delta accuracy       |
| **26-alert-end-to-end**        |     7 | Alert pipeline: IDS alert generation, REST query, source/destination fields, count increment, false positive   |
| **27-hot-reload-rules**        |     4 | Config hot-reload: initial rule count, SIGHUP adds rules, invalid config rollback, agent stays healthy        |
| **28-ebpf-dlp-scenarios**      |     5 | DLP: program attachment, configuration API, metrics, pattern loading, mode verification                       |

### Performance & Benchmark Suites (suites 15, 29-30)

Require **root** and **kernel >= 6.1** (or 2-VM mode). Measure agent overhead using iperf3, hping3, and `/proc` sampling.

| Suite                          | Tests | What it covers                                                                                                   |
| ------------------------------ | ----: | ---------------------------------------------------------------------------------------------------------------- |
| **15-performance-benchmark**   |     9 | TCP/UDP throughput, ICMP latency, TCP SYN latency, packets-per-second, CPU/RSS overhead, JSON report generation  |
| **29-ebpf-feature-overhead**   |     8 | Per-feature overhead: baseline, then cumulative (firewall, +IDS, +ratelimit, +threatintel, +all), NFR2 threshold |
| **30-ebpf-map-operation-bench**|    12 | Bulk API latency: firewall rules (100/1K/10K), threatintel IOCs, ratelimit policies, LB backends, DNS blocklist  |

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

*(Values above are examples — run the benchmark to get real numbers.)*

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
| `test-ebpf-scenarios`     | Suites 11-14, 18-24          | root, kernel >= 6.1 |
| `test-performance`        | Suite 15                     | root, kernel >= 6.1 |
| `test-ebpf-all`           | Suites 11-15                 | root, kernel >= 6.1 |
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
