# Integration Tests

End-to-end test suite for the eBPFsentinel agent. Covers agent lifecycle, REST/gRPC APIs, eBPF packet processing scenarios, performance benchmarks, Docker/Kubernetes deployments, and host-to-VM network testing.

## Directory Structure

```
tests/integration/
├── Makefile                            # Test orchestration (21 targets)
├── suites/                             # 15 BATS test suites (~116 tests)
│   ├── 01-agent-lifecycle.bats
│   ├── 02-rest-api-health.bats
│   ├── ...
│   └── 15-performance-benchmark.bats
├── lib/                                # Shared bash helper libraries
│   ├── helpers.bash                    # Core: agent start/stop, HTTP/gRPC wrappers
│   ├── assertions.bash                 # Custom BATS assertions
│   ├── constants.bash                  # Ports, paths, network constants
│   ├── retry.bash                      # Exponential backoff retry
│   ├── ebpf_helpers.bash               # Netns/veth, packet gen, eBPF guards
│   └── perf_helpers.bash               # iperf3/hping3/hey measurement functions
├── scripts/                            # Standalone utilities
│   ├── start-agent.sh                  # Launch agent in background
│   ├── stop-agent.sh                   # Graceful agent shutdown
│   ├── wait-for-agent.sh               # Poll /healthz
│   ├── wait-for-ready.sh               # Poll /readyz (eBPF loaded)
│   ├── generate-certs.sh               # Self-signed CA + server cert
│   ├── generate-jwt-keys.sh            # RSA keypair + test JWT tokens
│   ├── run-in-vm.sh                    # Main test runner (suite discovery)
│   ├── perf-test-docker.sh             # Intra-VM performance tests
│   ├── perf-test-vagrant.sh            # Binary vs Docker comparison (intra-VM)
│   ├── perf-test-host-to-vm.sh         # Host-to-VM perf over VirtualBox
│   └── vm-measure-resources.sh         # CPU/RSS sampling helper (runs in VM)
├── fixtures/                           # Config templates + test data
│   ├── config-minimal.yaml
│   ├── config-full.yaml
│   ├── config-docker-test.yaml         # Docker integration test config
│   ├── config-ebpf-*.yaml              # eBPF scenario configs
│   ├── config-perf-*.yaml              # Performance test configs
│   ├── docker-compose-test.yml         # Docker integration test compose
│   ├── health.proto                    # gRPC health check proto
│   └── k8s/                            # Kubernetes manifests (DaemonSet)
└── vagrant/                            # VM-based test environment
    ├── Vagrantfile                     # VirtualBox/VMware VM definition
    └── provision/
        ├── setup.sh                    # Build agent, install certs/eBPF
        └── teardown.sh                 # Cleanup
```

## Quick Start

```bash
# Run all suites locally (agent binary must be pre-built)
make test

# Run a single suite
make test-suite SUITE=01-agent-lifecycle

# Run eBPF scenario tests (requires root + kernel >= 5.17)
make test-ebpf-scenarios

# Quick performance test
make test-perf-docker-quick

# Host-to-VM performance test over VirtualBox private network
make test-perf-host-to-vm-quick
```

## Test Suites

### Functional Tests (suites 01-10)

Run without root. Require the agent binary built (`cargo build --release`).

| Suite                    | Tests | What it covers                                                                                                                                                                   |
| ------------------------ | ----: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **01-agent-lifecycle**   |     7 | Startup, graceful shutdown, SIGHUP reload, invalid config rejection, PID file management                                                                                         |
| **02-rest-api-health**   |     6 | `/healthz`, `/readyz`, `/metrics` (Prometheus), system metrics (CPU/memory/uptime)                                                                                               |
| **03-rest-api-firewall** |     8 | Firewall rule CRUD via REST: create, read, update, delete, priority ordering, bulk operations                                                                                    |
| **04-rest-api-domains**  |    23 | Domain-specific REST APIs: IDS rules, IPS blacklist, rate limit config, threat intel feeds, alerting routes, L7 inspection, DLP patterns, DNS cache/blocklist, domain reputation |
| **05-grpc-streaming**    |     4 | gRPC health check, server reflection, event streaming subscription                                                                                                               |
| **06-ebpf-programs**     |     3 | eBPF program loading and attachment to a veth interface (requires kernel >= 5.17)                                                                                                |
| **07-authentication**    |    11 | JWT RS256 validation, OIDC JWKS endpoint, API key auth, role-based access control (admin/operator/viewer), token expiry, composite auth                                          |
| **08-tls**               |     5 | HTTPS termination on port 18443, gRPC over TLS, self-signed certificate validation, mTLS                                                                                         |
| **09-docker**            |     4 | Docker image build, `docker compose` deployment with health checks, healthz via agent CLI (requires kernel BTF)                                                                  |
| **10-kubernetes**        |     5 | Minikube DaemonSet deployment, ConfigMap injection, RBAC, pod health (VM-only)                                                                                                   |

### eBPF Scenario Tests (suites 11-14)

Require **root** and **kernel >= 5.17**. Use isolated network namespaces with veth pairs (10.200.0.0/24) to test real eBPF packet processing.

| Suite                           | Tests | What it covers                                                                                                                                    |
| ------------------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **11-ebpf-firewall-scenarios**  |     9 | Packet matching: source/dest CIDR, port ranges, protocol filters, priority-based rule ordering, default policy (pass/deny), IPv6, VLAN tagging    |
| **12-ebpf-ids-scenarios**       |     6 | Intrusion detection: reverse shell detection (port 4444), SSH brute-force threshold alerts, alert deduplication, REST alert notification pipeline |
| **13-ebpf-ips-scenarios**       |     6 | Intrusion prevention: auto-blacklist after threshold, dynamic rule injection, whitelist bypass for trusted subnets, blacklist expiry, TTL         |
| **14-ebpf-ratelimit-scenarios** |     5 | Token bucket rate limiting: per-rule rate enforcement, ICMP/TCP/UDP rate control, burst handling, global vs per-source tracking                   |

### Performance Benchmark (suite 15)

Requires **root**. Measures agent overhead on a veth pair using iperf3, hping3, and `/proc` sampling.

| Suite                        | Tests | What it covers                                                                                                                   |
| ---------------------------- | ----: | -------------------------------------------------------------------------------------------------------------------------------- |
| **15-performance-benchmark** |     9 | TCP/UDP throughput, ICMP latency, TCP SYN latency, packets-per-second, CPU/RSS overhead, eBPF map memory, JSON report generation |

## Performance Test Scripts

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
├── hey http://192.168.56.10:18080 ───> agent REST API
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

| Config                            | Use case                                                        |
| --------------------------------- | --------------------------------------------------------------- |
| `config-minimal.yaml`             | Smoke tests -- firewall only on loopback                        |
| `config-full.yaml`                | Full feature integration -- all domains enabled                 |
| `config-invalid.yaml`             | Negative test -- malformed YAML                                 |
| `config-auth-jwt.yaml`            | JWT/OIDC authentication tests                                   |
| `config-tls.yaml`                 | TLS termination (port 18443)                                    |
| `config-docker-test.yaml`         | Docker integration tests (loopback, minimal features)           |
| `config-ebpf-benchmark.yaml`      | eBPF benchmark configuration                                    |
| `config-ebpf-firewall.yaml`       | Firewall scenario tests (block mode, CIDR rules)                |
| `config-ebpf-ids.yaml`            | IDS scenario tests (alert mode, threshold detection)            |
| `config-ebpf-ips.yaml`            | IPS scenario tests (auto-blacklist, whitelist bypass)           |
| `config-ebpf-ratelimit.yaml`      | Rate limit tests (token bucket, per-rule rates)                 |
| `config-perf-alert.yaml`          | Performance -- all domains, alert mode (observe only)           |
| `config-perf-block.yaml`          | Performance -- all domains, block mode (ports 9999/7777 denied) |
| `config-perf-firewall-only.yaml`  | Perf isolation -- firewall domain only                          |
| `config-perf-ratelimit-only.yaml` | Perf isolation -- ratelimit domain only                         |
| `docker-compose-test.yml`         | Docker integration test compose (loopback, BTF mounts)          |

## Vagrant VM

The test VM provides a reproducible environment with all dependencies pre-installed.

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

**Port forwards:** 18080 (HTTP), 50151 (gRPC), 19090 (metrics), 18443 (TLS)

## Makefile Targets

### Test Execution

| Target                    | Description                  | Requirements         |
| ------------------------- | ---------------------------- | -------------------- |
| `test`                    | Run all suites locally       | agent binary         |
| `test-build-and-run`      | Build + run all suites       | Rust toolchain       |
| `test-vm`                 | Run all suites in Vagrant VM | Vagrant              |
| `test-suite SUITE=<name>` | Run a single suite           | agent binary         |
| `test-k8s`                | Kubernetes suite only        | Minikube             |
| `test-ebpf-scenarios`     | Suites 11-14                 | root, kernel >= 5.17 |
| `test-performance`        | Suite 15                     | root, kernel >= 5.17 |
| `test-ebpf-all`           | Suites 11-15                 | root, kernel >= 5.17 |
| `test-ebpf-vm`            | eBPF suites in Vagrant VM    | Vagrant              |

### Performance Tests

| Target                       | Description                       | Duration |
| ---------------------------- | --------------------------------- | -------- |
| `test-perf-docker`           | Full Docker perf test             | ~15 min  |
| `test-perf-docker-quick`     | Quick Docker perf                 | ~3 min   |
| `test-perf-docker-soak`      | Docker soak test (leak detection) | ~20 min  |
| `test-perf-vagrant`          | Binary vs Docker comparison in VM | ~30 min  |
| `test-perf-vagrant-quick`    | Quick binary vs Docker            | ~10 min  |
| `test-perf-host-to-vm`       | Host-to-VM over VirtualBox        | ~30 min  |
| `test-perf-host-to-vm-quick` | Quick host-to-VM                  | ~10 min  |

### Utilities

| Target                 | Description                            |
| ---------------------- | -------------------------------------- |
| `prepare-docker-image` | Save Docker image tar for VM injection |
| `clean`                | Remove temp files, stop running agents |
| `nuke`                 | Destroy VM + clean all artifacts       |

## Design Patterns

- **Template substitution** -- Fixture configs use `__PLACEHOLDER__` tokens replaced by `prepare_ebpf_config()` at runtime, enabling the same config templates for veth, Docker, and VM topologies.
- **Skip guards** -- `require_root()`, `require_kernel()`, `require_tool()` functions skip tests gracefully on unsupported environments instead of failing.
- **Dual launch strategy** -- eBPF tests try a local binary first, then fall back to `docker run --privileged` if no local build is available.
- **Network isolation** -- eBPF scenario tests (11-15) create a dedicated network namespace with a veth pair (`10.200.0.0/24`), preventing interference with the host network.
- **JSON reports** -- Performance tests produce structured JSON reports (`/tmp/ebpfsentinel-*.json`) with metadata, per-phase measurements, threshold results, and a pass/fail verdict.
- **Exponential backoff** -- Agent readiness checks use `retry()` with configurable backoff (0.2s to 10s) to handle variable startup times.
