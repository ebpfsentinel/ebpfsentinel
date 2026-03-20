# eBPFsentinel

High-performance network security agent powered by eBPF. Monitors, filters, and protects network traffic at wire speed with near-zero overhead. Written entirely in Rust.

## What it does

> **One agent. All layers.** Replaces iptables + Suricata + tc + ipset + fail2ban
> with a single Rust binary that enforces security at kernel speed (XDP/TC).
> No sidecar, no kernel module, no C code.

### Network Security & Control

| Feature | What it does |
|---------|-------------|
| **DDoS Mitigation** | XDP-speed SYN cookie validation, UDP/ICMP/TCP flood detection, volumetric attack mitigation, per-country thresholds, automatic CIDR blocking — drops attacks before they reach the TCP stack |
| **Stateful Firewall** | L3/L4 kernel-side filtering with connection tracking, GeoIP blocking, security zones, VLAN/QinQ support, schedule-based rules, full IPv4/IPv6 dual-stack |
| **L7 Filtering** | Protocol-aware rules for HTTP, TLS/SNI, gRPC, SMTP, FTP, SMB with GeoIP source/destination matching |
| **L4 Load Balancer** | TCP/UDP/TLS passthrough with round-robin, weighted, IP hash, and least-connections algorithms |
| **Traffic Shaping** | Bandwidth limits, delay/loss simulation, weighted fair queuing, per-flow token buckets, EDT pacing, FQ-CoDel AQM |
| **Rate Limiting** | Four algorithms (token bucket, fixed window, sliding window, leaky bucket), kernel-side per-country tiers |
| **NAT** | SNAT, DNAT, masquerade, port forwarding, 1:1 NAT, NPTv6 prefix translation, hairpin NAT |
| **Traffic Normalization** | TTL normalization, MSS clamping, TCP flag/timestamp scrubbing, IP ID randomization, DF/ECN/DSCP rewriting |
| **Policy Routing** | Multi-gateway selection with ICMP/TCP health checks, automatic failover, geographic preference |

### Threat Detection & Response

| Feature | What it does |
|---------|-------------|
| **IDS / IPS** | Kernel-side pattern matching with automatic blocking — detects and blocks, not just alerts |
| **Threat Intelligence** | Plug any OSINT feed (CSV, JSON, plaintext, STIX 2.1) — real-time IOC matching, auto-blocking, no vendor lock-in |
| **DLP** | Inspects TLS traffic for PCI card numbers, PII, and credential patterns via uprobe interception |
| **DNS Security** | Passive DNS capture, domain blocklists, behavioral reputation scoring, DNS-enriched alerts |
| **MITRE ATT&CK Mapping** | Every alert tagged with tactic + technique ID — ready for SOC dashboards and SIEM correlation |
| **GeoIP Enforcement** | MaxMind-backed country resolution shared across all engines: DDoS auto-block, IPS subnet injection, rate-limit tiers, L7 filtering |

### Operations

- **REST API** with OpenAPI 3.0, Swagger UI, and SecurityScheme
- **gRPC Streaming** for real-time alert subscriptions with severity, component, and MITRE ATT&CK filters
- **Prometheus Metrics** with per-domain counters, histograms, kernel-side eBPF counters, and system-level tracking
- **Alert Pipeline** with routing to email, webhook, and log sinks
- **Audit Trail** with rule change history
- **Hot Reload** — update configuration without restart (file watcher, SIGHUP, or API)
- **CLI** with 13 domain subcommands covering all endpoints (firewall, ids, ratelimit, qos, threatintel, dlp, dns, nat, nptv6, scrub, lb, conntrack, audit)
- **JWT/OIDC/API Key Authentication** with role-based access control (Admin, Operator, Viewer)
- **TLS 1.3** for REST and gRPC (rustls + aws_lc_rs)

## Architecture

```mermaid
flowchart TB
    subgraph kernel["Linux Kernel"]
        direction LR
        subgraph xdp["XDP (L3)"]
            fw[xdp-firewall]
            rl[xdp-ratelimit]
            lb[xdp-loadbalancer]
        end
        subgraph tc["TC (L4/L7)"]
            ids[tc-ids]
            ti[tc-threatintel]
            dns[tc-dns]
            ct[tc-conntrack]
            qos[tc-qos]
            scrub[tc-scrub]
            nat_i[tc-nat-ingress]
            nat_e[tc-nat-egress]
        end
        uprobe[uprobe-dlp]
    end

    packets(("Packets")) --> xdp
    packets --> tc

    subgraph agent["Userspace Agent (Rust)"]
        direction LR
        subgraph domain["Domain Engines"]
            de["Pure business logic\n(zero deps)"]
        end
        subgraph app["Application Services"]
            as["Use cases\n& orchestration"]
        end
        subgraph adapters["Adapters"]
            ebpf_a["eBPF maps\n& events"]
            http["REST API\n(Axum)"]
            grpc["gRPC\n(tonic)"]
            store["Storage\n(redb)"]
        end
    end

    xdp -- "RingBuf / Maps" --> ebpf_a
    tc -- "RingBuf / Maps" --> ebpf_a
    uprobe -- "RingBuf" --> ebpf_a

    ebpf_a --> as
    as --> de
    http --> as
    grpc --> as
    store --> as

    cli(("CLI")) --> http
    swagger(("Swagger UI")) --> http
    prom(("Prometheus")) --> http
    alerts(("Alert clients")) --> grpc
```

## Quick start

**Requirements:** Linux kernel 6.1+ with BTF, Rust stable + nightly

```bash
# Build
cargo build --release
cargo xtask ebpf-build

# Run
sudo ./target/release/ebpfsentinel-agent --config config/ebpfsentinel.yaml
```

Or with Docker:

```bash
docker run --privileged --network host \
  -v ./config:/etc/ebpfsentinel \
  ghcr.io/ebpfsentinel/ebpfsentinel:latest
```

Minimal configuration — only the interface is required:

```yaml
agent:
  interfaces: [eth0]
```

See the [Getting Started guide](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/getting-started/quickstart.md) for detailed setup instructions.

## Documentation

Full documentation is available at [ebpfsentinel/ebpfsentinel-docs](https://github.com/ebpfsentinel/ebpfsentinel-docs):

| Section | Description |
| ------- | ----------- |
| [Getting Started](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/getting-started/quickstart.md) | Installation, prerequisites, first run |
| [Features](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/features/overview.md) | Detailed feature guides (firewall, IDS, DLP, ...) |
| [Configuration](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/configuration/overview.md) | YAML reference for all sections |
| [Architecture](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/architecture/overview.md) | Hexagonal/DDD design, eBPF pipeline, data flow |
| [Kernel Reference](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/kernel/overview.md) | eBPF programs, maps, helpers, pipeline |
| [REST API](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/api-reference/rest-api.md) | All endpoints with request/response formats |
| [gRPC API](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/api-reference/grpc-api.md) | Alert streaming service |
| [CLI Reference](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/cli-reference/index.md) | All commands and options |
| [Prometheus Metrics](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/api-reference/prometheus-metrics.md) | Metric names and labels |
| [Deployment](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/operations/deployment/docker.md) | Docker, Kubernetes, binary |
| [Security](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/architecture/security-model.md) | TLS, auth, hardening |
| [Development](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/development/building.md) | Building, testing, contributing |
| [Examples](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/examples/index.md) | Real-world deployment scenarios |

Per-feature configuration examples are in [`config/examples/`](config/examples/).

## Compatibility

- **OS:** Linux only (kernel 6.1+ with BTF)
- **Distros:** Debian 12+, Ubuntu 24.04+ (or 22.04 HWE), RHEL 9.4+, Fedora 37+, Alpine 3.18+, Arch, NixOS, Talos
- **Arch:** x86_64 (primary), aarch64 (cross-tested)
- **Runtime:** Docker, Podman, Kubernetes (DaemonSet), Nomad

See [Compatibility](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/operations/compatibility.md) for the full matrix.

## OSS vs Enterprise

The open-source agent includes all security domains, APIs, CLI, authentication, and observability. An enterprise version adds ML anomaly detection, multi-tenancy, DLP, SIEM integration, compliance reporting, HA clustering, multi-cluster federation, RBAC, air-gap support, analytics dashboards, and AI/LLM security. See [Enterprise Features](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/features/enterprise/overview.md) for details.

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).
