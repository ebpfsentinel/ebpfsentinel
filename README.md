# eBPFsentinel

High-performance network security agent powered by eBPF. Monitors, filters, and protects network traffic at wire speed with near-zero overhead. Written entirely in Rust.

## What it does

eBPFsentinel combines a stateful firewall, intrusion detection, rate limiting, and threat intelligence into a single agent that runs directly in the Linux kernel via eBPF — no kernel modules, no packet copies to userspace.
on
### Network Security

- **Stateful Firewall** — L3/L4 packet filtering with conntrack, CIDR matching, IP set aliases, security zones, VLAN filtering, schedule-based rules, and IPv4/IPv6 dual-stack
- **NAT** — SNAT, DNAT, masquerade, port forwarding, 1:1 NAT with full packet rewriting
- **Rate Limiting** — Per-IP protection with 5 algorithms (token bucket, fixed window, sliding window, leaky bucket, SYN cookie)
- **DDoS Mitigation** — Detects and mitigates SYN flood, UDP amplification, ICMP/RST/FIN/ACK flood, and volumetric attacks
- **L7 Firewall** — Application-layer filtering for HTTP, TLS/SNI, gRPC, SMTP, FTP, and SMB
- **Packet Scrubbing** — Kernel-side traffic normalization (TTL, MSS clamping, DF clearing, IP ID randomization)
- **Multi-WAN Routing** — Policy-based gateway selection with ICMP/TCP health checks and failover

### Threat Detection & Prevention

- **IDS/IPS** — Intrusion detection and prevention with pattern matching, sampling, and threshold detection
- **Threat Intelligence** — OSINT feed integration with IOC correlation and auto-blocking
- **DLP** — Data loss prevention scanning SSL/TLS traffic for sensitive data patterns (PCI, PII, credentials)
- **DNS Intelligence** — Passive DNS capture, domain blocklists, behavioral reputation scoring, and DNS-based alert enrichment

### Operations

- **REST API** with OpenAPI 3.0 and Swagger UI
- **gRPC Streaming** for real-time alert subscriptions
- **Prometheus Metrics** with per-domain counters, histograms, kernel-side eBPF counters, and system-level tracking
- **Alert Pipeline** with routing to email, webhook, and log sinks
- **Audit Trail** with rule change history
- **Hot Reload** — update configuration without restart (file watcher, SIGHUP, or API)
- **CLI** with 10 domain subcommands covering all endpoints
- **JWT/OIDC/API Key Authentication** with role-based access control
- **TLS 1.3** for REST and gRPC

## Quick start

**Requirements:** Linux kernel 5.17+ with BTF, Rust stable + nightly

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
  ebpfsentinel
```

Minimal configuration — only the interface is required:

```yaml
agent:
  interfaces: [eth0]
```

See the [Getting Started guide](../docs/getting-started/quickstart.md) for detailed setup instructions.

## Documentation

Full documentation is available in the [`docs/`](../docs/) directory:

| Section | Description |
| ------- | ----------- |
| [Getting Started](../docs/getting-started/quickstart.md) | Installation, prerequisites, first run |
| [Features](../docs/features/overview.md) | Detailed feature guides (firewall, IDS, DLP, ...) |
| [Configuration](../docs/configuration/overview.md) | YAML reference for all sections |
| [Architecture](../docs/architecture/overview.md) | Hexagonal/DDD design, eBPF pipeline, data flow |
| [Kernel Reference](../docs/kernel/overview.md) | eBPF programs, maps, helpers, pipeline |
| [REST API](../docs/api-reference/rest-api.md) | All endpoints with request/response formats |
| [gRPC API](../docs/api-reference/grpc-api.md) | Alert streaming service |
| [CLI Reference](../docs/cli-reference/index.md) | All commands and options |
| [Prometheus Metrics](../docs/api-reference/prometheus-metrics.md) | Metric names and labels |
| [Deployment](../docs/operations/deployment/docker.md) | Docker, Kubernetes, binary |
| [Security](../docs/architecture/security-model.md) | TLS, auth, hardening |
| [Development](../docs/development/building.md) | Building, testing, contributing |
| [Examples](../docs/examples/index.md) | Real-world deployment scenarios |

Per-feature configuration examples are in [`config/examples/`](config/examples/).

## Compatibility

- **OS:** Linux only (kernel 5.17+ with BTF)
- **Distros:** Debian 12+, Ubuntu 22.04+, RHEL 9+, Fedora 37+, Alpine 3.18+, Arch, NixOS, Talos
- **Arch:** x86_64 (primary), aarch64 (cross-tested)
- **Runtime:** Docker, Podman, Kubernetes (DaemonSet), Nomad

See [Compatibility](../docs/operations/compatibility.md) for the full matrix.

## License

GNU Affero General Public License v3.0 — see [LICENSE](../LICENSE).
