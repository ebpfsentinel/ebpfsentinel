# eBPFsentinel

High-performance network security agent powered by eBPF. Monitors, filters, and protects network traffic at wire speed with near-zero overhead. Written entirely in Rust.

## What it does

eBPFsentinel combines a stateful firewall, intrusion detection, rate limiting, and threat intelligence into a single agent that runs directly in the Linux kernel via eBPF — no kernel modules, no packet copies to userspace.

### Network Security

- **Stateful Firewall** — L3/L4 packet filtering with conntrack, CIDR matching, IP set aliases, GeoIP country blocking (LPM Trie), security zones, VLAN filtering, schedule-based rules, and IPv4/IPv6 dual-stack
- **NAT** — SNAT, DNAT, masquerade, port forwarding, 1:1 NAT with full packet rewriting (IPv4/IPv6)
- **Rate Limiting** — Per-IP protection with 5 algorithms (token bucket, fixed window, sliding window, leaky bucket, SYN cookie) and per-country tiers via kernel-side LPM Trie lookup
- **DDoS Mitigation** — Detects and mitigates SYN flood, UDP amplification, ICMP/RST/FIN/ACK flood, and volumetric attacks with per-country detection thresholds and automatic country CIDR blocking via LPM maps
- **L7 Firewall** — Application-layer filtering for HTTP, TLS/SNI, gRPC, SMTP, FTP, and SMB with GeoIP-based source/destination country matching
- **Packet Scrubbing** — Kernel-side traffic normalization (TTL, MSS clamping, DF clearing, IP ID randomization)
- **Multi-WAN Routing** — Policy-based gateway selection with ICMP/TCP health checks, failover, and geographic gateway preference (preferred_for_countries)
- **L4 Load Balancer** — TCP/UDP/TLS passthrough load balancing with round-robin, weighted, IP hash, and least-connections algorithms

### Threat Detection & Prevention

- **IDS/IPS** — Intrusion detection and prevention with pattern matching, country-aware sampling, per-country detection thresholds, and automatic /24 subnet blocking for high-risk countries via LPM maps
- **Threat Intelligence** — OSINT feed integration with IOC correlation, auto-blocking, and confidence boost for high-risk source countries
- **GeoIP Blocking** — Country-based traffic blocking via MaxMind databases with O(log n) kernel-side LPM Trie lookup, automatic periodic refresh, and cross-domain enforcement (DDoS auto-block, IPS /24 injection, rate limit country tiers) via coordinated LPM maps
- **DLP** — Data loss prevention scanning SSL/TLS traffic for sensitive data patterns (PCI, PII, credentials)
- **DNS Intelligence** — Passive DNS capture, domain blocklists, behavioral reputation scoring with high-risk country factors, and DNS-based alert enrichment

### Operations

- **REST API** with OpenAPI 3.0 and Swagger UI
- **gRPC Streaming** for real-time alert subscriptions
- **Prometheus Metrics** with per-domain counters, histograms, kernel-side eBPF counters, and system-level tracking
- **Alert Pipeline** with routing to email, webhook, and log sinks
- **Audit Trail** with rule change history
- **Hot Reload** — update configuration without restart (file watcher, SIGHUP, or API)
- **CLI** with 11 domain subcommands covering all endpoints
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

- **OS:** Linux only (kernel 5.17+ with BTF)
- **Distros:** Debian 12+, Ubuntu 22.04+, RHEL 9+, Fedora 37+, Alpine 3.18+, Arch, NixOS, Talos
- **Arch:** x86_64 (primary), aarch64 (cross-tested)
- **Runtime:** Docker, Podman, Kubernetes (DaemonSet), Nomad

See [Compatibility](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/operations/compatibility.md) for the full matrix.

## License

GNU Affero General Public License v3.0 — see [LICENSE](../LICENSE).
