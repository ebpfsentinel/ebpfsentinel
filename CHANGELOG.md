# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versioning follows **CalVer**: `YYYY.M.RELEASE` (year, month without leading zero, release index within that month). Tags use the `v` prefix: `v2026.3.1`.

## [2026.3.1] - 2026-03-15

### Added

- Full Rust eBPF network security agent with 12 kernel programs (XDP + TC + uprobe)
- Stateful firewall with L3/L4 filtering, conntrack, CIDR/GeoIP, IPv4/IPv6, VLAN, schedule rules, IP sets
- NAT: SNAT, DNAT, masquerade, port forwarding, 1:1 NAT, NPTv6 (RFC 6296), hairpin NAT
- IDS/IPS with pattern matching, auto IP blacklisting, /24 subnet blocking
- DLP: SSL/TLS content scanning for PCI, PII, credentials
- Rate limiting: 4 algorithms (token bucket, fixed/sliding window, leaky bucket) + SYN cookies + per-country tiers
- DDoS mitigation: SYN/UDP/ICMP/volumetric flood detection, automatic country CIDR blocking
- Threat intelligence: source-agnostic feed integration with bloom filter + LRU hash IOC correlation
- DNS intelligence: passive capture, domain blocklists, behavioral reputation scoring
- L7 firewall: HTTP, TLS/SNI, gRPC, SMTP, FTP, SMB with GeoIP matching
- Packet scrubbing: TTL, MSS clamping, DF clearing, IP ID randomization, TCP flag scrubbing
- Multi-WAN routing with health checks and failover
- L4 load balancer: TCP/UDP/TLS passthrough with 4 algorithms, up to 4096 services / 256 backends per service
- Traffic shaping / QoS: dummynet-inspired pipes, WF2Q+ queues, 5-tuple classifiers, FQ-CoDel
- REST API with OpenAPI 3.0 and Swagger UI (52 endpoints)
- gRPC streaming for real-time alert subscriptions
- Prometheus metrics with per-domain counters and eBPF kernel-side tracking
- Alert pipeline with circuit breaker, dedup, email/webhook/log routing
- CLI with 13 domain subcommands, table/JSON output
- JWT (RS256) + OIDC (JWKS) + API key authentication with RBAC
- TLS 1.3 for REST and gRPC
- Hot reload via file watcher, SIGHUP, or API
- Security zones with per-interface policies
- Interface groups for rule scoping
- Multi-level HashMap fast-path for firewall (O(1) 5-tuple + port lookup) and NAT rules
- Consolidated ratelimit bucket union (4 maps to 1, 75% memory reduction)
- Two-level LB HashMap architecture (services 64 to 4096, backends/svc 16 to 256)
- Map pinning for shared CT_TABLE and INTERFACE_GROUPS (~49MB memory savings)
- Tiered RingBuf events: L7 (192B/576B), DLP (280B/4120B) — 67-94% savings
- User RingBuf infrastructure for atomic config push (eBPF side ready, userspace pending aya API)
- 24 fuzz targets covering all domain engines and parsers
- Docker multi-arch image (distroless/static)
- 7 CI workflows (format, lint, test, audit, eBPF build, integration, security)

### Known Limitations

- QoS EDT (Earliest Departure Time) pacing: delay is tracked in metrics but not enforced in the eBPF datapath (awaiting aya-ebpf `bpf_skb_set_tstamp` API)
- User RingBuf config push: eBPF drain callback is wired, but userspace write requires mmap-based access not yet available in aya 0.13.1
- gRPC is alerts-only (streaming); all CRUD/management operations use REST API
