# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Versioning follows **CalVer**: `YYYY.M.RELEASE` (year, month without leading zero, release index within that month). Tags use the `v` prefix: `v2026.3.1`.

## [2026.3.2] - 2026-03-28

### Added

#### Agent Architecture
- **API-only mode**: agent runs without eBPF privileges for development, testing, and management-plane-only deployments
- **Agent runtime as reusable library**: extracted startup/reload/shutdown modules, `load_ebpf_programs()`, state providers/consumers as pub API for enterprise extension
- **Hot-reload eBPF lifecycle**: `EbpfProgramManager` with per-program loading/unloading, `CancellationToken` readers, XDP chain rewiring, dynamic metrics
- **Configurable XDP attach mode**: auto/native/generic/offloaded with smart fallback and startup logging
- **Parallel event dispatch**: per-source worker partitioning, parallel alert sender dispatch, parallel threat intel feed fetches

#### Detection & Response
- **MITRE ATT&CK v18 mapping**: technique registry wired into all alerts, REST API/gRPC/CLI filtering by tactic/technique, coverage endpoint and dashboard
- **JA4+ TLS fingerprinting**: ClientHello parser → JA4/JA4S/JA4H hash computation → flow cache → alert enrichment → REST API + gRPC + CLI + Prometheus metrics
- **Post-quantum TLS**: X25519MLKEM768 hybrid key exchange for server TLS, PQ `CryptoProvider` at startup for all outbound clients, public API for enterprise mTLS
- **OTLP Logs export**: fire-and-forget via official opentelemetry-rust gRPC/HTTP client
- **Manual response actions**: time-bounded block/throttle via CLI/API with TTL auto-expiry and audit trail
- **Manual packet capture**: on-demand PCAP via CLI/API, duration-limited, libpcap format
- **Auto-capture**: event-triggered PCAP on high-severity alerts
- **Auto-response**: automated TTL-bounded actions on detection events
- **DoH/DoT detection**: encrypted DNS detection with built-in resolver domain list, custom resolvers, metrics
- **DNS over TCP**: capture on port 53 alongside existing UDP support
- **STIX 2.1 feed parsing**: multi-engine distribution to threat intel, DNS blocklist, domain reputation, L7 firewall
- **Contextual MITRE mapping**: per-destination-port technique selection for IDS, threat intel, firewall, ratelimit, L7, IPS alerts
- **Alert pipeline integration**: firewall, ratelimit, L7, IPS, DNS blocklist, reputation, and encrypted DNS events routed through the unified alert system

#### eBPF Datapath
- **QoS EDT pacing enforced**: `bpf_skb_set_tstamp` in eBPF datapath (previously metrics-only)
- **BPF MTU guard**: `bpf_check_mtu` in xdp-firewall and xdp-ratelimit with `mtu_exceeded` metric
- **XDP load balancer integration**: tail-call chain with standalone fallback, shared asm/checksum patterns
- **XDP firewall reject**: tail-called `xdp-firewall-reject` program for TCP RST / ICMP unreachable
- **XDP SYN cookie refactor**: extracted as tail-called `xdp-ratelimit-syncookie` with shared helpers
- **TC socket cookie**: wired in TC programs for flow correlation
- **IDS packet mirroring**: `bpf_clone_redirect` support
- **Conntrack lazy timeout eviction**: DevMap/CpuMap infrastructure, SYN cookie helpers
- **Per-CPU LRU**: coarse timestamps, ECN marking, SKB linearization, MTU check
- **Tenant-aware eBPF**: `tenant_id` field on all entry structs, VLAN/subnet LPM resolution, `tenant_matches()` helper, `TenantRateLimitBucket`, `TenantVlanMapManager`
- **BPF compiler barrier**: fix verifier packet pointer tracking after `bpf_xdp_adjust_tail`
- **Shared `emit_packet_event!` macro**: deduplicated across tc-ids/threatintel/qos/nat-ingress/nat-egress with NPTv6 helpers

#### CLI
- **`watch`**: real-time alert streaming
- **`investigate`**: deep inspection of IPs, flows, and connections
- **`alerts stats`**: alert statistics and trends
- **`risk-score`**: network risk score computation
- **`top-talkers`**: top sources/destinations by volume
- **`network-flows`**: active flow listing
- **Enhanced `status`**: expanded health and operational metrics

#### Kubernetes & Deployment
- **Production Helm chart**: JSON schema validation, ServiceAccount, NOTES.txt, full values reference
- **PrometheusRule**: 8 alerting rules for agent health and detection
- **Fine-grained capabilities**: replace privileged mode in docker-compose and systemd
- **Configurable `securityContext`**, PodDisruptionBudget, container resource limits, optional NetworkPolicy
- **CAP_NET_RAW**: added to systemd service, captures directory at `/var/lib/ebpfsentinel/captures`

#### Security Hardening
- **gRPC API key auth**: `x-api-key` header support; gRPC reflection now opt-in
- **Token revocation**: constant-time API key lookup with revocation list
- **SSRF protection**: webhook URLs, feed URLs, alert destinations validated against private/loopback/multicast with header injection prevention
- **Input validation**: BPF filter length limits, interface/namespace name validation, DLP regex validation at config time, JSON nesting depth and YAML size limits
- **TLS hardening**: default TLS 1.3 only (opt-in 1.2), minimum 2048-bit RSA for JWT, restricted key paths
- **API rate limiting**: auth-specific rate limits, metrics endpoint rate-limited regardless of auth config
- **CORS hardening**: exact host validation (fixes origin bypass), restricted to localhost or explicit origins
- **HTTP security headers**: standard headers on all responses
- **Salted API key hashes**: `/dev/urandom` for cryptographically secure salt generation
- **Startup hardening**: restrictive umask, privilege check, strict config file permissions (640), minimum kernel 6.6

#### CI/CD & Quality
- **Miri + cargo-careful CI jobs**: `deny(unsafe_op_in_unsafe_fn)` in ebpf-common
- **32 property-based tests (proptest)**: DNS, STIX, CIDR, L7 parsers
- **Realistic benchmark scripts**: SYN/UDP/ICMP flood, IDS payload scenarios, rule-count impact with 2-VM delta method
- **DLP TLS tests**: real traffic validation of all OSS regex patterns (PCI/PII/credentials)
- **Integration test suite expansion**: new suites, API schema validation, timing fixes
- **Fuzz testing CI job**: critical parsers in security workflow
- **Helm lint CI job**
- **CI composite actions**: deduplicated workflows, removed redundant audit job
- **Least-privilege CI/CD permissions**: all workflows hardened
- **Per-worker Prometheus metrics**: parallel event dispatch observability

### Fixed

- **CORS origin bypass** (P0): prefix match replaced with exact host validation
- **eBPF verifier failures**: tc-conntrack, tc-nat, uprobe-dlp, xdp-firewall, xdp-ratelimit compatibility fixes
- **DLP auto-detect SSL library**: OpenSSL/BoringSSL path detection for uprobe attachment
- **JA4 pipeline**: end-to-end wiring — compute in L7 events, cache, enrich alerts, real cache in API
- **OTLP config**: wired tests, DoH/DoT metrics, custom resolvers
- **tc-dns SKB linearization**: jumbo frame support via `bpf_skb_pull_data`
- **tc-ids `ctx.len()`**: use instead of linear buffer size for `bpf_skb_pull_data`
- **Kernel memory leak padding**: ESP/AH IPv6 parsing, IHL validation, ICMP conntrack
- **`take_map` consuming ProgramArray**: on repeated eBPF wiring
- **JWKS fetch logic**: composite auth provider no longer leaks internal error details
- **Token revocation not enforced**: revocation list wired into authentication chain
- **Namespace access default-deny**: absent `namespaces` JWT claim now denies access
- **DNS compression pointer off-by-one**: hop limit boundary corrected
- **Firewall stale fast-path**: HashMaps flushed on rule reload
- **RwLock poison handling**: logged and handled instead of silently recovering
- **LB ifindex path traversal**: interface name validated in load balancer resolver
- **DLP uprobe memory leak**: `LruHashMap` for bounded memory, `saturating_sub` for safe arithmetic
- **Bearer token parsing**: malformed tokens rejected early
- **SHA validation**: corrected binary integrity version check
- **Async alert pipeline**: `std::sync::Mutex` → `tokio::sync::Mutex` in async senders
- **Docker distroless**: `COPY` from builder stage instead of `RUN mkdir`
- **Docker kernel headers**: symlink Linux headers into musl include path for libpcap build
- **API latency test**: was measuring timeout duration instead of actual latency
- **OpenAPI spec**: added QoS endpoints, SecurityScheme, 401/403 responses on all protected paths
- **Unused `asm_experimental_arch`**: removed from eBPF programs that don't use inline assembly
- **Benchmark methodology**: 2-VM delta method with 3-run averaging, 5Gbps cap, 500Mbps volume baseline

### Changed

- Agent runtime extracted as library with pub startup/reload/shutdown API
- Fingerprint cache migrated to interior mutability (eliminated last RwLock from hot path)
- `AlertDestination::Otlp` simplified to unit variant (endpoint lives in `OtlpExportConfig`)
- Config file permissions enforced to 640 across all environments
- JWT validation leeway explicitly set to zero
- SMTP TLS disabled now emits a warning
- gRPC timeouts configured, eBPF crash cleanup on shutdown
- eBPF Rust 2024 edition: `unsafe` blocks added, unused imports removed, `transmute` replaced
- Config examples updated with PQ mode, OTLP export, DoH resolver settings
- QUICKSTART.md added alongside Helm chart

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
