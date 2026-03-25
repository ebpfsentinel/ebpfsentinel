# ebpfsentinel

eBPF-native Network Detection & Response (NDR) platform for Linux

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.0-dev](https://img.shields.io/badge/AppVersion-0.0.0--dev-informational?style=flat-square)

## Overview

Deploys [eBPFsentinel](https://github.com/ebpfsentinel/ebpfsentinel) — a kernel-native **Network Detection & Response (NDR)** platform — as a Kubernetes DaemonSet. One privileged agent per node, attached to host network interfaces via eBPF (XDP/TC).

## Edition: OSS (AGPL-3.0)

This chart deploys the **open-source edition**. All 14 security domains are included:

| Domain | Default |
|--------|---------|
| Stateful Firewall (L3/L4) | enabled |
| IDS/IPS | enabled |
| DLP (SSL/TLS uprobe) | enabled |
| Rate Limiting | enabled |
| Threat Intelligence | enabled |
| DNS Intelligence | enabled |
| L7 Firewall | disabled |
| DDoS Mitigation | disabled |
| NAT / NPTv6 | disabled |
| QoS / Traffic Shaping | disabled |
| L4 Load Balancer | disabled |
| Connection Tracking | disabled |
| Policy Routing | disabled |
| Security Zones | disabled |

### OSS Limitations

- **Auto-response**: max 3 policies (unlimited in Enterprise)
- **PCAP capture**: manual only, 60s max, 1 concurrent (Enterprise adds event-triggered, ring buffer, multi-capture)
- **No HA clustering**: single agent per node, no state replication (Enterprise adds active-passive HA)
- **No multi-agent per node**: one DaemonSet only (Enterprise supports multi-tenant node sharing)
- **No SIEM connectors**: use OTLP export or webhook sinks (Enterprise adds Splunk, Elastic, QRadar, S3, etc.)
- **No ML anomaly detection**: rule-based detection only (Enterprise adds ONNX-based streaming ML)
- **No compliance reporting**: use Prometheus + Grafana (Enterprise generates PCI-DSS, NIS2, DORA reports)

See [OSS vs Enterprise](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/features/enterprise/overview.md) for the full comparison.

## Kubernetes Deployment Constraints

### Required Privileges

| Requirement | Reason |
|-------------|--------|
| `hostNetwork: true` | XDP/TC programs attach to host interfaces, not pod veth |
| `privileged: true` | eBPF program loading requires `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` |
| `/sys/fs/bpf` mount | BPF filesystem for map pinning |
| `/sys/kernel/debug` mount | eBPF tracing (debugfs) |
| Kernel 6.6+ with BTF | CO-RE eBPF requires BTF type information |

### Feature Limitations in Kubernetes

| Feature | DaemonSet | Notes |
|---------|-----------|-------|
| Firewall, IDS, DDoS, Rate Limiting | Full | Attached to host NIC — sees all node traffic |
| DLP | Partial | Only sees pod processes unless `hostPID: true` |
| Multi-WAN Routing | Full\* | `hostNetwork` shares host routing table. \*Test with Calico BGP — see CNI note below |
| Sidecar mode | Not recommended | XDP works on veth (generic mode) but only sees the pod's own traffic — no host or cross-pod visibility |

**DLP full coverage** requires `hostPID: true` in the DaemonSet spec:

```yaml
daemonset:
  hostPID: true
```

This grants the uprobe visibility into all node processes using `libssl.so.3`. Without it, DLP only inspects TLS traffic from processes inside the agent pod.

### CNI Compatibility

eBPFsentinel attaches to the **host physical interface** (e.g., `eth0`), not to the CNI bridge or veth pairs. This means:

- It does **not** interfere with pod-to-pod (east-west) traffic managed by the CNI
- It **only** sees north-south traffic entering/leaving the node
- Compatible with: Calico, Flannel, Cilium, Weave, any CNI
- Firewall rules apply to the host interface — they affect all pods on the node equally

For per-pod network policy, use your CNI's native policy engine (e.g., Cilium NetworkPolicy). eBPFsentinel complements CNI by adding NDR capabilities (IDS, DLP, threat intel, DDoS) at the node boundary.

## Quick Start

```bash
helm repo add ebpfsentinel https://charts.ebpfsentinel.io
helm repo update

helm install ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}'
```

Verify:

```bash
kubectl -n ebpfsentinel get pods -o wide
kubectl -n ebpfsentinel logs -l app.kubernetes.io/name=ebpfsentinel --tail=20
```

## Examples

### Minimal (firewall + IDS only)

```bash
helm install ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}'
```

### Full NDR with Prometheus monitoring

```bash
helm install ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{ens192}' \
  --set ddos.enabled=true \
  --set l7.enabled=true \
  --set conntrack.enabled=true \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.labels.release=kube-prometheus-stack
```

### DLP with full node visibility

```bash
helm install ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}' \
  --set daemonset.hostPID=true \
  --set dlp.enabled=true
```

### Custom config (bypass values.yaml)

```bash
helm install ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --create-namespace \
  --set-file configOverride=my-config.yaml
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `image.repository` | string | `ghcr.io/ebpfsentinel/ebpfsentinel` | Container image repository |
| `image.tag` | string | `""` | Image tag (defaults to Chart appVersion) |
| `image.pullPolicy` | string | `IfNotPresent` | Image pull policy |
| `imagePullSecrets` | list | `[]` | Registry pull secrets |
| `agent.interfaces` | list | `[eth0]` | **REQUIRED** — host NICs to attach eBPF programs |
| `agent.bindAddress` | string | `0.0.0.0` | Listen address for HTTP/gRPC/metrics |
| `agent.httpPort` | int | `8080` | REST API port |
| `agent.grpcPort` | int | `50051` | gRPC streaming port |
| `agent.metricsPort` | int | `9090` | Prometheus metrics port |
| `agent.logLevel` | string | `info` | Log level (trace, debug, info, warn, error) |
| `agent.logFormat` | string | `json` | Log format (json, text) |
| `agent.swaggerUi` | bool | `false` | Enable Swagger UI at `/swagger-ui` |
| `agent.xdpMode` | string | `auto` | XDP attach mode (auto, native, generic, offloaded) |
| `agent.eventWorkers` | int | `4` | Parallel event dispatch workers |
| `daemonset.hostPID` | bool | `false` | Enable hostPID for full DLP uprobe coverage |
| `daemonset.resources.requests.memory` | string | `128Mi` | Memory request |
| `daemonset.resources.requests.cpu` | string | `100m` | CPU request |
| `daemonset.resources.limits.memory` | string | `512Mi` | Memory limit |
| `daemonset.resources.limits.cpu` | string | `1000m` | CPU limit |
| `daemonset.nodeSelector` | object | `{}` | Node selector |
| `daemonset.tolerations` | list | `[{operator: Exists}]` | Tolerations (default: all nodes) |
| `daemonset.affinity` | object | `{}` | Affinity rules |
| `daemonset.extraVolumeMounts` | list | `[]` | Additional volume mounts |
| `daemonset.extraVolumes` | list | `[]` | Additional volumes |
| `daemonset.extraEnv` | list | `[]` | Additional environment variables |
| `daemonset.podAnnotations` | object | `{}` | Extra pod annotations |
| `firewall.enabled` | bool | `true` | Stateful L3/L4 firewall |
| `ids.enabled` | bool | `true` | Intrusion Detection System |
| `ips.enabled` | bool | `true` | Intrusion Prevention (auto-blacklist) |
| `dlp.enabled` | bool | `true` | Data Loss Prevention (SSL/TLS uprobe) |
| `ratelimit.enabled` | bool | `true` | Rate limiting (4 algorithms) |
| `threatintel.enabled` | bool | `true` | Threat intelligence (OSINT feeds) |
| `dns.enabled` | bool | `true` | DNS intelligence + blocklists |
| `alerting.enabled` | bool | `false` | Alert routing (email, webhook, OTLP) |
| `audit.enabled` | bool | `false` | Audit trail |
| `auth.enabled` | bool | `false` | JWT/OIDC/API key authentication |
| `conntrack.enabled` | bool | `false` | Connection tracking |
| `ddos.enabled` | bool | `false` | DDoS mitigation (SYN cookie, flood detection) |
| `l7.enabled` | bool | `false` | L7 protocol filtering (HTTP, TLS/SNI, gRPC) |
| `nat.enabled` | bool | `false` | NAT / NPTv6 |
| `routing.enabled` | bool | `false` | Multi-WAN policy routing |
| `loadbalancer.enabled` | bool | `false` | L4 load balancer |
| `geoip.enabled` | bool | `false` | GeoIP enrichment (MaxMind) |
| `zones.enabled` | bool | `false` | Security zones |
| `qos.enabled` | bool | `false` | QoS / traffic shaping |
| `metrics.serviceMonitor.enabled` | bool | `false` | Create Prometheus ServiceMonitor |
| `metrics.serviceMonitor.interval` | string | `15s` | Scrape interval |
| `metrics.serviceMonitor.labels` | object | `{}` | Extra ServiceMonitor labels |
| `configOverride` | string | `""` | Full config.yaml override (ignores all above) |

## Upgrading

```bash
helm upgrade ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --reuse-values
```

Config changes trigger a rolling restart automatically (config checksum annotation on pods).

## Uninstalling

```bash
helm uninstall ebpfsentinel --namespace ebpfsentinel
kubectl delete namespace ebpfsentinel
```

> **Note**: Uninstalling removes the DaemonSet and ConfigMap but does not unpin BPF maps from `/sys/fs/bpf`. These are cleaned up automatically when the last program reference is dropped.

## Maintainers

| Name | URL |
|------|-----|
| ebpfsentinel | <https://github.com/ebpfsentinel> |
