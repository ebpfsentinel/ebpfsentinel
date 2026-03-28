# ebpfsentinel

eBPF-native Network Detection & Response (NDR) platform for Linux

## Overview

Deploys [eBPFsentinel](https://github.com/ebpfsentinel/ebpfsentinel) — a kernel-native **Network Detection & Response (NDR)** platform — as a Kubernetes DaemonSet. One agent per node with fine-grained capabilities (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_NET_RAW`), attached to host network interfaces via eBPF (XDP/TC).

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
| `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_SYS_ADMIN` + `CAP_NET_RAW` | eBPF program loading and network access (default). Fallback: `privileged: true` for kernels without `CAP_BPF` |
| `/sys/fs/bpf` mount | BPF filesystem for map pinning |
| `/sys/kernel/debug` mount | eBPF tracing (debugfs) |
| Kernel 6.6+ with BTF | CO-RE eBPF requires BTF type information (TCX link-based TC attach) |

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

### TLS with post-quantum key exchange

```bash
helm install ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}' \
  --set agent.tls.enabled=true \
  --set agent.tls.certPath=/etc/ebpfsentinel/tls/tls.crt \
  --set agent.tls.keyPath=/etc/ebpfsentinel/tls/tls.key \
  --set agent.tls.pqMode=prefer \
  --set 'daemonset.extraVolumes[0].name=tls-certs' \
  --set 'daemonset.extraVolumes[0].secret.secretName=ebpfsentinel-tls' \
  --set 'daemonset.extraVolumeMounts[0].name=tls-certs' \
  --set 'daemonset.extraVolumeMounts[0].mountPath=/etc/ebpfsentinel/tls' \
  --set 'daemonset.extraVolumeMounts[0].readOnly=true'
```

### Auto-response and auto-capture

```bash
helm install ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}' \
  --set auto_response.enabled=true \
  --set auto_capture.enabled=true \
  --set-file configOverride=my-response-config.yaml
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
| agent | object | `{"bindAddress":"0.0.0.0","eventWorkers":4,"grpcPort":50051,"grpcReflection":false,"httpPort":8080,"interfaces":["eth0"],"logFormat":"json","logLevel":"info","metricsPort":9090,"swaggerUi":false,"tls":{"allowTls12":false,"certPath":"","enabled":false,"keyPath":"","pqMode":"prefer"},"xdpMode":"auto"}` | Agent configuration (generates config.yaml) |
| agent.bindAddress | string | `"0.0.0.0"` | Listen address for HTTP/gRPC/metrics |
| agent.eventWorkers | int | `4` | Parallel event dispatch workers |
| agent.grpcPort | int | `50051` | gRPC streaming port |
| agent.grpcReflection | bool | `false` | Enable gRPC reflection (disabled by default for security) |
| agent.httpPort | int | `8080` | REST API port |
| agent.interfaces | list | `["eth0"]` | Network interfaces to attach eBPF programs to (REQUIRED) |
| agent.logFormat | string | `"json"` | Log format (json, text) |
| agent.logLevel | string | `"info"` | Log level (trace, debug, info, warn, error) |
| agent.metricsPort | int | `9090` | Prometheus metrics port |
| agent.swaggerUi | bool | `false` | Enable Swagger UI at /swagger-ui |
| agent.tls | object | `{"allowTls12":false,"certPath":"","enabled":false,"keyPath":"","pqMode":"prefer"}` | TLS configuration for HTTP and gRPC listeners |
| agent.tls.allowTls12 | bool | `false` | Allow TLS 1.2 (default: TLS 1.3 only) |
| agent.tls.certPath | string | `""` | Path to PEM-encoded server certificate (mount via extraVolumeMounts) |
| agent.tls.enabled | bool | `false` | Enable TLS termination |
| agent.tls.keyPath | string | `""` | Path to PEM-encoded private key |
| agent.tls.pqMode | string | `"prefer"` | Post-quantum key exchange: prefer, require, or disable |
| agent.xdpMode | string | `"auto"` | XDP attach mode (auto, native, generic, offloaded) |
| alerting.enabled | bool | `false` | Enable alert routing (email, webhook, OTLP) |
| aliases | object | `{}` | Named IP/port aliases for rule scoping |
| audit.enabled | bool | `false` | Enable audit trail |
| auth.enabled | bool | `false` | Enable JWT/OIDC/API key authentication |
| auto_capture | object | `{"enabled":false}` | Auto-capture: start PCAP on high-severity alert (max 60s in OSS) |
| auto_response | object | `{"enabled":false}` | Auto-response: automatic block/throttle on high-severity alerts (max 3 policies in OSS) |
| commonAnnotations | object | `{}` | Annotations added to all resources |
| commonLabels | object | `{}` | Labels added to all resources |
| configOverride | string | `""` | Override the entire config.yaml content. When set, all agent.* and domain toggles above are ignored. |
| conntrack.enabled | bool | `false` | Enable connection tracking |
| daemonset | object | `{"affinity":{},"extraContainers":[],"extraEnv":[],"extraVolumeMounts":[],"extraVolumes":[],"hostPID":false,"initContainers":[],"minReadySeconds":0,"nodeSelector":{},"podAnnotations":{},"podLabels":{},"priorityClassName":"","resources":{"limits":{"cpu":"1000m","memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}},"revisionHistoryLimit":10,"securityContext":{"capabilities":{"add":["BPF","NET_ADMIN","SYS_ADMIN","NET_RAW","PERFMON"],"drop":["ALL"]}},"terminationGracePeriodSeconds":30,"tolerations":[{"operator":"Exists"}],"updateStrategy":{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}}` | DaemonSet configuration |
| daemonset.affinity | object | `{}` | Affinity rules |
| daemonset.extraContainers | list | `[]` | Extra containers (sidecars) |
| daemonset.extraEnv | list | `[]` | Extra environment variables |
| daemonset.extraVolumeMounts | list | `[]` | Extra volume mounts (e.g., GeoIP database, TLS certs) |
| daemonset.extraVolumes | list | `[]` | Extra volumes |
| daemonset.hostPID | bool | `false` | Enable hostPID for full DLP uprobe coverage on all node processes |
| daemonset.initContainers | list | `[]` | Init containers |
| daemonset.minReadySeconds | int | `0` | Minimum seconds a pod must be ready before considered available |
| daemonset.nodeSelector | object | `{}` | Node selector |
| daemonset.podAnnotations | object | `{}` | Extra annotations on DaemonSet pods |
| daemonset.podLabels | object | `{}` | Extra labels on DaemonSet pods |
| daemonset.priorityClassName | string | `""` | Pod priority class name |
| daemonset.resources | object | `{"limits":{"cpu":"1000m","memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | Resource requests and limits |
| daemonset.revisionHistoryLimit | int | `10` | Number of old ReplicaSets to retain |
| daemonset.securityContext | object | `{"capabilities":{"add":["BPF","NET_ADMIN","SYS_ADMIN","NET_RAW","PERFMON"],"drop":["ALL"]}}` | Container security context (fine-grained capabilities by default) |
| daemonset.terminationGracePeriodSeconds | int | `30` | Grace period for pod termination (seconds) |
| daemonset.tolerations | list | `[{"operator":"Exists"}]` | Tolerations (default: schedule on all nodes including control-plane) |
| daemonset.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | DaemonSet update strategy |
| ddos.enabled | bool | `false` | Enable DDoS mitigation (SYN cookie, flood detection) |
| dlp.enabled | bool | `true` | Enable Data Loss Prevention (SSL/TLS uprobe) |
| dns.enabled | bool | `true` | Enable DNS intelligence + blocklists |
| firewall | object | `{"enabled":true}` | Security domain toggles (maps to config.yaml sections) |
| firewall.enabled | bool | `true` | Enable stateful L3/L4 firewall |
| fullnameOverride | string | `""` | Override the full resource name (disables auto-generated name) |
| geoip.enabled | bool | `false` | Enable GeoIP enrichment (MaxMind) |
| ids.enabled | bool | `true` | Enable Intrusion Detection System |
| image | object | `{"pullPolicy":"IfNotPresent","repository":"ghcr.io/ebpfsentinel/ebpfsentinel","tag":""}` | Container image |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.repository | string | `"ghcr.io/ebpfsentinel/ebpfsentinel"` | Image repository |
| image.tag | string | `""` | Image tag (defaults to Chart appVersion) |
| imagePullSecrets | list | `[]` | Image pull secrets for private registries |
| interface_groups | object | `{}` | Interface groups for multi-interface rule scoping (max 31 groups) |
| ips.enabled | bool | `true` | Enable Intrusion Prevention (auto-blacklist) |
| l7.enabled | bool | `false` | Enable L7 protocol filtering (HTTP, TLS/SNI, gRPC) |
| loadbalancer.enabled | bool | `false` | Enable L4 load balancer |
| metrics | object | `{"prometheusRule":{"enabled":false,"labels":{},"rules":[]},"serviceMonitor":{"enabled":false,"interval":"15s","labels":{}}}` | Prometheus metrics |
| metrics.prometheusRule.enabled | bool | `false` | Create a PrometheusRule with built-in alerting rules |
| metrics.prometheusRule.labels | object | `{}` | Extra labels on the PrometheusRule |
| metrics.prometheusRule.rules | list | `[]` | Override the default rules (when empty, built-in rules are used) |
| metrics.serviceMonitor.enabled | bool | `false` | Create a Prometheus ServiceMonitor |
| metrics.serviceMonitor.interval | string | `"15s"` | Scrape interval |
| metrics.serviceMonitor.labels | object | `{}` | Extra labels on the ServiceMonitor (e.g., release: kube-prometheus-stack) |
| nameOverride | string | `""` | Override the chart name used in resource names |
| nat.enabled | bool | `false` | Enable NAT / NPTv6 |
| networkPolicy | object | `{"enabled":false,"extraEgress":[],"extraIngress":[]}` | Network policy (restricts pod-to-pod traffic) |
| networkPolicy.enabled | bool | `false` | Create a NetworkPolicy |
| networkPolicy.extraEgress | list | `[]` | Extra egress rules (added to the default: DNS egress) |
| networkPolicy.extraIngress | list | `[]` | Extra ingress rules (added to the defaults: API + gRPC + metrics ports) |
| podDisruptionBudget | object | `{"enabled":false,"maxUnavailable":1}` | Pod disruption budget (protects against voluntary evictions) |
| podDisruptionBudget.enabled | bool | `false` | Create a PodDisruptionBudget |
| podDisruptionBudget.maxUnavailable | int | `1` | Maximum number of pods that can be unavailable during voluntary disruptions |
| qos.enabled | bool | `false` | Enable QoS / traffic shaping |
| ratelimit.enabled | bool | `true` | Enable rate limiting (4 algorithms) |
| routing.enabled | bool | `false` | Enable multi-WAN policy routing |
| serviceAccount | object | `{"annotations":{},"create":true,"name":""}` | Service account configuration |
| serviceAccount.annotations | object | `{}` | Annotations on the ServiceAccount (e.g., IAM role for GeoIP download) |
| serviceAccount.create | bool | `true` | Create a dedicated ServiceAccount |
| serviceAccount.name | string | `""` | ServiceAccount name (auto-generated if empty) |
| threatintel.enabled | bool | `true` | Enable threat intelligence (OSINT feeds) |
| zones.enabled | bool | `false` | Enable security zones |

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

| Name | Email | Url |
| ---- | ------ | --- |
| ebpfsentinel |  | <https://github.com/ebpfsentinel> |
