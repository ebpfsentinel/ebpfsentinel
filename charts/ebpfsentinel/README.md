# ebpfsentinel

eBPF-native Network & Security platform for Linux

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.0-dev](https://img.shields.io/badge/AppVersion-0.0.0--dev-informational?style=flat-square)

## Overview

Deploys [eBPFsentinel](https://github.com/ebpfsentinel/ebpfsentinel) - a kernel-native **Network & Security platform** - as a Kubernetes DaemonSet. One agent per node, attached to host network interfaces via eBPF (XDP/TC). eBPF loads **exclusively** through a BPF token. Each pod runs two containers: a privileged `warden` broker (native sidecar) and the rootless `agent`. The agent self-unshares a user namespace, has the warden delegate a bpffs over a shared socket, and creates the token there - so the agent holds **no** host capabilities and only the warden sidecar is granted them (never `privileged: true`).

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

See [OSS vs Enterprise](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/docs/features/enterprise/overview.md) for the full comparison.

## Kubernetes Deployment Constraints

### Required Privileges

| Requirement | Reason |
|-------------|--------|
| `hostNetwork: true` | XDP/TC programs attach to host interfaces, not pod veth |
| `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` + `CAP_NET_RAW` on the **warden sidecar** only | eBPF loads **exclusively** through a BPF token - there is no capability-based loading path. The warden broker holds these capabilities for bpffs delegation, conntrack/routes, and the pcap pool/ARP. The `agent` container drops every capability (`cap_drop: ALL`, non-root): it self-unshares a user namespace and loads its own eBPF through the token. Both run Unconfined seccomp/AppArmor (the mount/userns/bpf syscalls). |
| unprivileged user namespaces enabled on the node | `BPF_TOKEN_CREATE` is `EOPNOTSUPP` outside a user namespace |
| `/sys/fs/bpf` mount | BPF filesystem for map pinning + delegated token bpffs |
| `/sys/kernel/debug` mount | eBPF tracing (debugfs) |
| Kernel 6.9+ with BTF | Agent minimum: BPF token delegation, ARENA maps, kfuncs; CO-RE requires BTF |

### Feature Limitations in Kubernetes

| Feature | DaemonSet | Notes |
|---------|-----------|-------|
| Firewall, IDS, DDoS, Rate Limiting | Full | Attached to host NIC - sees all node traffic |
| DLP | Full | Covers every process on the node without the host pid namespace: the warden and the agent read the node's procfs through the read-only `/host/proc` mount, and the uprobe link is created against a path and an offset rather than a pid |
| Multi-WAN Routing | Full | `hostNetwork` shares the routing table; route application (`ip rule`/`ip route`) is brokered to the `warden`, which holds `CAP_NET_ADMIN` in the init network namespace. Same path as `conntrack -D` flow-kill and gratuitous ARP |
| Sidecar mode | Not recommended | XDP works on veth (generic mode) but only sees the pod's own traffic - no host or cross-pod visibility |

**DLP covers the whole node out of the box**, with `daemonset.hostPID` off. The
pod mounts the node's `/proc` read-only at `/host/proc`, both containers are
told about it through `EBPFSENTINEL_HOST_PROC`, and the library path the warden
hands back is rooted on that mount. The uprobe itself is a `BPF_LINK_CREATE`
against a path and an offset with `pid = 0`, so it fires for every process that
maps `libssl.so.3`, in whatever namespace. Turning `hostPID` on adds the node's
process list and command lines to what the pod can see and buys no coverage,
and Pod Security Admission `baseline` forbids it.

### CNI Compatibility

eBPFsentinel attaches to the **host physical interface** (e.g., `eth0`), not to the CNI bridge or veth pairs. This means:

- It does **not** interfere with pod-to-pod (east-west) traffic managed by the CNI
- It **only** sees north-south traffic entering/leaving the node
- Compatible with: Calico, Flannel, Cilium, Weave, any CNI
- Firewall rules apply to the host interface - they affect all pods on the node equally

For per-pod network policy, use your CNI's native policy engine (e.g., Cilium NetworkPolicy). eBPFsentinel complements CNI by adding network security capabilities (IDS, DLP, threat intel, DDoS) at the node boundary.

## Quick Start

```bash
helm install ebpfsentinel oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel \
  --version <version> \
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
helm install ebpfsentinel oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel --version <version> \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}'
```

### Full Network & Security deployment with Prometheus monitoring

```bash
helm install ebpfsentinel oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel --version <version> \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{ens192}' \
  --set ddos.enabled=true \
  --set l7.enabled=true \
  --set conntrack.enabled=true \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.labels.release=kube-prometheus-stack
```

### DLP with full node visibility

Nothing extra is needed: the host procfs mount is always there, so DLP sees
every process on the node as soon as it is enabled.

```bash
helm install ebpfsentinel oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel --version <version> \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}' \
  --set dlp.enabled=true
```

### TLS with post-quantum key exchange

```bash
helm install ebpfsentinel oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel --version <version> \
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

### State kept across rollouts

The alert, audit and rule-history stores, packet captures, downloaded GeoIP databases and the telemetry installation identifier live under `/var/lib/ebpfsentinel`. By default that is a node directory, `/var/lib/ebpfsentinel/k8s/<namespace>/<release>`, so all of it carries over a rollout. The kubelet creates a hostPath owned by root and Kubernetes applies no `fsGroup` to one, so a `state-dir` init container runs the warden image once as root, with `CHOWN` and `FOWNER` alone, to create the directory at `0700` owned by uid 65534. Nothing has to be prepared on the node.

The installation identifier is not random on a node that has `/etc/machine-id`: the chart mounts that file read-only and the agent keeps a keyed hash of it, never the identifier itself, so the node answers to one name even after its state directory is lost or the chart is reinstalled under another release name. A node without the file would keep the pod from starting, so set `daemonset.state.machineId=false` there; the identifier is then random and lives as long as the state does.

```bash
# another node directory
--set daemonset.state.hostPath=/srv/ebpfsentinel
# an emptyDir instead: empty stores and a new installation identifier after every rollout
--set daemonset.state.ephemeral=true
# a node with no /etc/machine-id: a random installation identifier kept with the state
--set daemonset.state.machineId=false
```

### Auto-response and auto-capture

`auto_response`, `auto_capture`, `aliases` and `interface_groups` are rendered verbatim into the matching sections of `config.yaml`:

```yaml
# response-values.yaml
auto_response:
  enabled: true
  policies:
    - name: block-critical
      min_severity: critical
      action: block
      ttl_secs: 3600
auto_capture:
  enabled: true
  min_severity: high
  duration_secs: 30
```

```bash
helm install ebpfsentinel oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel --version <version> \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}' \
  -f response-values.yaml
```

### Kubernetes pod metadata on alerts

```bash
helm install ebpfsentinel oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel --version <version> \
  --namespace ebpfsentinel --create-namespace \
  --set agent.interfaces='{eth0}' \
  --set container.kubernetes.enabled=true
```

This creates a ClusterRole with `get`/`list`/`watch` on `pods` and `list`/`watch` on `namespaces`, whose labels a workload rule naming namespaces is matched against, and nothing else, binds it to the chart's ServiceAccount and mounts that account's token into the pod. With the enricher off the token is not mounted at all.

### Custom config (bypass values.yaml)

```bash
helm install ebpfsentinel oci://ghcr.io/ebpfsentinel/charts/ebpfsentinel --version <version> \
  --namespace ebpfsentinel --create-namespace \
  --set-file configOverride=my-config.yaml
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| agent | object | `{"allowPlaintextApi":true,"allowUnauthenticatedApi":false,"bindAddress":"0.0.0.0","eventWorkers":4,"grpcPort":50051,"grpcReflection":false,"httpPort":8080,"interfaces":["eth0"],"logFormat":"json","logLevel":"info","metricsPort":9090,"swaggerUi":false,"tls":{"allowTls12":false,"certPath":"","enabled":false,"keyPath":"","pqMode":"prefer"},"xdpMode":"auto"}` | Agent configuration (generates config.yaml) |
| agent.allowPlaintextApi | bool | `true` | Allow the control API on a non-loopback bind without TLS. On, because the pod binds 0.0.0.0 and the chart ships no certificate: the API key and the configuration travel the cluster network readable by anything on the path. Fix it properly with `agent.tls` below (a cert from cert-manager, mounted through extraVolumes) and set this to false; a service mesh carrying mTLS is the other way to earn it. |
| agent.allowUnauthenticatedApi | bool | `false` | Allow the control API on a non-loopback bind while auth is disabled. Off, because authentication is on by default (see `auth` below) and the pod binds 0.0.0.0 only so the kubelet can reach the probes. Turning `auth.enabled` off makes this mandatory, and it leaves the firewall, IPS and config-reload routes open to anything that can reach the pod. |
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
| auth.enabled | bool | `true` | Establish a principal before the control API answers. On by default: the same routes reload configuration, write firewall rules and arm the IPS. `/healthz` and `/readyz` stay public whatever this says, which is what the kubelet probes use. |
| auth.existingSecret | string | `""` | Name of an existing Secret holding the API key. When empty, the agent draws one for itself at first start and keeps it under the state volume, printed once in the pod log:   kubectl logs -l app.kubernetes.io/name=ebpfsentinel | grep "API key" With `daemonset.state.ephemeral: true` that state is an emptyDir, so a replaced pod draws a new key - name a Secret here instead. |
| auth.secretKey | string | `"api-key"` | Key inside `auth.existingSecret` holding the API key. Its value must be a key the agent recognises: `sk-` followed by 64 hexadecimal characters.   kubectl create secret generic ebpfsentinel-auth \     --from-literal=api-key="sk-$(openssl rand -hex 32)" |
| auto_capture | object | `{"enabled":false}` | Auto-capture: start PCAP on high-severity alert (max 60s in OSS) |
| auto_response | object | `{"enabled":false}` | Auto-response: automatic block/throttle on high-severity alerts (max 3 policies in OSS) |
| commonAnnotations | object | `{}` | Annotations added to all resources |
| commonLabels | object | `{}` | Labels added to all resources |
| configOverride | string | `""` | Override the entire config.yaml content. When set, all agent.* and domain toggles above are ignored. |
| conntrack.enabled | bool | `false` | Enable connection tracking |
| container | object | `{"kubernetes":{"enabled":false,"labelFilter":[],"networkPolicy":{"mode":"off"}}}` | Container awareness |
| container.kubernetes.enabled | bool | `false` | Enable the Kubernetes pod metadata enricher: alerts carry the pod name, namespace and labels of the container that produced them. Turning it on creates a ClusterRole with get/list/watch on `pods` and list/watch on `namespaces`, binds it to the ServiceAccount and mounts the ServiceAccount token into the pod, which is otherwise left unmounted. |
| container.kubernetes.labelFilter | list | `[]` | Optional label selector (`key=value` pairs) narrowing the pod watcher |
| container.kubernetes.networkPolicy.mode | string | `"off"` | Kubernetes NetworkPolicy on this node's pods: `off`, `observe` (refusals counted and let through) or `enforce`. Needs `enabled`, and widens the ClusterRole to list and watch networkpolicies, services and endpointslices across the cluster. |
| daemonset | object | `{"affinity":{},"bpfToken":{"bpffsEmptyDir":false,"bpffsPath":"/sys/fs/bpf/ebpfsentinel"},"extraContainers":[],"extraEnv":[],"extraVolumeMounts":[],"extraVolumes":[],"hostNetwork":true,"hostPID":false,"initContainers":[],"minReadySeconds":0,"nodeSelector":{},"podAnnotations":{},"podLabels":{},"podSecurityAdmission":"privileged","preStopSleepSeconds":5,"priorityClassName":"","resources":{"limits":{"cpu":"1000m","memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}},"revisionHistoryLimit":10,"securityContext":{"allowPrivilegeEscalation":true,"appArmorProfile":{"type":"Unconfined"},"capabilities":{"drop":["ALL"]},"runAsGroup":65534,"runAsUser":65534,"seccompProfile":{"type":"Unconfined"}},"state":{"ephemeral":false,"hostPath":"","machineId":true},"terminationGracePeriodSeconds":30,"tolerations":[{"operator":"Exists"}],"updateStrategy":{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"},"warden":{"resources":{"limits":{"cpu":"1000m","memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}},"securityContext":{"allowPrivilegeEscalation":true,"appArmorProfile":{"type":"Unconfined"},"capabilities":{"add":["SYS_ADMIN","NET_ADMIN","NET_RAW","SYS_PTRACE","BPF","PERFMON"],"drop":["ALL"]},"runAsUser":0,"seccompProfile":{"type":"Unconfined"}}}}` | DaemonSet configuration |
| daemonset.affinity | object | `{}` | Affinity rules |
| daemonset.bpfToken | object | `{"bpffsEmptyDir":false,"bpffsPath":"/sys/fs/bpf/ebpfsentinel"}` | BPF token delegation. eBPF is loaded EXCLUSIVELY through a BPF token (kernel 6.9+), a user-namespace feature. The pod runs the warden broker as a native sidecar; the agent self-unshares a user namespace, has the warden delegate a bpffs at `bpffsPath`, and loads its own eBPF through the token - holding no host capabilities. There is no capability-based loading path. `bpffsPath` drives BOTH the `EBPFSENTINEL_BPFFS` env (DaemonSet, the agent's mount target) and the agent's `bpf_token.bpffs_path` (ConfigMap) - keep them in sync via this one value; they must point at the same mount. |
| daemonset.bpfToken.bpffsEmptyDir | bool | `false` | Back the bpffs mount with an in-pod tmpfs (emptyDir medium: Memory) instead of the host's /sys/fs/bpf. Required on nested runtimes (kind, minikube) whose node /sys/fs/bpf is read-only or absent - there the hostPath mount fails. On a real node leave this false so pinned maps live on the host bpffs. |
| daemonset.extraContainers | list | `[]` | Extra containers (sidecars) |
| daemonset.extraEnv | list | `[]` | Extra environment variables |
| daemonset.extraVolumeMounts | list | `[]` | Extra volume mounts (e.g., GeoIP database, TLS certs) |
| daemonset.extraVolumes | list | `[]` | Extra volumes |
| daemonset.hostNetwork | bool | `true` | Share the host network namespace. The XDP and TC programs attach to the node's own interfaces, which only exist in it; turning it off leaves the datapath with the pod's veth and nothing else. Forbidden by `baseline`. |
| daemonset.hostPID | bool | `false` | Share the host PID namespace. Off: cross-container TLS DLP no longer needs it. The warden and the agent both read the host procfs through the read-only `/host/proc` mount (`EBPFSENTINEL_HOST_PROC`), the library path they exchange is rooted on it, and the uprobe link is created against a path and an offset with `pid = 0`, so it covers every process that maps the library whatever namespace it is in. Turning it on adds the node's command lines to what the pod can see and buys no coverage; `baseline` forbids it. |
| daemonset.initContainers | list | `[]` | Init containers |
| daemonset.minReadySeconds | int | `0` | Minimum seconds a pod must be ready before considered available |
| daemonset.nodeSelector | object | `{}` | Node selector |
| daemonset.podAnnotations | object | `{}` | Extra annotations on DaemonSet pods |
| daemonset.podLabels | object | `{}` | Extra labels on DaemonSet pods |
| daemonset.podSecurityAdmission | string | `"privileged"` | The Pod Security Admission level this pod is meant to satisfy: `privileged`, `baseline` or `restricted`. It enforces nothing by itself - the namespace label does that - but the chart refuses to render when these values ask for something the named level forbids, listing every offending value at once instead of letting admission reject the pod on the first one it notices. As shipped the pod is `privileged`, and the reasons are the host network namespace (XDP and TC attach to the node's interfaces) and the warden's capabilities and unconfined profiles (bpffs delegation, netlink, the DLP uprobe). Cross-container DLP is no longer one of them. |
| daemonset.preStopSleepSeconds | int | `5` | Seconds the preStop hook holds the agent before it is signalled, so the endpoint is out of every node's rules before the stop begins. `0` removes the hook. Must stay below terminationGracePeriodSeconds minus the agent's 20s stop budget. |
| daemonset.priorityClassName | string | `""` | Pod priority class name |
| daemonset.resources | object | `{"limits":{"cpu":"1000m","memory":"512Mi"},"requests":{"cpu":"100m","memory":"128Mi"}}` | Resource requests and limits |
| daemonset.revisionHistoryLimit | int | `10` | Number of old ReplicaSets to retain |
| daemonset.securityContext | object | `{"allowPrivilegeEscalation":true,"appArmorProfile":{"type":"Unconfined"},"capabilities":{"drop":["ALL"]},"runAsGroup":65534,"runAsUser":65534,"seccompProfile":{"type":"Unconfined"}}` | Agent container security context. The agent runs non-root (uid 65534) with every capability dropped. It self-unshares a user namespace and loads its own eBPF, so it issues mount/userns/bpf syscalls; holding NO CAP_SYS_ADMIN, the default seccomp profile (which gates those on CAP_SYS_ADMIN) would block them, so seccomp + AppArmor are Unconfined. NOTE: nested user namespaces + bpffs delegation can require cluster-specific runtime config (allow unprivileged userns). On nodes whose kernel sets kernel.apparmor_restrict_unprivileged_userns=1 (Ubuntu 24.04+), the agent (uid 65534) cannot self-unshare a user namespace - the in-pod `seccompProfile`/ `appArmorProfile: Unconfined` above does NOT lift this host-level gate. Set the sysctl to 0 on each node (e.g. a privileged init DaemonSet, a node-bootstrap MachineConfig, or /etc/sysctl.d/), or load a per-binary AppArmor profile granting `userns`. Nodes without that restriction (most non-Ubuntu kernels, e.g. Talos) need nothing. |
| daemonset.state.ephemeral | bool | `false` | Keep the state in an emptyDir instead: it survives a container restart but not the pod being replaced, so every rollout starts with empty stores and a new installation identifier. |
| daemonset.state.hostPath | string | `""` | Node directory holding the agent state. Empty means /var/lib/ebpfsentinel/k8s/<namespace>/<release>, one directory per release. It is created when missing and handed to uid/gid 65534 with mode 0700 by the state-dir init container before the agent starts, so the stores and the installation identifier carry over a rollout. |
| daemonset.state.machineId | bool | `true` | Mount the node's /etc/machine-id read-only so the telemetry installation identifier is derived from it: a keyed hash, never the identifier itself. The node then answers to one name whatever happens to the state, a reinstall under another release name included. Set false on a node that has no /etc/machine-id, where the mount would keep the pod from starting; the identifier is then random and lives with the state. |
| daemonset.terminationGracePeriodSeconds | int | `30` | Grace period for pod termination (seconds). Covers the preStop hook and the agent's own stop budget (TimeoutStopSec=20s in the systemd unit, the same ordered stop here): 5 + 20 = 25, so 30 leaves room rather than turning a correct stop into a SIGKILL. The arithmetic is pinned by a test in crates/infrastructure/src/constants.rs. |
| daemonset.tolerations | list | `[{"operator":"Exists"}]` | Tolerations (default: schedule on all nodes including control-plane) |
| daemonset.updateStrategy | object | `{"rollingUpdate":{"maxUnavailable":1},"type":"RollingUpdate"}` | DaemonSet update strategy |
| daemonset.warden | object | `{"resources":{"limits":{"cpu":"1000m","memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}},"securityContext":{"allowPrivilegeEscalation":true,"appArmorProfile":{"type":"Unconfined"},"capabilities":{"add":["SYS_ADMIN","NET_ADMIN","NET_RAW","SYS_PTRACE","BPF","PERFMON"],"drop":["ALL"]},"runAsUser":0,"seccompProfile":{"type":"Unconfined"}}}` | The privileged warden broker (native sidecar). |
| daemonset.warden.resources | object | `{"limits":{"cpu":"1000m","memory":"256Mi"},"requests":{"cpu":"50m","memory":"64Mi"}}` | Warden resource requests and limits |
| daemonset.warden.securityContext | object | `{"allowPrivilegeEscalation":true,"appArmorProfile":{"type":"Unconfined"},"capabilities":{"add":["SYS_ADMIN","NET_ADMIN","NET_RAW","SYS_PTRACE","BPF","PERFMON"],"drop":["ALL"]},"runAsUser":0,"seccompProfile":{"type":"Unconfined"}}` | Warden security context. The broker holds the host capabilities: CAP_SYS_ADMIN (bpffs delegation / FSCONFIG_CMD_CREATE), CAP_NET_ADMIN (conntrack teardown + routes), CAP_NET_RAW (pcap pool + gratuitous ARP), CAP_SYS_PTRACE (read a neighbouring container's `/proc/<pid>/root` to reach its `libssl`), and CAP_BPF + CAP_PERFMON (create the DLP uprobe `BPF_LINK_CREATE`). These tracing capabilities live on the warden ONLY - the agent stays `cap-drop: ALL`. It issues fsconfig + netlink + AF_PACKET + bpf, so AppArmor + seccomp are Unconfined. |
| ddos.enabled | bool | `false` | Enable DDoS mitigation (SYN cookie, flood detection) |
| dlp.enabled | bool | `true` | Enable Data Loss Prevention (SSL/TLS uprobe) |
| dns.enabled | bool | `true` | Enable DNS intelligence + blocklists |
| firewall | object | `{"enabled":true}` | Security domain toggles (maps to config.yaml sections) |
| firewall.enabled | bool | `true` | Enable stateful L3/L4 firewall |
| fullnameOverride | string | `""` | Override the full resource name (disables auto-generated name) |
| geoip.enabled | bool | `false` | Enable GeoIP enrichment (MaxMind) |
| geoip.source | object | `{}` | GeoIP database source (REQUIRED when enabled). Rendered verbatim under `geoip.source`. Examples:   source: { mode: file, city_path: /var/lib/ebpfsentinel/geoip/GeoLite2-City.mmdb }   source: { mode: url, city_url: https://mirror/GeoLite2-City.mmdb }   source: { mode: maxmind_account, account_id: "123", license_key: "key" } |
| ids.enabled | bool | `true` | Enable Intrusion Detection System |
| image | object | `{"pullPolicy":"IfNotPresent","repository":"ghcr.io/ebpfsentinel/ebpfsentinel","tag":""}` | Agent container image (the rootless agent) |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.repository | string | `"ghcr.io/ebpfsentinel/ebpfsentinel"` | Image repository |
| image.tag | string | `""` | Image tag (defaults to Chart appVersion) |
| imagePullSecrets | list | `[]` | Image pull secrets for private registries |
| interface_groups | object | `{}` | Interface groups for multi-interface rule scoping (max 31 groups) |
| ips.enabled | bool | `true` | Enable Intrusion Prevention (auto-blacklist) |
| l7.enabled | bool | `false` | Enable L7 protocol filtering (HTTP, TLS/SNI, gRPC) |
| loadbalancer.enabled | bool | `false` | Enable L4 load balancer |
| metrics | object | `{"authRequired":false,"prometheusRule":{"enabled":false,"labels":{},"rules":[]},"serviceMonitor":{"enabled":false,"interval":"15s","labels":{}}}` | Prometheus metrics |
| metrics.authRequired | bool | `false` | Require the API key on `/metrics` as well. The control plane is what authentication is for; the metrics port serves counters and no secret, so a scraper reaches it without a credential by default. Set this true and name `auth.existingSecret`, otherwise the key the agent drew for itself is one nothing outside the pod can present and every scrape answers 401. |
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
| wardenImage | object | `{"repository":"ghcr.io/ebpfsentinel/ebpfsentinel-warden","tag":""}` | Warden broker image (the privileged sidecar) |
| wardenImage.repository | string | `"ghcr.io/ebpfsentinel/ebpfsentinel-warden"` | Image repository |
| wardenImage.tag | string | `""` | Image tag (defaults to Chart appVersion) |
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
