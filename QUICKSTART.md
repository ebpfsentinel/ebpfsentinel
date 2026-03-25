# Quick Start

Get eBPFsentinel running in minutes. Pick your deployment mode.

**Requirements**: Linux kernel 6.6+ with BTF, root/privileged access.

## Option 1: Binary

```bash
# Build
cargo build --release
cargo xtask ebpf-build

# Run (minimal config — only interface is required)
sudo ./target/release/ebpfsentinel-agent --config config/ebpfsentinel.yaml
```

Expected output:

```
INFO ebpfsentinel agent starting  version="0.0.0-dev"
INFO XDP program attached  interface="eth0" mode="auto"
INFO TC programs attached  interface="eth0" count=8
INFO HTTP API server listening  bind_address="127.0.0.1" port=8080
INFO gRPC server listening  port=50051
INFO Prometheus metrics available  port=9090
```

Verify:

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}

curl http://localhost:8080/api/v1/agent/status
# {"version":"0.0.0-dev","uptime_seconds":5,"ebpf_loaded":true,"rule_count":0}

# CLI
./target/release/ebpfsentinel-agent status
```

## Option 2: Docker

```bash
docker run -d --name ebpfsentinel \
  --privileged --network host \
  -v ./config/ebpfsentinel.yaml:/etc/ebpfsentinel/config.yaml \
  ghcr.io/ebpfsentinel/ebpfsentinel:latest
```

Or with Docker Compose:

```bash
docker compose up -d
docker compose logs -f
```

Verify:

```bash
curl http://localhost:8080/healthz
docker exec ebpfsentinel ebpfsentinel-agent health
```

## Option 3: Kubernetes / Helm

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
# NAME                  READY   STATUS    RESTARTS   AGE   IP            NODE
# ebpfsentinel-xxxxx    1/1     Running   0          30s   10.0.0.1      node-1

kubectl -n ebpfsentinel logs -l app.kubernetes.io/name=ebpfsentinel --tail=10
```

With Prometheus monitoring:

```bash
helm upgrade ebpfsentinel ebpfsentinel/ebpfsentinel \
  --namespace ebpfsentinel --reuse-values \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.prometheusRule.enabled=true
```

## First Configuration

Edit `config/ebpfsentinel.yaml` (or Helm values) to match your setup:

```yaml
agent:
  interfaces: [eth0]       # your host NIC (ip -o link show)
  bind_address: "0.0.0.0"  # listen on all interfaces

firewall:
  enabled: true

ids:
  enabled: true

# Enable more domains as needed:
# ddos:
#   enabled: true
# l7:
#   enabled: true
# threatintel:
#   enabled: true
#   feeds:
#     - id: abuse-ch
#       name: abuse.ch Feodo Tracker
#       url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
#       format: plaintext
```

Changes are picked up automatically via hot reload (file watcher). No restart needed.

## First Firewall Rule

```bash
# Via CLI
curl -X POST http://localhost:8080/api/v1/firewall/rules \
  -H "Content-Type: application/json" \
  -d '{
    "id": "block-telnet",
    "priority": 10,
    "action": "deny",
    "protocol": "tcp",
    "dst_port": 23
  }'

# Verify
curl http://localhost:8080/api/v1/firewall/rules
```

## Watch Alerts in Real-Time

```bash
# CLI tail (like journalctl -f)
ebpfsentinel-agent watch

# Or via gRPC streaming
grpcurl -plaintext localhost:50051 \
  ebpfsentinel.v1.AlertService/StreamAlerts
```

## Prometheus Metrics

```bash
curl http://localhost:9090/metrics | grep ebpfsentinel_

# Key metrics:
# ebpfsentinel_packets_total{interface="firewall",action="pass"}
# ebpfsentinel_alerts_total{component="ids",severity="high"}
# ebpfsentinel_worker_events_total{worker_id="0"}
# ebpfsentinel_events_dropped_total{reason="..."}
# ebpfsentinel_ebpf_program_status{program="xdp_firewall"}
```

## Next Steps

- [Configuration Reference](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/configuration/overview.md) — all YAML options
- [Feature Guides](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/features/overview.md) — per-domain documentation
- [REST API Reference](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/api-reference/rest-api.md) — all 65+ endpoints
- [Deployment Matrix](https://github.com/ebpfsentinel/ebpfsentinel-docs/blob/main/features/deployment-matrix.md) — what works where
- [Example Configs](config/examples/) — 20 pre-built configurations
