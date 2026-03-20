#!/usr/bin/env bash
# teardown.sh — Clean up test environment in the VM
set -euxo pipefail

echo "=== Tearing down test environment ==="

# Stop any running agent
echo "  Stopping agent..."
AGENT_PID_FILE="/tmp/ebpfsentinel-test.pid"
if [ -f "$AGENT_PID_FILE" ]; then
    PID="$(cat "$AGENT_PID_FILE" 2>/dev/null)" || true
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        sleep 2
        kill -KILL "$PID" 2>/dev/null || true
    fi
    rm -f "$AGENT_PID_FILE"
fi

# Kill any stale agent processes
pkill -f ebpfsentinel-agent 2>/dev/null || true

# Clean up eBPF state
echo "  Cleaning eBPF state..."
if command -v bpftool &>/dev/null; then
    # Detach XDP programs from all interfaces
    for iface in $(ip -o link show | awk -F: '{print $2}' | tr -d ' '); do
        ip link set dev "$iface" xdp off 2>/dev/null || true
    done
    # Clean up pinned maps
    rm -rf /sys/fs/bpf/ebpfsentinel* 2>/dev/null || true
fi

# Clean up network namespaces
echo "  Cleaning network namespaces..."
ip netns del ebpf-test-ns 2>/dev/null || true
ip link delete veth-ebpf0 2>/dev/null || true

# Stop iperf3 server
pkill -f "iperf3 -s" 2>/dev/null || true

# Stop HTTP fixture servers
pkill -f "python3 -m http.server" 2>/dev/null || true

# Delete minikube cluster
if command -v minikube &>/dev/null; then
    echo "  Deleting minikube cluster..."
    minikube delete 2>/dev/null || true
fi

# Prune Docker
if command -v docker &>/dev/null; then
    echo "  Pruning Docker..."
    docker rm -f "$(docker ps -aq --filter name=ebpfsentinel)" 2>/dev/null || true
fi

# Clean up test data
echo "  Cleaning temp files..."
rm -rf /tmp/ebpfsentinel-test-data*
rm -rf /tmp/ebpfsentinel-test-certs
rm -rf /tmp/ebpfsentinel-test-jwt
rm -f /tmp/ebpfsentinel-test.pid
rm -f /tmp/ebpfsentinel-test.log
rm -f /tmp/ebpfsentinel-prepared-*.yaml
rm -f /tmp/ebpfsentinel-smoke.log
rm -f /tmp/ebpfsentinel-agent-ready

echo "=== Teardown complete ==="
