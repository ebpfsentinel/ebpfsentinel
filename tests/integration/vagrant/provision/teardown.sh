#!/usr/bin/env bash
# teardown.sh — Clean up test environment in the VM
set -euxo pipefail

echo "=== Tearing down test environment ==="

# Stop any running agent
AGENT_PID_FILE="/tmp/ebpfsentinel-test.pid"
if [ -f "$AGENT_PID_FILE" ]; then
    PID="$(cat "$AGENT_PID_FILE" 2>/dev/null)" || true
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        echo "Stopping agent (PID ${PID})..."
        kill -TERM "$PID" 2>/dev/null || true
        sleep 2
        kill -KILL "$PID" 2>/dev/null || true
    fi
    rm -f "$AGENT_PID_FILE"
fi

# Delete minikube cluster
if command -v minikube &>/dev/null; then
    echo "Deleting minikube cluster..."
    minikube delete 2>/dev/null || true
fi

# Prune Docker
if command -v docker &>/dev/null; then
    echo "Pruning Docker..."
    docker system prune -af 2>/dev/null || true
fi

# Clean up test data
rm -rf /tmp/ebpfsentinel-test-data*
rm -rf /tmp/ebpfsentinel-test-certs
rm -rf /tmp/ebpfsentinel-test-jwt
rm -f /tmp/ebpfsentinel-test.pid
rm -f /tmp/ebpfsentinel-test.log
rm -f /tmp/ebpfsentinel-prepared-*.yaml

echo "=== Teardown complete ==="
