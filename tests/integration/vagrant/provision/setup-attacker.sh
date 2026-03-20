#!/usr/bin/env bash
# setup-attacker.sh — Fully autonomous provisioner for the attacker VM (192.168.56.20)
#
# Sets up SSH key auth to agent VM, installs test tools, generates local
# certs/keys, waits for agent readiness, and runs a connectivity check.
set -euxo pipefail

PROJECT_DIR="/home/vagrant/ebpfsentinel"
INTEGRATION_DIR="${PROJECT_DIR}/tests/integration"
CERT_DIR="/tmp/ebpfsentinel-test-certs"
JWT_DIR="/tmp/ebpfsentinel-test-jwt"
AGENT_IP="192.168.56.10"

export PATH="${HOME}/.cargo/bin:${PATH}"

# ── Set up SSH access to agent VM ──────────────────────────────────
echo "=== [1/5] Setting up SSH access to agent VM ==="
mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [ ! -f ~/.ssh/agent_key ]; then
    ssh-keygen -t ed25519 -f ~/.ssh/agent_key -N ""
fi

if command -v sshpass &>/dev/null; then
    for attempt in $(seq 1 10); do
        if sshpass -p vagrant ssh-copy-id \
            -i ~/.ssh/agent_key.pub \
            -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            vagrant@${AGENT_IP} 2>/dev/null; then
            echo "  SSH key copied (attempt ${attempt})"
            break
        fi
        echo "  Waiting for agent SSH... (attempt ${attempt}/10)"
        sleep 10
    done
else
    echo "ERROR: sshpass not installed"
    exit 1
fi

# Verify
ssh -i ~/.ssh/agent_key -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    vagrant@${AGENT_IP} echo "SSH connection OK"

# ── Generate local TLS certificates and JWT keys ───────────────────
echo "=== [2/5] Generating local TLS certificates ==="
bash "${INTEGRATION_DIR}/scripts/generate-certs.sh" --out-dir "$CERT_DIR"

echo "=== [3/5] Generating local JWT keys and tokens ==="
bash "${INTEGRATION_DIR}/scripts/generate-jwt-keys.sh" --out-dir "$JWT_DIR"

# ── Set up environment variables ───────────────────────────────────
echo "=== [4/5] Configuring environment ==="
cat > ~/.ebpfsentinel-test-env <<'ENVEOF'
# eBPFsentinel 2-VM test environment
export EBPF_2VM_MODE=true
export AGENT_VM_IP=192.168.56.10
export ATTACKER_VM_IP=192.168.56.20
export AGENT_SSH_KEY=~/.ssh/agent_key
export AGENT_SSH="ssh -i ~/.ssh/agent_key -o StrictHostKeyChecking=no vagrant@192.168.56.10"
export AGENT_HOST=192.168.56.10
export AGENT_HTTP_PORT=8080
export AGENT_GRPC_PORT=50051
ENVEOF

# Add to bashrc if not already there
if ! grep -q 'ebpfsentinel-test-env' ~/.bashrc 2>/dev/null; then
    echo 'source ~/.ebpfsentinel-test-env 2>/dev/null || true' >> ~/.bashrc
fi
source ~/.ebpfsentinel-test-env

# ── Wait for agent VM to be ready ──────────────────────────────────
echo "=== [5/5] Waiting for agent VM ==="
MAX_RETRIES=60
RETRY_INTERVAL=5

for i in $(seq 1 "$MAX_RETRIES"); do
    if ssh -i ~/.ssh/agent_key -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        vagrant@${AGENT_IP} "test -f /tmp/ebpfsentinel-agent-ready" 2>/dev/null; then
        echo "  Agent VM is ready (attempt ${i}/${MAX_RETRIES})"
        break
    fi

    if [ "$i" -eq "$MAX_RETRIES" ]; then
        echo "ERROR: Agent VM did not become ready within $((MAX_RETRIES * RETRY_INTERVAL))s"
        exit 1
    fi

    echo "  Waiting... (attempt ${i}/${MAX_RETRIES})"
    sleep "$RETRY_INTERVAL"
done

# ── Connectivity check ─────────────────────────────────────────────
echo ""
echo "=== Connectivity check ==="
echo -n "  Agent HTTP: "
curl -sf --max-time 5 "http://${AGENT_IP}:8080/healthz" 2>/dev/null && echo "OK" || echo "NOT REACHABLE (agent may not be running)"
echo -n "  Agent ping: "
ping -c 1 -W 2 "${AGENT_IP}" >/dev/null 2>&1 && echo "OK" || echo "FAILED"

echo ""
echo "============================================"
echo "  Attacker VM setup complete"
echo "============================================"
echo ""
echo "Run tests from the attacker VM:"
echo "  vagrant ssh attacker"
echo "  source ~/.ebpfsentinel-test-env"
echo "  cd ${INTEGRATION_DIR}"
echo "  bats --timing suites/"
echo ""
echo "Or run a single suite:"
echo "  bats --timing suites/36-api-stix-feed.bats"
echo ""
echo "Run tests on the agent VM directly (eBPF suites):"
echo "  vagrant ssh agent"
echo "  cd ${INTEGRATION_DIR}"
echo "  sudo bats --timing suites/"
echo ""
