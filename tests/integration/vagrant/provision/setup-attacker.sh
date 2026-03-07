#!/usr/bin/env bash
# setup-attacker.sh — Vagrant provisioner for the attacker VM (192.168.56.20)
# Sets up SSH access to agent VM, generates local certs/keys, waits for agent readiness.
set -euxo pipefail

PROJECT_DIR="/home/vagrant/ebpfsentinel"
INTEGRATION_DIR="${PROJECT_DIR}/tests/integration"
CERT_DIR="/tmp/ebpfsentinel-test-certs"
JWT_DIR="/tmp/ebpfsentinel-test-jwt"

export PATH="${HOME}/.cargo/bin:${PATH}"

# ── Set up SSH access to agent VM ──────────────────────────────────
echo "=== Setting up SSH access to agent VM ==="
mkdir -p ~/.ssh
chmod 700 ~/.ssh

if [ ! -f ~/.ssh/agent_key ]; then
    ssh-keygen -t ed25519 -f ~/.ssh/agent_key -N ""
fi

# Copy public key to the agent VM (default vagrant password is "vagrant")
if command -v sshpass &>/dev/null; then
    sshpass -p vagrant ssh-copy-id \
        -i ~/.ssh/agent_key.pub \
        -o StrictHostKeyChecking=no \
        vagrant@192.168.56.10
else
    echo "ERROR: sshpass not installed — cannot set up SSH key auth"
    exit 1
fi

# Verify SSH connectivity
echo "=== Verifying SSH connectivity ==="
ssh -i ~/.ssh/agent_key -o StrictHostKeyChecking=no vagrant@192.168.56.10 echo "SSH connection OK"

# ── Set up environment variables for test execution ────────────────
echo "=== Configuring environment variables ==="
cat >> ~/.bashrc <<'ENVEOF'

# eBPFsentinel 2-VM test environment
export EBPF_2VM_MODE=true
export AGENT_VM_IP=192.168.56.10
export ATTACKER_VM_IP=192.168.56.20
export AGENT_SSH_KEY=~/.ssh/agent_key
export AGENT_SSH="ssh -i ~/.ssh/agent_key -o StrictHostKeyChecking=no vagrant@192.168.56.10"
ENVEOF

# Source them for the rest of this script
export EBPF_2VM_MODE=true
export AGENT_VM_IP=192.168.56.10
export ATTACKER_VM_IP=192.168.56.20
export AGENT_SSH_KEY=~/.ssh/agent_key
export AGENT_SSH="ssh -i ~/.ssh/agent_key -o StrictHostKeyChecking=no vagrant@192.168.56.10"

# ── Generate local TLS certificates and JWT keys (for API auth) ───
echo "=== Generating local TLS certificates ==="
bash "${INTEGRATION_DIR}/scripts/generate-certs.sh" --out-dir "$CERT_DIR"

echo "=== Generating local JWT keys and tokens ==="
bash "${INTEGRATION_DIR}/scripts/generate-jwt-keys.sh" --out-dir "$JWT_DIR"

# ── Wait for agent VM to be ready ──────────────────────────────────
echo "=== Waiting for agent VM to be ready ==="
MAX_RETRIES=60
RETRY_INTERVAL=5

for i in $(seq 1 "$MAX_RETRIES"); do
    if ssh -i ~/.ssh/agent_key -o StrictHostKeyChecking=no vagrant@192.168.56.10 \
        "test -f /tmp/ebpfsentinel-agent-ready" 2>/dev/null; then
        echo "  Agent VM is ready (attempt ${i}/${MAX_RETRIES})"
        break
    fi

    if [ "$i" -eq "$MAX_RETRIES" ]; then
        echo "ERROR: Agent VM did not become ready within $((MAX_RETRIES * RETRY_INTERVAL))s"
        exit 1
    fi

    echo "  Waiting for agent VM... (attempt ${i}/${MAX_RETRIES})"
    sleep "$RETRY_INTERVAL"
done

echo ""
echo "=== Attacker VM setup complete ==="
echo ""
echo "To run integration tests:"
echo "  vagrant ssh attacker"
echo "  cd ${INTEGRATION_DIR}"
echo "  bats --timing suites/"
echo ""
echo "Environment variables available:"
echo "  EBPF_2VM_MODE=true"
echo "  AGENT_VM_IP=192.168.56.10"
echo "  ATTACKER_VM_IP=192.168.56.20"
echo "  AGENT_SSH_KEY=~/.ssh/agent_key"
echo '  AGENT_SSH="ssh -i ~/.ssh/agent_key -o StrictHostKeyChecking=no vagrant@192.168.56.10"'
