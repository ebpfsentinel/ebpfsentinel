#!/usr/bin/env bash
# sync-to-agent-vm.sh — Sync local binary and/or Docker image to agent VM
#
# Pushes the locally-built agent binary and Docker image to the agent VM
# without rebuilding on the VM. Much faster than compiling in the VM.
#
# Usage:
#   ./sync-to-agent-vm.sh              # sync both binary + Docker image
#   ./sync-to-agent-vm.sh --binary     # sync binary only
#   ./sync-to-agent-vm.sh --docker     # sync Docker image only
#
# Environment:
#   AGENT_VM_IP       Agent VM IP (default: 192.168.56.10)
#   AGENT_SSH_KEY     SSH key for agent VM (auto-detected from Vagrant)
#   AGENT_BINARY      Path to local binary (default: target/release/ebpfsentinel-agent)
#   DOCKER_IMAGE      Docker image name (default: ebpfsentinel:integration-test)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VAGRANT_DIR="${INTEGRATION_DIR}/vagrant"
PROJECT_ROOT="${INTEGRATION_DIR}/../.."

AGENT_VM_IP="${AGENT_VM_IP:-192.168.56.10}"
SSH_KEY="${AGENT_SSH_KEY:-}"
AGENT_BINARY="${AGENT_BINARY:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
DOCKER_IMAGE="${DOCKER_IMAGE:-ebpfsentinel:integration-test}"

SYNC_BINARY=true
SYNC_DOCKER=true

# ── Parse args ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)  SYNC_BINARY=true; SYNC_DOCKER=false; shift ;;
        --docker)  SYNC_BINARY=false; SYNC_DOCKER=true; shift ;;
        --help|-h)
            head -16 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Resolve SSH key ──────────────────────────────────────────────
if [ -z "$SSH_KEY" ]; then
    VAGRANT_KEY="${VAGRANT_DIR}/.vagrant/machines/agent/virtualbox/private_key"
    if [ -f "$VAGRANT_KEY" ]; then
        SSH_KEY="$VAGRANT_KEY"
    else
        # Try vagrant ssh-config
        VAGRANT_KEY="$(cd "$VAGRANT_DIR" && vagrant ssh-config agent 2>/dev/null \
            | grep IdentityFile | awk '{print $2}' | head -1)" || true
        if [ -n "$VAGRANT_KEY" ] && [ -f "$VAGRANT_KEY" ]; then
            SSH_KEY="$VAGRANT_KEY"
        else
            echo "ERROR: SSH key not found. Set AGENT_SSH_KEY or run 'vagrant up agent'" >&2
            exit 1
        fi
    fi
fi

_ssh() {
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "vagrant@${AGENT_VM_IP}" "$@"
}

# ── Verify VM is reachable ───────────────────────────────────────
echo "==> Checking agent VM connectivity (${AGENT_VM_IP})..."
if ! _ssh true 2>/dev/null; then
    echo "ERROR: Cannot SSH to agent VM. Run 'vagrant up agent' first." >&2
    exit 1
fi
echo "    OK"

# ── Sync binary ─────────────────────────────────────────────────
if [ "$SYNC_BINARY" = true ]; then
    if [ ! -f "$AGENT_BINARY" ]; then
        echo "ERROR: Binary not found at ${AGENT_BINARY}" >&2
        echo "       Run 'cargo build --release' first, or set AGENT_BINARY" >&2
        exit 1
    fi

    local_size=$(stat -c%s "$AGENT_BINARY" 2>/dev/null || stat -f%z "$AGENT_BINARY")
    local_size_mb=$(( local_size / 1048576 ))
    echo "==> Syncing binary to agent VM (${local_size_mb} MB)..."
    echo "    ${AGENT_BINARY} -> /usr/local/bin/ebpfsentinel-agent"

    # Stop running agent first
    _ssh "sudo pkill -f ebpfsentinel-agent 2>/dev/null || true"
    sleep 1

    # SCP to tmp then move (avoids permission issues during transfer)
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$AGENT_BINARY" "vagrant@${AGENT_VM_IP}:/tmp/ebpfsentinel-agent-new"

    _ssh "sudo mv /tmp/ebpfsentinel-agent-new /usr/local/bin/ebpfsentinel-agent && \
          sudo chmod 755 /usr/local/bin/ebpfsentinel-agent"

    # Verify
    remote_version="$(_ssh "/usr/local/bin/ebpfsentinel-agent --version 2>/dev/null || echo 'unknown'")"
    echo "    Installed: ${remote_version}"
    echo "==> Binary sync complete."
fi

# ── Sync Docker image ───────────────────────────────────────────
if [ "$SYNC_DOCKER" = true ]; then
    if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
        echo "ERROR: Docker image '${DOCKER_IMAGE}' not found locally." >&2
        echo "       Build it first: docker build -t ${DOCKER_IMAGE} ${PROJECT_ROOT}" >&2
        exit 1
    fi

    image_size="$(docker image inspect "$DOCKER_IMAGE" --format='{{.Size}}' 2>/dev/null)" || image_size=0
    image_size_mb=$(( image_size / 1048576 ))
    echo "==> Streaming Docker image '${DOCKER_IMAGE}' to agent VM (~${image_size_mb} MB)..."
    echo "    docker save | gzip | ssh docker load"

    docker save "$DOCKER_IMAGE" | gzip | _ssh 'gunzip | sudo docker load'

    # Verify
    remote_img="$(_ssh "sudo docker image ls --format '{{.Repository}}:{{.Tag}}' \
        | grep -F '${DOCKER_IMAGE}'" 2>/dev/null)" || true
    if [ -n "$remote_img" ]; then
        echo "    Loaded: ${remote_img}"
    fi
    echo "==> Docker image sync complete."
fi

echo ""
echo "==> All done. Agent VM is ready for testing."
