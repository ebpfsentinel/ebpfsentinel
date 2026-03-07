#!/usr/bin/env bash
# push-docker-image.sh — Build Docker image on host and push to agent VM
#
# Builds ebpfsentinel:integration-test locally (where CPU/RAM are plentiful),
# then streams the image to the agent VM via SSH + docker load.
#
# Usage:
#   ./push-docker-image.sh                    # build + push
#   ./push-docker-image.sh --no-cache         # build without Docker cache
#   ./push-docker-image.sh --skip-build       # push existing image only
#   ./push-docker-image.sh --image myimg:tag  # use a custom image name

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}/../../.."
VAGRANT_DIR="${SCRIPT_DIR}/../vagrant"

IMAGE_NAME="ebpfsentinel:integration-test"
AGENT_VM_IP="${AGENT_VM_IP:-192.168.56.10}"
SSH_KEY="${AGENT_SSH_KEY:-${HOME}/.ssh/agent_key}"
SKIP_BUILD=false
DOCKER_BUILD_ARGS=()

# ── Parse args ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-cache)
            DOCKER_BUILD_ARGS+=(--no-cache)
            shift ;;
        --skip-build)
            SKIP_BUILD=true
            shift ;;
        --image)
            IMAGE_NAME="$2"
            shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--no-cache] [--skip-build] [--image name:tag]"
            exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1 ;;
    esac
done

# ── Resolve SSH key ──────────────────────────────────────────────
# Try Vagrant's insecure key if the custom key doesn't exist
if [ ! -f "$SSH_KEY" ]; then
    VAGRANT_KEY="$(cd "$VAGRANT_DIR" && vagrant ssh-config agent 2>/dev/null | grep IdentityFile | awk '{print $2}' | head -1)" || true
    if [ -n "$VAGRANT_KEY" ] && [ -f "$VAGRANT_KEY" ]; then
        SSH_KEY="$VAGRANT_KEY"
    else
        echo "ERROR: SSH key not found at $SSH_KEY" >&2
        echo "       Set AGENT_SSH_KEY or ensure 'vagrant ssh-config agent' works" >&2
        exit 1
    fi
fi

SSH_CMD="ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10 vagrant@${AGENT_VM_IP}"

# ── Verify agent VM reachable ────────────────────────────────────
echo "==> Checking agent VM connectivity (${AGENT_VM_IP})..."
if ! $SSH_CMD true 2>/dev/null; then
    echo "ERROR: Cannot SSH to agent VM at ${AGENT_VM_IP}" >&2
    echo "       Ensure 'vagrant up agent' has been run" >&2
    exit 1
fi

# ── Build ────────────────────────────────────────────────────────
if [ "$SKIP_BUILD" = false ]; then
    echo "==> Building Docker image '${IMAGE_NAME}' from ${PROJECT_ROOT}..."
    echo "    (this may take a while on first build)"
    docker build --network=host "${DOCKER_BUILD_ARGS[@]}" -t "$IMAGE_NAME" "$PROJECT_ROOT"
    echo "==> Build complete."
else
    # Verify image exists locally
    if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
        echo "ERROR: Image '${IMAGE_NAME}' not found locally. Run without --skip-build first." >&2
        exit 1
    fi
    echo "==> Skipping build, using existing image '${IMAGE_NAME}'."
fi

# ── Push to agent VM ─────────────────────────────────────────────
echo "==> Streaming image '${IMAGE_NAME}' to agent VM (${AGENT_VM_IP})..."
echo "    docker save | ssh docker load (no intermediate file)"

# Get image size for progress info
IMAGE_SIZE="$(docker image inspect "$IMAGE_NAME" --format='{{.Size}}' 2>/dev/null)" || IMAGE_SIZE=0
IMAGE_SIZE_MB=$(( IMAGE_SIZE / 1048576 ))
echo "    Image size: ~${IMAGE_SIZE_MB} MB"

# Stream with gzip compression for faster transfer over VirtualBox network
docker save "$IMAGE_NAME" | gzip | $SSH_CMD 'gunzip | sudo docker load'

echo "==> Image '${IMAGE_NAME}' loaded on agent VM."

# ── Verify ───────────────────────────────────────────────────────
echo "==> Verifying image on agent VM..."
REMOTE_IMAGE="$($SSH_CMD "sudo docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -F '${IMAGE_NAME}'" 2>/dev/null)" || true

if [ -n "$REMOTE_IMAGE" ]; then
    echo "==> SUCCESS: ${REMOTE_IMAGE} available on agent VM"
else
    echo "WARNING: Image not found in 'docker image ls' on agent VM (may use a different tag)" >&2
fi
