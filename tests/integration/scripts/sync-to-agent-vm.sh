#!/usr/bin/env bash
# sync-to-agent-vm.sh — Sync local build artifacts and/or Docker image to agent VM
#
# Pushes the locally-built agent binary, warden broker, eBPF objects and Docker
# image to the agent VM without rebuilding on the VM. Much faster than compiling
# in the VM.
#
# The warden and the eBPF objects are part of the default set on purpose: the
# agent self-unshares a userns and the warden delegates it a bpffs, and the
# objects are loaded from disk rather than embedded. Pushing only the agent
# leaves two thirds of the deployment stale, which reads as a product failure.
#
# Usage:
#   ./sync-to-agent-vm.sh              # sync agent + warden + eBPF objects + Docker image
#   ./sync-to-agent-vm.sh --binary     # sync agent binary only
#   ./sync-to-agent-vm.sh --warden     # sync warden broker only
#   ./sync-to-agent-vm.sh --ebpf       # sync eBPF objects only
#   ./sync-to-agent-vm.sh --docker     # sync Docker image only
#   ./sync-to-agent-vm.sh --binary --warden --ebpf   # flags combine
#
# Environment:
#   AGENT_VM_IP       Agent VM IP (default: 192.168.56.10)
#   AGENT_SSH_KEY     SSH key for agent VM (auto-detected from Vagrant)
#   AGENT_BINARY      Path to local binary (default: target/release/ebpfsentinel-agent)
#   WARDEN_BINARY     Path to local warden (default: target/release/warden)
#   EBPF_OBJ_DIR      Local eBPF object dir (default: target/bpfel-unknown-none/release)
#   DOCKER_IMAGE      Docker image name (default: ebpfsentinel:integration-test)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTEGRATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VAGRANT_DIR="${INTEGRATION_DIR}/vagrant"
PROJECT_ROOT="${INTEGRATION_DIR}/../.."

AGENT_VM_IP="${AGENT_VM_IP:-192.168.56.10}"
SSH_KEY="${AGENT_SSH_KEY:-}"
AGENT_BINARY="${AGENT_BINARY:-${PROJECT_ROOT}/target/release/ebpfsentinel-agent}"
WARDEN_BINARY="${WARDEN_BINARY:-${PROJECT_ROOT}/target/release/warden}"
EBPF_OBJ_DIR="${EBPF_OBJ_DIR:-${PROJECT_ROOT}/target/bpfel-unknown-none/release}"
DOCKER_IMAGE="${DOCKER_IMAGE:-ebpfsentinel:integration-test}"

# Where the VM expects each artifact. `EBPF_PROGRAM_DIR` in the VM helpers
# points at the object dir, so keep the two in step.
REMOTE_EBPF_DIR="/usr/local/lib/ebpfsentinel"

# THE LANE RESOLVES TWO DIFFERENT SETS OF PATHS, AND INSTALLING ONLY THE FIRST
# IS INDISTINGUISHABLE FROM A SUCCESSFUL SYNC. The API suites read the installed
# binary under /usr/local, but `_has_local_ebpf` in lib/ebpf_helpers.bash gates
# on ${PROJECT_ROOT}/target/release/ebpfsentinel-agent and runs whatever it
# finds there - and Vagrant excludes target/ from its rsync, so that tree is
# whatever was last built inside the VM. Push both, or an eBPF suite quietly
# validates a stale datapath while this script prints "ready for testing".
REMOTE_LANE_ROOT="${REMOTE_LANE_ROOT:-/home/vagrant/ebpfsentinel}"
REMOTE_LANE_BIN="${REMOTE_LANE_ROOT}/target/release"
REMOTE_LANE_EBPF="${REMOTE_LANE_ROOT}/target/bpfel-unknown-none/release"

# Mirror an installed artifact into the lane tree. Ownership goes back to
# vagrant so a later in-VM `cargo build` can still overwrite it.
_mirror_to_lane() {
    local src="$1" dest_dir="$2" name="$3"
    _ssh "sudo mkdir -p ${dest_dir} && sudo cp ${src} ${dest_dir}/${name} && \
          sudo chown vagrant:vagrant ${dest_dir}/${name} && \
          sudo chmod 755 ${dest_dir}/${name}"
}

SYNC_BINARY=true
SYNC_WARDEN=true
SYNC_EBPF=true
SYNC_DOCKER=true

# ── Parse args ──────────────────────────────────────────────────
# The first explicit flag clears the default set so flags can be combined
# (`--binary --warden` syncs exactly those two).
_selective=false
_select() {
    if [ "$_selective" = false ]; then
        SYNC_BINARY=false; SYNC_WARDEN=false; SYNC_EBPF=false; SYNC_DOCKER=false
        _selective=true
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)  _select; SYNC_BINARY=true; shift ;;
        --warden)  _select; SYNC_WARDEN=true; shift ;;
        --ebpf)    _select; SYNC_EBPF=true; shift ;;
        --docker)  _select; SYNC_DOCKER=true; shift ;;
        --help|-h)
            head -28 "$0" | grep '^#' | sed 's/^# \?//'
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

    # `local` is a function-only builtin: using it here would fail under
    # `set -e` before a single byte was copied.
    local_size=$(stat -c%s "$AGENT_BINARY" 2>/dev/null || stat -f%z "$AGENT_BINARY")
    local_size_mb=$(( local_size / 1048576 ))
    echo "==> Syncing binary to agent VM (${local_size_mb} MB)..."
    echo "    ${AGENT_BINARY} -> /usr/local/bin/ebpfsentinel-agent"

    # Stop running agent first. `pkill -x` matches the process name only:
    # `pkill -f` would also match this very ssh command line, kill the remote
    # shell, and abort the sync under `set -e` while still reporting progress.
    _ssh "sudo pkill -x ebpfsentinel-agent 2>/dev/null || true"
    sleep 1

    # SCP to tmp then move (avoids permission issues during transfer)
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$AGENT_BINARY" "vagrant@${AGENT_VM_IP}:/tmp/ebpfsentinel-agent-new"

    _ssh "sudo mv /tmp/ebpfsentinel-agent-new /usr/local/bin/ebpfsentinel-agent && \
          sudo chmod 755 /usr/local/bin/ebpfsentinel-agent"

    _mirror_to_lane /usr/local/bin/ebpfsentinel-agent "$REMOTE_LANE_BIN" ebpfsentinel-agent

    # Verify
    remote_version="$(_ssh "/usr/local/bin/ebpfsentinel-agent --version 2>/dev/null || echo 'unknown'")"
    echo "    Installed: ${remote_version}"

    # Both copies must be the same bytes, because which one runs depends on
    # which suite is running.
    lane_sum="$(_ssh "md5sum ${REMOTE_LANE_BIN}/ebpfsentinel-agent | cut -d' ' -f1")"
    installed_sum="$(_ssh "md5sum /usr/local/bin/ebpfsentinel-agent | cut -d' ' -f1")"
    if [ "$lane_sum" != "$installed_sum" ]; then
        echo "ERROR: lane copy differs from installed binary (${lane_sum} vs ${installed_sum})" >&2
        exit 1
    fi
    echo "    Mirrored: ${REMOTE_LANE_BIN}/ebpfsentinel-agent (same bytes)"
    echo "==> Binary sync complete."
fi

# ── Sync warden broker ──────────────────────────────────────────
if [ "$SYNC_WARDEN" = true ]; then
    if [ ! -f "$WARDEN_BINARY" ]; then
        echo "ERROR: Warden not found at ${WARDEN_BINARY}" >&2
        echo "       Run 'cargo build --release --bin warden' first, or set WARDEN_BINARY" >&2
        exit 1
    fi

    echo "==> Syncing warden to agent VM..."
    echo "    ${WARDEN_BINARY} -> /usr/local/bin/warden"

    _ssh "sudo pkill -x warden 2>/dev/null || true"
    sleep 1

    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "$WARDEN_BINARY" "vagrant@${AGENT_VM_IP}:/tmp/warden-new"

    _ssh "sudo mv /tmp/warden-new /usr/local/bin/warden && sudo chmod 755 /usr/local/bin/warden"

    # The warden has no --version flag, so compare sizes: that is enough to
    # catch the failure this check exists for (a stale binary left in place).
    warden_size=$(stat -c%s "$WARDEN_BINARY" 2>/dev/null || stat -f%z "$WARDEN_BINARY")
    remote_warden_size="$(_ssh "stat -c%s /usr/local/bin/warden")"
    if [ "$warden_size" != "$remote_warden_size" ]; then
        echo "ERROR: warden size mismatch (local ${warden_size}, remote ${remote_warden_size})" >&2
        exit 1
    fi
    # start_ebpf_agent looks for the warden beside the agent it chose, so the
    # lane tree needs its own copy for the same reason the agent does.
    _mirror_to_lane /usr/local/bin/warden "$REMOTE_LANE_BIN" warden

    echo "    Installed: ${remote_warden_size} bytes (matches local)"
    echo "==> Warden sync complete."
fi

# ── Sync eBPF objects ───────────────────────────────────────────
# The agent loads its programs from disk, so a rebuilt object that never
# reaches the VM silently leaves the previous datapath running.
if [ "$SYNC_EBPF" = true ]; then
    if [ ! -d "$EBPF_OBJ_DIR" ] || [ ! -f "${EBPF_OBJ_DIR}/xdp-firewall" ]; then
        echo "ERROR: eBPF objects not found in ${EBPF_OBJ_DIR}" >&2
        echo "       Run 'cargo xtask ebpf-build' first, or set EBPF_OBJ_DIR" >&2
        exit 1
    fi

    obj_count=$(find "$EBPF_OBJ_DIR" -maxdepth 1 -type f ! -name '*.d' | wc -l)
    echo "==> Syncing ${obj_count} eBPF objects to agent VM..."
    echo "    ${EBPF_OBJ_DIR} -> ${REMOTE_EBPF_DIR}"

    _ssh "sudo mkdir -p ${REMOTE_EBPF_DIR} && sudo chmod 755 ${REMOTE_EBPF_DIR}"

    # Stage in /tmp then move as root: the destination is root-owned.
    _ssh "rm -rf /tmp/ebpf-objs-new && mkdir -p /tmp/ebpf-objs-new"
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "${EBPF_OBJ_DIR}"/* "vagrant@${AGENT_VM_IP}:/tmp/ebpf-objs-new/" >/dev/null

    _ssh "sudo find /tmp/ebpf-objs-new -maxdepth 1 -name '*.d' -delete; \
          sudo cp /tmp/ebpf-objs-new/* ${REMOTE_EBPF_DIR}/ && \
          sudo chmod 644 ${REMOTE_EBPF_DIR}/* && rm -rf /tmp/ebpf-objs-new"

    # Same split as the binaries: EBPF_PROGRAM_DIR points into the lane tree
    # whenever the lane picked the lane-tree agent, so mirror the objects too.
    # A stale object here is the quietest failure of all - it loads, it runs,
    # and it is the previous datapath.
    _ssh "sudo mkdir -p ${REMOTE_LANE_EBPF} && \
          sudo cp ${REMOTE_EBPF_DIR}/* ${REMOTE_LANE_EBPF}/ && \
          sudo chown -R vagrant:vagrant ${REMOTE_LANE_EBPF}"

    remote_count="$(_ssh "ls -1 ${REMOTE_EBPF_DIR} | wc -l")"
    lane_count="$(_ssh "ls -1 ${REMOTE_LANE_EBPF} | wc -l")"
    if [ "$remote_count" != "$lane_count" ]; then
        echo "ERROR: lane object count differs (${lane_count} vs ${remote_count})" >&2
        exit 1
    fi
    echo "    Installed: ${remote_count} objects (mirrored to ${REMOTE_LANE_EBPF})"
    echo "==> eBPF object sync complete."
fi

# ── Sync Docker image ───────────────────────────────────────────
if [ "$SYNC_DOCKER" = true ]; then
    if ! docker image inspect "$DOCKER_IMAGE" &>/dev/null; then
        echo "ERROR: Docker image '${DOCKER_IMAGE}' not found locally." >&2
        echo "       Build it first: docker build -f ${PROJECT_ROOT}/Dockerfile.agent -t ${DOCKER_IMAGE} ${PROJECT_ROOT}" >&2
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
