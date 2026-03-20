#!/usr/bin/env bash
# setup-agent.sh — Fully autonomous provisioner for the agent VM (192.168.56.10)
#
# Builds everything from source (agent + eBPF programs), generates certs/keys,
# prepares configs, installs BATS, and verifies eBPF programs load.
#
# Modes (via PROVISION_MODE env var):
#   "full"   — build from source + Docker image (default, ~5min)
#   "fast"   — build from source only, skip Docker (saves ~2min)
#   "docker" — extract from Docker image only (requires pre-built image tar)
#
# Environment:
#   PROVISION_MODE        — "full" (default), "fast", or "docker"
#   EBPF_SKIP_VALIDATION  — set to "true" to skip the eBPF load verification step
set -euxo pipefail

PROVISION_MODE="${PROVISION_MODE:-full}"

PROJECT_DIR="/home/vagrant/ebpfsentinel"
INTEGRATION_DIR="${PROJECT_DIR}/tests/integration"
CERT_DIR="/tmp/ebpfsentinel-test-certs"
JWT_DIR="/tmp/ebpfsentinel-test-jwt"
DATA_DIR="/tmp/ebpfsentinel-test-data"
AGENT_INSTALL_DIR="/usr/local/bin"
EBPF_INSTALL_DIR="/usr/local/lib/ebpfsentinel"
IMAGE_TAR="${PROJECT_DIR}/ebpfsentinel-image.tar"
AGENT_IFACE="eth1"

export PATH="${HOME}/.cargo/env:${HOME}/.cargo/bin:${PATH}"
source "${HOME}/.cargo/env" 2>/dev/null || true

# ── Generate TLS certificates ─────────────────────────────────────
echo "=== [1/8] Generating TLS certificates ==="
bash "${INTEGRATION_DIR}/scripts/generate-certs.sh" --out-dir "$CERT_DIR"

# ── Generate JWT keys and tokens ───────────────────────────────────
echo "=== [2/8] Generating JWT keys and tokens ==="
bash "${INTEGRATION_DIR}/scripts/generate-jwt-keys.sh" --out-dir "$JWT_DIR"

# ── Install BATS (needed for local test execution) ─────────────────
echo "=== [3/8] Installing BATS ==="
if ! command -v bats &>/dev/null; then
    git clone --depth 1 https://github.com/bats-core/bats-core.git /tmp/bats-core
    sudo /tmp/bats-core/install.sh /usr/local
    rm -rf /tmp/bats-core
fi
bats --version

# ── Install grpcurl ────────────────────────────────────────────────
echo "=== [4/8] Installing grpcurl ==="
if ! command -v grpcurl &>/dev/null; then
    GRPCURL_VERSION="1.9.1"
    ARCH=$(dpkg --print-architecture)
    [ "$ARCH" = "amd64" ] && GRPCURL_ARCH="x86_64" || GRPCURL_ARCH="$ARCH"
    curl -sSL "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_${GRPCURL_ARCH}.tar.gz" | \
        sudo tar -xz -C /usr/local/bin grpcurl
fi

# ── Build / install agent + eBPF programs ──────────────────────────
install_from_prebuilt() {
    local src="${PROJECT_DIR}/target/release/ebpfsentinel-agent"
    sudo cp "$src" "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"
    sudo chmod +x "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"

    local ebpf_src="${PROJECT_DIR}/target/bpfel-unknown-none/release"
    if [ -d "$ebpf_src" ]; then
        sudo mkdir -p "$EBPF_INSTALL_DIR"
        sudo cp -r "${ebpf_src}/." "${EBPF_INSTALL_DIR}/"
    fi
}

install_from_docker_image() {
    sudo docker load -i "$IMAGE_TAR"
    local container_id
    container_id="$(sudo docker create ebpfsentinel-agent:latest true)"
    sudo mkdir -p "$EBPF_INSTALL_DIR"
    sudo docker cp "${container_id}:/usr/local/bin/ebpfsentinel-agent" "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"
    sudo docker cp "${container_id}:/usr/local/lib/ebpfsentinel/." "${EBPF_INSTALL_DIR}/" 2>/dev/null || true
    sudo chmod +x "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"
    sudo docker rm "$container_id" >/dev/null
}

build_from_source() {
    echo "  Building eBPF programs (nightly)..."
    (cd "$PROJECT_DIR" && cargo xtask ebpf-build)

    echo "  Building agent binary (release)..."
    (cd "$PROJECT_DIR" && cargo build --release --bin ebpfsentinel-agent)

    install_from_prebuilt
}

echo "=== [5/8] Installing agent (mode: ${PROVISION_MODE}) ==="
case "$PROVISION_MODE" in
    docker)
        if [ -f "$IMAGE_TAR" ] && command -v docker &>/dev/null; then
            install_from_docker_image
        else
            echo "ERROR: Docker mode requires ${IMAGE_TAR} and docker"
            exit 1
        fi
        ;;
    fast)
        build_from_source
        ;;
    full)
        build_from_source
        # Also build Docker image for Docker-based tests
        if command -v docker &>/dev/null; then
            echo "  Building Docker image..."
            (cd "$PROJECT_DIR" && sudo docker build -t ebpfsentinel-agent:latest .) || \
                echo "  WARNING: Docker image build failed (non-fatal)"
        fi
        ;;
    *)
        echo "ERROR: Unknown PROVISION_MODE=${PROVISION_MODE}"
        exit 1
        ;;
esac

# Verify binary is installed
"${AGENT_INSTALL_DIR}/ebpfsentinel-agent" --version || true

# Verify eBPF programs are present
echo "  eBPF programs:"
ls -1 "${EBPF_INSTALL_DIR}/" 2>/dev/null || echo "  WARNING: No eBPF programs found in ${EBPF_INSTALL_DIR}"

# ── Start iperf3 server ────────────────────────────────────────────
echo "=== [6/8] Starting iperf3 server ==="
pkill -f "iperf3 -s" 2>/dev/null || true
if command -v iperf3 &>/dev/null; then
    iperf3 -s -B 192.168.56.10 -p 5201 -D
    echo "  iperf3 listening on 192.168.56.10:5201"
fi

# ── Prepare runtime configs from templates ─────────────────────────
echo "=== [7/8] Preparing config files ==="
mkdir -p "$DATA_DIR"

for template in "${INTEGRATION_DIR}/fixtures/"config-*.yaml; do
    [ -f "$template" ] || continue
    basename="$(basename "$template")"
    dest="/tmp/ebpfsentinel-prepared-${basename}"

    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__CERT_PATH__|${CERT_DIR}/server.pem|g" \
        -e "s|__KEY_PATH__|${CERT_DIR}/server-key.pem|g" \
        -e "s|__JWT_PUBKEY__|${JWT_DIR}/jwt-public.pem|g" \
        -e "s|__INTERFACE__|${AGENT_IFACE}|g" \
        "$template" > "$dest"

    echo "  Prepared: ${dest}"
done

# Also prepare STIX fixture directory (for suite 36)
if [ -d "${INTEGRATION_DIR}/fixtures/stix" ]; then
    cp -r "${INTEGRATION_DIR}/fixtures/stix" "${DATA_DIR}/stix"
    echo "  Copied STIX fixtures to ${DATA_DIR}/stix"
fi

# ── Validate eBPF load capability ──────────────────────────────────
echo "=== [8/8] Validating eBPF environment ==="
if [ "${EBPF_SKIP_VALIDATION:-false}" = "true" ]; then
    echo "  Skipping eBPF validation (EBPF_SKIP_VALIDATION=true)"
else
    # Quick smoke test: start agent, check eBPF loads, stop
    SMOKE_CONFIG="/tmp/ebpfsentinel-prepared-config-minimal.yaml"
    if [ -f "$SMOKE_CONFIG" ]; then
        echo "  Starting smoke test (5s timeout)..."
        sudo "${AGENT_INSTALL_DIR}/ebpfsentinel-agent" --config "$SMOKE_CONFIG" \
            > /tmp/ebpfsentinel-smoke.log 2>&1 &
        SMOKE_PID=$!
        sleep 3

        if kill -0 "$SMOKE_PID" 2>/dev/null; then
            # Check if eBPF loaded
            if grep -q '"ebpf_loaded":true\|eBPF programs loaded' /tmp/ebpfsentinel-smoke.log 2>/dev/null; then
                echo "  eBPF programs loaded successfully"
            elif sudo bpftool prog list 2>/dev/null | grep -q 'xdp\|tc_cls'; then
                echo "  eBPF programs detected via bpftool"
            else
                echo "  WARNING: eBPF programs may not have loaded (check kernel BTF support)"
                echo "  Kernel: $(uname -r)"
                echo "  BTF: $(ls /sys/kernel/btf/vmlinux 2>/dev/null && echo 'present' || echo 'MISSING')"
            fi
            sudo kill "$SMOKE_PID" 2>/dev/null || true
            wait "$SMOKE_PID" 2>/dev/null || true
        else
            echo "  WARNING: Agent smoke test exited early"
            tail -5 /tmp/ebpfsentinel-smoke.log 2>/dev/null || true
        fi
        rm -f /tmp/ebpfsentinel-smoke.log
    else
        echo "  Skipping smoke test (no minimal config)"
    fi
fi

# ── Mark agent VM as ready ─────────────────────────────────────────
touch /tmp/ebpfsentinel-agent-ready

echo ""
echo "============================================"
echo "  Agent VM setup complete"
echo "============================================"
echo "  Mode:      ${PROVISION_MODE}"
echo "  Binary:    ${AGENT_INSTALL_DIR}/ebpfsentinel-agent"
echo "  eBPF:      ${EBPF_INSTALL_DIR}/"
echo "  Interface: ${AGENT_IFACE}"
echo "  Certs:     ${CERT_DIR}"
echo "  JWT keys:  ${JWT_DIR}"
echo "  Configs:   /tmp/ebpfsentinel-prepared-config-*.yaml"
echo "  iperf3:    192.168.56.10:5201"
echo "  BATS:      $(which bats)"
echo "  Kernel:    $(uname -r)"
echo "  BTF:       $(ls /sys/kernel/btf/vmlinux 2>/dev/null && echo 'present' || echo 'MISSING')"
echo ""
echo "Run tests locally:"
echo "  cd ${INTEGRATION_DIR}"
echo "  sudo bats --timing suites/"
echo ""
