#!/usr/bin/env bash
# setup.sh — Vagrant provisioner: generate certs/keys, install agent, prepare configs
set -euxo pipefail

PROJECT_DIR="/home/vagrant/ebpfsentinel"
INTEGRATION_DIR="${PROJECT_DIR}/tests/integration"
CERT_DIR="/tmp/ebpfsentinel-test-certs"
JWT_DIR="/tmp/ebpfsentinel-test-jwt"
DATA_DIR="/tmp/ebpfsentinel-test-data"
AGENT_INSTALL_DIR="/usr/local/bin"
EBPF_INSTALL_DIR="/usr/local/lib/ebpfsentinel"
IMAGE_TAR="${PROJECT_DIR}/ebpfsentinel-image.tar"

export PATH="${HOME}/.cargo/bin:${PATH}"

# ── Generate TLS certificates ─────────────────────────────────────
echo "=== Generating TLS certificates ==="
bash "${INTEGRATION_DIR}/scripts/generate-certs.sh" --out-dir "$CERT_DIR"

# ── Generate JWT keys and tokens ───────────────────────────────────
echo "=== Generating JWT keys and tokens ==="
bash "${INTEGRATION_DIR}/scripts/generate-jwt-keys.sh" --out-dir "$JWT_DIR"

# ── Install agent binary ─────────────────────────────────────────
# Priority:
#   1. Docker image extraction (fastest — pre-built image tar)
#   2. Pre-built binary from synced target/ directory
#   3. Build from source (slowest, opt-in via EBPF_BUILD_FROM_SOURCE=true)

install_from_docker_image() {
    echo "=== Extracting agent from Docker image ==="
    sudo docker load -i "$IMAGE_TAR"

    local container_id
    container_id="$(sudo docker create ebpfsentinel-agent:latest true)"

    sudo mkdir -p "$EBPF_INSTALL_DIR"
    sudo docker cp "${container_id}:/usr/local/bin/ebpfsentinel-agent" "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"
    sudo docker cp "${container_id}:/usr/local/lib/ebpfsentinel/." "${EBPF_INSTALL_DIR}/" 2>/dev/null || true
    sudo chmod +x "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"

    sudo docker rm "$container_id" >/dev/null
    echo "  Installed agent from Docker image"
}

install_from_prebuilt() {
    echo "=== Using pre-built agent binary ==="
    local src="${PROJECT_DIR}/target/release/ebpfsentinel-agent"
    sudo cp "$src" "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"
    sudo chmod +x "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"

    # Copy eBPF programs if present
    local ebpf_src="${PROJECT_DIR}/target/bpfel-unknown-none/release"
    if [ -d "$ebpf_src" ]; then
        sudo mkdir -p "$EBPF_INSTALL_DIR"
        sudo cp -r "${ebpf_src}/." "${EBPF_INSTALL_DIR}/"
    fi
    echo "  Installed agent from pre-built binary"
}

build_from_source() {
    echo "=== Building eBPF programs ==="
    if rustup run nightly rustc --version &>/dev/null 2>&1; then
        (cd "$PROJECT_DIR" && cargo xtask ebpf-build 2>/dev/null) || echo "eBPF build skipped (non-fatal)"
    fi

    echo "=== Building agent binary ==="
    (cd "$PROJECT_DIR" && cargo build --release --bin ebpfsentinel-agent)
}

if [ "${EBPF_BUILD_FROM_SOURCE:-false}" = "true" ]; then
    build_from_source
elif [ -f "$IMAGE_TAR" ] && command -v docker &>/dev/null; then
    install_from_docker_image
elif [ -x "${PROJECT_DIR}/target/release/ebpfsentinel-agent" ]; then
    install_from_prebuilt
else
    echo "No pre-built binary or Docker image found — building from source"
    build_from_source
fi

# ── Prepare runtime configs from templates ─────────────────────────
echo "=== Preparing config files ==="
mkdir -p "$DATA_DIR"

for template in "${INTEGRATION_DIR}/fixtures/"config-*.yaml; do
    basename="$(basename "$template")"
    dest="/tmp/ebpfsentinel-prepared-${basename}"

    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__CERT_PATH__|${CERT_DIR}/server.pem|g" \
        -e "s|__KEY_PATH__|${CERT_DIR}/server-key.pem|g" \
        -e "s|__JWT_PUBKEY__|${JWT_DIR}/jwt-public.pem|g" \
        -e "s|__INTERFACE__|lo|g" \
        "$template" > "$dest"

    echo "  Prepared: ${dest}"
done

echo ""
echo "=== Setup complete ==="
echo "Run tests with: cd ${INTEGRATION_DIR} && bats --timing suites/"
