#!/usr/bin/env bash
# setup.sh — Single-VM provisioner (alternative to 2-VM setup)
#
# Runs on the agent VM only. Builds from source, generates certs/keys,
# prepares configs, installs BATS. Agent runs locally on loopback.
#
# Usage (from Vagrantfile or direct):
#   PROVISION_MODE=fast bash provision/setup.sh
set -euxo pipefail

PROVISION_MODE="${PROVISION_MODE:-fast}"

PROJECT_DIR="/home/vagrant/ebpfsentinel"
INTEGRATION_DIR="${PROJECT_DIR}/tests/integration"
CERT_DIR="/tmp/ebpfsentinel-test-certs"
JWT_DIR="/tmp/ebpfsentinel-test-jwt"
DATA_DIR="/tmp/ebpfsentinel-test-data"
AGENT_INSTALL_DIR="/usr/local/bin"
EBPF_INSTALL_DIR="/usr/local/lib/ebpfsentinel"

export PATH="${HOME}/.cargo/env:${HOME}/.cargo/bin:${PATH}"
source "${HOME}/.cargo/env" 2>/dev/null || true

# ── Generate TLS certificates ─────────────────────────────────────
echo "=== Generating TLS certificates ==="
bash "${INTEGRATION_DIR}/scripts/generate-certs.sh" --out-dir "$CERT_DIR"

# ── Generate JWT keys and tokens ───────────────────────────────────
echo "=== Generating JWT keys and tokens ==="
bash "${INTEGRATION_DIR}/scripts/generate-jwt-keys.sh" --out-dir "$JWT_DIR"

# ── Install BATS ──────────────────────────────────────────────────
echo "=== Installing BATS ==="
if ! command -v bats &>/dev/null; then
    git clone --depth 1 https://github.com/bats-core/bats-core.git /tmp/bats-core
    sudo /tmp/bats-core/install.sh /usr/local
    rm -rf /tmp/bats-core
fi

# ── Build from source ─────────────────────────────────────────────
echo "=== Building from source ==="

echo "  Building eBPF programs..."
(cd "$PROJECT_DIR" && cargo xtask ebpf-build)

echo "  Building agent binary..."
(cd "$PROJECT_DIR" && cargo build --release --bin ebpfsentinel-agent)

# Install
sudo cp "${PROJECT_DIR}/target/release/ebpfsentinel-agent" "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"
sudo chmod +x "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"

local_ebpf="${PROJECT_DIR}/target/bpfel-unknown-none/release"
if [ -d "$local_ebpf" ]; then
    sudo mkdir -p "$EBPF_INSTALL_DIR"
    sudo cp -r "${local_ebpf}/." "${EBPF_INSTALL_DIR}/"
fi

# Docker image (full mode only)
if [ "$PROVISION_MODE" = "full" ] && command -v docker &>/dev/null; then
    echo "  Building Docker image..."
    (cd "$PROJECT_DIR" && sudo docker build -t ebpfsentinel-agent:latest .) || \
        echo "  WARNING: Docker image build failed (non-fatal)"
fi

# ── Prepare runtime configs ───────────────────────────────────────
echo "=== Preparing config files ==="
mkdir -p "$DATA_DIR"

for template in "${INTEGRATION_DIR}/fixtures/"config-*.yaml; do
    [ -f "$template" ] || continue
    basename="$(basename "$template")"
    dest="/tmp/ebpfsentinel-prepared-${basename}"

    sed -e "s|__DATA_DIR__|${DATA_DIR}|g" \
        -e "s|__CERT_PATH__|${CERT_DIR}/server.pem|g" \
        -e "s|__KEY_PATH__|${CERT_DIR}/server-key.pem|g" \
        -e "s|__JWT_PUBKEY__|${JWT_DIR}/jwt-public.pem|g" \
        -e "s|__INTERFACE__|lo|g" \
        "$template" > "$dest"
done

# Copy STIX fixtures
if [ -d "${INTEGRATION_DIR}/fixtures/stix" ]; then
    cp -r "${INTEGRATION_DIR}/fixtures/stix" "${DATA_DIR}/stix"
fi

echo ""
echo "=== Setup complete (single-VM mode) ==="
echo "  Run tests: cd ${INTEGRATION_DIR} && sudo bats --timing suites/"
