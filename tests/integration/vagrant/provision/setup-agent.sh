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
# Wait for DNS + outbound connectivity before any github fetch. The VMware
# NAT DNS resolver can lag a few seconds after boot, which otherwise breaks
# the first `git clone`/`curl` to github.com mid-provision.
wait_for_network() {
    for _ in $(seq 1 30); do
        getent hosts github.com >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "WARNING: DNS/network not ready after 60s; continuing anyway" >&2
}

echo "=== [3/8] Installing BATS ==="
wait_for_network
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

# ── Load kernel modules exposing eBPF kfuncs ───────────────────────
# xdp-firewall uses the conntrack lookup kfuncs (bpf_xdp_ct_lookup),
# tc-ids uses the FOU/GUE encap kfuncs (bpf_skb_get_fou_encap) and
# tc-nat-ingress/egress use the xfrm interface kfuncs
# (bpf_skb_get_xfrm_info). Those kfuncs are registered by the
# `nf_conntrack`, `fou` and `xfrm_interface` modules; loading the modules
# publishes their BTF under /sys/kernel/btf/<module> so the agent's kfunc
# resolver can bind them at program-load time. Without nf_conntrack the
# xdp-firewall load fails ("kfunc bpf_xdp_ct_lookup not found") and the
# agent stays in degraded mode (ebpf_loaded=false), which skips the eBPF
# suites. Persisted across reboot via modules-load.d.
echo "=== [5/9] Loading kernel modules for eBPF kfuncs ==="
sudo tee /etc/modules-load.d/ebpfsentinel-kfuncs.conf >/dev/null <<'KMODS'
nf_conntrack
fou
fou6
xfrm_interface
KMODS
for kmod in nf_conntrack fou fou6 xfrm_interface; do
    sudo modprobe "$kmod" 2>/dev/null || echo "    NOTE: modprobe ${kmod} deferred until reboot"
done

# The `conntrack` userspace CLI (separate from the nf_conntrack kmod above) is
# how suite 51 reads/kills kernel CT entries; `ensure_conntrack_tool` skips the
# whole CT-kill suite when it's absent. The kmod publishes the kfunc BTF; this
# package provides the /usr/sbin/conntrack tool the test drives.
sudo apt-get install -y conntrack >/dev/null 2>&1 || true

# ── Build / install agent + eBPF programs ──────────────────────────
install_from_prebuilt() {
    local src="${PROJECT_DIR}/target/release/ebpfsentinel-agent"
    sudo cp "$src" "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"
    sudo chmod +x "${AGENT_INSTALL_DIR}/ebpfsentinel-agent"

    # The agent loads eBPF EXCLUSIVELY through a BPF token. The combined-unit
    # launcher starts the warden broker (bpffs delegation), then execs the agent,
    # which self-unshares a userns and creates the token. Without them the agent
    # starts in "API-only mode (no eBPF)" and every datapath suite sees
    # ebpf_loaded=false — so BOTH the launcher and the warden MUST be installed
    # alongside the agent (the launcher finds `warden` as a sibling).
    local warden_src="${PROJECT_DIR}/target/release/warden"
    local launch_src="${PROJECT_DIR}/target/release/ebpfsentinel-launch"
    if [ -f "$warden_src" ]; then
        sudo cp "$warden_src" "${AGENT_INSTALL_DIR}/warden"
        sudo chmod +x "${AGENT_INSTALL_DIR}/warden"
    fi
    if [ -f "$launch_src" ]; then
        sudo cp "$launch_src" "${AGENT_INSTALL_DIR}/ebpfsentinel-launch"
        sudo chmod +x "${AGENT_INSTALL_DIR}/ebpfsentinel-launch"
    fi

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
    # The launcher + warden are required to load eBPF (BPF token) — see install_from_prebuilt.
    sudo docker cp "${container_id}:/usr/local/bin/warden" "${AGENT_INSTALL_DIR}/warden" 2>/dev/null || true
    sudo docker cp "${container_id}:/usr/local/bin/ebpfsentinel-launch" "${AGENT_INSTALL_DIR}/ebpfsentinel-launch" 2>/dev/null || true
    sudo docker cp "${container_id}:/usr/local/lib/ebpfsentinel/." "${EBPF_INSTALL_DIR}/" 2>/dev/null || true
    sudo chmod +x "${AGENT_INSTALL_DIR}/ebpfsentinel-agent" "${AGENT_INSTALL_DIR}/warden" "${AGENT_INSTALL_DIR}/ebpfsentinel-launch" 2>/dev/null || true
    sudo docker rm "$container_id" >/dev/null
}

build_from_source() {
    echo "  Building eBPF programs (nightly)..."
    (cd "$PROJECT_DIR" && cargo xtask ebpf-build)

    echo "  Building agent binary (release)..."
    (cd "$PROJECT_DIR" && cargo build --release --bin ebpfsentinel-agent)

    echo "  Building warden broker + combined-unit launcher (release)..."
    (cd "$PROJECT_DIR" && cargo build --release --bin warden --bin ebpfsentinel-launch)

    install_from_prebuilt
}

echo "=== [6/9] Installing agent (mode: ${PROVISION_MODE}) ==="
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
            (cd "$PROJECT_DIR" && sudo docker build -f Dockerfile.agent -t ebpfsentinel-agent:latest .) || \
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
echo "=== [7/9] Starting iperf3 server ==="
pkill -f "iperf3 -s" 2>/dev/null || true
if command -v iperf3 &>/dev/null; then
    iperf3 -s -B 192.168.56.10 -p 5201 -D
    echo "  iperf3 listening on 192.168.56.10:5201"
fi

# ── Prepare runtime configs from templates ─────────────────────────
echo "=== [8/9] Preparing config files ==="
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
echo "=== [9/9] Validating eBPF environment ==="
if [ "${EBPF_SKIP_VALIDATION:-false}" = "true" ]; then
    echo "  Skipping eBPF validation (EBPF_SKIP_VALIDATION=true)"
else
    # Quick smoke test: start agent, check eBPF loads, stop
    SMOKE_CONFIG="/tmp/ebpfsentinel-prepared-config-minimal.yaml"
    if [ -f "$SMOKE_CONFIG" ]; then
        echo "  Starting smoke test (5s timeout)..."
        # Agent refuses world-readable config; match the 640 the bats harness sets.
        sudo chmod 640 "$SMOKE_CONFIG"
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

# ── JWKS/JWT verification deps (suite 39) ──────────────────────────
# 39-agent-jwks signs an EdDSA JWT and serves a matching JWKS to prove the
# auth middleware accepts it. The helper scripts call the system `python3`
# directly (build_eddsa_jwks.py needs `cryptography`, mint_eddsa_jwt.py needs
# PyJWT), so both modules must be importable from the system interpreter — a
# venv won't do, the suite hard-codes bare python3. Install via apt to dodge
# PEP-668 (externally-managed-environment) on the system Python.
echo "=== Installing JWKS/JWT deps (python3-jwt, python3-cryptography) ==="
sudo apt-get install -y python3-jwt python3-cryptography >/dev/null 2>&1 || true
echo "  jwt: $(python3 -c 'import jwt; print(jwt.__version__)' 2>&1)" \
     "| cryptography: $(python3 -c 'import cryptography; print(cryptography.__version__)' 2>&1)"

# ── OpenSSL 3.5 (PQ-hybrid client for suite 61) ────────────────────
# 61-pqc-handshake drives an X25519MLKEM768 handshake against the agent's PQ
# TLS server. The hybrid named group needs OpenSSL >= 3.5, which Ubuntu 24.04
# does not package, so build it to a private prefix (/opt/openssl-3.5) without
# touching the system openssl. The suite auto-detects this build and only then
# runs the PQ-handshake assertions (otherwise they skip). Idempotent: skip the
# ~5-minute build if the binary already advertises the group.
if { /opt/openssl-3.5/bin/openssl list -groups 2>/dev/null; \
     /opt/openssl-3.5/bin/openssl list -kem-algorithms 2>/dev/null; } \
     | grep -q 'X25519MLKEM768'; then
    echo "=== OpenSSL 3.5 PQ client already present ==="
else
    echo "=== Building OpenSSL 3.5 (PQ-hybrid client for suite 61) ==="
    OSSL_VER="3.5.0"
    sudo apt-get install -y build-essential perl wget >/dev/null 2>&1 || true
    tmp_ossl="$(mktemp -d)"
    if wget -qO "${tmp_ossl}/openssl.tar.gz" \
        "https://github.com/openssl/openssl/releases/download/openssl-${OSSL_VER}/openssl-${OSSL_VER}.tar.gz"; then
        tar -xzf "${tmp_ossl}/openssl.tar.gz" -C "${tmp_ossl}"
        (
            cd "${tmp_ossl}/openssl-${OSSL_VER}" || exit 1
            # rpath so the binary loads its own libcrypto/libssl 3.5 rather than
            # the system 3.0 (otherwise: "version OPENSSL_3.5.0 not found").
            ./Configure --prefix=/opt/openssl-3.5 --openssldir=/opt/openssl-3.5 \
                --libdir=lib no-docs "-Wl,-rpath,/opt/openssl-3.5/lib" >/dev/null 2>&1
            make -j"$(nproc)" >/dev/null 2>&1
            sudo make install_sw >/dev/null 2>&1
        )
        rm -rf "${tmp_ossl}"
        echo "  openssl: $(/opt/openssl-3.5/bin/openssl version 2>&1)" \
             "| MLKEM: $(/opt/openssl-3.5/bin/openssl list -groups 2>/dev/null | grep -c X25519MLKEM768)"
    else
        echo "  WARN: openssl ${OSSL_VER} download failed — suite 61 PQ tests will skip"
        rm -rf "${tmp_ossl}"
    fi
fi

# ── Scapy venv (agent-local netns suites) ──────────────────────────
# The agent-local (netns) suites — VIP-announcer ARP probes, byte-level
# scrub, DSR/Maglev — craft raw frames with scapy on the agent itself.
# lib/ebpf_helpers.bash resolves EBPF_SCAPY_PY=/opt/scapy-venv/bin/python3;
# without the venv those suites silently skip. Pin matches setup-attacker.sh.
echo "=== Installing scapy venv ==="
sudo apt-get install -y python3-venv python3-pip >/dev/null 2>&1 || true
sudo mkdir -p /opt/scapy-venv && sudo chown "${USER}:${USER}" /opt/scapy-venv
[ -d /opt/scapy-venv/bin ] || python3 -m venv /opt/scapy-venv
/opt/scapy-venv/bin/pip install --upgrade pip >/dev/null
/opt/scapy-venv/bin/pip install "scapy==2.7.0" >/dev/null
echo "  scapy: $(/opt/scapy-venv/bin/python3 -c 'import scapy; print(scapy.__version__)' 2>&1)"

# ── Reclaim build space ────────────────────────────────────────────
# The VM builds from source on a ~31G root disk. Leaving the docker builder
# cache and apt/journal cruft behind once filled the disk to 100%, which
# corrupted the ext4 filesystem ("Structure needs cleaning") and wedged sshd.
# Reclaim those here. Do NOT `cargo clean`: the bats harness (_has_local_ebpf
# in lib/ebpf_helpers.bash) launches the agent from ${PROJECT_DIR}/target/
# release/ebpfsentinel-agent and target/bpfel-unknown-none/release/*, so the
# target/ tree must survive. Docker builder prune alone reclaims the bulk in
# full mode; target/ (~3G) on a 31G disk stays comfortably under the ceiling.
echo "=== Reclaiming build space ==="
if command -v docker &>/dev/null; then
    sudo docker builder prune -f 2>/dev/null || true
fi
sudo apt-get clean 2>/dev/null || true
sudo journalctl --vacuum-size=50M 2>/dev/null || true
echo "  Disk after reclaim: $(df -h / | awk 'NR==2 {print $4" free ("$5" used)"}')"

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
