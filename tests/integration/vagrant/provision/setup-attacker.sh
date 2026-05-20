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

# ── Attack toolkit installation ────────────────────────────────────
echo ""
echo "=== Installing attack toolkit ==="

PROVISION_DIR="${INTEGRATION_DIR}/vagrant/provision"

# [tk/1] apt-managed tools
echo "  [tk/1] apt-managed tools"
sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    slowhttptest nmap t50 wrk dnsperf hydra ncrack tcpdump \
    python3-venv python3-pip cmake build-essential pkg-config \
    libpcap-dev unzip jq

# [tk/2] vendored MHDDoS submodule + venv
echo "  [tk/2] MHDDoS submodule + venv"
if [ -d "${PROJECT_DIR}/.git" ]; then
    (cd "${PROJECT_DIR}" && git submodule update --init --depth 1 --recursive \
        -- tests/integration/vendor/MHDDoS) || true
fi
sudo mkdir -p /opt/MHDDoS
sudo cp -r "${INTEGRATION_DIR}/vendor/MHDDoS/." /opt/MHDDoS/
sudo chown -R "${USER}:${USER}" /opt/MHDDoS
if [ ! -d /opt/MHDDoS/.venv ]; then
    python3 -m venv /opt/MHDDoS/.venv
fi
/opt/MHDDoS/.venv/bin/pip install --upgrade pip >/dev/null
/opt/MHDDoS/.venv/bin/pip install -r /opt/MHDDoS/requirements.txt
# Disable Tor by default (avoids slow startup probe)
if [ -f /opt/MHDDoS/start.py ] && ! [ -f /opt/MHDDoS/.tor-disabled ]; then
    sudo touch /opt/MHDDoS/.tor-disabled
fi

# [tk/3] scapy venv
echo "  [tk/3] scapy venv"
sudo mkdir -p /opt/scapy-venv && sudo chown "${USER}:${USER}" /opt/scapy-venv
[ -d /opt/scapy-venv/bin ] || python3 -m venv /opt/scapy-venv
/opt/scapy-venv/bin/pip install --upgrade pip >/dev/null
/opt/scapy-venv/bin/pip install "scapy==2.7.0"

# [tk/4] mitmproxy venv
echo "  [tk/4] mitmproxy venv"
sudo mkdir -p /opt/mitmproxy-venv && sudo chown "${USER}:${USER}" /opt/mitmproxy-venv
[ -d /opt/mitmproxy-venv/bin ] || python3 -m venv /opt/mitmproxy-venv
/opt/mitmproxy-venv/bin/pip install --upgrade pip >/dev/null
/opt/mitmproxy-venv/bin/pip install "mitmproxy==12.2.3"

# [tk/5] release tarballs (sha256-verified — pins kept in TOOL_VERSIONS.md)
echo "  [tk/5] release tarballs"
install_release() {
    local name="$1" url="$2" sha="$3" install_cmd="$4"
    local tmp
    tmp="$(mktemp -d)"
    local dst="${tmp}/$(basename "${url}")"
    if ! curl -fsSL --retry 3 --max-time 120 -o "${dst}" "${url}"; then
        echo "    ERROR: download failed for ${name} (${url})" >&2
        rm -rf "${tmp}"
        return 1
    fi
    local got
    got="$(sha256sum "${dst}" | awk '{print $1}')"
    if [ "${got}" != "${sha}" ]; then
        echo "    ERROR: ${name} sha256 mismatch (expected ${sha}, got ${got})" >&2
        echo "    refusing to install; refresh pin from upstream checksum file or bump TOOL_VERSIONS.md" >&2
        rm -rf "${tmp}"
        return 1
    fi
    (cd "${tmp}" && eval "${install_cmd}")
    rm -rf "${tmp}"
}

install_release vegeta \
    "https://github.com/tsenart/vegeta/releases/download/v12.13.0/vegeta_12.13.0_linux_amd64.tar.gz" \
    "e8759ce45c14e18374bdccd3ba6068197bc3a9f9b7e484db3837f701b9d12e61" \
    'tar -xzf vegeta_12.13.0_linux_amd64.tar.gz vegeta && sudo install -m0755 vegeta /usr/local/bin/'

install_release k6 \
    "https://github.com/grafana/k6/releases/download/v2.0.0/k6-v2.0.0-linux-amd64.tar.gz" \
    "2ae87d976f6cdba17185bdd980d8819a3a98e9092c6f0638cd58272ecefc8b90" \
    'tar -xzf k6-v2.0.0-linux-amd64.tar.gz && sudo install -m0755 k6-v2.0.0-linux-amd64/k6 /usr/local/bin/'

install_release nuclei \
    "https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip" \
    "cd4ea43c88b50af8ab96eb6ad3fb4debd8e9d51efaff4d4c2d99106041578943" \
    'unzip -o nuclei_3.8.0_linux_amd64.zip nuclei && sudo install -m0755 nuclei /usr/local/bin/'

install_release dnscrypt-proxy \
    "https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.15/dnscrypt-proxy-linux_x86_64-2.1.15.tar.gz" \
    "bc43b8fe41a5962e5fc39e3887c1d881d51f1ad87221fef85b48fc0b35f19244" \
    'tar -xzf dnscrypt-proxy-linux_x86_64-2.1.15.tar.gz && sudo install -m0755 linux-x86_64/dnscrypt-proxy /usr/local/bin/'

install_release cloudflared \
    "https://github.com/cloudflare/cloudflared/releases/download/2026.5.0/cloudflared-linux-amd64" \
    "0095e46fdc88855d801c4d304cb1f5dd4bd656116c47ab94c2ad0ae7cda1c7ec" \
    'sudo install -m0755 cloudflared-linux-amd64 /usr/local/bin/cloudflared'

# [tk/6] hyenae-ng source build (tag v0.10)
echo "  [tk/6] hyenae-ng source build"
if ! command -v hyenae-ng >/dev/null 2>&1; then
    HN_DIR="$(mktemp -d)"
    if git clone --depth 1 --branch v0.10 \
        https://github.com/r-richter/hyenae-ng "${HN_DIR}" 2>/dev/null; then
        (cd "${HN_DIR}" && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && \
            cmake --build build --parallel 2 >/dev/null && \
            sudo cmake --install build --prefix /usr/local >/dev/null) || \
            echo "    WARN: hyenae-ng build failed; skipping"
    else
        echo "    WARN: hyenae-ng clone failed; skipping"
    fi
    rm -rf "${HN_DIR}"
fi

# [tk/7] pktgen kernel module + udev rule
echo "  [tk/7] pktgen kernel module"
sudo tee /etc/modules-load.d/pktgen.conf >/dev/null <<'PKTGEN'
# Loaded by attacker VM provisioner; used by suites 41/42 for high-pps L4 floods.
pktgen
PKTGEN
sudo modprobe pktgen 2>/dev/null || echo "    NOTE: pktgen modprobe deferred until reboot"
sudo tee /etc/udev/rules.d/60-pktgen-net.rules >/dev/null <<'UDEV'
# Lift default ring depth for pktgen-driven sources so floods don't drop early.
ACTION=="add", SUBSYSTEM=="net", KERNEL=="eth*", \
  RUN+="/sbin/ethtool -G %k rx 4096 tx 4096 || true"
UDEV
sudo udevadm control --reload 2>/dev/null || true

# [tk/8] verification gate
echo "  [tk/8] verifying installation"
if [ -x "${PROVISION_DIR}/attacker_tools_check.sh" ]; then
    bash "${PROVISION_DIR}/attacker_tools_check.sh"
else
    echo "    ERROR: attacker_tools_check.sh missing from ${PROVISION_DIR}" >&2
    exit 1
fi

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
